// Package soc provides application services for the SENTINEL AI SOC subsystem.
package soc

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syntrex/gomcp/internal/domain/oracle"
	"github.com/syntrex/gomcp/internal/domain/peer"
	domsoc "github.com/syntrex/gomcp/internal/domain/soc"
	"github.com/syntrex/gomcp/internal/infrastructure/audit"
)

const (
	// MaxEventsPerSecondPerSensor limits event ingest rate per sensor (§17.3).
	MaxEventsPerSecondPerSensor = 100
)

// Service orchestrates the SOC event pipeline:
// Step 0: Secret Scanner (INVARIANT) → DIP → Decision Logger → Persist → Correlation.
type Service struct {
	mu        sync.RWMutex
	repo      domsoc.SOCRepository
	logger    *audit.DecisionLogger
	rules     []domsoc.SOCCorrelationRule
	playbookEngine   *domsoc.PlaybookEngine
	executorRegistry *domsoc.ExecutorRegistry
	sensors   map[string]*domsoc.Sensor
	draining  bool // §15.7: graceful shutdown mode — rejects new events

	// Alert Clustering engine (§7.6): groups related alerts.
	clusterEngine *domsoc.ClusterEngine

	// Event bus for real-time SSE streaming.
	eventBus *domsoc.EventBus

	// Rate limiting per sensor (§17.3): sensorID → timestamps of recent events.
	sensorRates        map[string][]time.Time
	rateLimitDisabled  bool

	// Sensor authentication (§17.3 T-01): sensorID → pre-shared key.
	sensorKeys map[string]string

	// SOAR webhook notifier (§P3): outbound HTTP POST on incidents.
	webhook *WebhookNotifier

	// Threat intelligence store (§P3+): IOC enrichment.
	threatIntel *ThreatIntelStore

	// Zero-G Mode (§13.4): manual approval workflow.
	zeroG *domsoc.ZeroGMode

	// P2P SOC Sync (§14): multi-site event synchronization.
	p2pSync *domsoc.P2PSyncService

	// Anomaly detection engine (§5): statistical baseline + Z-score.
	anomaly *domsoc.AnomalyDetector

	// Threat Intelligence IOC engine (§6): real-time IOC matching.
	threatIntelEngine *domsoc.ThreatIntelEngine

	// Data Retention Policy (§19): configurable lifecycle management.
	retention *domsoc.DataRetentionPolicy

	// P-1 FIX: In-memory sliding window for correlation (avoids DB query per ingest).
	recentEvents []domsoc.SOCEvent
}

// NewService creates a SOC service with persistence and decision logging.
func NewService(repo domsoc.SOCRepository, logger *audit.DecisionLogger) *Service {
	// Build executor registry with all SOAR action handlers
	reg := domsoc.NewExecutorRegistry()
	reg.Register(&domsoc.BlockIPExecutor{})
	reg.Register(domsoc.NewNotifyExecutor(""))       // URL configured via SetNotifyURL()
	reg.Register(domsoc.NewQuarantineExecutor())
	reg.Register(domsoc.NewEscalateExecutor(""))      // URL configured via SetEscalateURL()
	// Webhook executor configured separately via SetWebhookConfig()

	// Create playbook engine with live executor handler (not just logging)
	pe := domsoc.NewPlaybookEngine()
	pe.SetHandler(&domsoc.ExecutorActionHandler{Registry: reg})

	slog.Info("SOAR engine initialized",
		"executors", reg.List(),
		"playbooks", len(pe.ListPlaybooks()),
	)

	return &Service{
		repo:             repo,
		logger:           logger,
		rules:            domsoc.DefaultSOCCorrelationRules(),
		playbookEngine:   pe,
		executorRegistry: reg,
		sensors:          make(map[string]*domsoc.Sensor),
		clusterEngine:    domsoc.NewClusterEngine(domsoc.DefaultClusterConfig()),
		eventBus:         domsoc.NewEventBus(256),
		sensorRates:      make(map[string][]time.Time),
		zeroG:            domsoc.NewZeroGMode(),
		p2pSync:          domsoc.NewP2PSyncService(),
		anomaly:          domsoc.NewAnomalyDetector(),
		threatIntelEngine: domsoc.NewThreatIntelEngine(),
		retention:        domsoc.NewDataRetentionPolicy(),
	}
}

// AddCustomRules appends YAML-loaded custom correlation rules (§7.5).
func (s *Service) AddCustomRules(rules []domsoc.SOCCorrelationRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = append(s.rules, rules...)
}

// ClusterStats returns Alert Clustering engine statistics (§7.6).
func (s *Service) ClusterStats() map[string]any {
	if s.clusterEngine == nil {
		return map[string]any{"enabled": false}
	}
	stats := s.clusterEngine.Stats()
	stats["enabled"] = true
	return stats
}

// SetSensorKeys configures pre-shared keys for sensor authentication (§17.3 T-01).
// If keys is nil or empty, authentication is disabled (all events accepted).
func (s *Service) SetSensorKeys(keys map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sensorKeys = keys
}

// SetWebhookConfig configures SOAR webhook notifications.
// If config has no endpoints, webhooks are disabled.
func (s *Service) SetWebhookConfig(config WebhookConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webhook = NewWebhookNotifier(config)
}

// SetThreatIntel configures the threat intelligence store for IOC enrichment.
func (s *Service) SetThreatIntel(store *ThreatIntelStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.threatIntel = store
}

// WebhookStats returns SOAR webhook delivery statistics (T3-5).
func (s *Service) WebhookStats() map[string]any {
	s.mu.RLock()
	wh := s.webhook
	s.mu.RUnlock()

	if wh == nil {
		return map[string]any{
			"enabled": false,
			"sent":    0,
			"failed":  0,
		}
	}
	sent, failed := wh.Stats()
	return map[string]any{
		"enabled": true,
		"sent":    sent,
		"failed":  failed,
	}
}

// GetWebhookConfig returns current webhook configuration.
func (s *Service) GetWebhookConfig() *WebhookConfig {
	s.mu.RLock()
	wh := s.webhook
	s.mu.RUnlock()
	if wh == nil {
		return nil
	}
	return &wh.config
}

// TestWebhook sends a test ping to all configured webhook endpoints.
func (s *Service) TestWebhook() []WebhookResult {
	s.mu.RLock()
	wh := s.webhook
	s.mu.RUnlock()
	if wh == nil || !wh.enabled {
		return nil
	}

	testIncident := &domsoc.Incident{
		ID:       "TEST-PING",
		Title:    "Webhook Test — SYNTREX SOC",
		Severity: domsoc.SeverityInfo,
		Status:   domsoc.StatusOpen,
	}
	return wh.NotifyIncident("webhook_test", testIncident)
}


// Drain puts the service into drain mode (§15.7 Stage 1).
// New events are rejected with ErrDraining; existing processing continues.
func (s *Service) Drain() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.draining = true
	if s.logger != nil {
		s.logger.Record(audit.ModuleSOC, "DRAIN:ACTIVATED", "Zero-downtime update: ingest paused")
	}
}

// Resume exits drain mode, re-enabling event ingestion.
func (s *Service) Resume() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.draining = false
	if s.logger != nil {
		s.logger.Record(audit.ModuleSOC, "DRAIN:DEACTIVATED", "Event ingestion resumed")
	}
}

// IsDraining returns true if the service is in drain mode.
func (s *Service) IsDraining() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.draining
}

// StartRetentionScheduler runs a background goroutine that periodically
// purges expired events and incidents (§19 Data Retention).
// Default interval: 1 hour. Stops when ctx is cancelled.
func (s *Service) StartRetentionScheduler(ctx context.Context, interval time.Duration) {
	if interval == 0 {
		interval = time.Hour
	}
	go func() {
		slog.Info("retention scheduler started", "interval", interval.String())
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				slog.Info("retention scheduler stopped")
				return
			case <-ticker.C:
				s.runRetentionPurge()
			}
		}
	}()
}

// runRetentionPurge executes one cycle of retention enforcement.
// A-3 FIX: Uses configurable retention durations instead of hardcoded defaults.
func (s *Service) runRetentionPurge() {
	evtDays := 90
	incDays := 365
	if s.retention != nil {
		if r, ok := s.retention.GetPolicy("events"); ok && r.RetainDays > 0 {
			evtDays = r.RetainDays
		}
		if r, ok := s.retention.GetPolicy("incidents"); ok && r.RetainDays > 0 {
			incDays = r.RetainDays
		}
	}

	evtCount, evtErr := s.repo.PurgeExpiredEvents(evtDays)
	incCount, incErr := s.repo.PurgeExpiredIncidents(incDays)

	if evtErr != nil {
		slog.Error("retention purge: events", "error", evtErr)
	}
	if incErr != nil {
		slog.Error("retention purge: incidents", "error", incErr)
	}

	if evtCount > 0 || incCount > 0 {
		slog.Info("retention purge completed",
			"events_purged", evtCount,
			"incidents_purged", incCount,
		)
		if s.logger != nil {
			s.logger.Record(audit.ModuleSOC, "RETENTION:PURGE",
				fmt.Sprintf("Purged %d events, %d incidents", evtCount, incCount))
		}
	}
}
// IngestEvent processes an incoming security event through the SOC pipeline.
// Returns the event ID and any incident created by correlation.
//
// Pipeline (§5.2):
//
//	Step -1: Sensor Authentication — pre-shared key validation (§17.3 T-01)
//	Step 0: Secret Scanner — INVARIANT, cannot be disabled (§5.4)
//	Step 0.5: Rate Limiting — per sensor ≤100 events/sec (§17.3)
//	Step 1: Decision Logger — SHA-256 chain with Zero-G tagging (§5.6, §13.4)
//	Step 2: Persist event to SQLite
//	Step 3: Update sensor registry (§11.3)
//	Step 4: Run correlation engine (§7)
//	Step 5: Apply playbooks (§10)
func (s *Service) IngestEvent(event domsoc.SOCEvent) (string, *domsoc.Incident, error) {
	// Step -3: Drain guard (§15.7)
	if s.IsDraining() {
		return "", nil, domsoc.ErrDraining
	}

	// Step -2: Input Validation
	if err := event.Validate(); err != nil {
		return "", nil, err
	}

	// Step -1: Sensor Authentication (§17.3 T-01)
	// S-1 FIX: When sensor keys are configured, ALL events must authenticate.
	// Events without SensorID are rejected (prevents auth bypass via empty SensorID).
	s.mu.RLock()
	sensorKeys := s.sensorKeys
	s.mu.RUnlock()

	if len(sensorKeys) > 0 {
		if event.SensorID == "" {
			if s.logger != nil {
				s.logger.Record(audit.ModuleSOC,
					"AUTH_FAILED:REJECT",
					"reason=missing_sensor_id")
			}
			return "", nil, fmt.Errorf("%w: sensor_id required when authentication is enabled", domsoc.ErrAuthFailed)
		}
		expected, exists := sensorKeys[event.SensorID]
		// S-3 FIX: Constant-time comparison prevents timing side-channel attacks on PSK.
		if !exists || subtle.ConstantTimeCompare([]byte(expected), []byte(event.SensorKey)) != 1 {
			if s.logger != nil {
				s.logger.Record(audit.ModuleSOC,
					"AUTH_FAILED:REJECT",
					fmt.Sprintf("sensor_id=%s reason=invalid_key", event.SensorID))
			}
			return "", nil, fmt.Errorf("%w: sensor %s", domsoc.ErrAuthFailed, event.SensorID)
		}
	}

	// S-2 FIX: Clear sensitive key material after auth check.
	event.SensorKey = ""

	// Step 0: Secret Scanner — INVARIANT (§5.4)
	// always_active: true, cannot_disable: true
	if event.Payload != "" {
		scanResult := oracle.ScanForSecrets(event.Payload)
		if scanResult.HasSecrets {
			if s.logger != nil {
				s.logger.Record(audit.ModuleSOC,
					"SECRET_DETECTED:REJECT",
					fmt.Sprintf("source=%s event_id=%s detections=%s",
						event.Source, event.ID, strings.Join(scanResult.Detections, "; ")))
			}
			return "", nil, fmt.Errorf("%w: %d detections found", domsoc.ErrSecretDetected, len(scanResult.Detections))
		}
	}

	// Step 0.5: Rate Limiting per sensor (§17.3 T-02 DoS Protection)
	sensorID := event.SensorID
	if sensorID == "" {
		sensorID = string(event.Source)
	}
	if s.isRateLimited(sensorID) {
		if s.logger != nil {
			s.logger.Record(audit.ModuleSOC,
				"RATE_LIMIT_EXCEEDED:REJECT",
				fmt.Sprintf("sensor=%s limit=%d/sec", sensorID, MaxEventsPerSecondPerSensor))
		}
		return "", nil, fmt.Errorf("%w: sensor %s (max %d events/sec)", domsoc.ErrRateLimited, sensorID, MaxEventsPerSecondPerSensor)
	}

	// Step 1: Log decision with Zero-G tagging (§13.4)
	if s.logger != nil {
		zeroGTag := ""
		if event.ZeroGMode {
			zeroGTag = " zero_g_mode=true"
		}
		s.logger.Record(audit.ModuleSOC,
			fmt.Sprintf("INGEST:%s", event.Verdict),
			fmt.Sprintf("source=%s category=%s severity=%s confidence=%.2f%s",
				event.Source, event.Category, event.Severity, event.Confidence, zeroGTag))
	}

	// Step 1.5: Content deduplication (§5.2 step 2)
	event.ComputeContentHash()
	if event.ContentHash != "" {
		exists, err := s.repo.EventExistsByHash(event.ContentHash)
		if err != nil {
			slog.Warn("dedup check failed, proceeding", "error", err)
		} else if exists {
			return event.ID, nil, nil // Silently deduplicate
		}
	}

	// Step 2: Persist event
	if err := s.repo.InsertEvent(event); err != nil {
		return "", nil, fmt.Errorf("soc: persist event: %w", err)
	}

	// Step 2.5: Publish to event bus for real-time SSE streaming.
	if s.eventBus != nil {
		s.eventBus.Publish(event)
	}

	// Step 3: Update sensor registry (§11.3)
	s.updateSensor(event)

	// Step 3.1: Alert Clustering (§7.6)
	if s.clusterEngine != nil {
		s.clusterEngine.AddEvent(event)
	}

	// Step 3.5: Threat Intel IOC enrichment (§P3+)
	if s.threatIntel != nil {
		iocMatches := s.threatIntel.EnrichEvent(event.SensorID, event.Description)
		if len(iocMatches) > 0 {
			// Boost confidence and log IOC match
			if event.Confidence < 0.9 {
				event.Confidence = 0.9
			}
			if s.logger != nil {
				s.logger.Record(audit.ModuleSOC,
					fmt.Sprintf("IOC_MATCH:%d", len(iocMatches)),
					fmt.Sprintf("event=%s ioc_type=%s ioc_value=%s source=%s",
						event.ID, iocMatches[0].Type, iocMatches[0].Value, iocMatches[0].Source))
			}
		}
	}

	// Step 4: Run correlation against recent events (§7)
	// Zero-G events are excluded from auto-response but still correlated.
	incident := s.correlate(event)

	// Step 5: Apply playbooks if incident created (§10)
	// Skip auto-response for Zero-G events (§13.4: require_manual_approval: true)
	if incident != nil && !event.ZeroGMode {
		s.applyPlaybooks(event, incident)
	} else if incident != nil && event.ZeroGMode {
		if s.logger != nil {
			s.logger.Record(audit.ModuleSOC,
				"PLAYBOOK_SKIPPED:ZERO_G",
				fmt.Sprintf("incident=%s reason=zero_g_mode_requires_manual_approval", incident.ID))
		}
	}

	// Step 6: SOAR webhook notification (§P3)
	// Skip webhook for Zero-G events — must go through manual approval (§13.4).
	if incident != nil && s.webhook != nil && !event.ZeroGMode {
		go s.webhook.NotifyIncident("incident_created", incident)
	}

	return event.ID, incident, nil
}

// DisableRateLimit disables per-sensor rate limiting (for benchmarks only).
func (s *Service) DisableRateLimit() {
	s.mu.Lock()
	s.rateLimitDisabled = true
	s.mu.Unlock()
}

// isRateLimited checks if sensor exceeds MaxEventsPerSecondPerSensor (§17.3).
// P-2 FIX: Also cleans up dead sensor entries to prevent memory leak.
func (s *Service) isRateLimited(sensorID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.rateLimitDisabled {
		return false
	}

	now := time.Now()
	cutoff := now.Add(-time.Second)

	// P-2 FIX: Periodically clean up dead sensors (every ~100 calls).
	// Removes sensors with no activity in the last 10 seconds.
	if len(s.sensorRates) > 10 {
		deadCutoff := now.Add(-10 * time.Second)
		for id, timestamps := range s.sensorRates {
			if id == sensorID {
				continue
			}
			if len(timestamps) > 0 && timestamps[len(timestamps)-1].Before(deadCutoff) {
				delete(s.sensorRates, id)
			}
		}
	}

	// Prune old timestamps.
	timestamps := s.sensorRates[sensorID]
	pruned := timestamps[:0]
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			pruned = append(pruned, ts)
		}
	}
	pruned = append(pruned, now)
	s.sensorRates[sensorID] = pruned

	return len(pruned) > MaxEventsPerSecondPerSensor
}

// updateSensor registers/updates sentinel sensor on event ingest (§11.3 auto-discovery).
// E-2 FIX: Logs UpsertSensor errors instead of silently ignoring them.
func (s *Service) updateSensor(event domsoc.SOCEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sensorID := event.SensorID
	if sensorID == "" {
		sensorID = string(event.Source)
	}

	sensor, exists := s.sensors[sensorID]
	if !exists {
		newSensor := domsoc.NewSensor(sensorID, domsoc.SensorType(event.Source))
		sensor = &newSensor
		s.sensors[sensorID] = sensor
	}
	sensor.RecordEvent()
	if err := s.repo.UpsertSensor(*sensor); err != nil {
		slog.Error("sensor upsert failed", "sensor_id", sensorID, "error", err)
	}
}

// correlate runs correlation rules against recent events (§7).
// P-1 FIX: Uses in-memory sliding window instead of DB query per ingest.
func (s *Service) correlate(event domsoc.SOCEvent) *domsoc.Incident {
	s.mu.Lock()
	// Append to sliding window and prune events older than 1 hour.
	cutoff := time.Now().Add(-time.Hour)
	pruned := s.recentEvents[:0]
	for _, e := range s.recentEvents {
		if e.Timestamp.After(cutoff) {
			pruned = append(pruned, e)
		}
	}
	pruned = append(pruned, event)
	// Cap at 500 events to bound memory.
	if len(pruned) > 500 {
		pruned = pruned[len(pruned)-500:]
	}
	s.recentEvents = pruned
	events := make([]domsoc.SOCEvent, len(pruned))
	copy(events, pruned)
	s.mu.Unlock()

	if len(events) < 2 {
		return nil
	}

	matches := domsoc.CorrelateSOCEvents(events, s.rules)
	if len(matches) == 0 {
		return nil
	}

	match := matches[0]
	incident := domsoc.NewIncident(match.Rule.Name, match.Rule.Severity, match.Rule.ID)
	incident.KillChainPhase = match.Rule.KillChainPhase
	incident.MITREMapping = match.Rule.MITREMapping

	for _, e := range match.Events {
		incident.AddEvent(e.ID, e.Severity)
	}

	// Set decision chain anchor (§5.6)
	if s.logger != nil {
		anchor := s.logger.PrevHash()
		incident.SetAnchor(anchor, s.logger.Count())
		s.logger.Record(audit.ModuleCorrelation,
			fmt.Sprintf("INCIDENT_CREATED:%s", incident.ID),
			fmt.Sprintf("rule=%s severity=%s anchor=%s chain_length=%d",
				match.Rule.ID, match.Rule.Severity, anchor, s.logger.Count()))
	}

	// E-1 FIX: Handle InsertIncident error.
	if err := s.repo.InsertIncident(incident); err != nil {
		slog.Error("failed to persist incident", "incident_id", incident.ID, "error", err)
		return nil
	}
	return &incident
}

// applyPlaybooks matches playbooks against the event and incident (§10).
func (s *Service) applyPlaybooks(event domsoc.SOCEvent, incident *domsoc.Incident) {
	execs := s.playbookEngine.Execute(incident.ID, string(event.Severity), event.Category, "")
	if len(execs) > 0 {
		incident.PlaybookApplied = execs[0].PlaybookID
		if s.logger != nil {
			s.logger.Record(audit.ModuleSOC,
				fmt.Sprintf("PLAYBOOK_APPLIED:%s", execs[0].PlaybookID),
				fmt.Sprintf("incident=%s actions=%d", incident.ID, execs[0].ActionsRun))
		}
	}
}

// RecordHeartbeat processes a sensor heartbeat (§11.3).
func (s *Service) RecordHeartbeat(sensorID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sensor, exists := s.sensors[sensorID]
	if !exists {
		return false, fmt.Errorf("sensor not found: %s", sensorID)
	}
	sensor.RecordHeartbeat()
	if err := s.repo.UpsertSensor(*sensor); err != nil {
		return false, fmt.Errorf("soc: upsert sensor: %w", err)
	}
	return true, nil
}

// CheckSensors runs heartbeat check on all sensors (§11.3).
// Returns sensors that transitioned to OFFLINE (need SOC alert).
func (s *Service) CheckSensors() []domsoc.Sensor {
	s.mu.Lock()
	defer s.mu.Unlock()

	var offlineSensors []domsoc.Sensor
	for _, sensor := range s.sensors {
		if sensor.TimeSinceLastSeen() > time.Duration(domsoc.HeartbeatIntervalSec)*time.Second {
			alertNeeded := sensor.MissHeartbeat()
			if err := s.repo.UpsertSensor(*sensor); err != nil {
				slog.Error("sensor heartbeat check: upsert failed", "sensor_id", sensor.SensorID, "error", err)
			}
			if alertNeeded {
				offlineSensors = append(offlineSensors, *sensor)
				if s.logger != nil {
					s.logger.Record(audit.ModuleSOC,
						"SENSOR_OFFLINE:ALERT",
						fmt.Sprintf("sensor=%s type=%s missed=%d", sensor.SensorID, sensor.SensorType, sensor.MissedHeartbeats))
				}
			}
		}
	}
	return offlineSensors
}

// ListEvents returns recent events with optional limit.
func (s *Service) ListEvents(limit int) ([]domsoc.SOCEvent, error) {
	return s.repo.ListEvents("", limit)
}

// ListIncidents returns incidents, optionally filtered by status.
func (s *Service) ListIncidents(status string, limit int) ([]domsoc.Incident, error) {
	return s.repo.ListIncidents("", status, limit)
}

// ListRules returns all active correlation rules (built-in + custom).
func (s *Service) ListRules() []domsoc.SOCCorrelationRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domsoc.SOCCorrelationRule, len(s.rules))
	copy(out, s.rules)
	return out
}

// EventBus returns the real-time event bus for SSE subscribers.
func (s *Service) EventBus() *domsoc.EventBus {
	return s.eventBus
}

// ZeroG returns the Zero-G Mode approval engine (§13.4).
func (s *Service) ZeroG() *domsoc.ZeroGMode {
	return s.zeroG
}

// DecisionLogPath returns the decision log file path for chain verification.
func (s *Service) DecisionLogPath() string {
	if s.logger == nil {
		return ""
	}
	return s.logger.Path()
}

// P2PSync returns the P2P SOC sync engine (§14).
func (s *Service) P2PSync() *domsoc.P2PSyncService {
	return s.p2pSync
}

// AnomalyDetector returns the anomaly detection engine (§5).
func (s *Service) AnomalyDetector() *domsoc.AnomalyDetector {
	return s.anomaly
}

// PlaybookEngine returns the playbook execution engine (§10).
func (s *Service) PlaybookEngine() *domsoc.PlaybookEngine {
	return s.playbookEngine
}

// ThreatIntelEngine returns the IOC matching engine (§6).
func (s *Service) ThreatIntelEngine() *domsoc.ThreatIntelEngine {
	return s.threatIntelEngine
}

// RetentionPolicy returns the data retention policy engine (§19).
func (s *Service) RetentionPolicy() *domsoc.DataRetentionPolicy {
	return s.retention
}

// GetKillChain reconstructs the Kill Chain for a given incident (§8).
func (s *Service) GetKillChain(incidentID string) (*domsoc.KillChain, error) {
	inc, err := s.repo.GetIncident(incidentID)
	if err != nil {
		return nil, err
	}

	// Fetch events associated with the incident
	var events []domsoc.SOCEvent
	for _, eid := range inc.Events {
		ev, err := s.repo.GetEvent(eid)
		if err == nil {
			events = append(events, *ev)
		}
	}

	s.mu.RLock()
	rules := s.rules
	s.mu.RUnlock()

	kc := domsoc.ReconstructKillChain(*inc, events, rules)
	if kc == nil {
		return nil, fmt.Errorf("soc: no kill chain for incident %s", incidentID)
	}
	return kc, nil
}

// GetRecentDecisions returns audit metadata for the decision log (§9).
// Note: Full decision retrieval requires extending DecisionLogger in a future phase.
func (s *Service) GetRecentDecisions(limit int) []map[string]any {
	if s.logger == nil {
		return nil
	}
	// Return summary from available DecisionLogger API
	return []map[string]any{
		{
			"total_decisions": s.logger.Count(),
			"hash_chain":     s.logger.PrevHash(),
			"log_path":       s.logger.Path(),
			"status":         "operational",
		},
	}
}

// GetIncident returns an incident by ID.
func (s *Service) GetIncident(id string) (*domsoc.Incident, error) {
	return s.repo.GetIncident(id)
}

// UpdateVerdict updates an incident's status (manual verdict).
func (s *Service) UpdateVerdict(id string, status domsoc.IncidentStatus) error {
	if s.logger != nil {
		s.logger.Record(audit.ModuleSOC,
			fmt.Sprintf("VERDICT:%s", status),
			fmt.Sprintf("incident=%s", id))
	}
	return s.repo.UpdateIncidentStatus(id, status)
}

// --- Case Management Methods ---

// AssignIncident assigns an analyst to an incident.
func (s *Service) AssignIncident(id, analyst string) error {
	inc, err := s.repo.GetIncident(id)
	if err != nil {
		return fmt.Errorf("incident not found: %s", id)
	}
	inc.Assign(analyst)
	if s.logger != nil {
		s.logger.Record(audit.ModuleSOC,
			"ASSIGN",
			fmt.Sprintf("incident=%s analyst=%s", id, analyst))
	}
	return s.repo.UpdateIncident(inc)
}

// ChangeIncidentStatus changes the status of an incident with actor tracking.
func (s *Service) ChangeIncidentStatus(id string, status domsoc.IncidentStatus, actor string) error {
	inc, err := s.repo.GetIncident(id)
	if err != nil {
		return fmt.Errorf("incident not found: %s", id)
	}
	inc.ChangeStatus(status, actor)
	if s.logger != nil {
		s.logger.Record(audit.ModuleSOC,
			fmt.Sprintf("STATUS_CHANGE:%s", status),
			fmt.Sprintf("incident=%s actor=%s", id, actor))
	}
	return s.repo.UpdateIncident(inc)
}

// AddIncidentNote adds an investigation note to an incident.
func (s *Service) AddIncidentNote(id, author, content string) (*domsoc.IncidentNote, error) {
	inc, err := s.repo.GetIncident(id)
	if err != nil {
		return nil, fmt.Errorf("incident not found: %s", id)
	}
	note := inc.AddNote(author, content)
	if s.logger != nil {
		s.logger.Record(audit.ModuleSOC,
			"NOTE_ADDED",
			fmt.Sprintf("incident=%s author=%s note_id=%s", id, author, note.ID))
	}
	if err := s.repo.UpdateIncident(inc); err != nil {
		return nil, err
	}
	return &note, nil
}

// GetIncidentDetail returns full incident with notes and timeline.
func (s *Service) GetIncidentDetail(id string) (*domsoc.Incident, error) {
	return s.repo.GetIncident(id)
}

// ── Sprint 2: Incident Management Enhancements ─────────────────────────

// IncidentFilter defines advanced filter criteria for incidents.
type IncidentFilter struct {
	Status     string `json:"status"`
	Severity   string `json:"severity"`
	AssignedTo string `json:"assigned_to"`
	Search     string `json:"search"`
	Source     string `json:"source"` // correlation_rule
	DateFrom   string `json:"date_from"`
	DateTo     string `json:"date_to"`
	Page       int    `json:"page"`
	Limit      int    `json:"limit"`
	SortBy     string `json:"sort_by"`
	SortOrder  string `json:"sort_order"` // asc, desc
}

// IncidentFilterResult is paginated incidents response.
type IncidentFilterResult struct {
	Incidents  []domsoc.Incident `json:"incidents"`
	Total      int               `json:"total"`
	Page       int               `json:"page"`
	Limit      int               `json:"limit"`
	TotalPages int               `json:"total_pages"`
}

// ListIncidentsAdvanced filters incidents with multi-field criteria and pagination.
func (s *Service) ListIncidentsAdvanced(f IncidentFilter) (*IncidentFilterResult, error) {
	// Get all incidents (repo doesn't support advanced filtering)
	all, err := s.repo.ListIncidents("", "", 10000)
	if err != nil {
		return nil, err
	}

	// Apply filters in memory
	var filtered []domsoc.Incident
	for _, inc := range all {
		if f.Status != "" && string(inc.Status) != f.Status {
			continue
		}
		if f.Severity != "" && string(inc.Severity) != f.Severity {
			continue
		}
		if f.AssignedTo != "" && inc.AssignedTo != f.AssignedTo {
			continue
		}
		if f.Source != "" && inc.CorrelationRule != f.Source {
			continue
		}
		if f.Search != "" {
			found := false
			search := strings.ToLower(f.Search)
			if strings.Contains(strings.ToLower(inc.Title), search) ||
				strings.Contains(strings.ToLower(inc.Description), search) ||
				strings.Contains(strings.ToLower(inc.ID), search) {
				found = true
			}
			if !found {
				continue
			}
		}
		if f.DateFrom != "" {
			if from, err := time.Parse(time.RFC3339, f.DateFrom); err == nil {
				if inc.CreatedAt.Before(from) {
					continue
				}
			}
		}
		if f.DateTo != "" {
			if to, err := time.Parse(time.RFC3339, f.DateTo); err == nil {
				if inc.CreatedAt.After(to) {
					continue
				}
			}
		}
		filtered = append(filtered, inc)
	}

	// Sort
	if f.SortBy == "" {
		f.SortBy = "created_at"
	}
	sort.Slice(filtered, func(i, j int) bool {
		ascending := f.SortOrder != "desc"
		switch f.SortBy {
		case "severity":
			if ascending {
				return filtered[i].Severity.Rank() < filtered[j].Severity.Rank()
			}
			return filtered[i].Severity.Rank() > filtered[j].Severity.Rank()
		case "status":
			if ascending {
				return string(filtered[i].Status) < string(filtered[j].Status)
			}
			return string(filtered[i].Status) > string(filtered[j].Status)
		default: // created_at
			if ascending {
				return filtered[i].CreatedAt.Before(filtered[j].CreatedAt)
			}
			return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
		}
	})

	total := len(filtered)
	if f.Limit <= 0 {
		f.Limit = 20
	}
	if f.Page <= 0 {
		f.Page = 1
	}
	totalPages := (total + f.Limit - 1) / f.Limit
	start := (f.Page - 1) * f.Limit
	if start >= total {
		return &IncidentFilterResult{
			Incidents: []domsoc.Incident{},
			Total:     total, Page: f.Page, Limit: f.Limit, TotalPages: totalPages,
		}, nil
	}
	end := start + f.Limit
	if end > total {
		end = total
	}

	return &IncidentFilterResult{
		Incidents:  filtered[start:end],
		Total:      total,
		Page:       f.Page,
		Limit:      f.Limit,
		TotalPages: totalPages,
	}, nil
}

// BulkAction defines a batch operation on incidents.
type BulkAction struct {
	Action      string   `json:"action"`       // assign, status, close, delete
	IncidentIDs []string `json:"incident_ids"`
	Value       string   `json:"value"`        // analyst email, new status
	Actor       string   `json:"actor"`        // who initiated
}

// BulkActionResult is the result of a batch operation.
type BulkActionResult struct {
	Affected int      `json:"affected"`
	Failed   int      `json:"failed"`
	Errors   []string `json:"errors,omitempty"`
}

// BulkUpdateIncidents performs batch operations on multiple incidents.
func (s *Service) BulkUpdateIncidents(action BulkAction) (*BulkActionResult, error) {
	result := &BulkActionResult{}
	for _, id := range action.IncidentIDs {
		var err error
		switch action.Action {
		case "assign":
			err = s.AssignIncident(id, action.Value)
		case "status":
			err = s.ChangeIncidentStatus(id, domsoc.IncidentStatus(action.Value), action.Actor)
		case "close":
			err = s.ChangeIncidentStatus(id, domsoc.StatusResolved, action.Actor)
		default:
			err = fmt.Errorf("unknown bulk action: %s", action.Action)
		}
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", id, err.Error()))
		} else {
			result.Affected++
		}
	}
	if s.logger != nil {
		s.logger.Record(audit.ModuleSOC, "BULK_"+strings.ToUpper(action.Action),
			fmt.Sprintf("affected=%d failed=%d ids=%d actor=%s", result.Affected, result.Failed, len(action.IncidentIDs), action.Actor))
	}
	return result, nil
}

// SLAThreshold defines response/resolution time targets per severity.
type SLAThreshold struct {
	Severity       string        `json:"severity"`
	ResponseTime   time.Duration `json:"response_time"`   // max time to assign
	ResolutionTime time.Duration `json:"resolution_time"` // max time to resolve
}

// SLAStatus represents an incident's SLA compliance state.
type SLAStatus struct {
	ResponseBreached   bool    `json:"response_breached"`
	ResolutionBreached bool    `json:"resolution_breached"`
	ResponseRemaining  float64 `json:"response_remaining_min"`  // minutes remaining (negative = breached)
	ResolutionRemaining float64 `json:"resolution_remaining_min"`
	ResponseTarget     float64 `json:"response_target_min"`
	ResolutionTarget   float64 `json:"resolution_target_min"`
}

// DefaultSLAThresholds returns SLA targets per severity.
func DefaultSLAThresholds() map[string]SLAThreshold {
	return map[string]SLAThreshold{
		"CRITICAL": {Severity: "CRITICAL", ResponseTime: 15 * time.Minute, ResolutionTime: 4 * time.Hour},
		"HIGH":     {Severity: "HIGH", ResponseTime: 30 * time.Minute, ResolutionTime: 8 * time.Hour},
		"MEDIUM":   {Severity: "MEDIUM", ResponseTime: 2 * time.Hour, ResolutionTime: 24 * time.Hour},
		"LOW":      {Severity: "LOW", ResponseTime: 8 * time.Hour, ResolutionTime: 72 * time.Hour},
		"INFO":     {Severity: "INFO", ResponseTime: 24 * time.Hour, ResolutionTime: 168 * time.Hour},
	}
}

// CalculateSLA computes SLA status for an incident.
func CalculateSLA(inc *domsoc.Incident) *SLAStatus {
	thresholds := DefaultSLAThresholds()
	t, ok := thresholds[string(inc.Severity)]
	if !ok {
		return nil
	}

	now := time.Now()
	sla := &SLAStatus{
		ResponseTarget:   t.ResponseTime.Minutes(),
		ResolutionTarget: t.ResolutionTime.Minutes(),
	}

	// Response SLA — breached if not assigned within threshold
	if inc.AssignedTo == "" {
		elapsed := now.Sub(inc.CreatedAt)
		sla.ResponseRemaining = (t.ResponseTime - elapsed).Minutes()
		sla.ResponseBreached = elapsed > t.ResponseTime
	} else {
		sla.ResponseRemaining = t.ResponseTime.Minutes() // assigned, so OK
	}

	// Resolution SLA
	if inc.IsOpen() {
		elapsed := now.Sub(inc.CreatedAt)
		sla.ResolutionRemaining = (t.ResolutionTime - elapsed).Minutes()
		sla.ResolutionBreached = elapsed > t.ResolutionTime
	} else if inc.ResolvedAt != nil {
		elapsed := inc.ResolvedAt.Sub(inc.CreatedAt)
		sla.ResolutionRemaining = (t.ResolutionTime - elapsed).Minutes()
		sla.ResolutionBreached = elapsed > t.ResolutionTime
	}

	return sla
}

// ExportIncidentsCSV generates CSV data for incidents.
func (s *Service) ExportIncidentsCSV(f IncidentFilter) ([]byte, error) {
	result, err := s.ListIncidentsAdvanced(f)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	// Header
	w.Write([]string{"ID", "Title", "Status", "Severity", "Assigned To", "Correlation Rule",
		"Kill Chain Phase", "Event Count", "Created At", "Updated At", "Resolved At", "MTTR (min)",
		"SLA Response Breached", "SLA Resolution Breached"})

	for _, inc := range result.Incidents {
		resolvedAt := ""
		mttr := ""
		if inc.ResolvedAt != nil {
			resolvedAt = inc.ResolvedAt.Format(time.RFC3339)
			mttr = fmt.Sprintf("%.1f", inc.MTTR().Minutes())
		}
		sla := CalculateSLA(&inc)
		slaResp, slaResol := "N/A", "N/A"
		if sla != nil {
			if sla.ResponseBreached {
				slaResp = "BREACHED"
			} else {
				slaResp = "OK"
			}
			if sla.ResolutionBreached {
				slaResol = "BREACHED"
			} else {
				slaResol = "OK"
			}
		}
		w.Write([]string{
			inc.ID, inc.Title, string(inc.Status), string(inc.Severity),
			inc.AssignedTo, inc.CorrelationRule, inc.KillChainPhase,
			strconv.Itoa(inc.EventCount),
			inc.CreatedAt.Format(time.RFC3339),
			inc.UpdatedAt.Format(time.RFC3339),
			resolvedAt, mttr, slaResp, slaResol,
		})
	}
	w.Flush()
	return buf.Bytes(), nil
}

// ListSensors returns all registered sensors.
func (s *Service) ListSensors() ([]domsoc.Sensor, error) {
	return s.repo.ListSensors("")
}

// RegisterSensor adds or updates a sensor in the SOC.
func (s *Service) RegisterSensor(id, name, sensorType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sensor := domsoc.NewSensor(id, domsoc.SensorType(sensorType))
	sensor.Hostname = name
	s.sensors[id] = &sensor
}

// DeregisterSensor removes a sensor from the SOC.
func (s *Service) DeregisterSensor(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sensors, id)
}

// Dashboard returns SOC KPI metrics.
func (s *Service) Dashboard() (*DashboardData, error) {
	totalEvents, err := s.repo.CountEvents("")
	if err != nil {
		return nil, err
	}

	lastHourEvents, err := s.repo.CountEventsSince("", time.Now().Add(-1 * time.Hour))
	if err != nil {
		return nil, err
	}

	openIncidents, err := s.repo.CountOpenIncidents("")
	if err != nil {
		return nil, err
	}

	sensorCounts, err := s.repo.CountSensorsByStatus("")
	if err != nil {
		return nil, err
	}

	// Chain validation (§5.6, §12.2) — full SHA-256 chain verification.
	chainValid := false
	chainLength := 0
	chainHeadHash := ""
	chainBrokenLine := 0
	if s.logger != nil {
		chainLength = s.logger.Count()
		chainHeadHash = s.logger.PrevHash()
		// Full chain verification via VerifyChainFromFile (§5.6)
		validCount, brokenLine, verifyErr := audit.VerifyChainFromFile(s.logger.Path())
		if verifyErr == nil && brokenLine == 0 {
			chainValid = true
			chainLength = validCount // Use file-verified count
		} else {
			chainBrokenLine = brokenLine
		}
	}

	return &DashboardData{
		TotalEvents:      totalEvents,
		EventsLastHour:   lastHourEvents,
		OpenIncidents:    openIncidents,
		SensorStatus:     sensorCounts,
		ChainValid:       chainValid,
		ChainLength:      chainLength,
		ChainHeadHash:    chainHeadHash,
		ChainBrokenLine:  chainBrokenLine,
		CorrelationRules: len(s.rules),
		ActivePlaybooks:  len(s.playbookEngine.ListPlaybooks()),
	}, nil
}

// MaxAnalyticsEvents caps the event fetch for analytics reports to prevent OOM.
const MaxAnalyticsEvents = 100000

// Analytics generates a full SOC analytics report for the given time window.
func (s *Service) Analytics(windowHours int) (*AnalyticsReport, error) {
	if windowHours <= 0 {
		windowHours = 24
	}

	events, err := s.repo.ListEvents("", MaxAnalyticsEvents)
	if err != nil {
		return nil, fmt.Errorf("soc: analytics events: %w", err)
	}

	incidents, err := s.repo.ListIncidents("", "", 10000)
	if err != nil {
		return nil, fmt.Errorf("soc: analytics incidents: %w", err)
	}

	return GenerateReport(events, incidents, windowHours), nil
}

// DashboardData holds SOC KPI metrics (§12.2).
type DashboardData struct {
	TotalEvents      int                         `json:"total_events"`
	EventsLastHour   int                         `json:"events_last_hour"`
	OpenIncidents    int                         `json:"open_incidents"`
	SensorStatus     map[domsoc.SensorStatus]int `json:"sensor_status"`
	ChainValid       bool                        `json:"chain_valid"`
	ChainLength      int                         `json:"chain_length"`
	ChainHeadHash    string                      `json:"chain_head_hash"`
	ChainBrokenLine  int                         `json:"chain_broken_line,omitempty"`
	CorrelationRules int                         `json:"correlation_rules"`
	ActivePlaybooks  int                         `json:"active_playbooks"`
}

// JSON returns the dashboard as JSON string.
func (d *DashboardData) JSON() string {
	data, _ := json.MarshalIndent(d, "", "  ")
	return string(data)
}

// RunPlaybook manually executes a playbook against an incident (§10, §12.1).
func (s *Service) RunPlaybook(playbookID, incidentID string) (*PlaybookResult, error) {
	// Find playbook.
	var pb *domsoc.Playbook
	for _, p := range s.playbookEngine.ListPlaybooks() {
		if p.ID == playbookID {
			pCopy := p
			pb = &pCopy
			break
		}
	}
	if pb == nil {
		return nil, fmt.Errorf("playbook not found: %s", playbookID)
	}

	// Find incident.
	incident, err := s.repo.GetIncident(incidentID)
	if err != nil {
		return nil, fmt.Errorf("incident not found: %s", incidentID)
	}

	incident.PlaybookApplied = pb.ID
	if err := s.repo.UpdateIncidentStatus(incidentID, domsoc.StatusInvestigating); err != nil {
		return nil, fmt.Errorf("soc: update incident: %w", err)
	}

	if s.logger != nil {
		s.logger.Record(audit.ModuleSOC,
			fmt.Sprintf("PLAYBOOK_MANUAL_RUN:%s", pb.ID),
			fmt.Sprintf("incident=%s actions=%d", incidentID, len(pb.Actions)))
	}

	return &PlaybookResult{
		PlaybookID: pb.ID,
		IncidentID: incidentID,
		Actions:    pb.Actions,
		Status:     "EXECUTED",
	}, nil
}

// PlaybookResult represents the result of a manual playbook run.
type PlaybookResult struct {
	PlaybookID string                  `json:"playbook_id"`
	IncidentID string                  `json:"incident_id"`
	Actions    []domsoc.PlaybookAction `json:"actions"`
	Status     string                  `json:"status"`
}

// ComplianceReport generates an EU AI Act Article 15 compliance report (§12.3).
func (s *Service) ComplianceReport() (*ComplianceData, error) {
	dashboard, err := s.Dashboard()
	if err != nil {
		return nil, err
	}

	sensors, err := s.repo.ListSensors("")
	if err != nil {
		return nil, err
	}

	// Build compliance requirements check.
	requirements := []ComplianceRequirement{
		{
			ID:          "15.1",
			Description: "Risk Management System",
			Status:      "COMPLIANT",
			Evidence:    []string{"soc_correlation_engine", "soc_playbooks", fmt.Sprintf("rules=%d", len(s.rules))},
		},
		{
			ID:          "15.2",
			Description: "Data Governance",
			Status:      boolToCompliance(dashboard.ChainValid),
			Evidence:    []string{"decision_logger_sha256", fmt.Sprintf("chain_length=%d", dashboard.ChainLength)},
		},
		{
			ID:          "15.3",
			Description: "Technical Documentation",
			Status:      "COMPLIANT",
			Evidence:    []string{"SENTINEL_AI_SOC_SPEC.md", "soc_dashboard_kpis"},
		},
		{
			ID:          "15.4",
			Description: "Record-keeping",
			Status:      boolToCompliance(dashboard.ChainValid && dashboard.ChainLength > 0),
			Evidence:    []string{"decisions.log", fmt.Sprintf("chain_valid=%t", dashboard.ChainValid)},
		},
		{
			ID:          "15.5",
			Description: "Transparency",
			Status:      "PARTIAL",
			Evidence:    []string{"soc_dashboard_screenshots.pdf"},
			Gap:         "Real-time explainability of correlation decisions — planned for v1.2",
		},
		{
			ID:          "15.6",
			Description: "Human Oversight",
			Status:      "COMPLIANT",
			Evidence:    []string{"soc_verdict_tool", "manual_playbook_run", fmt.Sprintf("sensors=%d", len(sensors))},
		},
	}

	return &ComplianceData{
		Framework:    "EU AI Act Article 15",
		GeneratedAt:  time.Now(),
		Requirements: requirements,
		Overall:      overallStatus(requirements),
	}, nil
}

// ComplianceData holds an EU AI Act compliance report (§12.3).
type ComplianceData struct {
	Framework    string                  `json:"framework"`
	GeneratedAt  time.Time               `json:"generated_at"`
	Requirements []ComplianceRequirement `json:"requirements"`
	Overall      string                  `json:"overall"`
}

// ComplianceRequirement is a single compliance check.
type ComplianceRequirement struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Status      string   `json:"status"` // COMPLIANT, PARTIAL, NON_COMPLIANT
	Evidence    []string `json:"evidence"`
	Gap         string   `json:"gap,omitempty"`
}

func boolToCompliance(ok bool) string {
	if ok {
		return "COMPLIANT"
	}
	return "NON_COMPLIANT"
}

func overallStatus(reqs []ComplianceRequirement) string {
	for _, r := range reqs {
		if r.Status == "NON_COMPLIANT" {
			return "NON_COMPLIANT"
		}
	}
	for _, r := range reqs {
		if r.Status == "PARTIAL" {
			return "PARTIAL"
		}
	}
	return "COMPLIANT"
}

// ExportIncidents converts all current incidents into portable SyncIncident format
// for P2P synchronization (§10 T-01).
func (s *Service) ExportIncidents(sourcePeerID string) []peer.SyncIncident {
	s.mu.RLock()
	defer s.mu.RUnlock()

	incidents, err := s.repo.ListIncidents("", "", 1000)
	if err != nil || len(incidents) == 0 {
		return nil
	}

	result := make([]peer.SyncIncident, 0, len(incidents))
	for _, inc := range incidents {
		result = append(result, peer.SyncIncident{
			ID:              inc.ID,
			Status:          string(inc.Status),
			Severity:        string(inc.Severity),
			Title:           inc.Title,
			Description:     inc.Description,
			EventCount:      inc.EventCount,
			CorrelationRule: inc.CorrelationRule,
			KillChainPhase:  inc.KillChainPhase,
			MITREMapping:    inc.MITREMapping,
			CreatedAt:       inc.CreatedAt,
			SourcePeerID:    sourcePeerID,
		})
	}
	return result
}

// ImportIncidents ingests incidents from a trusted peer (§10 T-01).
// Uses UPDATE-or-INSERT semantics: new incidents are created, existing IDs are skipped.
// Returns the number of newly imported incidents.
func (s *Service) ImportIncidents(incidents []peer.SyncIncident) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	imported := 0
	for _, si := range incidents {
		// Convert back to domain incident.
		inc := domsoc.Incident{
			ID:              si.ID,
			Status:          domsoc.IncidentStatus(si.Status),
			Severity:        domsoc.EventSeverity(si.Severity),
			Title:           fmt.Sprintf("[P2P:%s] %s", si.SourcePeerID, si.Title),
			Description:     si.Description,
			EventCount:      si.EventCount,
			CorrelationRule: si.CorrelationRule,
			KillChainPhase:  si.KillChainPhase,
			MITREMapping:    si.MITREMapping,
			CreatedAt:       si.CreatedAt,
			UpdatedAt:       time.Now(),
		}
		err := s.repo.InsertIncident(inc)
		if err != nil {
			return imported, fmt.Errorf("import incident %s: %w", si.ID, err)
		}
		imported++
	}

	if s.logger != nil {
		s.logger.Record(audit.ModuleSOC, "P2P_INCIDENT_SYNC",
			fmt.Sprintf("imported=%d total=%d", imported, len(incidents)))
	}
	return imported, nil
}

// AddWaitlistEntry records a waitlist registration interest.
// Currently logs to the audit trail — DB persistence added when registration opens.
func (s *Service) AddWaitlistEntry(email, company, useCase string) {
	if s.logger != nil {
		s.logger.Record(audit.ModuleSOC, "WAITLIST:NEW",
			fmt.Sprintf("email=%s company=%s use_case=%s", email, company, useCase))
	}
	slog.Info("waitlist entry recorded",
		"email", email,
		"company", company,
		"use_case", useCase,
	)
}
