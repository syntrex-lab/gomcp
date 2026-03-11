// Package soc provides application services for the SENTINEL AI SOC subsystem.
package soc

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/syntrex/gomcp/internal/domain/oracle"
	"github.com/syntrex/gomcp/internal/domain/peer"
	domsoc "github.com/syntrex/gomcp/internal/domain/soc"
	"github.com/syntrex/gomcp/internal/infrastructure/audit"
	"github.com/syntrex/gomcp/internal/infrastructure/sqlite"
)

const (
	// MaxEventsPerSecondPerSensor limits event ingest rate per sensor (§17.3).
	MaxEventsPerSecondPerSensor = 100
)

// Service orchestrates the SOC event pipeline:
// Step 0: Secret Scanner (INVARIANT) → DIP → Decision Logger → Persist → Correlation.
type Service struct {
	mu        sync.RWMutex
	repo      *sqlite.SOCRepo
	logger    *audit.DecisionLogger
	rules     []domsoc.SOCCorrelationRule
	playbooks []domsoc.Playbook
	sensors   map[string]*domsoc.Sensor

	// Rate limiting per sensor (§17.3): sensorID → timestamps of recent events.
	sensorRates map[string][]time.Time

	// Sensor authentication (§17.3 T-01): sensorID → pre-shared key.
	sensorKeys map[string]string

	// SOAR webhook notifier (§P3): outbound HTTP POST on incidents.
	webhook *WebhookNotifier

	// Threat intelligence store (§P3+): IOC enrichment.
	threatIntel *ThreatIntelStore
}

// NewService creates a SOC service with persistence and decision logging.
func NewService(repo *sqlite.SOCRepo, logger *audit.DecisionLogger) *Service {
	return &Service{
		repo:        repo,
		logger:      logger,
		rules:       domsoc.DefaultSOCCorrelationRules(),
		playbooks:   domsoc.DefaultPlaybooks(),
		sensors:     make(map[string]*domsoc.Sensor),
		sensorRates: make(map[string][]time.Time),
	}
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
	// Step -1: Sensor Authentication (§17.3 T-01)
	// If sensorKeys configured, validate sensor_key before processing.
	if len(s.sensorKeys) > 0 && event.SensorID != "" {
		expected, exists := s.sensorKeys[event.SensorID]
		if !exists || expected != event.SensorKey {
			if s.logger != nil {
				s.logger.Record(audit.ModuleSOC,
					"AUTH_FAILED:REJECT",
					fmt.Sprintf("sensor_id=%s reason=invalid_key", event.SensorID))
			}
			return "", nil, fmt.Errorf("soc: sensor auth failed for %s", event.SensorID)
		}
	}

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
			return "", nil, fmt.Errorf("soc: secret scanner rejected event: %d detections found", len(scanResult.Detections))
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
		return "", nil, fmt.Errorf("soc: rate limit exceeded for sensor %s (max %d events/sec)", sensorID, MaxEventsPerSecondPerSensor)
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

	// Step 2: Persist event
	if err := s.repo.InsertEvent(event); err != nil {
		return "", nil, fmt.Errorf("soc: persist event: %w", err)
	}

	// Step 3: Update sensor registry (§11.3)
	s.updateSensor(event)

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
	if incident != nil && s.webhook != nil {
		go s.webhook.NotifyIncident("incident_created", incident)
	}

	return event.ID, incident, nil
}

// isRateLimited checks if sensor exceeds MaxEventsPerSecondPerSensor (§17.3).
func (s *Service) isRateLimited(sensorID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Second)

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
	s.repo.UpsertSensor(*sensor)
}

// correlate runs correlation rules against recent events (§7).
func (s *Service) correlate(event domsoc.SOCEvent) *domsoc.Incident {
	events, err := s.repo.ListEvents(100)
	if err != nil || len(events) < 2 {
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

	s.repo.InsertIncident(incident)
	return &incident
}

// applyPlaybooks matches playbooks against the event and incident (§10).
func (s *Service) applyPlaybooks(event domsoc.SOCEvent, incident *domsoc.Incident) {
	for _, pb := range s.playbooks {
		if pb.Matches(event) {
			incident.PlaybookApplied = pb.ID
			if s.logger != nil {
				s.logger.Record(audit.ModuleSOC,
					fmt.Sprintf("PLAYBOOK_APPLIED:%s", pb.ID),
					fmt.Sprintf("incident=%s actions=%v", incident.ID, pb.Actions))
			}
			break
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
			s.repo.UpsertSensor(*sensor)
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
	return s.repo.ListEvents(limit)
}

// ListIncidents returns incidents, optionally filtered by status.
func (s *Service) ListIncidents(status string, limit int) ([]domsoc.Incident, error) {
	return s.repo.ListIncidents(status, limit)
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

// ListSensors returns all registered sensors.
func (s *Service) ListSensors() ([]domsoc.Sensor, error) {
	return s.repo.ListSensors()
}

// Dashboard returns SOC KPI metrics.
func (s *Service) Dashboard() (*DashboardData, error) {
	totalEvents, err := s.repo.CountEvents()
	if err != nil {
		return nil, err
	}

	lastHourEvents, err := s.repo.CountEventsSince(time.Now().Add(-1 * time.Hour))
	if err != nil {
		return nil, err
	}

	openIncidents, err := s.repo.CountOpenIncidents()
	if err != nil {
		return nil, err
	}

	sensorCounts, err := s.repo.CountSensorsByStatus()
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
		ActivePlaybooks:  len(s.playbooks),
	}, nil
}

// Analytics generates a full SOC analytics report for the given time window.
func (s *Service) Analytics(windowHours int) (*AnalyticsReport, error) {
	events, err := s.repo.ListEvents(10000) // large window
	if err != nil {
		return nil, fmt.Errorf("soc: analytics events: %w", err)
	}

	incidents, err := s.repo.ListIncidents("", 1000)
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
	for i := range s.playbooks {
		if s.playbooks[i].ID == playbookID {
			pb = &s.playbooks[i]
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
			fmt.Sprintf("incident=%s actions=%v", incidentID, pb.Actions))
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

	sensors, err := s.repo.ListSensors()
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

	incidents, err := s.repo.ListIncidents("", 1000)
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
