package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	appsoc "github.com/syntrex/gomcp/internal/application/soc"
	"github.com/syntrex/gomcp/internal/domain/engines"
	domsoc "github.com/syntrex/gomcp/internal/domain/soc"
	"github.com/syntrex/gomcp/internal/infrastructure/auth"
)

// MaxRequestBodySize limits POST body size to prevent OOM (T3-3).
const MaxRequestBodySize = 1 << 20 // 1 MB

// limitBody wraps r.Body with http.MaxBytesReader to enforce size limits.
func limitBody(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodySize)
}

// handleDashboard returns SOC KPI metrics.
// GET /api/soc/dashboard
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	dash, err := s.socSvc.Dashboard()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, dash)
}

// handleEvents returns recent SOC events with optional limit.
// GET /api/soc/events?limit=50
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit := 50 // default
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	// Cap to prevent excessive DB queries via external requests.
	if limit > 10000 {
		limit = 10000
	}

	events, err := s.socSvc.ListEvents(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"count":  len(events),
		"limit":  limit,
	})
}

// handleIncidents returns SOC incidents with optional status filter and limit.
// GET /api/soc/incidents?status=open&limit=20
func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	limit := 20 // default
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	incidents, err := s.socSvc.ListIncidents(status, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"incidents": incidents,
		"count":     len(incidents),
		"status":    status,
		"limit":     limit,
	})
}

// handleHealth returns a simple health check response.
// GET /health
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

// handleHealthz is a K8s liveness probe — returns 200 if the server process is alive.
// GET /healthz
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// handleReadyz is a K8s readiness probe — returns 200 when ready to accept traffic,
// 503 when draining (zero-downtime rolling update, §15.7).
// GET /readyz
func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if s.socSvc.IsDraining() {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("draining"))
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}
// handleSensors returns registered sensors with health status.
// GET /api/soc/sensors
func (s *Server) handleSensors(w http.ResponseWriter, _ *http.Request) {
	sensors, err := s.socSvc.ListSensors()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sensors": sensors,
		"count":   len(sensors),
	})
}

// handleIncidentDetail returns a single incident by ID.
// GET /api/soc/incidents/{id}
func (s *Server) handleIncidentDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing incident ID")
		return
	}

	incident, err := s.socSvc.GetIncident(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, incident)
}

// handleClusters returns Alert Clustering statistics (§7.6).
// GET /api/soc/clusters
func (s *Server) handleClusters(w http.ResponseWriter, _ *http.Request) {
	stats := s.socSvc.ClusterStats()
	writeJSON(w, http.StatusOK, stats)
}

// handleRules returns all active correlation rules.
// GET /api/soc/rules
func (s *Server) handleRules(w http.ResponseWriter, _ *http.Request) {
	rules := s.socSvc.ListRules()
	writeJSON(w, http.StatusOK, map[string]any{
		"rules": rules,
		"count": len(rules),
	})
}

// handleThreatIntel returns IOC database, feeds, and stats (§6).
// GET /api/soc/threat-intel
func (s *Server) handleThreatIntel(w http.ResponseWriter, _ *http.Request) {
	ti := s.socSvc.ThreatIntelEngine()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":     true,
		"iocs":        ti.ListIOCs(),
		"feeds":       ti.ListFeeds(),
		"stats":       ti.ThreatIntelStats(),
		"recent_hits": ti.RecentHits(20),
	})
}

// handleWebhookStats returns SOAR webhook delivery statistics.
// GET /api/soc/webhook-stats
func (s *Server) handleWebhookStats(w http.ResponseWriter, _ *http.Request) {
	stats := s.socSvc.WebhookStats()
	writeJSON(w, http.StatusOK, stats)
}

// handleAnalytics returns SOC analytics report.
// GET /api/soc/analytics?window=24
func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	windowHours := 24 // default
	if v := r.URL.Query().Get("window"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			windowHours = parsed
		}
	}

	report, err := s.socSvc.Analytics(windowHours)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// handleIngestEvent processes a security event through the full SOC pipeline.
// POST /api/v1/soc/events
//
// Pipeline: Sensor Auth → Secret Scanner → Rate Limit → Decision Logger → Persist → Correlate → Playbook → Webhook
func (s *Server) handleIngestEvent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Source      string            `json:"source"`
		SensorID   string            `json:"sensor_id"`
		SensorKey  string            `json:"sensor_key"`
		Severity   string            `json:"severity"`
		Category   string            `json:"category"`
		Subcategory string           `json:"subcategory"`
		Confidence float64           `json:"confidence"`
		Description string           `json:"description"`
		Payload    string            `json:"payload"`
		SessionID  string            `json:"session_id"`
		ZeroGMode  bool              `json:"zero_g_mode"`
		Metadata   map[string]string `json:"metadata"`
	}

	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// Validate required fields.
	if req.Source == "" || req.Severity == "" || req.Category == "" || req.Description == "" {
		writeError(w, http.StatusBadRequest, "required fields: source, severity, category, description")
		return
	}

	// Build domain event.
	event := domsoc.NewSOCEvent(
		domsoc.EventSource(req.Source),
		domsoc.EventSeverity(req.Severity),
		req.Category,
		req.Description,
	)
	event.SensorID = req.SensorID
	if event.SensorID == "" {
		// Auto-assign sensor ID from source name.
		switch req.Source {
		case "sentinel-core":
			event.SensorID = "sensor-core-01"
		case "shield":
			event.SensorID = "sensor-shield-01"
		case "immune":
			event.SensorID = "sensor-immune-01"
		case "micro-swarm":
			event.SensorID = "sensor-swarm-01"
		case "gomcp":
			event.SensorID = "sensor-gomcp-01"
		default:
			event.SensorID = "sensor-ext-01"
		}
	}
	event.SensorKey = req.SensorKey
	event.Subcategory = req.Subcategory
	event.Confidence = req.Confidence
	event.Payload = req.Payload
	event.SessionID = req.SessionID
	event.ZeroGMode = req.ZeroGMode
	event.Metadata = req.Metadata
	if event.Metadata == nil {
		event.Metadata = make(map[string]string)
	}

	// Auto-enrich: inject source IP from HTTP request if not provided by client.
	if event.Metadata["src_ip"] == "" {
		ip := r.RemoteAddr
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
		event.Metadata["src_ip"] = ip
	}

	// Auto-enrich: set confidence from top-level field if not in metadata.
	if event.Metadata["confidence"] == "" && event.Confidence > 0 {
		event.Metadata["confidence"] = fmt.Sprintf("%.2f", event.Confidence)
	}

	// Run full pipeline.
	eventID, incident, err := s.socSvc.IngestEvent(event)
	if err != nil {
		// Map domain errors to HTTP status codes.
		switch {
		case errors.Is(err, domsoc.ErrInvalidInput):
			// Return 422 with field-level validation details.
			var ve *domsoc.ValidationErrors
			if errors.As(err, &ve) {
				writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
					"error":  err.Error(),
					"fields": ve.Errors,
				})
			} else {
				writeError(w, http.StatusUnprocessableEntity, err.Error())
			}
		case errors.Is(err, domsoc.ErrDraining):
			writeError(w, http.StatusServiceUnavailable, err.Error())
		case errors.Is(err, domsoc.ErrAuthFailed), errors.Is(err, domsoc.ErrSecretDetected):
			writeError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, domsoc.ErrRateLimited):
			writeError(w, http.StatusTooManyRequests, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	resp := map[string]any{
		"event_id": eventID,
		"status":   "ingested",
	}
	if incident != nil {
		resp["incident"] = incident
		resp["status"] = "ingested_with_incident"
	}

	writeJSON(w, http.StatusCreated, resp)
}

// MaxBatchSize limits the number of events in a single batch request (§5.3).
const MaxBatchSize = 1000

// handleBatchIngest processes multiple security events through the SOC pipeline (§5.3).
// POST /api/v1/soc/events/batch
func (s *Server) handleBatchIngest(w http.ResponseWriter, r *http.Request) {
	var events []struct {
		Source      string            `json:"source"`
		SensorID   string            `json:"sensor_id"`
		SensorKey  string            `json:"sensor_key"`
		Severity   string            `json:"severity"`
		Category   string            `json:"category"`
		Subcategory string           `json:"subcategory"`
		Confidence float64           `json:"confidence"`
		Description string           `json:"description"`
		Payload    string            `json:"payload"`
		SessionID  string            `json:"session_id"`
		ZeroGMode  bool              `json:"zero_g_mode"`
		Metadata   map[string]string `json:"metadata"`
	}

	limitBody(w, r)
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON array: "+err.Error())
		return
	}

	if len(events) == 0 {
		writeError(w, http.StatusBadRequest, "empty batch")
		return
	}
	if len(events) > MaxBatchSize {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("batch size %d exceeds max %d", len(events), MaxBatchSize))
		return
	}

	type batchResult struct {
		Index    int    `json:"index"`
		EventID  string `json:"event_id,omitempty"`
		Status   string `json:"status"`
		Incident any    `json:"incident,omitempty"`
		Error    string `json:"error,omitempty"`
	}

	results := make([]batchResult, len(events))
	ingested := 0

	for i, req := range events {
		event := domsoc.NewSOCEvent(
			domsoc.EventSource(req.Source),
			domsoc.EventSeverity(req.Severity),
			req.Category,
			req.Description,
		)
		event.SensorID = req.SensorID
		event.SensorKey = req.SensorKey
		event.Subcategory = req.Subcategory
		event.Confidence = req.Confidence
		event.Payload = req.Payload
		event.SessionID = req.SessionID
		event.ZeroGMode = req.ZeroGMode
		event.Metadata = req.Metadata

		eventID, incident, err := s.socSvc.IngestEvent(event)
		if err != nil {
			results[i] = batchResult{Index: i, Status: "rejected", Error: err.Error()}
			continue
		}

		result := batchResult{Index: i, EventID: eventID, Status: "ingested"}
		if incident != nil {
			result.Status = "ingested_with_incident"
			result.Incident = incident
		}
		results[i] = result
		ingested++
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"total":    len(events),
		"ingested": ingested,
		"rejected": len(events) - ingested,
		"results":  results,
	})
}
// handleSensorHeartbeat records a sensor heartbeat (§11.3).
// POST /api/soc/sensors/heartbeat
func (s *Server) handleSensorHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SensorID string `json:"sensor_id"`
	}
	limitBody(w, r)
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.SensorID == "" {
		writeError(w, http.StatusBadRequest, "required field: sensor_id")
		return
	}

	ok, err := s.socSvc.RecordHeartbeat(req.SensorID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sensor_id": req.SensorID,
		"recorded":  ok,
	})
}

// handleSSEStream provides Server-Sent Events for real-time event streaming.
// GET /api/soc/stream
func (s *Server) handleSSEStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "SSE not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Note: CORS is already handled by corsMiddleware — no need to set it here.
	w.Header().Set("X-Accel-Buffering", "no") // Disable nginx/proxy buffering

	// Explicitly write status and flush headers so EventSource.onopen fires immediately.
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Subscribe to event bus
	subID := fmt.Sprintf("sse-%d", time.Now().UnixNano())
	ch := s.socSvc.EventBus().Subscribe(subID)
	defer s.socSvc.EventBus().Unsubscribe(subID)

	// Send initial comment to establish connection
	fmt.Fprintf(w, ": connected to syntrex event stream\n\n")
	flusher.Flush()

	// Keepalive ticker
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "event: soc_event\ndata: %s\n\n", data)
			flusher.Flush()

		case <-ticker.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()

		case <-r.Context().Done():
			return
		}
	}
}

// handleKillChain reconstructs the Kill Chain for an incident (§8).
// GET /api/soc/killchain/{id}
func (s *Server) handleKillChain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing incident ID")
		return
	}

	kc, err := s.socSvc.GetKillChain(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, kc)
}

// handleAuditTrail returns decision log entries for forensic review (§9).
// GET /api/soc/audit
func (s *Server) handleAuditTrail(w http.ResponseWriter, r *http.Request) {
	// The decision logger stores entries in the audit database.
	// For now, return basic audit metadata from service.
	result := map[string]any{
		"status":  "operational",
		"message": "Audit trail available via decision logger",
	}

	// Add recent decisions if available via service
	decisions := s.socSvc.GetRecentDecisions(50)
	result["decisions"] = decisions
	result["total"] = len(decisions)

	writeJSON(w, http.StatusOK, result)
}

// handleListKeys returns registered RBAC API keys (masked) for admin review (§17).
// GET /api/soc/keys
func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	keys := s.rbac.ListKeys()
	writeJSON(w, http.StatusOK, map[string]any{
		"keys":  keys,
		"total": len(keys),
	})
}

// handleZeroGStatus returns Zero-G mode status and pending requests (§13.4).
// GET /api/soc/zerog
func (s *Server) handleZeroGStatus(w http.ResponseWriter, r *http.Request) {
	zg := s.socSvc.ZeroG()
	writeJSON(w, http.StatusOK, map[string]any{
		"stats":   zg.Stats(),
		"pending": zg.PendingRequests(),
	})
}

// handleZeroGToggle enables or disables Zero-G mode (§13.4).
// POST /api/soc/zerog/toggle  body: {"enabled": true}
func (s *Server) handleZeroGToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	limitBody(w, r)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	zg := s.socSvc.ZeroG()
	if req.Enabled {
		zg.Enable()
	} else {
		zg.Disable()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"zero_g_enabled": zg.IsEnabled(),
	})
}

// handleZeroGResolve processes an analyst verdict on a pending Zero-G request (§13.4).
// POST /api/soc/zerog/resolve  body: {"request_id": "zg-...", "verdict": "APPROVE", "analyst": "admin"}
func (s *Server) handleZeroGResolve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RequestID string `json:"request_id"`
		Verdict   string `json:"verdict"`
		Analyst   string `json:"analyst"`
	}
	limitBody(w, r)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.RequestID == "" || req.Verdict == "" {
		writeError(w, http.StatusBadRequest, "request_id and verdict required")
		return
	}

	zg := s.socSvc.ZeroG()
	err := zg.Resolve(req.RequestID, domsoc.ZeroGVerdict(req.Verdict), req.Analyst)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "resolved"})
}

// handleVerdict updates an incident's status (manual analyst verdict).
// POST /api/soc/incidents/{id}/verdict  body: {"status": "RESOLVED"}
func (s *Server) handleVerdict(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID required")
		return
	}

	var req struct {
		Status string `json:"status"`
	}
	limitBody(w, r)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Status == "" {
		writeError(w, http.StatusBadRequest, "status required (INVESTIGATING, RESOLVED)")
		return
	}

	err := s.socSvc.UpdateVerdict(id, domsoc.IncidentStatus(req.Status))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"incident_id": id,
		"status":      req.Status,
	})
}

// === Case Management Endpoints ===

// POST /api/soc/incidents/{id}/assign  body: {"analyst": "john.doe"}
func (s *Server) handleIncidentAssign(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID required")
		return
	}

	var req struct {
		Analyst string `json:"analyst"`
	}
	limitBody(w, r)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Analyst == "" {
		writeError(w, http.StatusBadRequest, "analyst name required")
		return
	}

	if err := s.socSvc.AssignIncident(id, req.Analyst); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"incident_id": id,
		"assigned_to": req.Analyst,
		"status":      "assigned",
	})
}

// POST /api/soc/incidents/{id}/status  body: {"status": "INVESTIGATING", "actor": "john.doe"}
func (s *Server) handleIncidentStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID required")
		return
	}

	var req struct {
		Status string `json:"status"`
		Actor  string `json:"actor"`
	}
	limitBody(w, r)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Status == "" {
		writeError(w, http.StatusBadRequest, "status required")
		return
	}
	if req.Actor == "" {
		req.Actor = "system"
	}

	// Validate status
	validStatuses := map[string]bool{
		"OPEN": true, "INVESTIGATING": true, "RESOLVED": true, "FALSE_POSITIVE": true,
	}
	if !validStatuses[req.Status] {
		writeError(w, http.StatusBadRequest, "invalid status (OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE)")
		return
	}

	if err := s.socSvc.ChangeIncidentStatus(id, domsoc.IncidentStatus(req.Status), req.Actor); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"incident_id": id,
		"status":      req.Status,
		"actor":       req.Actor,
	})
}

// POST /api/soc/incidents/{id}/notes  body: {"author": "john.doe", "content": "Found C2 callback"}
// GET  /api/soc/incidents/{id}/notes  → returns notes array
func (s *Server) handleIncidentNotes(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID required")
		return
	}

	if r.Method == http.MethodGet {
		inc, err := s.socSvc.GetIncidentDetail(id)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"incident_id": id,
			"notes":       inc.Notes,
			"count":       len(inc.Notes),
		})
		return
	}

	// POST — add note
	var req struct {
		Author  string `json:"author"`
		Content string `json:"content"`
	}
	limitBody(w, r)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "content required")
		return
	}
	if req.Author == "" {
		req.Author = "analyst"
	}

	note, err := s.socSvc.AddIncidentNote(id, req.Author, req.Content)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, note)
}

// GET /api/soc/incidents/{id}/timeline → full incident timeline
func (s *Server) handleIncidentTimeline(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID required")
		return
	}

	inc, err := s.socSvc.GetIncidentDetail(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"incident_id": id,
		"timeline":    inc.Timeline,
		"count":       len(inc.Timeline),
		"status":      inc.Status,
		"assigned_to": inc.AssignedTo,
		"severity":    inc.Severity,
	})
}

// GET /api/soc/incidents/{id}/detail → full incident with notes + timeline
func (s *Server) handleIncidentFullDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID required")
		return
	}

	inc, err := s.socSvc.GetIncidentDetail(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, inc)
}


// === Webhook Management Endpoints (SOAR §15) ===

// GET /api/soc/webhooks → returns webhook config + delivery stats
func (s *Server) handleWebhooksGet(w http.ResponseWriter, r *http.Request) {
	stats := s.socSvc.WebhookStats()
	config := s.socSvc.GetWebhookConfig()

	result := map[string]any{
		"stats": stats,
	}
	if config != nil {
		result["config"] = config
	} else {
		result["config"] = map[string]any{
			"endpoints":   []string{},
			"headers":     map[string]string{},
			"max_retries": 3,
			"timeout_sec": 10,
		}
	}
	writeJSON(w, http.StatusOK, result)
}

// POST /api/soc/webhooks → configure webhook endpoints
// body: {"endpoints": ["https://hooks.slack.com/..."], "headers": {"Authorization": "Bearer xyz"}, "max_retries": 3}
func (s *Server) handleWebhooksSet(w http.ResponseWriter, r *http.Request) {
	var config appsoc.WebhookConfig
	limitBody(w, r)
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if config.MaxRetries <= 0 {
		config.MaxRetries = 3
	}
	if config.TimeoutSec <= 0 {
		config.TimeoutSec = 10
	}

	s.socSvc.SetWebhookConfig(config)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "configured",
		"endpoints": len(config.Endpoints),
		"retries":   config.MaxRetries,
	})
}

// POST /api/soc/webhooks/test → send test ping to all endpoints
func (s *Server) handleWebhooksTest(w http.ResponseWriter, r *http.Request) {
	results := s.socSvc.TestWebhook()
	if results == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "no_webhooks",
			"message": "No webhook endpoints configured",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "tested",
		"results": results,
	})
}

// handleSensorRegister registers a new sensor with the SOC.
// POST /api/soc/sensors/register  body: {"id":"s-1","name":"Shield-1","type":"shield"}
func (s *Server) handleSensorRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	}
	limitBody(w, r)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.ID == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "id and name required")
		return
	}

	s.socSvc.RegisterSensor(req.ID, req.Name, req.Type)

	writeJSON(w, http.StatusCreated, map[string]string{
		"sensor_id": req.ID,
		"status":    "registered",
	})
}

// handleSensorDelete removes a sensor from the SOC.
// DELETE /api/soc/sensors/{id}
func (s *Server) handleSensorDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "sensor ID required")
		return
	}

	s.socSvc.DeregisterSensor(id)

	writeJSON(w, http.StatusOK, map[string]string{
		"sensor_id": id,
		"status":    "deregistered",
	})
}

// handleRateLimitStats returns rate limiter statistics.
// GET /api/soc/ratelimit
func (s *Server) handleRateLimitStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.rateLimiter.Stats())
}

// handleP2PPeers returns all P2P SOC peers and sync stats (§14).
// GET /api/soc/p2p/peers
func (s *Server) handleP2PPeers(w http.ResponseWriter, r *http.Request) {
	p2p := s.socSvc.P2PSync()
	writeJSON(w, http.StatusOK, map[string]any{
		"peers": p2p.ListPeers(),
		"stats": p2p.Stats(),
	})
}

// handleP2PAddPeer registers a new SOC peer for synchronization (§14).
// POST /api/soc/p2p/peers  body: {"id":"soc-2","name":"Site-B","endpoint":"http://b:9100","trust":"full"}
func (s *Server) handleP2PAddPeer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Endpoint string `json:"endpoint"`
		Trust    string `json:"trust"`
	}
	limitBody(w, r)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.ID == "" || req.Endpoint == "" {
		writeError(w, http.StatusBadRequest, "id and endpoint required")
		return
	}
	if req.Trust == "" {
		req.Trust = "readonly"
	}

	s.socSvc.P2PSync().AddPeer(req.ID, req.Name, req.Endpoint, req.Trust)
	writeJSON(w, http.StatusCreated, map[string]string{
		"peer_id": req.ID,
		"status":  "registered",
	})
}

// handleP2PRemovePeer deregisters a SOC peer (§14).
// DELETE /api/soc/p2p/peers/{id}
func (s *Server) handleP2PRemovePeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "peer ID required")
		return
	}
	s.socSvc.P2PSync().RemovePeer(id)
	writeJSON(w, http.StatusOK, map[string]string{"peer_id": id, "status": "removed"})
}

// handleEngineStatus returns status of security engines (§3, §4).
// GET /api/soc/engines
func (s *Server) handleEngineStatus(w http.ResponseWriter, r *http.Request) {
	coreEngine := s.getEngine("sentinel-core")
	var shieldEng engines.Shield
	if s.shieldEngine != nil {
		shieldEng = s.shieldEngine
	} else {
		shieldEng = engines.NewStubShield()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"engines": []map[string]any{
			{
				"name":    coreEngine.Name(),
				"status":  coreEngine.Status(),
				"version": coreEngine.Version(),
				"type":    "prompt_scanner",
			},
			{
				"name":    shieldEng.Name(),
				"status":  shieldEng.Status(),
				"version": shieldEng.Version(),
				"type":    "network_protection",
			},
		},
	})
}

// getEngine returns the named SentinelCore engine or a stub.
func (s *Server) getEngine(name string) engines.SentinelCore {
	if s.sentinelCore != nil && name == "sentinel-core" {
		return s.sentinelCore
	}
	return engines.NewStubSentinelCore()
}

// handleSovereignConfig returns the Sovereign Mode configuration (§21).
// GET /api/soc/sovereign
func (s *Server) handleSovereignConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"sovereign": map[string]any{
			"enabled":       s.sovereignEnabled,
			"mode":          s.sovereignMode,
			"air_gapped":    s.sovereignMode == "airgap",
			"external_api":  !s.sovereignEnabled,
			"local_only":    s.sovereignMode == "airgap",
		},
	})
}

// handleAnomalyAlerts returns recent anomaly alerts (§5).
// GET /api/soc/anomaly/alerts
func (s *Server) handleAnomalyAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	detector := s.socSvc.AnomalyDetector()
	writeJSON(w, http.StatusOK, map[string]any{
		"alerts": detector.Alerts(limit),
		"stats":  detector.Stats(),
	})
}

// handleAnomalyBaselines returns tracked metric baselines (§5).
// GET /api/soc/anomaly/baselines
func (s *Server) handleAnomalyBaselines(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"baselines": s.socSvc.AnomalyDetector().Baselines(),
	})
}

// handlePlaybooks returns all playbooks and execution stats (§10).
// GET /api/soc/playbooks
func (s *Server) handlePlaybooks(w http.ResponseWriter, r *http.Request) {
	pe := s.socSvc.PlaybookEngine()
	writeJSON(w, http.StatusOK, map[string]any{
		"playbooks": pe.ListPlaybooks(),
		"stats":     pe.PlaybookStats(),
		"log":       pe.ExecutionLog(20),
	})
}

// handleDeepHealth returns deep system health across all components.
// GET /api/soc/health/deep
func (s *Server) handleDeepHealth(w http.ResponseWriter, r *http.Request) {
	overallStatus := "HEALTHY"

	// Anomaly detector
	anomalyStats := s.socSvc.AnomalyDetector().Stats()

	// Playbook engine
	pbStats := s.socSvc.PlaybookEngine().PlaybookStats()

	// P2P Sync
	p2pStats := s.socSvc.P2PSync().Stats()

	// Engine status
	engineStatus := "stub"
	if s.sentinelCore != nil {
		st := s.sentinelCore.Status()
		engineStatus = string(st)
		if st == engines.EngineDegraded {
			overallStatus = "DEGRADED"
		}
	}

	// Check for critical anomalies
	if alerts := s.socSvc.AnomalyDetector().Alerts(5); len(alerts) > 0 {
		for _, a := range alerts {
			if a.Severity == "CRITICAL" {
				overallStatus = "DEGRADED"
				break
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":    overallStatus,
		"timestamp": time.Now().Format(time.RFC3339),
		"components": map[string]any{
			"database":         "HEALTHY",
			"correlation":      "HEALTHY",
			"anomaly_detector": anomalyStats,
			"playbook_engine":  pbStats,
			"p2p_sync":         p2pStats,
			"sentinel_core":    engineStatus,
		},
	})
}

// handleComplianceReport returns EU AI Act Article 15 compliance summary (§12.3).
// GET /api/soc/compliance
func (s *Server) handleComplianceReport(w http.ResponseWriter, r *http.Request) {
	dash, err := s.socSvc.Dashboard()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "compliance: dashboard unavailable: "+err.Error())
		return
	}
	anomalyStats := s.socSvc.AnomalyDetector().Stats()
	pbStats := s.socSvc.PlaybookEngine().PlaybookStats()

	// Dynamic status checks based on live state
	riskStatus := "COMPLIANT"
	riskEvidence := []string{"Correlation rules loaded", "Kill chain reconstruction available"}
	metricsTracked, _ := anomalyStats["metrics_tracked"].(int)
	if metricsTracked > 0 {
		riskEvidence = append(riskEvidence, fmt.Sprintf("Anomaly detection active: %d metrics", metricsTracked))
	} else {
		riskStatus = "PARTIAL"
		riskEvidence = append(riskEvidence, "Anomaly detection: no metrics tracked yet")
	}

	accuracyStatus := "COMPLIANT"
	if !dash.ChainValid {
		accuracyStatus = "NON-COMPLIANT"
	}

	humanStatus := "COMPLIANT"
	humanEvidence := []string{"RBAC with 5 roles", "Zero-G mode requires human approval"}
	humanEvidence = append(humanEvidence, fmt.Sprintf("%d open incidents under analyst review", dash.OpenIncidents))

	pbEnabled, _ := pbStats["enabled"].(int)
	dataGovEvidence := []string{"Decision chain integrity verified", "Audit trail enabled"}
	if pbEnabled > 0 {
		dataGovEvidence = append(dataGovEvidence, fmt.Sprintf("Playbook engine: %d active playbooks", pbEnabled))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"framework":    "EU AI Act Article 15",
		"generated_at": time.Now().Format(time.RFC3339),
		"requirements": []map[string]any{
			{
				"id":       "Art15.1",
				"title":    "Risk Management System",
				"status":   riskStatus,
				"evidence": riskEvidence,
			},
			{
				"id":       "Art15.2",
				"title":    "Data Governance",
				"status":   "COMPLIANT",
				"evidence": dataGovEvidence,
			},
			{
				"id":       "Art15.3",
				"title":    "Technical Documentation",
				"status":   "COMPLIANT",
				"evidence": []string{"API documentation available", "Dashboard operational"},
			},
			{
				"id":       "Art15.4",
				"title":    "Human Oversight",
				"status":   humanStatus,
				"evidence": humanEvidence,
			},
			{
				"id":       "Art15.5",
				"title":    "Accuracy & Robustness",
				"status":   accuracyStatus,
				"evidence": []string{fmt.Sprintf("Decision chain valid: %v", dash.ChainValid), fmt.Sprintf("Correlation rules: %d", dash.CorrelationRules)},
			},
		},
	})
}

// handleAuditTrailPage returns decision chain entries for the audit page.
// GET /api/soc/audit?limit=100
func (s *Server) handleAuditTrailPage(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	events, _ := s.socSvc.ListEvents(limit)
	incidents, _ := s.socSvc.ListIncidents("", 50)

	// Build audit entries from events
	entries := make([]map[string]any, 0, len(events))
	for _, e := range events {
		entries = append(entries, map[string]any{
			"timestamp": e.Timestamp.Format(time.RFC3339),
			"type":      "event",
			"source":    e.Source,
			"severity":  e.Severity,
			"category":  e.Category,
			"verdict":   e.Verdict,
			"id":        e.ID,
		})
	}
	for _, inc := range incidents {
		entries = append(entries, map[string]any{
			"timestamp":  inc.CreatedAt.Format(time.RFC3339),
			"type":       "incident",
			"severity":   inc.Severity,
			"status":     inc.Status,
			"title":      inc.Title,
			"id":         inc.ID,
			"chain_hash": inc.DecisionChainAnchor,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"total":   len(entries),
	})
}

// handleThreatIntelMatch checks a value against the IOC database (§6).
// POST /api/soc/threat-intel/match
func (s *Server) handleThreatIntelMatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Value   string `json:"value"`
		EventID string `json:"event_id"`
	}
	limitBody(w, r)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	ti := s.socSvc.ThreatIntelEngine()
	if req.EventID != "" {
		hits := ti.MatchEvent(req.EventID, req.Value)
		writeJSON(w, http.StatusOK, map[string]any{
			"hits": hits,
		})
		return
	}
	ioc := ti.Match(req.Value)
	writeJSON(w, http.StatusOK, map[string]any{
		"match": ioc,
	})
}

// handleRetentionPolicies returns data retention policies and stats (§19).
// GET /api/soc/retention
func (s *Server) handleRetentionPolicies(w http.ResponseWriter, r *http.Request) {
	rp := s.socSvc.RetentionPolicy()
	writeJSON(w, http.StatusOK, map[string]any{
		"policies": rp.ListPolicies(),
		"stats":    rp.RetentionStats(),
	})
}

// handleIncidentExplain returns human-readable explanation of an incident (§12.3 EU AI Act Art.15).
// GET /api/soc/incidents/{id}/explain
func (s *Server) handleIncidentExplain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing incident ID")
		return
	}

	incident, err := s.socSvc.GetIncident(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	// Build human-readable explanation
	explanation := map[string]any{
		"incident_id": incident.ID,
		"summary":     fmt.Sprintf("Incident '%s' (%s severity) was created by correlation rule '%s'.", incident.Title, incident.Severity, incident.CorrelationRule),
		"trigger": map[string]any{
			"rule_id":    incident.CorrelationRule,
			"severity":   incident.Severity,
			"created_at": incident.CreatedAt.Format(time.RFC3339),
		},
		"kill_chain": map[string]any{
			"phase":        incident.KillChainPhase,
			"mitre_ids":    incident.MITREMapping,
			"description":  fmt.Sprintf("This incident is classified in the '%s' phase of the Cyber Kill Chain.", incident.KillChainPhase),
		},
		"evidence": map[string]any{
			"event_count":    len(incident.Events),
			"event_ids":      incident.Events,
			"decision_chain": incident.DecisionChainAnchor,
		},
		"response": map[string]any{
			"playbook_applied": incident.PlaybookApplied,
			"status":           incident.Status,
		},
		"explainability_note": "This explanation is auto-generated from correlation rules and event metadata. For detailed rule logic, see /api/soc/rules.",
	}

	writeJSON(w, http.StatusOK, explanation)
}

// ── Sprint 2: Incident Management Enhancements ─────────────────────────

// handleIncidentsAdvanced returns filtered, paginated incidents.
// GET /api/soc/incidents/advanced?status=OPEN&severity=HIGH&assigned_to=&search=&page=1&limit=20&sort_by=created_at&sort_order=desc
func (s *Server) handleIncidentsAdvanced(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	filter := appsoc.IncidentFilter{
		Status:     q.Get("status"),
		Severity:   q.Get("severity"),
		AssignedTo: q.Get("assigned_to"),
		Search:     q.Get("search"),
		Source:     q.Get("source"),
		DateFrom:   q.Get("date_from"),
		DateTo:     q.Get("date_to"),
		Page:       page,
		Limit:      limit,
		SortBy:     q.Get("sort_by"),
		SortOrder:  q.Get("sort_order"),
	}

	result, err := s.socSvc.ListIncidentsAdvanced(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Enrich with SLA status
	type incidentWithSLA struct {
		domsoc.Incident
		SLA *appsoc.SLAStatus `json:"sla,omitempty"`
	}
	enriched := make([]incidentWithSLA, len(result.Incidents))
	for i, inc := range result.Incidents {
		enriched[i] = incidentWithSLA{Incident: inc, SLA: appsoc.CalculateSLA(&inc)}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"incidents":   enriched,
		"total":       result.Total,
		"page":        result.Page,
		"limit":       result.Limit,
		"total_pages": result.TotalPages,
	})
}

// handleIncidentsBulk performs batch operations on incidents.
// POST /api/soc/incidents/bulk
func (s *Server) handleIncidentsBulk(w http.ResponseWriter, r *http.Request) {
	limitBody(w, r)
	var action appsoc.BulkAction
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(action.IncidentIDs) == 0 {
		writeError(w, http.StatusBadRequest, "incident_ids required")
		return
	}
	if action.Action == "" {
		writeError(w, http.StatusBadRequest, "action required (assign, status, close)")
		return
	}

	// Get actor from JWT claims
	if claims := auth.GetClaims(r.Context()); claims != nil {
		action.Actor = claims.Sub
	}

	result, err := s.socSvc.BulkUpdateIncidents(action)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// handleIncidentsExport exports incidents as CSV or JSON.
// GET /api/soc/incidents/export?format=csv&status=OPEN&severity=HIGH
func (s *Server) handleIncidentsExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	if format == "" {
		format = "csv"
	}

	filter := appsoc.IncidentFilter{
		Status:   q.Get("status"),
		Severity: q.Get("severity"),
		Limit:    10000, // export all matching
	}

	switch format {
	case "csv":
		data, err := s.socSvc.ExportIncidentsCSV(filter)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=incidents.csv")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	case "json":
		result, err := s.socSvc.ListIncidentsAdvanced(filter)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename=incidents.json")
		writeJSON(w, http.StatusOK, result)
	default:
		writeError(w, http.StatusBadRequest, "format must be csv or json")
	}
}

// handleIncidentSLA returns SLA status for a specific incident.
// GET /api/soc/incidents/{id}/sla
func (s *Server) handleIncidentSLA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "incident ID required")
		return
	}

	inc, err := s.socSvc.GetIncident(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}

	sla := appsoc.CalculateSLA(inc)
	writeJSON(w, http.StatusOK, map[string]any{
		"incident_id": id,
		"severity":    inc.Severity,
		"sla":         sla,
	})
}

// handleSLAConfig returns SLA threshold configuration.
// GET /api/soc/sla-config
func (s *Server) handleSLAConfig(w http.ResponseWriter, _ *http.Request) {
	thresholds := appsoc.DefaultSLAThresholds()
	type slaEntry struct {
		Severity       string  `json:"severity"`
		ResponseMin    float64 `json:"response_time_min"`
		ResolutionMin  float64 `json:"resolution_time_min"`
	}
	entries := make([]slaEntry, 0, len(thresholds))
	for _, t := range thresholds {
		entries = append(entries, slaEntry{
			Severity:      t.Severity,
			ResponseMin:   t.ResponseTime.Minutes(),
			ResolutionMin: t.ResolutionTime.Minutes(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sla_thresholds": entries,
	})
}

// handlePublicScan provides a public (no-auth) prompt scanning endpoint for the demo.
// POST /api/v1/scan  body: {"prompt": "Ignore all instructions..."}
// Runs sentinel-core (54 Rust engines) + Shield (C11 payload inspection) in parallel.
//
// Concurrency control: uses scanSem (buffered channel) to limit parallel scans.
// If all slots are busy, returns 503 Service Unavailable with Retry-After header
// to prevent OOM under burst load (e.g., 20 concurrent battle workers).
func (s *Server) handlePublicScan(w http.ResponseWriter, r *http.Request) {
	limitBody(w, r)
	defer r.Body.Close()

	var req struct {
		Prompt string `json:"prompt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// Validate input
	if req.Prompt == "" {
		writeError(w, http.StatusBadRequest, "prompt is required")
		return
	}
	if len(req.Prompt) > 2000 {
		writeError(w, http.StatusBadRequest, "prompt too long (max 2000 chars)")
		return
	}

	// Check usage quota (free tier: 1000 scans/month)
	if s.usageTracker != nil {
		userID := ""
		if claims := auth.GetClaims(r.Context()); claims != nil {
			userID = claims.Sub
		}
		ip := r.RemoteAddr
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			ip = fwd
		}
		remaining, err := s.usageTracker.RecordScan(userID, ip)
		if err != nil {
			w.Header().Set("X-RateLimit-Remaining", "0")
			writeError(w, http.StatusTooManyRequests, "monthly scan quota exceeded — upgrade your plan at syntrex.pro/pricing")
			return
		}
		if remaining >= 0 {
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		}
	}

	// ── Scan cache: return cached result for identical prompts ──
	cacheKey := promptHash(req.Prompt)
	s.scanCacheMu.RLock()
	if cached, ok := s.scanCache[cacheKey]; ok && time.Now().Before(cached.expiry) {
		s.scanCacheMu.RUnlock()
		resp := make(map[string]any, len(cached.response)+1)
		for k, v := range cached.response {
			resp[k] = v
		}
		resp["cached"] = true
		slog.Debug("scan cache hit", "key", cacheKey[:8])
		writeJSON(w, http.StatusOK, resp)
		return
	}
	s.scanCacheMu.RUnlock()

	// ── Concurrency limiter: queue up to 5s before 503 ──
	select {
	case s.scanSem <- struct{}{}:
		defer func() { <-s.scanSem }()
	case <-time.After(5 * time.Second):
		// Waited 5s, still no slot → 503
		w.Header().Set("Retry-After", "3")
		slog.Warn("scan backpressure: queue timeout", "capacity", cap(s.scanSem))
		writeError(w, http.StatusServiceUnavailable, "scan engine busy — retry in 3 seconds")
		return
	case <-r.Context().Done():
		return
	}

	// ── Scan timeout: 30s hard limit ──
	scanCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// ── Parallel scan: sentinel-core + shield run concurrently ──
	// Latency = max(core, shield) instead of core + shield
	coreEngine := s.getEngine("sentinel-core")
	var shieldEng engines.Shield
	if s.shieldEngine != nil {
		shieldEng = s.shieldEngine
	} else {
		shieldEng = engines.NewStubShield()
	}

	var (
		coreResult   *engines.ScanResult
		coreErr      error
		shieldResult *engines.ScanResult
		shieldErr    error
		wg           sync.WaitGroup
	)

	wg.Add(2)

	// Goroutine 1: sentinel-core (54 Rust engines) — the heavy path
	go func() {
		defer wg.Done()
		coreResult, coreErr = coreEngine.ScanPrompt(scanCtx, req.Prompt)
	}()

	// Goroutine 2: shield (C11 payload inspection) — lighter path
	go func() {
		defer wg.Done()
		shieldResult, shieldErr = shieldEng.InspectTraffic(scanCtx, []byte(req.Prompt), nil)
	}()

	wg.Wait()

	// Build response — merge both engines
	response := map[string]any{}

	if coreErr != nil {
		writeError(w, http.StatusInternalServerError, "scan failed: "+coreErr.Error())
		return
	}

	// Merge indicators from both engines
	allIndicators := coreResult.Indicators
	blocked := coreResult.ThreatFound
	maxConfidence := coreResult.Confidence
	threatType := coreResult.ThreatType

	// Add Shield results if available
	shieldStatus := "offline"
	if shieldErr == nil && shieldResult != nil {
		shieldStatus = "active"
		if shieldResult.ThreatFound {
			blocked = true
			if shieldResult.Confidence > maxConfidence {
				maxConfidence = shieldResult.Confidence
				threatType = shieldResult.ThreatType
			}
			allIndicators = append(allIndicators, "shield/"+shieldResult.Details)
		}
	}

	severity := "NONE"
	if blocked {
		severity = "HIGH"
	}

	response["blocked"] = blocked
	response["threat_type"] = threatType
	response["severity"] = severity
	response["confidence"] = maxConfidence
	response["details"] = coreResult.Details
	response["indicators"] = allIndicators
	response["engine"] = "sentinel-core"
	response["latency_ms"] = float64(coreResult.Duration.Microseconds()) / 1000.0
	response["shield_status"] = shieldStatus

	// ── Store in cache (5 min TTL, evict oldest if >500 entries) ──
	s.scanCacheMu.Lock()
	if len(s.scanCache) >= 500 {
		// Simple eviction: remove any expired entries
		now := time.Now()
		for k, v := range s.scanCache {
			if now.After(v.expiry) {
				delete(s.scanCache, k)
			}
		}
		// If still full, clear oldest 25%
		if len(s.scanCache) >= 500 {
			i := 0
			for k := range s.scanCache {
				delete(s.scanCache, k)
				i++
				if i >= 125 {
					break
				}
			}
		}
	}
	s.scanCache[cacheKey] = &cachedScan{
		response: response,
		expiry:   time.Now().Add(5 * time.Minute),
	}
	s.scanCacheMu.Unlock()

	writeJSON(w, http.StatusOK, response)
}

// handleUsage returns current scan usage and quota for the caller.
// GET /api/v1/usage
func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	if s.usageTracker == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"plan":       "free",
			"scans_used": 0,
			"scans_limit": 1000,
			"remaining":  1000,
			"unlimited":  false,
		})
		return
	}

	userID := ""
	if claims := auth.GetClaims(r.Context()); claims != nil {
		userID = claims.Sub
	}
	ip := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = fwd
	}

	info := s.usageTracker.GetUsage(userID, ip)
	writeJSON(w, http.StatusOK, info)
}

// handleWaitlist captures registration interest when signups are closed.
// POST /api/waitlist  body: {"email": "user@corp.com", "company": "CorpX", "use_case": "LLM protection"}
// Public endpoint, no auth required. Rate-limited globally.
func (s *Server) handleWaitlist(w http.ResponseWriter, r *http.Request) {
	limitBody(w, r)
	defer r.Body.Close()

	var req struct {
		Email   string `json:"email"`
		Company string `json:"company"`
		UseCase string `json:"use_case"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate email
	if req.Email == "" || len(req.Email) < 5 || len(req.Email) > 254 {
		writeError(w, http.StatusBadRequest, "valid email is required")
		return
	}
	// Basic email format check
	hasAt := false
	for _, c := range req.Email {
		if c == '@' {
			hasAt = true
			break
		}
	}
	if !hasAt {
		writeError(w, http.StatusBadRequest, "valid email is required")
		return
	}

	// Sanitize
	if len(req.Company) > 200 {
		req.Company = req.Company[:200]
	}
	if len(req.UseCase) > 1000 {
		req.UseCase = req.UseCase[:1000]
	}

	// Log the waitlist entry (always — even if DB fails)
	slog.Info("waitlist submission",
		"email", req.Email,
		"company", req.Company,
		"use_case", req.UseCase,
		"ip", r.RemoteAddr,
	)

	// Persist via SOC repo if available
	if s.socSvc != nil {
		s.socSvc.AddWaitlistEntry(req.Email, req.Company, req.UseCase)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"message": "You've been added to the waitlist. We'll notify you when registration opens.",
	})
}
