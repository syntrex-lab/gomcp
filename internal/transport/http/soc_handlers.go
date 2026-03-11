package httpserver

import (
	"net/http"
	"strconv"
)

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

// handleThreatIntel returns IOC database statistics and feed status.
// GET /api/soc/threat-intel
func (s *Server) handleThreatIntel(w http.ResponseWriter, _ *http.Request) {
	if s.threatIntel == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"message": "Threat intelligence not configured",
		})
		return
	}

	stats := s.threatIntel.Stats()
	stats["enabled"] = true
	writeJSON(w, http.StatusOK, stats)
}

// handleWebhookStats returns SOAR webhook delivery statistics.
// GET /api/soc/webhook-stats
func (s *Server) handleWebhookStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Use SOC service webhook configuration for stats",
	})
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
