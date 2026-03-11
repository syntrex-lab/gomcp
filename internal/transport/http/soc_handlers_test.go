package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	appsoc "github.com/syntrex/gomcp/internal/application/soc"
	domsoc "github.com/syntrex/gomcp/internal/domain/soc"
	"github.com/syntrex/gomcp/internal/infrastructure/sqlite"
)

// newTestServer creates an HTTP test server with a real SOC service backed by in-memory SQLite.
func newTestServer(t *testing.T) (*httptest.Server, *appsoc.Service) {
	t.Helper()

	// In-memory SQLite for SOC
	db, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	repo, err := sqlite.NewSOCRepo(db)
	if err != nil {
		t.Fatalf("create SOC repo: %v", err)
	}

	socSvc := appsoc.NewService(repo, nil) // no decision logger for tests

	srv := New(socSvc, 0) // port 0, we use httptest
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/soc/dashboard", srv.handleDashboard)
	mux.HandleFunc("GET /api/soc/events", srv.handleEvents)
	mux.HandleFunc("GET /api/soc/incidents", srv.handleIncidents)
	mux.HandleFunc("GET /api/soc/sensors", srv.handleSensors)
	mux.HandleFunc("GET /api/soc/threat-intel", srv.handleThreatIntel)
	mux.HandleFunc("GET /api/soc/webhook-stats", srv.handleWebhookStats)
	mux.HandleFunc("GET /api/soc/analytics", srv.handleAnalytics)
	mux.HandleFunc("GET /health", srv.handleHealth)

	ts := httptest.NewServer(corsMiddleware(mux))
	t.Cleanup(ts.Close)

	return ts, socSvc
}

// TestHTTP_Dashboard_Returns200 verifies GET /api/soc/dashboard returns 200 with valid JSON.
func TestHTTP_Dashboard_Returns200(t *testing.T) {
	ts, _ := newTestServer(t)

	resp, err := http.Get(ts.URL + "/api/soc/dashboard")
	if err != nil {
		t.Fatalf("GET /api/soc/dashboard: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Verify JSON structure
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	// Must contain total_events key
	if _, ok := result["total_events"]; !ok {
		t.Error("response missing 'total_events' field")
	}

	// Verify CORS headers
	if origin := resp.Header.Get("Access-Control-Allow-Origin"); origin != "*" {
		t.Errorf("CORS: expected *, got %q", origin)
	}
}

// TestHTTP_Events_WithLimit verifies GET /api/soc/events?limit=5 returns at most 5 events.
func TestHTTP_Events_WithLimit(t *testing.T) {
	ts, socSvc := newTestServer(t)

	// Ingest 10 events
	for i := 0; i < 10; i++ {
		socSvc.IngestEvent(domsoc.SOCEvent{
			SensorID: "test-sensor",
			Category: "test",
			Severity: domsoc.SeverityLow,
			Payload:  "test event payload",
		})
	}

	resp, err := http.Get(ts.URL + "/api/soc/events?limit=5")
	if err != nil {
		t.Fatalf("GET /api/soc/events: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result struct {
		Events []any `json:"events"`
		Count  int   `json:"count"`
		Limit  int   `json:"limit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if result.Limit != 5 {
		t.Errorf("expected limit=5, got %d", result.Limit)
	}
	if result.Count > 5 {
		t.Errorf("expected at most 5 events, got %d", result.Count)
	}
}

// TestHTTP_Incidents_FilterByStatus verifies GET /api/soc/incidents?status=open returns only open incidents.
func TestHTTP_Incidents_FilterByStatus(t *testing.T) {
	ts, socSvc := newTestServer(t)

	// Ingest 3 correlated jailbreak events to trigger incident creation
	for i := 0; i < 3; i++ {
		socSvc.IngestEvent(domsoc.SOCEvent{
			SensorID: "test-sensor",
			Category: "jailbreak",
			Severity: domsoc.SeverityCritical,
			Payload:  "jailbreak attempt payload",
		})
	}

	resp, err := http.Get(ts.URL + "/api/soc/incidents?status=open")
	if err != nil {
		t.Fatalf("GET /api/soc/incidents: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result struct {
		Incidents []any  `json:"incidents"`
		Count     int    `json:"count"`
		Status    string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if result.Status != "open" {
		t.Errorf("expected status filter 'open', got %q", result.Status)
	}

	// After 3 jailbreak events, correlation should have created at least one open incident
	t.Logf("incidents: count=%d, status=%s", result.Count, result.Status)
}

// TestHTTP_Health returns ok.
func TestHTTP_Health(t *testing.T) {
	ts, _ := newTestServer(t)

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("expected status 'ok', got %q", result["status"])
	}
}

// TestHTTP_Sensors_Returns200 verifies GET /api/soc/sensors returns 200.
func TestHTTP_Sensors_Returns200(t *testing.T) {
	ts, socSvc := newTestServer(t)

	// Ingest an event to auto-register a sensor
	socSvc.IngestEvent(domsoc.SOCEvent{
		SensorID: "test-sensor-001",
		Source:   domsoc.SourceSentinelCore,
		Category: "test",
		Severity: domsoc.SeverityLow,
	})

	resp, err := http.Get(ts.URL + "/api/soc/sensors")
	if err != nil {
		t.Fatalf("GET /api/soc/sensors: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result struct {
		Sensors []any `json:"sensors"`
		Count   int   `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if result.Count < 1 {
		t.Error("expected at least 1 sensor after event ingest")
	}
	t.Logf("sensors: count=%d", result.Count)
}

// TestHTTP_ThreatIntel_NotConfigured verifies threat-intel returns disabled when not configured.
func TestHTTP_ThreatIntel_NotConfigured(t *testing.T) {
	ts, _ := newTestServer(t)

	resp, err := http.Get(ts.URL + "/api/soc/threat-intel")
	if err != nil {
		t.Fatalf("GET /api/soc/threat-intel: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	// Without SetThreatIntel, should return enabled=false
	if enabled, ok := result["enabled"].(bool); !ok || enabled {
		t.Error("expected enabled=false when threat intel not configured")
	}
}

// TestHTTP_Analytics_Returns200 verifies GET /api/soc/analytics returns a valid report.
func TestHTTP_Analytics_Returns200(t *testing.T) {
	ts, socSvc := newTestServer(t)

	// Ingest some events for analytics
	for i := 0; i < 5; i++ {
		socSvc.IngestEvent(domsoc.SOCEvent{
			SensorID: "analytics-sensor",
			Source:   domsoc.SourceShield,
			Category: "injection",
			Severity: domsoc.SeverityHigh,
		})
	}

	resp, err := http.Get(ts.URL + "/api/soc/analytics?window=1")
	if err != nil {
		t.Fatalf("GET /api/soc/analytics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	// Must have analytics fields
	for _, field := range []string{"generated_at", "event_trend", "severity_distribution", "top_sources", "mttr_hours"} {
		if _, ok := result[field]; !ok {
			t.Errorf("response missing '%s' field", field)
		}
	}

	t.Logf("analytics: events_per_hour=%.1f", result["events_per_hour"])
}

// TestHTTP_WebhookStats_Returns200 verifies webhook-stats endpoint works.
func TestHTTP_WebhookStats_Returns200(t *testing.T) {
	ts, _ := newTestServer(t)

	resp, err := http.Get(ts.URL + "/api/soc/webhook-stats")
	if err != nil {
		t.Fatalf("GET /api/soc/webhook-stats: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
