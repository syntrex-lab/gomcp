// Package webhook provides outbound SOAR webhook notifications
// for the SOC pipeline. Fires HTTP POST on incident creation/update.
package soc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	domsoc "github.com/sentinel-community/gomcp/internal/domain/soc"
)

// WebhookConfig holds SOAR webhook settings.
type WebhookConfig struct {
	// Endpoints is a list of webhook URLs to POST to.
	Endpoints []string `json:"endpoints"`

	// Headers are custom HTTP headers added to every request (e.g., auth tokens).
	Headers map[string]string `json:"headers,omitempty"`

	// MaxRetries is the number of retry attempts on failure (default 3).
	MaxRetries int `json:"max_retries"`

	// TimeoutSec is the HTTP client timeout in seconds (default 10).
	TimeoutSec int `json:"timeout_sec"`

	// MinSeverity filters: only incidents >= this severity trigger webhooks.
	// Empty string means all severities.
	MinSeverity domsoc.EventSeverity `json:"min_severity,omitempty"`
}

// WebhookPayload is the JSON body sent to SOAR endpoints.
type WebhookPayload struct {
	EventType string          `json:"event_type"` // incident_created, incident_updated, sensor_offline
	Timestamp time.Time       `json:"timestamp"`
	Source    string           `json:"source"`
	Data     json.RawMessage  `json:"data"`
}

// WebhookResult tracks delivery status per endpoint.
type WebhookResult struct {
	Endpoint   string `json:"endpoint"`
	StatusCode int    `json:"status_code"`
	Success    bool   `json:"success"`
	Retries    int    `json:"retries"`
	Error      string `json:"error,omitempty"`
}

// WebhookNotifier handles outbound SOAR notifications.
type WebhookNotifier struct {
	mu      sync.RWMutex
	config  WebhookConfig
	client  *http.Client
	enabled bool

	// Stats
	Sent   int64 `json:"sent"`
	Failed int64 `json:"failed"`
}

// NewWebhookNotifier creates a notifier with the given config.
func NewWebhookNotifier(config WebhookConfig) *WebhookNotifier {
	if config.MaxRetries <= 0 {
		config.MaxRetries = 3
	}
	timeout := time.Duration(config.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	return &WebhookNotifier{
		config:  config,
		client:  &http.Client{Timeout: timeout},
		enabled: len(config.Endpoints) > 0,
	}
}

// severityRank returns numeric rank for severity comparison.
func severityRank(s domsoc.EventSeverity) int {
	switch s {
	case domsoc.SeverityCritical:
		return 5
	case domsoc.SeverityHigh:
		return 4
	case domsoc.SeverityMedium:
		return 3
	case domsoc.SeverityLow:
		return 2
	case domsoc.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// NotifyIncident sends an incident webhook to all configured endpoints.
// Non-blocking: fires goroutines for each endpoint.
func (w *WebhookNotifier) NotifyIncident(eventType string, incident *domsoc.Incident) []WebhookResult {
	if !w.enabled || incident == nil {
		return nil
	}

	// Severity filter
	if w.config.MinSeverity != "" {
		if severityRank(incident.Severity) < severityRank(w.config.MinSeverity) {
			return nil
		}
	}

	data, err := json.Marshal(incident)
	if err != nil {
		return nil
	}

	payload := WebhookPayload{
		EventType: eventType,
		Timestamp: time.Now().UTC(),
		Source:    "sentinel-soc",
		Data:     data,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil
	}

	// Fire all endpoints in parallel
	var wg sync.WaitGroup
	results := make([]WebhookResult, len(w.config.Endpoints))

	for i, endpoint := range w.config.Endpoints {
		wg.Add(1)
		go func(idx int, url string) {
			defer wg.Done()
			results[idx] = w.sendWithRetry(url, body)
		}(i, endpoint)
	}
	wg.Wait()

	// Update stats
	w.mu.Lock()
	for _, r := range results {
		if r.Success {
			w.Sent++
		} else {
			w.Failed++
		}
	}
	w.mu.Unlock()

	return results
}

// NotifySensorOffline sends a sensor offline alert to all endpoints.
func (w *WebhookNotifier) NotifySensorOffline(sensor domsoc.Sensor) []WebhookResult {
	if !w.enabled {
		return nil
	}

	data, _ := json.Marshal(sensor)
	payload := WebhookPayload{
		EventType: "sensor_offline",
		Timestamp: time.Now().UTC(),
		Source:    "sentinel-soc",
		Data:     data,
	}

	body, _ := json.Marshal(payload)

	var wg sync.WaitGroup
	results := make([]WebhookResult, len(w.config.Endpoints))
	for i, endpoint := range w.config.Endpoints {
		wg.Add(1)
		go func(idx int, url string) {
			defer wg.Done()
			results[idx] = w.sendWithRetry(url, body)
		}(i, endpoint)
	}
	wg.Wait()

	return results
}

// sendWithRetry sends POST request with exponential backoff.
func (w *WebhookNotifier) sendWithRetry(url string, body []byte) WebhookResult {
	result := WebhookResult{Endpoint: url}

	for attempt := 0; attempt <= w.config.MaxRetries; attempt++ {
		result.Retries = attempt

		req, err := http.NewRequest("POST", url, bytes.NewReader(body))
		if err != nil {
			result.Error = err.Error()
			return result
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "SENTINEL-SOC/1.0")
		req.Header.Set("X-Sentinel-Event", "soc-webhook")

		// Add custom headers
		for k, v := range w.config.Headers {
			req.Header.Set(k, v)
		}

		resp, err := w.client.Do(req)
		if err != nil {
			result.Error = err.Error()
			if attempt < w.config.MaxRetries {
				backoff := time.Duration(1<<uint(attempt)) * 500 * time.Millisecond
				jitter := time.Duration(rand.Intn(500)) * time.Millisecond
				time.Sleep(backoff + jitter)
				continue
			}
			return result
		}
		resp.Body.Close()

		result.StatusCode = resp.StatusCode
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			result.Success = true
			return result
		}

		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		if attempt < w.config.MaxRetries {
			backoff := time.Duration(1<<uint(attempt)) * 500 * time.Millisecond
			jitter := time.Duration(rand.Intn(500)) * time.Millisecond
			time.Sleep(backoff + jitter)
		}
	}

	log.Printf("[SOC] webhook failed after %d retries: %s → %s", w.config.MaxRetries, url, result.Error)
	return result
}

// Stats returns webhook delivery stats.
func (w *WebhookNotifier) Stats() (sent, failed int64) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.Sent, w.Failed
}
