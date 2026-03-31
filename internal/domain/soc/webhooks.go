// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

package soc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// WebhookEventType defines events that trigger webhooks (§15).
type WebhookEventType string

const (
	WebhookIncidentCreated  WebhookEventType = "incident_created"
	WebhookIncidentResolved WebhookEventType = "incident_resolved"
	WebhookCriticalEvent    WebhookEventType = "critical_event"
	WebhookSensorOffline    WebhookEventType = "sensor_offline"
	WebhookKillChainAlert   WebhookEventType = "kill_chain_alert"
)

// WebhookConfig defines a webhook destination.
type WebhookConfig struct {
	ID      string             `yaml:"id" json:"id"`
	URL     string             `yaml:"url" json:"url"`
	Events  []WebhookEventType `yaml:"events" json:"events"`
	Headers map[string]string  `yaml:"headers" json:"headers"`
	Active  bool               `yaml:"active" json:"active"`
	Retries int                `yaml:"retries" json:"retries"`
}

// WebhookPayload is the JSON body sent to webhook endpoints.
type WebhookPayload struct {
	EventType   WebhookEventType `json:"event_type"`
	Timestamp   time.Time        `json:"timestamp"`
	IncidentID  string           `json:"incident_id,omitempty"`
	Severity    string           `json:"severity"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	URL         string           `json:"url,omitempty"` // Link to dashboard
}

// WebhookEngine manages webhook delivery with retry logic (§15).
type WebhookEngine struct {
	mu       sync.RWMutex
	webhooks []WebhookConfig
	client   *http.Client

	// Stats
	sent   int
	failed int
	queue  chan webhookJob
}

type webhookJob struct {
	config  WebhookConfig
	payload WebhookPayload
	attempt int
}

// NewWebhookEngine creates a webhook delivery engine.
func NewWebhookEngine() *WebhookEngine {
	e := &WebhookEngine{
		client: &http.Client{Timeout: 10 * time.Second},
		queue:  make(chan webhookJob, 100),
	}
	// Start async delivery worker
	go e.deliveryWorker()
	return e
}

// AddWebhook registers a webhook destination.
func (e *WebhookEngine) AddWebhook(wh WebhookConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if wh.Retries == 0 {
		wh.Retries = 3
	}
	if wh.ID == "" {
		wh.ID = fmt.Sprintf("wh-%d", time.Now().UnixNano())
	}
	e.webhooks = append(e.webhooks, wh)
}

// RemoveWebhook deactivates a webhook by ID.
func (e *WebhookEngine) RemoveWebhook(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range e.webhooks {
		if e.webhooks[i].ID == id {
			e.webhooks[i].Active = false
		}
	}
}

// Fire sends a webhook payload to all matching subscribers.
func (e *WebhookEngine) Fire(eventType WebhookEventType, payload WebhookPayload) {
	payload.EventType = eventType
	payload.Timestamp = time.Now()

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, wh := range e.webhooks {
		if !wh.Active {
			continue
		}
		for _, et := range wh.Events {
			if et == eventType {
				select {
				case e.queue <- webhookJob{config: wh, payload: payload, attempt: 0}:
				default:
					slog.Warn("webhook queue full, dropping event", "event_type", eventType, "url", wh.URL)
				}
				break
			}
		}
	}
}

// deliveryWorker processes webhook jobs with retries.
func (e *WebhookEngine) deliveryWorker() {
	for job := range e.queue {
		err := e.deliver(job.config, job.payload)
		if err != nil {
			job.attempt++
			if job.attempt < job.config.Retries {
				// Exponential backoff: 1s, 2s, 4s
				go func(j webhookJob) {
					time.Sleep(time.Duration(1<<j.attempt) * time.Second)
					select {
					case e.queue <- j:
					default:
					}
				}(job)
			} else {
				e.mu.Lock()
				e.failed++
				e.mu.Unlock()
				slog.Error("webhook delivery failed", "attempts", job.attempt, "url", job.config.URL, "error", err)
			}
		} else {
			e.mu.Lock()
			e.sent++
			e.mu.Unlock()
		}
	}
}

// deliver sends the HTTP request.
func (e *WebhookEngine) deliver(wh WebhookConfig, payload WebhookPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", wh.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SYNTREX-SOAR/1.0")

	for k, v := range wh.Headers {
		req.Header.Set(k, v)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

// Stats returns webhook delivery statistics.
func (e *WebhookEngine) Stats() map[string]any {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return map[string]any{
		"webhooks_configured": len(e.webhooks),
		"sent":                e.sent,
		"failed":              e.failed,
		"queue_depth":         len(e.queue),
	}
}

// Webhooks returns all configured webhooks.
func (e *WebhookEngine) Webhooks() []WebhookConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]WebhookConfig, len(e.webhooks))
	copy(result, e.webhooks)
	return result
}
