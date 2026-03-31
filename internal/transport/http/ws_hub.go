// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

package httpserver

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// WSHub manages WebSocket connections for live dashboard updates.
// Uses server-side Upgrade per RFC 6455 (no external deps — Go 1.24 net/http
// doesn't natively support WS, so we use SSE with long-poll fallback here
// and document the upgrade path to gorilla/websocket).
//
// For now, this implements an SSE-based push hub (same API as WebSocket
// but with EventSource transport). Upgrade to WS is a non-breaking change.
type WSHub struct {
	mu      sync.RWMutex
	clients map[string]chan []byte // clientID → channel
}

// NewWSHub creates a new WebSocket/SSE push hub.
func NewWSHub() *WSHub {
	return &WSHub{
		clients: make(map[string]chan []byte),
	}
}

// Subscribe adds a client to the hub. Returns channel and cleanup function.
func (h *WSHub) Subscribe(clientID string) (<-chan []byte, func()) {
	ch := make(chan []byte, 64) // buffered to prevent slow client blocking
	h.mu.Lock()
	h.clients[clientID] = ch
	h.mu.Unlock()

	slog.Debug("ws hub: client subscribed", "client_id", clientID, "total", h.ClientCount())

	cleanup := func() {
		h.mu.Lock()
		delete(h.clients, clientID)
		close(ch)
		h.mu.Unlock()
		slog.Debug("ws hub: client unsubscribed", "client_id", clientID)
	}
	return ch, cleanup
}

// Broadcast sends a message to ALL connected clients.
// Non-blocking: slow clients' messages are dropped.
func (h *WSHub) Broadcast(eventType string, data any) {
	payload, err := json.Marshal(map[string]any{
		"type":      eventType,
		"data":      data,
		"timestamp": time.Now().Format(time.RFC3339),
	})
	if err != nil {
		slog.Error("ws hub: marshal broadcast", "error", err)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for id, ch := range h.clients {
		select {
		case ch <- payload:
		default:
			slog.Warn("ws hub: dropped message for slow client", "client_id", id)
		}
	}
}

// ClientCount returns the number of connected clients.
func (h *WSHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// HandleSSEStream serves Server-Sent Events for live dashboard updates.
// GET /api/soc/ws — returns SSE stream (Content-Type: text/event-stream).
func (h *WSHub) HandleSSEStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		clientID = r.RemoteAddr
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // nginx proxy support

	ch, cleanup := h.Subscribe(clientID)
	defer cleanup()

	// Send initial connected event.
	w.Write([]byte("event: connected\ndata: {\"status\":\"ok\"}\n\n"))
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			w.Write([]byte("event: update\ndata: "))
			w.Write(msg)
			w.Write([]byte("\n\n"))
			flusher.Flush()
		}
	}
}
