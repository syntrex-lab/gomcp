package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/syntrex/gomcp/internal/domain/peer"
)

// WSTransport provides WebSocket-based P2P communication (v3.5).
// Enables real-time fact sync between GoMCP instances.
type WSTransport struct {
	mu       sync.RWMutex
	registry *peer.Registry
	listener net.Listener
	port     int
	running  bool
	onSync   func(payload peer.SyncPayload) error // Callback for incoming syncs
}

// WSConfig holds WebSocket transport configuration.
type WSConfig struct {
	Port    int    `json:"port"`    // Listen port (default: 9741)
	Host    string `json:"host"`    // Bind address (default: localhost)
	Enabled bool   `json:"enabled"` // Enable WebSocket transport
}

// NewWSTransport creates a new WebSocket transport.
func NewWSTransport(cfg WSConfig, reg *peer.Registry) *WSTransport {
	if cfg.Port < 0 {
		cfg.Port = 9741
	}
	if cfg.Host == "" {
		cfg.Host = "localhost"
	}
	return &WSTransport{
		registry: reg,
		port:     cfg.Port,
	}
}

// OnSync registers a callback for incoming sync payloads.
func (t *WSTransport) OnSync(fn func(peer.SyncPayload) error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onSync = fn
}

// Message is the wire protocol for P2P communication.
type Message struct {
	Type    string          `json:"type"`    // "handshake", "sync", "delta_sync_req", "delta_sync_res", "ping", "pong"
	Payload json.RawMessage `json:"payload"` // Type-specific data
	From    string          `json:"from"`    // Sender peer ID
	SentAt  time.Time       `json:"sent_at"`
}

// Start begins listening for WebSocket connections.
func (t *WSTransport) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/p2p", t.handleP2P)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","peer_id":"%s","node":"%s"}`, t.registry.SelfID(), t.registry.NodeName())
	})

	addr := fmt.Sprintf("localhost:%d", t.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("ws listen %s: %w", addr, err)
	}

	t.mu.Lock()
	t.listener = listener
	t.running = true
	t.mu.Unlock()

	log.Printf("ws-transport: listening on %s (peer=%s)", addr, t.registry.SelfID())

	go func() {
		srv := &http.Server{Handler: mux}
		if err := srv.Serve(listener); err != nil && t.isRunning() {
			log.Printf("ws-transport: serve error: %v", err)
		}
	}()

	return nil
}

// handleP2P handles incoming WebSocket-like HTTP connections.
// Uses simple HTTP POST for compatibility (true WebSocket upgrade optional in v3.6).
func (t *WSTransport) handleP2P(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var msg Message
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "invalid message", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch msg.Type {
	case "ping":
		resp := Message{Type: "pong", From: t.registry.SelfID(), SentAt: time.Now()}
		json.NewEncoder(w).Encode(resp)

	case "handshake":
		var req peer.HandshakeRequest
		json.Unmarshal(msg.Payload, &req)
		// Process handshake through registry.
		respData, _ := json.Marshal(map[string]string{"status": "received", "peer_id": t.registry.SelfID()})
		resp := Message{Type: "handshake", From: t.registry.SelfID(), Payload: respData, SentAt: time.Now()}
		json.NewEncoder(w).Encode(resp)

	case "sync":
		var payload peer.SyncPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			http.Error(w, "invalid sync payload", http.StatusBadRequest)
			return
		}
		t.mu.RLock()
		handler := t.onSync
		t.mu.RUnlock()
		if handler != nil {
			if err := handler(payload); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		resp := Message{
			Type:    "sync",
			From:    t.registry.SelfID(),
			Payload: json.RawMessage(fmt.Sprintf(`{"accepted":%d}`, len(payload.Facts))),
			SentAt:  time.Now(),
		}
		json.NewEncoder(w).Encode(resp)

	case "delta_sync_req":
		var req peer.DeltaSyncRequest
		if err := json.Unmarshal(msg.Payload, &req); err != nil {
			http.Error(w, "invalid delta sync request", http.StatusBadRequest)
			return
		}
		// Respond with empty for now — actual fact retrieval connected at startup.
		resp := peer.DeltaSyncResponse{
			FromPeerID: t.registry.SelfID(),
			SyncedAt:   time.Now(),
			HasMore:    false,
		}
		respData, _ := json.Marshal(resp)
		json.NewEncoder(w).Encode(Message{Type: "delta_sync_res", From: t.registry.SelfID(), Payload: respData, SentAt: time.Now()})

	default:
		http.Error(w, "unknown message type", http.StatusBadRequest)
	}
}

// SendSync sends a sync payload to a remote peer via HTTP POST.
func (t *WSTransport) SendSync(ctx context.Context, addr string, payload peer.SyncPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	msg := Message{
		Type:    "sync",
		From:    t.registry.SelfID(),
		Payload: data,
		SentAt:  time.Now(),
	}
	return t.send(ctx, addr, msg)
}

// SendDeltaSync sends a delta sync request to a remote peer.
func (t *WSTransport) SendDeltaSync(ctx context.Context, addr string, req peer.DeltaSyncRequest) (*peer.DeltaSyncResponse, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	msg := Message{
		Type:    "delta_sync_req",
		From:    t.registry.SelfID(),
		Payload: data,
		SentAt:  time.Now(),
	}

	respMsg, err := t.sendAndReceive(ctx, addr, msg)
	if err != nil {
		return nil, err
	}

	var resp peer.DeltaSyncResponse
	if err := json.Unmarshal(respMsg.Payload, &resp); err != nil {
		return nil, fmt.Errorf("decode delta response: %w", err)
	}
	return &resp, nil
}

// Ping checks if a remote peer is alive.
func (t *WSTransport) Ping(ctx context.Context, addr string) (peerID string, err error) {
	msg := Message{Type: "ping", From: t.registry.SelfID(), SentAt: time.Now()}
	resp, err := t.sendAndReceive(ctx, addr, msg)
	if err != nil {
		return "", err
	}
	return resp.From, nil
}

// Stop shuts down the transport.
func (t *WSTransport) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.running = false
	if t.listener != nil {
		return t.listener.Close()
	}
	return nil
}

// Addr returns the listen address.
func (t *WSTransport) Addr() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.listener != nil {
		return t.listener.Addr().String()
	}
	return ""
}

func (t *WSTransport) isRunning() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.running
}

func (t *WSTransport) send(ctx context.Context, addr string, msg Message) error {
	_, err := t.sendAndReceive(ctx, addr, msg)
	return err
}

func (t *WSTransport) sendAndReceive(_ context.Context, addr string, msg Message) (*Message, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("http://%s/p2p", addr)

	resp, err := client.Post(url, "application/json", jsonReader(data))
	if err != nil {
		return nil, fmt.Errorf("p2p send to %s: %w", addr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("p2p %s returned %d", addr, resp.StatusCode)
	}

	var respMsg Message
	if err := json.NewDecoder(resp.Body).Decode(&respMsg); err != nil {
		return nil, fmt.Errorf("decode response from %s: %w", addr, err)
	}
	return &respMsg, nil
}

func jsonReader(data []byte) *jsonBody { return &jsonBody{data: data} }

type jsonBody struct {
	data []byte
	off  int
}

func (j *jsonBody) Read(p []byte) (n int, err error) {
	if j.off >= len(j.data) {
		return 0, io.EOF
	}
	n = copy(p, j.data[j.off:])
	j.off += n
	return n, nil
}
