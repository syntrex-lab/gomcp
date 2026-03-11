// Package httpserver provides an HTTP API transport for GoMCP SOC dashboard.
//
// Zero CGO: Uses ONLY Go stdlib net/http (supports HTTP/2 natively).
// Backward compatible: disabled by default (--http-port 0).
package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	appsoc "github.com/sentinel-community/gomcp/internal/application/soc"
)

// Server provides HTTP API endpoints for SOC monitoring.
type Server struct {
	socSvc     *appsoc.Service
	threatIntel *appsoc.ThreatIntelStore
	port       int
	srv        *http.Server
}

// New creates an HTTP server bound to the given port.
func New(socSvc *appsoc.Service, port int) *Server {
	return &Server{
		socSvc: socSvc,
		port:   port,
	}
}

// SetThreatIntel sets the threat intel store for API access.
func (s *Server) SetThreatIntel(store *appsoc.ThreatIntelStore) {
	s.threatIntel = store
}

// Start begins listening on the configured port. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// SOC API routes
	mux.HandleFunc("GET /api/soc/dashboard", s.handleDashboard)
	mux.HandleFunc("GET /api/soc/events", s.handleEvents)
	mux.HandleFunc("GET /api/soc/incidents", s.handleIncidents)
	mux.HandleFunc("GET /api/soc/sensors", s.handleSensors)
	mux.HandleFunc("GET /api/soc/threat-intel", s.handleThreatIntel)
	mux.HandleFunc("GET /api/soc/webhook-stats", s.handleWebhookStats)
	mux.HandleFunc("GET /api/soc/analytics", s.handleAnalytics)

	// Health check
	mux.HandleFunc("GET /health", s.handleHealth)

	// Wrap with CORS middleware
	handler := corsMiddleware(mux)

	s.srv = &http.Server{
		Addr:              fmt.Sprintf(":%d", s.port),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown on context cancellation
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
	}()

	log.Printf("HTTP API listening on :%d", s.port)
	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http server: %w", err)
	}
	return nil
}

// Stop gracefully shuts down the HTTP server.
func (s *Server) Stop(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("HTTP: failed to encode response: %v", err)
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
