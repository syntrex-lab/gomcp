// Package httpserver provides an HTTP API transport for GoMCP SOC dashboard.
//
// Zero CGO: Uses ONLY Go stdlib net/http (supports HTTP/2 natively).
// Backward compatible: disabled by default (--http-port 0).
package httpserver

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	shadowai "github.com/syntrex/gomcp/internal/application/shadow_ai"
	appsoc "github.com/syntrex/gomcp/internal/application/soc"
	"github.com/syntrex/gomcp/internal/domain/engines"
	"github.com/syntrex/gomcp/internal/infrastructure/auth"
	"github.com/syntrex/gomcp/internal/infrastructure/email"
	"github.com/syntrex/gomcp/internal/infrastructure/tracing"
)

// Server provides HTTP API endpoints for SOC monitoring.
type Server struct {
	socSvc           *appsoc.Service
	threatIntel      *appsoc.ThreatIntelStore
	shadowAI         *shadowai.ShadowAIController
	rbac             *RBACMiddleware
	rateLimiter      *RateLimiter
	metrics          *Metrics
	logger           *RequestLogger
	sentinelCore     engines.SentinelCore
	jwtAuth          *auth.JWTMiddleware
	userStore        *auth.UserStore
	tenantStore      *auth.TenantStore
	emailService     *email.Service
	jwtSecret        []byte
	wsHub            *WSHub
	sovereignEnabled bool
	sovereignMode    string
	pprofEnabled     bool
	port             int
	srv              *http.Server
	tlsCert          string
	tlsKey           string
}

// New creates an HTTP server bound to the given port.
func New(socSvc *appsoc.Service, port int) *Server {
	return &Server{
		socSvc:      socSvc,
		port:        port,
		rbac:        NewRBACMiddleware(RBACConfig{Enabled: false}),
		rateLimiter: NewRateLimiter(context.Background(), 100, time.Minute),
		metrics:     NewMetrics(),
		logger:      NewRequestLogger(true),
		wsHub:       NewWSHub(),
	}
}

// SetThreatIntel sets the threat intel store for API access.
func (s *Server) SetThreatIntel(store *appsoc.ThreatIntelStore) {
	s.threatIntel = store
}

// SetShadowAI sets the Shadow AI Controller for API access.
func (s *Server) SetShadowAI(controller *shadowai.ShadowAIController) {
	s.shadowAI = controller
}

// SetEmailService sets the email service for sending verification codes and alerts.
func (s *Server) SetEmailService(svc *email.Service) {
	s.emailService = svc
}

// SetSentinelCore sets the Rust-native detection engine for real-time scanning.
func (s *Server) SetSentinelCore(core engines.SentinelCore) {
	s.sentinelCore = core
}

// SetJWTAuth enables JWT authentication with the given secret.
// If secret is empty or <32 bytes, JWT is disabled (backward compatible).
// Optional db parameter enables SQLite-backed user persistence.
func (s *Server) SetJWTAuth(secret []byte, db ...*sql.DB) {
	if len(secret) < 32 {
		slog.Warn("JWT auth disabled: secret too short or not set")
		return
	}
	s.jwtSecret = secret
	s.jwtAuth = auth.NewJWTMiddleware(secret)
	if len(db) > 0 && db[0] != nil {
		s.userStore = auth.NewUserStore(db[0])
		s.tenantStore = auth.NewTenantStore(db[0])
	} else {
		s.userStore = auth.NewUserStore()
	}
	slog.Info("JWT authentication enabled")
}

// SetRBAC configures RBAC middleware with API key authentication (§17).
func (s *Server) SetRBAC(rbac *RBACMiddleware) {
	s.rbac = rbac
}

// SetTLS enables TLS with the given certificate and key files.
// Cipher suites are hardened to AEAD-only (§P2 TLS hardening).
func (s *Server) SetTLS(certFile, keyFile string) {
	s.tlsCert = certFile
	s.tlsKey = keyFile
}

// StartEventBridge subscribes to the SOC EventBus and forwards events
// to the WSHub for real-time SSE/WebSocket dashboard streaming (§P1).
// Should be called once after server creation. Runs as a background goroutine.
func (s *Server) StartEventBridge(ctx context.Context) {
	bus := s.socSvc.EventBus()
	if bus == nil {
		slog.Warn("event bridge: no EventBus available")
		return
	}

	ch := bus.Subscribe("ws-hub-bridge")
	go func() {
		for {
			select {
			case <-ctx.Done():
				bus.Unsubscribe("ws-hub-bridge")
				return
			case evt, ok := <-ch:
				if !ok {
					return
				}
				s.wsHub.Broadcast("soc_event", map[string]any{
					"id":       evt.ID,
					"source":   string(evt.Source),
					"severity": string(evt.Severity),
					"category": evt.Category,
					"description": evt.Description,
					"session_id":  evt.SessionID,
				})
			}
		}
	}()
	slog.Info("event bridge started: EventBus → WSHub")
}

// Start begins listening on the configured port. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// SOC API routes — read (requires Viewer role when RBAC enabled)
	mux.HandleFunc("GET /api/soc/dashboard", s.rbac.Require(RoleViewer, s.handleDashboard))
	mux.HandleFunc("GET /api/soc/events", s.rbac.Require(RoleViewer, s.handleEvents))
	mux.HandleFunc("GET /api/soc/incidents", s.rbac.Require(RoleViewer, s.handleIncidents))
	// Sprint 2: Advanced incident management (must be before generic {id})
	mux.HandleFunc("GET /api/soc/incidents/advanced", s.rbac.Require(RoleViewer, s.handleIncidentsAdvanced))
	mux.HandleFunc("POST /api/soc/incidents/bulk", s.rbac.Require(RoleAnalyst, s.handleIncidentsBulk))
	mux.HandleFunc("GET /api/soc/incidents/export", s.rbac.Require(RoleViewer, s.handleIncidentsExport))
	mux.HandleFunc("GET /api/soc/sla-config", s.rbac.Require(RoleViewer, s.handleSLAConfig))
	mux.HandleFunc("GET /api/soc/incidents/{id}", s.rbac.Require(RoleViewer, s.handleIncidentDetail))
	mux.HandleFunc("GET /api/soc/incidents/{id}/sla", s.rbac.Require(RoleViewer, s.handleIncidentSLA))
	mux.HandleFunc("GET /api/soc/sensors", s.rbac.Require(RoleViewer, s.handleSensors))
	mux.HandleFunc("GET /api/soc/clusters", s.rbac.Require(RoleViewer, s.handleClusters))
	mux.HandleFunc("GET /api/soc/rules", s.rbac.Require(RoleViewer, s.handleRules))
	mux.HandleFunc("GET /api/soc/killchain/{id}", s.rbac.Require(RoleViewer, s.handleKillChain))
	mux.HandleFunc("GET /api/soc/stream", s.rbac.Require(RoleViewer, s.handleSSEStream))
	mux.HandleFunc("GET /api/soc/threat-intel", s.rbac.Require(RoleAnalyst, s.handleThreatIntel))
	mux.HandleFunc("GET /api/soc/webhook-stats", s.rbac.Require(RoleAnalyst, s.handleWebhookStats))
	mux.HandleFunc("GET /api/soc/analytics", s.rbac.Require(RoleViewer, s.handleAnalytics))

	// SOC API routes — write (requires Analyst/Sensor role when RBAC enabled)
	mux.HandleFunc("POST /api/v1/soc/events", s.rbac.Require(RoleSensor, s.handleIngestEvent))
	mux.HandleFunc("POST /api/v1/soc/events/batch", s.rbac.Require(RoleSensor, s.handleBatchIngest))
	mux.HandleFunc("POST /api/soc/sensors/heartbeat", s.rbac.Require(RoleSensor, s.handleSensorHeartbeat))
	mux.HandleFunc("POST /api/soc/incidents/{id}/verdict", s.rbac.Require(RoleAnalyst, s.handleVerdict))
	// Case Management (SOAR §P3)
	mux.HandleFunc("POST /api/soc/incidents/{id}/assign", s.rbac.Require(RoleAnalyst, s.handleIncidentAssign))
	mux.HandleFunc("POST /api/soc/incidents/{id}/status", s.rbac.Require(RoleAnalyst, s.handleIncidentStatus))
	mux.HandleFunc("GET /api/soc/incidents/{id}/notes", s.rbac.Require(RoleViewer, s.handleIncidentNotes))
	mux.HandleFunc("POST /api/soc/incidents/{id}/notes", s.rbac.Require(RoleAnalyst, s.handleIncidentNotes))
	mux.HandleFunc("GET /api/soc/incidents/{id}/timeline", s.rbac.Require(RoleViewer, s.handleIncidentTimeline))
	mux.HandleFunc("GET /api/soc/incidents/{id}/detail", s.rbac.Require(RoleViewer, s.handleIncidentFullDetail))
	// Webhook Management (SOAR §15)
	mux.HandleFunc("GET /api/soc/webhooks", s.rbac.Require(RoleAnalyst, s.handleWebhooksGet))
	mux.HandleFunc("POST /api/soc/webhooks", s.rbac.Require(RoleAdmin, s.handleWebhooksSet))
	mux.HandleFunc("POST /api/soc/webhooks/test", s.rbac.Require(RoleAdmin, s.handleWebhooksTest))
	mux.HandleFunc("POST /api/soc/sensors/register", s.rbac.Require(RoleAdmin, s.handleSensorRegister))
	mux.HandleFunc("DELETE /api/soc/sensors/{id}", s.rbac.Require(RoleAdmin, s.handleSensorDelete))

	// Admin routes (§9, §17)
	mux.HandleFunc("GET /api/soc/audit", s.rbac.Require(RoleAdmin, s.handleAuditTrail))
	mux.HandleFunc("GET /api/soc/keys", s.rbac.Require(RoleAdmin, s.handleListKeys))

	// Zero-G Mode routes (§13.4)
	mux.HandleFunc("GET /api/soc/zerog", s.rbac.Require(RoleAnalyst, s.handleZeroGStatus))
	mux.HandleFunc("POST /api/soc/zerog/toggle", s.rbac.Require(RoleAdmin, s.handleZeroGToggle))
	mux.HandleFunc("POST /api/soc/zerog/resolve", s.rbac.Require(RoleAnalyst, s.handleZeroGResolve))

	// P2P SOC Sync routes (§14)
	mux.HandleFunc("GET /api/soc/p2p/peers", s.rbac.Require(RoleAnalyst, s.handleP2PPeers))
	mux.HandleFunc("POST /api/soc/p2p/peers", s.rbac.Require(RoleAdmin, s.handleP2PAddPeer))
	mux.HandleFunc("DELETE /api/soc/p2p/peers/{id}", s.rbac.Require(RoleAdmin, s.handleP2PRemovePeer))

	// Engine & Sovereign routes (§3, §4, §21)
	mux.HandleFunc("GET /api/soc/engines", s.rbac.Require(RoleViewer, s.handleEngineStatus))
	mux.HandleFunc("GET /api/soc/sovereign", s.rbac.Require(RoleAdmin, s.handleSovereignConfig))

	// Anomaly detection (§5) + Playbook engine (§10)
	mux.HandleFunc("GET /api/soc/anomaly/alerts", s.rbac.Require(RoleAnalyst, s.handleAnomalyAlerts))
	mux.HandleFunc("GET /api/soc/anomaly/baselines", s.rbac.Require(RoleAnalyst, s.handleAnomalyBaselines))
	mux.HandleFunc("GET /api/soc/playbooks", s.rbac.Require(RoleViewer, s.handlePlaybooks))

	// Live updates — WebSocket-style SSE push (§20)
	mux.HandleFunc("GET /api/soc/ws", s.rbac.Require(RoleViewer, s.wsHub.HandleSSEStream))

	// Deep health, compliance, audit, explainability (§12, §15)
	mux.HandleFunc("GET /api/soc/health/deep", s.rbac.Require(RoleViewer, s.handleDeepHealth))
	mux.HandleFunc("GET /api/soc/compliance", s.rbac.Require(RoleAdmin, s.handleComplianceReport))
	mux.HandleFunc("GET /api/soc/audit/trail", s.rbac.Require(RoleAnalyst, s.handleAuditTrailPage))
	mux.HandleFunc("GET /api/soc/incidents/{id}/explain", s.rbac.Require(RoleAnalyst, s.handleIncidentExplain))

	// Threat intel matching (§6) + Data retention (§19)
	mux.HandleFunc("POST /api/soc/threat-intel/match", s.rbac.Require(RoleAnalyst, s.handleThreatIntelMatch))
	mux.HandleFunc("GET /api/soc/retention", s.rbac.Require(RoleAdmin, s.handleRetentionPolicies))

	// Shadow AI Control Module routes (§Shadow AI ТЗ)
	mux.HandleFunc("GET /api/v1/shadow-ai/stats", s.rbac.Require(RoleViewer, s.handleShadowAIStats))
	mux.HandleFunc("GET /api/v1/shadow-ai/events", s.rbac.Require(RoleViewer, s.handleShadowAIEvents))
	mux.HandleFunc("GET /api/v1/shadow-ai/events/{id}", s.rbac.Require(RoleViewer, s.handleShadowAIEventDetail))
	mux.HandleFunc("POST /api/v1/shadow-ai/block", s.rbac.Require(RoleAnalyst, s.handleShadowAIBlock))
	mux.HandleFunc("POST /api/v1/shadow-ai/unblock", s.rbac.Require(RoleAnalyst, s.handleShadowAIUnblock))
	mux.HandleFunc("POST /api/v1/shadow-ai/scan", s.rbac.Require(RoleAnalyst, s.handleShadowAIScan))
	mux.HandleFunc("GET /api/v1/shadow-ai/integrations", s.rbac.Require(RoleViewer, s.handleShadowAIIntegrations))
	mux.HandleFunc("GET /api/v1/shadow-ai/integrations/{vendor}/health", s.rbac.Require(RoleViewer, s.handleShadowAIVendorHealth))
	mux.HandleFunc("GET /api/v1/shadow-ai/compliance", s.rbac.Require(RoleAdmin, s.handleShadowAICompliance))
	mux.HandleFunc("POST /api/v1/shadow-ai/doc-review", s.rbac.Require(RoleAnalyst, s.handleShadowAIDocReview))
	mux.HandleFunc("GET /api/v1/shadow-ai/doc-review/{id}", s.rbac.Require(RoleViewer, s.handleShadowAIDocReviewStatus))
	mux.HandleFunc("GET /api/v1/shadow-ai/approvals", s.rbac.Require(RoleAnalyst, s.handleShadowAIPendingApprovals))
	mux.HandleFunc("GET /api/v1/shadow-ai/approvals/tiers", s.rbac.Require(RoleViewer, s.handleShadowAIApprovalTiers))
	mux.HandleFunc("POST /api/v1/shadow-ai/approvals/{id}/verdict", s.rbac.Require(RoleAnalyst, s.handleShadowAIApprovalVerdict))

	// Observability — always public (unauthenticated, K8s probes)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /metrics", s.metrics.Handler())
	mux.HandleFunc("GET /api/soc/ratelimit", s.handleRateLimitStats)

	// Public scan endpoint — demo scanner (no auth required, rate-limited)
	mux.HandleFunc("POST /api/v1/scan", s.handlePublicScan)

	// pprof debug endpoints (§P4C) — gated behind EnablePprof()
	if s.pprofEnabled {
		mux.HandleFunc("GET /debug/pprof/", s.handlePprof)
		mux.HandleFunc("GET /debug/pprof/profile", s.handlePprofProfile)
		mux.HandleFunc("GET /debug/pprof/heap", s.handlePprofHeap)
		mux.HandleFunc("GET /debug/pprof/goroutine", s.handlePprofGoroutine)
		slog.Info("pprof endpoints enabled", "path", "/debug/pprof/")
	}

	// Auth routes — login/refresh are public (JWT middleware exempts these)
	if s.jwtAuth != nil {
		loginLimiter := auth.NewRateLimiter(5, time.Minute)
		mux.HandleFunc("POST /api/auth/login", auth.RateLimitMiddleware(loginLimiter, auth.HandleLogin(s.userStore, s.jwtSecret)))
		mux.HandleFunc("POST /api/auth/refresh", auth.HandleRefresh(s.jwtSecret))
		// Auth routes — require authentication
		mux.HandleFunc("GET /api/auth/me", auth.HandleMe(s.userStore))
		// User management (admin only)
		mux.HandleFunc("GET /api/auth/users", auth.HandleListUsers(s.userStore))
		mux.HandleFunc("POST /api/auth/users", auth.HandleCreateUser(s.userStore))
		mux.HandleFunc("PUT /api/auth/users/{id}", auth.HandleUpdateUser(s.userStore))
		mux.HandleFunc("DELETE /api/auth/users/{id}", auth.HandleDeleteUser(s.userStore))
		// API key management
		mux.HandleFunc("GET /api/auth/keys", auth.HandleListAPIKeys(s.userStore))
		mux.HandleFunc("POST /api/auth/keys", auth.HandleCreateAPIKey(s.userStore))
		mux.HandleFunc("DELETE /api/auth/keys/{id}", auth.HandleDeleteAPIKey(s.userStore))
		// Tenant management (§SaaS multi-tenancy)
		if s.tenantStore != nil {
			registrationLimiter := auth.NewRateLimiter(3, time.Minute)
			var emailFn auth.EmailSendFunc
			if s.emailService != nil {
				emailFn = s.emailService.SendVerificationCode
			}
			mux.HandleFunc("POST /api/auth/register", auth.RateLimitMiddleware(registrationLimiter, auth.HandleRegister(s.userStore, s.tenantStore, s.jwtSecret, emailFn)))
			mux.HandleFunc("POST /api/auth/verify", auth.RateLimitMiddleware(registrationLimiter, auth.HandleVerifyEmail(s.userStore, s.tenantStore, s.jwtSecret)))
			mux.HandleFunc("GET /api/auth/plans", auth.HandleListPlans())
			mux.HandleFunc("GET /api/auth/tenant", auth.HandleGetTenant(s.tenantStore))
			mux.HandleFunc("POST /api/auth/tenant/plan", auth.HandleUpdateTenantPlan(s.tenantStore))
			mux.HandleFunc("GET /api/auth/billing", auth.HandleBillingStatus(s.tenantStore))
			mux.HandleFunc("POST /api/billing/webhook", auth.HandleStripeWebhook(s.tenantStore))
		}
	}

	// Build middleware chain: Tracing → Logger → Metrics → Rate Limiter → Security → CORS → [JWT] → mux
	var handler http.Handler = mux
	if s.jwtAuth != nil {
		handler = s.jwtAuth.Middleware(handler)
	}
	handler = corsMiddleware(handler)
	handler = securityHeadersMiddleware(handler)
	handler = s.rateLimiter.Middleware(handler)
	handler = s.metrics.Middleware(handler)
	handler = s.logger.Middleware(handler)
	handler = tracing.HTTPMiddleware(handler)

	s.srv = &http.Server{
		Addr:              fmt.Sprintf(":%d", s.port),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// NOTE: WriteTimeout is intentionally 0 (disabled) to support SSE/WebSocket
		// long-lived connections. ReadHeaderTimeout protects against slowloris.
		// SSE keepalive (15s) ensures dead connections are detected.
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on context cancellation (applies to both TLS and plain HTTP).
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("HTTP server shutdown error", "error", err)
		}
	}()

	// Apply TLS if configured.
	if s.tlsCert != "" && s.tlsKey != "" {
		s.srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		}
		slog.Info("HTTPS API listening", "port", s.port, "cert", s.tlsCert, "min_version", "TLS1.2")
		if err := s.srv.ListenAndServeTLS(s.tlsCert, s.tlsKey); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("https server: %w", err)
		}
		return nil
	}

	slog.Info("HTTP API listening", "port", s.port)
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
		slog.Error("failed to encode response", "error", err)
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
