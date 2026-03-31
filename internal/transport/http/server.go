// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

// Package httpserver provides an HTTP API transport for GoMCP SOC dashboard.
//
// Zero CGO: Uses ONLY Go stdlib net/http (supports HTTP/2 natively).
// Backward compatible: disabled by default (--http-port 0).
package httpserver

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	shadowai "github.com/syntrex-lab/gomcp/internal/application/shadow_ai"
	appsoc "github.com/syntrex-lab/gomcp/internal/application/soc"
	"github.com/syntrex-lab/gomcp/internal/domain/engines"
	"github.com/syntrex-lab/gomcp/internal/infrastructure/auth"
	"github.com/syntrex-lab/gomcp/internal/infrastructure/email"
	"github.com/syntrex-lab/gomcp/internal/infrastructure/tracing"
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
	shieldEngine     engines.Shield
	jwtAuth          *auth.JWTMiddleware
	userStore        *auth.UserStore
	tenantStore      *auth.TenantStore
	emailService     *email.Service
	jwtSecret        []byte
	wsHub            *WSHub
	usageTracker     *auth.UsageTracker
	scanSem          chan struct{} // Limits concurrent CPU-heavy scans
	scanCache        map[string]*cachedScan
	scanCacheMu      sync.RWMutex
	sovereignEnabled bool
	sovereignMode    string
	pprofEnabled     bool
	port             int
	srv              *http.Server
	tlsCert          string
	tlsKey           string
	corsOrigins      []string
}

// cachedScan stores a cached scan result with expiry.
type cachedScan struct {
	response map[string]any
	expiry   time.Time
}

// promptHash returns a SHA-256 hash of the prompt for cache keying.
// T4-4 FIX: Uses full 256-bit hash (was truncated to 128-bit).
func promptHash(prompt string) string {
	h := sha256.Sum256([]byte(prompt))
	return hex.EncodeToString(h[:]) // Full 256-bit — no truncation
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
		scanSem:     make(chan struct{}, 6), // Max 6 concurrent scans (~2 per CPU)
		scanCache:   make(map[string]*cachedScan, 500),
		corsOrigins: []string{"http://localhost:3000", "https://syntrex.pro"}, // Default secure fallback
	}
}

// SetCORSOrigins configures the allowed origins for CORS strictly.
func (s *Server) SetCORSOrigins(origins []string) {
	if len(origins) > 0 {
		s.corsOrigins = origins
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

// SetShieldEngine sets the C-native Shield engine for payload inspection.
func (s *Server) SetShieldEngine(shield engines.Shield) {
	s.shieldEngine = shield
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

	// Seed demo tenant with read-only demo/demo account (idempotent)
	if s.tenantStore != nil && s.socSvc != nil {
		go auth.SeedDemoTenant(s.userStore, s.tenantStore, s.socSvc.Repo())
	}
}

// SetUsageTracker sets the usage/quota tracker for scan metering.
func (s *Server) SetUsageTracker(tracker *auth.UsageTracker) {
	s.usageTracker = tracker
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
					"id":          evt.ID,
					"source":      string(evt.Source),
					"severity":    string(evt.Severity),
					"category":    evt.Category,
					"description": evt.Description,
					"session_id":  evt.SessionID,
				})
			}
		}
	}()
	slog.Info("event bridge started: EventBus → WSHub")
}

// requireSOC wraps a handler to enforce SOC Dashboard plan access.
// Returns 403 for tenants on the Free plan (SOCEnabled=false).
// SEC: Also denies access when TenantID is empty — prevents data leak
// when tenant_id was not properly set during registration.
// No-op when tenantStore is nil (backward compatible with tests).
func (s *Server) requireSOC(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.tenantStore == nil {
			next(w, r) // no tenant store = no enforcement (tests, legacy)
			return
		}
		claims := auth.GetClaims(r.Context())
		if claims == nil {
			writeError(w, http.StatusUnauthorized, "authentication required for SOC access")
			return
		}
		if claims.TenantID == "" {
			// SEC: Empty TenantID = either tenant_id wasn't saved (pgx bug)
			// or user has no tenant. Block access to prevent cross-tenant leak.
			writeError(w, http.StatusForbidden,
				"no tenant context — re-login required. If this persists, contact support.")
			return
		}
		tenant, err := s.tenantStore.GetTenant(claims.TenantID)
		if err != nil {
			writeError(w, http.StatusForbidden, "tenant not found")
			return
		}
		if !tenant.CanAccessSOC() {
			writeError(w, http.StatusForbidden,
				"SOC Dashboard requires Starter plan or above — upgrade at syntrex.pro/pricing")
			return
		}
		next(w, r)
	}
}

// Start begins listening on the configured port. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// SOC API routes — read (requires Viewer role + SOC plan when RBAC/JWT enabled)
	mux.HandleFunc("GET /api/soc/dashboard", s.rbac.Require(RoleViewer, s.requireSOC(s.handleDashboard)))
	mux.HandleFunc("GET /api/soc/events", s.rbac.Require(RoleViewer, s.requireSOC(s.handleEvents)))
	mux.HandleFunc("GET /api/soc/incidents", s.rbac.Require(RoleViewer, s.requireSOC(s.handleIncidents)))
	// Sprint 2: Advanced incident management (must be before generic {id})
	mux.HandleFunc("GET /api/soc/incidents/advanced", s.rbac.Require(RoleViewer, s.requireSOC(s.handleIncidentsAdvanced)))
	mux.HandleFunc("POST /api/soc/incidents/bulk", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleIncidentsBulk)))
	mux.HandleFunc("GET /api/soc/incidents/export", s.rbac.Require(RoleViewer, s.requireSOC(s.handleIncidentsExport)))
	mux.HandleFunc("GET /api/soc/sla-config", s.rbac.Require(RoleViewer, s.requireSOC(s.handleSLAConfig)))
	mux.HandleFunc("GET /api/soc/incidents/{id}", s.rbac.Require(RoleViewer, s.requireSOC(s.handleIncidentDetail)))
	mux.HandleFunc("GET /api/soc/incidents/{id}/sla", s.rbac.Require(RoleViewer, s.requireSOC(s.handleIncidentSLA)))
	mux.HandleFunc("GET /api/soc/sensors", s.rbac.Require(RoleViewer, s.requireSOC(s.handleSensors)))
	mux.HandleFunc("GET /api/soc/clusters", s.rbac.Require(RoleViewer, s.requireSOC(s.handleClusters)))
	mux.HandleFunc("GET /api/soc/rules", s.rbac.Require(RoleViewer, s.requireSOC(s.handleRules)))
	mux.HandleFunc("GET /api/soc/killchain/{id}", s.rbac.Require(RoleViewer, s.requireSOC(s.handleKillChain)))
	mux.HandleFunc("GET /api/soc/stream", s.rbac.Require(RoleViewer, s.requireSOC(s.handleSSEStream)))
	mux.HandleFunc("GET /api/soc/threat-intel", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleThreatIntel)))
	mux.HandleFunc("GET /api/soc/webhook-stats", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleWebhookStats)))
	mux.HandleFunc("GET /api/soc/analytics", s.rbac.Require(RoleViewer, s.requireSOC(s.handleAnalytics)))

	// SOC API routes — write (requires Analyst/Sensor role + SOC plan when RBAC enabled)
	mux.HandleFunc("POST /api/v1/soc/events", s.rbac.Require(RoleSensor, s.requireSOC(s.handleIngestEvent)))
	mux.HandleFunc("POST /api/v1/soc/events/batch", s.rbac.Require(RoleSensor, s.requireSOC(s.handleBatchIngest)))
	mux.HandleFunc("POST /api/soc/sensors/heartbeat", s.rbac.Require(RoleSensor, s.requireSOC(s.handleSensorHeartbeat)))
	mux.HandleFunc("POST /api/soc/incidents/{id}/verdict", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleVerdict)))
	// Case Management (SOAR §P3)
	mux.HandleFunc("POST /api/soc/incidents/{id}/assign", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleIncidentAssign)))
	mux.HandleFunc("POST /api/soc/incidents/{id}/status", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleIncidentStatus)))
	mux.HandleFunc("GET /api/soc/incidents/{id}/notes", s.rbac.Require(RoleViewer, s.requireSOC(s.handleIncidentNotes)))
	mux.HandleFunc("POST /api/soc/incidents/{id}/notes", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleIncidentNotes)))
	mux.HandleFunc("GET /api/soc/incidents/{id}/timeline", s.rbac.Require(RoleViewer, s.requireSOC(s.handleIncidentTimeline)))
	mux.HandleFunc("GET /api/soc/incidents/{id}/detail", s.rbac.Require(RoleViewer, s.requireSOC(s.handleIncidentFullDetail)))
	// Webhook Management (SOAR §15)
	mux.HandleFunc("GET /api/soc/webhooks", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleWebhooksGet)))
	mux.HandleFunc("POST /api/soc/webhooks", s.rbac.Require(RoleAdmin, s.requireSOC(s.handleWebhooksSet)))
	mux.HandleFunc("POST /api/soc/webhooks/test", s.rbac.Require(RoleAdmin, s.requireSOC(s.handleWebhooksTest)))
	mux.HandleFunc("POST /api/soc/sensors/register", s.rbac.Require(RoleAdmin, s.requireSOC(s.handleSensorRegister)))
	mux.HandleFunc("DELETE /api/soc/sensors/{id}", s.rbac.Require(RoleAdmin, s.requireSOC(s.handleSensorDelete)))

	// Admin routes (§9, §17) — require SOC plan
	mux.HandleFunc("GET /api/soc/audit", s.rbac.Require(RoleAdmin, s.requireSOC(s.handleAuditTrail)))
	mux.HandleFunc("GET /api/soc/keys", s.rbac.Require(RoleAdmin, s.requireSOC(s.handleListKeys)))

	// Zero-G Mode routes (§13.4) — require SOC plan
	mux.HandleFunc("GET /api/soc/zerog", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleZeroGStatus)))
	mux.HandleFunc("POST /api/soc/zerog/toggle", s.rbac.Require(RoleAdmin, s.requireSOC(s.handleZeroGToggle)))
	mux.HandleFunc("POST /api/soc/zerog/resolve", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleZeroGResolve)))

	// P2P SOC Sync routes (§14) — require SOC plan
	mux.HandleFunc("GET /api/soc/p2p/peers", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleP2PPeers)))
	mux.HandleFunc("POST /api/soc/p2p/peers", s.rbac.Require(RoleAdmin, s.requireSOC(s.handleP2PAddPeer)))
	mux.HandleFunc("DELETE /api/soc/p2p/peers/{id}", s.rbac.Require(RoleAdmin, s.requireSOC(s.handleP2PRemovePeer)))

	// Engine & Sovereign routes (§3, §4, §21) — require SOC plan
	mux.HandleFunc("GET /api/soc/engines", s.rbac.Require(RoleViewer, s.requireSOC(s.handleEngineStatus)))
	mux.HandleFunc("GET /api/soc/sovereign", s.rbac.Require(RoleAdmin, s.requireSOC(s.handleSovereignConfig)))

	// Anomaly detection (§5) + Playbook engine (§10) — require SOC plan
	mux.HandleFunc("GET /api/soc/anomaly/alerts", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleAnomalyAlerts)))
	mux.HandleFunc("GET /api/soc/anomaly/baselines", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleAnomalyBaselines)))
	mux.HandleFunc("GET /api/soc/playbooks", s.rbac.Require(RoleViewer, s.requireSOC(s.handlePlaybooks)))

	// Live updates — WebSocket-style SSE push (§20) — require SOC plan
	mux.HandleFunc("GET /api/soc/ws", s.rbac.Require(RoleViewer, s.requireSOC(s.wsHub.HandleSSEStream)))

	// Deep health, compliance, audit, explainability (§12, §15) — require SOC plan
	mux.HandleFunc("GET /api/soc/health/deep", s.rbac.Require(RoleViewer, s.requireSOC(s.handleDeepHealth)))
	mux.HandleFunc("GET /api/soc/compliance", s.rbac.Require(RoleAdmin, s.requireSOC(s.handleComplianceReport)))
	mux.HandleFunc("GET /api/soc/audit/trail", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleAuditTrailPage)))
	mux.HandleFunc("GET /api/soc/incidents/{id}/explain", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleIncidentExplain)))

	// Threat intel matching (§6) + Data retention (§19) — require SOC plan
	mux.HandleFunc("POST /api/soc/threat-intel/match", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleThreatIntelMatch)))
	mux.HandleFunc("GET /api/soc/retention", s.rbac.Require(RoleAdmin, s.requireSOC(s.handleRetentionPolicies)))

	// Shadow AI Control Module routes (§Shadow AI ТЗ) — require SOC plan
	mux.HandleFunc("GET /api/v1/shadow-ai/stats", s.rbac.Require(RoleViewer, s.requireSOC(s.handleShadowAIStats)))
	mux.HandleFunc("GET /api/v1/shadow-ai/events", s.rbac.Require(RoleViewer, s.requireSOC(s.handleShadowAIEvents)))
	mux.HandleFunc("GET /api/v1/shadow-ai/events/{id}", s.rbac.Require(RoleViewer, s.requireSOC(s.handleShadowAIEventDetail)))
	mux.HandleFunc("POST /api/v1/shadow-ai/block", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleShadowAIBlock)))
	mux.HandleFunc("POST /api/v1/shadow-ai/unblock", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleShadowAIUnblock)))
	mux.HandleFunc("POST /api/v1/shadow-ai/scan", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleShadowAIScan)))
	mux.HandleFunc("GET /api/v1/shadow-ai/integrations", s.rbac.Require(RoleViewer, s.requireSOC(s.handleShadowAIIntegrations)))
	mux.HandleFunc("GET /api/v1/shadow-ai/integrations/{vendor}/health", s.rbac.Require(RoleViewer, s.requireSOC(s.handleShadowAIVendorHealth)))
	mux.HandleFunc("GET /api/v1/shadow-ai/compliance", s.rbac.Require(RoleAdmin, s.requireSOC(s.handleShadowAICompliance)))
	mux.HandleFunc("POST /api/v1/shadow-ai/doc-review", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleShadowAIDocReview)))
	mux.HandleFunc("GET /api/v1/shadow-ai/doc-review/{id}", s.rbac.Require(RoleViewer, s.requireSOC(s.handleShadowAIDocReviewStatus)))
	mux.HandleFunc("GET /api/v1/shadow-ai/approvals", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleShadowAIPendingApprovals)))
	mux.HandleFunc("GET /api/v1/shadow-ai/approvals/tiers", s.rbac.Require(RoleViewer, s.requireSOC(s.handleShadowAIApprovalTiers)))
	mux.HandleFunc("POST /api/v1/shadow-ai/approvals/{id}/verdict", s.rbac.Require(RoleAnalyst, s.requireSOC(s.handleShadowAIApprovalVerdict)))

	// Observability — always public (unauthenticated, K8s probes)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /metrics", s.metrics.Handler())
	mux.HandleFunc("GET /api/soc/ratelimit", s.handleRateLimitStats)

	// Public scan endpoint — demo scanner (no auth, rate-limited, plan-aware quota)
	mux.HandleFunc("POST /api/v1/scan", s.handlePublicScan)
	// Usage endpoint — returns scan quota for caller
	mux.HandleFunc("GET /api/v1/usage", s.handleUsage)
	// Waitlist endpoint — registration interest capture (no auth, rate-limited)
	mux.HandleFunc("POST /api/waitlist", s.handleWaitlist)

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
		mux.HandleFunc("POST /api/auth/logout", auth.HandleLogout())
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
			// Superadmin endpoints
			mux.HandleFunc("GET /api/auth/tenants", auth.HandleListTenants(s.tenantStore))
			mux.HandleFunc("POST /api/auth/impersonate", auth.HandleImpersonateTenant(s.tenantStore, s.jwtSecret))
			// Demo provisioning endpoint
			demolimiter := auth.NewRateLimiter(2, time.Minute)
			mux.HandleFunc("GET /api/auth/demo", auth.RateLimitMiddleware(demolimiter, auth.HandleDemo(s.userStore, s.tenantStore, s.jwtSecret)))
		}
	}

	// Build middleware chain: Tracing → Logger → Metrics → Rate Limiter → Security → CORS → [JWT] → mux
	var handler http.Handler = mux
	if s.jwtAuth != nil {
		handler = s.jwtAuth.Middleware(handler)
	}
	handler = corsMiddleware(s.corsOrigins)(handler)
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
		IdleTimeout: 120 * time.Second,
	}

	// Start SOC Demo Background Simulator
	go s.runDemoSimulator(ctx)

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
