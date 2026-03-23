// Package main provides the standalone SOC API server entry point.
//
// Usage:
//
//	go run ./cmd/soc/
//	SOC_DB_PATH=/data/soc.db SOC_PORT=9100 go run ./cmd/soc/
//	SOC_DB_DRIVER=postgres SOC_DB_DSN=postgres://sentinel:pass@localhost:5432/soc go run ./cmd/soc/
//
// SEC-003 Memory Safety: set GOMEMLIMIT, SOC_GOMAXPROCS for runtime hardening.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"

	"github.com/syntrex/gomcp/internal/application/soc"
	socdomain "github.com/syntrex/gomcp/internal/domain/soc"
	"github.com/syntrex/gomcp/internal/infrastructure/audit"
	"github.com/syntrex/gomcp/internal/infrastructure/email"
	"github.com/syntrex/gomcp/internal/infrastructure/logging"
	"github.com/syntrex/gomcp/internal/infrastructure/postgres"
	"github.com/syntrex/gomcp/internal/infrastructure/sqlite"
	"github.com/syntrex/gomcp/internal/infrastructure/tracing"
	sochttp "github.com/syntrex/gomcp/internal/transport/http"
)

func main() {
	// SEC-003: Top-level panic recovery — log stack trace before crash.
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			fmt.Fprintf(os.Stderr, "SENTINEL SOC FATAL PANIC: %v\n%s\n", r, buf[:n])
			os.Exit(2)
		}
	}()

	// Structured logger: JSON for production, text for dev.
	logFormat := env("SOC_LOG_FORMAT", "text")
	logLevel := env("SOC_LOG_LEVEL", "info")
	logger := logging.New(logFormat, logLevel)
	slog.SetDefault(logger)

	// SEC-003: Go runtime memory safety hardening.
	configureMemorySafety(logger)

	portStr := env("SOC_PORT", "9100")
	dbPath := env("SOC_DB_PATH", "soc.db")
	auditDir := env("SOC_AUDIT_DIR", ".")

	port, err := strconv.Atoi(portStr)
	if err != nil {
		logger.Error("invalid port", "port", portStr, "error", err)
		os.Exit(1)
	}

	logger.Info("starting SENTINEL SOC API",
		"port", port,
		"db", dbPath,
		"log_format", logFormat,
		"log_level", logLevel,
	)

	// Infrastructure — database driver selection.
	dbDriver := env("SOC_DB_DRIVER", "sqlite")
	dbDSN := env("SOC_DB_DSN", "")

	var socRepo socdomain.SOCRepository
	var dbCloser func() error
	var sqlDB interface{} // raw DB reference for auth user store

	switch dbDriver {
	case "postgres":
		if dbDSN == "" {
			logger.Error("SOC_DB_DSN required for postgres driver")
			os.Exit(1)
		}
		pgDB, err := postgres.Open(dbDSN, logger)
		if err != nil {
			logger.Error("PostgreSQL open failed", "error", err)
			os.Exit(1)
		}
		dbCloser = pgDB.Close
		socRepo = postgres.NewSOCRepo(pgDB)
		sqlDB = pgDB.Pool() // pass PG pool to auth user/tenant stores
		logger.Info("using PostgreSQL backend")
	default: // "sqlite"
		db, err := sqlite.Open(dbPath)
		if err != nil {
			logger.Error("database open failed", "path", dbPath, "error", err)
			os.Exit(1)
		}
		dbCloser = db.Close
		sqlDB = db // save for auth
		repo, err := sqlite.NewSOCRepo(db)
		if err != nil {
			logger.Error("SOC repo init failed", "error", err)
			os.Exit(1)
		}
		socRepo = repo
		logger.Info("using SQLite backend", "path", dbPath)
	}
	defer dbCloser()

	decisionLogger, err := audit.NewDecisionLogger(auditDir)
	if err != nil {
		logger.Error("decision logger init failed", "error", err)
		os.Exit(1)
	}

	// Service + HTTP
	socSvc := soc.NewService(socRepo, decisionLogger)
	srv := sochttp.New(socSvc, port)

	// Threat Intelligence Store — always initialized for IOC enrichment (§6)
	threatIntelStore := soc.NewThreatIntelStore()
	threatIntelStore.AddDefaultFeeds()
	socSvc.SetThreatIntel(threatIntelStore)
	srv.SetThreatIntel(threatIntelStore)

	// JWT Authentication (optional — set SOC_JWT_SECRET to enable)
	if jwtSecret := env("SOC_JWT_SECRET", ""); jwtSecret != "" {
		if db, ok := sqlDB.(*sql.DB); ok {
			srv.SetJWTAuth([]byte(jwtSecret), db)
		} else {
			srv.SetJWTAuth([]byte(jwtSecret))
		}
		logger.Info("JWT authentication configured")
	}

	// Email service — Resend (set RESEND_API_KEY to enable real email delivery)
	if resendKey := env("RESEND_API_KEY", ""); resendKey != "" {
		fromAddr := env("EMAIL_FROM", "SYNTREX <noreply@xn--80akacl3adqr.xn--p1acf>")
		resendSender := email.NewResendSender(resendKey, fromAddr)
		emailSvc := email.NewService(resendSender, "SYNTREX", fromAddr)
		srv.SetEmailService(emailSvc)
		logger.Info("email service configured", "provider", "Resend", "from", fromAddr)
	} else {
		logger.Warn("email service: RESEND_API_KEY not set — verification codes shown in API response (dev mode)")
	}

	// OpenTelemetry tracing (§P4B) — enabled when OTEL_EXPORTER_OTLP_ENDPOINT is set
	otelEndpoint := env("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	tp, otelErr := tracing.InitTracer(context.Background(), otelEndpoint)
	if otelErr != nil {
		logger.Error("tracing init failed", "error", otelErr)
	}

	// Graceful shutdown via context
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer tracing.Shutdown(ctx, tp)

	// STIX/TAXII Feed Sync (§P4A) — auto-enabled when OTX key is set
	if otxKey := env("SOC_OTX_API_KEY", ""); otxKey != "" {
		otxFeed := soc.DefaultOTXFeed(otxKey)
		feedSync := soc.NewFeedSync(threatIntelStore, []soc.STIXFeedConfig{otxFeed})
		feedSync.Start(ctx.Done())
		logger.Info("STIX feed sync started", "feeds", 1, "feed", otxFeed.Name)
	}

	// Start background retention scheduler (§19)
	socSvc.StartRetentionScheduler(ctx, 0) // 0 = default 1 hour

	// pprof profiling (§P4C) — enabled by SOC_PPROF=true
	if env("SOC_PPROF", "") == "true" {
		srv.EnablePprof()
	}

	logger.Info("server ready", "endpoints", 49, "dashboard_pages", 20)
	if err := srv.Start(ctx); err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
	logger.Info("server stopped")
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// configureMemorySafety applies SEC-003 runtime hardening:
// - GOMEMLIMIT: soft memory limit (default 450MiB) to avoid OOM kills
// - SOC_GOMAXPROCS: restrict CPU parallelism
// - Logs runtime memory stats at startup for diagnostics.
func configureMemorySafety(logger *slog.Logger) {
	// GOMEMLIMIT: set soft memory limit via env var.
	// Format: integer bytes, or use Go's debug.SetMemoryLimit default parsing.
	if limitStr := os.Getenv("GOMEMLIMIT"); limitStr == "" {
		// Default: 450 MiB (90% of typical 512Mi container limit).
		const defaultLimit = 450 * 1024 * 1024
		debug.SetMemoryLimit(defaultLimit)
		logger.Info("SEC-003: GOMEMLIMIT set", "limit_mib", 450, "source", "default")
	} else {
		// When GOMEMLIMIT env var is set, Go runtime handles it automatically.
		logger.Info("SEC-003: GOMEMLIMIT from env", "value", limitStr)
	}

	// SOC_GOMAXPROCS: optional CPU limit (useful in containers).
	if maxProcs := os.Getenv("SOC_GOMAXPROCS"); maxProcs != "" {
		if n, err := strconv.Atoi(maxProcs); err == nil && n > 0 {
			prev := runtime.GOMAXPROCS(n)
			logger.Info("SEC-003: GOMAXPROCS set", "new", n, "previous", prev)
		}
	}

	// Log runtime info for diagnostics.
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	logger.Info("SEC-003: runtime memory stats",
		"go_version", runtime.Version(),
		"num_cpu", runtime.NumCPU(),
		"gomaxprocs", runtime.GOMAXPROCS(0),
		"heap_alloc_mib", m.HeapAlloc/1024/1024,
		"sys_mib", m.Sys/1024/1024,
	)
}

