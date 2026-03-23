// Package main provides the SOC Ingest process (SEC-001 Process Isolation).
//
// Responsibility: HTTP endpoint, authentication, secret scanner,
// rate limiting, dedup, SQLite persistence.
// Forwards persisted events to soc-correlate via IPC.
//
// Usage:
//
//	go run ./cmd/soc-ingest/
//	SOC_DB_PATH=/data/soc.db SOC_INGEST_PORT=9750 go run ./cmd/soc-ingest/
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"

	"github.com/syntrex/gomcp/internal/application/soc"
	"github.com/syntrex/gomcp/internal/infrastructure/audit"
	"github.com/syntrex/gomcp/internal/infrastructure/ipc"
	"github.com/syntrex/gomcp/internal/infrastructure/logging"
	"github.com/syntrex/gomcp/internal/infrastructure/sqlite"
	sochttp "github.com/syntrex/gomcp/internal/transport/http"
)

func main() {
	// SEC-003: Panic recovery.
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			fmt.Fprintf(os.Stderr, "SOC-INGEST FATAL PANIC: %v\n%s\n", r, buf[:n])
			os.Exit(2)
		}
	}()

	logger := logging.New(env("SOC_LOG_FORMAT", "text"), env("SOC_LOG_LEVEL", "info"))
	slog.SetDefault(logger)

	// SEC-003: Memory safety.
	if limitStr := os.Getenv("GOMEMLIMIT"); limitStr == "" {
		debug.SetMemoryLimit(256 * 1024 * 1024) // 256 MiB for ingest
	}

	port, _ := strconv.Atoi(env("SOC_INGEST_PORT", "9750"))
	dbPath := env("SOC_DB_PATH", "soc.db")

	logger.Info("starting SOC-INGEST (SEC-001 isolated process)",
		"port", port, "db", dbPath,
		"ipc_pipe", "soc-ingest-to-correlate",
	)

	// Infrastructure.
	db, err := sqlite.Open(dbPath)
	if err != nil {
		logger.Error("database open failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	socRepo, err := sqlite.NewSOCRepo(db)
	if err != nil {
		logger.Error("SOC repo init failed", "error", err)
		os.Exit(1)
	}

	decisionLogger, err := audit.NewDecisionLogger(env("SOC_AUDIT_DIR", "."))
	if err != nil {
		logger.Error("decision logger init failed", "error", err)
		os.Exit(1)
	}

	// Service (ingest-only mode).
	socSvc := soc.NewService(socRepo, decisionLogger)

	// IPC: Connect to downstream soc-correlate.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	correlateConn, err := ipc.DialWithRetry(ctx, "soc-ingest-to-correlate", 30)
	if err != nil {
		logger.Warn("soc-correlate not available — running in standalone ingest mode", "error", err)
	} else {
		ipcSender := ipc.NewBufferedSender(correlateConn, "soc-ingest-to-correlate")
		defer ipcSender.Close()

		// Subscribe to event bus and forward events via IPC.
		eventCh := socSvc.EventBus().Subscribe("ipc-forwarder")
		go func() {
			for event := range eventCh {
				msg, err := ipc.NewSOCMessage(ipc.SOCMsgEvent, event)
				if err != nil {
					logger.Error("ipc: marshal event", "error", err)
					continue
				}
				if err := ipcSender.Send(msg); err != nil {
					logger.Error("ipc: forward to correlate", "error", err)
				}
			}
		}()
		logger.Info("IPC connected to soc-correlate", "pending_buffer", ipc.BufferSize)
	}

	// HTTP server (ingest endpoints only).
	srv := sochttp.New(socSvc, port)

	// JWT auth.
	if jwtSecret := env("SOC_JWT_SECRET", ""); jwtSecret != "" {
		srv.SetJWTAuth([]byte(jwtSecret))
	}

	logger.Info("SOC-INGEST ready", "port", port)
	if err := srv.Start(ctx); err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
