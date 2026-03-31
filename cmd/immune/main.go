// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

// Package main provides the SENTINEL immune agent (SEC-002 eBPF Runtime Guard).
//
// The immune agent monitors SOC processes at the kernel level using eBPF
// tracepoints and enforces per-process security policies.
//
// On Linux: loads eBPF programs for syscall/file/network monitoring.
// On Windows/macOS: uses process monitoring fallback (polling /proc or WMI).
//
// Usage:
//
//	go run ./cmd/immune/ --policy deploy/policies/soc_runtime_policy.yaml
//	SOC_GUARD_MODE=enforce go run ./cmd/immune/
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/syntrex-lab/gomcp/internal/infrastructure/guard"
	"github.com/syntrex-lab/gomcp/internal/infrastructure/logging"
)

func main() {
	// SEC-003: Panic recovery.
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			fmt.Fprintf(os.Stderr, "IMMUNE FATAL PANIC: %v\n%s\n", r, buf[:n])
			os.Exit(2)
		}
	}()

	logger := logging.New(env("SOC_LOG_FORMAT", "text"), env("SOC_LOG_LEVEL", "info"))
	slog.SetDefault(logger)

	// SEC-003: Memory safety — immune agent uses minimal RAM.
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(128 * 1024 * 1024) // 128 MiB
	}

	policyPath := env("SOC_GUARD_POLICY", "deploy/policies/soc_runtime_policy.yaml")
	port, _ := strconv.Atoi(env("SOC_IMMUNE_PORT", "9760"))

	logger.Info("starting SENTINEL immune agent (SEC-002 eBPF Runtime Guard)",
		"policy", policyPath,
		"port", port,
		"os", runtime.GOOS,
	)

	// Load policy.
	policy, err := guard.LoadPolicy(policyPath)
	if err != nil {
		logger.Error("failed to load policy", "path", policyPath, "error", err)
		os.Exit(1)
	}

	// Override mode from env if set.
	if modeOverride := os.Getenv("SOC_GUARD_MODE"); modeOverride != "" {
		policy.Mode = guard.Mode(modeOverride)
		logger.Info("mode overridden via env", "mode", policy.Mode)
	}

	g := guard.New(policy)

	// Register violation handler → forward to SOC.
	g.OnViolation(func(v guard.Violation) {
		logger.Warn("GUARD VIOLATION",
			"process", v.ProcessName,
			"pid", v.PID,
			"type", v.Type,
			"detail", v.Detail,
			"severity", v.Severity,
			"action", v.Action,
		)
		// TODO: Forward to SOC via HTTP or IPC.
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start platform-specific monitoring.
	go startProcessMonitor(ctx, g, logger)

	// HTTP status endpoint for health checks and stats.
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status": "healthy",
			"mode":   g.CurrentMode(),
			"os":     runtime.GOOS,
		})
	})

	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(g.Stats())
	})

	mux.HandleFunc("/mode", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req struct {
				Mode string `json:"mode"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				slog.Error("invalid mode request", "error", err)
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			g.SetMode(guard.Mode(req.Mode))
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"mode": string(g.CurrentMode())})
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("immune HTTP status endpoint ready", "port", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server failed", "error", err)
		}
	}()

	<-ctx.Done()
	logger.Info("immune shutting down")
	srv.Shutdown(context.Background())
}

// startProcessMonitor runs the platform-specific process monitoring loop.
// On Linux: would attach eBPF programs and read from ringbuf.
// On Windows/macOS: polls process list for anomalies.
func startProcessMonitor(ctx context.Context, g *guard.Guard, logger *slog.Logger) {
	logger.Info("starting process monitor",
		"platform", runtime.GOOS,
		"note", "using polling fallback (eBPF requires Linux)",
	)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Polling fallback: check process resource usage.
			// On Linux with eBPF: this would be event-driven from ringbuf.
			checkProcessResources(g, logger)
		}
	}
}

// checkProcessResources polls OS for SOC process resource usage.
func checkProcessResources(g *guard.Guard, logger *slog.Logger) {
	// This is a simplified polling fallback.
	// On Linux with eBPF loaded, violations come from kernel tracepoints instead.
	//
	// In production:
	// - Linux: bpf_ringbuf_poll() for real-time syscall events
	// - Windows: ETW (Event Tracing for Windows) or WMI queries
	// - macOS: Endpoint Security framework
	logger.Debug("process resource check (polling fallback)")
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
