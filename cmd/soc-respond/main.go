// Package main provides the SOC Respond process (SEC-001 Process Isolation).
//
// Responsibility: Receives incidents from soc-correlate via IPC,
// executes playbooks, dispatches webhooks, writes audit log.
//
// Network access: restricted to outbound HTTPS (webhook endpoints only).
//
// Usage:
//
//	go run ./cmd/soc-respond/
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"

	domsoc "github.com/syntrex-lab/gomcp/internal/domain/soc"
	"github.com/syntrex-lab/gomcp/internal/infrastructure/ipc"
	"github.com/syntrex-lab/gomcp/internal/infrastructure/logging"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			fmt.Fprintf(os.Stderr, "SOC-RESPOND FATAL PANIC: %v\n%s\n", r, buf[:n])
			os.Exit(2)
		}
	}()

	logger := logging.New(env("SOC_LOG_FORMAT", "text"), env("SOC_LOG_LEVEL", "info"))
	slog.SetDefault(logger)

	// SEC-003: Memory safety — respond process uses minimal RAM.
	if limitStr := os.Getenv("GOMEMLIMIT"); limitStr == "" {
		debug.SetMemoryLimit(128 * 1024 * 1024) // 128 MiB
	}

	logger.Info("starting SOC-RESPOND (SEC-001 isolated process)",
		"upstream_pipe", "soc-correlate-to-respond",
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Playbook engine for automated response.
	playbookEngine := domsoc.NewPlaybookEngine()

	// IPC: Listen for incidents from soc-correlate.
	listener, err := ipc.Listen("soc-correlate-to-respond")
	if err != nil {
		logger.Error("failed to listen", "error", err)
		os.Exit(1)
	}
	defer listener.Close()
	logger.Info("IPC listener ready", "pipe", "soc-correlate-to-respond")

	// Accept connections from correlate.
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logger.Error("accept failed", "error", err)
				continue
			}

			go handleCorrelateConnection(ctx, conn, playbookEngine, logger)
		}
	}()

	<-ctx.Done()
	logger.Info("SOC-RESPOND shutting down")
}

// handleCorrelateConnection processes incidents from soc-correlate.
func handleCorrelateConnection(
	ctx context.Context,
	conn net.Conn,
	playbookEngine *domsoc.PlaybookEngine,
	logger *slog.Logger,
) {
	defer conn.Close()
	receiver := ipc.NewReceiver(conn, "correlate")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := receiver.Next()
		if err == io.EOF {
			logger.Info("correlate connection closed")
			return
		}
		if err != nil {
			logger.Error("read incident", "error", err)
			continue
		}

		if msg.Type != ipc.SOCMsgIncident {
			continue
		}

		var incident domsoc.Incident
		if err := json.Unmarshal(msg.Payload, &incident); err != nil {
			logger.Error("unmarshal incident", "error", err)
			continue
		}

		logger.Info("incident received for response",
			"id", incident.ID,
			"severity", incident.Severity,
			"correlation_rule", incident.CorrelationRule,
		)

		// Execute matching playbooks.
		for _, pb := range playbookEngine.ListPlaybooks() {
			if pb.Enabled {
				logger.Info("executing playbook",
					"playbook", pb.ID,
					"incident", incident.ID,
				)
				for _, action := range pb.Actions {
					logger.Info("playbook action",
						"playbook", pb.ID,
						"action_type", action.Type,
						"params", action.Params,
					)
				}
			}
		}

		// TODO: Webhook dispatch (restricted to HTTPS only).
		// TODO: Audit log write.
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
