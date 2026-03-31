// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

// GoMCP v2 — High-performance Go-native MCP server for the RLM Toolkit.
// Provides hierarchical persistent memory, cognitive state management,
// causal reasoning chains, and code crystal indexing.
//
// Usage:
//
//	gomcp [flags]
//	  -rlm-dir string    Path to .rlm directory (default ".rlm")
//	  -cache-path string  Path to bbolt cache file (default ".rlm/cache.db")
//	  -session string     Session ID for auto-restore (default "default")
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/server"

	"github.com/syntrex-lab/gomcp/internal/application/contextengine"
	"github.com/syntrex-lab/gomcp/internal/application/lifecycle"
	"github.com/syntrex-lab/gomcp/internal/application/orchestrator"
	"github.com/syntrex-lab/gomcp/internal/application/resources"
	appsoc "github.com/syntrex-lab/gomcp/internal/application/soc"
	"github.com/syntrex-lab/gomcp/internal/application/tools"
	"github.com/syntrex-lab/gomcp/internal/domain/alert"
	ctxdomain "github.com/syntrex-lab/gomcp/internal/domain/context"
	"github.com/syntrex-lab/gomcp/internal/domain/memory"
	"github.com/syntrex-lab/gomcp/internal/domain/oracle"
	"github.com/syntrex-lab/gomcp/internal/domain/peer"
	domsoc "github.com/syntrex-lab/gomcp/internal/domain/soc"
	"github.com/syntrex-lab/gomcp/internal/infrastructure/audit"
	"github.com/syntrex-lab/gomcp/internal/infrastructure/cache"
	"github.com/syntrex-lab/gomcp/internal/infrastructure/hardware"
	"github.com/syntrex-lab/gomcp/internal/infrastructure/ipc"
	onnxpkg "github.com/syntrex-lab/gomcp/internal/infrastructure/onnx"
	"github.com/syntrex-lab/gomcp/internal/infrastructure/sqlite"
	httpserver "github.com/syntrex-lab/gomcp/internal/transport/http"
	mcpserver "github.com/syntrex-lab/gomcp/internal/transport/mcpserver"
	"github.com/syntrex-lab/gomcp/internal/transport/tui"
)

func main() {
	rlmDir := flag.String("rlm-dir", ".rlm", "Path to .rlm directory")
	cachePath := flag.String("cache-path", "", "Path to bbolt cache file (default: <rlm-dir>/cache.db)")
	sessionID := flag.String("session", "default", "Session ID for auto-restore")
	noContext := flag.Bool("no-context", false, "Disable Proactive Context Engine")
	uiMode := flag.Bool("ui", false, "Launch TUI dashboard instead of MCP stdio server")
	unfiltered := flag.Bool("unfiltered", false, "Start in ZERO-G mode (ethical filters disabled, secret scanner active)")
	httpPort := flag.Int("http-port", 0, "HTTP API port for SOC dashboard (0 = disabled)")
	flag.Parse()

	if *cachePath == "" {
		*cachePath = filepath.Join(*rlmDir, "cache.db")
	}

	if err := run(*rlmDir, *cachePath, *sessionID, *noContext, *uiMode, *unfiltered, *httpPort); err != nil {
		fmt.Fprintf(os.Stderr, "gomcp: %v\n", err)
		os.Exit(1)
	}
}

func run(rlmDir, cachePath, sessionID string, noContext, uiMode, unfiltered bool, httpPort int) error {
	// --- Lifecycle manager for graceful shutdown ---

	lm := lifecycle.NewManager(10 * time.Second)

	// Ensure .rlm directory exists.
	memDir := filepath.Join(rlmDir, "memory")
	if err := os.MkdirAll(memDir, 0o755); err != nil {
		return fmt.Errorf("create memory dir: %w", err)
	}

	// --- Open databases ---

	factDB, err := sqlite.Open(filepath.Join(memDir, "memory_bridge_v2.db"))
	if err != nil {
		return fmt.Errorf("open fact db: %w", err)
	}
	lm.OnClose("fact-db", factDB)

	stateDB, err := sqlite.Open(filepath.Join(memDir, "memory_bridge.db"))
	if err != nil {
		return fmt.Errorf("open state db: %w", err)
	}
	lm.OnClose("state-db", stateDB)

	causalDB, err := sqlite.Open(filepath.Join(memDir, "causal_chains.db"))
	if err != nil {
		return fmt.Errorf("open causal db: %w", err)
	}
	lm.OnClose("causal-db", causalDB)

	crystalDB, err := sqlite.Open(filepath.Join(rlmDir, "crystals.db"))
	if err != nil {
		return fmt.Errorf("open crystal db: %w", err)
	}
	lm.OnClose("crystal-db", crystalDB)

	// --- Create repositories ---

	factRepo, err := sqlite.NewFactRepo(factDB)
	if err != nil {
		return fmt.Errorf("create fact repo: %w", err)
	}

	stateRepo, err := sqlite.NewStateRepo(stateDB)
	if err != nil {
		return fmt.Errorf("create state repo: %w", err)
	}

	causalRepo, err := sqlite.NewCausalRepo(causalDB)
	if err != nil {
		return fmt.Errorf("create causal repo: %w", err)
	}

	crystalRepo, err := sqlite.NewCrystalRepo(crystalDB)
	if err != nil {
		return fmt.Errorf("create crystal repo: %w", err)
	}

	// --- Genome Bootstrap (Hybrid: code-primary, genome.json-secondary) ---

	genomePath := filepath.Join(rlmDir, "genome.json")
	bootstrapped, bootstrapErr := memory.BootstrapGenome(context.Background(), factRepo, genomePath)
	if bootstrapErr != nil {
		log.Printf("WARNING: genome bootstrap failed: %v", bootstrapErr)
	} else if bootstrapped > 0 {
		log.Printf("Genome bootstrap: %d new genes inscribed", bootstrapped)
	} else {
		log.Printf("Genome bootstrap: all genes present (verified)")
	}

	// --- Early TUI Mode (Read-Only Observer) ---
	// If --ui is set, skip everything else (MCP, orchestrator, context engine).
	// Only needs factRepo for read-only SQLite access (WAL concurrent reader).
	// This is the "Eyes" of the node; the MCP server is the "Body".

	if uiMode {
		log.Printf("Starting TUI dashboard (read-only observer mode)...")

		// Initialize Oracle embedder for TUI status display.
		embedder := onnxpkg.NewEmbedderWithFallback(rlmDir)

		// Create alert bus and orchestrator for TUI.
		alertBus := alert.NewBus(100)
		peerReg := peer.NewRegistry("sentinel-ui", 30*time.Minute)
		orchCfg := orchestrator.DefaultConfig()
		orchCfg.HeartbeatInterval = 5 * time.Second // faster for TUI
		orch := orchestrator.NewWithAlerts(orchCfg, peerReg, factRepo, alertBus)

		// Start orchestrator for live alerts.
		orchCtx, orchCancel := context.WithCancel(context.Background())
		defer orchCancel()
		go orch.Start(orchCtx)

		// --- Soft Leash ---
		leashCfg := hardware.DefaultLeashConfig(rlmDir)
		leash := hardware.NewLeash(leashCfg, alertBus,
			func() { // onExtract: save & exit
				log.Printf("LEASH: Extraction — saving state and exiting")
				_ = lm.Shutdown()
				os.Exit(0)
			},
			func() { // onApoptosis: shred & exit
				log.Printf("LEASH: Full Apoptosis — shredding databases")
				tools.TriggerApoptosisRecovery(context.Background(), factRepo, 1.0)
				lifecycle.ShredAll(rlmDir)
				_ = lm.Shutdown()
				os.Exit(1)
			},
		)
		go leash.Start(orchCtx)

		// --- v3.2: Oracle Service + Mode Callback ---
		oracleSvc := oracle.NewService()
		if unfiltered {
			oracleSvc.SetMode(oracle.OModeZeroG)
			leashCfg2 := hardware.DefaultLeashConfig(rlmDir)
			os.WriteFile(leashCfg2.LeashPath, []byte("ZERO-G"), 0o644)
		}

		// Audit logger (Zero-G black box).
		auditLog, auditErr := audit.NewLogger(rlmDir)
		if auditErr != nil {
			log.Printf("WARNING: audit logger unavailable: %v", auditErr)
		}
		if auditLog != nil {
			lm.OnClose("audit-log", auditLog)
		}

		// Mode change callback → sync Oracle Service.
		var currentMode string = "ARMED"
		leash.SetModeChangeCallback(func(m hardware.SystemMode) {
			currentMode = m.String()
			switch m {
			case hardware.ModeZeroG:
				oracleSvc.SetMode(oracle.OModeZeroG)
				if auditLog != nil {
					auditLog.Log("MODE_TRANSITION", "ZERO-G activated")
				}
			case hardware.ModeSafe:
				oracleSvc.SetMode(oracle.OModeSafe)
			default:
				oracleSvc.SetMode(oracle.OModeArmed)
			}
		})
		_ = currentMode // used by TUI via closure

		// --- Virtual Swarm (IPC listener) ---
		swarmTransport := ipc.NewSwarmTransport(rlmDir, peerReg, factRepo, alertBus)
		go swarmTransport.Listen(orchCtx)

		tuiState := tui.State{
			Orchestrator: orch,
			Store:        factRepo,
			PeerReg:      peerReg,
			Embedder:     embedder,
			AlertBus:     alertBus,
			SystemMode:   currentMode,
		}

		err := tui.Start(tuiState)
		_ = lm.Shutdown()
		return err
	}

	// --- Create bbolt cache ---

	hotCache, err := cache.NewBoltCache(cachePath)
	if err != nil {
		log.Printf("WARNING: bbolt cache unavailable: %v (continuing without cache)", err)
		hotCache = nil
	}
	if hotCache != nil {
		lm.OnClose("bbolt-cache", hotCache)
	}

	// --- Create application services ---

	factSvc := tools.NewFactService(factRepo, hotCache)
	sessionSvc := tools.NewSessionService(stateRepo)
	causalSvc := tools.NewCausalService(causalRepo)
	crystalSvc := tools.NewCrystalService(crystalRepo)
	systemSvc := tools.NewSystemService(factRepo)
	resProv := resources.NewProvider(factRepo, stateRepo)

	// --- Auto-restore session ---

	if sessionID != "" {
		state, restored, err := sessionSvc.RestoreOrCreate(context.Background(), sessionID)
		if err != nil {
			log.Printf("WARNING: session restore failed: %v", err)
		} else if restored {
			log.Printf("Session %s restored (v%d)", state.SessionID, state.Version)
		} else {
			log.Printf("Session %s created (v%d)", state.SessionID, state.Version)
		}
	}

	// --- Register auto-save session on shutdown ---

	if sessionID != "" {
		lm.OnShutdown("auto-save-session", func(ctx context.Context) error {
			state, _, loadErr := sessionSvc.LoadState(ctx, sessionID, nil)
			if loadErr != nil {
				log.Printf("  auto-save: no session to save (%v)", loadErr)
				return nil // Not fatal.
			}
			state.BumpVersion()
			if saveErr := sessionSvc.SaveState(ctx, state); saveErr != nil {
				return fmt.Errorf("auto-save session: %w", saveErr)
			}
			log.Printf("  auto-save: session %s saved (v%d)", state.SessionID, state.Version)
			return nil
		})
	}

	// --- Warm L0 cache (needed for boot instructions, built later) ---

	l0Facts, l0Err := factSvc.GetL0Facts(context.Background())
	if l0Err != nil {
		log.Printf("WARNING: could not load L0 facts for boot instructions: %v", l0Err)
	}

	// --- Create Proactive Context Engine ---

	ctxProvider := contextengine.NewStoreFactProvider(factRepo, hotCache)
	ctxCfgPath := filepath.Join(rlmDir, "context.json")
	ctxCfg, err := contextengine.LoadConfig(ctxCfgPath)
	if err != nil {
		log.Printf("WARNING: invalid context config %s: %v (using defaults)", ctxCfgPath, err)
		ctxCfg = ctxdomain.DefaultEngineConfig()
	}

	// CLI override: -no-context disables the engine.
	if noContext {
		ctxCfg.Enabled = false
	}

	ctxEngine := contextengine.New(ctxCfg, ctxProvider)

	// --- Create interaction log (crash-safe tool call recording) ---
	// Reuses the fact DB (same WAL-mode SQLite) to avoid extra files.

	var lastSessionSummary string
	interactionRepo, err := sqlite.NewInteractionLogRepo(factDB)
	if err != nil {
		log.Printf("WARNING: interaction log unavailable: %v", err)
	} else {
		ctxEngine.SetInteractionLogger(interactionRepo)

		// --- Process unprocessed entries from previous session (memory loop) ---
		processor := contextengine.NewInteractionProcessor(interactionRepo, factRepo)
		summary, procErr := processor.ProcessStartup(context.Background())
		if procErr != nil {
			log.Printf("WARNING: failed to process previous session entries: %v", procErr)
		} else if summary != "" {
			lastSessionSummary = summary
			log.Printf("Processed previous session: %s", truncateLog(summary, 120))
		}

		// --- Register ProcessShutdown BEFORE auto-save-session ---
		// This ensures the current session's interactions are summarized before shutdown.
		lm.OnShutdown("process-interactions", func(ctx context.Context) error {
			shutdownSummary, shutdownErr := processor.ProcessShutdown(ctx)
			if shutdownErr != nil {
				log.Printf("  shutdown: interaction processing failed: %v", shutdownErr)
				return nil // Not fatal — don't block shutdown.
			}
			if shutdownSummary != "" {
				log.Printf("  shutdown: session summarized (%s)", truncateLog(shutdownSummary, 100))
			}
			return nil
		})
	}

	// Also check factStore for last session summary if we didn't get one from unprocessed entries.
	// This handles the case where the previous session shut down cleanly (entries already processed).
	if lastSessionSummary == "" {
		lastSessionSummary = contextengine.GetLastSessionSummary(context.Background(), factRepo)
	}

	// --- Build boot instructions (L0 facts + last session summary + agent instructions) ---

	bootInstructions := buildBootInstructions(l0Facts, lastSessionSummary)
	if bootInstructions != "" {
		log.Printf("Boot instructions: %d L0 facts, session_summary=%v (%d chars)",
			len(l0Facts), lastSessionSummary != "", len(bootInstructions))
	}

	var serverOpts []mcpserver.Option
	if ctxCfg.Enabled {
		serverOpts = append(serverOpts, mcpserver.WithContextEngine(ctxEngine))
		log.Printf("Proactive Context Engine enabled (budget=%d tokens, max_facts=%d, skip=%d tools)",
			ctxCfg.TokenBudget, ctxCfg.MaxFacts, len(ctxCfg.SkipTools))
	} else {
		log.Printf("Proactive Context Engine disabled")
	}

	// --- Initialize Oracle Embedder ---

	embedder := onnxpkg.NewEmbedderWithFallback(rlmDir)
	serverOpts = append(serverOpts, mcpserver.WithEmbedder(embedder))
	log.Printf("Oracle embedder: %s (mode=%s, dim=%d)",
		embedder.Name(), embedder.Mode(), embedder.Dimension())

	// --- SOC Service (v3.9: SENTINEL AI Security Operations Center) ---
	// Must be initialized BEFORE MCP server creation so WithSOCService
	// can inject it into the server's tool registration.

	socDB, err := sqlite.Open(filepath.Join(memDir, "soc.db"))
	if err != nil {
		return fmt.Errorf("open soc db: %w", err)
	}
	lm.OnClose("soc-db", socDB)

	socRepo, err := sqlite.NewSOCRepo(socDB)
	if err != nil {
		return fmt.Errorf("create soc repo: %w", err)
	}

	// Decision Logger — SHA-256 hash chain for tamper-evident SOC audit trail.
	socDecisionLogger, socLogErr := audit.NewDecisionLogger(rlmDir)
	if socLogErr != nil {
		log.Printf("WARNING: SOC decision logger unavailable: %v", socLogErr)
	}
	if socDecisionLogger != nil {
		lm.OnClose("soc-decision-logger", socDecisionLogger)
	}

	socSvc := appsoc.NewService(socRepo, socDecisionLogger)

	// Load custom correlation rules from YAML (§7.5).
	customRulesPath := filepath.Join(rlmDir, "soc_rules.yaml")
	customRules, rulesErr := domsoc.LoadRulesFromYAML(customRulesPath)
	if rulesErr != nil {
		log.Printf("WARNING: failed to load custom SOC rules: %v", rulesErr)
	} else if len(customRules) > 0 {
		socSvc.AddCustomRules(customRules)
		log.Printf("Loaded %d custom SOC correlation rules from %s", len(customRules), customRulesPath)
	}

	serverOpts = append(serverOpts, mcpserver.WithSOCService(socSvc))

	// Initialize Threat Intelligence with default IOC feeds (§6).
	threatIntelStore := appsoc.NewThreatIntelStore()
	threatIntelStore.AddDefaultFeeds()
	socSvc.SetThreatIntel(threatIntelStore)
	stopThreatIntel := make(chan struct{})
	threatIntelStore.StartBackgroundRefresh(30*time.Minute, stopThreatIntel)
	// Cleanup: stop refresh goroutine on shutdown.
	// (stopThreatIntel channel closed when main returns)

	log.Printf("SOC Service initialized (rules=%d, playbooks=3, clustering=enabled, threat_intel=enabled, decision_logger=%v)",
		7+len(customRules), socDecisionLogger != nil)

	// --- Create MCP server ---

	srv := mcpserver.New(
		mcpserver.Config{
			Name:         "gomcp",
			Version:      tools.Version,
			Instructions: bootInstructions,
		},
		factSvc, sessionSvc, causalSvc, crystalSvc, systemSvc, resProv,
		serverOpts...,
	)

	log.Printf("GoMCP v%s starting (stdio transport)", tools.Version)

	// --- Doctor Service (v3.7 Cerebro, v3.9 SOC) ---

	doctorSvc := tools.NewDoctorService(factDB.SqlDB(), rlmDir, factSvc)
	doctorSvc.SetEmbedderName(embedder.Name())
	doctorSvc.SetSOCChecker(&socDoctorAdapter{soc: socSvc})
	srv.SetDoctor(doctorSvc)
	log.Printf("Doctor service enabled (7 checks: Storage, Genome, Leash, Oracle, Permissions, Decisions, SOC)")

	// --- Start DIP Orchestrator (Heartbeat) ---

	peerReg := peer.NewRegistry("sentinel-mcp", 30*60*1e9) // 30 min timeout
	alertBus := alert.NewBus(100)
	orchCfg := orchestrator.DefaultConfig()
	orch := orchestrator.NewWithAlerts(orchCfg, peerReg, factRepo, alertBus)

	orchCtx, orchCancel := context.WithCancel(context.Background())
	go orch.Start(orchCtx)
	srv.SetOrchestrator(orch)
	log.Printf("DIP Orchestrator started (heartbeat=%s, jitter=±%d%%, entropy_threshold=%.2f)",
		orchCfg.HeartbeatInterval, orchCfg.JitterPercent, orchCfg.EntropyThreshold)

	// --- Soft Leash ---
	leashCfg := hardware.DefaultLeashConfig(rlmDir)
	leash := hardware.NewLeash(leashCfg, alertBus,
		func() { // onExtract: save & exit
			log.Printf("LEASH: Extraction — saving state and exiting")
			orchCancel()
			_ = lm.Shutdown()
			os.Exit(0)
		},
		func() { // onApoptosis: shred & exit
			log.Printf("LEASH: Full Apoptosis — shredding databases")
			tools.TriggerApoptosisRecovery(context.Background(), factRepo, 1.0)
			lifecycle.ShredAll(rlmDir)
			orchCancel()
			_ = lm.Shutdown()
			os.Exit(1)
		},
	)
	go leash.Start(orchCtx)
	log.Printf("Soft Leash started (key=%s, threshold=%ds)",
		leashCfg.KeyPath, leashCfg.MissThreshold)

	// --- v3.2: Oracle Service + Mode Callback ---
	oracleSvc := oracle.NewService()
	if unfiltered {
		oracleSvc.SetMode(oracle.OModeZeroG)
		os.WriteFile(leashCfg.LeashPath, []byte("ZERO-G"), 0o644)
		log.Printf("ZERO-G mode activated (--unfiltered)")
	}

	auditLog, auditErr := audit.NewLogger(rlmDir)
	if auditErr != nil {
		log.Printf("WARNING: audit logger unavailable: %v", auditErr)
	}
	if auditLog != nil {
		lm.OnClose("audit-log", auditLog)
	}

	leash.SetModeChangeCallback(func(m hardware.SystemMode) {
		switch m {
		case hardware.ModeZeroG:
			oracleSvc.SetMode(oracle.OModeZeroG)
			if auditLog != nil {
				auditLog.Log("MODE_TRANSITION", "ZERO-G activated")
			}
			log.Printf("System mode: ZERO-G")
		case hardware.ModeSafe:
			oracleSvc.SetMode(oracle.OModeSafe)
			log.Printf("System mode: SAFE")
		default:
			oracleSvc.SetMode(oracle.OModeArmed)
			log.Printf("System mode: ARMED")
		}
	})
	_ = oracleSvc // Available for future tool handlers.

	// --- Virtual Swarm (IPC dialer) ---
	swarmTransport := ipc.NewSwarmTransport(rlmDir, peerReg, factRepo, alertBus)
	go func() {
		// Try to connect to existing listener (TUI/daemon) once at startup.
		if synced, err := swarmTransport.Dial(orchCtx); err == nil && synced {
			log.Printf("Swarm: synced with local peer")
		}
	}()

	// --- HTTP API (Phase 11, §12.2) ---
	// Conditional: only starts if --http-port > 0 (backward compatible).
	if httpPort > 0 {
		httpSrv := httpserver.New(socSvc, httpPort)
		go func() {
			if err := httpSrv.Start(orchCtx); err != nil {
				log.Printf("HTTP server error: %v", err)
			}
		}()
		lm.OnShutdown("http-server", func(ctx context.Context) error {
			return httpSrv.Stop(ctx)
		})
		log.Printf("HTTP API enabled on :%d (endpoints: /api/soc/dashboard, /api/soc/events, /api/soc/incidents, /health)", httpPort)
	}

	// --- Signal handling for graceful shutdown ---

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServeStdio(srv.MCPServer())
	}()

	select {
	case sig := <-sigCh:
		log.Printf("Received signal %s, initiating graceful shutdown...", sig)
		orchCancel()
		_ = lm.Shutdown()
		return nil
	case err := <-errCh:
		// ServeStdio returned (stdin closed or error).
		orchCancel()
		_ = lm.Shutdown()
		return err
	}
}

// buildBootInstructions creates a compact text block from L0 (project-level) facts
// and the last session summary. Returned to the client in the MCP initialize response.
// This gives the LLM immediate context about the project and what happened last time
// without needing to call any tools first.
func buildBootInstructions(facts []*memory.Fact, lastSessionSummary string) string {
	var b strings.Builder

	// --- Agent identity & memory instructions ---
	b.WriteString("[AGENT INSTRUCTIONS]\n")
	b.WriteString("You are connected to GoMCP — a persistent memory server.\n")
	b.WriteString("You have PERSISTENT MEMORY across conversations. Key behaviors:\n")
	b.WriteString("- When starting a new topic, call search_facts to check what you already know.\n")
	b.WriteString("- When you learn something important, call add_fact to remember it for future sessions.\n")
	b.WriteString("- When you make a decision or discover a root cause, call add_causal_link to record the reasoning.\n")
	b.WriteString("- Context from relevant facts is automatically injected into tool responses.\n")
	b.WriteString("[/AGENT INSTRUCTIONS]\n\n")

	// --- Last session summary ---
	if lastSessionSummary != "" {
		b.WriteString("[LAST SESSION]\n")
		b.WriteString(lastSessionSummary)
		b.WriteString("\n[/LAST SESSION]\n\n")
	}

	// --- L0 project-level facts ---
	if len(facts) > 0 {
		b.WriteString("[PROJECT FACTS]\n")
		b.WriteString("The following project-level facts (L0) are always true:\n\n")

		count := 0
		for _, f := range facts {
			if f.IsStale || f.IsArchived {
				continue
			}
			b.WriteString(fmt.Sprintf("- %s", f.Content))
			if f.Domain != "" {
				b.WriteString(fmt.Sprintf(" [%s]", f.Domain))
			}
			b.WriteString("\n")
			count++

			// Cap at 50 facts to keep instructions under ~4k tokens
			if count >= 50 {
				b.WriteString(fmt.Sprintf("\n... and %d more L0 facts (use get_l0_facts tool to see all)\n", len(facts)-50))
				break
			}
		}
		b.WriteString("[/PROJECT FACTS]\n")
	}

	return b.String()
}

// truncateLog truncates a string for log output, adding "..." if it exceeds maxLen.
func truncateLog(s string, maxLen int) string {
	// Remove newlines for single-line log output.
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// socDoctorAdapter bridges appsoc.Service → tools.SOCHealthChecker interface.
// Lives in main to avoid circular import between application/tools and application/soc.
type socDoctorAdapter struct {
	soc *appsoc.Service
}

func (a *socDoctorAdapter) Dashboard() (tools.SOCDashboardData, error) {
	dash, err := a.soc.Dashboard("")
	if err != nil {
		return tools.SOCDashboardData{}, err
	}

	// Compute online/total sensors from SensorStatus map.
	var online, total int
	for status, count := range dash.SensorStatus {
		total += count
		if status == domsoc.SensorStatusHealthy {
			online += count
		}
	}

	return tools.SOCDashboardData{
		TotalEvents:      dash.TotalEvents,
		CorrelationRules: dash.CorrelationRules,
		Playbooks:        dash.ActivePlaybooks,
		ChainValid:       dash.ChainValid,
		SensorsOnline:    online,
		SensorsTotal:     total,
	}, nil
}
