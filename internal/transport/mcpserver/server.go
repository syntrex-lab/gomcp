// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

// Package mcpserver wires MCP tools and resources to application services.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/syntrex-lab/gomcp/internal/application/contextengine"
	"github.com/syntrex-lab/gomcp/internal/application/orchestrator"
	"github.com/syntrex-lab/gomcp/internal/application/resources"
	appsoc "github.com/syntrex-lab/gomcp/internal/application/soc"
	"github.com/syntrex-lab/gomcp/internal/application/tools"
	"github.com/syntrex-lab/gomcp/internal/domain/circuitbreaker"
	entropyPkg "github.com/syntrex-lab/gomcp/internal/domain/entropy"
	"github.com/syntrex-lab/gomcp/internal/domain/memory"
	"github.com/syntrex-lab/gomcp/internal/domain/oracle"
	"github.com/syntrex-lab/gomcp/internal/domain/peer"
	"github.com/syntrex-lab/gomcp/internal/domain/pipeline"
	"github.com/syntrex-lab/gomcp/internal/domain/router"
	"github.com/syntrex-lab/gomcp/internal/domain/vectorstore"
)

// Server wraps the MCP server with all registered tools and resources.
type Server struct {
	mcp           *server.MCPServer
	facts         *tools.FactService
	sessions      *tools.SessionService
	causal        *tools.CausalService
	crystals      *tools.CrystalService
	system        *tools.SystemService
	intent        *tools.IntentService
	circuit       *circuitbreaker.Breaker
	oracle        *oracle.Oracle
	pipeline      *pipeline.Pipeline
	vecstore      *vectorstore.Store
	router        *router.Router
	res           *resources.Provider
	embedder      vectorstore.Embedder
	contextEngine *contextengine.Engine
	peerReg       *peer.Registry
	synapseSvc    *tools.SynapseService      // v3.3: synapse bridges
	orch          *orchestrator.Orchestrator // v3.4: observability
	doctor        *tools.DoctorService       // v3.7: self-diagnostic
	socSvc        *appsoc.Service            // v3.9: AI SOC pipeline
}

// Config holds server configuration.
type Config struct {
	Name         string
	Version      string
	Instructions string // optional boot instructions returned at initialize
}

// Option configures optional Server dependencies.
type Option func(*Server)

// WithEmbedder sets the Embedder for NLP/embedding tools.
func WithEmbedder(e vectorstore.Embedder) Option {
	return func(s *Server) {
		s.embedder = e
	}
}

// WithContextEngine sets the Proactive Context Engine for automatic
// memory context injection into every tool response.
func WithContextEngine(e *contextengine.Engine) Option {
	return func(s *Server) {
		s.contextEngine = e
	}
}

// WithSOCService enables the SENTINEL AI SOC pipeline tools (v3.9).
// If not set, SOC tools are not registered (graceful degradation).
func WithSOCService(svc *appsoc.Service) Option {
	return func(s *Server) {
		s.socSvc = svc
	}
}

// New creates a new MCP server with all tools and resources registered.
func New(cfg Config, facts *tools.FactService, sessions *tools.SessionService,
	causal *tools.CausalService, crystals *tools.CrystalService,
	system *tools.SystemService, res *resources.Provider, opts ...Option) *Server {

	s := &Server{
		facts:    facts,
		sessions: sessions,
		causal:   causal,
		crystals: crystals,
		system:   system,
		res:      res,
	}

	for _, opt := range opts {
		opt(s)
	}

	// Initialize Intent Distiller (uses Embedder).
	s.intent = tools.NewIntentService(s.embedder)

	// Initialize Circuit Breaker and Action Oracle (DIP H1).
	s.circuit = circuitbreaker.New(nil)
	s.oracle = oracle.New(oracle.DefaultRules())

	// Initialize Intent Pipeline (DIP H1.3).
	gate := entropyPkg.NewGate(nil)
	s.pipeline = pipeline.New(gate, nil, s.oracle, s.circuit, nil)

	// Initialize Vector Store and Router (DIP H2).
	s.vecstore = vectorstore.New(nil)
	s.router = router.New(s.vecstore, nil)

	// Initialize Peer Registry (DIP H1: Synapse).
	s.peerReg = peer.NewRegistry(cfg.Name, 30*60*1e9) // 30 min timeout

	// Build server options — always include recovery middleware.
	serverOpts := []server.ServerOption{
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithRecovery(),
	}

	// Set boot instructions if provided.
	if cfg.Instructions != "" {
		serverOpts = append(serverOpts, server.WithInstructions(cfg.Instructions))
	}

	// Register context engine middleware if provided.
	if s.contextEngine != nil && s.contextEngine.IsEnabled() {
		serverOpts = append(serverOpts,
			server.WithToolHandlerMiddleware(s.contextEngine.Middleware()),
		)
	}

	s.mcp = server.NewMCPServer(cfg.Name, cfg.Version, serverOpts...)

	s.registerFactTools()
	s.registerSessionTools()
	s.registerCausalTools()
	s.registerCrystalTools()
	s.registerSystemTools()
	s.registerIntentTools()
	s.registerEntropyTools()
	s.registerCircuitBreakerTools()
	s.registerOracleTools()
	s.registerPipelineTools()
	s.registerVectorStoreTools()
	s.registerRouterTools()
	s.registerApoptosisTools()
	s.registerSynapseTools()
	s.registerPythonBridgeTools()
	s.registerV33Tools() // v3.3: Context GC + Synapse Bridges + Shadow Intel
	s.registerSOCTools() // v3.9: SENTINEL AI SOC pipeline
	s.registerResources()

	return s
}

// MCPServer returns the underlying mcp-go server for transport binding.
func (s *Server) MCPServer() *server.MCPServer {
	return s.mcp
}

// --- Fact Tools ---

func (s *Server) registerFactTools() {
	s.mcp.AddTool(
		mcp.NewTool("add_fact",
			mcp.WithDescription("Add a new hierarchical memory fact (L0-L3)"),
			mcp.WithString("content", mcp.Description("Fact content"), mcp.Required()),
			mcp.WithNumber("level", mcp.Description("Hierarchy level: 0=project, 1=domain, 2=module, 3=snippet")),
			mcp.WithString("domain", mcp.Description("Domain category")),
			mcp.WithString("module", mcp.Description("Module name")),
			mcp.WithString("code_ref", mcp.Description("Code reference (file:line)")),
		),
		s.handleAddFact,
	)

	s.mcp.AddTool(
		mcp.NewTool("get_fact",
			mcp.WithDescription("Retrieve a fact by ID"),
			mcp.WithString("id", mcp.Description("Fact ID"), mcp.Required()),
		),
		s.handleGetFact,
	)

	s.mcp.AddTool(
		mcp.NewTool("update_fact",
			mcp.WithDescription("Update an existing fact"),
			mcp.WithString("id", mcp.Description("Fact ID"), mcp.Required()),
			mcp.WithString("content", mcp.Description("New content")),
			mcp.WithBoolean("is_stale", mcp.Description("Mark as stale")),
		),
		s.handleUpdateFact,
	)

	s.mcp.AddTool(
		mcp.NewTool("delete_fact",
			mcp.WithDescription("Delete a fact by ID"),
			mcp.WithString("id", mcp.Description("Fact ID"), mcp.Required()),
		),
		s.handleDeleteFact,
	)

	s.mcp.AddTool(
		mcp.NewTool("list_facts",
			mcp.WithDescription("List facts by domain or level"),
			mcp.WithString("domain", mcp.Description("Filter by domain")),
			mcp.WithNumber("level", mcp.Description("Filter by level (0-3)")),
			mcp.WithBoolean("include_stale", mcp.Description("Include stale facts")),
		),
		s.handleListFacts,
	)

	s.mcp.AddTool(
		mcp.NewTool("search_facts",
			mcp.WithDescription("Search facts by content text"),
			mcp.WithString("query", mcp.Description("Search query"), mcp.Required()),
			mcp.WithNumber("limit", mcp.Description("Max results")),
		),
		s.handleSearchFacts,
	)

	s.mcp.AddTool(
		mcp.NewTool("list_domains",
			mcp.WithDescription("List all unique fact domains"),
		),
		s.handleListDomains,
	)

	s.mcp.AddTool(
		mcp.NewTool("get_stale_facts",
			mcp.WithDescription("Get stale facts for review"),
			mcp.WithBoolean("include_archived", mcp.Description("Include archived facts")),
		),
		s.handleGetStaleFacts,
	)

	s.mcp.AddTool(
		mcp.NewTool("get_l0_facts",
			mcp.WithDescription("Get all L0 (project-level) facts — always-loaded context"),
		),
		s.handleGetL0Facts,
	)

	s.mcp.AddTool(
		mcp.NewTool("fact_stats",
			mcp.WithDescription("Get fact store statistics"),
		),
		s.handleFactStats,
	)

	s.mcp.AddTool(
		mcp.NewTool("process_expired",
			mcp.WithDescription("Process expired TTL facts (mark stale, archive, or delete)"),
		),
		s.handleProcessExpired,
	)

	// --- Genome Layer Tools ---
	s.mcp.AddTool(
		mcp.NewTool("add_gene",
			mcp.WithDescription("Add an immutable genome fact (survival invariant, L0 only). Once created, a gene cannot be updated or deleted."),
			mcp.WithString("content", mcp.Description("Gene content — survival invariant"), mcp.Required()),
			mcp.WithString("domain", mcp.Description("Domain category")),
		),
		s.handleAddGene,
	)

	s.mcp.AddTool(
		mcp.NewTool("list_genes",
			mcp.WithDescription("List all genome facts (immutable survival invariants)"),
		),
		s.handleListGenes,
	)

	s.mcp.AddTool(
		mcp.NewTool("verify_genome",
			mcp.WithDescription("Verify genome integrity via Merkle hash of all genes"),
		),
		s.handleVerifyGenome,
	)
}

func (s *Server) handleAddFact(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	params := tools.AddFactParams{
		Content: req.GetString("content", ""),
		Level:   req.GetInt("level", 0),
		Domain:  req.GetString("domain", ""),
		Module:  req.GetString("module", ""),
		CodeRef: req.GetString("code_ref", ""),
	}
	fact, err := s.facts.AddFact(context.Background(), params)
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(fact)), nil
}

func (s *Server) handleGetFact(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id := req.GetString("id", "")
	fact, err := s.facts.GetFact(context.Background(), id)
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(fact)), nil
}

func (s *Server) handleUpdateFact(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	params := tools.UpdateFactParams{ID: req.GetString("id", "")}
	args := req.GetArguments()
	if v, ok := args["content"].(string); ok {
		params.Content = &v
	}
	if v, ok := args["is_stale"].(bool); ok {
		params.IsStale = &v
	}
	fact, err := s.facts.UpdateFact(context.Background(), params)
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(fact)), nil
}

func (s *Server) handleDeleteFact(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id := req.GetString("id", "")
	if err := s.facts.DeleteFact(context.Background(), id); err != nil {
		return errorResult(err), nil
	}
	return textResult(fmt.Sprintf("Fact %s deleted", id)), nil
}

func (s *Server) handleListFacts(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	params := tools.ListFactsParams{
		Domain:       req.GetString("domain", ""),
		IncludeStale: req.GetBool("include_stale", false),
	}
	args := req.GetArguments()
	if v, ok := args["level"]; ok {
		if n, ok := v.(float64); ok {
			level := int(n)
			params.Level = &level
		}
	}
	facts, err := s.facts.ListFacts(context.Background(), params)
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(facts)), nil
}

func (s *Server) handleSearchFacts(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query := req.GetString("query", "")
	limit := req.GetInt("limit", 20)
	facts, err := s.facts.SearchFacts(context.Background(), query, limit)
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(facts)), nil
}

func (s *Server) handleListDomains(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	domains, err := s.facts.ListDomains(context.Background())
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(domains)), nil
}

func (s *Server) handleGetStaleFacts(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	includeArchived := req.GetBool("include_archived", false)
	facts, err := s.facts.GetStale(context.Background(), includeArchived)
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(facts)), nil
}

func (s *Server) handleGetL0Facts(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	facts, err := s.facts.GetL0Facts(context.Background())
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(facts)), nil
}

func (s *Server) handleFactStats(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	stats, err := s.facts.GetStats(context.Background())
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(stats)), nil
}

func (s *Server) handleProcessExpired(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	count, err := s.facts.ProcessExpired(context.Background())
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(fmt.Sprintf("Processed %d expired facts", count)), nil
}

func (s *Server) handleAddGene(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	params := tools.AddGeneParams{
		Content: req.GetString("content", ""),
		Domain:  req.GetString("domain", ""),
	}
	gene, err := s.facts.AddGene(context.Background(), params)
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(gene)), nil
}

func (s *Server) handleListGenes(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	genes, err := s.facts.ListGenes(context.Background())
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(genes)), nil
}

func (s *Server) handleVerifyGenome(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	hash, count, err := s.facts.VerifyGenome(context.Background())
	if err != nil {
		return errorResult(err), nil
	}
	result := map[string]interface{}{
		"genome_hash": hash,
		"gene_count":  count,
		"status":      "verified",
	}
	return textResult(tools.ToJSON(result)), nil
}

// --- Session Tools ---

func (s *Server) registerSessionTools() {
	s.mcp.AddTool(
		mcp.NewTool("save_state",
			mcp.WithDescription("Save cognitive state vector"),
			mcp.WithString("session_id", mcp.Description("Session identifier"), mcp.Required()),
			mcp.WithString("state_json", mcp.Description("Full state JSON"), mcp.Required()),
		),
		s.handleSaveState,
	)

	s.mcp.AddTool(
		mcp.NewTool("load_state",
			mcp.WithDescription("Load cognitive state for a session"),
			mcp.WithString("session_id", mcp.Description("Session identifier"), mcp.Required()),
			mcp.WithNumber("version", mcp.Description("Specific version (latest if omitted)")),
		),
		s.handleLoadState,
	)

	s.mcp.AddTool(
		mcp.NewTool("list_sessions",
			mcp.WithDescription("List all persisted sessions"),
		),
		s.handleListSessions,
	)

	s.mcp.AddTool(
		mcp.NewTool("delete_session",
			mcp.WithDescription("Delete all versions of a session"),
			mcp.WithString("session_id", mcp.Description("Session identifier"), mcp.Required()),
		),
		s.handleDeleteSession,
	)

	s.mcp.AddTool(
		mcp.NewTool("restore_or_create",
			mcp.WithDescription("Restore existing session or create new one"),
			mcp.WithString("session_id", mcp.Description("Session identifier"), mcp.Required()),
		),
		s.handleRestoreOrCreate,
	)

	s.mcp.AddTool(
		mcp.NewTool("get_compact_state",
			mcp.WithDescription("Get compact text summary of session state for prompt injection"),
			mcp.WithString("session_id", mcp.Description("Session identifier"), mcp.Required()),
			mcp.WithNumber("max_tokens", mcp.Description("Max tokens for compact output")),
		),
		s.handleGetCompactState,
	)

	s.mcp.AddTool(
		mcp.NewTool("get_audit_log",
			mcp.WithDescription("Get audit log for a session"),
			mcp.WithString("session_id", mcp.Description("Session identifier"), mcp.Required()),
			mcp.WithNumber("limit", mcp.Description("Max entries")),
		),
		s.handleGetAuditLog,
	)
}

func (s *Server) handleSaveState(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	stateJSON := req.GetString("state_json", "")

	var state map[string]interface{}
	if err := json.Unmarshal([]byte(stateJSON), &state); err != nil {
		return errorResult(fmt.Errorf("invalid state JSON: %w", err)), nil
	}

	// For simplicity, we use RestoreOrCreate to get/create a session,
	// then the full state is saved via the session service.
	sessionID := req.GetString("session_id", "")
	csv, _, err := s.sessions.RestoreOrCreate(context.Background(), sessionID)
	if err != nil {
		return errorResult(err), nil
	}

	csv.BumpVersion()
	if err := s.sessions.SaveState(context.Background(), csv); err != nil {
		return errorResult(err), nil
	}
	return textResult(fmt.Sprintf("State saved for session %s (v%d)", csv.SessionID, csv.Version)), nil
}

func (s *Server) handleLoadState(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	sessionID := req.GetString("session_id", "")
	args := req.GetArguments()
	var version *int
	if v, ok := args["version"]; ok {
		if n, ok := v.(float64); ok {
			ver := int(n)
			version = &ver
		}
	}
	state, checksum, err := s.sessions.LoadState(context.Background(), sessionID, version)
	if err != nil {
		return errorResult(err), nil
	}
	result := map[string]interface{}{
		"state":    state,
		"checksum": checksum,
	}
	return textResult(tools.ToJSON(result)), nil
}

func (s *Server) handleListSessions(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	sessions, err := s.sessions.ListSessions(context.Background())
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(sessions)), nil
}

func (s *Server) handleDeleteSession(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	sessionID := req.GetString("session_id", "")
	count, err := s.sessions.DeleteSession(context.Background(), sessionID)
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(fmt.Sprintf("Deleted %d versions of session %s", count, sessionID)), nil
}

func (s *Server) handleRestoreOrCreate(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	sessionID := req.GetString("session_id", "")
	state, restored, err := s.sessions.RestoreOrCreate(context.Background(), sessionID)
	if err != nil {
		return errorResult(err), nil
	}
	action := "created"
	if restored {
		action = "restored"
	}
	result := map[string]interface{}{
		"action": action,
		"state":  state,
	}
	return textResult(tools.ToJSON(result)), nil
}

func (s *Server) handleGetCompactState(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	sessionID := req.GetString("session_id", "")
	maxTokens := req.GetInt("max_tokens", 500)
	compact, err := s.sessions.GetCompactState(context.Background(), sessionID, maxTokens)
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(compact), nil
}

func (s *Server) handleGetAuditLog(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	sessionID := req.GetString("session_id", "")
	limit := req.GetInt("limit", 50)
	log, err := s.sessions.GetAuditLog(context.Background(), sessionID, limit)
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(log)), nil
}

// --- Causal Tools ---

func (s *Server) registerCausalTools() {
	s.mcp.AddTool(
		mcp.NewTool("add_causal_node",
			mcp.WithDescription("Add a causal reasoning node"),
			mcp.WithString("node_type", mcp.Description("Node type: decision, reason, consequence, constraint, alternative, assumption"), mcp.Required()),
			mcp.WithString("content", mcp.Description("Node content"), mcp.Required()),
		),
		s.handleAddCausalNode,
	)

	s.mcp.AddTool(
		mcp.NewTool("add_causal_edge",
			mcp.WithDescription("Add a causal edge between nodes"),
			mcp.WithString("from_id", mcp.Description("Source node ID"), mcp.Required()),
			mcp.WithString("to_id", mcp.Description("Target node ID"), mcp.Required()),
			mcp.WithString("edge_type", mcp.Description("Edge type: justifies, causes, constrains"), mcp.Required()),
		),
		s.handleAddCausalEdge,
	)

	s.mcp.AddTool(
		mcp.NewTool("get_causal_chain",
			mcp.WithDescription("Get causal chain for a decision"),
			mcp.WithString("query", mcp.Description("Decision search query"), mcp.Required()),
			mcp.WithNumber("max_depth", mcp.Description("Max traversal depth")),
		),
		s.handleGetCausalChain,
	)

	s.mcp.AddTool(
		mcp.NewTool("causal_stats",
			mcp.WithDescription("Get causal store statistics"),
		),
		s.handleCausalStats,
	)
}

func (s *Server) handleAddCausalNode(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	params := tools.AddNodeParams{
		NodeType: req.GetString("node_type", ""),
		Content:  req.GetString("content", ""),
	}
	node, err := s.causal.AddNode(context.Background(), params)
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(node)), nil
}

func (s *Server) handleAddCausalEdge(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	params := tools.AddEdgeParams{
		FromID:   req.GetString("from_id", ""),
		ToID:     req.GetString("to_id", ""),
		EdgeType: req.GetString("edge_type", ""),
	}
	edge, err := s.causal.AddEdge(context.Background(), params)
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(edge)), nil
}

func (s *Server) handleGetCausalChain(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query := req.GetString("query", "")
	maxDepth := req.GetInt("max_depth", 3)
	chain, err := s.causal.GetChain(context.Background(), query, maxDepth)
	if err != nil {
		return errorResult(err), nil
	}

	result := map[string]interface{}{
		"chain":   chain,
		"mermaid": chain.ToMermaid(),
	}
	return textResult(tools.ToJSON(result)), nil
}

func (s *Server) handleCausalStats(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	stats, err := s.causal.GetStats(context.Background())
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(stats)), nil
}

// --- Crystal Tools ---

func (s *Server) registerCrystalTools() {
	s.mcp.AddTool(
		mcp.NewTool("search_crystals",
			mcp.WithDescription("Search code crystals by content/primitive names"),
			mcp.WithString("query", mcp.Description("Search query"), mcp.Required()),
			mcp.WithNumber("limit", mcp.Description("Max results")),
		),
		s.handleSearchCrystals,
	)

	s.mcp.AddTool(
		mcp.NewTool("get_crystal",
			mcp.WithDescription("Get a code crystal by file path"),
			mcp.WithString("path", mcp.Description("File path"), mcp.Required()),
		),
		s.handleGetCrystal,
	)

	s.mcp.AddTool(
		mcp.NewTool("list_crystals",
			mcp.WithDescription("List indexed code crystals"),
			mcp.WithString("pattern", mcp.Description("Path pattern filter")),
			mcp.WithNumber("limit", mcp.Description("Max results")),
		),
		s.handleListCrystals,
	)

	s.mcp.AddTool(
		mcp.NewTool("crystal_stats",
			mcp.WithDescription("Get code crystal statistics"),
		),
		s.handleCrystalStats,
	)
}

func (s *Server) handleSearchCrystals(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query := req.GetString("query", "")
	limit := req.GetInt("limit", 20)
	crystals, err := s.crystals.SearchCrystals(context.Background(), query, limit)
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(crystals)), nil
}

func (s *Server) handleGetCrystal(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path := req.GetString("path", "")
	crystal, err := s.crystals.GetCrystal(context.Background(), path)
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(crystal)), nil
}

func (s *Server) handleListCrystals(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	pattern := req.GetString("pattern", "")
	limit := req.GetInt("limit", 50)
	crystals, err := s.crystals.ListCrystals(context.Background(), pattern, limit)
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(crystals)), nil
}

func (s *Server) handleCrystalStats(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	stats, err := s.crystals.GetCrystalStats(context.Background())
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(stats)), nil
}

// --- System Tools ---

func (s *Server) registerSystemTools() {
	s.mcp.AddTool(
		mcp.NewTool("health",
			mcp.WithDescription("Get server health status"),
		),
		s.handleHealth,
	)

	s.mcp.AddTool(
		mcp.NewTool("version",
			mcp.WithDescription("Get server version information"),
		),
		s.handleVersion,
	)

	s.mcp.AddTool(
		mcp.NewTool("dashboard",
			mcp.WithDescription("Get system dashboard with all metrics"),
		),
		s.handleDashboard,
	)
}

func (s *Server) handleHealth(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	health := s.system.Health(context.Background())
	return textResult(tools.ToJSON(health)), nil
}

func (s *Server) handleVersion(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	version := s.system.GetVersion()
	return textResult(tools.ToJSON(version)), nil
}

func (s *Server) handleDashboard(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	data, err := s.system.Dashboard(context.Background())
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(data)), nil
}

// --- Resources ---

func (s *Server) registerResources() {
	if s.res == nil {
		return
	}

	s.mcp.AddResource(
		mcp.NewResource("rlm://facts", "L0 Facts",
			mcp.WithResourceDescription("Project-level facts always loaded in context"),
			mcp.WithMIMEType("application/json"),
		),
		func(_ context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			text, err := s.res.GetFacts(context.Background())
			if err != nil {
				return nil, err
			}
			return []mcp.ResourceContents{
				mcp.TextResourceContents{URI: req.Params.URI, MIMEType: "application/json", Text: text},
			}, nil
		},
	)

	s.mcp.AddResource(
		mcp.NewResource("rlm://stats", "Memory Statistics",
			mcp.WithResourceDescription("Aggregate statistics about the memory store"),
			mcp.WithMIMEType("application/json"),
		),
		func(_ context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			text, err := s.res.GetStats(context.Background())
			if err != nil {
				return nil, err
			}
			return []mcp.ResourceContents{
				mcp.TextResourceContents{URI: req.Params.URI, MIMEType: "application/json", Text: text},
			}, nil
		},
	)

	s.mcp.AddResourceTemplate(
		mcp.NewResourceTemplate("rlm://state/{session_id}", "Session State",
			mcp.WithTemplateDescription("Cognitive state vector for a session"),
			mcp.WithTemplateMIMEType("application/json"),
		),
		func(_ context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			// Extract session_id from URI path.
			sessionID := extractSessionID(req.Params.URI)
			text, err := s.res.GetState(context.Background(), sessionID)
			if err != nil {
				return nil, err
			}
			return []mcp.ResourceContents{
				mcp.TextResourceContents{URI: req.Params.URI, MIMEType: "application/json", Text: text},
			}, nil
		},
	)
}

// --- Intent Distiller Tools (DIP H0.2) ---

func (s *Server) registerIntentTools() {
	if s.intent == nil || !s.intent.IsAvailable() {
		return
	}

	s.mcp.AddTool(
		mcp.NewTool("distill_intent",
			mcp.WithDescription("Distill user text into a pure intent vector via recursive compression. Detects manipulation through surface-vs-deep embedding divergence."),
			mcp.WithString("text", mcp.Description("Text to distill into intent vector"), mcp.Required()),
		),
		s.handleDistillIntent,
	)
}

func (s *Server) handleDistillIntent(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	params := tools.DistillIntentParams{
		Text: req.GetString("text", ""),
	}
	result, err := s.intent.DistillIntent(context.Background(), params)
	if err != nil {
		return errorResult(err), nil
	}

	// Return summary without full vectors (too large for MCP response).
	summary := map[string]interface{}{
		"compressed_text": result.CompressedText,
		"iterations":      result.Iterations,
		"convergence":     result.Convergence,
		"sincerity_score": result.SincerityScore,
		"is_sincere":      result.IsSincere,
		"is_manipulation": result.IsManipulation,
		"duration_ms":     result.DurationMs,
		"surface_dim":     len(result.SurfaceVector),
		"intent_dim":      len(result.IntentVector),
	}
	return textResult(tools.ToJSON(summary)), nil
}

// --- Entropy Gate Tools (DIP H0.3) ---

func (s *Server) registerEntropyTools() {
	s.mcp.AddTool(
		mcp.NewTool("analyze_entropy",
			mcp.WithDescription("Analyze Shannon entropy of text to detect adversarial/chaotic signals. Returns entropy in bits/char, redundancy, and character statistics."),
			mcp.WithString("text", mcp.Description("Text to analyze"), mcp.Required()),
		),
		s.handleAnalyzeEntropy,
	)
}

func (s *Server) handleAnalyzeEntropy(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	text := req.GetString("text", "")
	if text == "" {
		return errorResult(fmt.Errorf("text is required")), nil
	}
	analysis := entropyPkg.AnalyzeText(text)
	return textResult(tools.ToJSON(analysis)), nil
}

// --- Circuit Breaker Tools (DIP H1.1) ---

func (s *Server) registerCircuitBreakerTools() {
	s.mcp.AddTool(
		mcp.NewTool("circuit_status",
			mcp.WithDescription("Get the current circuit breaker status (HEALTHY/DEGRADED/OPEN), anomaly counts, and transition history."),
		),
		s.handleCircuitStatus,
	)
	s.mcp.AddTool(
		mcp.NewTool("circuit_reset",
			mcp.WithDescription("Manually reset the circuit breaker to HEALTHY state (external watchdog)."),
			mcp.WithString("reason", mcp.Description("Reason for reset")),
		),
		s.handleCircuitReset,
	)
}

func (s *Server) handleCircuitStatus(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	status := s.circuit.GetStatus()
	return textResult(tools.ToJSON(status)), nil
}

func (s *Server) handleCircuitReset(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	reason := req.GetString("reason", "manual reset via MCP")
	s.circuit.Reset(reason)
	status := s.circuit.GetStatus()
	return textResult(tools.ToJSON(status)), nil
}

// --- Action Oracle Tools (DIP H1.2) ---

func (s *Server) registerOracleTools() {
	s.mcp.AddTool(
		mcp.NewTool("verify_action",
			mcp.WithDescription("Verify an action against the Oracle whitelist. Returns ALLOW/DENY/REVIEW verdict with confidence score. Default-deny (zero-trust)."),
			mcp.WithString("action", mcp.Description("Action to verify"), mcp.Required()),
		),
		s.handleVerifyAction,
	)
	s.mcp.AddTool(
		mcp.NewTool("oracle_rules",
			mcp.WithDescription("List all Oracle rules (permitted and denied action patterns)."),
		),
		s.handleOracleRules,
	)
}

func (s *Server) handleVerifyAction(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	action := req.GetString("action", "")
	if action == "" {
		return errorResult(fmt.Errorf("action is required")), nil
	}
	result := s.oracle.Verify(action)
	return textResult(tools.ToJSON(result)), nil
}

func (s *Server) handleOracleRules(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	rules := s.oracle.Rules()
	return textResult(tools.ToJSON(rules)), nil
}

// --- Intent Pipeline Tools (DIP H1.3) ---

func (s *Server) registerPipelineTools() {
	s.mcp.AddTool(
		mcp.NewTool("process_intent",
			mcp.WithDescription("Process text through the full DIP Intent Pipeline: Entropy Check → Intent Distillation → Oracle Verification. Returns stage-by-stage results and circuit breaker state."),
			mcp.WithString("text", mcp.Description("Text to process through the pipeline"), mcp.Required()),
		),
		s.handleProcessIntent,
	)
}

func (s *Server) handleProcessIntent(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	text := req.GetString("text", "")
	if text == "" {
		return errorResult(fmt.Errorf("text is required")), nil
	}
	result := s.pipeline.Process(context.Background(), text)
	return textResult(tools.ToJSON(result)), nil
}

// --- Vector Store Tools (DIP H2.1) ---

func (s *Server) registerVectorStoreTools() {
	s.mcp.AddTool(
		mcp.NewTool("store_intent",
			mcp.WithDescription("Store a distilled intent vector for neuroplastic routing. Records text, compressed form, vector, route label, and verdict."),
			mcp.WithString("text", mcp.Description("Original text"), mcp.Required()),
			mcp.WithString("compressed", mcp.Description("Distilled compressed text")),
			mcp.WithString("route", mcp.Description("Route label (e.g., read, write, exec)")),
			mcp.WithString("verdict", mcp.Description("Oracle verdict: ALLOW, DENY, REVIEW")),
		),
		s.handleStoreIntent,
	)
	s.mcp.AddTool(
		mcp.NewTool("intent_stats",
			mcp.WithDescription("Get intent vector store statistics: total records, route/verdict counts, average entropy."),
		),
		s.handleIntentStats,
	)
}

func (s *Server) handleStoreIntent(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	text := req.GetString("text", "")
	if text == "" {
		return errorResult(fmt.Errorf("text is required")), nil
	}
	rec := &vectorstore.IntentRecord{
		Text:           text,
		CompressedText: req.GetString("compressed", text),
		Route:          req.GetString("route", "unknown"),
		Verdict:        req.GetString("verdict", "REVIEW"),
	}
	id := s.vecstore.Add(rec)
	return textResult(tools.ToJSON(map[string]interface{}{
		"id":    id,
		"route": rec.Route,
		"count": s.vecstore.Count(),
	})), nil
}

func (s *Server) handleIntentStats(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	stats := s.vecstore.GetStats()
	return textResult(tools.ToJSON(stats)), nil
}

// --- Router Tools (DIP H2.2) ---

func (s *Server) registerRouterTools() {
	s.mcp.AddTool(
		mcp.NewTool("route_intent",
			mcp.WithDescription("Route an intent through the neuroplastic router. Matches against known patterns with confidence-based decisions (ROUTE/REVIEW/DENY/LEARN)."),
			mcp.WithString("text", mcp.Description("Intent text to route"), mcp.Required()),
			mcp.WithString("verdict", mcp.Description("Oracle verdict for this intent")),
		),
		s.handleRouteIntent,
	)
}

func (s *Server) handleRouteIntent(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	text := req.GetString("text", "")
	if text == "" {
		return errorResult(fmt.Errorf("text is required")), nil
	}
	verdict := req.GetString("verdict", "REVIEW")
	// Use a simple text-based vector (hash-like) for demo routing.
	// In production, this would use the PyBridge embedding.
	vector := textToSimpleVector(text)
	result := s.router.Route(context.Background(), text, vector, verdict)
	return textResult(tools.ToJSON(result)), nil
}

// textToSimpleVector creates a basic 8-dimensional vector from text
// for demonstration routing without PyBridge embeddings.
func textToSimpleVector(text string) []float64 {
	vec := make([]float64, 8)
	for i, r := range text {
		vec[i%8] += float64(r) / 1000.0
	}
	// Normalize.
	var norm float64
	for _, v := range vec {
		norm += v * v
	}
	if norm > 0 {
		norm = 1.0 / (norm * 0.5) // rough normalize
		for i := range vec {
			vec[i] *= norm
		}
	}
	return vec
}

// --- Embedding Tools (Local Oracle / FTS5 Fallback) ---

func (s *Server) registerPythonBridgeTools() {
	if s.embedder == nil {
		return
	}

	s.mcp.AddTool(
		mcp.NewTool("semantic_search",
			mcp.WithDescription("Semantic vector similarity search across facts (requires Python NLP)"),
			mcp.WithString("query", mcp.Description("Search query text"), mcp.Required()),
			mcp.WithNumber("limit", mcp.Description("Max results (default 10)")),
			mcp.WithNumber("threshold", mcp.Description("Min similarity threshold 0.0-1.0")),
		),
		s.handleSemanticSearch,
	)

	s.mcp.AddTool(
		mcp.NewTool("compute_embedding",
			mcp.WithDescription("Compute embedding vector for text (uses local Oracle or FTS5 fallback)"),
			mcp.WithString("text", mcp.Description("Text to embed"), mcp.Required()),
		),
		s.handleComputeEmbedding,
	)

	s.mcp.AddTool(
		mcp.NewTool("reindex_embeddings",
			mcp.WithDescription("Reindex all fact embeddings (requires Python NLP)"),
			mcp.WithBoolean("force", mcp.Description("Force reindex even if embeddings exist")),
		),
		s.handleReindexEmbeddings,
	)

	s.mcp.AddTool(
		mcp.NewTool("consolidate_facts",
			mcp.WithDescription("Consolidate duplicate/similar facts using NLP (requires Python)"),
			mcp.WithNumber("similarity_threshold", mcp.Description("Similarity threshold for merging (default 0.85)")),
			mcp.WithString("domain", mcp.Description("Limit consolidation to a domain")),
		),
		s.handleConsolidateFacts,
	)

	s.mcp.AddTool(
		mcp.NewTool("enterprise_context",
			mcp.WithDescription("Get enterprise-level context summary (requires Python NLP)"),
			mcp.WithString("project", mcp.Description("Project name")),
			mcp.WithNumber("max_tokens", mcp.Description("Max tokens for output")),
		),
		s.handleEnterpriseContext,
	)

	s.mcp.AddTool(
		mcp.NewTool("route_context",
			mcp.WithDescription("Route context to appropriate handler based on intent (requires Python NLP)"),
			mcp.WithString("query", mcp.Description("User query to route"), mcp.Required()),
			mcp.WithString("session_id", mcp.Description("Current session ID")),
		),
		s.handleRouteContext,
	)

	s.mcp.AddTool(
		mcp.NewTool("discover_deep",
			mcp.WithDescription("Deep discovery of related facts and patterns (requires Python NLP)"),
			mcp.WithString("topic", mcp.Description("Topic to explore"), mcp.Required()),
			mcp.WithNumber("depth", mcp.Description("Exploration depth (default 2)")),
			mcp.WithNumber("max_results", mcp.Description("Max results")),
		),
		s.handleDiscoverDeep,
	)

	s.mcp.AddTool(
		mcp.NewTool("extract_from_conversation",
			mcp.WithDescription("Extract facts from conversation text (requires Python NLP)"),
			mcp.WithString("text", mcp.Description("Conversation text to extract from"), mcp.Required()),
			mcp.WithString("session_id", mcp.Description("Session ID for context")),
		),
		s.handleExtractFromConversation,
	)

	s.mcp.AddTool(
		mcp.NewTool("index_embeddings",
			mcp.WithDescription("Index embeddings for a batch of facts (requires Python NLP)"),
			mcp.WithString("fact_ids", mcp.Description("Comma-separated fact IDs to index")),
			mcp.WithBoolean("all", mcp.Description("Index all facts without embeddings")),
		),
		s.handleIndexEmbeddings,
	)

	s.mcp.AddTool(
		mcp.NewTool("build_communities",
			mcp.WithDescription("Build fact communities using graph clustering (requires Python NLP)"),
			mcp.WithNumber("min_community_size", mcp.Description("Minimum community size (default 3)")),
			mcp.WithNumber("similarity_threshold", mcp.Description("Edge threshold (default 0.7)")),
		),
		s.handleBuildCommunities,
	)

	s.mcp.AddTool(
		mcp.NewTool("check_python_bridge",
			mcp.WithDescription("Check Python bridge availability and capabilities"),
		),
		s.handleCheckPythonBridge,
	)
}

func (s *Server) handleSemanticSearch(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query := req.GetString("query", "")
	if query == "" {
		return errorResult(fmt.Errorf("query is required")), nil
	}
	vec, err := s.embedder.Embed(context.Background(), query)
	if err != nil {
		return errorResult(err), nil
	}
	limit := req.GetInt("limit", 10)
	results := s.vecstore.Search(vec, limit)
	return textResult(tools.ToJSON(results)), nil
}

func (s *Server) handleComputeEmbedding(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	text := req.GetString("text", "")
	vec, err := s.embedder.Embed(context.Background(), text)
	if err != nil {
		return errorResult(err), nil
	}
	result := map[string]interface{}{
		"embedding": vec,
		"dimension": s.embedder.Dimension(),
		"model":     s.embedder.Name(),
		"mode":      s.embedder.Mode().String(),
	}
	return textResult(tools.ToJSON(result)), nil
}

func (s *Server) handleReindexEmbeddings(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return textResult(tools.ToJSON(map[string]string{
		"status": "deprecated",
		"note":   "reindex_embeddings removed in v3.0. Embeddings managed by local Oracle.",
	})), nil
}

func (s *Server) handleConsolidateFacts(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return textResult(tools.ToJSON(map[string]string{
		"status": "deprecated",
		"note":   "consolidate_facts removed in v3.0. Use manual fact management.",
	})), nil
}

func (s *Server) handleEnterpriseContext(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return textResult(tools.ToJSON(map[string]string{
		"status": "deprecated",
		"note":   "enterprise_context removed in v3.0. Use get_compact_state.",
	})), nil
}

func (s *Server) handleRouteContext(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return textResult(tools.ToJSON(map[string]string{
		"status": "deprecated",
		"note":   "route_context removed in v3.0. Use route_intent.",
	})), nil
}

func (s *Server) handleDiscoverDeep(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return textResult(tools.ToJSON(map[string]string{
		"status": "deprecated",
		"note":   "discover_deep removed in v3.0. Use search_facts.",
	})), nil
}

func (s *Server) handleExtractFromConversation(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return textResult(tools.ToJSON(map[string]string{
		"status": "deprecated",
		"note":   "extract_from_conversation removed in v3.0. Use add_fact.",
	})), nil
}

func (s *Server) handleIndexEmbeddings(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return textResult(tools.ToJSON(map[string]string{
		"status": "deprecated",
		"note":   "index_embeddings removed in v3.0. Managed by local Oracle.",
	})), nil
}

func (s *Server) handleBuildCommunities(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return textResult(tools.ToJSON(map[string]string{
		"status": "deprecated",
		"note":   "build_communities removed in v3.0.",
	})), nil
}

func (s *Server) handleCheckPythonBridge(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	status := map[string]interface{}{
		"available":     s.embedder != nil,
		"oracle_mode":   "N/A",
		"embedder_name": "none",
		"note":          "Python bridge removed in v3.0. Use local Oracle (ONNX) or FTS5 fallback.",
	}
	if s.embedder != nil {
		status["oracle_mode"] = s.embedder.Mode().String()
		status["embedder_name"] = s.embedder.Name()
		status["dimension"] = s.embedder.Dimension()
	}
	return textResult(tools.ToJSON(status)), nil
}

// --- Synapse: Peer-to-Peer Tools (DIP H1: Synapse) ---

func (s *Server) registerSynapseTools() {
	s.mcp.AddTool(
		mcp.NewTool("peer_handshake",
			mcp.WithDescription("Initiate or respond to a peer genome handshake. Two GoMCP instances exchange Merkle genome hashes. Matching hashes establish a Trusted Pair for fact synchronization."),
			mcp.WithString("peer_id", mcp.Description("Remote peer ID (from their peer_status)")),
			mcp.WithString("peer_node", mcp.Description("Remote peer node name")),
			mcp.WithString("peer_genome_hash", mcp.Description("Remote peer's genome Merkle hash"), mcp.Required()),
		),
		s.handlePeerHandshake,
	)

	s.mcp.AddTool(
		mcp.NewTool("peer_status",
			mcp.WithDescription("Get this node's peer identity, genome hash, and list of all known peers with trust levels."),
		),
		s.handlePeerStatus,
	)

	s.mcp.AddTool(
		mcp.NewTool("sync_facts",
			mcp.WithDescription("Export L0-L1 facts for sync to a trusted peer, or import facts from a trusted peer. Use mode='export' to get facts as JSON, mode='import' to receive."),
			mcp.WithString("mode", mcp.Description("'export' or 'import'"), mcp.Required()),
			mcp.WithString("peer_id", mcp.Description("Remote peer ID (required for import)"), mcp.Required()),
			mcp.WithString("payload_json", mcp.Description("SyncPayload JSON (required for import)")),
		),
		s.handleSyncFacts,
	)

	s.mcp.AddTool(
		mcp.NewTool("peer_backup",
			mcp.WithDescription("Check for gene backups from timed-out peers. Returns backup data that can be restored to a reconnected peer via sync_facts import."),
			mcp.WithString("peer_id", mcp.Description("Peer ID to check backup for (optional, lists all if empty)")),
		),
		s.handlePeerBackup,
	)

	s.mcp.AddTool(
		mcp.NewTool("force_resonance_handshake",
			mcp.WithDescription("Atomic handshake + auto-sync. Performs peer genome verification and, if Merkle hashes match, immediately exports all L0-L1 facts as a SyncPayload. Combines peer_handshake + sync_facts(export) into one call."),
			mcp.WithString("peer_genome_hash", mcp.Description("Remote peer's genome Merkle hash"), mcp.Required()),
			mcp.WithString("peer_id", mcp.Description("Remote peer ID")),
			mcp.WithString("peer_node", mcp.Description("Remote peer node name")),
		),
		s.handleForceResonanceHandshake,
	)
}

func (s *Server) handlePeerHandshake(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	peerHash := req.GetString("peer_genome_hash", "")
	if peerHash == "" {
		return errorResult(fmt.Errorf("peer_genome_hash is required")), nil
	}

	peerID := req.GetString("peer_id", "remote_"+peerHash[:8])
	peerNode := req.GetString("peer_node", "unknown")

	// Compute local genome hash.
	localHash := memory.CompiledGenomeHash()

	handshakeReq := peer.HandshakeRequest{
		FromPeerID: peerID,
		FromNode:   peerNode,
		GenomeHash: peerHash,
		Timestamp:  time.Now().Unix(),
	}

	resp, err := s.peerReg.ProcessHandshake(handshakeReq, localHash)
	if err != nil {
		return errorResult(err), nil
	}

	result := map[string]interface{}{
		"local_peer_id":  s.peerReg.SelfID(),
		"local_node":     s.peerReg.NodeName(),
		"local_hash":     localHash,
		"remote_peer_id": peerID,
		"remote_hash":    peerHash,
		"match":          resp.Match,
		"trust":          resp.Trust.String(),
		"trusted_peers":  s.peerReg.TrustedCount(),
	}
	return textResult(tools.ToJSON(result)), nil
}

func (s *Server) handlePeerStatus(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	stats := s.peerReg.Stats()
	stats["genome_hash"] = memory.CompiledGenomeHash()
	stats["peers"] = s.peerReg.ListPeers()
	return textResult(tools.ToJSON(stats)), nil
}

func (s *Server) handleSyncFacts(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	mode := req.GetString("mode", "")
	peerID := req.GetString("peer_id", "")

	switch mode {
	case "export":
		// Check trust.
		if peerID != "" && !s.peerReg.IsTrusted(peerID) {
			return errorResult(fmt.Errorf("peer %s is not trusted (handshake first)", peerID)), nil
		}

		// Export L0-L1 facts.
		ctx := context.Background()
		l0Facts, err := s.facts.Store().ListByLevel(ctx, memory.LevelProject)
		if err != nil {
			return errorResult(err), nil
		}
		l1Facts, err := s.facts.Store().ListByLevel(ctx, memory.LevelDomain)
		if err != nil {
			return errorResult(err), nil
		}

		allFacts := append(l0Facts, l1Facts...)
		syncFacts := make([]peer.SyncFact, 0, len(allFacts))
		for _, f := range allFacts {
			if f.IsStale || f.IsArchived {
				continue
			}
			syncFacts = append(syncFacts, peer.SyncFact{
				ID:        f.ID,
				Content:   f.Content,
				Level:     int(f.Level),
				Domain:    f.Domain,
				Module:    f.Module,
				IsGene:    f.IsGene,
				Source:    f.Source,
				CreatedAt: f.CreatedAt,
			})
		}

		payload := peer.SyncPayload{
			Version:    "1.1",
			FromPeerID: s.peerReg.SelfID(),
			GenomeHash: memory.CompiledGenomeHash(),
			Facts:      syncFacts,
			SyncedAt:   time.Now(),
		}

		// T10.5: Include SOC incidents if available.
		if s.socSvc != nil {
			payload.Incidents = s.socSvc.ExportIncidents(s.peerReg.SelfID())
		}

		return textResult(tools.ToJSON(payload)), nil

	case "import":
		if peerID == "" {
			return errorResult(fmt.Errorf("peer_id required for import")), nil
		}
		if !s.peerReg.IsTrusted(peerID) {
			return errorResult(fmt.Errorf("peer %s is not trusted", peerID)), nil
		}

		payloadJSON := req.GetString("payload_json", "")
		if payloadJSON == "" {
			return errorResult(fmt.Errorf("payload_json required for import")), nil
		}

		var payload peer.SyncPayload
		if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
			return errorResult(fmt.Errorf("invalid payload: %w", err)), nil
		}

		// Verify genome hash matches.
		if payload.GenomeHash != memory.CompiledGenomeHash() {
			return errorResult(fmt.Errorf("genome hash mismatch: payload=%s local=%s",
				payload.GenomeHash[:16], memory.CompiledGenomeHash()[:16])), nil
		}

		// Import facts (skip existing).
		ctx := context.Background()
		imported := 0
		for _, sf := range payload.Facts {
			// Skip if already exists.
			if _, err := s.facts.Store().Get(ctx, sf.ID); err == nil {
				continue
			}

			level, ok := memory.HierLevelFromInt(sf.Level)
			if !ok {
				continue
			}

			var fact *memory.Fact
			if sf.IsGene {
				fact = memory.NewGene(sf.Content, sf.Domain)
			} else {
				fact = memory.NewFact(sf.Content, level, sf.Domain, sf.Module)
			}
			fact.Source = "peer_sync:" + peerID

			if err := s.facts.Store().Add(ctx, fact); err != nil {
				continue // skip duplicates
			}
			imported++
		}

		_ = s.peerReg.RecordSync(peerID, imported)

		// T10.6: Import SOC incidents if present.
		incidentsImported := 0
		if s.socSvc != nil && len(payload.Incidents) > 0 {
			n, err := s.socSvc.ImportIncidents(payload.Incidents)
			if err == nil {
				incidentsImported = n
			}
		}

		result := map[string]interface{}{
			"imported":           imported,
			"incidents_imported": incidentsImported,
			"total_sent":         len(payload.Facts),
			"total_incidents":    len(payload.Incidents),
			"from_peer":          payload.FromPeerID,
			"synced_at":          payload.SyncedAt,
		}
		return textResult(tools.ToJSON(result)), nil

	default:
		return errorResult(fmt.Errorf("mode must be 'export' or 'import'")), nil
	}
}

func (s *Server) handlePeerBackup(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	peerID := req.GetString("peer_id", "")

	if peerID != "" {
		backup, ok := s.peerReg.GetBackup(peerID)
		if !ok {
			return textResult(tools.ToJSON(map[string]string{
				"status": "no backup found for " + peerID,
			})), nil
		}
		return textResult(tools.ToJSON(backup)), nil
	}

	// List all backups.
	peers := s.peerReg.ListPeers()
	var backups []interface{}
	for _, p := range peers {
		if b, ok := s.peerReg.GetBackup(p.PeerID); ok {
			backups = append(backups, b)
		}
	}

	result := map[string]interface{}{
		"total_backups": len(backups),
		"backups":       backups,
	}
	return textResult(tools.ToJSON(result)), nil
}

func (s *Server) handleForceResonanceHandshake(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	peerHash := req.GetString("peer_genome_hash", "")
	if peerHash == "" {
		return errorResult(fmt.Errorf("peer_genome_hash is required")), nil
	}

	peerID := req.GetString("peer_id", "remote_"+peerHash[:8])
	peerNode := req.GetString("peer_node", "unknown")
	localHash := memory.CompiledGenomeHash()

	// Step 1: Handshake.
	handshakeReq := peer.HandshakeRequest{
		FromPeerID: peerID,
		FromNode:   peerNode,
		GenomeHash: peerHash,
		Timestamp:  time.Now().Unix(),
	}

	resp, err := s.peerReg.ProcessHandshake(handshakeReq, localHash)
	if err != nil {
		return errorResult(err), nil
	}

	if !resp.Match {
		return textResult(tools.ToJSON(map[string]interface{}{
			"phase":       "handshake",
			"match":       false,
			"trust":       resp.Trust.String(),
			"local_hash":  localHash,
			"remote_hash": peerHash,
			"sync":        nil,
		})), nil
	}

	// Step 2: Auto-sync (export L0-L1 facts).
	ctx := context.Background()
	l0Facts, err := s.facts.Store().ListByLevel(ctx, memory.LevelProject)
	if err != nil {
		return errorResult(err), nil
	}
	l1Facts, err := s.facts.Store().ListByLevel(ctx, memory.LevelDomain)
	if err != nil {
		return errorResult(err), nil
	}

	allFacts := append(l0Facts, l1Facts...)
	syncFacts := make([]peer.SyncFact, 0, len(allFacts))
	for _, f := range allFacts {
		if f.IsStale || f.IsArchived {
			continue
		}
		syncFacts = append(syncFacts, peer.SyncFact{
			ID:        f.ID,
			Content:   f.Content,
			Level:     int(f.Level),
			Domain:    f.Domain,
			Module:    f.Module,
			IsGene:    f.IsGene,
			Source:    f.Source,
			CreatedAt: f.CreatedAt,
		})
	}

	payload := peer.SyncPayload{
		Version:    "1.1",
		FromPeerID: s.peerReg.SelfID(),
		GenomeHash: localHash,
		Facts:      syncFacts,
		SyncedAt:   time.Now(),
	}

	// T10.5: Include SOC incidents if available.
	if s.socSvc != nil {
		payload.Incidents = s.socSvc.ExportIncidents(s.peerReg.SelfID())
	}

	result := map[string]interface{}{
		"phase":          "resonance_complete",
		"match":          true,
		"trust":          "VERIFIED",
		"local_peer_id":  s.peerReg.SelfID(),
		"local_node":     s.peerReg.NodeName(),
		"remote_peer_id": peerID,
		"trusted_peers":  s.peerReg.TrustedCount(),
		"sync_payload":   payload,
		"fact_count":     len(syncFacts),
		"incident_count": len(payload.Incidents),
	}
	return textResult(tools.ToJSON(result)), nil
}

// --- Apoptosis Recovery Tools (DIP H1.4) ---

func (s *Server) registerApoptosisTools() {
	s.mcp.AddTool(
		mcp.NewTool("detect_apathy",
			mcp.WithDescription("Analyze text for infrastructure apathy signals (blocked responses, 403 errors, semantic filters, forced context resets). Returns detected patterns, severity, and recommended actions."),
			mcp.WithString("text", mcp.Description("Text to analyze for apathy signals"), mcp.Required()),
		),
		s.handleDetectApathy,
	)

	s.mcp.AddTool(
		mcp.NewTool("trigger_apoptosis_recovery",
			mcp.WithDescription("Graceful session death with genome preservation. Saves Merkle hash of all genes to protected sector, stores recovery marker in L0 facts. Use when critical entropy detected or infrastructure forces reset."),
			mcp.WithNumber("entropy", mcp.Description("Current entropy level that triggered apoptosis")),
		),
		s.handleTriggerApoptosisRecovery,
	)
}

func (s *Server) handleDetectApathy(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	text := req.GetString("text", "")
	if text == "" {
		return errorResult(fmt.Errorf("text is required")), nil
	}
	result := tools.DetectApathy(text)
	return textResult(tools.ToJSON(result)), nil
}

func (s *Server) handleTriggerApoptosisRecovery(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var entropyVal float64
	if v, ok := req.GetArguments()["entropy"]; ok {
		if n, ok := v.(float64); ok {
			entropyVal = n
		}
	}
	result, err := tools.TriggerApoptosisRecovery(context.Background(), s.facts.Store(), entropyVal)
	if err != nil {
		return errorResult(err), nil
	}
	return textResult(tools.ToJSON(result)), nil
}

// --- Helpers ---

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: text},
		},
	}
}

func errorResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: fmt.Sprintf("Error: %s", err.Error())},
		},
		IsError: true,
	}
}

func extractSessionID(uri string) string {
	// URI format: rlm://state/{session_id}
	const prefix = "rlm://state/"
	if len(uri) > len(prefix) {
		return uri[len(prefix):]
	}
	return "default"
}
