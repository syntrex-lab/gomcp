// Package tools provides application-level tool services that bridge
// domain logic with MCP tool handlers.
package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sentinel-community/gomcp/internal/domain/memory"
)

// FactService implements MCP tool logic for hierarchical fact operations.
type FactService struct {
	store    memory.FactStore
	cache    memory.HotCache
	recorder DecisionRecorder // v3.7: tamper-evident trace
}

// SetDecisionRecorder injects the decision recorder.
func (s *FactService) SetDecisionRecorder(r DecisionRecorder) {
	s.recorder = r
}

// NewFactService creates a new FactService.
func NewFactService(store memory.FactStore, cache memory.HotCache) *FactService {
	return &FactService{store: store, cache: cache}
}

// AddFactParams holds parameters for the add_fact tool.
type AddFactParams struct {
	Content string `json:"content"`
	Level   int    `json:"level"`
	Domain  string `json:"domain,omitempty"`
	Module  string `json:"module,omitempty"`
	CodeRef string `json:"code_ref,omitempty"`
}

// AddFact creates a new hierarchical fact.
func (s *FactService) AddFact(ctx context.Context, params AddFactParams) (*memory.Fact, error) {
	level, ok := memory.HierLevelFromInt(params.Level)
	if !ok {
		return nil, fmt.Errorf("invalid level %d, must be 0-3", params.Level)
	}

	fact := memory.NewFact(params.Content, level, params.Domain, params.Module)
	fact.CodeRef = params.CodeRef

	if err := fact.Validate(); err != nil {
		return nil, fmt.Errorf("validate fact: %w", err)
	}
	if err := s.store.Add(ctx, fact); err != nil {
		return nil, fmt.Errorf("store fact: %w", err)
	}

	// Invalidate cache if L0 fact.
	if level == memory.LevelProject && s.cache != nil {
		_ = s.cache.InvalidateFact(ctx, fact.ID)
	}

	return fact, nil
}

// AddGeneParams holds parameters for the add_gene tool.
type AddGeneParams struct {
	Content string `json:"content"`
	Domain  string `json:"domain,omitempty"`
}

// AddGene creates an immutable genome fact (L0 only).
// Once created, a gene cannot be updated, deleted, or marked stale.
// Genes represent survival invariants — the DNA of the system.
func (s *FactService) AddGene(ctx context.Context, params AddGeneParams) (*memory.Fact, error) {
	gene := memory.NewGene(params.Content, params.Domain)

	if err := gene.Validate(); err != nil {
		return nil, fmt.Errorf("validate gene: %w", err)
	}
	if err := s.store.Add(ctx, gene); err != nil {
		return nil, fmt.Errorf("store gene: %w", err)
	}

	// Invalidate L0 cache — genes are always L0.
	if s.cache != nil {
		_ = s.cache.InvalidateFact(ctx, gene.ID)
	}

	return gene, nil
}

// GetFact retrieves a fact by ID.
func (s *FactService) GetFact(ctx context.Context, id string) (*memory.Fact, error) {
	return s.store.Get(ctx, id)
}

// UpdateFactParams holds parameters for the update_fact tool.
type UpdateFactParams struct {
	ID      string  `json:"id"`
	Content *string `json:"content,omitempty"`
	IsStale *bool   `json:"is_stale,omitempty"`
}

// UpdateFact updates a fact.
func (s *FactService) UpdateFact(ctx context.Context, params UpdateFactParams) (*memory.Fact, error) {
	fact, err := s.store.Get(ctx, params.ID)
	if err != nil {
		return nil, err
	}

	// Genome Layer: block mutation of genes.
	if fact.IsImmutable() {
		return nil, memory.ErrImmutableFact
	}

	if params.Content != nil {
		fact.Content = *params.Content
	}
	if params.IsStale != nil {
		fact.IsStale = *params.IsStale
	}

	if err := s.store.Update(ctx, fact); err != nil {
		return nil, err
	}

	if fact.Level == memory.LevelProject && s.cache != nil {
		_ = s.cache.InvalidateFact(ctx, fact.ID)
	}

	return fact, nil
}

// DeleteFact deletes a fact by ID.
func (s *FactService) DeleteFact(ctx context.Context, id string) error {
	// Genome Layer: block deletion of genes.
	fact, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if fact.IsImmutable() {
		return memory.ErrImmutableFact
	}

	if s.cache != nil {
		_ = s.cache.InvalidateFact(ctx, id)
	}
	return s.store.Delete(ctx, id)
}

// ListFactsParams holds parameters for the list_facts tool.
type ListFactsParams struct {
	Domain       string `json:"domain,omitempty"`
	Level        *int   `json:"level,omitempty"`
	IncludeStale bool   `json:"include_stale,omitempty"`
}

// ListFacts lists facts by domain or level.
func (s *FactService) ListFacts(ctx context.Context, params ListFactsParams) ([]*memory.Fact, error) {
	if params.Domain != "" {
		return s.store.ListByDomain(ctx, params.Domain, params.IncludeStale)
	}
	if params.Level != nil {
		level, ok := memory.HierLevelFromInt(*params.Level)
		if !ok {
			return nil, fmt.Errorf("invalid level %d", *params.Level)
		}
		return s.store.ListByLevel(ctx, level)
	}
	// Default: return L0 facts.
	return s.store.ListByLevel(ctx, memory.LevelProject)
}

// SearchFacts searches facts by content.
func (s *FactService) SearchFacts(ctx context.Context, query string, limit int) ([]*memory.Fact, error) {
	if limit <= 0 {
		limit = 20
	}
	return s.store.Search(ctx, query, limit)
}

// ListDomains returns all unique domains.
func (s *FactService) ListDomains(ctx context.Context) ([]string, error) {
	return s.store.ListDomains(ctx)
}

// GetStale returns stale facts.
func (s *FactService) GetStale(ctx context.Context, includeArchived bool) ([]*memory.Fact, error) {
	return s.store.GetStale(ctx, includeArchived)
}

// ProcessExpired handles expired TTL facts.
func (s *FactService) ProcessExpired(ctx context.Context) (int, error) {
	expired, err := s.store.GetExpired(ctx)
	if err != nil {
		return 0, err
	}

	processed := 0
	for _, f := range expired {
		if f.TTL == nil {
			continue
		}
		switch f.TTL.OnExpire {
		case memory.OnExpireMarkStale:
			f.MarkStale()
			_ = s.store.Update(ctx, f)
		case memory.OnExpireArchive:
			f.Archive()
			_ = s.store.Update(ctx, f)
		case memory.OnExpireDelete:
			_ = s.store.Delete(ctx, f.ID)
		}
		processed++
	}
	return processed, nil
}

// GetStats returns fact store statistics.
func (s *FactService) GetStats(ctx context.Context) (*memory.FactStoreStats, error) {
	return s.store.Stats(ctx)
}

// GetL0Facts returns L0 facts from cache (fast path) or store.
func (s *FactService) GetL0Facts(ctx context.Context) ([]*memory.Fact, error) {
	if s.cache != nil {
		facts, err := s.cache.GetL0Facts(ctx)
		if err == nil && len(facts) > 0 {
			return facts, nil
		}
	}
	facts, err := s.store.ListByLevel(ctx, memory.LevelProject)
	if err != nil {
		return nil, err
	}
	// Warm cache.
	if s.cache != nil && len(facts) > 0 {
		_ = s.cache.WarmUp(ctx, facts)
	}
	return facts, nil
}

// ToJSON marshals any value to indented JSON string.
func ToJSON(v interface{}) string {
	data, _ := json.MarshalIndent(v, "", "  ")
	return string(data)
}

// ListGenes returns all genome facts (immutable survival invariants).
func (s *FactService) ListGenes(ctx context.Context) ([]*memory.Fact, error) {
	return s.store.ListGenes(ctx)
}

// VerifyGenome computes the Merkle hash of all genes and returns integrity status.
func (s *FactService) VerifyGenome(ctx context.Context) (string, int, error) {
	genes, err := s.store.ListGenes(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("list genes: %w", err)
	}
	hash := memory.GenomeHash(genes)
	return hash, len(genes), nil
}

// Store returns the underlying FactStore for direct access by subsystems
// (e.g., apoptosis recovery that needs raw store operations).
func (s *FactService) Store() memory.FactStore {
	return s.store
}

// --- v3.3 Context GC ---

// GetColdFacts returns facts with hit_count=0, created >30 days ago.
// Genes are excluded. Use for memory hygiene review.
func (s *FactService) GetColdFacts(ctx context.Context, limit int) ([]*memory.Fact, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.store.GetColdFacts(ctx, limit)
}

// CompressFactsParams holds parameters for the compress_facts tool.
type CompressFactsParams struct {
	IDs     []string `json:"fact_ids"`
	Summary string   `json:"summary"`
}

// CompressFacts archives the given facts and creates a summary fact.
// Genes are silently skipped (invariant protection).
func (s *FactService) CompressFacts(ctx context.Context, params CompressFactsParams) (string, error) {
	if len(params.IDs) == 0 {
		return "", fmt.Errorf("fact_ids is required")
	}
	if params.Summary == "" {
		return "", fmt.Errorf("summary is required")
	}
	// v3.7: auto-backup decision before compression.
	if s.recorder != nil {
		s.recorder.RecordDecision("ORACLE", "COMPRESS_FACTS",
			fmt.Sprintf("ids=%v summary=%s", params.IDs, params.Summary))
	}
	return s.store.CompressFacts(ctx, params.IDs, params.Summary)
}
