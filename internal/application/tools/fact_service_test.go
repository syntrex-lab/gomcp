package tools

import (
	"context"
	"testing"

	"github.com/syntrex/gomcp/internal/domain/memory"
	"github.com/syntrex/gomcp/internal/infrastructure/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestFactService(t *testing.T) *FactService {
	t.Helper()
	db, err := sqlite.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	repo, err := sqlite.NewFactRepo(db)
	require.NoError(t, err)

	return NewFactService(repo, nil)
}

func TestFactService_AddFact(t *testing.T) {
	svc := newTestFactService(t)
	ctx := context.Background()

	fact, err := svc.AddFact(ctx, AddFactParams{
		Content: "Go is fast",
		Level:   0,
		Domain:  "core",
		Module:  "engine",
		CodeRef: "main.go:42",
	})
	require.NoError(t, err)
	require.NotNil(t, fact)

	assert.Equal(t, "Go is fast", fact.Content)
	assert.Equal(t, memory.LevelProject, fact.Level)
	assert.Equal(t, "core", fact.Domain)
}

func TestFactService_AddFact_InvalidLevel(t *testing.T) {
	svc := newTestFactService(t)
	ctx := context.Background()

	_, err := svc.AddFact(ctx, AddFactParams{Content: "test", Level: 99})
	assert.Error(t, err)
}

func TestFactService_GetFact(t *testing.T) {
	svc := newTestFactService(t)
	ctx := context.Background()

	fact, err := svc.AddFact(ctx, AddFactParams{Content: "test", Level: 0})
	require.NoError(t, err)

	got, err := svc.GetFact(ctx, fact.ID)
	require.NoError(t, err)
	assert.Equal(t, fact.ID, got.ID)
}

func TestFactService_UpdateFact(t *testing.T) {
	svc := newTestFactService(t)
	ctx := context.Background()

	fact, err := svc.AddFact(ctx, AddFactParams{Content: "original", Level: 0})
	require.NoError(t, err)

	newContent := "updated"
	updated, err := svc.UpdateFact(ctx, UpdateFactParams{
		ID:      fact.ID,
		Content: &newContent,
	})
	require.NoError(t, err)
	assert.Equal(t, "updated", updated.Content)
}

func TestFactService_DeleteFact(t *testing.T) {
	svc := newTestFactService(t)
	ctx := context.Background()

	fact, err := svc.AddFact(ctx, AddFactParams{Content: "delete me", Level: 0})
	require.NoError(t, err)

	err = svc.DeleteFact(ctx, fact.ID)
	require.NoError(t, err)

	_, err = svc.GetFact(ctx, fact.ID)
	assert.Error(t, err)
}

func TestFactService_ListFacts_ByDomain(t *testing.T) {
	svc := newTestFactService(t)
	ctx := context.Background()

	_, _ = svc.AddFact(ctx, AddFactParams{Content: "f1", Level: 0, Domain: "backend"})
	_, _ = svc.AddFact(ctx, AddFactParams{Content: "f2", Level: 1, Domain: "backend"})
	_, _ = svc.AddFact(ctx, AddFactParams{Content: "f3", Level: 0, Domain: "frontend"})

	facts, err := svc.ListFacts(ctx, ListFactsParams{Domain: "backend"})
	require.NoError(t, err)
	assert.Len(t, facts, 2)
}

func TestFactService_SearchFacts(t *testing.T) {
	svc := newTestFactService(t)
	ctx := context.Background()

	_, _ = svc.AddFact(ctx, AddFactParams{Content: "Go concurrency", Level: 0})
	_, _ = svc.AddFact(ctx, AddFactParams{Content: "Python is slow", Level: 0})

	results, err := svc.SearchFacts(ctx, "Go", 10)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}

func TestFactService_GetStats(t *testing.T) {
	svc := newTestFactService(t)
	ctx := context.Background()

	_, _ = svc.AddFact(ctx, AddFactParams{Content: "f1", Level: 0, Domain: "core"})
	_, _ = svc.AddFact(ctx, AddFactParams{Content: "f2", Level: 1, Domain: "core"})

	stats, err := svc.GetStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, stats.TotalFacts)
}

func TestFactService_GetL0Facts(t *testing.T) {
	svc := newTestFactService(t)
	ctx := context.Background()

	_, _ = svc.AddFact(ctx, AddFactParams{Content: "L0 fact", Level: 0})
	_, _ = svc.AddFact(ctx, AddFactParams{Content: "L1 fact", Level: 1})

	facts, err := svc.GetL0Facts(ctx)
	require.NoError(t, err)
	assert.Len(t, facts, 1)
	assert.Equal(t, "L0 fact", facts[0].Content)
}

func TestFactService_ListDomains(t *testing.T) {
	svc := newTestFactService(t)
	ctx := context.Background()

	_, _ = svc.AddFact(ctx, AddFactParams{Content: "f1", Level: 0, Domain: "backend"})
	_, _ = svc.AddFact(ctx, AddFactParams{Content: "f2", Level: 0, Domain: "frontend"})

	domains, err := svc.ListDomains(ctx)
	require.NoError(t, err)
	assert.Len(t, domains, 2)
}

func TestToJSON(t *testing.T) {
	result := ToJSON(map[string]string{"key": "value"})
	assert.Contains(t, result, "\"key\"")
	assert.Contains(t, result, "\"value\"")
}
