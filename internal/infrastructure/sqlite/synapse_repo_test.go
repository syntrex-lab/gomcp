package sqlite_test

import (
	"context"
	"testing"

	"github.com/syntrex-lab/gomcp/internal/domain/memory"
	"github.com/syntrex-lab/gomcp/internal/infrastructure/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupSynapseTest(t *testing.T) (*sqlite.SynapseRepo, *sqlite.FactRepo) {
	t.Helper()
	db, err := sqlite.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// FactRepo migration creates synapses table.
	factRepo, err := sqlite.NewFactRepo(db)
	require.NoError(t, err)

	synapseRepo := sqlite.NewSynapseRepo(db)
	return synapseRepo, factRepo
}

func TestSynapseRepo_CreateAndListPending(t *testing.T) {
	repo, factRepo := setupSynapseTest(t)
	ctx := context.Background()

	// Create two facts to link.
	f1 := memory.NewFact("Architecture overview", memory.LevelDomain, "arch", "")
	f2 := memory.NewFact("Security module design", memory.LevelDomain, "security", "")
	require.NoError(t, factRepo.Add(ctx, f1))
	require.NoError(t, factRepo.Add(ctx, f2))

	// Create synapse.
	id, err := repo.Create(ctx, f1.ID, f2.ID, 0.92)
	require.NoError(t, err)
	assert.Greater(t, id, int64(0))

	// List pending.
	pending, err := repo.ListPending(ctx, 10)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, f1.ID, pending[0].FactIDA)
	assert.Equal(t, f2.ID, pending[0].FactIDB)
	assert.InDelta(t, 0.92, pending[0].Confidence, 0.01)
	assert.Equal(t, "PENDING", string(pending[0].Status))
}

func TestSynapseRepo_AcceptAndListVerified(t *testing.T) {
	repo, factRepo := setupSynapseTest(t)
	ctx := context.Background()

	f1 := memory.NewFact("fact A", memory.LevelModule, "test", "")
	f2 := memory.NewFact("fact B", memory.LevelModule, "test", "")
	require.NoError(t, factRepo.Add(ctx, f1))
	require.NoError(t, factRepo.Add(ctx, f2))

	id, err := repo.Create(ctx, f1.ID, f2.ID, 0.88)
	require.NoError(t, err)

	// Accept.
	require.NoError(t, repo.Accept(ctx, id))

	// Should no longer be in pending.
	pending, _ := repo.ListPending(ctx, 10)
	assert.Empty(t, pending)

	// Should be in verified.
	verified, err := repo.ListVerified(ctx)
	require.NoError(t, err)
	require.Len(t, verified, 1)
	assert.Equal(t, "VERIFIED", string(verified[0].Status))
}

func TestSynapseRepo_Reject(t *testing.T) {
	repo, factRepo := setupSynapseTest(t)
	ctx := context.Background()

	f1 := memory.NewFact("fact X", memory.LevelProject, "", "")
	f2 := memory.NewFact("fact Y", memory.LevelProject, "", "")
	require.NoError(t, factRepo.Add(ctx, f1))
	require.NoError(t, factRepo.Add(ctx, f2))

	id, err := repo.Create(ctx, f1.ID, f2.ID, 0.50)
	require.NoError(t, err)

	require.NoError(t, repo.Reject(ctx, id))

	pending, _ := repo.ListPending(ctx, 10)
	assert.Empty(t, pending)

	verified, _ := repo.ListVerified(ctx)
	assert.Empty(t, verified)
}

func TestSynapseRepo_Count(t *testing.T) {
	repo, factRepo := setupSynapseTest(t)
	ctx := context.Background()

	f1 := memory.NewFact("a", memory.LevelProject, "", "")
	f2 := memory.NewFact("b", memory.LevelProject, "", "")
	f3 := memory.NewFact("c", memory.LevelProject, "", "")
	require.NoError(t, factRepo.Add(ctx, f1))
	require.NoError(t, factRepo.Add(ctx, f2))
	require.NoError(t, factRepo.Add(ctx, f3))

	id1, _ := repo.Create(ctx, f1.ID, f2.ID, 0.90)
	id2, _ := repo.Create(ctx, f1.ID, f3.ID, 0.85)
	_, _ = repo.Create(ctx, f2.ID, f3.ID, 0.40)

	_ = repo.Accept(ctx, id1)
	_ = repo.Reject(ctx, id2)

	pending, verified, rejected, err := repo.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, pending)
	assert.Equal(t, 1, verified)
	assert.Equal(t, 1, rejected)
}

func TestSynapseRepo_Exists(t *testing.T) {
	repo, factRepo := setupSynapseTest(t)
	ctx := context.Background()

	f1 := memory.NewFact("p", memory.LevelProject, "", "")
	f2 := memory.NewFact("q", memory.LevelProject, "", "")
	require.NoError(t, factRepo.Add(ctx, f1))
	require.NoError(t, factRepo.Add(ctx, f2))

	// No synapse yet.
	exists, err := repo.Exists(ctx, f1.ID, f2.ID)
	require.NoError(t, err)
	assert.False(t, exists)

	// Create one.
	_, _ = repo.Create(ctx, f1.ID, f2.ID, 0.95)

	// Should exist in both directions.
	exists, _ = repo.Exists(ctx, f1.ID, f2.ID)
	assert.True(t, exists)

	exists, _ = repo.Exists(ctx, f2.ID, f1.ID)
	assert.True(t, exists, "bidirectional check should work")
}

func TestSynapseRepo_AcceptNonPending_Fails(t *testing.T) {
	repo, factRepo := setupSynapseTest(t)
	ctx := context.Background()

	f1 := memory.NewFact("m", memory.LevelProject, "", "")
	f2 := memory.NewFact("n", memory.LevelProject, "", "")
	require.NoError(t, factRepo.Add(ctx, f1))
	require.NoError(t, factRepo.Add(ctx, f2))

	id, _ := repo.Create(ctx, f1.ID, f2.ID, 0.80)
	_ = repo.Accept(ctx, id)

	// Trying to accept again should fail.
	err := repo.Accept(ctx, id)
	assert.Error(t, err)
}
