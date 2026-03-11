package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecisionLogger_Record(t *testing.T) {
	dir := t.TempDir()
	dl, err := NewDecisionLogger(dir)
	require.NoError(t, err)
	defer dl.Close()

	err = dl.Record(ModuleSynapse, "ACCEPT_SYNAPSE", "similarity=0.92, threshold=0.85")
	require.NoError(t, err)

	err = dl.Record(ModulePeer, "TRUST_UPGRADE", "peer_abc: UNKNOWN → VERIFIED")
	require.NoError(t, err)

	err = dl.Record(ModuleMode, "MODE_TRANSITION", "ARMED → ZERO-G")
	require.NoError(t, err)

	assert.Equal(t, 3, dl.Count())
	assert.NotEqual(t, "GENESIS", dl.PrevHash())

	// Verify file content.
	data, err := os.ReadFile(filepath.Join(dir, "decisions.log"))
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	assert.Len(t, lines, 3)

	// First line should have GENESIS as PrevHash.
	assert.Contains(t, lines[0], "| GENESIS")
	assert.Contains(t, lines[0], "SYNAPSE")
	assert.Contains(t, lines[0], "ACCEPT_SYNAPSE")

	// Second line should NOT have GENESIS.
	assert.NotContains(t, lines[1], "GENESIS")
	assert.Contains(t, lines[1], "PEER")
}

func TestDecisionLogger_HashChain(t *testing.T) {
	dir := t.TempDir()
	dl, err := NewDecisionLogger(dir)
	require.NoError(t, err)

	// Record 10 decisions to build a chain.
	for i := 0; i < 10; i++ {
		err := dl.Record(ModuleDIPWatcher, "ALERT", "test alert")
		require.NoError(t, err)
	}
	dl.Close()

	assert.Equal(t, 10, dl.Count())
}

func TestDecisionLogger_AllModules(t *testing.T) {
	dir := t.TempDir()
	dl, err := NewDecisionLogger(dir)
	require.NoError(t, err)
	defer dl.Close()

	modules := []DecisionModule{ModuleSynapse, ModulePeer, ModuleMode, ModuleDIPWatcher, ModuleOracle, ModuleGenome, ModuleDoctor}
	for _, m := range modules {
		err := dl.Record(m, "TEST", "testing module "+string(m))
		require.NoError(t, err)
	}
	assert.Equal(t, 7, dl.Count())
}

func TestExtractPrevHash(t *testing.T) {
	line := "[2026-03-09T21:00:00.000+10:00] | SYNAPSE | ACCEPT | reason | abc123hash"
	hash := extractPrevHash(line)
	assert.Equal(t, "abc123hash", hash)
}

func TestSplitLines(t *testing.T) {
	lines := splitLines("line1\nline2\r\nline3")
	assert.Len(t, lines, 3)
	assert.Equal(t, "line1", lines[0])
	assert.Equal(t, "line2", lines[1])
	assert.Equal(t, "line3", lines[2])
}
