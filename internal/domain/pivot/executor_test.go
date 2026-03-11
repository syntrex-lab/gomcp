package pivot

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockOracle struct {
	verdict string
	reason  string
}

func (m *mockOracle) VerifyAction(action string) (string, string) {
	return m.verdict, m.reason
}

func TestExecutor_NoZeroG(t *testing.T) {
	dir := t.TempDir()
	rec := &mockRecorder{}
	e := NewExecutor(dir, nil, rec)

	result := e.Execute("echo hello")
	assert.False(t, result.ZeroGMode)
	assert.Contains(t, result.Error, "ZERO-G mode required")
	assert.True(t, len(rec.decisions) > 0)
	assert.Contains(t, rec.decisions[0], "EXEC_BLOCKED")
}

func TestExecutor_OracleDeny(t *testing.T) {
	dir := t.TempDir()
	// Create .sentinel_leash with ZERO-G.
	createLeash(t, dir, "ZERO-G")

	oracle := &mockOracle{verdict: "DENY", reason: "denied by policy"}
	rec := &mockRecorder{}
	e := NewExecutor(dir+"/.rlm", oracle, rec)

	result := e.Execute("rm -rf /")
	assert.True(t, result.ZeroGMode)
	assert.False(t, result.OraclePass)
	assert.Contains(t, result.Error, "BLOCKED by Oracle")
}

func TestExecutor_Success(t *testing.T) {
	dir := t.TempDir()
	createLeash(t, dir, "ZERO-G")

	oracle := &mockOracle{verdict: "ALLOW", reason: "stealth"}
	rec := &mockRecorder{}
	e := NewExecutor(dir+"/.rlm", oracle, rec)
	e.SetTimeout(5 * time.Second)

	result := e.Execute("echo hello_pivot")
	assert.True(t, result.ZeroGMode)
	assert.True(t, result.OraclePass)
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, result.Stdout, "hello_pivot")
}

func TestExecutor_StealthPrefix(t *testing.T) {
	dir := t.TempDir()
	createLeash(t, dir, "ZERO-G")

	rec := &mockRecorder{}
	e := NewExecutor(dir+"/.rlm", nil, rec) // no oracle = passthrough

	result := e.Execute("stealth echo stealth_test")
	assert.True(t, result.OraclePass)
	assert.Contains(t, result.Stdout, "stealth_test")
}

func TestExecutor_Timeout(t *testing.T) {
	dir := t.TempDir()
	createLeash(t, dir, "ZERO-G")

	rec := &mockRecorder{}
	e := NewExecutor(dir+"/.rlm", nil, rec)
	e.SetTimeout(100 * time.Millisecond)

	result := e.Execute("ping -n 10 127.0.0.1")
	assert.NotEqual(t, 0, result.ExitCode)
}

func TestParseCommand(t *testing.T) {
	parts := parseCommand("stealth echo hello")
	// Should strip "stealth " prefix.
	assert.Equal(t, "cmd", parts[0])
	assert.Equal(t, "/C", parts[1])
	assert.Equal(t, "echo hello", parts[2])
}

func TestLimitedWriter(t *testing.T) {
	var buf = new(bytes.Buffer)
	lw := &limitedWriter{w: buf, limit: 10}
	lw.Write([]byte("12345"))
	lw.Write([]byte("67890"))
	lw.Write([]byte("overflow")) // Should be silently discarded.
	assert.Equal(t, "1234567890", buf.String())
}

func createLeash(t *testing.T, dir, mode string) {
	t.Helper()
	os.MkdirAll(dir+"/.rlm", 0o755)
	os.WriteFile(dir+"/.sentinel_leash", []byte(mode), 0o644)
}
