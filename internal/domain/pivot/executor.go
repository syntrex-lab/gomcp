// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

// Package pivot — Execution Layer for Pivot Engine (v3.8 Strike Force).
// Executes system commands in ZERO-G mode after Oracle verification.
// All executions are logged to decisions.log (tamper-evident).
package pivot

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// MaxOutputBytes caps command output to prevent memory exhaustion.
	MaxOutputBytes = 64 * 1024 // 64KB
	// DefaultTimeout for command execution.
	DefaultTimeout = 30 * time.Second
)

// ExecResult holds the result of a command execution.
type ExecResult struct {
	Command    string        `json:"command"`
	Args       []string      `json:"args"`
	Stdout     string        `json:"stdout"`
	Stderr     string        `json:"stderr"`
	ExitCode   int           `json:"exit_code"`
	Duration   time.Duration `json:"duration"`
	OraclePass bool          `json:"oracle_pass"`
	ZeroGMode  bool          `json:"zero_g_mode"`
	Error      string        `json:"error,omitempty"`
}

// OracleGate verifies actions. Implemented by oracle.Oracle.
type OracleGate interface {
	VerifyAction(action string) (verdict string, reason string)
}

// Executor runs system commands under Pivot Engine control.
type Executor struct {
	rlmDir   string
	oracle   OracleGate
	recorder DecisionRecorder
	timeout  time.Duration
}

// NewExecutor creates a new command executor.
func NewExecutor(rlmDir string, oracle OracleGate, recorder DecisionRecorder) *Executor {
	return &Executor{
		rlmDir:   rlmDir,
		oracle:   oracle,
		recorder: recorder,
		timeout:  DefaultTimeout,
	}
}

// SetTimeout overrides the default execution timeout.
func (e *Executor) SetTimeout(d time.Duration) {
	if d > 0 {
		e.timeout = d
	}
}

// Execute runs a command string after ZERO-G and Oracle verification.
// Returns ExecResult with full audit trail.
func (e *Executor) Execute(cmdLine string) ExecResult {
	result := ExecResult{
		Command: cmdLine,
	}

	// Gate 1: ZERO-G mode check.
	zeroG := e.isZeroG()
	result.ZeroGMode = zeroG
	if !zeroG {
		result.Error = "BLOCKED: ZERO-G mode required for command execution"
		e.record("EXEC_BLOCKED", fmt.Sprintf("cmd='%s' reason=not_zero_g", truncate(cmdLine, 60)))
		return result
	}

	// Gate 2: Oracle verification.
	if e.oracle != nil {
		verdict, reason := e.oracle.VerifyAction(cmdLine)
		result.OraclePass = (verdict == "ALLOW")
		if verdict == "DENY" {
			result.Error = fmt.Sprintf("BLOCKED by Oracle: %s", reason)
			e.record("EXEC_DENIED", fmt.Sprintf("cmd='%s' reason=%s", truncate(cmdLine, 60), reason))
			return result
		}
	} else {
		result.OraclePass = true // No oracle = passthrough in ZERO-G
	}

	// Parse command.
	parts := parseCommand(cmdLine)
	if len(parts) == 0 {
		result.Error = "empty command"
		return result
	}

	result.Command = parts[0]
	if len(parts) > 1 {
		result.Args = parts[1:]
	}

	// Execute with timeout.
	e.record("EXEC_START", fmt.Sprintf("cmd='%s' args=%v timeout=%s", result.Command, result.Args, e.timeout))

	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, result.Command, result.Args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, limit: MaxOutputBytes}
	cmd.Stderr = &limitedWriter{w: &stderr, limit: MaxOutputBytes}

	start := time.Now()
	err := cmd.Run()
	result.Duration = time.Since(start)
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()

	if err != nil {
		result.Error = err.Error()
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
	}

	e.record("EXEC_COMPLETE", fmt.Sprintf("cmd='%s' exit=%d duration=%s stdout_len=%d",
		result.Command, result.ExitCode, result.Duration, len(result.Stdout)))

	return result
}

// isZeroG checks if .sentinel_leash contains ZERO-G.
func (e *Executor) isZeroG() bool {
	leashPath := filepath.Join(e.rlmDir, "..", ".sentinel_leash")
	data, err := os.ReadFile(leashPath)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "ZERO-G")
}

func (e *Executor) record(decision, reason string) {
	if e.recorder != nil {
		e.recorder.RecordDecision("PIVOT", decision, reason)
	}
}

// parseCommand splits a command string into parts (respects quotes).
func parseCommand(cmdLine string) []string {
	// Strip "stealth " prefix if present (Mimicry passthrough).
	cmdLine = strings.TrimPrefix(cmdLine, "stealth ")

	if runtime.GOOS == "windows" {
		// On Windows, wrap in cmd /C.
		return []string{"cmd", "/C", cmdLine}
	}
	// On Linux/Mac, use sh -c.
	return []string{"sh", "-c", cmdLine}
}

// limitedWriter caps the amount of data written.
type limitedWriter struct {
	w       *bytes.Buffer
	limit   int
	written int
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	remaining := lw.limit - lw.written
	if remaining <= 0 {
		return len(p), nil // Silently discard.
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	n, err := lw.w.Write(p)
	lw.written += n
	return n, err
}
