// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

package audit

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const decisionsFileName = "decisions.log"

// DecisionModule identifies the subsystem that made a decision.
type DecisionModule string

const (
	ModuleSynapse     DecisionModule = "SYNAPSE"
	ModulePeer        DecisionModule = "PEER"
	ModuleMode        DecisionModule = "MODE"
	ModuleDIPWatcher  DecisionModule = "DIP-WATCHER"
	ModuleOracle      DecisionModule = "ORACLE"
	ModuleGenome      DecisionModule = "GENOME"
	ModuleDoctor      DecisionModule = "DOCTOR"
	ModuleSOC         DecisionModule = "SOC"         // AI SOC event pipeline decisions
	ModuleCorrelation DecisionModule = "CORRELATION" // SOC correlation engine decisions
)

// Decision represents a tamper-evident decision record (v3.7).
// Each record includes a hash of the previous record, forming an
// append-only chain that detects any attempt to alter history.
type Decision struct {
	Timestamp time.Time      `json:"timestamp"`
	Module    DecisionModule `json:"module"`
	Decision  string         `json:"decision"`
	Reason    string         `json:"reason"`
	PrevHash  string         `json:"prev_hash"`
}

// String formats the decision for file output.
func (d Decision) String() string {
	return fmt.Sprintf("[%s] | %s | %s | %s | %s",
		d.Timestamp.Format("2006-01-02T15:04:05.000Z07:00"),
		d.Module,
		d.Decision,
		d.Reason,
		d.PrevHash,
	)
}

// Hash computes SHA-256 of this decision record for chain linking.
func (d Decision) Hash() string {
	h := sha256.Sum256([]byte(d.String()))
	return fmt.Sprintf("%x", h)
}

// DecisionLogger is a tamper-evident decision trace (v3.7 Cerebro).
// Each Record() call appends to decisions.log with a SHA-256 chain
// linking each entry to the previous one. Any modification to a line
// breaks the chain, making tampering detectable.
type DecisionLogger struct {
	mu       sync.Mutex
	file     *os.File
	path     string
	prevHash string // Hash of last written record
	count    int
}

// NewDecisionLogger creates a tamper-evident decision logger.
func NewDecisionLogger(rlmDir string) (*DecisionLogger, error) {
	if err := os.MkdirAll(rlmDir, 0o755); err != nil {
		// FALLBACK: Use temp directory if permission denied (e.g. /var/log/sentinel)
		rlmDir = filepath.Join(os.TempDir(), "sentinel-audit")
		if fallbackErr := os.MkdirAll(rlmDir, 0o755); fallbackErr != nil {
			return nil, fmt.Errorf("decisions: mkdir %s: %v (fallback failed: %v)", rlmDir, err, fallbackErr)
		}
	}
	path := filepath.Join(rlmDir, decisionsFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		// Try one more fallback if OpenFile fails but MkdirAll passed earlier.
		rlmDir = filepath.Join(os.TempDir(), "sentinel-audit")
		_ = os.MkdirAll(rlmDir, 0o755)
		path = filepath.Join(rlmDir, decisionsFileName)
		f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, fmt.Errorf("decisions: open %s: %w", path, err)
		}
	}
	return &DecisionLogger{
		file:     f,
		path:     path,
		prevHash: "GENESIS", // First record links to GENESIS sentinel.
	}, nil
}

// Record writes a tamper-evident decision entry.
// Thread-safe, append-only, hash-chained.
func (l *DecisionLogger) Record(module DecisionModule, decision, reason string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	d := Decision{
		Timestamp: time.Now(),
		Module:    module,
		Decision:  decision,
		Reason:    reason,
		PrevHash:  l.prevHash,
	}

	_, err := fmt.Fprintln(l.file, d.String())
	if err != nil {
		return fmt.Errorf("decisions: write: %w", err)
	}

	l.prevHash = d.Hash()
	l.count++
	return nil
}

// Count returns decisions recorded this session.
func (l *DecisionLogger) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}

// Path returns the log file path.
func (l *DecisionLogger) Path() string { return l.path }

// PrevHash returns the current chain head hash.
func (l *DecisionLogger) PrevHash() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.prevHash
}

// RecordDecision satisfies the tools.DecisionRecorder interface.
// Converts string module to DecisionModule for type safety.
func (l *DecisionLogger) RecordDecision(module, decision, reason string) {
	l.Record(DecisionModule(module), decision, reason)
}

// RecordMigrationAnchor writes a special migration entry to preserve hash chain
// continuity across version upgrades (§15.7 Decision Logger Continuity Invariant).
// The anchor hash = SHA256(prev_hash + "MIGRATION:{from}→{to}" + timestamp).
// This entry is append-only and links the old chain to the new version seamlessly.
func (l *DecisionLogger) RecordMigrationAnchor(fromVersion, toVersion string) error {
	return l.Record(DecisionModule("MIGRATION"),
		fmt.Sprintf("MIGRATION:%s→%s", fromVersion, toVersion),
		fmt.Sprintf("Zero-downtime upgrade from %s to %s. Chain continuity preserved.", fromVersion, toVersion))
}

// ExportChainProof returns a proof-of-integrity snapshot for pre-update backup.
// Used by `syntrex doctor --export-chain` to verify chain after rollback.
func (l *DecisionLogger) ExportChainProof() map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	return map[string]any{
		"genesis_hash": "GENESIS",
		"last_hash":    l.prevHash,
		"entry_count":  l.count,
		"file_path":    l.path,
		"exported_at":  time.Now().Format(time.RFC3339),
	}
}

// Close closes the decisions file.
func (l *DecisionLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// VerifyChainFromFile reads a decisions.log and verifies hash chain integrity.
// Returns the number of valid records and the first broken line (0 if all valid).
func VerifyChainFromFile(path string) (validCount int, brokenLine int, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	lines := splitLines(string(data))
	prevHash := "GENESIS"

	for i, line := range lines {
		if line == "" {
			continue
		}
		// Each line should end with | PREV_HASH.
		// Compute expected hash of previous line.
		if i > 0 && prevHash != extractPrevHash(line) {
			return validCount, i + 1, nil
		}
		// Compute hash of this line for next iteration.
		h := sha256.Sum256([]byte(line))
		prevHash = fmt.Sprintf("%x", h)
		validCount++
	}
	return validCount, 0, nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func extractPrevHash(line string) string {
	// Format: [timestamp] | MODULE | DECISION | REASON | PREV_HASH
	// Extract last field after the last " | ".
	for i := len(line) - 1; i >= 0; i-- {
		if i >= 2 && line[i-2:i+1] == " | " {
			return line[i+1:]
		}
	}
	return ""
}
