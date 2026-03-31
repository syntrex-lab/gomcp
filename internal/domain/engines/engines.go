// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

package engines

import (
	"context"
	"time"
)

// EngineStatus represents the health state of a security engine.
type EngineStatus string

const (
	EngineHealthy      EngineStatus = "HEALTHY"
	EngineDegraded     EngineStatus = "DEGRADED"
	EngineOffline      EngineStatus = "OFFLINE"
	EngineInitializing EngineStatus = "INITIALIZING"
)

// ScanResult is the unified output from any security engine.
type ScanResult struct {
	Engine      string        `json:"engine"`
	ThreatFound bool          `json:"threat_found"`
	ThreatType  string        `json:"threat_type,omitempty"`
	Severity    string        `json:"severity"`
	Confidence  float64       `json:"confidence"`
	Details     string        `json:"details,omitempty"`
	Indicators  []string      `json:"indicators,omitempty"`
	Duration    time.Duration `json:"duration_ns"`
	Timestamp   time.Time     `json:"timestamp"`
}

// SentinelCore defines the interface for the Rust-based detection engine (§3).
// Real implementation: FFI bridge to sentinel-core Rust binary.
// Stub implementation: used when sentinel-core is not deployed.
type SentinelCore interface {
	// Name returns the engine identifier.
	Name() string

	// Status returns current engine health.
	Status() EngineStatus

	// ScanPrompt analyzes an LLM prompt for injection/jailbreak patterns.
	ScanPrompt(ctx context.Context, prompt string) (*ScanResult, error)

	// ScanResponse analyzes an LLM response for data exfiltration or harmful content.
	ScanResponse(ctx context.Context, response string) (*ScanResult, error)

	// Version returns the engine version.
	Version() string
}

// Shield defines the interface for the C++ network protection engine (§4).
// Real implementation: FFI bridge to shield C++ shared library.
// Stub implementation: used when shield is not deployed.
type Shield interface {
	// Name returns the engine identifier.
	Name() string

	// Status returns current engine health.
	Status() EngineStatus

	// InspectTraffic analyzes network traffic for threats.
	InspectTraffic(ctx context.Context, payload []byte, metadata map[string]string) (*ScanResult, error)

	// BlockIP adds an IP to the block list.
	BlockIP(ctx context.Context, ip string, reason string, duration time.Duration) error

	// ListBlocked returns currently blocked IPs.
	ListBlocked(ctx context.Context) ([]BlockedIP, error)

	// Version returns the engine version.
	Version() string
}

// BlockedIP represents a blocked IP entry.
type BlockedIP struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// --- Stub implementations for standalone Go deployment ---

// StubSentinelCore is a no-op sentinel-core when Rust engine is not deployed.
type StubSentinelCore struct{}

func NewStubSentinelCore() *StubSentinelCore     { return &StubSentinelCore{} }
func (s *StubSentinelCore) Name() string         { return "sentinel-core-stub" }
func (s *StubSentinelCore) Status() EngineStatus { return EngineOffline }
func (s *StubSentinelCore) Version() string      { return "stub-1.0" }

func (s *StubSentinelCore) ScanPrompt(_ context.Context, _ string) (*ScanResult, error) {
	return &ScanResult{
		Engine:      "sentinel-core-stub",
		ThreatFound: false,
		Severity:    "NONE",
		Confidence:  0,
		Details:     "sentinel-core not deployed, stub mode",
		Timestamp:   time.Now(),
	}, nil
}

func (s *StubSentinelCore) ScanResponse(_ context.Context, _ string) (*ScanResult, error) {
	return &ScanResult{
		Engine:      "sentinel-core-stub",
		ThreatFound: false,
		Severity:    "NONE",
		Confidence:  0,
		Details:     "sentinel-core not deployed, stub mode",
		Timestamp:   time.Now(),
	}, nil
}

// StubShield is a no-op shield when C++ engine is not deployed.
type StubShield struct{}

func NewStubShield() *StubShield           { return &StubShield{} }
func (s *StubShield) Name() string         { return "shield-stub" }
func (s *StubShield) Status() EngineStatus { return EngineOffline }
func (s *StubShield) Version() string      { return "stub-1.0" }

func (s *StubShield) InspectTraffic(_ context.Context, _ []byte, _ map[string]string) (*ScanResult, error) {
	return &ScanResult{
		Engine:      "shield-stub",
		ThreatFound: false,
		Severity:    "NONE",
		Details:     "shield not deployed, stub mode",
		Timestamp:   time.Now(),
	}, nil
}

func (s *StubShield) BlockIP(_ context.Context, _ string, _ string, _ time.Duration) error {
	return nil
}

func (s *StubShield) ListBlocked(_ context.Context) ([]BlockedIP, error) {
	return nil, nil
}
