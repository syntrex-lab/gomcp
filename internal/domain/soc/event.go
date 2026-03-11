// Package soc defines domain entities for the SENTINEL AI SOC subsystem.
// SOC extends gomcp's alert/oracle layer with multi-source event ingestion,
// incident management, sensor lifecycle, and compliance reporting.
package soc

import (
	"fmt"
	"time"
)

// EventSeverity represents SOC-specific severity levels (extended from alert.Severity).
type EventSeverity string

const (
	SeverityInfo     EventSeverity = "INFO"
	SeverityLow      EventSeverity = "LOW"
	SeverityMedium   EventSeverity = "MEDIUM"
	SeverityHigh     EventSeverity = "HIGH"
	SeverityCritical EventSeverity = "CRITICAL"
)

// SeverityRank returns numeric rank for comparison (higher = more severe).
func (s EventSeverity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Verdict represents a SOC decision outcome.
type Verdict string

const (
	VerdictAllow    Verdict = "ALLOW"
	VerdictDeny     Verdict = "DENY"
	VerdictReview   Verdict = "REVIEW"
	VerdictEscalate Verdict = "ESCALATE"
)

// EventSource identifies the sensor or subsystem that generated the event.
type EventSource string

const (
	SourceSentinelCore EventSource = "sentinel-core"
	SourceShield       EventSource = "shield"
	SourceImmune       EventSource = "immune"
	SourceMicroSwarm   EventSource = "micro-swarm"
	SourceGoMCP        EventSource = "gomcp"
	SourceExternal     EventSource = "external"
)

// SOCEvent represents a security event ingested into the AI SOC Event Bus.
// This is the core entity flowing through the pipeline:
// Sensor → Secret Scanner (Step 0) → DIP → Decision Logger → Queue → Correlation.
type SOCEvent struct {
	ID           string            `json:"id"`
	Source       EventSource       `json:"source"`
	SensorID     string            `json:"sensor_id"`
	SensorKey    string            `json:"-"` // §17.3 T-01: pre-shared key (never serialized)
	Severity     EventSeverity     `json:"severity"`
	Category     string            `json:"category"`    // e.g., "jailbreak", "injection", "exfiltration"
	Subcategory  string            `json:"subcategory"` // e.g., "sql_injection", "tool_abuse"
	Confidence   float64           `json:"confidence"`  // 0.0 - 1.0
	Description  string            `json:"description"`
	Payload      string            `json:"payload,omitempty"` // Raw input for Secret Scanner Step 0
	SessionID    string            `json:"session_id,omitempty"`
	DecisionHash string            `json:"decision_hash,omitempty"` // SHA-256 chain link
	Verdict      Verdict           `json:"verdict"`
	ZeroGMode    bool              `json:"zero_g_mode,omitempty"` // §13.4: Strike Force operation tag
	Timestamp    time.Time         `json:"timestamp"`
	Metadata     map[string]string `json:"metadata,omitempty"` // Extensible key-value pairs
}

// NewSOCEvent creates a new SOC event with auto-generated ID.
func NewSOCEvent(source EventSource, severity EventSeverity, category, description string) SOCEvent {
	return SOCEvent{
		ID:          fmt.Sprintf("evt-%d-%s", time.Now().UnixMicro(), source),
		Source:      source,
		Severity:    severity,
		Category:    category,
		Description: description,
		Verdict:     VerdictReview, // Default: needs review
		Timestamp:   time.Now(),
	}
}

// WithSensor sets the sensor ID.
func (e SOCEvent) WithSensor(sensorID string) SOCEvent {
	e.SensorID = sensorID
	return e
}

// WithConfidence sets the confidence score.
func (e SOCEvent) WithConfidence(c float64) SOCEvent {
	if c < 0 {
		c = 0
	}
	if c > 1 {
		c = 1
	}
	e.Confidence = c
	return e
}

// WithVerdict sets the verdict.
func (e SOCEvent) WithVerdict(v Verdict) SOCEvent {
	e.Verdict = v
	return e
}

// IsCritical returns true if severity is HIGH or CRITICAL.
func (e SOCEvent) IsCritical() bool {
	return e.Severity == SeverityHigh || e.Severity == SeverityCritical
}
