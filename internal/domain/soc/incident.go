package soc

import (
	"fmt"
	"time"
)

// IncidentStatus tracks the lifecycle of a SOC incident.
type IncidentStatus string

const (
	StatusOpen          IncidentStatus = "OPEN"
	StatusInvestigating IncidentStatus = "INVESTIGATING"
	StatusResolved      IncidentStatus = "RESOLVED"
	StatusFalsePositive IncidentStatus = "FALSE_POSITIVE"
)

// Incident represents a correlated security incident aggregated from multiple SOCEvents.
// Each incident maintains a cryptographic anchor to the Decision Logger hash chain.
type Incident struct {
	ID                  string         `json:"id"` // INC-YYYY-NNNN
	Status              IncidentStatus `json:"status"`
	Severity            EventSeverity  `json:"severity"` // Max severity of constituent events
	Title               string         `json:"title"`
	Description         string         `json:"description"`
	Events              []string       `json:"events"` // Event IDs
	EventCount          int            `json:"event_count"`
	DecisionChainAnchor string         `json:"decision_chain_anchor"` // SHA-256 hash (§5.6)
	ChainLength         int            `json:"chain_length"`
	CorrelationRule     string         `json:"correlation_rule"` // Rule that triggered this incident
	KillChainPhase      string         `json:"kill_chain_phase"` // Reconnaissance/Exploitation/Exfiltration
	MITREMapping        []string       `json:"mitre_mapping"`    // T-codes
	PlaybookApplied     string         `json:"playbook_applied,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
	ResolvedAt          *time.Time     `json:"resolved_at,omitempty"`
	AssignedTo          string         `json:"assigned_to,omitempty"`
}

// incidentCounter is a simple in-memory counter for generating incident IDs.
var incidentCounter int

// NewIncident creates a new incident from a correlation match.
func NewIncident(title string, severity EventSeverity, correlationRule string) Incident {
	incidentCounter++
	return Incident{
		ID:              fmt.Sprintf("INC-%d-%04d", time.Now().Year(), incidentCounter),
		Status:          StatusOpen,
		Severity:        severity,
		Title:           title,
		CorrelationRule: correlationRule,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
}

// AddEvent adds an event ID to the incident and updates severity if needed.
func (inc *Incident) AddEvent(eventID string, severity EventSeverity) {
	inc.Events = append(inc.Events, eventID)
	inc.EventCount = len(inc.Events)
	if severity.Rank() > inc.Severity.Rank() {
		inc.Severity = severity
	}
	inc.UpdatedAt = time.Now()
}

// SetAnchor sets the Decision Logger chain anchor for forensics (§5.6).
func (inc *Incident) SetAnchor(hash string, chainLength int) {
	inc.DecisionChainAnchor = hash
	inc.ChainLength = chainLength
	inc.UpdatedAt = time.Now()
}

// Resolve marks the incident as resolved.
func (inc *Incident) Resolve(status IncidentStatus) {
	now := time.Now()
	inc.Status = status
	inc.ResolvedAt = &now
	inc.UpdatedAt = now
}

// IsOpen returns true if the incident is not resolved.
func (inc *Incident) IsOpen() bool {
	return inc.Status == StatusOpen || inc.Status == StatusInvestigating
}

// MTTD returns Mean Time To Detect (time from first event to incident creation).
// Requires the timestamp of the first correlated event.
func (inc *Incident) MTTD(firstEventTime time.Time) time.Duration {
	return inc.CreatedAt.Sub(firstEventTime)
}

// MTTR returns Mean Time To Resolve (time from creation to resolution).
// Returns 0 if not yet resolved.
func (inc *Incident) MTTR() time.Duration {
	if inc.ResolvedAt == nil {
		return 0
	}
	return inc.ResolvedAt.Sub(inc.CreatedAt)
}
