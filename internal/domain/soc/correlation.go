package soc

import (
	"sort"
	"time"
)

// SOCCorrelationRule defines a time-windowed correlation rule for SOC events.
// Unlike oracle.CorrelationRule (pattern-based), SOC rules operate on event
// categories within a sliding time window.
type SOCCorrelationRule struct {
	ID                 string        `json:"id"`
	Name               string        `json:"name"`
	RequiredCategories []string      `json:"required_categories"` // Event categories that must co-occur
	MinEvents          int           `json:"min_events"`          // Minimum distinct events to trigger
	TimeWindow         time.Duration `json:"time_window"`         // Sliding window for temporal correlation
	Severity           EventSeverity `json:"severity"`            // Resulting incident severity
	KillChainPhase     string        `json:"kill_chain_phase"`
	MITREMapping       []string      `json:"mitre_mapping"`
	Description        string        `json:"description"`
}

// DefaultSOCCorrelationRules returns built-in SOC correlation rules (§7 from spec).
func DefaultSOCCorrelationRules() []SOCCorrelationRule {
	return []SOCCorrelationRule{
		{
			ID:                 "SOC-CR-001",
			Name:               "Multi-stage Jailbreak",
			RequiredCategories: []string{"jailbreak", "tool_abuse"},
			MinEvents:          2,
			TimeWindow:         5 * time.Minute,
			Severity:           SeverityCritical,
			KillChainPhase:     "Exploitation",
			MITREMapping:       []string{"T1059", "T1203"},
			Description:        "Jailbreak attempt followed by tool abuse indicates a staged attack to bypass guardrails and escalate privileges.",
		},
		{
			ID:                 "SOC-CR-002",
			Name:               "Coordinated Attack",
			RequiredCategories: []string{}, // Any 3+ distinct categories from same source
			MinEvents:          3,
			TimeWindow:         10 * time.Minute,
			Severity:           SeverityCritical,
			KillChainPhase:     "Exploitation",
			MITREMapping:       []string{"T1595", "T1190"},
			Description:        "Three or more distinct threat categories from the same source within 10 minutes indicates a coordinated multi-vector attack.",
		},
		{
			ID:                 "SOC-CR-003",
			Name:               "Privilege Escalation Chain",
			RequiredCategories: []string{"auth_bypass", "exfiltration"},
			MinEvents:          2,
			TimeWindow:         15 * time.Minute,
			Severity:           SeverityCritical,
			KillChainPhase:     "Exfiltration",
			MITREMapping:       []string{"T1078", "T1041"},
			Description:        "Authentication bypass followed by data exfiltration attempt within 15 minutes indicates a credential compromise leading to data theft.",
		},
		{
			ID:                 "SOC-CR-004",
			Name:               "Injection Escalation",
			RequiredCategories: []string{"prompt_injection", "jailbreak"},
			MinEvents:          2,
			TimeWindow:         5 * time.Minute,
			Severity:           SeverityHigh,
			KillChainPhase:     "Exploitation",
			MITREMapping:       []string{"T1059.007"},
			Description:        "Prompt injection followed by jailbreak within 5 minutes indicates progressive guardrail erosion attack.",
		},
		{
			ID:                 "SOC-CR-005",
			Name:               "Sensor Manipulation",
			RequiredCategories: []string{"sensor_anomaly", "tool_abuse"},
			MinEvents:          2,
			TimeWindow:         5 * time.Minute,
			Severity:           SeverityCritical,
			KillChainPhase:     "Defense Evasion",
			MITREMapping:       []string{"T1562"},
			Description:        "Sensor anomaly combined with tool abuse suggests attacker is trying to blind defensing before exploitation.",
		},
		{
			ID:                 "SOC-CR-006",
			Name:               "Data Exfiltration Pipeline",
			RequiredCategories: []string{"exfiltration", "encoding"},
			MinEvents:          2,
			TimeWindow:         10 * time.Minute,
			Severity:           SeverityCritical,
			KillChainPhase:     "Exfiltration",
			MITREMapping:       []string{"T1041", "T1132"},
			Description:        "Data exfiltration combined with encoding/obfuscation indicates staged data theft with cover-up.",
		},
		{
			ID:                 "SOC-CR-007",
			Name:               "Stealth Persistence",
			RequiredCategories: []string{"jailbreak", "persistence"},
			MinEvents:          2,
			TimeWindow:         30 * time.Minute,
			Severity:           SeverityHigh,
			KillChainPhase:     "Persistence",
			MITREMapping:       []string{"T1546", "T1053"},
			Description:        "Jailbreak followed by persistence mechanism indicates attacker establishing long-term foothold.",
		},
	}
}

// CorrelationMatch represents a triggered correlation rule with matched events.
type CorrelationMatch struct {
	Rule      SOCCorrelationRule `json:"rule"`
	Events    []SOCEvent         `json:"events"`
	MatchedAt time.Time          `json:"matched_at"`
}

// CorrelateSOCEvents runs all correlation rules against a set of events.
// Events should be pre-filtered to a reasonable time window (e.g., last hour).
// Returns matches sorted by severity (CRITICAL first).
func CorrelateSOCEvents(events []SOCEvent, rules []SOCCorrelationRule) []CorrelationMatch {
	if len(events) == 0 || len(rules) == 0 {
		return nil
	}

	now := time.Now()
	var matches []CorrelationMatch

	for _, rule := range rules {
		match := evaluateRule(rule, events, now)
		if match != nil {
			matches = append(matches, *match)
		}
	}

	// Sort by severity (CRITICAL first)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Rule.Severity.Rank() > matches[j].Rule.Severity.Rank()
	})

	return matches
}

// evaluateRule checks if a single rule matches against the event set.
func evaluateRule(rule SOCCorrelationRule, events []SOCEvent, now time.Time) *CorrelationMatch {
	windowStart := now.Add(-rule.TimeWindow)

	// Filter events within time window.
	var inWindow []SOCEvent
	for _, e := range events {
		if !e.Timestamp.Before(windowStart) {
			inWindow = append(inWindow, e)
		}
	}

	if len(inWindow) < rule.MinEvents {
		return nil
	}

	// Special case: SOC-CR-002 (Coordinated Attack) — check distinct category count.
	if len(rule.RequiredCategories) == 0 && rule.MinEvents > 0 {
		return evaluateCoordinatedAttack(rule, inWindow)
	}

	// Standard case: check that all required categories are present.
	categorySet := make(map[string]bool)
	var matchedEvents []SOCEvent
	for _, e := range inWindow {
		categorySet[e.Category] = true
		// Collect events matching required categories.
		for _, rc := range rule.RequiredCategories {
			if e.Category == rc {
				matchedEvents = append(matchedEvents, e)
				break
			}
		}
	}

	// Check all required categories are present.
	for _, rc := range rule.RequiredCategories {
		if !categorySet[rc] {
			return nil
		}
	}

	if len(matchedEvents) < rule.MinEvents {
		return nil
	}

	return &CorrelationMatch{
		Rule:      rule,
		Events:    matchedEvents,
		MatchedAt: time.Now(),
	}
}

// evaluateCoordinatedAttack checks for N+ distinct categories from same source.
func evaluateCoordinatedAttack(rule SOCCorrelationRule, events []SOCEvent) *CorrelationMatch {
	// Group by source, count distinct categories.
	sourceCategories := make(map[EventSource]map[string]bool)
	sourceEvents := make(map[EventSource][]SOCEvent)

	for _, e := range events {
		if sourceCategories[e.Source] == nil {
			sourceCategories[e.Source] = make(map[string]bool)
		}
		sourceCategories[e.Source][e.Category] = true
		sourceEvents[e.Source] = append(sourceEvents[e.Source], e)
	}

	for source, cats := range sourceCategories {
		if len(cats) >= rule.MinEvents {
			return &CorrelationMatch{
				Rule:      rule,
				Events:    sourceEvents[source],
				MatchedAt: time.Now(),
			}
		}
	}
	return nil
}
