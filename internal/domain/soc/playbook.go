package soc

// PlaybookAction defines automated responses triggered by playbook rules.
type PlaybookAction string

const (
	ActionAutoBlock  PlaybookAction = "auto_block"  // Block source via shield
	ActionAutoReview PlaybookAction = "auto_review" // Flag for human review
	ActionNotify     PlaybookAction = "notify"      // Send notification
	ActionIsolate    PlaybookAction = "isolate"     // Isolate affected session
	ActionEscalate   PlaybookAction = "escalate"    // Escalate to senior analyst
)

// PlaybookCondition defines when a playbook fires.
type PlaybookCondition struct {
	MinSeverity EventSeverity `json:"min_severity" yaml:"min_severity"` // Minimum severity to trigger
	Categories  []string      `json:"categories" yaml:"categories"`     // Matching categories
	Sources     []EventSource `json:"sources,omitempty" yaml:"sources"` // Restrict to specific sources
	MinEvents   int           `json:"min_events" yaml:"min_events"`     // Minimum events before trigger
}

// Playbook is a YAML-defined automated response rule (§10).
type Playbook struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description" yaml:"description"`
	Enabled     bool              `json:"enabled" yaml:"enabled"`
	Condition   PlaybookCondition `json:"condition" yaml:"condition"`
	Actions     []PlaybookAction  `json:"actions" yaml:"actions"`
	Priority    int               `json:"priority" yaml:"priority"` // Higher = runs first
}

// Matches checks if a SOC event matches this playbook's conditions.
func (p *Playbook) Matches(event SOCEvent) bool {
	if !p.Enabled {
		return false
	}

	// Check severity threshold.
	if event.Severity.Rank() < p.Condition.MinSeverity.Rank() {
		return false
	}

	// Check category if specified.
	if len(p.Condition.Categories) > 0 {
		matched := false
		for _, cat := range p.Condition.Categories {
			if cat == event.Category {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check source restriction if specified.
	if len(p.Condition.Sources) > 0 {
		matched := false
		for _, src := range p.Condition.Sources {
			if src == event.Source {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// DefaultPlaybooks returns the built-in playbook set (§10 from spec).
func DefaultPlaybooks() []Playbook {
	return []Playbook{
		{
			ID:          "pb-auto-block-jailbreak",
			Name:        "Auto-Block Jailbreak",
			Description: "Automatically block confirmed jailbreak attempts",
			Enabled:     true,
			Condition: PlaybookCondition{
				MinSeverity: SeverityHigh,
				Categories:  []string{"jailbreak", "prompt_injection"},
			},
			Actions:  []PlaybookAction{ActionAutoBlock, ActionNotify},
			Priority: 100,
		},
		{
			ID:          "pb-escalate-exfiltration",
			Name:        "Escalate Exfiltration",
			Description: "Escalate data exfiltration attempts to senior analyst",
			Enabled:     true,
			Condition: PlaybookCondition{
				MinSeverity: SeverityCritical,
				Categories:  []string{"exfiltration", "data_leak"},
			},
			Actions:  []PlaybookAction{ActionIsolate, ActionEscalate, ActionNotify},
			Priority: 200,
		},
		{
			ID:          "pb-review-tool-abuse",
			Name:        "Review Tool Abuse",
			Description: "Flag tool abuse attempts for human review",
			Enabled:     true,
			Condition: PlaybookCondition{
				MinSeverity: SeverityMedium,
				Categories:  []string{"tool_abuse", "unauthorized_tool_use"},
			},
			Actions:  []PlaybookAction{ActionAutoReview},
			Priority: 50,
		},
	}
}
