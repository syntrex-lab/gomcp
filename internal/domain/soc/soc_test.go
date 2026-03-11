package soc

import (
	"testing"
	"time"
)

// === Event Tests ===

func TestNewSOCEvent(t *testing.T) {
	e := NewSOCEvent(SourceSentinelCore, SeverityHigh, "jailbreak", "Detected jailbreak attempt")
	if e.Source != SourceSentinelCore {
		t.Errorf("expected source sentinel-core, got %s", e.Source)
	}
	if e.Severity != SeverityHigh {
		t.Errorf("expected severity HIGH, got %s", e.Severity)
	}
	if e.Category != "jailbreak" {
		t.Errorf("expected category jailbreak, got %s", e.Category)
	}
	if e.Verdict != VerdictReview {
		t.Errorf("expected default verdict REVIEW, got %s", e.Verdict)
	}
	if e.ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestEventSeverityRank(t *testing.T) {
	tests := []struct {
		sev  EventSeverity
		rank int
	}{
		{SeverityInfo, 1},
		{SeverityLow, 2},
		{SeverityMedium, 3},
		{SeverityHigh, 4},
		{SeverityCritical, 5},
	}
	for _, tt := range tests {
		if got := tt.sev.Rank(); got != tt.rank {
			t.Errorf("%s.Rank() = %d, want %d", tt.sev, got, tt.rank)
		}
	}
}

func TestEventBuilders(t *testing.T) {
	e := NewSOCEvent(SourceShield, SeverityMedium, "network_block", "Blocked connection").
		WithSensor("shield-01").
		WithConfidence(0.85).
		WithVerdict(VerdictDeny)

	if e.SensorID != "shield-01" {
		t.Errorf("expected sensor shield-01, got %s", e.SensorID)
	}
	if e.Confidence != 0.85 {
		t.Errorf("expected confidence 0.85, got %f", e.Confidence)
	}
	if e.Verdict != VerdictDeny {
		t.Errorf("expected verdict DENY, got %s", e.Verdict)
	}
}

func TestEventConfidenceClamping(t *testing.T) {
	e := NewSOCEvent(SourceGoMCP, SeverityInfo, "test", "test")
	if e2 := e.WithConfidence(-0.5); e2.Confidence != 0 {
		t.Errorf("expected clamped to 0, got %f", e2.Confidence)
	}
	if e2 := e.WithConfidence(1.5); e2.Confidence != 1 {
		t.Errorf("expected clamped to 1, got %f", e2.Confidence)
	}
}

func TestEventIsCritical(t *testing.T) {
	if !NewSOCEvent(SourceGoMCP, SeverityHigh, "x", "x").IsCritical() {
		t.Error("HIGH should be critical")
	}
	if !NewSOCEvent(SourceGoMCP, SeverityCritical, "x", "x").IsCritical() {
		t.Error("CRITICAL should be critical")
	}
	if NewSOCEvent(SourceGoMCP, SeverityMedium, "x", "x").IsCritical() {
		t.Error("MEDIUM should not be critical")
	}
}

// === Incident Tests ===

func TestNewIncident(t *testing.T) {
	inc := NewIncident("Multi-stage Jailbreak", SeverityHigh, "jailbreak_chain")
	if inc.Status != StatusOpen {
		t.Errorf("expected OPEN, got %s", inc.Status)
	}
	if inc.Severity != SeverityHigh {
		t.Errorf("expected HIGH, got %s", inc.Severity)
	}
	if inc.ID == "" {
		t.Error("expected non-empty ID")
	}
	if !inc.IsOpen() {
		t.Error("new incident should be open")
	}
}

func TestIncidentAddEvent(t *testing.T) {
	inc := NewIncident("Test", SeverityMedium, "test_rule")
	inc.AddEvent("evt-1", SeverityMedium)
	inc.AddEvent("evt-2", SeverityCritical)

	if inc.EventCount != 2 {
		t.Errorf("expected 2 events, got %d", inc.EventCount)
	}
	if inc.Severity != SeverityCritical {
		t.Errorf("severity should escalate to CRITICAL, got %s", inc.Severity)
	}
}

func TestIncidentResolve(t *testing.T) {
	inc := NewIncident("Test", SeverityHigh, "test_rule")
	inc.Resolve(StatusResolved)

	if inc.IsOpen() {
		t.Error("resolved incident should not be open")
	}
	if inc.ResolvedAt == nil {
		t.Error("resolved incident should have resolved timestamp")
	}
	if inc.Status != StatusResolved {
		t.Errorf("expected RESOLVED, got %s", inc.Status)
	}
}

func TestIncidentSetAnchor(t *testing.T) {
	inc := NewIncident("Test", SeverityHigh, "test_rule")
	inc.SetAnchor("abc123def456", 7)
	if inc.DecisionChainAnchor != "abc123def456" {
		t.Error("anchor not set")
	}
	if inc.ChainLength != 7 {
		t.Errorf("expected chain length 7, got %d", inc.ChainLength)
	}
}

func TestIncidentMTTR(t *testing.T) {
	inc := NewIncident("Test", SeverityHigh, "test_rule")
	if inc.MTTR() != 0 {
		t.Error("unresolved MTTR should be 0")
	}
	time.Sleep(10 * time.Millisecond)
	inc.Resolve(StatusResolved)
	if inc.MTTR() <= 0 {
		t.Error("resolved MTTR should be positive")
	}
}

// === Sensor Tests ===

func TestSensorLifecycle(t *testing.T) {
	s := NewSensor("core-01", SensorTypeSentinelCore)

	// Initially UNKNOWN
	if s.Status != SensorStatusUnknown {
		t.Errorf("expected UNKNOWN, got %s", s.Status)
	}

	// After 2 events still UNKNOWN
	s.RecordEvent()
	s.RecordEvent()
	if s.Status != SensorStatusUnknown {
		t.Errorf("expected UNKNOWN after 2 events, got %s", s.Status)
	}

	// After 3rd event → HEALTHY
	s.RecordEvent()
	if s.Status != SensorStatusHealthy {
		t.Errorf("expected HEALTHY after 3 events, got %s", s.Status)
	}

	// 3 missed heartbeats → DEGRADED
	for i := 0; i < MissedHeartbeatDegraded; i++ {
		s.MissHeartbeat()
	}
	if s.Status != SensorStatusDegraded {
		t.Errorf("expected DEGRADED, got %s", s.Status)
	}

	// Activity recovers from DEGRADED
	s.RecordEvent()
	if s.Status != SensorStatusHealthy {
		t.Errorf("expected recovery to HEALTHY, got %s", s.Status)
	}
}

func TestSensorOfflineAlert(t *testing.T) {
	s := NewSensor("shield-01", SensorTypeShield)
	// Get to HEALTHY first
	for i := 0; i < EventsToHealthy; i++ {
		s.RecordEvent()
	}

	// Miss heartbeats until OFFLINE
	var alertGenerated bool
	for i := 0; i < MissedHeartbeatOffline; i++ {
		alertGenerated = s.MissHeartbeat()
	}
	if !alertGenerated {
		t.Error("expected alert on OFFLINE transition")
	}
	if s.Status != SensorStatusOffline {
		t.Errorf("expected OFFLINE, got %s", s.Status)
	}
}

func TestSensorHeartbeatRecovery(t *testing.T) {
	s := NewSensor("immune-01", SensorTypeImmune)
	for i := 0; i < EventsToHealthy; i++ {
		s.RecordEvent()
	}
	// Go degraded
	for i := 0; i < MissedHeartbeatDegraded; i++ {
		s.MissHeartbeat()
	}
	if s.Status != SensorStatusDegraded {
		t.Fatalf("expected DEGRADED, got %s", s.Status)
	}
	// Heartbeat recovery
	s.RecordHeartbeat()
	if s.Status != SensorStatusHealthy {
		t.Errorf("expected HEALTHY after heartbeat, got %s", s.Status)
	}
}

// === Playbook Tests ===

func TestPlaybookMatches(t *testing.T) {
	pb := Playbook{
		ID:      "pb-test",
		Enabled: true,
		Condition: PlaybookCondition{
			MinSeverity: SeverityHigh,
			Categories:  []string{"jailbreak", "prompt_injection"},
		},
		Actions: []PlaybookAction{ActionAutoBlock},
	}

	// Should match
	evt := NewSOCEvent(SourceSentinelCore, SeverityCritical, "jailbreak", "test")
	if !pb.Matches(evt) {
		t.Error("expected match for jailbreak + CRITICAL")
	}

	// Should not match — low severity
	evt2 := NewSOCEvent(SourceSentinelCore, SeverityLow, "jailbreak", "test")
	if pb.Matches(evt2) {
		t.Error("should not match LOW severity")
	}

	// Should not match — wrong category
	evt3 := NewSOCEvent(SourceSentinelCore, SeverityCritical, "network_block", "test")
	if pb.Matches(evt3) {
		t.Error("should not match wrong category")
	}

	// Disabled playbook
	pb.Enabled = false
	if pb.Matches(evt) {
		t.Error("disabled playbook should not match")
	}
}

func TestPlaybookSourceFilter(t *testing.T) {
	pb := Playbook{
		ID:      "pb-shield-only",
		Enabled: true,
		Condition: PlaybookCondition{
			MinSeverity: SeverityMedium,
			Categories:  []string{"network_block"},
			Sources:     []EventSource{SourceShield},
		},
		Actions: []PlaybookAction{ActionNotify},
	}

	// Shield source should match
	evt := NewSOCEvent(SourceShield, SeverityHigh, "network_block", "test")
	if !pb.Matches(evt) {
		t.Error("expected match for shield source")
	}

	// Non-shield source should not match
	evt2 := NewSOCEvent(SourceSentinelCore, SeverityHigh, "network_block", "test")
	if pb.Matches(evt2) {
		t.Error("should not match non-shield source")
	}
}

func TestDefaultPlaybooks(t *testing.T) {
	pbs := DefaultPlaybooks()
	if len(pbs) != 3 {
		t.Errorf("expected 3 default playbooks, got %d", len(pbs))
	}
	// Check all are enabled
	for _, pb := range pbs {
		if !pb.Enabled {
			t.Errorf("default playbook %s should be enabled", pb.ID)
		}
	}
}
