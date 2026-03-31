// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

package tools

// DecisionRecorder is the interface for recording tamper-evident decisions (v3.7).
// Implemented by audit.DecisionLogger. Optional — nil-safe callers should check.
type DecisionRecorder interface {
	RecordDecision(module, decision, reason string)
}

// SetDecisionRecorder injects the decision recorder into SynapseService.
func (s *SynapseService) SetDecisionRecorder(r DecisionRecorder) {
	s.recorder = r
}
