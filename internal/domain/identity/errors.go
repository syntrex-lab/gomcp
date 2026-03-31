// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

package identity

import "errors"

// Sentinel errors for identity operations.
var (
	ErrMissingAgentID   = errors.New("identity: agent_id is required")
	ErrMissingAgentName = errors.New("identity: agent_name is required")
	ErrMissingCreatedBy = errors.New("identity: created_by is required")
	ErrInvalidAgentType = errors.New("identity: invalid agent_type (valid: AUTONOMOUS, SUPERVISED, EXTERNAL)")
	ErrAgentNotFound    = errors.New("identity: agent not found")
	ErrAgentExists      = errors.New("identity: agent already exists")
)
