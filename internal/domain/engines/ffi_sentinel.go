// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

//go:build sentinel_native

package engines

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../../sentinel-core/target/release -lsentinel_core -ldl -lm -lpthread
#cgo CFLAGS: -I${SRCDIR}/../../../../sentinel-core/include

#include <sentinel_core.h>
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"unsafe"
)

// NativeSentinelCore wraps the Rust sentinel-core via CGo FFI.
// Build tag: sentinel_native
type NativeSentinelCore struct {
	mu          sync.RWMutex
	initialized bool
	version     string
	lastCheck   time.Time
}

// NewNativeSentinelCore creates the FFI bridge and initializes the Rust engine.
func NewNativeSentinelCore() (*NativeSentinelCore, error) {
	result := C.sentinel_init()
	if result != 0 {
		return nil, fmt.Errorf("sentinel_init failed with code %d", int(result))
	}

	// Get version from Rust
	cVer := C.sentinel_version()
	version := "unknown"
	if cVer != nil {
		version = C.GoString(cVer)
		C.sentinel_free(cVer)
	}

	return &NativeSentinelCore{
		initialized: true,
		version:     version,
		lastCheck:   time.Now(),
	}, nil
}

// sentinelAnalyzeResult matches the JSON returned by sentinel_analyze().
type sentinelAnalyzeResult struct {
	Confidence       float64  `json:"confidence"`
	Categories       []string `json:"categories"`
	IsThreat         bool     `json:"is_threat"`
	InputLength      int      `json:"input_length"`
	AnalyzeCount     uint64   `json:"analyze_count"`
	EnginesTriggered int      `json:"engines_triggered"`
	ProcessingTimeUs uint64   `json:"processing_time_us"`
	Indicators       []string `json:"indicators"`
	Error            string   `json:"error,omitempty"`
}

// analyze sends text through the Rust sentinel-core analysis pipeline.
func (n *NativeSentinelCore) analyze(text string) sentinelAnalyzeResult {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if !n.initialized {
		return sentinelAnalyzeResult{Error: "engine not initialized"}
	}

	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))

	cResult := C.sentinel_analyze(cText)
	if cResult == nil {
		return sentinelAnalyzeResult{Error: "sentinel_analyze returned null"}
	}
	defer C.sentinel_free(cResult)

	jsonStr := C.GoString(cResult)
	var result sentinelAnalyzeResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return sentinelAnalyzeResult{Error: fmt.Sprintf("json parse error: %v", err)}
	}

	return result
}

// ScanPrompt analyzes an LLM prompt for injection/jailbreak patterns.
func (n *NativeSentinelCore) ScanPrompt(_ context.Context, prompt string) (*ScanResult, error) {
	start := time.Now()
	res := n.analyze(prompt)

	if res.Error != "" {
		return nil, fmt.Errorf("sentinel-core: %s", res.Error)
	}

	severity := "NONE"
	threatType := ""
	if res.IsThreat {
		severity = "HIGH"
		if len(res.Categories) > 0 {
			threatType = res.Categories[0]
		}
	}

	return &ScanResult{
		Engine:      "sentinel-core",
		ThreatFound: res.IsThreat,
		ThreatType:  threatType,
		Severity:    severity,
		Confidence:  res.Confidence,
		Details:     fmt.Sprintf("engines=%d categories=%v", res.EnginesTriggered, res.Categories),
		Indicators:  res.Indicators,
		Duration:    time.Since(start),
		Timestamp:   time.Now(),
	}, nil
}

// ScanResponse analyzes an LLM response for data exfiltration or harmful content.
func (n *NativeSentinelCore) ScanResponse(ctx context.Context, response string) (*ScanResult, error) {
	return n.ScanPrompt(ctx, response)
}

// Status returns the engine health via FFI.
func (n *NativeSentinelCore) Status() EngineStatus {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if !n.initialized {
		return EngineOffline
	}

	cStatus := C.sentinel_status()
	if cStatus == nil {
		return EngineDegraded
	}
	defer C.sentinel_free(cStatus)

	var statusObj struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(C.GoString(cStatus)), &statusObj); err != nil {
		return EngineDegraded
	}

	switch statusObj.Status {
	case "HEALTHY":
		return EngineHealthy
	case "OFFLINE":
		return EngineOffline
	default:
		return EngineDegraded
	}
}

// Name returns the engine identifier.
func (n *NativeSentinelCore) Name() string {
	return "sentinel-core"
}

// Version returns the native library version.
func (n *NativeSentinelCore) Version() string {
	return n.version
}

// Shutdown gracefully closes the FFI bridge.
func (n *NativeSentinelCore) Shutdown() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.initialized {
		return nil
	}

	result := C.sentinel_shutdown()
	n.initialized = false
	if result != 0 {
		return fmt.Errorf("sentinel_shutdown failed with code %d", int(result))
	}
	return nil
}
