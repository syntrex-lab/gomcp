//go:build sentinel_native

package engines

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../../sentinel-core/target/release -lsentinel_core
#cgo CFLAGS: -I${SRCDIR}/../../../../sentinel-core/include

// sentinel_core.h — C-compatible FFI interface for Rust sentinel-core.
// These declarations match the Rust #[no_mangle] extern "C" functions.
//
// Build sentinel-core:
//   cd sentinel-core && cargo build --release
//
// The library exposes:
//   sentinel_init()     — Initialize the engine
//   sentinel_analyze()  — Analyze text for jailbreak/injection patterns
//   sentinel_status()   — Get engine health status
//   sentinel_shutdown() — Graceful shutdown

// Stub declarations for build without native library.
// When building WITH sentinel-core, replace stubs with actual FFI.
*/
import "C"

import (
	"sync"
	"time"
)

// NativeSentinelCore wraps the Rust sentinel-core via CGo FFI.
// Build tag: sentinel_native
//
// When sentinel-core.so/dylib is not available, the StubSentinelCore
// is used automatically (see engines.go).
type NativeSentinelCore struct {
	mu          sync.RWMutex
	initialized bool
	version     string
	lastCheck   time.Time
}

// NewNativeSentinelCore creates the FFI bridge.
// Returns error if the native library is not available.
func NewNativeSentinelCore() (*NativeSentinelCore, error) {
	n := &NativeSentinelCore{
		version: "0.1.0-ffi",
	}

	// TODO: Call C.sentinel_init() when native library is available
	// result := C.sentinel_init()
	// if result != 0 {
	//     return nil, fmt.Errorf("sentinel_init failed: %d", result)
	// }

	n.initialized = true
	n.lastCheck = time.Now()
	return n, nil
}

// Analyze sends text through the sentinel-core analysis pipeline.
// Returns: confidence (0-1), detected categories, is_threat flag.
func (n *NativeSentinelCore) Analyze(text string) SentinelResult {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if !n.initialized {
		return SentinelResult{Error: "engine not initialized"}
	}

	// TODO: FFI call
	// cText := C.CString(text)
	// defer C.free(unsafe.Pointer(cText))
	// result := C.sentinel_analyze(cText)

	// Stub analysis for now
	return SentinelResult{
		Confidence: 0.0,
		Categories: []string{},
		IsThreat:   false,
	}
}

// Status returns the engine health via FFI.
func (n *NativeSentinelCore) Status() EngineStatus {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if !n.initialized {
		return EngineOffline
	}

	// TODO: Call C.sentinel_status()
	return EngineHealthy
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

	// TODO: C.sentinel_shutdown()
	n.initialized = false
	return nil
}

// SentinelResult is returned by the Analyze function.
type SentinelResult struct {
	Confidence float64  `json:"confidence"`
	Categories []string `json:"categories"`
	IsThreat   bool     `json:"is_threat"`
	Error      string   `json:"error,omitempty"`
}
