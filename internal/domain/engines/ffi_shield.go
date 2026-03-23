//go:build shield_native

package engines

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../../shield/build -lshield
#cgo CFLAGS: -I${SRCDIR}/../../../../shield/include

// shield.h — C-compatible FFI interface for C++ shield engine.
// These declarations match the extern "C" functions from shield.
//
// Build shield:
//   cd shield && mkdir build && cd build && cmake .. && make
//
// The library exposes:
//   shield_init()       — Initialize the network protection engine
//   shield_inspect()    — Deep packet inspection / prompt filtering
//   shield_status()     — Get engine health
//   shield_shutdown()   — Graceful shutdown
*/
import "C"

import (
	"sync"
	"time"
)

// NativeShield wraps the C++ shield engine via CGo FFI.
// Build tag: shield_native
type NativeShield struct {
	mu          sync.RWMutex
	initialized bool
	version     string
	lastCheck   time.Time
}

// NewNativeShield creates the FFI bridge to the C++ shield engine.
func NewNativeShield() (*NativeShield, error) {
	n := &NativeShield{
		version: "0.1.0-ffi",
	}

	// TODO: Call C.shield_init()
	n.initialized = true
	n.lastCheck = time.Now()
	return n, nil
}

// Inspect runs deep packet inspection on the payload.
func (n *NativeShield) Inspect(payload []byte) ShieldResult {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if !n.initialized {
		return ShieldResult{Error: "engine not initialized"}
	}

	// TODO: FFI call
	// cPayload := C.CBytes(payload)
	// defer C.free(cPayload)
	// result := C.shield_inspect((*C.char)(cPayload), C.int(len(payload)))

	return ShieldResult{
		Blocked:    false,
		Reason:     "",
		Confidence: 0.0,
	}
}

// Status returns the engine health via FFI.
func (n *NativeShield) Status() EngineStatus {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if !n.initialized {
		return EngineOffline
	}

	return EngineHealthy
}

// Name returns the engine identifier.
func (n *NativeShield) Name() string {
	return "shield"
}

// Version returns the native library version.
func (n *NativeShield) Version() string {
	return n.version
}

// Shutdown gracefully closes the FFI bridge.
func (n *NativeShield) Shutdown() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// TODO: C.shield_shutdown()
	n.initialized = false
	return nil
}

// ShieldResult is returned by the Inspect function.
type ShieldResult struct {
	Blocked    bool    `json:"blocked"`
	Reason     string  `json:"reason,omitempty"`
	Confidence float64 `json:"confidence"`
	Error      string  `json:"error,omitempty"`
}
