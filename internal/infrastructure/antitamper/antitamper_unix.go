// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

//go:build !windows

package antitamper

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// platformInit applies Linux-specific anti-tamper controls.
func (s *Shield) platformInit() {
	// PR_SET_DUMPABLE = 0 prevents core dumps and ptrace attachment.
	// This is the strongest anti-debug measure on Linux without eBPF.
	if err := syscall.Prctl(syscall.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		s.logger.Warn("anti-tamper: PR_SET_DUMPABLE failed (non-Linux?)", "error", err)
	} else {
		s.logger.Info("anti-tamper: PR_SET_DUMPABLE=0 (core dumps disabled)")
	}

	// PR_SET_NO_NEW_PRIVS prevents privilege escalation.
	if err := syscall.Prctl(38 /* PR_SET_NO_NEW_PRIVS */, 1, 0, 0, 0); err != nil {
		s.logger.Warn("anti-tamper: PR_SET_NO_NEW_PRIVS failed", "error", err)
	} else {
		s.logger.Info("anti-tamper: PR_SET_NO_NEW_PRIVS=1")
	}
}

// isDebuggerAttached checks for debugger attachment on Linux.
func (s *Shield) isDebuggerAttached() bool {
	// Method 1: Check /proc/self/status for TracerPid.
	data, err := os.ReadFile("/proc/self/status")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "TracerPid:") {
				pidStr := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
				pid, _ := strconv.Atoi(pidStr)
				if pid != 0 {
					return true // A process is tracing us.
				}
			}
		}
	}

	return false
}
