// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

//go:build !windows

package ipc

import (
	"net"
	"time"
)

// listen creates a Unix Domain Socket listener.
func listen(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}

// dial connects to a Unix Domain Socket.
func dial(path string) (net.Conn, error) {
	return net.DialTimeout("unix", path, 2*time.Second)
}
