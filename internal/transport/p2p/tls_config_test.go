// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

package transport

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := GenerateSelfSignedCert("peer_test123")
	require.NoError(t, err)
	assert.NotEmpty(t, cert.Certificate)
	assert.NotNil(t, cert.PrivateKey)
}

func TestNewMutualTLSConfig(t *testing.T) {
	cert, err := GenerateSelfSignedCert("peer_tls_test")
	require.NoError(t, err)

	tlsCfg := NewMutualTLSConfig(cert)
	assert.Len(t, tlsCfg.Certificates, 1)
	assert.Equal(t, uint16(0x0304), tlsCfg.MinVersion) // TLS 1.3
}
