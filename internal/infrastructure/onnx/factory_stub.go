// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

//go:build !onnx

package onnx

import (
	"log"

	"github.com/syntrex-lab/gomcp/internal/domain/vectorstore"
)

// NewEmbedderWithFallback returns FTS5 fallback embedder when built without ONNX.
// To enable ONNX: go build -tags onnx
func NewEmbedderWithFallback(rlmDir string) vectorstore.Embedder {
	log.Printf("Oracle: ONNX not compiled (build without -tags onnx) — using FTS5 fallback [ORACLE: DEGRADED]")
	return vectorstore.NewFTS5Embedder()
}
