// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

package soc

import (
	"testing"
)

func TestGhostSinkhole_GenerateDecoy(t *testing.T) {
	gs := NewGhostSinkhole()

	resp := gs.GenerateDecoy("shadow_ai", "abc123hash", "10.0.0.1", "curl/7.0")
	if resp.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if resp.Category != "shadow_ai" {
		t.Fatalf("expected category shadow_ai, got %s", resp.Category)
	}
	if resp.DecoyTemplate != "fake_api_key" {
		t.Fatalf("expected fake_api_key template, got %s", resp.DecoyTemplate)
	}
	if resp.SourceIP != "10.0.0.1" {
		t.Fatalf("expected source IP 10.0.0.1, got %s", resp.SourceIP)
	}
	if resp.DecoyContent == "" {
		t.Fatal("expected non-empty decoy content")
	}
}

func TestGhostSinkhole_CategoryTemplateMatching(t *testing.T) {
	gs := NewGhostSinkhole()

	tests := []struct {
		category string
		template string
	}{
		{"shadow_ai", "fake_api_key"},
		{"jailbreak", "fake_model_response"},
		{"exfiltration", "fake_data_export"},
		{"auth_bypass", "fake_credentials"},
		{"unknown_category", "generic_success"},
	}

	for _, tt := range tests {
		t.Run(tt.category, func(t *testing.T) {
			resp := gs.GenerateDecoy(tt.category, "hash", "", "")
			if resp.DecoyTemplate != tt.template {
				t.Errorf("category %q: got template %q, want %q", tt.category, resp.DecoyTemplate, tt.template)
			}
		})
	}
}

func TestGhostSinkhole_GetResponses(t *testing.T) {
	gs := NewGhostSinkhole()

	for i := 0; i < 10; i++ {
		gs.GenerateDecoy("shadow_ai", "hash", "", "")
	}

	// Get last 5
	recent := gs.GetResponses(5)
	if len(recent) != 5 {
		t.Fatalf("expected 5 responses, got %d", len(recent))
	}

	// Most recent first
	if recent[0].Timestamp.Before(recent[4].Timestamp) {
		t.Fatal("responses should be ordered most recent first")
	}
}

func TestGhostSinkhole_GetResponse_ByID(t *testing.T) {
	gs := NewGhostSinkhole()
	resp := gs.GenerateDecoy("jailbreak", "hash", "", "")

	found, ok := gs.GetResponse(resp.ID)
	if !ok {
		t.Fatal("expected to find response by ID")
	}
	if found.Category != "jailbreak" {
		t.Fatalf("expected jailbreak, got %s", found.Category)
	}

	_, ok = gs.GetResponse("nonexistent-id")
	if ok {
		t.Fatal("should not find nonexistent ID")
	}
}

func TestGhostSinkhole_RingBuffer(t *testing.T) {
	gs := &GhostSinkhole{maxStore: 5, templates: NewGhostSinkhole().templates}

	for i := 0; i < 10; i++ {
		gs.GenerateDecoy("shadow_ai", "hash", "", "")
	}

	all := gs.GetResponses(0)
	if len(all) != 5 {
		t.Fatalf("ring buffer should cap at 5, got %d", len(all))
	}
}

func TestGhostSinkhole_Stats(t *testing.T) {
	gs := NewGhostSinkhole()

	gs.GenerateDecoy("shadow_ai", "h1", "", "")
	gs.GenerateDecoy("shadow_ai", "h2", "", "")
	gs.GenerateDecoy("jailbreak", "h3", "", "")

	stats := gs.Stats()
	if stats["total_decoys"].(int) != 3 {
		t.Fatalf("expected 3 total, got %v", stats["total_decoys"])
	}

	byCat := stats["by_category"].(map[string]int)
	if byCat["shadow_ai"] != 2 {
		t.Fatalf("expected 2 shadow_ai, got %d", byCat["shadow_ai"])
	}
	if byCat["jailbreak"] != 1 {
		t.Fatalf("expected 1 jailbreak, got %d", byCat["jailbreak"])
	}
}

func TestGhostSinkhole_TTPs(t *testing.T) {
	gs := NewGhostSinkhole()
	resp := gs.GenerateDecoy("exfiltration", "hash", "192.168.1.1", "python-requests/2.28")

	if resp.TTPs["technique"] != "exfiltration" {
		t.Fatalf("expected technique=exfiltration, got %s", resp.TTPs["technique"])
	}
	if resp.TTPs["decoy_served"] != "fake_data_export" {
		t.Fatalf("expected decoy_served=fake_data_export, got %s", resp.TTPs["decoy_served"])
	}
}

func TestGhostSinkhole_UniqueIDs(t *testing.T) {
	gs := NewGhostSinkhole()

	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		resp := gs.GenerateDecoy("shadow_ai", "hash", "", "")
		if ids[resp.ID] {
			t.Fatalf("duplicate ID generated: %s", resp.ID)
		}
		ids[resp.ID] = true
	}
}
