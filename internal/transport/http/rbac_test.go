// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRBAC_Disabled_PassesThrough(t *testing.T) {
	rbac := NewRBACMiddleware(RBACConfig{Enabled: false})

	handler := rbac.Require(RoleAdmin, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRBAC_Enabled_NoKey_Returns401(t *testing.T) {
	rbac := NewRBACMiddleware(RBACConfig{Enabled: true})

	handler := rbac.Require(RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRBAC_Enabled_ValidKey_AdminAccess(t *testing.T) {
	rbac := NewRBACMiddleware(RBACConfig{Enabled: true})
	rbac.RegisterKey("admin-key", "sk-admin-123", RoleAdmin)

	handler := rbac.Require(RoleAdmin, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("admin"))
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer sk-admin-123")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRBAC_Enabled_InsufficientRole_Returns403(t *testing.T) {
	rbac := NewRBACMiddleware(RBACConfig{Enabled: true})
	rbac.RegisterKey("viewer-key", "sk-viewer-456", RoleViewer)

	handler := rbac.Require(RoleAdmin, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer sk-viewer-456")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestRBAC_XAPIKeyHeader(t *testing.T) {
	rbac := NewRBACMiddleware(RBACConfig{Enabled: true})
	rbac.RegisterKey("sensor", "sk-sensor-789", RoleSensor)

	handler := rbac.Require(RoleSensor, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/ingest", nil)
	req.Header.Set("X-API-Key", "sk-sensor-789")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRBAC_RevokedKey_Returns401(t *testing.T) {
	rbac := NewRBACMiddleware(RBACConfig{Enabled: true})
	rbac.RegisterKey("temp-key", "sk-temp-000", RoleAdmin)
	rbac.RevokeKey("sk-temp-000")

	handler := rbac.Require(RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer sk-temp-000")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRBAC_ListKeys_MasksKeys(t *testing.T) {
	rbac := NewRBACMiddleware(RBACConfig{Enabled: true})
	rbac.RegisterKey("admin", "sk-admin-very-long-key-12345", RoleAdmin)

	keys := rbac.ListKeys()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Key == "sk-admin-very-long-key-12345" {
		t.Fatal("key should be masked")
	}
	if keys[0].Name != "admin" {
		t.Fatalf("expected name='admin', got %q", keys[0].Name)
	}
	t.Logf("masked key: %s", keys[0].Key)
}

func TestRBAC_RoleHierarchy(t *testing.T) {
	tests := []struct {
		userRole Role
		minRole  Role
		allowed  bool
	}{
		{RoleAdmin, RoleAdmin, true},
		{RoleAdmin, RoleSensor, true},
		{RoleAnalyst, RoleViewer, true},
		{RoleViewer, RoleAnalyst, false},
		{RoleSensor, RoleViewer, false},
		{RoleExternal, RoleAdmin, false},
		{RoleSensor, RoleSensor, true},
	}
	for _, tt := range tests {
		got := hasPermission(tt.userRole, tt.minRole)
		if got != tt.allowed {
			t.Errorf("hasPermission(%s, %s) = %v, want %v", tt.userRole, tt.minRole, got, tt.allowed)
		}
	}
}

// ── Security Regression Tests (T4 bug bounty patches) ──────────────

// TestRBAC_QueryParamKey_Rejected verifies that API keys in query params
// are no longer accepted (P1 fix: credential leakage via URL).
func TestRBAC_QueryParamKey_Rejected(t *testing.T) {
	rbac := NewRBACMiddleware(RBACConfig{Enabled: true})
	rbac.RegisterKey("api-test", "sk-query-key-001", RoleAdmin)

	handler := rbac.Require(RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Query param should NOT authenticate
	req := httptest.NewRequest("GET", "/test?api_key=sk-query-key-001", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("query param auth should be rejected (P1 fix), got %d", rec.Code)
	}
}

// TestRBAC_UndefinedRole_Denied verifies that undefined/fabricated roles
// are rejected by the permission check (P3 fix: default-deny).
func TestRBAC_UndefinedRole_Denied(t *testing.T) {
	tests := []struct {
		name     string
		user     Role
		required Role
	}{
		{"fabricated user role", Role("superadmin"), RoleViewer},
		{"empty user role", Role(""), RoleViewer},
		{"fabricated required role", RoleAdmin, Role("superviewer")},
		{"both undefined", Role("ghost"), Role("phantom")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if hasPermission(tt.user, tt.required) {
				t.Errorf("hasPermission(%q, %q) should be false (undefined role)", tt.user, tt.required)
			}
		})
	}
}

// TestRBAC_HMAC_MatchesRegisteredKey verifies that the HMAC-based
// constant-time lookup correctly authenticates valid keys.
func TestRBAC_HMAC_MatchesRegisteredKey(t *testing.T) {
	rbac := NewRBACMiddleware(RBACConfig{Enabled: true})
	// Register multiple keys to ensure iteration works
	rbac.RegisterKey("key-a", "sk-aaaa-1111-2222-3333", RoleAdmin)
	rbac.RegisterKey("key-b", "sk-bbbb-4444-5555-6666", RoleAnalyst)
	rbac.RegisterKey("key-c", "sk-cccc-7777-8888-9999", RoleViewer)

	handler := rbac.Require(RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Each key should authenticate successfully
	for _, key := range []string{"sk-aaaa-1111-2222-3333", "sk-bbbb-4444-5555-6666", "sk-cccc-7777-8888-9999"} {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		handler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("key %s should authenticate, got %d", key[:10]+"...", rec.Code)
		}
	}
}

// TestRBAC_HMAC_RejectsWrongKey verifies that similar-looking keys
// are rejected even if they share a common prefix.
func TestRBAC_HMAC_RejectsWrongKey(t *testing.T) {
	rbac := NewRBACMiddleware(RBACConfig{Enabled: true})
	rbac.RegisterKey("real-key", "sk-admin-secret-key-12345", RoleAdmin)

	handler := rbac.Require(RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrong keys — including prefix collision and off-by-one
	wrongKeys := []string{
		"sk-admin-secret-key-12346",  // off by last char
		"sk-admin-secret-key-1234",   // one char short
		"sk-admin-secret-key-123456", // one char extra
		"sk-admin-secret-key-12345 ", // trailing space
		"SK-ADMIN-SECRET-KEY-12345",  // wrong case
	}

	for _, key := range wrongKeys {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		handler(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("wrong key %q should be rejected, got %d", key, rec.Code)
		}
	}
}
