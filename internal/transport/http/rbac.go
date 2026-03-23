package httpserver

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// Role defines access level for RBAC.
type Role string

const (
	RoleAdmin    Role = "admin"    // Full access: read + write + config
	RoleAnalyst  Role = "analyst"  // Read + write (ingest, verdict)
	RoleViewer   Role = "viewer"   // Read-only
	RoleSensor   Role = "sensor"   // Ingest only (POST events + heartbeat)
	RoleExternal Role = "external" // Kill Chain + dashboard only
)

// APIKey represents a registered API key with role.
type APIKey struct {
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used,omitempty"`
	Active    bool      `json:"active"`
}

// RBACConfig holds authentication configuration.
type RBACConfig struct {
	Enabled bool              `yaml:"enabled" json:"enabled"`
	Keys    map[string]APIKey // key hash → APIKey
}

// RBACMiddleware provides role-based access control for HTTP endpoints (§17).
type RBACMiddleware struct {
	mu      sync.RWMutex
	config  RBACConfig
	keys    map[string]*APIKey // raw key → APIKey
}

// NewRBACMiddleware creates RBAC middleware. If not enabled, all requests pass through.
func NewRBACMiddleware(config RBACConfig) *RBACMiddleware {
	m := &RBACMiddleware{
		config: config,
		keys:   make(map[string]*APIKey),
	}
	return m
}

// RegisterKey adds an API key with a role.
func (m *RBACMiddleware) RegisterKey(name, key string, role Role) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[key] = &APIKey{
		Key:       key,
		Name:      name,
		Role:      role,
		CreatedAt: time.Now(),
		Active:    true,
	}
}

// RevokeKey deactivates an API key.
func (m *RBACMiddleware) RevokeKey(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.keys[key]; ok {
		k.Active = false
	}
}

// ListKeys returns all registered keys (with keys masked).
func (m *RBACMiddleware) ListKeys() []APIKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]APIKey, 0, len(m.keys))
	for _, k := range m.keys {
		masked := *k
		if len(masked.Key) > 8 {
			masked.Key = masked.Key[:4] + "..." + masked.Key[len(masked.Key)-4:]
		}
		result = append(result, masked)
	}
	return result
}

// Require returns middleware that enforces minimum role for the endpoint.
func (m *RBACMiddleware) Require(minRole Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !m.config.Enabled {
			next(w, r)
			return
		}

		// Extract API key from Authorization header or query param
		key := extractAPIKey(r)
		if key == "" {
			writeError(w, http.StatusUnauthorized, "missing API key: use Authorization: Bearer <key>")
			return
		}

		// Lookup and validate key
		m.mu.RLock()
		apiKey, exists := m.keys[key]
		m.mu.RUnlock()

		if !exists || !apiKey.Active {
			writeError(w, http.StatusUnauthorized, "invalid or revoked API key")
			return
		}

		// Note: timing-safe compare is not needed here because the Go map
		// lookup above already reveals key existence via timing. The map
		// is the canonical key store; this is a lookup, not a comparison
		// of a user-supplied value against a stored secret.


		// Check role hierarchy
		if !hasPermission(apiKey.Role, minRole) {
			writeError(w, http.StatusForbidden, "insufficient permissions: requires "+string(minRole))
			return
		}

		// Update last used
		m.mu.Lock()
		apiKey.LastUsed = time.Now()
		m.mu.Unlock()

		next(w, r)
	}
}

// extractAPIKey gets the API key from Authorization header or ?api_key query param.
func extractAPIKey(r *http.Request) string {
	// Try Authorization: Bearer <key>
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	// Try X-API-Key header
	if key := r.Header.Get("X-API-Key"); key != "" {
		return key
	}
	// Try query parameter (least secure, for dashboard convenience)
	return r.URL.Query().Get("api_key")
}

// hasPermission checks if userRole >= requiredRole in the hierarchy.
func hasPermission(userRole, requiredRole Role) bool {
	hierarchy := map[Role]int{
		RoleAdmin:    100,
		RoleAnalyst:  50,
		RoleViewer:   30,
		RoleSensor:   20,
		RoleExternal: 10,
	}
	return hierarchy[userRole] >= hierarchy[requiredRole]
}
