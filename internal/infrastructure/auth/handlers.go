package auth

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// LoginRequest is the POST /api/auth/login body.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// TokenResponse is returned on successful login/refresh.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"` // seconds
	TokenType    string `json:"token_type"`
	User         *User  `json:"user"`
}

// HandleLogin creates an HTTP handler for POST /api/auth/login.
func HandleLogin(store *UserStore, secret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAuthError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		// Support both "email" and legacy "username" field
		email := req.Email
		if email == "" {
			// Try legacy format
			var legacy struct{ Username string `json:"username"` }
			email = legacy.Username
		}

		user, err := store.Authenticate(email, req.Password)
		if err != nil {
			if err == ErrEmailNotVerified {
				writeAuthError(w, http.StatusForbidden, "email not verified — check your inbox for the verification code")
				return
			}
			writeAuthError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		accessToken, err := Sign(Claims{
			Sub:       user.Email,
			Role:      user.Role,
			TenantID:  user.TenantID,
			TokenType: "access",
			Exp:       time.Now().Add(15 * time.Minute).Unix(),
		}, secret)
		if err != nil {
			writeAuthError(w, http.StatusInternalServerError, "token generation failed")
			return
		}

		refreshToken, err := Sign(Claims{
			Sub:       user.Email,
			Role:      user.Role,
			TenantID:  user.TenantID,
			TokenType: "refresh",
			Exp:       time.Now().Add(7 * 24 * time.Hour).Unix(),
		}, secret)
		if err != nil {
			writeAuthError(w, http.StatusInternalServerError, "token generation failed")
			return
		}

		resp := TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    900, // 15 minutes
			TokenType:    "Bearer",
			User:         user,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// HandleRefresh creates an HTTP handler for POST /api/auth/refresh.
func HandleRefresh(secret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAuthError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		claims, err := Verify(req.RefreshToken, secret)
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized, "invalid or expired refresh token")
			return
		}

		// SEC-C5: Only accept refresh tokens for token renewal
		if claims.TokenType != "refresh" {
			writeAuthError(w, http.StatusUnauthorized, "invalid token type — refresh token required")
			return
		}

		accessToken, err := NewAccessToken(claims.Sub, claims.Role, secret, 0)
		if err != nil {
			writeAuthError(w, http.StatusInternalServerError, "token generation failed")
			return
		}

		resp := TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: req.RefreshToken,
			ExpiresIn:    900,
			TokenType:    "Bearer",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// HandleMe returns the current authenticated user profile.
// GET /api/auth/me
func HandleMe(store *UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r.Context())
		if claims == nil {
			writeAuthError(w, http.StatusUnauthorized, "not authenticated")
			return
		}

		user, err := store.GetByEmail(claims.Sub)
		if err != nil {
			writeAuthError(w, http.StatusNotFound, "user not found")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	}
}

// HandleListUsers returns users scoped to the caller's tenant (admin only).
// GET /api/auth/users
func HandleListUsers(store *UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r.Context())
		if claims == nil || claims.Role != "admin" {
			writeAuthError(w, http.StatusForbidden, "admin role required")
			return
		}

		// SEC: Filter users by tenant_id to prevent cross-tenant data leak
		allUsers := store.ListUsers()
		var filtered []*User
		for _, u := range allUsers {
			if u.TenantID == claims.TenantID {
				filtered = append(filtered, u)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"users": filtered,
			"total": len(filtered),
		})
	}
}

// HandleCreateUser creates a new user (admin only).
// POST /api/auth/users
func HandleCreateUser(store *UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
			Password    string `json:"password"`
			Role        string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAuthError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		if req.Email == "" || req.Password == "" {
			writeAuthError(w, http.StatusBadRequest, "email and password required")
			return
		}

		if req.Role == "" {
			req.Role = "viewer"
		}

		// Validate role
		validRoles := map[string]bool{"admin": true, "analyst": true, "viewer": true}
		if !validRoles[req.Role] {
			writeAuthError(w, http.StatusBadRequest, "invalid role (valid: admin, analyst, viewer)")
			return
		}

		user, err := store.CreateUser(req.Email, req.DisplayName, req.Password, req.Role)
		if err != nil {
			if err == ErrUserExists {
				writeAuthError(w, http.StatusConflict, "user already exists")
			} else {
				writeAuthError(w, http.StatusInternalServerError, err.Error())
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(user)
	}
}

// HandleUpdateUser updates a user's profile (admin only).
// PUT /api/auth/users/{id}
func HandleUpdateUser(store *UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			writeAuthError(w, http.StatusBadRequest, "user id required")
			return
		}

		var req struct {
			DisplayName string `json:"display_name"`
			Role        string `json:"role"`
			Active      *bool  `json:"active"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAuthError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		active := true
		if req.Active != nil {
			active = *req.Active
		}

		if err := store.UpdateUser(id, req.DisplayName, req.Role, active); err != nil {
			writeAuthError(w, http.StatusNotFound, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
	}
}

// HandleDeleteUser deletes a user (admin only).
// DELETE /api/auth/users/{id}
func HandleDeleteUser(store *UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			writeAuthError(w, http.StatusBadRequest, "user id required")
			return
		}

		if err := store.DeleteUser(id); err != nil {
			writeAuthError(w, http.StatusNotFound, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	}
}

// HandleCreateAPIKey generates a new API key for the authenticated user.
// POST /api/auth/keys
func HandleCreateAPIKey(store *UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r.Context())
		if claims == nil {
			writeAuthError(w, http.StatusUnauthorized, "not authenticated")
			return
		}

		user, err := store.GetByEmail(claims.Sub)
		if err != nil {
			writeAuthError(w, http.StatusNotFound, "user not found")
			return
		}

		var req struct {
			Name string `json:"name"`
			Role string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAuthError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if req.Name == "" {
			req.Name = "default"
		}
		if req.Role == "" {
			req.Role = user.Role
		}

		fullKey, ak, err := store.CreateAPIKey(user.ID, req.Name, req.Role)
		if err != nil {
			writeAuthError(w, http.StatusInternalServerError, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"key":     fullKey, // shown only once
			"details": ak,
		})
	}
}

// HandleListAPIKeys returns API keys for the authenticated user.
// GET /api/auth/keys
func HandleListAPIKeys(store *UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r.Context())
		if claims == nil {
			writeAuthError(w, http.StatusUnauthorized, "not authenticated")
			return
		}

		user, err := store.GetByEmail(claims.Sub)
		if err != nil {
			writeAuthError(w, http.StatusNotFound, "user not found")
			return
		}

		keys, err := store.ListAPIKeys(user.ID)
		if err != nil {
			writeAuthError(w, http.StatusInternalServerError, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}
}

// HandleDeleteAPIKey revokes an API key.
// DELETE /api/auth/keys/{id}
func HandleDeleteAPIKey(store *UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r.Context())
		if claims == nil {
			writeAuthError(w, http.StatusUnauthorized, "not authenticated")
			return
		}

		user, err := store.GetByEmail(claims.Sub)
		if err != nil {
			writeAuthError(w, http.StatusNotFound, "user not found")
			return
		}

		keyID := r.PathValue("id")
		if err := store.DeleteAPIKey(keyID, user.ID); err != nil {
			writeAuthError(w, http.StatusInternalServerError, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
	}
}

// APIKeyMiddleware checks for API key authentication alongside JWT.
// If Authorization header starts with "stx_", validate as API key.
func APIKeyMiddleware(store *UserStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer stx_") {
			key := strings.TrimPrefix(authHeader, "Bearer ")
			_, role, err := store.ValidateAPIKey(key)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "invalid API key")
				return
			}
			// Inject synthetic claims for RBAC compatibility
			claims := &Claims{Sub: "api-key", Role: role}
			ctx := SetClaimsContext(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		next.ServeHTTP(w, r)
	})
}
