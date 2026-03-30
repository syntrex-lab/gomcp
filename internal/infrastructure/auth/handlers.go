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

type TokenResponse struct {
	CSRFToken string `json:"csrf_token"`
	User      *User  `json:"user"`
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

		// SEC: H1 - Use httpOnly Cookies instead of localStorage
		http.SetCookie(w, &http.Cookie{
			Name:     "syntrex_token",
			Value:    accessToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   900,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "syntrex_refresh",
			Value:    refreshToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   7 * 24 * 3600,
		})

		// SEC: M2 - Generate stateless CSRF token
		csrfToken := hmacSign([]byte(accessToken), secret)[:32]

		resp := TokenResponse{
			CSRFToken: csrfToken,
			User:      user,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// HandleRefresh creates an HTTP handler for POST /api/auth/refresh.
func HandleRefresh(secret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract refresh token from cookie
		cookie, err := r.Cookie("syntrex_refresh")
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized, "missing refresh token cookie")
			return
		}

		claims, err := Verify(cookie.Value, secret)
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized, "invalid or expired refresh token")
			return
		}

		// SEC-C5: Only accept refresh tokens for token renewal
		if claims.TokenType != "refresh" {
			writeAuthError(w, http.StatusUnauthorized, "invalid token type — refresh token required")
			return
		}

		// SEC-CRIT2: Preserve TenantID from refresh token in new access token
		accessToken, err := Sign(Claims{
			Sub:       claims.Sub,
			Role:      claims.Role,
			TenantID:  claims.TenantID,
			TokenType: "access",
			Exp:       time.Now().Add(15 * time.Minute).Unix(),
		}, secret)
		if err != nil {
			writeAuthError(w, http.StatusInternalServerError, "token generation failed")
			return
		}

		// SEC: H1 - Set new httpOnly token with Secure flag
		http.SetCookie(w, &http.Cookie{
			Name:     "syntrex_token",
			Value:    accessToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   900,
		})

		csrfToken := hmacSign([]byte(accessToken), secret)[:32]

		resp := TokenResponse{
			CSRFToken: csrfToken,
			User:      &User{Email: claims.Sub, Role: claims.Role, TenantID: claims.TenantID},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// HandleLogout clears the auth cookies.
// POST /api/auth/logout
func HandleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "syntrex_token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "syntrex_refresh",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
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
// SEC-HIGH1: Returns empty list when TenantID is empty to prevent cross-tenant leak.
func HandleListUsers(store *UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r.Context())
		if claims == nil || claims.Role != "admin" {
			writeAuthError(w, http.StatusForbidden, "admin role required")
			return
		}

		// SEC-HIGH1: Block listing when TenantID is empty — prevents
		// empty-string match showing all users without a tenant.
		if claims.TenantID == "" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"users": []*User{},
				"total": 0,
			})
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

		// SEC-HIGH2: Scope new user to caller's tenant
		claims := GetClaims(r.Context())
		if claims == nil || claims.TenantID == "" {
			writeAuthError(w, http.StatusForbidden, "tenant context required to create users")
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
// SEC-CRIT3: Now resolves user from DB to inject correct TenantID.
func APIKeyMiddleware(store *UserStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer stx_") {
			key := strings.TrimPrefix(authHeader, "Bearer ")
			userID, role, err := store.ValidateAPIKey(key)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "invalid API key")
				return
			}
			// SEC-CRIT3: Look up user to get TenantID for tenant isolation
			var tenantID string
			if user, err := store.GetByID(userID); err == nil && user != nil {
				tenantID = user.TenantID
			}
			claims := &Claims{Sub: userID, Role: role, TenantID: tenantID}
			ctx := SetClaimsContext(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// HandleDemo provisions a read-only demo session and logs the user in.
// GET /api/auth/demo
func HandleDemo(userStore *UserStore, tenantStore *TenantStore, secret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const demoEmail = "demo@syntrex.pro"
		const demoTenantSlug = "syntrex-demo"

		// 1. Ensure Demo Tenant exists
		var tenant *Tenant
		s := tenantStore.ListTenants()
		for i := range s {
			if s[i].Slug == demoTenantSlug {
				tenant = s[i]
				break
			}
		}

		if tenant == nil {
			// Need to create demo user and tenant
			user, err := userStore.CreateUser(demoEmail, "Demo Visitor", "demo-random-pass-1234!!", "viewer")
			if err != nil && err != ErrUserExists {
				writeAuthError(w, http.StatusInternalServerError, "demo setup failed")
				return
			}
			if err == ErrUserExists {
				userStore.mu.RLock()
				user = userStore.users[demoEmail]
				userStore.mu.RUnlock()
			}

			// Force verify the email and make viewer
			if userStore.db != nil {
				_, _ = userStore.db.Exec(`UPDATE users SET email_verified = true, role = 'viewer' WHERE id = $1`, user.ID)
			}
			user.EmailVerified = true
			user.Role = "viewer"

			// Create tenant
			newTenant, err := tenantStore.CreateTenant("Syntrex Demo", demoTenantSlug, user.ID, "enterprise")
			if err == nil {
				tenant = newTenant
				// Link user to tenant
				if userStore.db != nil {
					_, _ = userStore.db.Exec(`UPDATE users SET tenant_id = $1 WHERE id = $2`, tenant.ID, user.ID)
				}
				user.TenantID = tenant.ID
			} else {
				// Fallback if tenant exists but wasn't found in cache
				for _, t := range tenantStore.ListTenants() {
					if t.Slug == demoTenantSlug {
						tenant = t
						break
					}
				}
			}
		}

		userStore.mu.RLock()
		user := userStore.users[demoEmail]
		userStore.mu.RUnlock()

		if user == nil {
			writeAuthError(w, http.StatusInternalServerError, "demo user not found")
			return
		}

		if !user.EmailVerified {
			if userStore.db != nil {
				_, _ = userStore.db.Exec(`UPDATE users SET email_verified = true, role = 'viewer' WHERE id = $1`, user.ID)
			}
			user.EmailVerified = true
			user.Role = "viewer"
		}

		// 2. Issuance of tokens
		accessToken, err := Sign(Claims{
			Sub:       user.Email,
			Role:      "viewer",
			TenantID:  tenant.ID,
			TokenType: "access",
			Exp:       time.Now().Add(15 * time.Minute).Unix(),
		}, secret)
		if err != nil {
			writeAuthError(w, http.StatusInternalServerError, "token generation failed")
			return
		}

		refreshToken, err := Sign(Claims{
			Sub:       user.Email,
			Role:      "viewer",
			TenantID:  tenant.ID,
			TokenType: "refresh",
			Exp:       time.Now().Add(7 * 24 * time.Hour).Unix(),
		}, secret)
		if err != nil {
			writeAuthError(w, http.StatusInternalServerError, "token generation failed")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "syntrex_token",
			Value:    accessToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   900,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "syntrex_refresh",
			Value:    refreshToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   7 * 24 * 3600,
		})

		csrfToken := hmacSign([]byte(accessToken), secret)[:32]

		resp := TokenResponse{
			CSRFToken: csrfToken,
			User:      user,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
