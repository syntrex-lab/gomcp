package auth

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
)

type ctxKey string

const claimsKey ctxKey = "jwt_claims"

// JWTMiddleware validates Bearer tokens on protected routes.
type JWTMiddleware struct {
	secret   []byte
	// PublicPaths are exempt from auth (e.g., /health, /api/auth/login).
	PublicPaths map[string]bool
}

// NewJWTMiddleware creates JWT middleware with the given secret.
func NewJWTMiddleware(secret []byte) *JWTMiddleware {
	return &JWTMiddleware{
		secret: secret,
		PublicPaths: map[string]bool{
			"/health":          true,
			"/healthz":         true,
			"/readyz":          true,
			"/metrics":         true,
			"/api/auth/login":  true,
			"/api/auth/refresh": true,
			"/api/auth/register": true,
			"/api/auth/verify":   true,
			"/api/auth/plans":    true,
			"/api/v1/scan":       true, // public demo scanner
			"/api/v1/usage":      true, // public usage/quota check
			"/api/v1/soc/events": true, // sensor ingest (auth via RBAC API key when enabled)
			"/api/soc/events/stream": true, // SSE uses query param auth
			"/api/soc/stream":         true, // SSE live feed (EventSource can't send headers)
			"/api/soc/ws":             true, // WebSocket-style SSE push
		},
	}
}

// Middleware wraps an http.Handler with JWT validation.
func (m *JWTMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for public paths.
		if m.PublicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		// Extract Bearer token.
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeAuthError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			writeAuthError(w, http.StatusUnauthorized, "invalid Authorization format (expected: Bearer <token>)")
			return
		}

		claims, err := Verify(parts[1], m.secret)
		if err != nil {
			slog.Warn("JWT auth failed",
				"error", err,
				"path", r.URL.Path,
				"remote", r.RemoteAddr,
			)
			if err == ErrExpiredToken {
				writeAuthError(w, http.StatusUnauthorized, "token expired")
			} else {
				writeAuthError(w, http.StatusUnauthorized, "invalid token")
			}
			return
		}

		// SEC-C5: Reject refresh tokens used as access tokens.
		// Only "access" tokens (or legacy tokens without type) can access protected routes.
		if claims.TokenType == "refresh" {
			slog.Warn("refresh token used as access token",
				"sub", claims.Sub,
				"path", r.URL.Path,
				"remote", r.RemoteAddr,
			)
			writeAuthError(w, http.StatusUnauthorized, "access token required — refresh tokens cannot be used for API access")
			return
		}

		// Inject claims into context for downstream handlers.
		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetClaims extracts JWT claims from request context.
func GetClaims(ctx context.Context) *Claims {
	if c, ok := ctx.Value(claimsKey).(*Claims); ok {
		return c
	}
	return nil
}

// SetClaimsContext injects claims into a context (used by API key auth).
func SetClaimsContext(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

func writeAuthError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="sentinel-soc"`)
	w.WriteHeader(status)
	w.Write([]byte(`{"error":"` + msg + `"}`))
}
