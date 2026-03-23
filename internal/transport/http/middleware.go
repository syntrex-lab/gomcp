package httpserver

import (
	"net/http"
	"os"
)

// corsAllowedOrigin returns the configured CORS origin.
// Set SOC_CORS_ORIGIN in production (e.g. "https://soc.отражение.рус").
// Defaults to "*" for local development.
func corsAllowedOrigin() string {
	if v := os.Getenv("SOC_CORS_ORIGIN"); v != "" {
		return v
	}
	return "*"
}

// corsMiddleware adds CORS headers with configurable origin.
// Production: set SOC_CORS_ORIGIN=https://your-domain.com
func corsMiddleware(next http.Handler) http.Handler {
	origin := corsAllowedOrigin()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin == "*" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			reqOrigin := r.Header.Get("Origin")
			if reqOrigin == origin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400")

		// Handle preflight
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware adds defense-in-depth headers to all responses.
// Mitigates XSS, clickjacking, MIME sniffing, and information leak vectors.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME type sniffing (IE/Chrome auto-exec attacks)
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Block iframe embedding (clickjacking defense)
		w.Header().Set("X-Frame-Options", "DENY")

		// XSS filter (legacy browsers)
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Referrer leak prevention (no full URL in Referer header)
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Content Security Policy — API only, no inline scripts
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		// Permissions Policy — deny all sensitive browser APIs
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")

		// Force HTTPS in production (1 year, include subdomains)
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Hide server identity
		w.Header().Set("X-Powered-By", "")
		w.Header().Del("Server")

		next.ServeHTTP(w, r)
	})
}
