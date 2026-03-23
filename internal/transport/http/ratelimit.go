package httpserver

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

// RateLimiter provides per-IP sliding window rate limiting (§17.3).
type RateLimiter struct {
	mu       sync.RWMutex
	windows  map[string][]time.Time
	limit    int           // max requests per window
	window   time.Duration // window size
	enabled  bool
}

// NewRateLimiter creates a rate limiter. Set limit=0 to disable.
// The cleanup goroutine stops when ctx is cancelled (T4-6).
func NewRateLimiter(ctx context.Context, limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		windows: make(map[string][]time.Time),
		limit:   limit,
		window:  window,
		enabled: limit > 0,
	}
	// Background cleanup every 60s — stops on ctx cancellation
	go rl.cleanup(ctx)
	return rl
}

// Allow checks if the IP is within limits. Returns true if allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	if !rl.enabled {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Slide window: keep only timestamps within the window
	timestamps := rl.windows[ip]
	valid := timestamps[:0]
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}

	if len(valid) >= rl.limit {
		rl.windows[ip] = valid
		return false
	}

	rl.windows[ip] = append(valid, now)
	return true
}

// Middleware wraps an HTTP handler with rate limiting.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// T4-3 FIX: Use RemoteAddr directly to prevent X-Forwarded-For spoofing.
		// When behind a trusted reverse proxy, configure the proxy to set
		// X-Real-IP and strip external X-Forwarded-For headers.
		ip := r.RemoteAddr
		// Strip port from RemoteAddr (e.g. "192.168.1.1:12345" → "192.168.1.1")
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}

		if !rl.Allow(ip) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Stats returns rate limiter statistics.
func (rl *RateLimiter) Stats() map[string]any {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return map[string]any{
		"enabled":     rl.enabled,
		"limit":       rl.limit,
		"window_sec":  rl.window.Seconds(),
		"tracked_ips": len(rl.windows),
	}
}

// cleanup removes expired entries periodically. Stops on ctx cancellation.
func (rl *RateLimiter) cleanup(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-rl.window)
			for ip, timestamps := range rl.windows {
				valid := timestamps[:0]
				for _, ts := range timestamps {
					if ts.After(cutoff) {
						valid = append(valid, ts)
					}
				}
				if len(valid) == 0 {
					delete(rl.windows, ip)
				} else {
					rl.windows[ip] = valid
				}
			}
			rl.mu.Unlock()
		}
	}
}
