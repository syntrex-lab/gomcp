// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

package httpserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// RateLimiter provides per-IP sliding window rate limiting (§17.3).
// Supports burst tolerance (soft/hard limits) and standard X-RateLimit headers.
type RateLimiter struct {
	mu      sync.RWMutex
	windows map[string][]time.Time
	limit   int           // max requests per window (soft limit)
	burst   int           // burst tolerance (hard limit = limit + burst)
	window  time.Duration // window size
	enabled bool
}

// NewRateLimiter creates a rate limiter. Set limit=0 to disable.
// Burst is set to 20% of limit (allows short spikes before hard-dropping).
// The cleanup goroutine stops when ctx is cancelled (T4-6).
func NewRateLimiter(ctx context.Context, limit int, window time.Duration) *RateLimiter {
	burst := limit / 5 // 20% burst tolerance
	if burst < 5 {
		burst = 5
	}
	rl := &RateLimiter{
		windows: make(map[string][]time.Time),
		limit:   limit,
		burst:   burst,
		window:  window,
		enabled: limit > 0,
	}
	// Background cleanup every 60s — stops on ctx cancellation
	go rl.cleanup(ctx)
	return rl
}

// Allow checks if the IP is within the hard limit (limit + burst).
// Returns true if allowed.
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

	hardLimit := rl.limit + rl.burst
	if len(valid) >= hardLimit {
		rl.windows[ip] = valid
		return false
	}

	rl.windows[ip] = append(valid, now)
	return true
}

// RemainingAndReset returns the remaining requests within the soft limit
// and the time when the window resets for this IP.
func (rl *RateLimiter) RemainingAndReset(ip string) (remaining int, resetAt time.Time) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)
	count := 0
	earliestInWindow := now

	for _, ts := range rl.windows[ip] {
		if ts.After(cutoff) {
			count++
			if ts.Before(earliestInWindow) {
				earliestInWindow = ts
			}
		}
	}

	remaining = rl.limit - count
	if remaining < 0 {
		remaining = 0
	}
	resetAt = earliestInWindow.Add(rl.window)
	return
}

// Middleware wraps an HTTP handler with rate limiting.
// Certain paths are excluded to prevent battle/scan traffic from blocking
// dashboard access (auth, SSE stream, event ingestion).
// Emits standard X-RateLimit-* headers on every response for client visibility.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Exclude critical dashboard paths from global rate limiter
		p := r.URL.Path
		switch {
		case p == "/api/auth/login",
			p == "/api/auth/refresh",
			p == "/api/soc/stream",
			p == "/api/v1/soc/events",
			p == "/api/soc/events",
			p == "/api/v1/scan",
			p == "/api/scan":
			next.ServeHTTP(w, r)
			return
		}

		// T4-3 FIX: Use RemoteAddr directly to prevent X-Forwarded-For spoofing.
		ip := r.RemoteAddr
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}

		if !rl.Allow(ip) {
			_, resetAt := rl.RemainingAndReset(ip)
			retryAfter := int(time.Until(resetAt).Seconds())
			if retryAfter < 1 {
				retryAfter = 1
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rl.limit))
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetAt.Unix()))
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		// Emit X-RateLimit headers on successful requests
		remaining, resetAt := rl.RemainingAndReset(ip)
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rl.limit))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetAt.Unix()))

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
		"burst":       rl.burst,
		"hard_limit":  rl.limit + rl.burst,
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
