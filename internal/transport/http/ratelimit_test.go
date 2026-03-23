package httpserver

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(context.Background(), 3, time.Second)

	// First 3 should pass
	for i := 0; i < 3; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// 4th should be denied
	if rl.Allow("1.2.3.4") {
		t.Fatal("4th request should be rate-limited")
	}

	// Different IP should be fine
	if !rl.Allow("5.6.7.8") {
		t.Fatal("different IP should be allowed")
	}
}

func TestRateLimiter_Disabled(t *testing.T) {
	rl := NewRateLimiter(context.Background(), 0, time.Second)

	for i := 0; i < 100; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatal("disabled rate limiter should allow all")
		}
	}
}

func TestRateLimiter_WindowExpiry(t *testing.T) {
	rl := NewRateLimiter(context.Background(), 2, 50*time.Millisecond)

	rl.Allow("1.2.3.4")
	rl.Allow("1.2.3.4")

	if rl.Allow("1.2.3.4") {
		t.Fatal("should be rate-limited")
	}

	// Wait for window to expire
	time.Sleep(60 * time.Millisecond)

	if !rl.Allow("1.2.3.4") {
		t.Fatal("should be allowed after window expires")
	}
}

func TestRateLimiter_Stats(t *testing.T) {
	rl := NewRateLimiter(context.Background(), 10, time.Minute)
	rl.Allow("1.1.1.1")
	rl.Allow("2.2.2.2")

	stats := rl.Stats()
	if stats["enabled"] != true {
		t.Fatal("should be enabled")
	}
	if stats["tracked_ips"].(int) != 2 {
		t.Fatal("should track 2 IPs")
	}
}

func TestMetrics_Counters(t *testing.T) {
	m := NewMetrics()
	m.IncRequests()
	m.IncRequests()
	m.IncErrors()
	m.IncEvents()
	m.IncIncidents()
	m.IncRateLimited()

	if m.requestsTotal.Load() != 2 {
		t.Fatalf("expected 2 requests, got %d", m.requestsTotal.Load())
	}
	if m.requestErrors.Load() != 1 {
		t.Fatalf("expected 1 error, got %d", m.requestErrors.Load())
	}
	if m.eventsIngested.Load() != 1 {
		t.Fatalf("expected 1 event, got %d", m.eventsIngested.Load())
	}
}
