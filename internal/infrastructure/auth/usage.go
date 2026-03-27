package auth

import (
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// UsageInfo represents current usage state for a caller.
type UsageInfo struct {
	Plan        string    `json:"plan"`
	ScansUsed   int       `json:"scans_used"`
	ScansLimit  int       `json:"scans_limit"`
	Remaining   int       `json:"remaining"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Unlimited   bool      `json:"unlimited"`
}

// UsageTracker tracks scan usage per user/IP with monthly quotas.
type UsageTracker struct {
	mu sync.Mutex
	db *sql.DB
}

// NewUsageTracker creates a usage tracker backed by PostgreSQL.
func NewUsageTracker(db *sql.DB) *UsageTracker {
	t := &UsageTracker{db: db}
	if db != nil {
		if err := t.migrate(); err != nil {
			slog.Error("usage tracker: migration failed", "error", err)
		}
		// Reset expired quotas on startup
		t.ResetExpired()
	}
	return t
}

func (t *UsageTracker) migrate() error {
	_, err := t.db.Exec(`
		CREATE TABLE IF NOT EXISTS usage_quotas (
			id           TEXT PRIMARY KEY,
			user_id      TEXT,
			ip_addr      TEXT,
			plan         TEXT NOT NULL DEFAULT 'free',
			scans_used   INTEGER NOT NULL DEFAULT 0,
			scans_limit  INTEGER NOT NULL DEFAULT 1000,
			period_start TIMESTAMPTZ NOT NULL,
			period_end   TIMESTAMPTZ NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_usage_user ON usage_quotas(user_id) WHERE user_id IS NOT NULL;
		CREATE INDEX IF NOT EXISTS idx_usage_ip ON usage_quotas(ip_addr) WHERE ip_addr IS NOT NULL;
	`)
	return err
}

// currentPeriod returns the start and end of the current monthly billing period.
func currentPeriod() (time.Time, time.Time) {
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	return start, end
}

// RecordScan atomically increments the scan counter and checks quota.
// Uses the free tier default limit (1000). For plan-aware quotas, use RecordScanWithLimit.
func (t *UsageTracker) RecordScan(userID, ip string) (int, error) {
	return t.RecordScanWithLimit(userID, ip, 1000)
}

// RecordScanWithLimit atomically increments the scan counter and checks against planLimit.
// planLimit: -1=unlimited, 0=no scans allowed, >0=monthly cap.
// Returns remaining scans. Returns error if quota exceeded.
func (t *UsageTracker) RecordScanWithLimit(userID, ip string, planLimit int) (int, error) {
	if t.db == nil {
		return 999, nil // no DB = no limits
	}

	// Plan explicitly forbids scanning
	if planLimit == 0 {
		return 0, fmt.Errorf("scanning not available on current plan")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	periodStart, periodEnd := currentPeriod()

	// Determine lookup key
	lookupCol := "ip_addr"
	lookupVal := ip
	if userID != "" {
		lookupCol = "user_id"
		lookupVal = userID
	}

	// Resolve effective limit for DB storage (unlimited = 0 sentinel in DB)
	dbLimit := planLimit
	if planLimit < 0 {
		dbLimit = 0 // 0 in DB = unlimited
	}

	// Try to get existing quota record for current period
	var scansUsed, scansLimit int
	var quotaID string
	query := fmt.Sprintf(
		`SELECT id, scans_used, scans_limit FROM usage_quotas 
		 WHERE %s = $1 AND period_start = $2`, lookupCol)

	err := t.db.QueryRow(query, lookupVal, periodStart).Scan(&quotaID, &scansUsed, &scansLimit)

	if err == sql.ErrNoRows {
		// Create new quota record with plan-based limit
		quotaID = generateID("usg")
		plan := "free"
		if planLimit > 1000 {
			plan = "paid"
		} else if planLimit < 0 {
			plan = "unlimited"
		}
		var insertQuery string
		if userID != "" {
			insertQuery = `INSERT INTO usage_quotas (id, user_id, plan, scans_used, scans_limit, period_start, period_end)
				VALUES ($1, $2, $3, 1, $4, $5, $6)`
		} else {
			insertQuery = `INSERT INTO usage_quotas (id, ip_addr, plan, scans_used, scans_limit, period_start, period_end)
				VALUES ($1, $2, $3, 1, $4, $5, $6)`
		}
		_, err = t.db.Exec(insertQuery, quotaID, lookupVal, plan, dbLimit, periodStart, periodEnd)
		if err != nil {
			slog.Error("usage: create quota", "error", err)
			return 999, nil // fail open — don't block on DB errors
		}
		if planLimit < 0 {
			return -1, nil // unlimited
		}
		return planLimit - 1, nil
	}

	if err != nil {
		slog.Error("usage: query quota", "error", err)
		return 999, nil // fail open
	}

	// Update stored limit if plan changed (e.g. upgrade mid-month)
	if scansLimit != dbLimit {
		t.db.Exec(`UPDATE usage_quotas SET scans_limit = $1 WHERE id = $2`, dbLimit, quotaID)
		scansLimit = dbLimit
	}

	// Unlimited plan (scans_limit = 0 in DB)
	if scansLimit == 0 {
		t.db.Exec(`UPDATE usage_quotas SET scans_used = scans_used + 1 WHERE id = $1`, quotaID)
		return -1, nil // unlimited
	}

	// Check quota
	if scansUsed >= scansLimit {
		return 0, fmt.Errorf("quota exceeded: %d/%d scans used this month — upgrade at syntrex.pro/pricing", scansUsed, scansLimit)
	}

	// Increment
	_, err = t.db.Exec(`UPDATE usage_quotas SET scans_used = scans_used + 1 WHERE id = $1`, quotaID)
	if err != nil {
		slog.Error("usage: increment", "error", err)
	}

	return scansLimit - scansUsed - 1, nil
}

// GetUsage returns current usage for a user or IP.
func (t *UsageTracker) GetUsage(userID, ip string) *UsageInfo {
	if t.db == nil {
		return &UsageInfo{Plan: "free", ScansLimit: 1000, Remaining: 1000, Unlimited: false}
	}

	periodStart, periodEnd := currentPeriod()

	lookupCol := "ip_addr"
	lookupVal := ip
	if userID != "" {
		lookupCol = "user_id"
		lookupVal = userID
	}

	var info UsageInfo
	query := fmt.Sprintf(
		`SELECT plan, scans_used, scans_limit FROM usage_quotas 
		 WHERE %s = $1 AND period_start = $2`, lookupCol)

	err := t.db.QueryRow(query, lookupVal, periodStart).Scan(&info.Plan, &info.ScansUsed, &info.ScansLimit)
	if err != nil {
		// No usage yet
		return &UsageInfo{
			Plan:        "free",
			ScansUsed:   0,
			ScansLimit:  1000,
			Remaining:   1000,
			PeriodStart: periodStart,
			PeriodEnd:   periodEnd,
		}
	}

	info.PeriodStart = periodStart
	info.PeriodEnd = periodEnd
	if info.ScansLimit == 0 {
		info.Unlimited = true
		info.Remaining = -1
	} else {
		info.Remaining = info.ScansLimit - info.ScansUsed
		if info.Remaining < 0 {
			info.Remaining = 0
		}
	}

	return &info
}

// ResetExpired cleans up old quota records from previous periods.
func (t *UsageTracker) ResetExpired() {
	if t.db == nil {
		return
	}
	result, err := t.db.Exec(`DELETE FROM usage_quotas WHERE period_end < $1`, time.Now().UTC())
	if err != nil {
		slog.Error("usage: reset expired", "error", err)
		return
	}
	if n, _ := result.RowsAffected(); n > 0 {
		slog.Info("usage: cleaned expired quotas", "count", n)
	}
}
