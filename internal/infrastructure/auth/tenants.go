package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Standard tenant errors.
var (
	ErrTenantNotFound = errors.New("auth: tenant not found")
	ErrTenantExists   = errors.New("auth: tenant already exists")
	ErrQuotaExceeded  = errors.New("auth: plan quota exceeded")
)

// Plan represents a subscription tier with resource limits.
type Plan struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Description       string `json:"description,omitempty"`
	MaxUsers          int    `json:"max_users"`
	MaxEventsMonth    int    `json:"max_events_month"`
	MaxIncidents      int    `json:"max_incidents"`
	MaxSensors        int    `json:"max_sensors"`
	RetentionDays     int    `json:"retention_days"`
	SLAEnabled        bool   `json:"sla_enabled"`
	SOAREnabled       bool   `json:"soar_enabled"`
	ComplianceEnabled bool   `json:"compliance_enabled"`
	OnPremise         bool   `json:"on_premise"`          // Enterprise: on-premise deployment
	PriceMonthCents   int    `json:"price_month_cents"`   // 0 = free, -1 = custom pricing
}

// DefaultPlans defines the standard pricing tiers (prices in RUB kopecks).
var DefaultPlans = map[string]Plan{
	"starter": {
		ID: "starter", Name: "Starter",
		Description: "AI-мониторинг: до 5 сенсоров, базовая корреляция и алерты",
		MaxUsers: 10, MaxEventsMonth: 100000, MaxIncidents: 200, MaxSensors: 5,
		RetentionDays: 30, SLAEnabled: true, SOAREnabled: false, ComplianceEnabled: false,
		PriceMonthCents: 8990000, // 89 900 ₽/мес
	},
	"professional": {
		ID: "professional", Name: "Professional",
		Description: "Полный AI SOC: SOAR, compliance, расширенная аналитика",
		MaxUsers: 50, MaxEventsMonth: 500000, MaxIncidents: 1000, MaxSensors: 25,
		RetentionDays: 90, SLAEnabled: true, SOAREnabled: true, ComplianceEnabled: true,
		PriceMonthCents: 14990000, // 149 900 ₽/мес
	},
	"enterprise": {
		ID: "enterprise", Name: "Enterprise",
		Description: "On-premise / выделенный инстанс. Сертификация — на стороне заказчика",
		MaxUsers: -1, MaxEventsMonth: -1, MaxIncidents: -1, MaxSensors: -1,
		RetentionDays: 365, SLAEnabled: true, SOAREnabled: true, ComplianceEnabled: true,
		OnPremise: true,
		PriceMonthCents: -1, // по запросу
	},
}

// Tenant represents an isolated organization in the multi-tenant system.
type Tenant struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Slug             string    `json:"slug"`
	PlanID           string    `json:"plan_id"`
	PaymentCustomerID string   `json:"payment_customer_id,omitempty"`
	PaymentSubID      string   `json:"payment_sub_id,omitempty"`
	OwnerUserID      string    `json:"owner_user_id"`
	Active           bool      `json:"active"`
	CreatedAt        time.Time `json:"created_at"`
	EventsThisMonth  int       `json:"events_this_month"`
	MonthResetAt     time.Time `json:"month_reset_at"`
}

// GetPlan returns the tenant's plan configuration.
func (t *Tenant) GetPlan() Plan {
	if p, ok := DefaultPlans[t.PlanID]; ok {
		return p
	}
	return DefaultPlans["starter"]
}

// CanIngestEvent checks if the tenant can still ingest events this month.
func (t *Tenant) CanIngestEvent() bool {
	plan := t.GetPlan()
	if plan.MaxEventsMonth < 0 {
		return true // unlimited
	}
	return t.EventsThisMonth < plan.MaxEventsMonth
}

// TenantStore manages tenant records backed by SQLite.
type TenantStore struct {
	mu      sync.RWMutex
	db      *sql.DB
	tenants map[string]*Tenant // id -> Tenant
}

// NewTenantStore creates a tenant store.
func NewTenantStore(db *sql.DB) *TenantStore {
	s := &TenantStore{
		db:      db,
		tenants: make(map[string]*Tenant),
	}
	if db != nil {
		if err := s.migrate(); err != nil {
			slog.Error("tenant store: migration failed", "error", err)
		} else {
			s.loadFromDB()
		}
	}
	return s
}

func (s *TenantStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS tenants (
			id                TEXT PRIMARY KEY,
			name              TEXT NOT NULL,
			slug              TEXT UNIQUE NOT NULL,
			plan_id           TEXT NOT NULL DEFAULT 'free',
			stripe_customer_id TEXT DEFAULT '',
			stripe_sub_id     TEXT DEFAULT '',
			owner_user_id     TEXT NOT NULL,
			active            INTEGER NOT NULL DEFAULT 1,
			created_at        TEXT NOT NULL,
			events_this_month INTEGER NOT NULL DEFAULT 0,
			month_reset_at    TEXT NOT NULL
		);
		-- Add tenant_id to users table if not exists
		-- SQLite doesn't support ADD COLUMN IF NOT EXISTS, so we use a trick
	`)
	if err != nil {
		return err
	}

	// Add tenant_id column to users if missing
	_, _ = s.db.Exec(`ALTER TABLE users ADD COLUMN tenant_id TEXT DEFAULT ''`)
	return nil
}

func (s *TenantStore) loadFromDB() {
	rows, err := s.db.Query(`SELECT id, name, slug, plan_id, stripe_customer_id, stripe_sub_id, 
		owner_user_id, active, created_at, events_this_month, month_reset_at FROM tenants`)
	if err != nil {
		slog.Error("load tenants from DB", "error", err)
		return
	}
	defer rows.Close()

	s.mu.Lock()
	defer s.mu.Unlock()
	for rows.Next() {
		var t Tenant
		var createdAt, monthReset string
		if err := rows.Scan(&t.ID, &t.Name, &t.Slug, &t.PlanID, &t.PaymentCustomerID,
			&t.PaymentSubID, &t.OwnerUserID, &t.Active, &createdAt, &t.EventsThisMonth, &monthReset); err != nil {
			continue
		}
		t.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		t.MonthResetAt, _ = time.Parse(time.RFC3339, monthReset)
		s.tenants[t.ID] = &t
	}
	slog.Info("tenants loaded from DB", "count", len(s.tenants))
}

func (s *TenantStore) persistTenant(t *Tenant) {
	if s.db == nil {
		return
	}
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO tenants (id, name, slug, plan_id, stripe_customer_id, stripe_sub_id,
			owner_user_id, active, created_at, events_this_month, month_reset_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.Slug, t.PlanID, t.PaymentCustomerID, t.PaymentSubID,
		t.OwnerUserID, t.Active, t.CreatedAt.Format(time.RFC3339),
		t.EventsThisMonth, t.MonthResetAt.Format(time.RFC3339),
	)
	if err != nil {
		slog.Error("persist tenant", "id", t.ID, "error", err)
	}
}

// CreateTenant creates a new tenant and assigns an owner.
func (s *TenantStore) CreateTenant(name, slug, ownerUserID, planID string) (*Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range s.tenants {
		if t.Slug == slug {
			return nil, ErrTenantExists
		}
	}

	if _, ok := DefaultPlans[planID]; !ok {
		planID = "starter"
	}

	t := &Tenant{
		ID:              generateID("tnt"),
		Name:            name,
		Slug:            slug,
		PlanID:          planID,
		OwnerUserID:     ownerUserID,
		Active:          true,
		CreatedAt:       time.Now(),
		EventsThisMonth: 0,
		MonthResetAt:    monthStart(time.Now().AddDate(0, 1, 0)),
	}

	s.tenants[t.ID] = t
	go s.persistTenant(t)
	return t, nil
}

// GetTenant returns a tenant by ID.
func (s *TenantStore) GetTenant(id string) (*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tenants[id]
	if !ok {
		return nil, ErrTenantNotFound
	}
	return t, nil
}

// GetTenantBySlug returns a tenant by slug.
func (s *TenantStore) GetTenantBySlug(slug string) (*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.tenants {
		if t.Slug == slug {
			return t, nil
		}
	}
	return nil, ErrTenantNotFound
}

// ListTenants returns all tenants.
func (s *TenantStore) ListTenants() []*Tenant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		result = append(result, t)
	}
	return result
}

// UpdatePlan changes a tenant's plan.
func (s *TenantStore) UpdatePlan(tenantID, planID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[tenantID]
	if !ok {
		return ErrTenantNotFound
	}
	if _, valid := DefaultPlans[planID]; !valid {
		return fmt.Errorf("auth: unknown plan %q", planID)
	}
	t.PlanID = planID
	go s.persistTenant(t)
	return nil
}

// SetStripeIDs saves Stripe customer + subscription IDs.
func (s *TenantStore) SetStripeIDs(tenantID, customerID, subID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[tenantID]
	if !ok {
		return ErrTenantNotFound
	}
	t.PaymentCustomerID = customerID
	t.PaymentSubID = subID
	go s.persistTenant(t)
	return nil
}

// IncrementEvents increments the monthly event counter. Returns error if quota exceeded.
func (s *TenantStore) IncrementEvents(tenantID string, count int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[tenantID]
	if !ok {
		return ErrTenantNotFound
	}

	// Auto-reset if past the reset date
	if time.Now().After(t.MonthResetAt) {
		t.EventsThisMonth = 0
		t.MonthResetAt = monthStart(time.Now().AddDate(0, 1, 0))
	}

	plan := t.GetPlan()
	if plan.MaxEventsMonth >= 0 && t.EventsThisMonth+count > plan.MaxEventsMonth {
		return ErrQuotaExceeded
	}

	t.EventsThisMonth += count
	go s.persistTenant(t)
	return nil
}

// DeactivateTenant marks a tenant as inactive (subscription cancelled).
func (s *TenantStore) DeactivateTenant(tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[tenantID]
	if !ok {
		return ErrTenantNotFound
	}
	t.Active = false
	go s.persistTenant(t)
	return nil
}

func monthStart(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location())
}
