package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"time"
)

// htmlTagRegex strips HTML/script tags from user input (M5 XSS prevention).
var htmlTagRegex = regexp.MustCompile(`<[^>]*>`)

// EmailSendFunc is a callback for sending verification emails.
// Signature: func(toEmail, userName, code string) error
type EmailSendFunc func(toEmail, userName, code string) error

// HandleRegister processes new tenant + owner registration.
// POST /api/auth/register { email, password, name, org_name, org_slug }
// Returns verification_required — user must verify email before login.
// If emailFn is nil, verification code is returned in response (dev mode).
func HandleRegister(userStore *UserStore, tenantStore *TenantStore, jwtSecret []byte, emailFn EmailSendFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// SEC-M4: Server-side registration gate
		if os.Getenv("SOC_REGISTRATION_OPEN") == "false" {
			http.Error(w, `{"error":"registration is closed — contact admin for an invitation"}`, http.StatusForbidden)
			return
		}

		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			Name     string `json:"name"`
			OrgName  string `json:"org_name"`
			OrgSlug  string `json:"org_slug"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}
		if req.Email == "" || req.Password == "" || req.OrgName == "" || req.OrgSlug == "" {
			http.Error(w, `{"error":"email, password, org_name, org_slug are required"}`, http.StatusBadRequest)
			return
		}
		if len(req.Password) < 8 {
			http.Error(w, `{"error":"password must be at least 8 characters"}`, http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			req.Name = req.Email
		}

		// SEC-M5: Strip HTML tags from user input to prevent stored XSS
		req.Name = htmlTagRegex.ReplaceAllString(req.Name, "")
		req.OrgName = htmlTagRegex.ReplaceAllString(req.OrgName, "")

		// Create user first (admin of new tenant)
		user, err := userStore.CreateUser(req.Email, req.Name, req.Password, "admin")
		if err != nil {
			if err == ErrUserExists {
				http.Error(w, `{"error":"email already registered"}`, http.StatusConflict)
				return
			}
			http.Error(w, `{"error":"failed to create user"}`, http.StatusInternalServerError)
			return
		}

		// Create tenant
		tenant, err := tenantStore.CreateTenant(req.OrgName, req.OrgSlug, user.ID, "free")
		if err != nil {
			if err == ErrTenantExists {
				http.Error(w, `{"error":"organization slug already taken"}`, http.StatusConflict)
				return
			}
			http.Error(w, `{"error":"failed to create organization"}`, http.StatusInternalServerError)
			return
		}

		// Update user with tenant_id
		// CRITICAL: pgx/v5 requires $1/$2 placeholders, NOT ? (silently fails with ?)
		if userStore.db != nil {
			if _, err := userStore.db.Exec(`UPDATE users SET tenant_id = $1 WHERE id = $2`, tenant.ID, user.ID); err != nil {
				slog.Error("register: failed to set tenant_id on user", "user", user.ID, "tenant", tenant.ID, "error", err)
			}
			// Also update in-memory cache
			userStore.mu.Lock()
			if u, ok := userStore.users[user.Email]; ok {
				u.TenantID = tenant.ID
			}
			userStore.mu.Unlock()
		}

		// Generate verification code
		code, err := userStore.SetVerifyToken(req.Email)
		if err != nil {
			http.Error(w, `{"error":"failed to generate verification code"}`, http.StatusInternalServerError)
			return
		}

		// Send verification email if email service is configured
		resp := map[string]interface{}{
			"status":  "verification_required",
			"email":   req.Email,
			"message": "Verification code sent to your email",
			"tenant":  tenant,
		}

		if emailFn != nil {
			if err := emailFn(req.Email, req.Name, code); err != nil {
				slog.Error("failed to send verification email", "email", req.Email, "error", err)
				// Still return success — code is in DB, user can retry
			}
		} else {
			// SEC: Never expose verification code in API response.
			// Log server-side only for development debugging.
			slog.Warn("email service not configured — verification code logged (dev only)",
				"email", req.Email, "code", code)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}
}

// HandleVerifyEmail validates the verification code and issues JWT.
// POST /api/auth/verify { email, code }
func HandleVerifyEmail(userStore *UserStore, tenantStore *TenantStore, jwtSecret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email string `json:"email"`
			Code  string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}
		if req.Email == "" || req.Code == "" {
			http.Error(w, `{"error":"email and code required"}`, http.StatusBadRequest)
			return
		}

		if err := userStore.VerifyEmail(req.Email, req.Code); err != nil {
			if err == ErrInvalidVerifyCode {
				http.Error(w, `{"error":"invalid or expired verification code"}`, http.StatusBadRequest)
				return
			}
			http.Error(w, `{"error":"verification failed"}`, http.StatusInternalServerError)
			return
		}

		// Get user and tenant
		user, err := userStore.GetByEmail(req.Email)
		if err != nil {
			http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
			return
		}

		// Find tenant for this user
		// CRITICAL: pgx/v5 requires $1 placeholder, NOT ?
		var tenantID string
		if userStore.db != nil {
			if err := userStore.db.QueryRow(`SELECT tenant_id FROM users WHERE id = $1`, user.ID).Scan(&tenantID); err != nil {
				slog.Warn("verify: could not read tenant_id from DB", "user", user.ID, "error", err)
			}
		}
		// Fallback: check in-memory user object
		if tenantID == "" && user.TenantID != "" {
			tenantID = user.TenantID
		}

		// Issue JWT with tenant context
		accessToken, err := Sign(Claims{
			Sub:       user.Email,
			Role:      user.Role,
			TenantID:  tenantID,
			TokenType: "access",
			Exp:       time.Now().Add(15 * time.Minute).Unix(),
		}, jwtSecret)
		if err != nil {
			http.Error(w, `{"error":"failed to issue token"}`, http.StatusInternalServerError)
			return
		}

		refreshToken, _ := Sign(Claims{
			Sub:       user.Email,
			Role:      user.Role,
			TenantID:  tenantID,
			TokenType: "refresh",
			Exp:       time.Now().Add(7 * 24 * time.Hour).Unix(),
		}, jwtSecret)

		var tenant *Tenant
		if tenantID != "" {
			tenant, _ = tenantStore.GetTenant(tenantID)
		}

		// SEC: H1 - Use httpOnly Cookies instead of returning JSON tokens
		http.SetCookie(w, &http.Cookie{
			Name:     "syntrex_token",
			Value:    accessToken,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   900,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "syntrex_refresh",
			Value:    refreshToken,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   7 * 24 * 3600,
		})

		// SEC: M2 - Generate stateless CSRF token
		csrfToken := hmacSign([]byte(accessToken), jwtSecret)[:32]

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"csrf_token": csrfToken,
			"user":       user,
			"tenant":     tenant,
		})
	}
}

// HandleGetTenant returns the current tenant info.
// GET /api/auth/tenant
func HandleGetTenant(tenantStore *TenantStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r.Context())
		if claims == nil || claims.TenantID == "" {
			http.Error(w, `{"error":"no tenant context"}`, http.StatusForbidden)
			return
		}

		tenant, err := tenantStore.GetTenant(claims.TenantID)
		if err != nil {
			http.Error(w, `{"error":"tenant not found"}`, http.StatusNotFound)
			return
		}

		plan := tenant.GetPlan()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tenant": tenant,
			"plan":   plan,
			"usage": map[string]interface{}{
				"events_this_month": tenant.EventsThisMonth,
				"events_limit":     plan.MaxEventsMonth,
				"usage_percent":    usagePercent(tenant.EventsThisMonth, plan.MaxEventsMonth),
			},
		})
	}
}

// HandleUpdateTenantPlan upgrades/downgrades the tenant plan.
// POST /api/auth/tenant/plan { plan_id }
// SEC: Only allows downgrade to 'free' without payment. Paid upgrades require
// Stripe webhook confirmation (HandleStripeWebhook). This prevents users from
// clicking "Перейти" on paid plans and getting access without payment.
func HandleUpdateTenantPlan(tenantStore *TenantStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r.Context())
		if claims == nil || claims.Role != "admin" {
			http.Error(w, `{"error":"admin role required"}`, http.StatusForbidden)
			return
		}
		if claims.TenantID == "" {
			http.Error(w, `{"error":"no tenant context"}`, http.StatusForbidden)
			return
		}

		var req struct {
			PlanID string `json:"plan_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
			return
		}

		// SEC: Block direct upgrades to paid plans — only Stripe webhook can do that
		if req.PlanID != "free" {
			http.Error(w, `{"error":"paid plan upgrades require payment — visit syntrex.pro/pricing"}`, http.StatusPaymentRequired)
			return
		}

		if err := tenantStore.UpdatePlan(claims.TenantID, req.PlanID); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}

		tenant, _ := tenantStore.GetTenant(claims.TenantID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tenant": tenant,
			"plan":   tenant.GetPlan(),
		})
	}
}

// HandleListPlans returns all available pricing plans.
// GET /api/auth/plans
func HandleListPlans() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		plans := make([]Plan, 0, len(DefaultPlans))
		order := []string{"free", "starter", "professional", "enterprise"}
		for _, id := range order {
			if p, ok := DefaultPlans[id]; ok {
				plans = append(plans, p)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"plans": plans})
	}
}

// HandleBillingStatus returns the billing status for the tenant.
// GET /api/auth/billing
func HandleBillingStatus(tenantStore *TenantStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r.Context())
		if claims == nil || claims.TenantID == "" {
			http.Error(w, `{"error":"no tenant context"}`, http.StatusForbidden)
			return
		}

		tenant, err := tenantStore.GetTenant(claims.TenantID)
		if err != nil {
			http.Error(w, `{"error":"tenant not found"}`, http.StatusNotFound)
			return
		}

		plan := tenant.GetPlan()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"plan":               plan,
			"payment_customer_id": tenant.PaymentCustomerID,
			"payment_sub_id":      tenant.PaymentSubID,
			"events_used":        tenant.EventsThisMonth,
			"events_limit":       plan.MaxEventsMonth,
			"usage_percent":      usagePercent(tenant.EventsThisMonth, plan.MaxEventsMonth),
			"next_reset":         tenant.MonthResetAt,
		})
	}
}

// HandleStripeWebhook processes Stripe webhook events.
// POST /api/billing/webhook
func HandleStripeWebhook(tenantStore *TenantStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var evt struct {
			Type string `json:"type"`
			Data struct {
				Object struct {
					CustomerID     string `json:"customer"`
					SubscriptionID string `json:"id"`
					Status         string `json:"status"`
					Metadata       struct {
						TenantID string `json:"tenant_id"`
						PlanID   string `json:"plan_id"`
					} `json:"metadata"`
				} `json:"object"`
			} `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}

		tenantID := evt.Data.Object.Metadata.TenantID

		switch evt.Type {
		case "customer.subscription.created", "customer.subscription.updated":
			if tenantID != "" {
				tenantStore.SetStripeIDs(tenantID,
					evt.Data.Object.CustomerID,
					evt.Data.Object.SubscriptionID)
				if planID := evt.Data.Object.Metadata.PlanID; planID != "" {
					tenantStore.UpdatePlan(tenantID, planID)
				}
			}
		case "customer.subscription.deleted":
			if tenantID != "" {
				tenantStore.UpdatePlan(tenantID, "starter")
				tenantStore.SetStripeIDs(tenantID, evt.Data.Object.CustomerID, "")
			}
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"received":true}`))
	}
}

func usagePercent(used, limit int) float64 {
	if limit <= 0 {
		return 0
	}
	pct := float64(used) / float64(limit) * 100
	if pct > 100 {
		return 100
	}
	return pct
}
