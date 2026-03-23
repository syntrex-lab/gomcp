package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Standard user errors.
var (
	ErrUserNotFound      = errors.New("auth: user not found")
	ErrUserExists        = errors.New("auth: user already exists")
	ErrInvalidPassword   = errors.New("auth: invalid password")
	ErrUserDisabled      = errors.New("auth: account disabled")
	ErrEmailNotVerified  = errors.New("auth: email not verified")
	ErrInvalidVerifyCode = errors.New("auth: invalid or expired verification code")
)

// User represents an authenticated user in the system.
type User struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	DisplayName   string     `json:"display_name"`
	Role          string     `json:"role"` // admin, analyst, viewer
	Active        bool       `json:"active"`
	EmailVerified bool       `json:"email_verified"`
	PasswordHash  string     `json:"-"` // never serialized
	VerifyToken   string     `json:"-"` // never serialized
	VerifyExpiry  *time.Time `json:"-"` // never serialized
	CreatedAt     time.Time  `json:"created_at"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
}

// UserStore manages user credentials backed by SQLite.
// Falls back to in-memory store if no DB is provided.
type UserStore struct {
	mu    sync.RWMutex
	db    *sql.DB
	users map[string]*User // email -> User (in-memory cache / fallback)
}

// NewUserStore creates a user store. If db is nil, uses in-memory only.
func NewUserStore(db ...*sql.DB) *UserStore {
	s := &UserStore{
		users: make(map[string]*User),
	}

	if len(db) > 0 && db[0] != nil {
		s.db = db[0]
		if err := s.migrate(); err != nil {
			slog.Error("user store: migration failed", "error", err)
		} else {
			s.loadFromDB()
		}
	}

	// Ensure default admin exists
	if _, err := s.GetByEmail("admin@xn--80akacl3adqr.xn--p1acf"); err != nil {
		hash, _ := bcrypt.GenerateFromPassword([]byte("syntrex-admin-2026"), bcrypt.DefaultCost)
		admin := &User{
			ID:            generateID("usr"),
			Email:         "admin@xn--80akacl3adqr.xn--p1acf",
			DisplayName:   "Administrator",
			Role:          "admin",
			Active:        true,
			EmailVerified: true, // default admin is pre-verified
			PasswordHash:  string(hash),
			CreatedAt:     time.Now(),
		}
		s.mu.Lock()
		s.users[admin.Email] = admin
		s.mu.Unlock()
		if s.db != nil {
			s.persistUser(admin)
		}
		slog.Info("default admin created", "email", admin.Email)
	}

	return s
}

// migrate creates the users table if not exists.
func (s *UserStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id             TEXT PRIMARY KEY,
			email          TEXT UNIQUE NOT NULL,
			display_name   TEXT NOT NULL DEFAULT '',
			role           TEXT NOT NULL DEFAULT 'viewer',
			active         BOOLEAN NOT NULL DEFAULT true,
			email_verified BOOLEAN NOT NULL DEFAULT false,
			password_hash  TEXT NOT NULL,
			verify_token   TEXT DEFAULT '',
			verify_expiry  TIMESTAMPTZ,
			created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_login_at  TIMESTAMPTZ
		);
		CREATE TABLE IF NOT EXISTS api_keys (
			id        TEXT PRIMARY KEY,
			user_id   TEXT NOT NULL REFERENCES users(id),
			key_hash  TEXT NOT NULL,
			name      TEXT NOT NULL DEFAULT '',
			role      TEXT NOT NULL DEFAULT 'viewer',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_used  TIMESTAMPTZ
		);
	`)
	if err != nil {
		return err
	}
	// Add columns if upgrading from older schema (ignore errors if column exists)
	s.db.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT NOT NULL DEFAULT ''`)
	s.db.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false`)
	s.db.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_token TEXT DEFAULT ''`)
	s.db.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_expiry TIMESTAMPTZ`)
	return nil
}

// loadFromDB loads all users from DB into memory cache.
func (s *UserStore) loadFromDB() {
	rows, err := s.db.Query(`SELECT id, email, display_name, role, active, password_hash, created_at, last_login_at FROM users`)
	if err != nil {
		slog.Error("load users from DB", "error", err)
		return
	}
	defer rows.Close()

	s.mu.Lock()
	defer s.mu.Unlock()
	for rows.Next() {
		var u User
		var lastLogin sql.NullTime
		if err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.Active, &u.PasswordHash, &u.CreatedAt, &lastLogin); err != nil {
			slog.Warn("load user row scan", "error", err)
			continue
		}
		if lastLogin.Valid {
			u.LastLoginAt = &lastLogin.Time
		}
		s.users[u.Email] = &u
	}
	slog.Info("users loaded from DB", "count", len(s.users))
}

// persistUser writes a user to DB (PostgreSQL-compatible upsert).
func (s *UserStore) persistUser(u *User) {
	if s.db == nil {
		return
	}
	_, err := s.db.Exec(`
		INSERT INTO users (id, email, display_name, role, active, email_verified, password_hash, verify_token, verify_expiry, created_at, last_login_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET
			email = EXCLUDED.email,
			display_name = EXCLUDED.display_name,
			role = EXCLUDED.role,
			active = EXCLUDED.active,
			email_verified = EXCLUDED.email_verified,
			password_hash = EXCLUDED.password_hash,
			verify_token = EXCLUDED.verify_token,
			verify_expiry = EXCLUDED.verify_expiry,
			last_login_at = EXCLUDED.last_login_at`,
		u.ID, u.Email, u.DisplayName, u.Role, u.Active, u.EmailVerified, u.PasswordHash, u.VerifyToken, u.VerifyExpiry, u.CreatedAt, u.LastLoginAt,
	)
	if err != nil {
		slog.Error("persist user", "email", u.Email, "error", err)
	}
}

// --- CRUD Operations ---

// CreateUser creates a new user with a hashed password.
func (s *UserStore) CreateUser(email, displayName, password, role string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[email]; exists {
		return nil, ErrUserExists
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("auth: hash password: %w", err)
	}

	u := &User{
		ID:           generateID("usr"),
		Email:        email,
		DisplayName:  displayName,
		Role:         role,
		Active:       true,
		PasswordHash: string(hash),
		CreatedAt:    time.Now(),
	}

	s.users[email] = u
	go s.persistUser(u)
	return u, nil
}

// Authenticate validates email/password and returns the user.
func (s *UserStore) Authenticate(email, password string) (*User, error) {
	s.mu.RLock()
	user, ok := s.users[email]
	s.mu.RUnlock()

	if !ok {
		return nil, ErrUserNotFound
	}
	if !user.Active {
		return nil, ErrUserDisabled
	}
	if !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidPassword
	}

	// Update last login
	now := time.Now()
	s.mu.Lock()
	user.LastLoginAt = &now
	s.mu.Unlock()
	go s.persistUser(user)

	return user, nil
}

// SetVerifyToken generates a 6-digit verification code for a user.
func (s *UserStore) SetVerifyToken(email string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[email]
	if !ok {
		return "", ErrUserNotFound
	}
	// Generate 6-digit code
	b := make([]byte, 3)
	rand.Read(b)
	code := fmt.Sprintf("%06d", int(b[0])<<16|int(b[1])<<8|int(b[2])%1000000)
	if len(code) > 6 {
		code = code[:6]
	}
	expiry := time.Now().Add(24 * time.Hour)
	user.VerifyToken = code
	user.VerifyExpiry = &expiry
	go s.persistUser(user)
	return code, nil
}

// VerifyEmail checks the verification code and marks email as verified.
func (s *UserStore) VerifyEmail(email, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[email]
	if !ok {
		return ErrUserNotFound
	}
	if user.VerifyToken == "" || user.VerifyToken != code {
		return ErrInvalidVerifyCode
	}
	if user.VerifyExpiry != nil && time.Now().After(*user.VerifyExpiry) {
		return ErrInvalidVerifyCode
	}
	user.EmailVerified = true
	user.VerifyToken = ""
	user.VerifyExpiry = nil
	go s.persistUser(user)
	return nil
}

// GetByEmail returns a user by email.
func (s *UserStore) GetByEmail(email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[email]
	if !ok {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// GetByID returns a user by ID.
func (s *UserStore) GetByID(id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, ErrUserNotFound
}

// ListUsers returns all users.
func (s *UserStore) ListUsers() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		result = append(result, u)
	}
	return result
}

// UpdateUser updates a user's display name, role, and active status.
func (s *UserStore) UpdateUser(id, displayName, role string, active bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.users {
		if u.ID == id {
			if displayName != "" {
				u.DisplayName = displayName
			}
			if role != "" {
				u.Role = role
			}
			u.Active = active
			go s.persistUser(u)
			return nil
		}
	}
	return ErrUserNotFound
}

// ChangePassword updates a user's password.
func (s *UserStore) ChangePassword(id, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("auth: hash password: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.ID == id {
			u.PasswordHash = string(hash)
			go s.persistUser(u)
			return nil
		}
	}
	return ErrUserNotFound
}

// DeleteUser permanently removes a user.
func (s *UserStore) DeleteUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for email, u := range s.users {
		if u.ID == id {
			delete(s.users, email)
			if s.db != nil {
				go s.db.Exec(`DELETE FROM users WHERE id = $1`, id)
			}
			return nil
		}
	}
	return ErrUserNotFound
}

// --- API Key Management ---

// APIKey represents an API key for programmatic access.
type APIKey struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	KeyPrefix string    `json:"key_prefix"` // first 8 chars for display
	CreatedAt time.Time `json:"created_at"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
}

// CreateAPIKey generates a new API key for a user. Returns the full key (only shown once).
func (s *UserStore) CreateAPIKey(userID, name, role string) (string, *APIKey, error) {
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		return "", nil, err
	}
	fullKey := "stx_" + hex.EncodeToString(rawKey)
	keyHash := hashKey(fullKey)

	ak := &APIKey{
		ID:        generateID("key"),
		UserID:    userID,
		Name:      name,
		Role:      role,
		KeyPrefix: fullKey[:12],
		CreatedAt: time.Now(),
	}

	if s.db != nil {
		_, err := s.db.Exec(`INSERT INTO api_keys (id, user_id, key_hash, name, role, created_at) VALUES ($1,$2,$3,$4,$5,$6)`,
			ak.ID, ak.UserID, keyHash, ak.Name, ak.Role, ak.CreatedAt)
		if err != nil {
			return "", nil, err
		}
	}

	return fullKey, ak, nil
}

// ValidateAPIKey checks an API key and returns the associated role.
func (s *UserStore) ValidateAPIKey(key string) (string, string, error) {
	if s.db == nil {
		return "", "", fmt.Errorf("no database for API keys")
	}
	keyHash := hashKey(key)
	var userID, role string
	err := s.db.QueryRow(`SELECT user_id, role FROM api_keys WHERE key_hash = $1`, keyHash).Scan(&userID, &role)
	if err != nil {
		return "", "", ErrInvalidToken
	}

	// Update last_used
	go s.db.Exec(`UPDATE api_keys SET last_used = $1 WHERE key_hash = $2`, time.Now(), keyHash)
	return userID, role, nil
}

// ListAPIKeys returns all API keys for a user.
func (s *UserStore) ListAPIKeys(userID string) ([]APIKey, error) {
	if s.db == nil {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT id, user_id, name, role, created_at, last_used FROM api_keys WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		var ak APIKey
		var lastUsed sql.NullTime
		if err := rows.Scan(&ak.ID, &ak.UserID, &ak.Name, &ak.Role, &ak.CreatedAt, &lastUsed); err != nil {
			continue
		}
		if lastUsed.Valid {
			ak.LastUsed = &lastUsed.Time
		}
		keys = append(keys, ak)
	}
	return keys, nil
}

// DeleteAPIKey revokes an API key.
func (s *UserStore) DeleteAPIKey(keyID, userID string) error {
	if s.db == nil {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM api_keys WHERE id = $1 AND user_id = $2`, keyID, userID)
	return err
}

// --- Helpers ---

func generateID(prefix string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}
