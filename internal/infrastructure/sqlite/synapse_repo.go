package sqlite

import (
	"context"
	"fmt"
	"time"

	"github.com/syntrex-lab/gomcp/internal/domain/synapse"
)

// SynapseRepo implements synapse.SynapseStore using SQLite.
type SynapseRepo struct {
	db *DB
}

// NewSynapseRepo creates a SynapseRepo (table created by FactRepo migration v3.3).
func NewSynapseRepo(db *DB) *SynapseRepo {
	return &SynapseRepo{db: db}
}

// Create inserts a new PENDING synapse.
func (r *SynapseRepo) Create(ctx context.Context, factIDA, factIDB string, confidence float64) (int64, error) {
	result, err := r.db.Exec(
		`INSERT INTO synapses (fact_id_a, fact_id_b, confidence, status, created_at)
		 VALUES (?, ?, ?, 'PENDING', ?)`,
		factIDA, factIDB, confidence, time.Now().Format(timeFormat))
	if err != nil {
		return 0, fmt.Errorf("create synapse: %w", err)
	}
	id, _ := result.LastInsertId()
	return id, nil
}

// ListPending returns synapses with status PENDING.
func (r *SynapseRepo) ListPending(ctx context.Context, limit int) ([]*synapse.Synapse, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.Query(
		`SELECT id, fact_id_a, fact_id_b, confidence, status, created_at
		 FROM synapses WHERE status = 'PENDING' ORDER BY confidence DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending: %w", err)
	}
	defer rows.Close()
	return scanSynapses(rows)
}

// Accept transitions a synapse to VERIFIED.
func (r *SynapseRepo) Accept(ctx context.Context, id int64) error {
	result, err := r.db.Exec(`UPDATE synapses SET status = 'VERIFIED' WHERE id = ? AND status = 'PENDING'`, id)
	if err != nil {
		return fmt.Errorf("accept synapse: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("synapse %d not found or not PENDING", id)
	}
	return nil
}

// Reject transitions a synapse to REJECTED.
func (r *SynapseRepo) Reject(ctx context.Context, id int64) error {
	result, err := r.db.Exec(`UPDATE synapses SET status = 'REJECTED' WHERE id = ? AND status = 'PENDING'`, id)
	if err != nil {
		return fmt.Errorf("reject synapse: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("synapse %d not found or not PENDING", id)
	}
	return nil
}

// ListVerified returns all VERIFIED synapses.
func (r *SynapseRepo) ListVerified(ctx context.Context) ([]*synapse.Synapse, error) {
	rows, err := r.db.Query(
		`SELECT id, fact_id_a, fact_id_b, confidence, status, created_at
		 FROM synapses WHERE status = 'VERIFIED' ORDER BY confidence DESC`)
	if err != nil {
		return nil, fmt.Errorf("list verified: %w", err)
	}
	defer rows.Close()
	return scanSynapses(rows)
}

// Count returns synapse counts by status.
func (r *SynapseRepo) Count(ctx context.Context) (pending, verified, rejected int, err error) {
	row := r.db.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN status='PENDING' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status='VERIFIED' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status='REJECTED' THEN 1 ELSE 0 END), 0)
		FROM synapses`)
	err = row.Scan(&pending, &verified, &rejected)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("count synapses: %w", err)
	}
	return
}

// Exists checks if a synapse exists between two facts (either direction).
func (r *SynapseRepo) Exists(ctx context.Context, factIDA, factIDB string) (bool, error) {
	var count int
	row := r.db.QueryRow(
		`SELECT COUNT(*) FROM synapses
		 WHERE (fact_id_a = ? AND fact_id_b = ?) OR (fact_id_a = ? AND fact_id_b = ?)`,
		factIDA, factIDB, factIDB, factIDA)
	if err := row.Scan(&count); err != nil {
		return false, fmt.Errorf("exists synapse: %w", err)
	}
	return count > 0, nil
}

// Ensure SynapseRepo implements synapse.SynapseStore.
var _ synapse.SynapseStore = (*SynapseRepo)(nil)

func scanSynapses(rows interface {
	Next() bool
	Scan(...any) error
}) ([]*synapse.Synapse, error) {
	var result []*synapse.Synapse
	for rows.Next() {
		var s synapse.Synapse
		var status, createdAt string
		if err := rows.Scan(&s.ID, &s.FactIDA, &s.FactIDB, &s.Confidence, &status, &createdAt); err != nil {
			return nil, fmt.Errorf("scan synapse: %w", err)
		}
		s.Status = synapse.Status(status)
		s.CreatedAt, _ = time.Parse(timeFormat, createdAt)
		result = append(result, &s)
	}
	return result, nil
}
