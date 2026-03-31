package postgres

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/syntrex-lab/gomcp/internal/domain/soc"
)

// SOCRepo provides PostgreSQL persistence for SOC events, incidents, and sensors.
// Implements domain/soc.SOCRepository.
type SOCRepo struct {
	db *DB
}

// NewSOCRepo creates a PostgreSQL-backed SOC repository.
// Unlike SQLite, tables are created via goose migrations (not inline DDL).
func NewSOCRepo(db *DB) *SOCRepo {
	return &SOCRepo{db: db}
}

// === Events ===

// InsertEvent persists a SOC event.
func (r *SOCRepo) InsertEvent(e soc.SOCEvent) error {
	_, err := r.db.Pool().Exec(
		`INSERT INTO soc_events (id, tenant_id, source, sensor_id, severity, category, subcategory,
		 confidence, description, session_id, content_hash, decision_hash, verdict, timestamp)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		e.ID, e.TenantID, e.Source, e.SensorID, e.Severity, e.Category, e.Subcategory,
		e.Confidence, e.Description, e.SessionID, e.ContentHash, e.DecisionHash, e.Verdict,
		e.Timestamp,
	)
	return err
}

// EventExistsByHash checks if an event with the given content hash already exists (§5.2 dedup).
func (r *SOCRepo) EventExistsByHash(contentHash string) (bool, error) {
	if contentHash == "" {
		return false, nil
	}
	var count int
	err := r.db.Pool().QueryRow(
		"SELECT COUNT(*) FROM soc_events WHERE content_hash = $1", contentHash,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ListEvents returns events ordered by timestamp (newest first), with limit.
func (r *SOCRepo) ListEvents(tenantID string, limit int) ([]soc.SOCEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	if tenantID != "" {
		rows, err = r.db.Pool().Query(
			`SELECT id, source, sensor_id, severity, category, subcategory,
			 confidence, description, session_id, decision_hash, verdict, timestamp
			 FROM soc_events WHERE tenant_id = $1 ORDER BY timestamp DESC LIMIT $2`, tenantID, limit)
	} else {
		rows, err = r.db.Pool().Query(
			`SELECT id, source, sensor_id, severity, category, subcategory,
			 confidence, description, session_id, decision_hash, verdict, timestamp
			 FROM soc_events ORDER BY timestamp DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// ListEventsByCategory returns events filtered by category.
func (r *SOCRepo) ListEventsByCategory(tenantID string, category string, limit int) ([]soc.SOCEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	if tenantID != "" {
		rows, err = r.db.Pool().Query(
			`SELECT id, source, sensor_id, severity, category, subcategory,
			 confidence, description, session_id, decision_hash, verdict, timestamp
			 FROM soc_events WHERE tenant_id = $1 AND category = $2 ORDER BY timestamp DESC LIMIT $3`,
			tenantID, category, limit)
	} else {
		rows, err = r.db.Pool().Query(
			`SELECT id, source, sensor_id, severity, category, subcategory,
			 confidence, description, session_id, decision_hash, verdict, timestamp
			 FROM soc_events WHERE category = $1 ORDER BY timestamp DESC LIMIT $2`,
			category, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// CountEvents returns total event count.
func (r *SOCRepo) CountEvents(tenantID string) (int, error) {
	var count int
	var err error
	if tenantID != "" {
		err = r.db.Pool().QueryRow("SELECT COUNT(*) FROM soc_events WHERE tenant_id = $1", tenantID).Scan(&count)
	} else {
		err = r.db.Pool().QueryRow("SELECT COUNT(*) FROM soc_events").Scan(&count)
	}
	return count, err
}

// GetEvent retrieves a single event by ID.
func (r *SOCRepo) GetEvent(id string) (*soc.SOCEvent, error) {
	var e soc.SOCEvent
	err := r.db.Pool().QueryRow(
		`SELECT id, source, sensor_id, severity, category, subcategory,
		 confidence, description, session_id, decision_hash, verdict, timestamp
		 FROM soc_events WHERE id = $1`, id,
	).Scan(&e.ID, &e.Source, &e.SensorID, &e.Severity,
		&e.Category, &e.Subcategory, &e.Confidence, &e.Description,
		&e.SessionID, &e.DecisionHash, &e.Verdict, &e.Timestamp)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// CountEventsSince returns events in the given time window.
func (r *SOCRepo) CountEventsSince(tenantID string, since time.Time) (int, error) {
	var count int
	var err error
	if tenantID != "" {
		err = r.db.Pool().QueryRow(
			"SELECT COUNT(*) FROM soc_events WHERE tenant_id = $1 AND timestamp >= $2", tenantID, since,
		).Scan(&count)
	} else {
		err = r.db.Pool().QueryRow(
			"SELECT COUNT(*) FROM soc_events WHERE timestamp >= $1", since,
		).Scan(&count)
	}
	return count, err
}

func scanEvents(rows *sql.Rows) ([]soc.SOCEvent, error) {
	var events []soc.SOCEvent
	for rows.Next() {
		var e soc.SOCEvent
		err := rows.Scan(&e.ID, &e.Source, &e.SensorID, &e.Severity,
			&e.Category, &e.Subcategory, &e.Confidence, &e.Description,
			&e.SessionID, &e.DecisionHash, &e.Verdict, &e.Timestamp)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// === Incidents ===

// InsertIncident persists a new incident.
func (r *SOCRepo) InsertIncident(inc soc.Incident) error {
	_, err := r.db.Pool().Exec(
		`INSERT INTO soc_incidents (id, tenant_id, status, severity, title, description,
		 event_count, decision_chain_anchor, chain_length, correlation_rule,
		 kill_chain_phase, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		inc.ID, inc.TenantID, inc.Status, inc.Severity, inc.Title, inc.Description,
		inc.EventCount, inc.DecisionChainAnchor, inc.ChainLength,
		inc.CorrelationRule, inc.KillChainPhase,
		inc.CreatedAt, inc.UpdatedAt,
	)
	return err
}

// GetIncident retrieves an incident by ID.
func (r *SOCRepo) GetIncident(id string) (*soc.Incident, error) {
	var inc soc.Incident
	var resolvedAt sql.NullTime
	err := r.db.Pool().QueryRow(
		`SELECT id, status, severity, title, description, event_count,
		 decision_chain_anchor, chain_length, correlation_rule,
		 kill_chain_phase, playbook_applied, created_at, updated_at, resolved_at
		 FROM soc_incidents WHERE id = $1`, id,
	).Scan(&inc.ID, &inc.Status, &inc.Severity, &inc.Title, &inc.Description,
		&inc.EventCount, &inc.DecisionChainAnchor, &inc.ChainLength,
		&inc.CorrelationRule, &inc.KillChainPhase, &inc.PlaybookApplied,
		&inc.CreatedAt, &inc.UpdatedAt, &resolvedAt)
	if err != nil {
		return nil, err
	}
	if resolvedAt.Valid {
		inc.ResolvedAt = &resolvedAt.Time
	}
	return &inc, nil
}

// ListIncidents returns incidents, optionally filtered by status.
func (r *SOCRepo) ListIncidents(tenantID string, status string, limit int) ([]soc.Incident, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	switch {
	case tenantID != "" && status != "":
		rows, err = r.db.Pool().Query(
			`SELECT id, status, severity, title, description, event_count,
			 decision_chain_anchor, chain_length, correlation_rule,
			 kill_chain_phase, playbook_applied, created_at, updated_at
			 FROM soc_incidents WHERE tenant_id = $1 AND status = $2 ORDER BY created_at DESC LIMIT $3`,
			tenantID, status, limit)
	case tenantID != "":
		rows, err = r.db.Pool().Query(
			`SELECT id, status, severity, title, description, event_count,
			 decision_chain_anchor, chain_length, correlation_rule,
			 kill_chain_phase, playbook_applied, created_at, updated_at
			 FROM soc_incidents WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2`,
			tenantID, limit)
	case status != "":
		rows, err = r.db.Pool().Query(
			`SELECT id, status, severity, title, description, event_count,
			 decision_chain_anchor, chain_length, correlation_rule,
			 kill_chain_phase, playbook_applied, created_at, updated_at
			 FROM soc_incidents WHERE status = $1 ORDER BY created_at DESC LIMIT $2`,
			status, limit)
	default:
		rows, err = r.db.Pool().Query(
			`SELECT id, status, severity, title, description, event_count,
			 decision_chain_anchor, chain_length, correlation_rule,
			 kill_chain_phase, playbook_applied, created_at, updated_at
			 FROM soc_incidents ORDER BY created_at DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var incidents []soc.Incident
	for rows.Next() {
		var inc soc.Incident
		err := rows.Scan(&inc.ID, &inc.Status, &inc.Severity, &inc.Title,
			&inc.Description, &inc.EventCount, &inc.DecisionChainAnchor,
			&inc.ChainLength, &inc.CorrelationRule, &inc.KillChainPhase,
			&inc.PlaybookApplied, &inc.CreatedAt, &inc.UpdatedAt)
		if err != nil {
			return nil, err
		}
		incidents = append(incidents, inc)
	}
	return incidents, rows.Err()
}

// UpdateIncidentStatus updates status (and optionally resolved_at).
func (r *SOCRepo) UpdateIncidentStatus(id string, status soc.IncidentStatus) error {
	now := time.Now()
	if status == soc.StatusResolved || status == soc.StatusFalsePositive {
		_, err := r.db.Pool().Exec(
			`UPDATE soc_incidents SET status = $1, updated_at = $2, resolved_at = $3 WHERE id = $4`,
			status, now, now, id)
		return err
	}
	_, err := r.db.Pool().Exec(
		`UPDATE soc_incidents SET status = $1, updated_at = $2 WHERE id = $3`,
		status, now, id)
	return err
}

// CountOpenIncidents returns count of non-resolved incidents.
func (r *SOCRepo) CountOpenIncidents(tenantID string) (int, error) {
	var count int
	var err error
	if tenantID != "" {
		err = r.db.Pool().QueryRow(
			"SELECT COUNT(*) FROM soc_incidents WHERE tenant_id = $1 AND status IN ('OPEN', 'INVESTIGATING')",
			tenantID,
		).Scan(&count)
	} else {
		err = r.db.Pool().QueryRow(
			"SELECT COUNT(*) FROM soc_incidents WHERE status IN ('OPEN', 'INVESTIGATING')",
		).Scan(&count)
	}
	return count, err
}

// UpdateIncident persists full incident state (case management).
func (r *SOCRepo) UpdateIncident(inc *soc.Incident) error {
	_, err := r.db.Pool().Exec(
		`UPDATE soc_incidents SET
		 status = $1, severity = $2, description = $3,
		 event_count = $4, assigned_to = COALESCE($5, ''),
		 playbook_applied = $6, kill_chain_phase = $7,
		 updated_at = $8, resolved_at = $9
		 WHERE id = $10`,
		inc.Status, inc.Severity, inc.Description,
		inc.EventCount, inc.AssignedTo,
		inc.PlaybookApplied, inc.KillChainPhase,
		inc.UpdatedAt, inc.ResolvedAt,
		inc.ID,
	)
	return err
}

// === Sensors ===

// UpsertSensor creates or updates a sensor entry.
func (r *SOCRepo) UpsertSensor(s soc.Sensor) error {
	_, err := r.db.Pool().Exec(
		`INSERT INTO soc_sensors (sensor_id, tenant_id, sensor_type, status, first_seen, last_seen,
		 event_count, missed_heartbeats, hostname, version)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT(sensor_id) DO UPDATE SET
		   status = EXCLUDED.status,
		   last_seen = EXCLUDED.last_seen,
		   event_count = EXCLUDED.event_count,
		   missed_heartbeats = EXCLUDED.missed_heartbeats`,
		s.SensorID, s.TenantID, s.SensorType, s.Status,
		s.FirstSeen, s.LastSeen,
		s.EventCount, s.MissedHeartbeats, s.Hostname, s.Version,
	)
	return err
}

// GetSensor retrieves a sensor by ID.
func (r *SOCRepo) GetSensor(id string) (*soc.Sensor, error) {
	var s soc.Sensor
	err := r.db.Pool().QueryRow(
		`SELECT sensor_id, sensor_type, status, first_seen, last_seen,
		 event_count, missed_heartbeats, hostname, version
		 FROM soc_sensors WHERE sensor_id = $1`, id,
	).Scan(&s.SensorID, &s.SensorType, &s.Status, &s.FirstSeen, &s.LastSeen,
		&s.EventCount, &s.MissedHeartbeats, &s.Hostname, &s.Version)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// ListSensors returns all registered sensors.
func (r *SOCRepo) ListSensors(tenantID string) ([]soc.Sensor, error) {
	var rows *sql.Rows
	var err error
	if tenantID != "" {
		rows, err = r.db.Pool().Query(
			`SELECT sensor_id, sensor_type, status, first_seen, last_seen,
			 event_count, missed_heartbeats, hostname, version
			 FROM soc_sensors WHERE tenant_id = $1 ORDER BY last_seen DESC`, tenantID)
	} else {
		rows, err = r.db.Pool().Query(
			`SELECT sensor_id, sensor_type, status, first_seen, last_seen,
			 event_count, missed_heartbeats, hostname, version
			 FROM soc_sensors ORDER BY last_seen DESC`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sensors []soc.Sensor
	for rows.Next() {
		var s soc.Sensor
		err := rows.Scan(&s.SensorID, &s.SensorType, &s.Status,
			&s.FirstSeen, &s.LastSeen, &s.EventCount, &s.MissedHeartbeats,
			&s.Hostname, &s.Version)
		if err != nil {
			return nil, err
		}
		sensors = append(sensors, s)
	}
	return sensors, rows.Err()
}

// CountSensorsByStatus returns sensor count grouped by status.
func (r *SOCRepo) CountSensorsByStatus(tenantID string) (map[soc.SensorStatus]int, error) {
	var rows *sql.Rows
	var err error
	if tenantID != "" {
		rows, err = r.db.Pool().Query("SELECT status, COUNT(*) FROM soc_sensors WHERE tenant_id = $1 GROUP BY status", tenantID)
	} else {
		rows, err = r.db.Pool().Query("SELECT status, COUNT(*) FROM soc_sensors GROUP BY status")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[soc.SensorStatus]int)
	for rows.Next() {
		var status soc.SensorStatus
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		result[status] = count
	}
	return result, rows.Err()
}

// PurgeExpiredEvents deletes events older than the retention period.
func (r *SOCRepo) PurgeExpiredEvents(retentionDays int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	result, err := r.db.Pool().Exec("DELETE FROM soc_events WHERE timestamp < $1", cutoff)
	if err != nil {
		return 0, fmt.Errorf("purge events: %w", err)
	}
	return result.RowsAffected()
}

// PurgeExpiredIncidents deletes resolved incidents older than the retention period.
func (r *SOCRepo) PurgeExpiredIncidents(retentionDays int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	result, err := r.db.Pool().Exec(
		"DELETE FROM soc_incidents WHERE status = $1 AND created_at < $2",
		soc.StatusResolved, cutoff)
	if err != nil {
		return 0, fmt.Errorf("purge incidents: %w", err)
	}
	return result.RowsAffected()
}

// Compile-time interface compliance check.
var _ soc.SOCRepository = (*SOCRepo)(nil)
