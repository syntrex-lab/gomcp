package sqlite

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/sentinel-community/gomcp/internal/domain/soc"
)

// SOCRepo provides SQLite persistence for SOC events, incidents, and sensors.
type SOCRepo struct {
	db *DB
}

// NewSOCRepo creates and initializes SOC tables.
func NewSOCRepo(db *DB) (*SOCRepo, error) {
	repo := &SOCRepo{db: db}
	if err := repo.migrate(); err != nil {
		return nil, fmt.Errorf("soc_repo: migrate: %w", err)
	}
	return repo, nil
}

func (r *SOCRepo) migrate() error {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS soc_events (
			id            TEXT PRIMARY KEY,
			source        TEXT NOT NULL,
			sensor_id     TEXT NOT NULL DEFAULT '',
			severity      TEXT NOT NULL,
			category      TEXT NOT NULL,
			subcategory   TEXT NOT NULL DEFAULT '',
			confidence    REAL NOT NULL DEFAULT 0.0,
			description   TEXT NOT NULL DEFAULT '',
			session_id    TEXT NOT NULL DEFAULT '',
			decision_hash TEXT NOT NULL DEFAULT '',
			verdict       TEXT NOT NULL DEFAULT 'REVIEW',
			timestamp     TEXT NOT NULL,
			metadata      TEXT NOT NULL DEFAULT '{}'
		)`,
		`CREATE TABLE IF NOT EXISTS soc_incidents (
			id                    TEXT PRIMARY KEY,
			status                TEXT NOT NULL DEFAULT 'OPEN',
			severity              TEXT NOT NULL,
			title                 TEXT NOT NULL,
			description           TEXT NOT NULL DEFAULT '',
			event_ids             TEXT NOT NULL DEFAULT '[]',
			event_count           INTEGER NOT NULL DEFAULT 0,
			decision_chain_anchor TEXT NOT NULL DEFAULT '',
			chain_length          INTEGER NOT NULL DEFAULT 0,
			correlation_rule      TEXT NOT NULL DEFAULT '',
			kill_chain_phase      TEXT NOT NULL DEFAULT '',
			mitre_mapping         TEXT NOT NULL DEFAULT '[]',
			playbook_applied      TEXT NOT NULL DEFAULT '',
			created_at            TEXT NOT NULL,
			updated_at            TEXT NOT NULL,
			resolved_at           TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS soc_sensors (
			sensor_id         TEXT PRIMARY KEY,
			sensor_type       TEXT NOT NULL,
			status            TEXT DEFAULT 'UNKNOWN',
			first_seen        TEXT NOT NULL,
			last_seen         TEXT NOT NULL,
			event_count       INTEGER DEFAULT 0,
			missed_heartbeats INTEGER DEFAULT 0,
			hostname          TEXT NOT NULL DEFAULT '',
			version           TEXT NOT NULL DEFAULT ''
		)`,
		// Indexes for common queries.
		`CREATE INDEX IF NOT EXISTS idx_soc_events_timestamp ON soc_events(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_soc_events_severity ON soc_events(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_soc_events_category ON soc_events(category)`,
		`CREATE INDEX IF NOT EXISTS idx_soc_events_sensor ON soc_events(sensor_id)`,
		`CREATE INDEX IF NOT EXISTS idx_soc_incidents_status ON soc_incidents(status)`,
		`CREATE INDEX IF NOT EXISTS idx_soc_sensors_status ON soc_sensors(status)`,
	}
	for _, ddl := range tables {
		if _, err := r.db.Exec(ddl); err != nil {
			return fmt.Errorf("exec %q: %w", ddl[:40], err)
		}
	}
	return nil
}

// === Events ===

// InsertEvent persists a SOC event.
func (r *SOCRepo) InsertEvent(e soc.SOCEvent) error {
	_, err := r.db.Exec(
		`INSERT INTO soc_events (id, source, sensor_id, severity, category, subcategory,
		 confidence, description, session_id, decision_hash, verdict, timestamp)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.Source, e.SensorID, e.Severity, e.Category, e.Subcategory,
		e.Confidence, e.Description, e.SessionID, e.DecisionHash, e.Verdict,
		e.Timestamp.Format(time.RFC3339Nano),
	)
	return err
}

// ListEvents returns events ordered by timestamp (newest first), with limit.
func (r *SOCRepo) ListEvents(limit int) ([]soc.SOCEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.Query(
		`SELECT id, source, sensor_id, severity, category, subcategory,
		 confidence, description, session_id, decision_hash, verdict, timestamp
		 FROM soc_events ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// ListEventsByCategory returns events filtered by category.
func (r *SOCRepo) ListEventsByCategory(category string, limit int) ([]soc.SOCEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.Query(
		`SELECT id, source, sensor_id, severity, category, subcategory,
		 confidence, description, session_id, decision_hash, verdict, timestamp
		 FROM soc_events WHERE category = ? ORDER BY timestamp DESC LIMIT ?`,
		category, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// CountEvents returns total event count.
func (r *SOCRepo) CountEvents() (int, error) {
	var count int
	err := r.db.QueryRow("SELECT COUNT(*) FROM soc_events").Scan(&count)
	return count, err
}

// CountEventsSince returns events in the given time window.
func (r *SOCRepo) CountEventsSince(since time.Time) (int, error) {
	var count int
	err := r.db.QueryRow(
		"SELECT COUNT(*) FROM soc_events WHERE timestamp >= ?",
		since.Format(time.RFC3339Nano),
	).Scan(&count)
	return count, err
}

func scanEvents(rows *sql.Rows) ([]soc.SOCEvent, error) {
	var events []soc.SOCEvent
	for rows.Next() {
		var e soc.SOCEvent
		var ts string
		err := rows.Scan(&e.ID, &e.Source, &e.SensorID, &e.Severity,
			&e.Category, &e.Subcategory, &e.Confidence, &e.Description,
			&e.SessionID, &e.DecisionHash, &e.Verdict, &ts)
		if err != nil {
			return nil, err
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		events = append(events, e)
	}
	return events, rows.Err()
}

// === Incidents ===

// InsertIncident persists a new incident.
func (r *SOCRepo) InsertIncident(inc soc.Incident) error {
	_, err := r.db.Exec(
		`INSERT INTO soc_incidents (id, status, severity, title, description,
		 event_count, decision_chain_anchor, chain_length, correlation_rule,
		 kill_chain_phase, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		inc.ID, inc.Status, inc.Severity, inc.Title, inc.Description,
		inc.EventCount, inc.DecisionChainAnchor, inc.ChainLength,
		inc.CorrelationRule, inc.KillChainPhase,
		inc.CreatedAt.Format(time.RFC3339Nano),
		inc.UpdatedAt.Format(time.RFC3339Nano),
	)
	return err
}

// GetIncident retrieves an incident by ID.
func (r *SOCRepo) GetIncident(id string) (*soc.Incident, error) {
	var inc soc.Incident
	var createdAt, updatedAt string
	var resolvedAt sql.NullString
	err := r.db.QueryRow(
		`SELECT id, status, severity, title, description, event_count,
		 decision_chain_anchor, chain_length, correlation_rule,
		 kill_chain_phase, playbook_applied, created_at, updated_at, resolved_at
		 FROM soc_incidents WHERE id = ?`, id,
	).Scan(&inc.ID, &inc.Status, &inc.Severity, &inc.Title, &inc.Description,
		&inc.EventCount, &inc.DecisionChainAnchor, &inc.ChainLength,
		&inc.CorrelationRule, &inc.KillChainPhase, &inc.PlaybookApplied,
		&createdAt, &updatedAt, &resolvedAt)
	if err != nil {
		return nil, err
	}
	inc.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	inc.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	if resolvedAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, resolvedAt.String)
		inc.ResolvedAt = &t
	}
	return &inc, nil
}

// ListIncidents returns incidents, optionally filtered by status.
func (r *SOCRepo) ListIncidents(status string, limit int) ([]soc.Incident, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	if status != "" {
		rows, err = r.db.Query(
			`SELECT id, status, severity, title, description, event_count,
			 decision_chain_anchor, chain_length, correlation_rule,
			 kill_chain_phase, playbook_applied, created_at, updated_at
			 FROM soc_incidents WHERE status = ? ORDER BY created_at DESC LIMIT ?`,
			status, limit)
	} else {
		rows, err = r.db.Query(
			`SELECT id, status, severity, title, description, event_count,
			 decision_chain_anchor, chain_length, correlation_rule,
			 kill_chain_phase, playbook_applied, created_at, updated_at
			 FROM soc_incidents ORDER BY created_at DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var incidents []soc.Incident
	for rows.Next() {
		var inc soc.Incident
		var createdAt, updatedAt string
		err := rows.Scan(&inc.ID, &inc.Status, &inc.Severity, &inc.Title,
			&inc.Description, &inc.EventCount, &inc.DecisionChainAnchor,
			&inc.ChainLength, &inc.CorrelationRule, &inc.KillChainPhase,
			&inc.PlaybookApplied, &createdAt, &updatedAt)
		if err != nil {
			return nil, err
		}
		inc.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		inc.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
		incidents = append(incidents, inc)
	}
	return incidents, rows.Err()
}

// UpdateIncidentStatus updates status (and optionally resolved_at).
func (r *SOCRepo) UpdateIncidentStatus(id string, status soc.IncidentStatus) error {
	now := time.Now().Format(time.RFC3339Nano)
	if status == soc.StatusResolved || status == soc.StatusFalsePositive {
		_, err := r.db.Exec(
			`UPDATE soc_incidents SET status = ?, updated_at = ?, resolved_at = ? WHERE id = ?`,
			status, now, now, id)
		return err
	}
	_, err := r.db.Exec(
		`UPDATE soc_incidents SET status = ?, updated_at = ? WHERE id = ?`,
		status, now, id)
	return err
}

// CountOpenIncidents returns count of non-resolved incidents.
func (r *SOCRepo) CountOpenIncidents() (int, error) {
	var count int
	err := r.db.QueryRow(
		"SELECT COUNT(*) FROM soc_incidents WHERE status IN ('OPEN', 'INVESTIGATING')",
	).Scan(&count)
	return count, err
}

// === Sensors ===

// UpsertSensor creates or updates a sensor entry.
func (r *SOCRepo) UpsertSensor(s soc.Sensor) error {
	_, err := r.db.Exec(
		`INSERT INTO soc_sensors (sensor_id, sensor_type, status, first_seen, last_seen,
		 event_count, missed_heartbeats, hostname, version)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(sensor_id) DO UPDATE SET
		   status = excluded.status,
		   last_seen = excluded.last_seen,
		   event_count = excluded.event_count,
		   missed_heartbeats = excluded.missed_heartbeats`,
		s.SensorID, s.SensorType, s.Status,
		s.FirstSeen.Format(time.RFC3339Nano),
		s.LastSeen.Format(time.RFC3339Nano),
		s.EventCount, s.MissedHeartbeats, s.Hostname, s.Version,
	)
	return err
}

// GetSensor retrieves a sensor by ID.
func (r *SOCRepo) GetSensor(id string) (*soc.Sensor, error) {
	var s soc.Sensor
	var firstSeen, lastSeen string
	err := r.db.QueryRow(
		`SELECT sensor_id, sensor_type, status, first_seen, last_seen,
		 event_count, missed_heartbeats, hostname, version
		 FROM soc_sensors WHERE sensor_id = ?`, id,
	).Scan(&s.SensorID, &s.SensorType, &s.Status, &firstSeen, &lastSeen,
		&s.EventCount, &s.MissedHeartbeats, &s.Hostname, &s.Version)
	if err != nil {
		return nil, err
	}
	s.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeen)
	s.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen)
	return &s, nil
}

// ListSensors returns all registered sensors.
func (r *SOCRepo) ListSensors() ([]soc.Sensor, error) {
	rows, err := r.db.Query(
		`SELECT sensor_id, sensor_type, status, first_seen, last_seen,
		 event_count, missed_heartbeats, hostname, version
		 FROM soc_sensors ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sensors []soc.Sensor
	for rows.Next() {
		var s soc.Sensor
		var firstSeen, lastSeen string
		err := rows.Scan(&s.SensorID, &s.SensorType, &s.Status,
			&firstSeen, &lastSeen, &s.EventCount, &s.MissedHeartbeats,
			&s.Hostname, &s.Version)
		if err != nil {
			return nil, err
		}
		s.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeen)
		s.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen)
		sensors = append(sensors, s)
	}
	return sensors, rows.Err()
}

// CountSensorsByStatus returns sensor count grouped by status.
func (r *SOCRepo) CountSensorsByStatus() (map[soc.SensorStatus]int, error) {
	rows, err := r.db.Query("SELECT status, COUNT(*) FROM soc_sensors GROUP BY status")
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
