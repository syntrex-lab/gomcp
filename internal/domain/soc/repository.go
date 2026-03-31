// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

package soc

import "time"

// SOCRepository defines the persistence contract for the SOC subsystem.
// Implementations: sqlite.SOCRepo (default), postgres.SOCRepo (production).
//
// All methods that list or count data accept a tenantID parameter for multi-tenant
// isolation. Pass "" (empty) for backward compatibility (returns all tenants).
type SOCRepository interface {
	// ── Events ──────────────────────────────────────────────
	InsertEvent(e SOCEvent) error
	GetEvent(id string) (*SOCEvent, error)
	ListEvents(tenantID string, limit int) ([]SOCEvent, error)
	ListEventsByCategory(tenantID string, category string, limit int) ([]SOCEvent, error)
	EventExistsByHash(contentHash string) (bool, error) // §5.2 dedup
	CountEvents(tenantID string) (int, error)
	CountEventsSince(tenantID string, since time.Time) (int, error)

	// ── Incidents ───────────────────────────────────────────
	InsertIncident(inc Incident) error
	GetIncident(id string) (*Incident, error)
	ListIncidents(tenantID string, status string, limit int) ([]Incident, error)
	UpdateIncidentStatus(id string, status IncidentStatus) error
	UpdateIncident(inc *Incident) error
	CountOpenIncidents(tenantID string) (int, error)

	// ── Sensors ─────────────────────────────────────────────
	UpsertSensor(s Sensor) error
	ListSensors(tenantID string) ([]Sensor, error)
	CountSensorsByStatus(tenantID string) (map[SensorStatus]int, error)

	// ── Retention ───────────────────────────────────────────
	PurgeExpiredEvents(retentionDays int) (int64, error)
	PurgeExpiredIncidents(retentionDays int) (int64, error)
}
