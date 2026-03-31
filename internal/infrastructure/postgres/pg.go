// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

// Package postgres provides PostgreSQL persistence for the SENTINEL SOC.
//
// Uses pgx/v5 driver (pure Go, no CGO) with connection pooling.
// Migrations managed by goose.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // pgx driver registered as "pgx"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

// DB wraps a PostgreSQL connection pool.
type DB struct {
	pool   *sql.DB
	logger *slog.Logger
}

// Open connects to PostgreSQL and runs any pending goose migrations.
//
//	dsn example: "postgres://sentinel:pass@localhost:5432/sentinel_soc?sslmode=disable"
func Open(dsn string, logger *slog.Logger) (*DB, error) {
	pool, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}

	// Connection pool tuning for SOC workload.
	pool.SetMaxOpenConns(25)
	pool.SetMaxIdleConns(10)
	pool.SetConnMaxLifetime(5 * time.Minute)
	pool.SetConnMaxIdleTime(1 * time.Minute)

	// Verify connectivity.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pool.PingContext(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}

	db := &DB{pool: pool, logger: logger}

	// Run pending goose migrations.
	if err := db.migrate(); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: migrate: %w", err)
	}

	logger.Info("PostgreSQL connected", "dsn_host", redactDSN(dsn))
	return db, nil
}

// Close releases the connection pool.
func (db *DB) Close() error {
	return db.pool.Close()
}

// Pool returns the underlying *sql.DB for direct queries.
func (db *DB) Pool() *sql.DB {
	return db.pool
}

func (db *DB) migrate() error {
	goose.SetBaseFS(migrations)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("goose dialect: %w", err)
	}
	if err := goose.Up(db.pool, "migrations"); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	db.logger.Info("goose migrations applied")
	return nil
}

// redactDSN extracts host:port for logging without exposing credentials.
func redactDSN(dsn string) string {
	if len(dsn) > 60 {
		return dsn[:20] + "…" + dsn[len(dsn)-15:]
	}
	return "***"
}
