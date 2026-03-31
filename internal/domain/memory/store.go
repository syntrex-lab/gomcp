// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

package memory

import "context"

// FactStore defines the interface for hierarchical fact persistence.
type FactStore interface {
	// CRUD
	Add(ctx context.Context, fact *Fact) error
	Get(ctx context.Context, id string) (*Fact, error)
	Update(ctx context.Context, fact *Fact) error
	Delete(ctx context.Context, id string) error

	// Queries
	ListByDomain(ctx context.Context, domain string, includeStale bool) ([]*Fact, error)
	ListByLevel(ctx context.Context, level HierLevel) ([]*Fact, error)
	ListDomains(ctx context.Context) ([]string, error)
	GetStale(ctx context.Context, includeArchived bool) ([]*Fact, error)
	Search(ctx context.Context, query string, limit int) ([]*Fact, error)

	// Genome Layer
	ListGenes(ctx context.Context) ([]*Fact, error)

	// TTL
	GetExpired(ctx context.Context) ([]*Fact, error)
	RefreshTTL(ctx context.Context, id string) error

	// v3.3 Context GC
	TouchFact(ctx context.Context, id string) error                                            // Increment hit_count + update last_accessed_at
	GetColdFacts(ctx context.Context, limit int) ([]*Fact, error)                              // hit_count=0, created >30 days ago
	CompressFacts(ctx context.Context, ids []string, summary string) (newID string, err error) // Archive originals, create summary

	// Stats
	Stats(ctx context.Context) (*FactStoreStats, error)
}

// HotCache defines the interface for in-memory L0 fact cache.
type HotCache interface {
	GetL0Facts(ctx context.Context) ([]*Fact, error)
	InvalidateFact(ctx context.Context, id string) error
	WarmUp(ctx context.Context, facts []*Fact) error
	Close() error
}
