// Package vectorstore implements persistent storage for intent vectors (DIP H2.1).
//
// Intent vectors are the output of the Intent Distiller (H0.2). Storing them
// enables neuroplastic routing — matching new intents against known patterns
// to determine optimal processing paths.
//
// Features:
//   - In-memory store with capacity management (LRU eviction)
//   - Cosine similarity search for nearest-neighbor matching
//   - Route labels for categorized intent patterns
//   - Thread-safe for concurrent access
package vectorstore

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// IntentRecord stores a distilled intent with metadata.
type IntentRecord struct {
	ID             string    `json:"id"`
	Text           string    `json:"text"`            // Original text
	CompressedText string    `json:"compressed_text"` // Distilled form
	Vector         []float64 `json:"vector"`          // Intent embedding vector
	Route          string    `json:"route"`           // Assigned route label
	Verdict        string    `json:"verdict"`         // Oracle verdict (ALLOW/DENY/REVIEW)
	SincerityScore float64   `json:"sincerity_score"`
	Entropy        float64   `json:"entropy"`
	CreatedAt      time.Time `json:"created_at"`
}

// SearchResult holds a similarity search result.
type SearchResult struct {
	Record     *IntentRecord `json:"record"`
	Similarity float64       `json:"similarity"` // Cosine similarity [0, 1]
}

// Stats holds store statistics.
type Stats struct {
	TotalRecords int            `json:"total_records"`
	Capacity     int            `json:"capacity"`
	RouteCount   map[string]int `json:"route_counts"`
	VerdictCount map[string]int `json:"verdict_counts"`
	AvgEntropy   float64        `json:"avg_entropy"`
}

// Config configures the vector store.
type Config struct {
	Capacity int // Max records before LRU eviction. Default: 1000.
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{Capacity: 1000}
}

// Store is an in-memory intent vector store with similarity search.
type Store struct {
	mu       sync.RWMutex
	records  []*IntentRecord
	index    map[string]int // id → position in records
	capacity int
	nextID   int
}

// New creates a new vector store.
func New(cfg *Config) *Store {
	c := DefaultConfig()
	if cfg != nil && cfg.Capacity > 0 {
		c.Capacity = cfg.Capacity
	}
	return &Store{
		index:    make(map[string]int),
		capacity: c.Capacity,
	}
}

// Add stores an intent record. Returns the assigned ID.
func (s *Store) Add(rec *IntentRecord) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Assign ID if empty.
	if rec.ID == "" {
		s.nextID++
		rec.ID = fmt.Sprintf("intent-%d", s.nextID)
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}

	// LRU eviction: remove oldest if at capacity.
	if len(s.records) >= s.capacity {
		oldest := s.records[0]
		delete(s.index, oldest.ID)
		s.records = s.records[1:]
		// Rebuild index after shift.
		for i, r := range s.records {
			s.index[r.ID] = i
		}
	}

	s.index[rec.ID] = len(s.records)
	s.records = append(s.records, rec)
	return rec.ID
}

// Search finds the k most similar records to the given vector.
func (s *Store) Search(vector []float64, k int) []SearchResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.records) == 0 || len(vector) == 0 {
		return nil
	}

	type scored struct {
		idx int
		sim float64
	}

	scores := make([]scored, 0, len(s.records))
	for i, rec := range s.records {
		if len(rec.Vector) == 0 {
			continue
		}
		sim := CosineSimilarity(vector, rec.Vector)
		scores = append(scores, scored{idx: i, sim: sim})
	}

	// Sort by similarity descending.
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].sim > scores[j].sim
	})

	if k > len(scores) {
		k = len(scores)
	}

	results := make([]SearchResult, k)
	for i := 0; i < k; i++ {
		results[i] = SearchResult{
			Record:     s.records[scores[i].idx],
			Similarity: scores[i].sim,
		}
	}
	return results
}

// SearchByRoute finds records matching a specific route.
func (s *Store) SearchByRoute(route string) []*IntentRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*IntentRecord
	for _, rec := range s.records {
		if rec.Route == route {
			results = append(results, rec)
		}
	}
	return results
}

// Get retrieves a record by ID.
func (s *Store) Get(id string) *IntentRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idx, ok := s.index[id]
	if !ok {
		return nil
	}
	return s.records[idx]
}

// GetStats returns store statistics.
func (s *Store) GetStats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := Stats{
		TotalRecords: len(s.records),
		Capacity:     s.capacity,
		RouteCount:   make(map[string]int),
		VerdictCount: make(map[string]int),
	}

	var totalEntropy float64
	for _, rec := range s.records {
		if rec.Route != "" {
			stats.RouteCount[rec.Route]++
		}
		if rec.Verdict != "" {
			stats.VerdictCount[rec.Verdict]++
		}
		totalEntropy += rec.Entropy
	}
	if len(s.records) > 0 {
		stats.AvgEntropy = totalEntropy / float64(len(s.records))
	}
	return stats
}

// Count returns the total number of records.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
}

// CosineSimilarity computes cosine similarity between two vectors.
// Returns value in [-1, 1], where 1 = identical direction.
func CosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}

	var dot, normA, normB float64
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	denom := math.Sqrt(normA) * math.Sqrt(normB)
	if denom == 0 {
		return 0
	}
	return dot / denom
}
