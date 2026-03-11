// Package soc provides a threat intelligence feed integration
// for enriching SOC events and correlation rules.
//
// Supports:
//   - STIX/TAXII 2.1 feeds (JSON)
//   - CSV IOC lists (hashes, IPs, domains)
//   - Local file-based IOC database
//   - Periodic background refresh
package soc

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ─── IOC Types ──────────────────────────────────────────

// IOCType represents the type of Indicator of Compromise.
type IOCType string

const (
	IOCTypeIP     IOCType = "ipv4-addr"
	IOCTypeDomain IOCType = "domain-name"
	IOCTypeHash   IOCType = "file:hashes"
	IOCTypeURL    IOCType = "url"
	IOCCVE        IOCType = "vulnerability"
	IOCPattern    IOCType = "pattern"
)

// IOC is an Indicator of Compromise.
type IOC struct {
	Type       IOCType   `json:"type"`
	Value      string    `json:"value"`
	Source     string    `json:"source"`     // Feed name
	Severity   string    `json:"severity"`   // critical/high/medium/low
	Tags       []string  `json:"tags"`       // MITRE ATT&CK, campaign, etc.
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Confidence float64   `json:"confidence"` // 0.0-1.0
}

// ThreatFeed represents a configured threat intelligence source.
type ThreatFeed struct {
	Name        string        `json:"name"`
	URL         string        `json:"url"`
	Type        string        `json:"type"` // stix, csv, json
	Enabled     bool          `json:"enabled"`
	Interval    time.Duration `json:"interval"`
	APIKey      string        `json:"api_key,omitempty"`
	LastFetch   time.Time     `json:"last_fetch"`
	IOCCount    int           `json:"ioc_count"`
	LastError   string        `json:"last_error,omitempty"`
}

// ─── Threat Intel Store ─────────────────────────────────

// ThreatIntelStore manages IOCs from multiple feeds.
type ThreatIntelStore struct {
	mu    sync.RWMutex
	iocs  map[string]*IOC     // key: type:value
	feeds []ThreatFeed
	client *http.Client

	// Stats
	TotalIOCs    int `json:"total_iocs"`
	TotalFeeds   int `json:"total_feeds"`
	LastRefresh  time.Time `json:"last_refresh"`
	MatchesFound int64 `json:"matches_found"`
}

// NewThreatIntelStore creates an empty threat intel store.
func NewThreatIntelStore() *ThreatIntelStore {
	return &ThreatIntelStore{
		iocs:   make(map[string]*IOC),
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// AddFeed registers a threat intel feed.
func (t *ThreatIntelStore) AddFeed(feed ThreatFeed) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.feeds = append(t.feeds, feed)
	t.TotalFeeds = len(t.feeds)
}

// AddIOC adds or updates an indicator.
func (t *ThreatIntelStore) AddIOC(ioc IOC) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := fmt.Sprintf("%s:%s", ioc.Type, strings.ToLower(ioc.Value))
	if existing, ok := t.iocs[key]; ok {
		// Update — keep earliest first_seen, latest last_seen
		if ioc.FirstSeen.Before(existing.FirstSeen) {
			existing.FirstSeen = ioc.FirstSeen
		}
		existing.LastSeen = ioc.LastSeen
		if ioc.Confidence > existing.Confidence {
			existing.Confidence = ioc.Confidence
		}
	} else {
		t.iocs[key] = &ioc
		t.TotalIOCs = len(t.iocs)
	}
}

// Lookup checks if a value matches any known IOC.
// Returns nil if not found.
func (t *ThreatIntelStore) Lookup(iocType IOCType, value string) *IOC {
	t.mu.RLock()
	key := fmt.Sprintf("%s:%s", iocType, strings.ToLower(value))
	ioc, ok := t.iocs[key]
	t.mu.RUnlock()
	if ok {
		t.mu.Lock()
		t.MatchesFound++
		t.mu.Unlock()
		return ioc
	}
	return nil
}

// LookupAny checks value against all IOC types (broad search).
func (t *ThreatIntelStore) LookupAny(value string) []*IOC {
	t.mu.RLock()
	defer t.mu.RUnlock()

	lowValue := strings.ToLower(value)
	var matches []*IOC
	for key, ioc := range t.iocs {
		if strings.HasSuffix(key, ":"+lowValue) {
			matches = append(matches, ioc)
		}
	}
	return matches
}

// EnrichEvent checks event fields against IOC database and returns matches.
func (t *ThreatIntelStore) EnrichEvent(sourceIP, description string) []IOC {
	var matches []IOC

	// Check source IP
	if sourceIP != "" {
		if ioc := t.Lookup(IOCTypeIP, sourceIP); ioc != nil {
			matches = append(matches, *ioc)
		}
	}

	// Check description for domain/URL IOCs
	if description != "" {
		words := strings.Fields(description)
		for _, word := range words {
			word = strings.Trim(word, ".,;:\"'()[]{}!")
			if strings.Contains(word, ".") && len(word) > 4 {
				if ioc := t.Lookup(IOCTypeDomain, word); ioc != nil {
					matches = append(matches, *ioc)
				}
			}
		}
	}

	return matches
}

// ─── Feed Fetching ──────────────────────────────────────

// RefreshAll fetches all enabled feeds and updates IOC database.
func (t *ThreatIntelStore) RefreshAll() error {
	t.mu.RLock()
	feeds := make([]ThreatFeed, len(t.feeds))
	copy(feeds, t.feeds)
	t.mu.RUnlock()

	var errs []string
	for i, feed := range feeds {
		if !feed.Enabled {
			continue
		}

		iocs, err := t.fetchFeed(feed)
		if err != nil {
			feeds[i].LastError = err.Error()
			errs = append(errs, fmt.Sprintf("%s: %v", feed.Name, err))
			continue
		}

		for _, ioc := range iocs {
			t.AddIOC(ioc)
		}

		feeds[i].LastFetch = time.Now()
		feeds[i].IOCCount = len(iocs)
		feeds[i].LastError = ""
	}

	// Update feed states
	t.mu.Lock()
	t.feeds = feeds
	t.LastRefresh = time.Now()
	t.mu.Unlock()

	if len(errs) > 0 {
		return fmt.Errorf("feed errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// fetchFeed retrieves IOCs from a single feed.
func (t *ThreatIntelStore) fetchFeed(feed ThreatFeed) ([]IOC, error) {
	req, err := http.NewRequest("GET", feed.URL, nil)
	if err != nil {
		return nil, err
	}

	if feed.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+feed.APIKey)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SENTINEL-ThreatIntel/1.0")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	switch feed.Type {
	case "stix":
		return t.parseSTIX(resp)
	case "json":
		return t.parseJSON(resp)
	default:
		return nil, fmt.Errorf("unsupported feed type: %s", feed.Type)
	}
}

// parseSTIX parses STIX 2.1 bundle response.
func (t *ThreatIntelStore) parseSTIX(resp *http.Response) ([]IOC, error) {
	var bundle struct {
		Type    string          `json:"type"`
		ID      string          `json:"id"`
		Objects json.RawMessage `json:"objects"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, fmt.Errorf("stix parse: %w", err)
	}

	var objects []struct {
		Type    string `json:"type"`
		Pattern string `json:"pattern"`
		Name    string `json:"name"`
	}
	if err := json.Unmarshal(bundle.Objects, &objects); err != nil {
		return nil, fmt.Errorf("stix objects: %w", err)
	}

	var iocs []IOC
	now := time.Now()
	for _, obj := range objects {
		if obj.Type != "indicator" {
			continue
		}
		iocs = append(iocs, IOC{
			Type:       IOCPattern,
			Value:      obj.Pattern,
			Source:     "stix",
			FirstSeen:  now,
			LastSeen:   now,
			Confidence: 0.8,
		})
	}
	return iocs, nil
}

// parseJSON parses a simple JSON IOC list.
func (t *ThreatIntelStore) parseJSON(resp *http.Response) ([]IOC, error) {
	var iocs []IOC
	if err := json.NewDecoder(resp.Body).Decode(&iocs); err != nil {
		return nil, fmt.Errorf("json parse: %w", err)
	}
	return iocs, nil
}

// ─── Background Refresh ─────────────────────────────────

// StartBackgroundRefresh runs periodic feed refresh in a goroutine.
func (t *ThreatIntelStore) StartBackgroundRefresh(interval time.Duration, stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Initial fetch
		if err := t.RefreshAll(); err != nil {
			log.Printf("[ThreatIntel] initial refresh error: %v", err)
		}

		for {
			select {
			case <-ticker.C:
				if err := t.RefreshAll(); err != nil {
					log.Printf("[ThreatIntel] refresh error: %v", err)
				} else {
					log.Printf("[ThreatIntel] refreshed: %d IOCs from %d feeds",
						t.TotalIOCs, t.TotalFeeds)
				}
			case <-stop:
				return
			}
		}
	}()
}

// Stats returns threat intel statistics.
func (t *ThreatIntelStore) Stats() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return map[string]interface{}{
		"total_iocs":    t.TotalIOCs,
		"total_feeds":   t.TotalFeeds,
		"last_refresh":  t.LastRefresh,
		"matches_found": t.MatchesFound,
		"feeds":         t.feeds,
	}
}

// GetFeeds returns all configured feeds with their status.
func (t *ThreatIntelStore) GetFeeds() []ThreatFeed {
	t.mu.RLock()
	defer t.mu.RUnlock()
	feeds := make([]ThreatFeed, len(t.feeds))
	copy(feeds, t.feeds)
	return feeds
}

// AddDefaultFeeds registers SENTINEL-native threat feeds.
func (t *ThreatIntelStore) AddDefaultFeeds() {
	t.AddFeed(ThreatFeed{
		Name:     "OWASP LLM Top 10",
		Type:     "json",
		Enabled:  false, // Enable when URL configured
		Interval: 24 * time.Hour,
	})
	t.AddFeed(ThreatFeed{
		Name:     "MITRE ATLAS",
		Type:     "stix",
		Enabled:  false,
		Interval: 12 * time.Hour,
	})
	t.AddFeed(ThreatFeed{
		Name:     "SENTINEL Community IOCs",
		Type:     "json",
		Enabled:  false,
		Interval: 1 * time.Hour,
	})
}
