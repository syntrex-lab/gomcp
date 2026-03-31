// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

package soc

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// STIXBundle represents a STIX 2.1 bundle (simplified).
type STIXBundle struct {
	Type    string       `json:"type"` // "bundle"
	ID      string       `json:"id"`
	Objects []STIXObject `json:"objects"`
}

// STIXObject represents a generic STIX 2.1 object.
type STIXObject struct {
	Type        string    `json:"type"` // indicator, malware, attack-pattern, etc.
	ID          string    `json:"id"`
	Created     time.Time `json:"created"`
	Modified    time.Time `json:"modified"`
	Name        string    `json:"name,omitempty"`
	Description string    `json:"description,omitempty"`
	Pattern     string    `json:"pattern,omitempty"`      // STIX pattern (indicators)
	PatternType string    `json:"pattern_type,omitempty"` // stix, pcre, sigma
	ValidFrom   time.Time `json:"valid_from,omitempty"`
	Labels      []string  `json:"labels,omitempty"`
	// Kill chain phases for attack-pattern objects.
	KillChainPhases []struct {
		KillChainName string `json:"kill_chain_name"`
		PhaseName     string `json:"phase_name"`
	} `json:"kill_chain_phases,omitempty"`
	// External references (CVE, etc.)
	ExternalReferences []struct {
		SourceName  string `json:"source_name"`
		ExternalID  string `json:"external_id,omitempty"`
		URL         string `json:"url,omitempty"`
		Description string `json:"description,omitempty"`
	} `json:"external_references,omitempty"`
}

// STIXFeedConfig configures automatic STIX feed polling.
type STIXFeedConfig struct {
	Name     string            `json:"name"`     // Feed name (e.g., "OTX", "MISP")
	URL      string            `json:"url"`      // TAXII or HTTP feed URL
	APIKey   string            `json:"api_key"`  // Authentication key
	Headers  map[string]string `json:"headers"`  // Additional headers
	Interval time.Duration     `json:"interval"` // Poll interval (default: 1h)
	Enabled  bool              `json:"enabled"`
}

// FeedSync syncs IOCs from STIX/TAXII feeds into the ThreatIntelStore.
type FeedSync struct {
	feeds  []STIXFeedConfig
	store  *ThreatIntelStore
	client *http.Client
}

// NewFeedSync creates a feed synchronizer.
func NewFeedSync(store *ThreatIntelStore, feeds []STIXFeedConfig) *FeedSync {
	return &FeedSync{
		feeds: feeds,
		store: store,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Start begins polling all enabled feeds in the background.
func (f *FeedSync) Start(done <-chan struct{}) {
	for _, feed := range f.feeds {
		if !feed.Enabled {
			continue
		}
		go f.pollFeed(feed, done)
	}
}

// pollFeed periodically fetches and processes a single STIX feed.
func (f *FeedSync) pollFeed(feed STIXFeedConfig, done <-chan struct{}) {
	interval := feed.Interval
	if interval == 0 {
		interval = time.Hour
	}

	slog.Info("stix feed started", "feed", feed.Name, "url", feed.URL, "interval", interval)

	// Initial fetch.
	f.fetchFeed(feed)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			slog.Info("stix feed stopped", "feed", feed.Name)
			return
		case <-ticker.C:
			f.fetchFeed(feed)
		}
	}
}

// fetchFeed performs a single HTTP GET and processes the STIX bundle.
func (f *FeedSync) fetchFeed(feed STIXFeedConfig) {
	req, err := http.NewRequest(http.MethodGet, feed.URL, nil)
	if err != nil {
		slog.Error("stix feed: request error", "feed", feed.Name, "error", err)
		return
	}

	req.Header.Set("Accept", "application/stix+json;version=2.1")
	if feed.APIKey != "" {
		req.Header.Set("X-OTX-API-KEY", feed.APIKey)
	}
	for k, v := range feed.Headers {
		req.Header.Set(k, v)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		slog.Error("stix feed: fetch error", "feed", feed.Name, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("stix feed: non-200 response", "feed", feed.Name, "status", resp.StatusCode)
		return
	}

	var bundle STIXBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		slog.Error("stix feed: decode error", "feed", feed.Name, "error", err)
		return
	}

	imported := f.processBundle(feed.Name, bundle)
	slog.Info("stix feed synced",
		"feed", feed.Name,
		"objects", len(bundle.Objects),
		"iocs_imported", imported,
	)
}

// processBundle extracts IOCs from STIX indicators and adds to the store.
func (f *FeedSync) processBundle(feedName string, bundle STIXBundle) int {
	imported := 0
	for _, obj := range bundle.Objects {
		if obj.Type != "indicator" || obj.Pattern == "" {
			continue
		}

		ioc := stixPatternToIOC(obj)
		if ioc == nil {
			continue
		}
		ioc.Source = feedName
		ioc.Tags = obj.Labels

		f.store.AddIOC(*ioc)
		imported++
	}
	return imported
}

// stixPatternToIOC converts a STIX indicator pattern to our IOC format.
// Supports: [file:hashes.'SHA-256' = '...'], [ipv4-addr:value = '...'],
// [domain-name:value = '...'], [url:value = '...']
func stixPatternToIOC(obj STIXObject) *IOC {
	pattern := obj.Pattern
	now := obj.Modified
	if now.IsZero() {
		now = obj.Created
	}
	ioc := &IOC{
		Value:      "",
		Severity:   "medium",
		FirstSeen:  now,
		LastSeen:   now,
		Confidence: 0.7,
	}

	switch {
	case strings.Contains(pattern, "file:hashes"):
		ioc.Type = IOCTypeHash
		ioc.Value = extractSTIXValue(pattern)
	case strings.Contains(pattern, "ipv4-addr:value"):
		ioc.Type = IOCTypeIP
		ioc.Value = extractSTIXValue(pattern)
	case strings.Contains(pattern, "domain-name:value"):
		ioc.Type = IOCTypeDomain
		ioc.Value = extractSTIXValue(pattern)
	case strings.Contains(pattern, "url:value"):
		ioc.Type = IOCTypeURL
		ioc.Value = extractSTIXValue(pattern)
	default:
		return nil
	}

	if ioc.Value == "" {
		return nil
	}

	// Derive severity from STIX labels.
	for _, label := range obj.Labels {
		switch {
		case strings.Contains(label, "anomalous-activity"):
			ioc.Severity = "low"
		case strings.Contains(label, "malicious-activity"):
			ioc.Severity = "critical"
		case strings.Contains(label, "attribution"):
			ioc.Severity = "high"
		}
	}

	return ioc
}

// extractSTIXValue pulls the quoted value from a STIX pattern like:
// [ipv4-addr:value = '192.168.1.1']
// [file:hashes.'SHA-256' = 'e3b0c44...']
func extractSTIXValue(pattern string) string {
	// Anchor on "= '" to skip any earlier quotes (e.g., hashes.'SHA-256').
	eqIdx := strings.Index(pattern, "= '")
	if eqIdx < 0 {
		return ""
	}
	start := eqIdx + 3 // skip "= '"
	end := strings.Index(pattern[start:], "'")
	if end < 0 {
		return ""
	}
	return pattern[start : start+end]
}

// DefaultOTXFeed returns a pre-configured AlienVault OTX feed config.
func DefaultOTXFeed(apiKey string) STIXFeedConfig {
	return STIXFeedConfig{
		Name:     "AlienVault OTX",
		URL:      "https://otx.alienvault.com/api/v1/pulses/subscribed",
		APIKey:   apiKey,
		Interval: time.Hour,
		Enabled:  apiKey != "",
		Headers: map[string]string{
			"X-OTX-API-KEY": apiKey,
		},
	}
}

// IOC type is defined in threat_intel.go — this file uses it directly.
