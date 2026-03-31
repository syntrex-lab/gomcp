// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

// Package soc provides SOC analytics: event trends, severity distribution,
// top sources, MITRE ATT&CK coverage, and time-series aggregation.
package soc

import (
	"sort"
	"time"

	domsoc "github.com/syntrex-lab/gomcp/internal/domain/soc"
)

// ─── Analytics Types ──────────────────────────────────────

// TimeSeriesPoint represents a single data point in time series.
type TimeSeriesPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Count     int       `json:"count"`
}

// SeverityDistribution counts events by severity.
type SeverityDistribution struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// SourceBreakdown counts events per source.
type SourceBreakdown struct {
	Source string `json:"source"`
	Count  int    `json:"count"`
}

// CategoryBreakdown counts events per category.
type CategoryBreakdown struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}

// IncidentTimeline shows incident trend.
type IncidentTimeline struct {
	Created  []TimeSeriesPoint `json:"created"`
	Resolved []TimeSeriesPoint `json:"resolved"`
}

// AnalyticsReport is the full SOC analytics output.
type AnalyticsReport struct {
	GeneratedAt time.Time `json:"generated_at"`
	TimeRange   struct {
		From time.Time `json:"from"`
		To   time.Time `json:"to"`
	} `json:"time_range"`

	// Event analytics
	EventTrend           []TimeSeriesPoint    `json:"event_trend"`
	SeverityDistribution SeverityDistribution `json:"severity_distribution"`
	TopSources           []SourceBreakdown    `json:"top_sources"`
	TopCategories        []CategoryBreakdown  `json:"top_categories"`

	// Incident analytics
	IncidentTimeline IncidentTimeline `json:"incident_timeline"`
	MTTR             float64          `json:"mttr_hours"` // Mean Time to Resolve

	// Derived KPIs
	EventsPerHour float64 `json:"events_per_hour"`
	IncidentRate  float64 `json:"incident_rate"` // incidents / 100 events
}

// ─── Analytics Functions ──────────────────────────────────

// GenerateReport builds a full analytics report from events and incidents.
func GenerateReport(events []domsoc.SOCEvent, incidents []domsoc.Incident, windowHours int) *AnalyticsReport {
	if windowHours <= 0 {
		windowHours = 24
	}

	now := time.Now()
	windowStart := now.Add(-time.Duration(windowHours) * time.Hour)

	report := &AnalyticsReport{
		GeneratedAt: now,
	}
	report.TimeRange.From = windowStart
	report.TimeRange.To = now

	// Filter events within window
	var windowEvents []domsoc.SOCEvent
	for _, e := range events {
		if e.Timestamp.After(windowStart) {
			windowEvents = append(windowEvents, e)
		}
	}

	// Severity distribution
	report.SeverityDistribution = calcSeverityDist(windowEvents)

	// Event trend (hourly buckets)
	report.EventTrend = calcEventTrend(windowEvents, windowStart, now)

	// Top sources
	report.TopSources = calcTopSources(windowEvents, 10)

	// Top categories
	report.TopCategories = calcTopCategories(windowEvents, 10)

	// Incident timeline
	report.IncidentTimeline = calcIncidentTimeline(incidents, windowStart, now)

	// MTTR
	report.MTTR = calcMTTR(incidents)

	// KPIs
	hours := now.Sub(windowStart).Hours()
	if hours > 0 {
		report.EventsPerHour = float64(len(windowEvents)) / hours
	}
	if len(windowEvents) > 0 {
		report.IncidentRate = float64(len(incidents)) / float64(len(windowEvents)) * 100
	}

	return report
}

// ─── Internal Computations ────────────────────────────────

func calcSeverityDist(events []domsoc.SOCEvent) SeverityDistribution {
	var d SeverityDistribution
	for _, e := range events {
		switch e.Severity {
		case domsoc.SeverityCritical:
			d.Critical++
		case domsoc.SeverityHigh:
			d.High++
		case domsoc.SeverityMedium:
			d.Medium++
		case domsoc.SeverityLow:
			d.Low++
		case domsoc.SeverityInfo:
			d.Info++
		}
	}
	return d
}

func calcEventTrend(events []domsoc.SOCEvent, from, to time.Time) []TimeSeriesPoint {
	hours := int(to.Sub(from).Hours()) + 1
	buckets := make([]int, hours)

	for _, e := range events {
		idx := int(e.Timestamp.Sub(from).Hours())
		if idx >= 0 && idx < len(buckets) {
			buckets[idx]++
		}
	}

	points := make([]TimeSeriesPoint, hours)
	for i := range points {
		points[i] = TimeSeriesPoint{
			Timestamp: from.Add(time.Duration(i) * time.Hour),
			Count:     buckets[i],
		}
	}
	return points
}

func calcTopSources(events []domsoc.SOCEvent, limit int) []SourceBreakdown {
	counts := make(map[string]int)
	for _, e := range events {
		counts[string(e.Source)]++
	}

	result := make([]SourceBreakdown, 0, len(counts))
	for src, cnt := range counts {
		result = append(result, SourceBreakdown{Source: src, Count: cnt})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func calcTopCategories(events []domsoc.SOCEvent, limit int) []CategoryBreakdown {
	counts := make(map[string]int)
	for _, e := range events {
		counts[string(e.Category)]++
	}

	result := make([]CategoryBreakdown, 0, len(counts))
	for cat, cnt := range counts {
		result = append(result, CategoryBreakdown{Category: cat, Count: cnt})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func calcIncidentTimeline(incidents []domsoc.Incident, from, to time.Time) IncidentTimeline {
	hours := int(to.Sub(from).Hours()) + 1
	created := make([]int, hours)
	resolved := make([]int, hours)

	for _, inc := range incidents {
		idx := int(inc.CreatedAt.Sub(from).Hours())
		if idx >= 0 && idx < hours {
			created[idx]++
		}
		if inc.Status == domsoc.StatusResolved {
			ridx := int(inc.UpdatedAt.Sub(from).Hours())
			if ridx >= 0 && ridx < hours {
				resolved[ridx]++
			}
		}
	}

	timeline := IncidentTimeline{
		Created:  make([]TimeSeriesPoint, hours),
		Resolved: make([]TimeSeriesPoint, hours),
	}
	for i := range timeline.Created {
		t := from.Add(time.Duration(i) * time.Hour)
		timeline.Created[i] = TimeSeriesPoint{Timestamp: t, Count: created[i]}
		timeline.Resolved[i] = TimeSeriesPoint{Timestamp: t, Count: resolved[i]}
	}
	return timeline
}

func calcMTTR(incidents []domsoc.Incident) float64 {
	var total float64
	var count int
	for _, inc := range incidents {
		if inc.Status == domsoc.StatusResolved && !inc.UpdatedAt.IsZero() {
			duration := inc.UpdatedAt.Sub(inc.CreatedAt).Hours()
			if duration > 0 {
				total += duration
				count++
			}
		}
	}
	if count == 0 {
		return 0
	}
	return total / float64(count)
}
