// Package stats keeps live in-memory telemetry for the dashboard. Counters for
// "today" (since local midnight) are restored from the query log at startup,
// so restarts do not reset the overview.
package stats

import (
	"sort"
	"sync"
	"time"

	"sinkhole/src/store"
)

// maxKeys bounds per-day maps so a flood of random names cannot exhaust RAM.
const maxKeys = 250_000

// Stats is safe for concurrent use.
type Stats struct {
	mu             sync.Mutex
	dayStart       time.Time
	total          int64
	blocked        int64
	cached         int64
	errors         int64
	latencySum     int64 // upstream latency (µs) of forwarded queries
	upstreamed     int64
	domains        map[string]int64
	blockedDomains map[string]int64
	clients        map[string]int64
	hours          map[int64]*[2]int64 // hour start (unix s) -> {total, blocked}
	started        time.Time
}

// New returns empty stats.
func New() *Stats {
	s := &Stats{started: time.Now()}
	s.resetDay(time.Now())
	s.hours = map[int64]*[2]int64{}
	return s
}

// DayStart returns local midnight for t.
func DayStart(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

func (s *Stats) resetDay(now time.Time) {
	s.dayStart = DayStart(now)
	s.total, s.blocked, s.cached, s.errors, s.latencySum, s.upstreamed = 0, 0, 0, 0, 0, 0
	s.domains = map[string]int64{}
	s.blockedDomains = map[string]int64{}
	s.clients = map[string]int64{}
}

// Restore seeds counters from an aggregate of the persisted log.
func (s *Stats) Restore(a store.Aggregate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total, s.blocked, s.cached = a.Total, a.Blocked, a.Cached
	s.latencySum, s.upstreamed = a.LatencyUs, a.Upstreamed
	s.domains, s.blockedDomains, s.clients = a.Domains, a.BlockedDomains, a.Clients
	for h, v := range a.Hours {
		s.hours[h] = &[2]int64{v[0], v[1]}
	}
}

func bump(m map[string]int64, k string) {
	if _, ok := m[k]; ok || len(m) < maxKeys {
		m[k]++
	}
}

// Record accounts for one query.
func (s *Stats) Record(e store.QueryEntry) {
	t := time.UnixMilli(e.TS)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !t.Before(s.dayStart.AddDate(0, 0, 1)) {
		s.resetDay(t)
	}
	s.total++
	isBlocked := e.Status == "blocked"
	switch {
	case isBlocked:
		s.blocked++
		bump(s.blockedDomains, e.Domain)
	case e.Status == "error":
		s.errors++
	}
	if e.Cached {
		s.cached++
	} else if e.Status == "allowed" && e.Upstream != "" {
		s.upstreamed++
		s.latencySum += e.LatencyUs
	}
	bump(s.domains, e.Domain)
	bump(s.clients, e.Client)

	h := t.Unix() / 3600 * 3600
	b, ok := s.hours[h]
	if !ok {
		b = &[2]int64{}
		s.hours[h] = b
		cutoff := h - 24*3600
		for k := range s.hours {
			if k <= cutoff {
				delete(s.hours, k)
			}
		}
	}
	b[0]++
	if isBlocked {
		b[1]++
	}
}

// Counters is the cheap subset streamed to the dashboard every second.
type Counters struct {
	Total        int64   `json:"total"`
	Blocked      int64   `json:"blocked"`
	Cached       int64   `json:"cached"`
	Errors       int64   `json:"errors"`
	BlockedPct   float64 `json:"blocked_pct"`
	AvgLatencyMs float64 `json:"avg_upstream_ms"`
	UptimeSec    int64   `json:"uptime_sec"`
}

// Counters returns today's counters.
func (s *Stats) Counters() Counters {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Now().After(s.dayStart.AddDate(0, 0, 1)) {
		s.resetDay(time.Now())
	}
	c := Counters{Total: s.total, Blocked: s.blocked, Cached: s.cached, Errors: s.errors,
		UptimeSec: int64(time.Since(s.started).Seconds())}
	if s.total > 0 {
		c.BlockedPct = float64(s.blocked) * 100 / float64(s.total)
	}
	if s.upstreamed > 0 {
		c.AvgLatencyMs = float64(s.latencySum) / float64(s.upstreamed) / 1000
	}
	return c
}

// Entry is a ranked key/count pair.
type Entry struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// Hour is one bar of the 24h histogram.
type Hour struct {
	TS      int64 `json:"ts"` // unix seconds
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
}

// Snapshot is the full overview payload.
type Snapshot struct {
	Counters
	TopDomains []Entry `json:"top_domains"`
	TopBlocked []Entry `json:"top_blocked"`
	TopClients []Entry `json:"top_clients"`
	Hours      []Hour  `json:"hours"`
}

// Snapshot builds the overview with top-n rankings.
func (s *Stats) Snapshot(n int) Snapshot {
	c := s.Counters()
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := Snapshot{
		Counters:   c,
		TopDomains: top(s.domains, n),
		TopBlocked: top(s.blockedDomains, n),
		TopClients: top(s.clients, n),
	}
	now := time.Now().Unix() / 3600 * 3600
	for h := now - 23*3600; h <= now; h += 3600 {
		hr := Hour{TS: h}
		if b, ok := s.hours[h]; ok {
			hr.Total, hr.Blocked = b[0], b[1]
		}
		snap.Hours = append(snap.Hours, hr)
	}
	return snap
}

func top(m map[string]int64, n int) []Entry {
	out := make([]Entry, 0, len(m))
	for k, v := range m {
		out = append(out, Entry{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
