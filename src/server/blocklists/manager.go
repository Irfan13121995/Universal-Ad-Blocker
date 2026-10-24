// Package blocklists downloads, caches and compiles blocklist subscriptions
// into the in-memory filter engine.
package blocklists

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sinkhole/src/server/filter"
	"sinkhole/src/server/upstream"
	"sinkhole/src/store"
)

const maxListSize = 150 << 20 // 150 MiB

// Manager owns the blocklist lifecycle.
type Manager struct {
	st     *store.Store
	engine *filter.Engine
	dir    string
	client *http.Client
	log    *slog.Logger

	mu        sync.Mutex // serialises downloads and rebuilds
	updating  atomic.Bool
	lastBuild atomic.Int64 // unix ms
	buildMs   atomic.Int64
}

// New creates a manager storing list files in dataDir/lists.
func New(st *store.Store, engine *filter.Engine, dataDir string, boot *upstream.Bootstrap, log *slog.Logger) (*Manager, error) {
	dir := filepath.Join(dataDir, "lists")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           boot.DialContext(true),
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}
	return &Manager{
		st: st, engine: engine, dir: dir, log: log,
		client: &http.Client{Transport: tr, Timeout: 3 * time.Minute},
	}, nil
}

// Status describes the manager state.
type Status struct {
	Updating    bool  `json:"updating"`
	LastBuild   int64 `json:"last_build"`
	BuildMs     int64 `json:"build_ms"`
	ListRules   int   `json:"list_rules"`
	CustomRules int   `json:"custom_rules"`
}

// Status returns the current state.
func (m *Manager) Status() Status {
	return Status{
		Updating:    m.updating.Load(),
		LastBuild:   m.lastBuild.Load(),
		BuildMs:     m.buildMs.Load(),
		ListRules:   m.engine.ListRuleCount(),
		CustomRules: m.engine.CustomRuleCount(),
	}
}

func (m *Manager) path(id int64) string { return filepath.Join(m.dir, fmt.Sprintf("%d.txt", id)) }

// Rebuild compiles every enabled, downloaded list into a new snapshot and
// swaps it into the engine atomically (queries are never blocked).
func (m *Manager) Rebuild() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rebuildLocked()
}

func (m *Manager) rebuildLocked() error {
	start := time.Now()
	lists, err := m.st.ListBlocklists()
	if err != nil {
		return err
	}
	b := filter.NewBuilder(m.engine.ListRuleCount() + 1024)
	for _, bl := range lists {
		if !bl.Enabled {
			continue
		}
		f, err := os.Open(m.path(bl.ID))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				m.log.Warn("cannot open cached list", "list", bl.Name, "err", err)
			}
			continue
		}
		id := uint32(bl.ID)
		b.SetListName(id, bl.Name)
		st, err := filter.Parse(f, func(r filter.Rule) { b.Add(id, r) })
		f.Close()
		if err != nil {
			m.log.Warn("parse list failed", "list", bl.Name, "err", err)
			continue
		}
		if st.Rules != bl.RuleCount {
			_ = m.st.SetBlocklistRuleCount(bl.ID, st.Rules)
		}
	}
	ls := b.Build()
	m.engine.SetLists(ls)
	m.lastBuild.Store(time.Now().UnixMilli())
	m.buildMs.Store(time.Since(start).Milliseconds())
	m.log.Info("blocklists compiled", "unique_rules", ls.Size(), "took", time.Since(start).Round(time.Millisecond))
	debug.FreeOSMemory() // release the previous snapshot promptly
	return nil
}

// UpdateAll downloads enabled lists (stale ones, or all when force) and rebuilds.
func (m *Manager) UpdateAll(ctx context.Context, force bool, maxAge time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updating.Store(true)
	defer m.updating.Store(false)

	lists, err := m.st.ListBlocklists()
	if err != nil {
		return err
	}
	var errs []error
	changed := false
	for _, bl := range lists {
		if !bl.Enabled {
			continue
		}
		_, statErr := os.Stat(m.path(bl.ID))
		stale := maxAge > 0 && time.Since(time.UnixMilli(bl.LastUpdated)) > maxAge
		if !force && statErr == nil && !stale {
			continue
		}
		if err := m.downloadLocked(ctx, bl); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", bl.Name, err))
			continue
		}
		changed = true
	}
	if changed || force {
		if err := m.rebuildLocked(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// UpdateOne downloads a single list and rebuilds.
func (m *Manager) UpdateOne(ctx context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updating.Store(true)
	defer m.updating.Store(false)
	bl, err := m.st.GetBlocklist(id)
	if err != nil {
		return err
	}
	if err := m.downloadLocked(ctx, bl); err != nil {
		return err
	}
	return m.rebuildLocked()
}

// Remove deletes a cached list file and rebuilds.
func (m *Manager) Remove(id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = os.Remove(m.path(id))
	return m.rebuildLocked()
}

func (m *Manager) downloadLocked(ctx context.Context, bl store.Blocklist) (err error) {
	start := time.Now()
	defer func() {
		if err != nil {
			m.log.Warn("blocklist download failed", "list", bl.Name, "url", bl.URL, "err", err)
			_ = m.st.SetBlocklistResult(bl.ID, 0, 0, err.Error())
		}
	}()
	src, err := m.open(ctx, bl.URL)
	if err != nil {
		return err
	}
	defer src.Close()

	tmp, err := os.CreateTemp(m.dir, "dl-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(src, maxListSize+1))
	if err != nil {
		tmp.Close()
		return err
	}
	if n > maxListSize {
		tmp.Close()
		return fmt.Errorf("list exceeds %d MiB", maxListSize>>20)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		tmp.Close()
		return err
	}
	st, err := filter.Parse(tmp, func(filter.Rule) {})
	tmp.Close()
	if err != nil {
		return err
	}
	if st.Rules == 0 {
		return errors.New("no valid DNS rules found (is this a hosts / AdBlock / domain list?)")
	}
	if err := os.Rename(tmp.Name(), m.path(bl.ID)); err != nil {
		// Windows cannot rename over an open file; retry after removing.
		_ = os.Remove(m.path(bl.ID))
		if err := os.Rename(tmp.Name(), m.path(bl.ID)); err != nil {
			return err
		}
	}
	m.log.Info("blocklist downloaded", "list", bl.Name, "rules", st.Rules, "bytes", n, "took", time.Since(start).Round(time.Millisecond))
	return m.st.SetBlocklistResult(bl.ID, st.Rules, time.Now().UnixMilli(), "")
}

func (m *Manager) open(ctx context.Context, raw string) (io.ReadCloser, error) {
	u, err := url.Parse(raw)
	if err == nil && u.Scheme == "file" {
		p := u.Path
		if u.Host != "" {
			p = "//" + u.Host + p
		}
		return os.Open(filepath.FromSlash(strings.TrimPrefix(p, "/")))
	}
	if filepath.IsAbs(raw) {
		return os.Open(raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Sinkhole/1.0 (+Windows DNS sinkhole)")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// ValidateURL checks that a list URL is http(s), file:// or an absolute path.
func ValidateURL(raw string) error {
	if filepath.IsAbs(raw) {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "http", "https":
		if u.Host == "" {
			return errors.New("URL has no host")
		}
		return nil
	case "file":
		return nil
	}
	return errors.New("URL must start with http://, https:// or file://")
}

// RunScheduler downloads missing lists shortly after start and refreshes stale
// lists according to intervalHours (0 disables periodic refreshes).
func (m *Manager) RunScheduler(ctx context.Context, intervalHours func() int) {
	select {
	case <-time.After(5 * time.Second):
	case <-ctx.Done():
		return
	}
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		maxAge := time.Duration(intervalHours()) * time.Hour
		if err := m.UpdateAll(ctx, false, maxAge); err != nil && ctx.Err() == nil {
			m.log.Warn("scheduled blocklist update had errors", "err", err)
		}
		select {
		case <-t.C:
		case <-ctx.Done():
			return
		}
	}
}
