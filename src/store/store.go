// Package store persists settings, blocklist metadata, custom rules and the
// query log in an embedded SQLite database (pure Go, no CGO required).
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"sinkhole/src/config"
	"sinkhole/src/server/filter"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blocklists (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	name         TEXT NOT NULL,
	url          TEXT NOT NULL UNIQUE,
	enabled      INTEGER NOT NULL DEFAULT 1,
	rule_count   INTEGER NOT NULL DEFAULT 0,
	last_updated INTEGER NOT NULL DEFAULT 0,
	last_error   TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS custom_rules (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	domain     TEXT NOT NULL,
	action     TEXT NOT NULL CHECK (action IN ('block','allow')),
	subdomains INTEGER NOT NULL DEFAULT 1,
	comment    TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	UNIQUE (domain, action)
);
CREATE TABLE IF NOT EXISTS query_log (
	id         INTEGER PRIMARY KEY,
	ts         INTEGER NOT NULL,
	client     TEXT NOT NULL,
	domain     TEXT NOT NULL,
	qtype      TEXT NOT NULL,
	status     TEXT NOT NULL,
	reason     TEXT NOT NULL DEFAULT '',
	upstream   TEXT NOT NULL DEFAULT '',
	rcode      TEXT NOT NULL DEFAULT '',
	latency_us INTEGER NOT NULL DEFAULT 0,
	cached     INTEGER NOT NULL DEFAULT 0,
	answer     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_query_log_ts ON query_log (ts);
`

// Open opens (and creates / migrates) the database in dataDir.
func Open(dataDir string) (*Store, error) {
	path := filepath.Join(dataDir, "sinkhole.db")
	dsn := "file:" + filepath.ToSlash(path) + "?" + url.Values{
		"_pragma": {"busy_timeout(10000)", "journal_mode(WAL)", "synchronous(NORMAL)", "foreign_keys(ON)"},
	}.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// ---------------------------------------------------------------- settings

// GetSetting returns a raw setting value ("" if missing).
func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting upserts a raw setting value.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// LoadConfig loads the configuration, creating defaults on first run.
func (s *Store) LoadConfig() (config.Config, bool, error) {
	raw, err := s.GetSetting("config")
	if err != nil {
		return config.Config{}, false, err
	}
	if raw == "" {
		cfg := config.Default()
		return cfg, true, s.SaveConfig(cfg)
	}
	cfg := config.Default()
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return cfg, false, fmt.Errorf("decode config: %w", err)
	}
	cfg.Normalize()
	return cfg, false, nil
}

// SaveConfig persists the configuration.
func (s *Store) SaveConfig(cfg config.Config) error {
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return s.SetSetting("config", string(b))
}

// ---------------------------------------------------------------- blocklists

// Blocklist is an upstream list subscription.
type Blocklist struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Enabled     bool   `json:"enabled"`
	RuleCount   int    `json:"rule_count"`
	LastUpdated int64  `json:"last_updated"` // unix ms
	LastError   string `json:"last_error"`
	CreatedAt   int64  `json:"created_at"`
}

// DefaultBlocklists are subscribed on first run.
var DefaultBlocklists = []Blocklist{
	{Name: "AdGuard DNS filter", URL: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", Enabled: true},
	{Name: "StevenBlack Unified hosts", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", Enabled: true},
	{Name: "OISD Small", URL: "https://small.oisd.nl/", Enabled: true},
	{Name: "Perflyst Smart-TV Blocklist (Samsung Tizen, Google TV, LG)", URL: "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt", Enabled: true},
	{Name: "EasyList (browser list, partial DNS coverage)", URL: "https://easylist.to/easylist/easylist.txt", Enabled: false},
}

// SeedDefaults inserts the default blocklists.
func (s *Store) SeedDefaults() error {
	for _, b := range DefaultBlocklists {
		if _, err := s.AddBlocklist(b.Name, b.URL, b.Enabled); err != nil && !strings.Contains(err.Error(), "UNIQUE") {
			return err
		}
	}
	return nil
}

// ListBlocklists returns every list subscription.
func (s *Store) ListBlocklists() ([]Blocklist, error) {
	rows, err := s.db.Query(`SELECT id, name, url, enabled, rule_count, last_updated, last_error, created_at
		FROM blocklists ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Blocklist{}
	for rows.Next() {
		var b Blocklist
		if err := rows.Scan(&b.ID, &b.Name, &b.URL, &b.Enabled, &b.RuleCount, &b.LastUpdated, &b.LastError, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// GetBlocklist returns one list.
func (s *Store) GetBlocklist(id int64) (Blocklist, error) {
	var b Blocklist
	err := s.db.QueryRow(`SELECT id, name, url, enabled, rule_count, last_updated, last_error, created_at
		FROM blocklists WHERE id = ?`, id).
		Scan(&b.ID, &b.Name, &b.URL, &b.Enabled, &b.RuleCount, &b.LastUpdated, &b.LastError, &b.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return b, ErrNotFound
	}
	return b, err
}

// AddBlocklist inserts a list subscription.
func (s *Store) AddBlocklist(name, rawURL string, enabled bool) (Blocklist, error) {
	res, err := s.db.Exec(`INSERT INTO blocklists (name, url, enabled, created_at) VALUES (?, ?, ?, ?)`,
		name, rawURL, enabled, time.Now().UnixMilli())
	if err != nil {
		return Blocklist{}, err
	}
	id, _ := res.LastInsertId()
	return s.GetBlocklist(id)
}

// UpdateBlocklist changes the name and enabled flag.
func (s *Store) UpdateBlocklist(id int64, name string, enabled bool) error {
	res, err := s.db.Exec(`UPDATE blocklists SET name = ?, enabled = ? WHERE id = ?`, name, enabled, id)
	return affected(res, err)
}

// SetBlocklistResult records the outcome of a download.
func (s *Store) SetBlocklistResult(id int64, rules int, updated int64, lastErr string) error {
	if lastErr != "" {
		_, err := s.db.Exec(`UPDATE blocklists SET last_error = ? WHERE id = ?`, lastErr, id)
		return err
	}
	_, err := s.db.Exec(`UPDATE blocklists SET rule_count = ?, last_updated = ?, last_error = '' WHERE id = ?`,
		rules, updated, id)
	return err
}

// SetBlocklistRuleCount records the parsed rule count without touching timestamps.
func (s *Store) SetBlocklistRuleCount(id int64, rules int) error {
	_, err := s.db.Exec(`UPDATE blocklists SET rule_count = ? WHERE id = ?`, rules, id)
	return err
}

// DeleteBlocklist removes a subscription.
func (s *Store) DeleteBlocklist(id int64) error {
	res, err := s.db.Exec(`DELETE FROM blocklists WHERE id = ?`, id)
	return affected(res, err)
}

// ---------------------------------------------------------------- custom rules

// ListRules returns all custom rules.
func (s *Store) ListRules() ([]filter.CustomRule, error) {
	rows, err := s.db.Query(`SELECT id, domain, action, subdomains, comment, created_at FROM custom_rules ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []filter.CustomRule{}
	for rows.Next() {
		var r filter.CustomRule
		if err := rows.Scan(&r.ID, &r.Domain, &r.Action, &r.Subdomains, &r.Comment, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddRule inserts or updates a custom rule (unique per domain + action).
func (s *Store) AddRule(r filter.CustomRule) (filter.CustomRule, error) {
	r.CreatedAt = time.Now().UnixMilli()
	tx, err := s.db.Begin()
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	// A domain is either blocked or allowed, never both.
	if _, err := tx.Exec(`DELETE FROM custom_rules WHERE domain = ? AND action <> ?`, r.Domain, r.Action); err != nil {
		return r, err
	}
	err = tx.QueryRow(`INSERT INTO custom_rules (domain, action, subdomains, comment, created_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(domain, action) DO UPDATE SET subdomains = excluded.subdomains, comment = excluded.comment
		RETURNING id, created_at`,
		r.Domain, r.Action, r.Subdomains, r.Comment, r.CreatedAt).Scan(&r.ID, &r.CreatedAt)
	if err != nil {
		return r, err
	}
	return r, tx.Commit()
}

// DeleteRule removes a custom rule.
func (s *Store) DeleteRule(id int64) error {
	res, err := s.db.Exec(`DELETE FROM custom_rules WHERE id = ?`, id)
	return affected(res, err)
}

// ---------------------------------------------------------------- query log

// QueryEntry is one logged DNS query.
type QueryEntry struct {
	ID        int64  `json:"id"`
	TS        int64  `json:"ts"` // unix ms
	Client    string `json:"client"`
	Domain    string `json:"domain"`
	QType     string `json:"qtype"`
	Status    string `json:"status"` // allowed | blocked | error
	Reason    string `json:"reason"`
	Upstream  string `json:"upstream"`
	RCode     string `json:"rcode"`
	LatencyUs int64  `json:"latency_us"`
	Cached    bool   `json:"cached"`
	Answer    string `json:"answer"`
}

// InsertQueries writes a batch in a single transaction.
func (s *Store) InsertQueries(batch []QueryEntry) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO query_log (ts, client, domain, qtype, status, reason, upstream, rcode, latency_us, cached, answer)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, q := range batch {
		if _, err := stmt.Exec(q.TS, q.Client, q.Domain, q.QType, q.Status, q.Reason, q.Upstream, q.RCode,
			q.LatencyUs, q.Cached, q.Answer); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// QueryFilter selects log rows.
type QueryFilter struct {
	Search   string // substring of domain or client
	Status   string // allowed | blocked | cached | error | ""
	BeforeID int64
	Limit    int
}

// QueryLog returns the newest matching rows.
func (s *Store) QueryLog(ctx context.Context, f QueryFilter) ([]QueryEntry, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	var where []string
	var args []any
	if f.BeforeID > 0 {
		where = append(where, "id < ?")
		args = append(args, f.BeforeID)
	}
	if f.Search != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(f.Search)) + "%"
		where = append(where, `(domain LIKE ? ESCAPE '\' OR client LIKE ? ESCAPE '\')`)
		args = append(args, like, like)
	}
	switch f.Status {
	case "allowed", "blocked", "error":
		where = append(where, "status = ?")
		args = append(args, f.Status)
	case "cached":
		where = append(where, "cached = 1")
	}
	q := `SELECT id, ts, client, domain, qtype, status, reason, upstream, rcode, latency_us, cached, answer FROM query_log`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, f.Limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []QueryEntry{}
	for rows.Next() {
		var e QueryEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Client, &e.Domain, &e.QType, &e.Status, &e.Reason, &e.Upstream,
			&e.RCode, &e.LatencyUs, &e.Cached, &e.Answer); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneQueries deletes rows older than before (unix ms).
func (s *Store) PruneQueries(before int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM query_log WHERE ts < ?`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ClearQueries deletes the entire query log.
func (s *Store) ClearQueries() error {
	_, err := s.db.Exec(`DELETE FROM query_log`)
	return err
}

// ---------------------------------------------------------------- stats bootstrap

// Aggregate holds counters restored from the log at startup.
type Aggregate struct {
	Total, Blocked, Cached, LatencyUs, Upstreamed int64
	Domains, BlockedDomains, Clients map[string]int64
	Hours map[int64][2]int64 // hour (unix) -> {total, blocked}
}

// AggregateSince computes counters for rows with ts >= since (unix ms).
func (s *Store) AggregateSince(since, hoursSince int64) (Aggregate, error) {
	a := Aggregate{Domains: map[string]int64{}, BlockedDomains: map[string]int64{}, Clients: map[string]int64{}, Hours: map[int64][2]int64{}}
	err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(status = 'blocked'),0), COALESCE(SUM(cached),0),
		COALESCE(SUM(CASE WHEN status='allowed' AND cached=0 AND upstream<>'' THEN latency_us ELSE 0 END),0),
		COALESCE(SUM(status='allowed' AND cached=0 AND upstream<>''),0)
		FROM query_log WHERE ts >= ?`, since).Scan(&a.Total, &a.Blocked, &a.Cached, &a.LatencyUs, &a.Upstreamed)
	if err != nil {
		return a, err
	}
	rows, err := s.db.Query(`SELECT domain, COUNT(*), SUM(status = 'blocked') FROM query_log WHERE ts >= ? GROUP BY domain`, since)
	if err != nil {
		return a, err
	}
	for rows.Next() {
		var d string
		var n, b int64
		if err := rows.Scan(&d, &n, &b); err != nil {
			rows.Close()
			return a, err
		}
		a.Domains[d] = n
		if b > 0 {
			a.BlockedDomains[d] = b
		}
	}
	rows.Close()
	rows, err = s.db.Query(`SELECT client, COUNT(*) FROM query_log WHERE ts >= ? GROUP BY client`, since)
	if err != nil {
		return a, err
	}
	for rows.Next() {
		var c string
		var n int64
		if err := rows.Scan(&c, &n); err != nil {
			rows.Close()
			return a, err
		}
		a.Clients[c] = n
	}
	rows.Close()
	rows, err = s.db.Query(`SELECT ts / 3600000, COUNT(*), SUM(status = 'blocked') FROM query_log WHERE ts >= ? GROUP BY 1`, hoursSince)
	if err != nil {
		return a, err
	}
	defer rows.Close()
	for rows.Next() {
		var h, n, b int64
		if err := rows.Scan(&h, &n, &b); err != nil {
			return a, err
		}
		a.Hours[h*3600] = [2]int64{n, b}
	}
	return a, rows.Err()
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
