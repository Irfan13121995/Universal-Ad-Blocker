// Package web serves the admin dashboard (embedded static files) and its JSON
// API on the configured address (default http://127.0.0.1:3002).
package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sinkhole/src/config"
	"sinkhole/src/server/blocklists"
	"sinkhole/src/server/ca"
	"sinkhole/src/server/cache"
	"sinkhole/src/server/content"
	"sinkhole/src/server/filter"
	"sinkhole/src/server/proxy"
	"sinkhole/src/server/stats"
	"sinkhole/src/server/tvshield"
	"sinkhole/src/server/upstream"
	"sinkhole/src/store"
	"sinkhole/src/system"
)

//go:embed static
var staticFS embed.FS

// Deps are the components the API operates on. Callbacks avoid an import
// cycle with the app package.
type Deps struct {
	Log     *slog.Logger
	Store   *store.Store
	Engine  *filter.Engine
	Stats   *stats.Stats
	Lists   *blocklists.Manager
	Cache   *cache.Cache
	Boot    *upstream.Bootstrap
	Hub     *Hub
	Version string
	DataDir string
	Started time.Time

	CA       *ca.CA
	Cosmetic *content.CosmeticEngine
	Proxy    *proxy.Proxy
	TVShield *tvshield.Manager

	Config      func() config.Config
	ApplyConfig func(config.Config) (restartRequired bool, err error)
	DNSBound    func() []string
	ReloadRules func() error
	BgCtx       context.Context
}

// Server is the dashboard HTTP server.
type Server struct {
	d    Deps
	srv  *http.Server
	host string // lower-case machine name for Host header checks
}

// New creates the server.
func New(d Deps) *Server {
	h, _ := os.Hostname()
	return &Server{d: d, host: strings.ToLower(h)}
}

// Start listens on addr in the background.
func (s *Server) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.srv = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.d.Log.Error("dashboard server stopped", "err", err)
		}
	}()
	s.d.Log.Info("dashboard listening", "url", "http://"+ln.Addr().String())
	return nil
}

// Stop shuts the server down.
func (s *Server) Stop(ctx context.Context) {
	if s.srv != nil {
		_ = s.srv.Shutdown(ctx)
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /", http.FileServerFS(sub))

	mux.HandleFunc("GET /api/status", s.status)
	mux.HandleFunc("GET /api/stats", s.statsHandler)
	mux.Handle("GET /api/events", s.d.Hub)
	mux.HandleFunc("GET /api/querylog", s.queryLog)
	mux.HandleFunc("DELETE /api/querylog", s.clearQueryLog)

	mux.HandleFunc("GET /api/blocklists", s.listBlocklists)
	mux.HandleFunc("POST /api/blocklists", s.addBlocklist)
	mux.HandleFunc("PATCH /api/blocklists/{id}", s.patchBlocklist)
	mux.HandleFunc("DELETE /api/blocklists/{id}", s.deleteBlocklist)
	mux.HandleFunc("POST /api/blocklists/{id}/update", s.updateBlocklist)
	mux.HandleFunc("POST /api/blocklists/update", s.updateAll)

	mux.HandleFunc("GET /api/rules", s.listRules)
	mux.HandleFunc("POST /api/rules", s.addRule)
	mux.HandleFunc("DELETE /api/rules/{id}", s.deleteRule)
	mux.HandleFunc("GET /api/check", s.check)

	mux.HandleFunc("GET /api/settings", s.getSettings)
	mux.HandleFunc("PUT /api/settings", s.putSettings)
	mux.HandleFunc("POST /api/protection", s.setProtection)
	mux.HandleFunc("POST /api/cache/flush", s.flushCache)
	mux.HandleFunc("POST /api/upstreams/test", s.testUpstream)
	mux.HandleFunc("POST /api/password", s.setPassword)

	mux.HandleFunc("GET /api/system/adapters", s.adapters)
	mux.HandleFunc("POST /api/system/adapters/{index}/sinkhole", s.adapterSinkhole)
	mux.HandleFunc("POST /api/system/adapters/{index}/restore", s.adapterRestore)

	mux.HandleFunc("GET /proxy.pac", s.proxyPAC)
	mux.HandleFunc("GET /api/ca/status", s.caStatus)
	mux.HandleFunc("POST /api/ca/install", s.caInstall)
	mux.HandleFunc("POST /api/ca/uninstall", s.caUninstall)
	mux.HandleFunc("GET /api/ca/cert", s.caDownloadCert)
	mux.HandleFunc("GET /api/proxy/status", s.proxyStatus)
	mux.HandleFunc("POST /api/proxy/enable", s.proxyEnable)
	mux.HandleFunc("POST /api/proxy/disable", s.proxyDisable)
	mux.HandleFunc("GET /api/youtube", s.getYoutube)
	mux.HandleFunc("PUT /api/youtube", s.putYoutube)
	mux.HandleFunc("GET /api/youtube/health", s.getYoutubeHealth)
	mux.HandleFunc("POST /api/youtube/setup", s.postYoutubeSetup)
	mux.HandleFunc("POST /api/youtube/teardown", s.postYoutubeTeardown)
	mux.HandleFunc("GET /api/cosmetic/rules", s.getCosmeticRules)
	mux.HandleFunc("POST /api/cosmetic/rules", s.addCosmeticRule)

	mux.HandleFunc("GET /api/tv/status", s.getTVStatus)
	mux.HandleFunc("PUT /api/tv/config", s.putTVConfig)
	mux.HandleFunc("POST /api/tv/discover", s.postTVDiscover)
	mux.HandleFunc("POST /api/tv/pair", s.postTVPair)
	mux.HandleFunc("PATCH /api/tv/devices/{id}", s.patchTVDevice)
	mux.HandleFunc("DELETE /api/tv/devices/{id}", s.deleteTVDevice)

	return s.middleware(mux)
}

// ---------------------------------------------------------------- middleware

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self' http: https: data:; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src *")

		// CORS support for mobile app (WebView, PWA, LAN clients)
		origin := r.Header.Get("Origin")
		if origin != "" {
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Content-Type, X-Sinkhole, Authorization")
			h.Set("Access-Control-Allow-Credentials", "true")
		} else {
			h.Set("Access-Control-Allow-Origin", "*")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Content-Type, X-Sinkhole, Authorization")
		}

		// Handle preflight OPTIONS requests immediately
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// DNS-rebinding protection: only accept IP literals / local names.
		if !s.allowedHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		// Optional password (HTTP basic auth, any user name).
		if hash, _ := s.d.Store.GetSetting("web_password"); hash != "" {
			_, pw, ok := r.BasicAuth()
			if !ok || !checkPassword(hash, pw) {
				h.Set("WWW-Authenticate", `Basic realm="Sinkhole", charset="UTF-8"`)
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
		}
		// CSRF protection: state-changing calls must carry a custom header,
		// which browsers refuse to send cross-origin without a CORS preflight.
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-Sinkhole") != "1" {
			http.Error(w, "missing X-Sinkhole header", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowedHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "" || net.ParseIP(host) != nil || host == "localhost" {
		return true
	}
	return s.host != "" && (host == s.host || strings.HasPrefix(host, s.host+"."))
}

func hashPassword(pw string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	sum := sha256.Sum256(append(salt, []byte(pw)...))
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(sum[:])
}

func checkPassword(stored, pw string) bool {
	saltHex, sumHex, ok := strings.Cut(stored, ":")
	if !ok {
		return false
	}
	salt, err1 := hex.DecodeString(saltHex)
	want, err2 := hex.DecodeString(sumHex)
	if err1 != nil || err2 != nil {
		return false
	}
	got := sha256.Sum256(append(salt, []byte(pw)...))
	return subtle.ConstantTimeCompare(got[:], want) == 1
}

// SetPasswordHash stores a password (used by the CLI). Empty disables auth.
func SetPasswordHash(st *store.Store, pw string) error {
	if pw == "" {
		return st.SetSetting("web_password", "")
	}
	return st.SetSetting("web_password", hashPassword(pw))
}

// ---------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON body: " + err.Error())
	}
	return nil
}

func pathID(r *http.Request, name string) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid " + name)
	}
	return id, nil
}

func (s *Server) bg(name string, fn func(ctx context.Context) error) {
	go func() {
		ctx, cancel := context.WithTimeout(s.d.BgCtx, 10*time.Minute)
		defer cancel()
		if err := fn(ctx); err != nil {
			s.d.Log.Warn(name+" failed", "err", err)
		}
	}()
}

// ---------------------------------------------------------------- overview

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	cfg := s.d.Config()
	entries, hits, misses := s.d.Cache.Stats()
	pw, _ := s.d.Store.GetSetting("web_password")
	writeJSON(w, http.StatusOK, map[string]any{
		"version":       s.d.Version,
		"started":       s.d.Started.UnixMilli(),
		"dns_bound":     s.d.DNSBound(),
		"web_listen":    cfg.WebListen,
		"protection":    cfg.ProtectionEnabled,
		"lists":         s.d.Lists.Status(),
		"cache":         map[string]int64{"entries": int64(entries), "hits": hits, "misses": misses},
		"data_dir":      s.d.DataDir,
		"password_set":  pw != "",
		"hostname":      s.host,
		"lan_addresses": lanAddresses(),
	})
}

func lanAddresses() []string {
	var out []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && ipn.IP.IsPrivate() {
			out = append(out, ipn.IP.String())
		}
	}
	return out
}

func (s *Server) statsHandler(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("top"))
	if n <= 0 || n > 100 {
		n = 10
	}
	writeJSON(w, http.StatusOK, s.d.Stats.Snapshot(n))
}

func (s *Server) queryLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	rows, err := s.d.Store.QueryLog(r.Context(), store.QueryFilter{
		Search: strings.TrimSpace(q.Get("search")), Status: q.Get("status"), BeforeID: before, Limit: limit,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) clearQueryLog(w http.ResponseWriter, r *http.Request) {
	if err := s.d.Store.ClearQueries(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- blocklists

func (s *Server) listBlocklists(w http.ResponseWriter, r *http.Request) {
	lists, err := s.d.Store.ListBlocklists()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lists": lists, "status": s.d.Lists.Status()})
}

func (s *Server) addBlocklist(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		Enabled *bool  `json:"enabled"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	in.URL, in.Name = strings.TrimSpace(in.URL), strings.TrimSpace(in.Name)
	if err := blocklists.ValidateURL(in.URL); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if in.Name == "" {
		if u, err := url.Parse(in.URL); err == nil && u.Host != "" {
			in.Name = u.Host + u.Path
		} else {
			in.Name = in.URL
		}
	}
	enabled := in.Enabled == nil || *in.Enabled
	bl, err := s.d.Store.AddBlocklist(in.Name, in.URL, enabled)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			err = errors.New("this URL is already subscribed")
		}
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if enabled {
		s.bg("blocklist download", func(ctx context.Context) error { return s.d.Lists.UpdateOne(ctx, bl.ID) })
	}
	writeJSON(w, http.StatusCreated, bl)
}

func (s *Server) patchBlocklist(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	bl, err := s.d.Store.GetBlocklist(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	var in struct {
		Name    *string `json:"name"`
		Enabled *bool   `json:"enabled"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if in.Name != nil && strings.TrimSpace(*in.Name) != "" {
		bl.Name = strings.TrimSpace(*in.Name)
	}
	if in.Enabled != nil {
		bl.Enabled = *in.Enabled
	}
	if err := s.d.Store.UpdateBlocklist(id, bl.Name, bl.Enabled); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.bg("blocklist rebuild", func(ctx context.Context) error {
		// Enabling a list that was never downloaded triggers a download.
		if bl.Enabled {
			if err := s.d.Lists.UpdateAll(ctx, false, 0); err != nil {
				s.d.Log.Warn("blocklist download failed", "err", err)
			}
		}
		return s.d.Lists.Rebuild()
	})
	writeJSON(w, http.StatusOK, bl)
}

func (s *Server) deleteBlocklist(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.d.Store.DeleteBlocklist(id); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	s.bg("blocklist removal", func(context.Context) error { return s.d.Lists.Remove(id) })
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) updateBlocklist(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if _, err := s.d.Store.GetBlocklist(id); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	s.bg("blocklist update", func(ctx context.Context) error { return s.d.Lists.UpdateOne(ctx, id) })
	writeJSON(w, http.StatusAccepted, map[string]bool{"started": true})
}

func (s *Server) updateAll(w http.ResponseWriter, r *http.Request) {
	s.bg("blocklist update", func(ctx context.Context) error { return s.d.Lists.UpdateAll(ctx, true, 0) })
	writeJSON(w, http.StatusAccepted, map[string]bool{"started": true})
}

// ---------------------------------------------------------------- custom rules

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.d.Store.ListRules()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

// ParseRuleInput turns user input into a normalised custom rule domain.
// Accepted: example.com, *.example.com, ||example.com^, @@||example.com^, URLs.
func ParseRuleInput(input string) (domain string, subdomains bool, allow bool, err error) {
	s := strings.TrimSpace(input)
	if strings.HasPrefix(s, "@@") {
		allow, s = true, s[2:]
	}
	if strings.HasPrefix(s, "||") {
		s, subdomains = strings.TrimSuffix(strings.TrimSuffix(s[2:], "|"), "^"), true
	}
	if strings.Contains(s, "://") {
		if u, perr := url.Parse(s); perr == nil && u.Hostname() != "" {
			s = u.Hostname()
		}
	}
	if strings.HasPrefix(s, "*.") {
		s, subdomains = s[2:], true
	}
	d, ok := filter.NormalizeDomain(s, false)
	if !ok {
		return "", false, false, errors.New("invalid domain: " + input)
	}
	return d, subdomains, allow, nil
}

func (s *Server) addRule(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain     string `json:"domain"`
		Action     string `json:"action"`
		Subdomains bool   `json:"subdomains"`
		Comment    string `json:"comment"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	d, sub, allow, err := ParseRuleInput(in.Domain)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if allow {
		in.Action = "allow"
	}
	if in.Action != "allow" && in.Action != "block" {
		writeErr(w, http.StatusBadRequest, errors.New(`action must be "block" or "allow"`))
		return
	}
	if in.Action == "block" {
		low := strings.ToLower(d)
		if low == "youtube.com" || low == "www.youtube.com" || low == "googlevideo.com" || low == "google.com" {
			if !strings.Contains(strings.ToLower(in.Comment), "force") {
				writeErr(w, http.StatusBadRequest, fmt.Errorf("safety check: blocking %s takes the platform offline; use YouTube Shield instead", d))
				return
			}
		}
	}
	rule, err := s.d.Store.AddRule(filter.CustomRule{
		Domain: d, Action: in.Action, Subdomains: in.Subdomains || sub, Comment: strings.TrimSpace(in.Comment),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.d.ReloadRules(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.d.Store.DeleteRule(id); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	if err := s.d.ReloadRules(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	d, _, _, err := ParseRuleInput(r.URL.Query().Get("domain"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	res := s.d.Engine.Match(d)
	writeJSON(w, http.StatusOK, map[string]any{"domain": d, "result": res, "protection": s.d.Config().ProtectionEnabled})
}

// ---------------------------------------------------------------- settings

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.d.Config())
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	cfg := s.d.Config()
	if err := readJSON(r, &cfg); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	restart, err := s.d.ApplyConfig(cfg)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restart_required": restart, "config": s.d.Config()})
}

func (s *Server) setProtection(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	cfg := s.d.Config()
	cfg.ProtectionEnabled = in.Enabled
	if _, err := s.d.ApplyConfig(cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": in.Enabled})
}

func (s *Server) flushCache(w http.ResponseWriter, r *http.Request) {
	s.d.Cache.Flush()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) testUpstream(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Upstream string `json:"upstream"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	d, answer, err := upstream.Test(r.Context(), in.Upstream, s.d.Boot)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "latency_ms": float64(d.Microseconds()) / 1000, "answer": answer})
}

func (s *Server) setPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if in.Password != "" && len(in.Password) < 6 {
		writeErr(w, http.StatusBadRequest, errors.New("password must be at least 6 characters"))
		return
	}
	if err := SetPasswordHash(s.d.Store, in.Password); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"password_set": in.Password != ""})
}

// ---------------------------------------------------------------- adapters

func (s *Server) loadBackups() map[string]system.Backup {
	m := map[string]system.Backup{}
	if raw, _ := s.d.Store.GetSetting("dns_backup"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &m)
	}
	return m
}

func (s *Server) saveBackups(m map[string]system.Backup) error {
	b, _ := json.Marshal(m)
	return s.d.Store.SetSetting("dns_backup", string(b))
}

func (s *Server) adapters(w http.ResponseWriter, r *http.Request) {
	list, err := system.ListAdapters(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	backups := s.loadBackups()
	for i := range list {
		_, list[i].HasBackup = backups[strconv.Itoa(list[i].Index)]
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) findAdapter(ctx context.Context, idx int) (system.Adapter, error) {
	list, err := system.ListAdapters(ctx)
	if err != nil {
		return system.Adapter{}, err
	}
	for _, a := range list {
		if a.Index == idx {
			return a, nil
		}
	}
	return system.Adapter{}, errors.New("adapter not found")
}

func (s *Server) adapterSinkhole(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "index")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	a, err := s.findAdapter(r.Context(), int(id))
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	backups := s.loadBackups()
	key := strconv.Itoa(a.Index)
	if _, ok := backups[key]; !ok && !a.UsesSinkhole {
		backups[key] = system.CaptureBackup(a)
	}
	if err := system.PointToSinkhole(r.Context(), a.Index); err != nil {
		writeErr(w, http.StatusForbidden, err)
		return
	}
	if err := s.saveBackups(backups); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.d.Log.Info("adapter DNS pointed at sinkhole", "adapter", a.Alias)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) adapterRestore(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "index")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	backups := s.loadBackups()
	key := strconv.FormatInt(id, 10)
	var b *system.Backup
	if v, ok := backups[key]; ok {
		b = &v
	}
	if err := system.Restore(r.Context(), int(id), b); err != nil {
		writeErr(w, http.StatusForbidden, err)
		return
	}
	delete(backups, key)
	_ = s.saveBackups(backups)
	s.d.Log.Info("adapter DNS restored", "index", id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- CA & Proxy & YouTube

func (s *Server) proxyPAC(w http.ResponseWriter, r *http.Request) {
	cfg := s.d.Config()
	host, port, _ := net.SplitHostPort(cfg.ProxyListen)
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
        isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) {
        return "DIRECT";
    }
    return "PROXY %s:%s; DIRECT";
}`, host, port)
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	_, _ = w.Write([]byte(pac))
}

func (s *Server) caStatus(w http.ResponseWriter, r *http.Request) {
	if s.d.CA == nil {
		writeJSON(w, http.StatusOK, map[string]any{"generated": false, "trusted": false})
		return
	}
	cert := s.d.CA.RootCertificate()
	if cert == nil {
		writeJSON(w, http.StatusOK, map[string]any{"generated": false, "trusted": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated": true,
		"trusted":   s.d.CA.IsTrusted(),
		"subject":   cert.Subject.CommonName,
		"expires":   cert.NotAfter.UnixMilli(),
		"cert_path": s.d.CA.CertPath(),
	})
}

func (s *Server) caInstall(w http.ResponseWriter, r *http.Request) {
	if s.d.CA == nil {
		writeErr(w, http.StatusBadRequest, errors.New("CA not initialized"))
		return
	}
	if err := s.d.CA.InstallWindowsRoot(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true, "trusted": s.d.CA.IsTrusted()})
}

func (s *Server) caUninstall(w http.ResponseWriter, r *http.Request) {
	if s.d.CA == nil {
		writeErr(w, http.StatusBadRequest, errors.New("CA not initialized"))
		return
	}
	if err := s.d.CA.UninstallWindowsRoot(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) caDownloadCert(w http.ResponseWriter, r *http.Request) {
	if s.d.CA == nil {
		http.Error(w, "CA not initialized", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, s.d.CA.CertPath())
}

func (s *Server) proxyStatus(w http.ResponseWriter, r *http.Request) {
	st, err := system.GetProxyStatus()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	cfg := s.d.Config()
	writeJSON(w, http.StatusOK, map[string]any{
		"system_proxy": st,
		"proxy_listen": cfg.ProxyListen,
		"filtering":    cfg.HTTPSFiltering,
	})
}

func (s *Server) proxyEnable(w http.ResponseWriter, r *http.Request) {
	cfg := s.d.Config()
	host, port, _ := net.SplitHostPort(cfg.ProxyListen)
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	proxyAddr := net.JoinHostPort(host, port)
	webHost, webPort, _ := net.SplitHostPort(cfg.WebListen)
	if webHost == "" || webHost == "0.0.0.0" {
		webHost = "127.0.0.1"
	}
	pacURL := "http://" + net.JoinHostPort(webHost, webPort) + "/proxy.pac"
	if err := system.EnableSystemProxy(proxyAddr, pacURL); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) proxyDisable(w http.ResponseWriter, r *http.Request) {
	if err := system.DisableSystemProxy(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) getYoutube(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.d.Config().YouTubeShield)
}

func (s *Server) getYoutubeHealth(w http.ResponseWriter, r *http.Request) {
	caTrusted := s.d.CA != nil && s.d.CA.IsTrusted()
	proxyStatus, _ := system.GetProxyStatus()
	quicBlocked := system.IsQUICBlocked()
	cfg := s.d.Config()

	writeJSON(w, http.StatusOK, map[string]any{
		"ca_trusted":      caTrusted,
		"proxy_enabled":   proxyStatus.Enabled,
		"proxy_server":    proxyStatus.Server,
		"proxy_listening": s.d.Proxy != nil,
		"quic_blocked":    quicBlocked,
		"shield_enabled":  cfg.YouTubeShield.Enabled,
		"all_healthy":     caTrusted && proxyStatus.Enabled && quicBlocked && cfg.YouTubeShield.Enabled,
	})
}

func (s *Server) postYoutubeSetup(w http.ResponseWriter, r *http.Request) {
	// 1. Ensure YouTube shield is enabled in configuration
	cfg := s.d.Config()
	cfg.YouTubeShield.Enabled = true
	if _, err := s.d.ApplyConfig(cfg); err != nil {
		s.d.Log.Warn("apply config error during youtube setup", "err", err)
	}
	if s.d.Proxy != nil {
		s.d.Proxy.SetYouTubeShield(content.YouTubeShield{
			Enabled:       true,
			BlockPrerolls: cfg.YouTubeShield.BlockPrerolls,
			BlockBanners:  cfg.YouTubeShield.BlockBanners,
			BlockShorts:   cfg.YouTubeShield.BlockShorts,
		})
	}

	// 2. Immediate non-elevated proxy configuration in HKCU
	host, port, _ := net.SplitHostPort(cfg.ProxyListen)
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	proxyAddr := net.JoinHostPort(host, port)
	if err := system.EnableSystemProxy(proxyAddr, ""); err != nil {
		s.d.Log.Warn("enable system proxy error", "err", err)
	}

	// 3. Resolve path to Enable-YouTubeShield.ps1
	scriptPath := filepath.Join(os.Getenv("ProgramData"), "Sinkhole", "scripts", "Enable-YouTubeShield.ps1")
	if _, err := os.Stat(scriptPath); err != nil {
		if abs, err := filepath.Abs("scripts/Enable-YouTubeShield.ps1"); err == nil {
			if _, err := os.Stat(abs); err == nil {
				scriptPath = abs
			}
		}
	}

	uacLaunched := false
	if _, err := os.Stat(scriptPath); err == nil {
		// Launch elevated process asynchronously without blocking HTTP request
		cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
			fmt.Sprintf(`Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File "%s"'`, scriptPath),
		)
		if err := cmd.Start(); err == nil {
			uacLaunched = true
			go func() { _ = cmd.Wait() }()
		} else {
			s.d.Log.Warn("failed to launch elevated youtube setup script", "err", err)
		}
	} else {
		// Fallback: direct in-process attempts
		if s.d.CA != nil && !s.d.CA.IsTrusted() {
			_ = s.d.CA.InstallWindowsRoot()
		}
		_ = system.SetQUICBlocked(true)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"uac_launched": uacLaunched,
		"message":      "1-Click YouTube Shield setup initiated. Accept the Windows UAC elevation prompt if shown.",
	})
}

func (s *Server) postYoutubeTeardown(w http.ResponseWriter, r *http.Request) {
	_ = system.DisableSystemProxy()

	scriptPath := filepath.Join(os.Getenv("ProgramData"), "Sinkhole", "scripts", "Disable-YouTubeShield.ps1")
	if _, err := os.Stat(scriptPath); err != nil {
		if abs, err := filepath.Abs("scripts/Disable-YouTubeShield.ps1"); err == nil {
			if _, err := os.Stat(abs); err == nil {
				scriptPath = abs
			}
		}
	}

	uacLaunched := false
	if _, err := os.Stat(scriptPath); err == nil {
		cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
			fmt.Sprintf(`Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File "%s"'`, scriptPath),
		)
		if err := cmd.Start(); err == nil {
			uacLaunched = true
			go func() { _ = cmd.Wait() }()
		} else {
			s.d.Log.Warn("failed to launch elevated youtube teardown script", "err", err)
		}
	} else {
		_ = system.SetQUICBlocked(false)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"uac_launched": uacLaunched,
		"message":      "YouTube Shield teardown initiated.",
	})
}

func (s *Server) putYoutube(w http.ResponseWriter, r *http.Request) {
	var in config.YouTubeConfig
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	cfg := s.d.Config()
	cfg.YouTubeShield = in
	if _, err := s.d.ApplyConfig(cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if s.d.Proxy != nil {
		s.d.Proxy.SetYouTubeShield(content.YouTubeShield{
			Enabled:       in.Enabled,
			BlockPrerolls: in.BlockPrerolls,
			BlockBanners:  in.BlockBanners,
			BlockShorts:   in.BlockShorts,
		})
	}
	writeJSON(w, http.StatusOK, cfg.YouTubeShield)
}

func (s *Server) getCosmeticRules(w http.ResponseWriter, r *http.Request) {
	count := 0
	if s.d.Cosmetic != nil {
		count = s.d.Cosmetic.RuleCount()
	}
	writeJSON(w, http.StatusOK, map[string]any{"rule_count": count})
}

func (s *Server) addCosmeticRule(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Rule string `json:"rule"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if s.d.Cosmetic == nil {
		writeErr(w, http.StatusBadRequest, errors.New("cosmetic engine not active"))
		return
	}
	if ok := s.d.Cosmetic.AddRule(in.Rule); !ok {
		writeErr(w, http.StatusBadRequest, errors.New("invalid cosmetic rule syntax (expected e.g. domain##.selector)"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- Smart TV Shield

func (s *Server) getTVStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.d.Config()
	if s.d.TVShield == nil {
		writeJSON(w, http.StatusOK, tvshield.StatusSnapshot{
			Enabled:      cfg.TVShield.Enabled,
			SkipAds:      cfg.TVShield.SkipAds,
			MuteAds:      cfg.TVShield.MuteAds,
			SponsorBlock: cfg.TVShield.SponsorBlock,
			Categories:   cfg.TVShield.Categories,
			Devices:      []tvshield.DeviceRuntimeStatus{},
			RecentEvents: []tvshield.TVEvent{},
		})
		return
	}
	writeJSON(w, http.StatusOK, s.d.TVShield.Status(cfg.TVShield))
}

func (s *Server) putTVConfig(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled      *bool    `json:"enabled"`
		SkipAds      *bool    `json:"skip_ads"`
		MuteAds      *bool    `json:"mute_ads"`
		SponsorBlock *bool    `json:"sponsor_block"`
		Categories   []string `json:"categories"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	cfg := s.d.Config()
	if in.Enabled != nil {
		cfg.TVShield.Enabled = *in.Enabled
	}
	if in.SkipAds != nil {
		cfg.TVShield.SkipAds = *in.SkipAds
	}
	if in.MuteAds != nil {
		cfg.TVShield.MuteAds = *in.MuteAds
	}
	if in.SponsorBlock != nil {
		cfg.TVShield.SponsorBlock = *in.SponsorBlock
	}
	if in.Categories != nil {
		cfg.TVShield.Categories = in.Categories
	}
	if _, err := s.d.ApplyConfig(cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.getTVStatus(w, r)
}

func (s *Server) postTVDiscover(w http.ResponseWriter, r *http.Request) {
	if s.d.TVShield == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("TV Shield manager not initialized"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()

	found, err := s.d.TVShield.Discover(ctx, s.d.Config().TVShield.Devices)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if found == nil {
		found = []tvshield.DiscoveredTV{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": found})
}

func (s *Server) postTVPair(w http.ResponseWriter, r *http.Request) {
	if s.d.TVShield == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("TV Shield manager not initialized"))
		return
	}
	var in struct {
		PairingCode string `json:"pairing_code"`
		DialAppURL  string `json:"dial_app_url"`
		ScreenID    string `json:"screen_id"`
		Name        string `json:"name"`
		Platform    string `json:"platform"`
		IP          string `json:"ip"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 22*time.Second)
	defer cancel()

	var (
		dev config.TVDeviceConfig
		err error
	)
	if strings.TrimSpace(in.PairingCode) != "" {
		dev, err = s.d.TVShield.PairByCode(ctx, in.PairingCode, in.Name, in.Platform)
	} else {
		dev, err = s.d.TVShield.PairByDIAL(ctx, in.DialAppURL, in.ScreenID, in.Name, in.Platform, in.IP)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}

	cfg := s.d.Config()
	cfg.TVShield.Enabled = true
	replaced := false
	for i := range cfg.TVShield.Devices {
		if cfg.TVShield.Devices[i].ScreenID == dev.ScreenID || cfg.TVShield.Devices[i].ID == dev.ID {
			if in.Name == "" && cfg.TVShield.Devices[i].Name != "" {
				dev.Name = cfg.TVShield.Devices[i].Name
			}
			cfg.TVShield.Devices[i] = dev
			replaced = true
			break
		}
	}
	if !replaced {
		cfg.TVShield.Devices = append(cfg.TVShield.Devices, dev)
	}

	if _, err := s.d.ApplyConfig(cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":     true,
		"device": dev,
		"status": s.d.TVShield.Status(s.d.Config().TVShield),
	})
}

func (s *Server) patchTVDevice(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, errors.New("missing device id"))
		return
	}
	var in struct {
		Name     *string `json:"name"`
		Platform *string `json:"platform"`
		Enabled  *bool   `json:"enabled"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}

	cfg := s.d.Config()
	found := false
	for i := range cfg.TVShield.Devices {
		d := &cfg.TVShield.Devices[i]
		if d.ID == id || d.ScreenID == id {
			if in.Name != nil && strings.TrimSpace(*in.Name) != "" {
				d.Name = strings.TrimSpace(*in.Name)
			}
			if in.Platform != nil && strings.TrimSpace(*in.Platform) != "" {
				d.Platform = strings.TrimSpace(*in.Platform)
			}
			if in.Enabled != nil {
				d.Enabled = *in.Enabled
			}
			found = true
			break
		}
	}
	if !found {
		writeErr(w, http.StatusNotFound, errors.New("TV device not found"))
		return
	}
	if _, err := s.d.ApplyConfig(cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.getTVStatus(w, r)
}

func (s *Server) deleteTVDevice(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, errors.New("missing device id"))
		return
	}
	cfg := s.d.Config()
	out := make([]config.TVDeviceConfig, 0, len(cfg.TVShield.Devices))
	removed := false
	for _, d := range cfg.TVShield.Devices {
		if d.ID == id || d.ScreenID == id {
			removed = true
			continue
		}
		out = append(out, d)
	}
	if !removed {
		writeErr(w, http.StatusNotFound, errors.New("TV device not found"))
		return
	}
	cfg.TVShield.Devices = out
	if _, err := s.d.ApplyConfig(cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
