// Package config defines the runtime configuration of the sinkhole and its
// validation rules. The configuration is persisted as a JSON document inside
// the SQLite settings table (see package store).
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Block modes.
const (
	BlockModeNullIP   = "null_ip"  // A -> 0.0.0.0, AAAA -> ::
	BlockModeNXDomain = "nxdomain" // NXDOMAIN with a synthetic SOA
)

// Upstream modes.
const (
	UpstreamFailover = "failover" // try upstreams in order
	UpstreamParallel = "parallel" // query all, fastest answer wins
)

// Config is the full user-editable configuration.
type Config struct {
	// DNSListen is the list of addresses the DNS server binds to (UDP + TCP).
	DNSListen []string `json:"dns_listen"`
	// WebListen is the address of the admin dashboard.
	WebListen string `json:"web_listen"`

	// Upstreams are the primary resolvers. Supported forms:
	//   1.1.1.1 | 1.1.1.1:53 | udp://1.1.1.1 | tcp://1.1.1.1
	//   tls://dns.quad9.net | https://cloudflare-dns.com/dns-query
	Upstreams []string `json:"upstreams"`
	// Fallbacks are used only when every primary upstream fails.
	Fallbacks []string `json:"fallbacks"`
	// Bootstrap are plain DNS servers (IP[:port]) used to resolve the host
	// names of DoH / DoT upstreams and blocklist URLs. They are never used
	// for client queries.
	Bootstrap         []string `json:"bootstrap"`
	UpstreamMode      string   `json:"upstream_mode"`
	UpstreamTimeoutMs int      `json:"upstream_timeout_ms"`

	ProtectionEnabled bool   `json:"protection_enabled"`
	BlockMode         string `json:"block_mode"`
	BlockedTTL        uint32 `json:"blocked_ttl"`
	// PrivateClientsOnly refuses queries from public IP addresses so the
	// server can never be abused as an open resolver.
	PrivateClientsOnly bool `json:"private_clients_only"`

	CacheEnabled bool   `json:"cache_enabled"`
	CacheSize    int    `json:"cache_size"`
	CacheMinTTL  uint32 `json:"cache_min_ttl"`
	CacheMaxTTL  uint32 `json:"cache_max_ttl"`

	LogQueries          bool `json:"log_queries"`
	LogRetentionDays    int  `json:"log_retention_days"`
	UpdateIntervalHours int  `json:"update_interval_hours"`
}

// Default returns the configuration used on first start.
func Default() Config {
	return Config{
		DNSListen: []string{"0.0.0.0:53", "[::]:53"},
		WebListen: "127.0.0.1:3000",
		Upstreams: []string{
			"https://cloudflare-dns.com/dns-query",
			"https://dns.quad9.net/dns-query",
		},
		Fallbacks:           []string{"1.1.1.1", "9.9.9.9"},
		Bootstrap:           []string{"1.1.1.1:53", "9.9.9.9:53", "8.8.8.8:53"},
		UpstreamMode:        UpstreamFailover,
		UpstreamTimeoutMs:   2500,
		ProtectionEnabled:   true,
		BlockMode:           BlockModeNullIP,
		BlockedTTL:          10,
		PrivateClientsOnly:  true,
		CacheEnabled:        true,
		CacheSize:           20000,
		CacheMinTTL:         0,
		CacheMaxTTL:         86400,
		LogQueries:          true,
		LogRetentionDays:    7,
		UpdateIntervalHours: 24,
	}
}

// Normalize trims whitespace, drops empty entries and fills zero values with
// defaults so that partially specified JSON documents remain usable.
func (c *Config) Normalize() {
	d := Default()
	c.DNSListen = clean(c.DNSListen)
	c.Upstreams = clean(c.Upstreams)
	c.Fallbacks = clean(c.Fallbacks)
	c.Bootstrap = clean(c.Bootstrap)
	c.WebListen = strings.TrimSpace(c.WebListen)
	if len(c.DNSListen) == 0 {
		c.DNSListen = d.DNSListen
	}
	if c.WebListen == "" {
		c.WebListen = d.WebListen
	}
	if len(c.Bootstrap) == 0 {
		c.Bootstrap = d.Bootstrap
	}
	if c.UpstreamMode == "" {
		c.UpstreamMode = d.UpstreamMode
	}
	if c.UpstreamTimeoutMs <= 0 {
		c.UpstreamTimeoutMs = d.UpstreamTimeoutMs
	}
	if c.BlockMode == "" {
		c.BlockMode = d.BlockMode
	}
	if c.CacheSize <= 0 {
		c.CacheSize = d.CacheSize
	}
	if c.CacheMaxTTL == 0 {
		c.CacheMaxTTL = d.CacheMaxTTL
	}
	if c.LogRetentionDays <= 0 {
		c.LogRetentionDays = d.LogRetentionDays
	}
	if c.UpdateIntervalHours < 0 {
		c.UpdateIntervalHours = 0
	}
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	var errs []error
	for _, l := range c.DNSListen {
		host, _, err := SplitHostPortDefault(l, "53")
		if err != nil || net.ParseIP(host) == nil {
			errs = append(errs, fmt.Errorf("dns_listen %q must be an IP address with optional port", l))
		}
	}
	if _, _, err := net.SplitHostPort(c.WebListen); err != nil {
		errs = append(errs, fmt.Errorf("web_listen %q: %w", c.WebListen, err))
	}
	if len(c.Upstreams) == 0 && len(c.Fallbacks) == 0 {
		errs = append(errs, errors.New("at least one upstream or fallback DNS server is required"))
	}
	for _, u := range append(append([]string{}, c.Upstreams...), c.Fallbacks...) {
		if _, err := ParseUpstream(u); err != nil {
			errs = append(errs, err)
		}
	}
	for _, b := range c.Bootstrap {
		host, _, err := SplitHostPortDefault(b, "53")
		if err != nil || net.ParseIP(host) == nil {
			errs = append(errs, fmt.Errorf("bootstrap %q must be an IP address with optional port", b))
		}
	}
	if c.UpstreamMode != UpstreamFailover && c.UpstreamMode != UpstreamParallel {
		errs = append(errs, fmt.Errorf("upstream_mode must be %q or %q", UpstreamFailover, UpstreamParallel))
	}
	if c.BlockMode != BlockModeNullIP && c.BlockMode != BlockModeNXDomain {
		errs = append(errs, fmt.Errorf("block_mode must be %q or %q", BlockModeNullIP, BlockModeNXDomain))
	}
	if c.UpstreamTimeoutMs < 200 || c.UpstreamTimeoutMs > 30000 {
		errs = append(errs, errors.New("upstream_timeout_ms must be between 200 and 30000"))
	}
	if c.CacheSize > 5_000_000 {
		errs = append(errs, errors.New("cache_size is too large (max 5,000,000)"))
	}
	if c.CacheMinTTL > c.CacheMaxTTL {
		errs = append(errs, errors.New("cache_min_ttl must not exceed cache_max_ttl"))
	}
	if c.LogRetentionDays > 365 {
		errs = append(errs, errors.New("log_retention_days must be at most 365"))
	}
	return errors.Join(errs...)
}

// Upstream is a parsed upstream resolver address.
type Upstream struct {
	Raw    string // original string
	Proto  string // udp | tcp | tls | https
	Host   string // host name or IP (no brackets)
	Port   string
	URL    string // full URL for DoH
	Pretty string // display form
}

// Addr returns host:port.
func (u Upstream) Addr() string { return net.JoinHostPort(u.Host, u.Port) }

// ParseUpstream parses an upstream specification.
func ParseUpstream(s string) (Upstream, error) {
	s = strings.TrimSpace(s)
	up := Upstream{Raw: s}
	if s == "" {
		return up, errors.New("empty upstream")
	}
	if strings.HasPrefix(s, "https://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return up, fmt.Errorf("upstream %q: invalid DoH URL", s)
		}
		up.Proto, up.Host, up.Port, up.URL = "https", u.Hostname(), u.Port(), u.String()
		if up.Port == "" {
			up.Port = "443"
		}
		if u.Path == "" {
			up.URL = strings.TrimRight(up.URL, "/") + "/dns-query"
		}
		up.Pretty = up.URL
		return up, nil
	}
	proto, rest := "udp", s
	if i := strings.Index(s, "://"); i >= 0 {
		proto, rest = strings.ToLower(s[:i]), s[i+3:]
	}
	defPort := "53"
	switch proto {
	case "udp", "tcp":
	case "tls":
		defPort = "853"
	default:
		return up, fmt.Errorf("upstream %q: unsupported scheme %q", s, proto)
	}
	rest = strings.TrimRight(rest, "/")
	host, port, err := SplitHostPortDefault(rest, defPort)
	if err != nil {
		return up, fmt.Errorf("upstream %q: %w", s, err)
	}
	if proto != "tls" && net.ParseIP(host) == nil {
		return up, fmt.Errorf("upstream %q: plain DNS upstreams must be IP addresses", s)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() && port == "53" {
		return up, fmt.Errorf("upstream %q points at this sinkhole (loopback:53) and would create a loop", s)
	}
	up.Proto, up.Host, up.Port = proto, host, port
	up.Pretty = proto + "://" + net.JoinHostPort(host, port)
	return up, nil
}

// SplitHostPortDefault splits "host[:port]" accepting bare IPv6 addresses.
func SplitHostPortDefault(s, defPort string) (string, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", errors.New("empty address")
	}
	if ip := net.ParseIP(strings.Trim(s, "[]")); ip != nil {
		return ip.String(), defPort, nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		// No port present.
		if strings.Contains(err.Error(), "missing port") {
			return strings.Trim(s, "[]"), defPort, nil
		}
		return "", "", err
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return "", "", fmt.Errorf("invalid port %q", port)
	}
	return host, port, nil
}

// DefaultDataDir returns %ProgramData%\Sinkhole (or a local folder as fallback).
func DefaultDataDir() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "Sinkhole")
	}
	exe, err := os.Executable()
	if err != nil {
		return "data"
	}
	return filepath.Join(filepath.Dir(exe), "data")
}

func clean(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
