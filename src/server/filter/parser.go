// Package filter implements blocklist parsing and sub-millisecond domain
// matching. Rules are stored in hash sets keyed by domain; a lookup walks the
// queried name from the full name up to its parents ("a.b.c" -> "b.c" -> "c"),
// which costs O(labels) map probes and zero allocations.
package filter

import (
	"bufio"
	"io"
	"net"
	"strings"
)

// RuleKind describes how a parsed rule matches.
type RuleKind uint8

const (
	// Exact matches only the domain itself (hosts-file semantics).
	Exact RuleKind = iota
	// Subdomains matches every child of the domain but not the domain itself
	// ("*.example.com").
	Subdomains
	// DomainAndSubdomains matches the domain and every child ("||example.com^").
	DomainAndSubdomains
)

// Rule is a single parsed rule.
type Rule struct {
	Domain string
	Kind   RuleKind
	Allow  bool // exception rule (@@||example.com^)
}

// ParseStats summarises a parse run.
type ParseStats struct {
	Lines   int
	Rules   int
	Skipped int
}

// Parse reads a hosts / domains / AdBlock-syntax list and calls fn for each
// rule. Unsupported rules (cosmetic, regex, path based, ...) are skipped.
func Parse(r io.Reader, fn func(Rule)) (ParseStats, error) {
	var st ParseStats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		st.Lines++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		switch line[0] {
		case '#', '!', '[', ';':
			continue // comments / adblock header
		}
		n := parseLine(line, fn)
		if n == 0 {
			st.Skipped++
		}
		st.Rules += n
	}
	return st, sc.Err()
}

// ParseLine parses a single rule line (exported for custom rule input).
func ParseLine(line string) []Rule {
	var out []Rule
	parseLine(strings.TrimSpace(line), func(r Rule) { out = append(out, r) })
	return out
}

func parseLine(line string, fn func(Rule)) int {
	// AdBlock-style syntax.
	if strings.HasPrefix(line, "||") || strings.HasPrefix(line, "@@||") {
		r, ok := parseAdblock(line)
		if !ok {
			return 0
		}
		fn(r)
		return 1
	}
	// Cosmetic / element hiding / regex / url rules are irrelevant for DNS.
	if strings.Contains(line, "##") || strings.Contains(line, "#@#") || strings.Contains(line, "#?#") ||
		strings.HasPrefix(line, "/") || strings.HasPrefix(line, "|") || strings.HasPrefix(line, "@@") {
		return 0
	}
	// Strip trailing comments.
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return 0
	}
	// hosts format: "<ip> domain [domain...]"
	if net.ParseIP(fields[0]) != nil {
		n := 0
		for _, f := range fields[1:] {
			if d, ok := NormalizeDomain(f, true); ok {
				fn(Rule{Domain: d, Kind: Exact})
				n++
			}
		}
		return n
	}
	if len(fields) != 1 {
		return 0
	}
	f := fields[0]
	// "*.example.com" wildcard (domains-wild format).
	if strings.HasPrefix(f, "*.") {
		if d, ok := NormalizeDomain(f[2:], true); ok {
			fn(Rule{Domain: d, Kind: Subdomains})
			return 1
		}
		return 0
	}
	// Plain domain list.
	if d, ok := NormalizeDomain(f, true); ok {
		fn(Rule{Domain: d, Kind: Exact})
		return 1
	}
	return 0
}

// supportedModifiers are AdBlock options that are compatible with DNS-level
// blocking. Rules with any other modifier are skipped (AdGuard Home semantics).
var supportedModifiers = map[string]bool{
	"important": true, "all": true, "document": true, "doc": true,
	"popup": true, "third-party": true, "3p": true,
}

func parseAdblock(line string) (Rule, bool) {
	r := Rule{Kind: DomainAndSubdomains}
	if strings.HasPrefix(line, "@@") {
		r.Allow = true
		line = line[2:]
	}
	line = line[2:] // strip "||"
	if i := strings.IndexByte(line, '$'); i >= 0 {
		for _, m := range strings.Split(line[i+1:], ",") {
			if !supportedModifiers[strings.ToLower(strings.TrimSpace(m))] {
				return r, false
			}
		}
		line = line[:i]
	}
	// Accept "domain^", "domain^|", "domain" and "domain|"; reject paths.
	line = strings.TrimRight(line, "|")
	line = strings.TrimSuffix(line, "^")
	if strings.ContainsAny(line, "/^*?:|=") {
		return r, false
	}
	d, ok := NormalizeDomain(line, true)
	if !ok {
		return r, false
	}
	r.Domain = d
	return r, true
}

// NormalizeDomain lowercases a domain, strips a trailing dot and validates it.
// When requireDot is true single-label names (localhost, local, ...) are
// rejected, which filters the boilerplate entries of hosts files.
func NormalizeDomain(s string, requireDot bool) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return "", false
	}
	if net.ParseIP(s) != nil {
		return "", false
	}
	switch s {
	case "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
		"ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
		"ip6-allhosts", "0.0.0.0":
		return "", false
	}
	labels := 0
	labelLen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if labelLen == 0 {
				return "", false
			}
			labels++
			labelLen = 0
			continue
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return "", false
		}
		labelLen++
		if labelLen > 63 {
			return "", false
		}
	}
	if labelLen == 0 {
		return "", false
	}
	labels++
	if requireDot && labels < 2 {
		return "", false
	}
	return s, true
}
