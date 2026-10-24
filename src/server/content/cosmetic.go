package content

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
)

// CosmeticEngine stores and matches element-hiding CSS selectors and scriptlets.
type CosmeticEngine struct {
	mu          sync.RWMutex
	domainRules map[string][]string // domain -> CSS selectors
	globalRules []string            // selectors applicable to all domains
	ruleCount   int
}

// NewCosmeticEngine creates an empty cosmetic engine.
func NewCosmeticEngine() *CosmeticEngine {
	return &CosmeticEngine{
		domainRules: make(map[string][]string, 1024),
		globalRules: make([]string, 0, 128),
	}
}

// AddRule parses and adds an AdBlock-syntax cosmetic rule.
// Supported formats:
//   - domain.com##.ad-banner
//   - domain1.com,domain2.com###sidebar-ad
//   - ##.common-ad-class (global)
func (e *CosmeticEngine) AddRule(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
		return false
	}

	idx := strings.Index(line, "##")
	if idx < 0 {
		return false
	}

	domainsPart := line[:idx]
	selector := strings.TrimSpace(line[idx+2:])
	if selector == "" {
		return false
	}

	// Skip element hiding exception rules (#@#) and extended syntax for basic engine
	if strings.HasPrefix(selector, "+js(") || strings.HasPrefix(selector, ":") {
		return false
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if domainsPart == "" {
		e.globalRules = append(e.globalRules, selector)
		e.ruleCount++
		return true
	}

	for _, d := range strings.Split(domainsPart, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || strings.HasPrefix(d, "~") {
			continue // skip domain inversions
		}
		e.domainRules[d] = append(e.domainRules[d], selector)
		e.ruleCount++
	}
	return true
}

// RuleCount returns the total number of cosmetic rules loaded.
func (e *CosmeticEngine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.ruleCount
}

// GenerateCSS returns compiled CSS stylesheet for the requested domain.
func (e *CosmeticEngine) GenerateCSS(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	e.mu.RLock()
	defer e.mu.RUnlock()

	var selectors []string
	// Match exact domain and parent domains
	for d := domain; ; {
		if rules, ok := e.domainRules[d]; ok {
			selectors = append(selectors, rules...)
		}
		idx := strings.IndexByte(d, '.')
		if idx < 0 {
			break
		}
		d = d[idx+1:]
	}

	if len(selectors) == 0 && len(e.globalRules) == 0 {
		return ""
	}

	all := append(selectors, e.globalRules...)
	if len(all) == 0 {
		return ""
	}

	// Combine into a single rule with display: none !important
	joined := strings.Join(all, ",\n")
	return fmt.Sprintf("/* Sinkhole Cosmetic Filter for %s */\n%s {\n  display: none !important;\n  visibility: hidden !important;\n}\n", domain, joined)
}

// InjectCosmeticCSS injects CSS into an HTML payload before </head> or <body>.
func InjectCosmeticCSS(html []byte, css string) []byte {
	if css == "" {
		return html
	}
	tag := "<style id=\"sinkhole-cosmetic-rules\">\n" + css + "\n</style>\n"

	if idx := bytes.Index(html, []byte("</head>")); idx >= 0 {
		var buf bytes.Buffer
		buf.Grow(len(html) + len(tag))
		buf.Write(html[:idx])
		buf.WriteString(tag)
		buf.Write(html[idx:])
		return buf.Bytes()
	}

	if idx := bytes.Index(html, []byte("<body")); idx >= 0 {
		var buf bytes.Buffer
		buf.Grow(len(html) + len(tag))
		buf.Write(html[:idx])
		buf.WriteString(tag)
		buf.Write(html[idx:])
		return buf.Bytes()
	}

	return append([]byte(tag), html...)
}
