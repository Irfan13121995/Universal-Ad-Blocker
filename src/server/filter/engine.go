package filter

import (
	"strings"
	"sync"
	"sync/atomic"
)

// Decision reasons.
const (
	ReasonNone        = ""
	ReasonCustomAllow = "custom_allow"
	ReasonCustomBlock = "custom_block"
	ReasonListAllow   = "list_allow"
	ReasonListBlock   = "list_block"
)

// Result is the outcome of a Match call.
type Result struct {
	Blocked  bool   `json:"blocked"`
	Reason   string `json:"reason"`    // one of the Reason* constants
	Rule     string `json:"rule"`      // the matching rule domain (may be a parent)
	ListID   int64  `json:"list_id"`   // blocklist id or custom rule id
	ListName string `json:"list_name"` // blocklist name ("Custom" for custom rules)
}

// ruleSet holds the exact / subdomain hash sets of one rule category.
type ruleSet[T any] struct {
	exact map[string]T // matches the name itself
	sub   map[string]T // matches strict children of the key
}

func newRuleSet[T any](hint int) ruleSet[T] {
	return ruleSet[T]{exact: make(map[string]T, hint), sub: make(map[string]T, hint/8)}
}

func (rs ruleSet[T]) add(r Rule, v T) {
	switch r.Kind {
	case Exact:
		if _, ok := rs.exact[r.Domain]; !ok {
			rs.exact[r.Domain] = v
		}
	case Subdomains:
		if _, ok := rs.sub[r.Domain]; !ok {
			rs.sub[r.Domain] = v
		}
	case DomainAndSubdomains:
		if _, ok := rs.exact[r.Domain]; !ok {
			rs.exact[r.Domain] = v
		}
		if _, ok := rs.sub[r.Domain]; !ok {
			rs.sub[r.Domain] = v
		}
	}
}

// lookup walks name and its parents. No allocations: parents are substrings.
func (rs ruleSet[T]) lookup(name string) (T, string, bool) {
	if v, ok := rs.exact[name]; ok {
		return v, name, true
	}
	if len(rs.sub) > 0 {
		for s := name; ; {
			i := strings.IndexByte(s, '.')
			if i < 0 {
				break
			}
			s = s[i+1:]
			if v, ok := rs.sub[s]; ok {
				return v, s, true
			}
		}
	}
	var zero T
	return zero, "", false
}

func (rs ruleSet[T]) size() int { return len(rs.exact) + len(rs.sub) }

// ListSet is an immutable snapshot of all blocklist rules.
type ListSet struct {
	block ruleSet[uint32]
	allow ruleSet[uint32]
	names map[uint32]string
}

// Size returns the number of unique blocking + allow entries.
func (l *ListSet) Size() int { return l.block.size() + l.allow.size() }

// Builder accumulates rules from several lists into a new ListSet.
type Builder struct{ ls *ListSet }

// NewBuilder returns a builder pre-sized for roughly hint rules.
func NewBuilder(hint int) *Builder {
	return &Builder{ls: &ListSet{
		block: newRuleSet[uint32](hint),
		allow: newRuleSet[uint32](64),
		names: map[uint32]string{},
	}}
}

// SetListName records a display name for a list id.
func (b *Builder) SetListName(id uint32, name string) { b.ls.names[id] = name }

// Add inserts a rule originating from list id.
func (b *Builder) Add(id uint32, r Rule) {
	if r.Allow {
		b.ls.allow.add(r, id)
	} else {
		b.ls.block.add(r, id)
	}
}

// Build returns the finished snapshot. The builder must not be reused.
func (b *Builder) Build() *ListSet { return b.ls }

// CustomRule is a manual user override.
type CustomRule struct {
	ID         int64  `json:"id"`
	Domain     string `json:"domain"`
	Action     string `json:"action"` // "block" | "allow"
	Subdomains bool   `json:"subdomains"`
	Comment    string `json:"comment"`
	CreatedAt  int64  `json:"created_at"`
}

// Engine is the thread-safe matcher used by the DNS server.
type Engine struct {
	lists atomic.Pointer[ListSet]

	mu          sync.RWMutex
	customBlock ruleSet[int64]
	customAllow ruleSet[int64]
	customCount int
}

// NewEngine returns an engine with no rules.
func NewEngine() *Engine {
	e := &Engine{}
	e.lists.Store(NewBuilder(0).Build())
	e.SetCustomRules(nil)
	return e
}

// SetLists atomically swaps the blocklist snapshot.
func (e *Engine) SetLists(ls *ListSet) { e.lists.Store(ls) }

// ListRuleCount returns the number of unique list entries loaded.
func (e *Engine) ListRuleCount() int { return e.lists.Load().Size() }

// CustomRuleCount returns the number of custom rules loaded.
func (e *Engine) CustomRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.customCount
}

// SetCustomRules replaces all custom rules; takes effect immediately.
func (e *Engine) SetCustomRules(rules []CustomRule) {
	block, allow := newRuleSet[int64](len(rules)), newRuleSet[int64](len(rules))
	for _, cr := range rules {
		r := Rule{Domain: cr.Domain, Kind: Exact}
		if cr.Subdomains {
			r.Kind = DomainAndSubdomains
		}
		if cr.Action == "allow" {
			allow.add(r, cr.ID)
		} else {
			block.add(r, cr.ID)
		}
	}
	e.mu.Lock()
	e.customBlock, e.customAllow, e.customCount = block, allow, len(rules)
	e.mu.Unlock()
}

// Match evaluates name (lowercase, no trailing dot). Precedence:
// custom allow > custom block > list allow > list block.
func (e *Engine) Match(name string) Result {
	e.mu.RLock()
	if id, rule, ok := e.customAllow.lookup(name); ok {
		e.mu.RUnlock()
		return Result{Reason: ReasonCustomAllow, Rule: rule, ListID: id, ListName: "Custom allowlist"}
	}
	if id, rule, ok := e.customBlock.lookup(name); ok {
		e.mu.RUnlock()
		return Result{Blocked: true, Reason: ReasonCustomBlock, Rule: rule, ListID: id, ListName: "Custom blocklist"}
	}
	e.mu.RUnlock()

	ls := e.lists.Load()
	if id, rule, ok := ls.allow.lookup(name); ok {
		return Result{Reason: ReasonListAllow, Rule: rule, ListID: int64(id), ListName: ls.names[id]}
	}
	if id, rule, ok := ls.block.lookup(name); ok {
		return Result{Blocked: true, Reason: ReasonListBlock, Rule: rule, ListID: int64(id), ListName: ls.names[id]}
	}
	return Result{}
}
