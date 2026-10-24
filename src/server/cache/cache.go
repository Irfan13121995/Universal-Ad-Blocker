// Package cache implements an in-memory, TTL-aware LRU cache for upstream DNS
// responses.
package cache

import (
	"container/list"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type key struct {
	name   string
	qtype  uint16
	qclass uint16
}

type entry struct {
	k       key
	msg     *dns.Msg
	stored  time.Time
	expires time.Time
}

// Cache is safe for concurrent use.
type Cache struct {
	mu     sync.Mutex
	ll     *list.List
	items  map[key]*list.Element
	max    int
	minTTL uint32
	maxTTL uint32

	hits   atomic.Int64
	misses atomic.Int64
}

// New creates a cache holding at most max entries.
func New(max int, minTTL, maxTTL uint32) *Cache {
	return &Cache{ll: list.New(), items: map[key]*list.Element{}, max: max, minTTL: minTTL, maxTTL: maxTTL}
}

// Configure updates limits, evicting entries if the cache shrank.
func (c *Cache) Configure(max int, minTTL, maxTTL uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.max, c.minTTL, c.maxTTL = max, minTTL, maxTTL
	for c.ll.Len() > c.max {
		c.removeOldest()
	}
}

func keyOf(q dns.Question) key {
	return key{name: strings.ToLower(q.Name), qtype: q.Qtype, qclass: q.Qclass}
}

// Get returns a copy of a cached response with decremented TTLs, or nil.
func (c *Cache) Get(q dns.Question) *dns.Msg {
	k := keyOf(q)
	now := time.Now()
	c.mu.Lock()
	el, ok := c.items[k]
	if !ok {
		c.mu.Unlock()
		c.misses.Add(1)
		return nil
	}
	e := el.Value.(*entry)
	if now.After(e.expires) {
		c.ll.Remove(el)
		delete(c.items, k)
		c.mu.Unlock()
		c.misses.Add(1)
		return nil
	}
	c.ll.MoveToFront(el)
	msg, stored := e.msg, e.stored
	c.mu.Unlock()

	c.hits.Add(1)
	out := msg.Copy()
	elapsed := uint32(now.Sub(stored) / time.Second)
	for _, sec := range [][]dns.RR{out.Answer, out.Ns, out.Extra} {
		for _, rr := range sec {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			if h.Ttl > elapsed {
				h.Ttl -= elapsed
			} else {
				h.Ttl = 1
			}
		}
	}
	return out
}

// Set stores a response if it is cacheable.
func (c *Cache) Set(q dns.Question, m *dns.Msg) {
	if m == nil || m.Truncated || (m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError) {
		return
	}
	c.mu.Lock()
	minTTL, maxTTL, max := c.minTTL, c.maxTTL, c.max
	c.mu.Unlock()
	if max <= 0 {
		return
	}
	ttl := responseTTL(m)
	if ttl < minTTL {
		ttl = minTTL
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	if ttl == 0 {
		return
	}
	now := time.Now()
	stored := m.Copy()
	if minTTL > 0 { // make sure clients see the clamped TTL
		for _, rr := range stored.Answer {
			if rr.Header().Ttl < minTTL {
				rr.Header().Ttl = minTTL
			}
		}
	}
	e := &entry{k: keyOf(q), msg: stored, stored: now, expires: now.Add(time.Duration(ttl) * time.Second)}

	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[e.k]; ok {
		el.Value = e
		c.ll.MoveToFront(el)
		return
	}
	c.items[e.k] = c.ll.PushFront(e)
	for c.ll.Len() > c.max {
		c.removeOldest()
	}
}

func (c *Cache) removeOldest() {
	el := c.ll.Back()
	if el == nil {
		return
	}
	c.ll.Remove(el)
	delete(c.items, el.Value.(*entry).k)
}

// Flush empties the cache.
func (c *Cache) Flush() {
	c.mu.Lock()
	c.ll.Init()
	c.items = map[key]*list.Element{}
	c.mu.Unlock()
}

// Stats reports entries, hits and misses.
func (c *Cache) Stats() (entries int, hits, misses int64) {
	c.mu.Lock()
	entries = c.ll.Len()
	c.mu.Unlock()
	return entries, c.hits.Load(), c.misses.Load()
}

// responseTTL picks the minimum TTL of the answer section, or the negative
// caching TTL from the SOA record (RFC 2308) for NXDOMAIN / NODATA.
func responseTTL(m *dns.Msg) uint32 {
	if len(m.Answer) > 0 && m.Rcode == dns.RcodeSuccess {
		ttl := ^uint32(0)
		for _, rr := range m.Answer {
			if t := rr.Header().Ttl; t < ttl {
				ttl = t
			}
		}
		return ttl
	}
	for _, rr := range m.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			ttl := soa.Hdr.Ttl
			if soa.Minttl < ttl {
				ttl = soa.Minttl
			}
			return ttl
		}
	}
	return 30
}
