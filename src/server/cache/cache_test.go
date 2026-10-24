package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCacheSetGet(t *testing.T) {
	c := New(10, 0, 3600)
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	// 1. Initial get should be miss
	if got := c.Get(q); got != nil {
		t.Fatalf("expected nil for uncached query, got %+v", got)
	}

	// 2. Set response
	resp := new(dns.Msg)
	resp.SetReply(&dns.Msg{Question: []dns.Question{q}})
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{93, 184, 216, 34},
	}}
	c.Set(q, resp)

	// 3. Get response
	cached := c.Get(q)
	if cached == nil {
		t.Fatalf("expected cached response, got nil")
	}
	if len(cached.Answer) != 1 {
		t.Fatalf("expected 1 answer record, got %d", len(cached.Answer))
	}
	if a, ok := cached.Answer[0].(*dns.A); !ok || a.A.String() != "93.184.216.34" {
		t.Fatalf("unexpected cached answer: %+v", cached.Answer[0])
	}

	// 4. Check stats
	entries, hits, misses := c.Stats()
	if entries != 1 || hits != 1 || misses != 1 {
		t.Fatalf("unexpected cache stats: entries=%d hits=%d misses=%d", entries, hits, misses)
	}

	// 5. Test flush
	c.Flush()
	entries, _, _ = c.Stats()
	if entries != 0 {
		t.Fatalf("expected 0 entries after flush, got %d", entries)
	}
}

func TestCacheExpiry(t *testing.T) {
	c := New(10, 1, 1) // 1 second TTL
	q := dns.Question{Name: "short.ttl.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	resp := new(dns.Msg)
	resp.SetReply(&dns.Msg{Question: []dns.Question{q}})
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
		A:   []byte{1, 1, 1, 1},
	}}
	c.Set(q, resp)

	if got := c.Get(q); got == nil {
		t.Fatalf("expected item to be in cache immediately")
	}

	time.Sleep(1100 * time.Millisecond)

	if got := c.Get(q); got != nil {
		t.Fatalf("expected expired item to be evicted, got %+v", got)
	}
}
