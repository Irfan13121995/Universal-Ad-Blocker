package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Bootstrap resolves host names of DoH/DoT upstreams and blocklist URLs using
// a fixed set of plain-DNS servers. This prevents a resolution loop when the
// Windows host itself is configured to use the sinkhole (127.0.0.1).
type Bootstrap struct {
	mu      sync.Mutex
	servers []string
	cache   map[string]bootEntry
}

type bootEntry struct {
	ips     []net.IP
	expires time.Time
}

// NewBootstrap creates a bootstrap resolver; servers are "ip[:port]".
func NewBootstrap(servers []string) *Bootstrap {
	b := &Bootstrap{cache: map[string]bootEntry{}}
	b.SetServers(servers)
	return b
}

// SetServers replaces the bootstrap servers and clears the cache.
func (b *Bootstrap) SetServers(servers []string) {
	norm := make([]string, 0, len(servers))
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if ip := net.ParseIP(strings.Trim(s, "[]")); ip != nil {
			s = net.JoinHostPort(ip.String(), "53")
		}
		norm = append(norm, s)
	}
	b.mu.Lock()
	b.servers = norm
	b.cache = map[string]bootEntry{}
	b.mu.Unlock()
}

// Resolve returns the IPs of host (IPv4 first).
func (b *Bootstrap) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	b.mu.Lock()
	if e, ok := b.cache[host]; ok && time.Now().Before(e.expires) {
		b.mu.Unlock()
		return e.ips, nil
	}
	servers := append([]string(nil), b.servers...)
	b.mu.Unlock()

	var lastErr error = errors.New("no bootstrap servers configured")
	for _, srv := range servers {
		ips, ttl, err := lookup(ctx, srv, host)
		if err != nil {
			lastErr = err
			continue
		}
		if ttl < 60 {
			ttl = 60
		}
		if ttl > 3600 {
			ttl = 3600
		}
		b.mu.Lock()
		b.cache[host] = bootEntry{ips: ips, expires: time.Now().Add(time.Duration(ttl) * time.Second)}
		b.mu.Unlock()
		return ips, nil
	}
	return nil, fmt.Errorf("bootstrap resolve %s: %w", host, lastErr)
}

func lookup(ctx context.Context, server, host string) ([]net.IP, uint32, error) {
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	var ips []net.IP
	ttl := uint32(3600)
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), qt)
		m.RecursionDesired = true
		r, _, err := c.ExchangeContext(ctx, m, server)
		if err != nil {
			if qt == dns.TypeA {
				return nil, 0, err
			}
			continue
		}
		for _, rr := range r.Answer {
			switch v := rr.(type) {
			case *dns.A:
				ips = append(ips, v.A)
			case *dns.AAAA:
				ips = append(ips, v.AAAA)
			default:
				continue
			}
			if rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
		if qt == dns.TypeA && len(ips) > 0 {
			break // IPv4 is enough; most home networks prefer it
		}
	}
	if len(ips) == 0 {
		return nil, 0, fmt.Errorf("no addresses for %s via %s", host, server)
	}
	return ips, ttl, nil
}

// DialContext dials addr, resolving its host through the bootstrap servers.
// When allowSystem is true the OS resolver is used as a last resort.
func (b *Bootstrap) DialContext(allowSystem bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := b.Resolve(ctx, host)
		if err != nil {
			if !allowSystem {
				return nil, err
			}
			return d.DialContext(ctx, network, addr)
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}
