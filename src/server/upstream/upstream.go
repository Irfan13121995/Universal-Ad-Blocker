// Package upstream forwards DNS queries to upstream resolvers over plain
// UDP/TCP, DNS-over-TLS or DNS-over-HTTPS (RFC 8484).
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"

	"sinkhole/src/config"
)

// Upstream is a single resolver.
type Upstream interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
	String() string
}

// New builds an Upstream from its textual specification.
func New(spec string, boot *Bootstrap) (Upstream, error) {
	u, err := config.ParseUpstream(spec)
	if err != nil {
		return nil, err
	}
	switch u.Proto {
	case "udp", "tcp":
		return &plain{addr: u.Addr(), proto: u.Proto, name: u.Pretty}, nil
	case "tls":
		return &dot{host: u.Host, port: u.Port, boot: boot, name: u.Pretty}, nil
	case "https":
		return newDoH(u, boot), nil
	}
	return nil, fmt.Errorf("unsupported upstream %q", spec)
}

// ---------------------------------------------------------------- plain DNS

type plain struct {
	addr, proto, name string
}

func (p *plain) String() string { return p.name }

func (p *plain) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Net: p.proto, UDPSize: dns.DefaultMsgSize}
	r, _, err := c.ExchangeContext(ctx, m, p.addr)
	if err == nil && r.Truncated && p.proto == "udp" {
		c.Net = "tcp"
		r, _, err = c.ExchangeContext(ctx, m, p.addr)
	}
	return r, err
}

// ---------------------------------------------------------------- DNS-over-TLS

type dot struct {
	host, port, name string
	boot             *Bootstrap
}

func (d *dot) String() string { return d.name }

func (d *dot) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	ips, err := d.boot.Resolve(ctx, d.host)
	if err != nil {
		return nil, err
	}
	c := &dns.Client{Net: "tcp-tls", TLSConfig: &tls.Config{ServerName: d.host, MinVersion: tls.VersionTLS12}}
	var lastErr error
	for _, ip := range ips {
		r, _, err := c.ExchangeContext(ctx, m, net.JoinHostPort(ip.String(), d.port))
		if err == nil {
			return r, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// ---------------------------------------------------------------- DNS-over-HTTPS

type doh struct {
	url, name string
	client    *http.Client
}

func newDoH(u config.Upstream, boot *Bootstrap) *doh {
	tr := &http.Transport{
		DialContext:         boot.DialContext(false),
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 5 * time.Second,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
	}
	return &doh{url: u.URL, name: u.Pretty, client: &http.Client{Transport: tr}}
}

func (d *doh) String() string { return d.name }

func (d *doh) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	q := m.Copy()
	q.Id = 0 // RFC 8484 §4.1: use ID 0 for cache friendliness
	buf, err := q.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH %s: HTTP %d", d.url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, fmt.Errorf("DoH %s: %w", d.url, err)
	}
	r.Id = m.Id
	return r, nil
}

// ---------------------------------------------------------------- group

// Group forwards queries to primaries (failover or parallel) and then to
// fallbacks if every primary failed.
type Group struct {
	mu        sync.RWMutex
	primaries []Upstream
	fallbacks []Upstream
	parallel  bool
	timeout   time.Duration
}

// NewGroup builds a group from configuration.
func NewGroup(cfg config.Config, boot *Bootstrap) (*Group, error) {
	g := &Group{}
	return g, g.Configure(cfg, boot)
}

// Configure atomically replaces upstreams and options.
func (g *Group) Configure(cfg config.Config, boot *Bootstrap) error {
	build := func(specs []string) ([]Upstream, error) {
		out := make([]Upstream, 0, len(specs))
		for _, s := range specs {
			u, err := New(s, boot)
			if err != nil {
				return nil, err
			}
			out = append(out, u)
		}
		return out, nil
	}
	p, err := build(cfg.Upstreams)
	if err != nil {
		return err
	}
	f, err := build(cfg.Fallbacks)
	if err != nil {
		return err
	}
	g.mu.Lock()
	g.primaries, g.fallbacks = p, f
	g.parallel = cfg.UpstreamMode == config.UpstreamParallel
	g.timeout = time.Duration(cfg.UpstreamTimeoutMs) * time.Millisecond
	g.mu.Unlock()
	return nil
}

// soft reports whether a response should cause failover to the next server.
func soft(r *dns.Msg) bool {
	return r.Rcode == dns.RcodeServerFailure || r.Rcode == dns.RcodeRefused
}

// Exchange resolves m and returns the response and the upstream that answered.
func (g *Group) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, string, error) {
	g.mu.RLock()
	primaries, fallbacks, parallel, timeout := g.primaries, g.fallbacks, g.parallel, g.timeout
	g.mu.RUnlock()

	var softResp *dns.Msg
	var softName string
	var errs []error

	if parallel && len(primaries) > 1 {
		r, name, err := g.race(ctx, primaries, m, timeout)
		if err == nil && !soft(r) {
			return r, name, nil
		}
		if err != nil {
			errs = append(errs, err)
		} else {
			softResp, softName = r, name
		}
	} else {
		for _, u := range primaries {
			r, err := exchangeOne(ctx, u, m, timeout)
			if err == nil && !soft(r) {
				return r, u.String(), nil
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", u, err))
			} else if softResp == nil {
				softResp, softName = r, u.String()
			}
			if ctx.Err() != nil {
				break
			}
		}
	}
	for _, u := range fallbacks {
		if ctx.Err() != nil {
			break
		}
		r, err := exchangeOne(ctx, u, m, timeout)
		if err == nil && !soft(r) {
			return r, u.String(), nil
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", u, err))
		} else if softResp == nil {
			softResp, softName = r, u.String()
		}
	}
	if softResp != nil {
		return softResp, softName, nil
	}
	if len(errs) == 0 {
		errs = append(errs, errors.New("no upstream servers configured"))
	}
	return nil, "", errors.Join(errs...)
}

func exchangeOne(ctx context.Context, u Upstream, m *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return u.Exchange(cctx, m)
}

func (g *Group) race(ctx context.Context, ups []Upstream, m *dns.Msg, timeout time.Duration) (*dns.Msg, string, error) {
	type res struct {
		r    *dns.Msg
		name string
		err  error
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ch := make(chan res, len(ups))
	for _, u := range ups {
		go func(u Upstream) {
			r, err := u.Exchange(cctx, m.Copy())
			ch <- res{r, u.String(), err}
		}(u)
	}
	var last res
	var errs []error
	for range ups {
		x := <-ch
		if x.err == nil && !soft(x.r) {
			return x.r, x.name, nil
		}
		if x.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", x.name, x.err))
		} else {
			last = x
		}
	}
	if last.r != nil {
		return last.r, last.name, nil
	}
	return nil, "", errors.Join(errs...)
}

// Test resolves example.com through a single upstream spec and reports latency.
func Test(ctx context.Context, spec string, boot *Bootstrap) (time.Duration, string, error) {
	u, err := New(spec, boot)
	if err != nil {
		return 0, "", err
	}
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.RecursionDesired = true
	start := time.Now()
	r, err := exchangeOne(ctx, u, m, 5*time.Second)
	if err != nil {
		return 0, "", err
	}
	answer := dns.RcodeToString[r.Rcode]
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			answer = a.A.String()
			break
		}
	}
	return time.Since(start), answer, nil
}
