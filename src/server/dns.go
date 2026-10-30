// Package server contains the DNS engine: listeners, request handling,
// filtering, caching and upstream forwarding.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"sinkhole/src/config"
	"sinkhole/src/server/cache"
	"sinkhole/src/server/filter"
	"sinkhole/src/server/upstream"
	"sinkhole/src/store"
)

// Options are the hot-reloadable request handling options.
type Options struct {
	Protection   bool
	BlockMode    string
	BlockedTTL   uint32
	PrivateOnly  bool
	CacheEnabled bool
}

// OptionsFromConfig extracts handler options from the configuration.
func OptionsFromConfig(c config.Config) Options {
	return Options{
		Protection:   c.ProtectionEnabled,
		BlockMode:    c.BlockMode,
		BlockedTTL:   c.BlockedTTL,
		PrivateOnly:  c.PrivateClientsOnly,
		CacheEnabled: c.CacheEnabled,
	}
}

// Server is the DNS server.
type Server struct {
	log    *slog.Logger
	engine *filter.Engine
	cache  *cache.Cache
	ups    *upstream.Group
	rec    *Recorder
	opts   atomic.Pointer[Options]

	mu      sync.Mutex
	servers []*dns.Server
	bound   []string
}

// New creates a DNS server.
func New(log *slog.Logger, engine *filter.Engine, c *cache.Cache, ups *upstream.Group, rec *Recorder, o Options) *Server {
	s := &Server{log: log, engine: engine, cache: c, ups: ups, rec: rec}
	s.SetOptions(o)
	return s
}

// SetOptions hot-swaps handler options.
func (s *Server) SetOptions(o Options) { s.opts.Store(&o) }

// Options returns the current handler options.
func (s *Server) Options() Options { return *s.opts.Load() }

// Bound returns the addresses currently being served.
func (s *Server) Bound() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.bound...)
}

// ---------------------------------------------------------------- listeners

// Start binds every listen address on UDP and TCP. If a wildcard address
// cannot be bound (e.g. Hyper-V / ICS already owns port 53 on one adapter) it
// falls back to binding each local interface address individually.
func (s *Server) Start(listen []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for _, addr := range listen {
		host, port, err := config.SplitHostPortDefault(addr, "53")
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil {
			errs = append(errs, fmt.Errorf("listen address %q must be an IP", addr))
			continue
		}
		err = s.bindLocked(ip, port)
		if err == nil {
			continue
		}
		if !ip.IsUnspecified() {
			errs = append(errs, err)
			continue
		}
		s.log.Warn("wildcard bind failed; falling back to per-interface binding", "addr", addr, "err", err)
		n := 0
		for _, lip := range localIPs(ip.To4() != nil) {
			if e := s.bindLocked(lip, port); e != nil {
				s.log.Warn("bind failed", "ip", lip.String(), "err", e)
				continue
			}
			n++
		}
		if n == 0 {
			errs = append(errs, err)
		}
	}
	if len(s.servers) == 0 {
		if len(errs) == 0 {
			errs = append(errs, errors.New("no DNS listen addresses configured"))
		}
		return fmt.Errorf("DNS server could not bind any address: %w", errors.Join(errs...))
	}
	for _, e := range errs {
		s.log.Warn("DNS listen error", "err", e)
	}
	s.log.Info("DNS server listening", "addresses", strings.Join(s.bound, ", "))
	return nil
}

func (s *Server) bindLocked(ip net.IP, port string) error {
	udpNet, tcpNet := "udp4", "tcp4"
	if ip.To4() == nil {
		udpNet, tcpNet = "udp6", "tcp6"
	}
	hp := net.JoinHostPort(ip.String(), port)
	pc, err := net.ListenPacket(udpNet, hp)
	if err != nil {
		return fmt.Errorf("udp %s: %w", hp, err)
	}
	l, err := net.Listen(tcpNet, hp)
	if err != nil {
		pc.Close()
		return fmt.Errorf("tcp %s: %w", hp, err)
	}
	us := &dns.Server{PacketConn: pc, Handler: s, UDPSize: 65535}
	ts := &dns.Server{Listener: l, Handler: s, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	for _, srv := range []*dns.Server{us, ts} {
		go func(srv *dns.Server) {
			if err := srv.ActivateAndServe(); err != nil && !strings.Contains(err.Error(), "closed") {
				s.log.Error("DNS listener stopped", "err", err)
			}
		}(srv)
	}
	s.servers = append(s.servers, us, ts)
	s.bound = append(s.bound, hp)
	return nil
}

// Stop shuts every listener down.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, srv := range s.servers {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = srv.ShutdownContext(ctx)
		cancel()
	}
	s.servers, s.bound = nil, nil
}

func localIPs(v4 bool) []net.IP {
	var out []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipn.IP
		if (ip.To4() != nil) != v4 || ip.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, ip)
	}
	return out
}

// ---------------------------------------------------------------- handling

// ServeDNS implements dns.Handler.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()
	if len(r.Question) != 1 || r.Opcode != dns.OpcodeQuery {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		if r.Opcode != dns.OpcodeQuery {
			m.Rcode = dns.RcodeNotImplemented
		}
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	if name == "" {
		name = "."
	}
	clientIP, isUDP := remoteIP(w.RemoteAddr())
	entry := store.QueryEntry{
		TS:     start.UnixMilli(),
		Client: clientIP.String(),
		Domain: name,
		QType:  typeString(q.Qtype),
	}

	opts := s.opts.Load()
	var resp *dns.Msg
	if opts.PrivateOnly && !isLocalClient(clientIP) {
		resp = new(dns.Msg)
		resp.SetRcode(r, dns.RcodeRefused)
		entry.Status, entry.Reason = "error", "refused: public client"
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resp = s.resolve(ctx, r, q, name, opts, &entry)
		cancel()
	}

	resp.Id = r.Id
	resp.Question = r.Question // preserve client's original casing (0x20)
	resp.RecursionAvailable = true
	clientOPT := r.IsEdns0()
	if clientOPT == nil {
		stripOPT(resp)
	}
	if isUDP {
		size := dns.MinMsgSize
		if clientOPT != nil && clientOPT.UDPSize() > dns.MinMsgSize {
			size = int(clientOPT.UDPSize())
		}
		resp.Truncate(size)
	}
	if err := w.WriteMsg(resp); err != nil {
		s.log.Debug("write response failed", "client", entry.Client, "err", err)
	}
	entry.LatencyUs = time.Since(start).Microseconds()
	entry.RCode = dns.RcodeToString[resp.Rcode]
	s.rec.Record(entry)
}

func isQUICSuppressed(name string, qtype uint16) bool {
	if qtype != dns.TypeHTTPS && qtype != dns.TypeSVCB {
		return false
	}
	n := strings.ToLower(name)
	return n == "youtube.com" || strings.HasSuffix(n, ".youtube.com") ||
		n == "googlevideo.com" || strings.HasSuffix(n, ".googlevideo.com") ||
		n == "youtu.be" || strings.HasSuffix(n, ".youtu.be") ||
		n == "ytimg.com" || strings.HasSuffix(n, ".ytimg.com")
}

func (s *Server) resolve(ctx context.Context, r *dns.Msg, q dns.Question, name string, opts *Options, e *store.QueryEntry) *dns.Msg {
	if m := s.localAnswer(r, q, name, opts); m != nil {
		e.Status, e.Reason, e.Answer = "allowed", "local", summarize(m)
		return m
	}

	if opts.Protection {
		if isQUICSuppressed(name, q.Qtype) {
			e.Status, e.Reason = "blocked", "suppressed QUIC/HTTPS record for YouTube"
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeSuccess
			m.Ns = []dns.RR{fakeSOA(q.Name, 60)}
			e.Answer = "NODATA (forced TCP fallback)"
			return m
		}

		if res := s.engine.Match(name); res.Blocked {
			e.Status, e.Reason = "blocked", describe(res)
			m := s.blockedResponse(r, q, opts)
			e.Answer = summarize(m)
			return m
		} else if res.Reason != filter.ReasonNone {
			e.Reason = describe(res)
		}
	}

	if opts.CacheEnabled {
		if m := s.cache.Get(q); m != nil {
			e.Status, e.Cached, e.Answer = "allowed", true, summarize(m)
			if blocked := s.checkCNAMEs(m, r, q, opts, e); blocked != nil {
				return blocked
			}
			return m
		}
	}

	up := r.Copy()
	up.Id = dns.Id()
	if up.IsEdns0() == nil {
		up.SetEdns0(1232, false)
	}
	resp, upName, err := s.ups.Exchange(ctx, up)
	e.Upstream = upName
	if err != nil {
		e.Status = "error"
		e.Reason = truncate("upstream failure: "+err.Error(), 300)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		return m
	}
	if opts.CacheEnabled {
		s.cache.Set(q, resp)
	}
	e.Status, e.Answer = "allowed", summarize(resp)
	if blocked := s.checkCNAMEs(resp, r, q, opts, e); blocked != nil {
		return blocked
	}
	return resp
}

// checkCNAMEs defeats CNAME cloaking: if any CNAME target in an allowed answer
// is on a blocklist, the whole response is blocked.
func (s *Server) checkCNAMEs(resp, r *dns.Msg, q dns.Question, opts *Options, e *store.QueryEntry) *dns.Msg {
	if !opts.Protection || strings.HasPrefix(e.Reason, "allowlisted") {
		return nil
	}
	for _, rr := range resp.Answer {
		c, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}
		target := strings.ToLower(strings.TrimSuffix(c.Target, "."))
		if res := s.engine.Match(target); res.Blocked {
			e.Status, e.Reason = "blocked", describe(res)+" (CNAME "+target+")"
			m := s.blockedResponse(r, q, opts)
			e.Answer = summarize(m)
			return m
		}
	}
	return nil
}

func describe(res filter.Result) string {
	switch res.Reason {
	case filter.ReasonCustomBlock:
		return "custom blocklist: " + res.Rule
	case filter.ReasonCustomAllow:
		return "allowlisted (custom): " + res.Rule
	case filter.ReasonListAllow:
		return "allowlisted by " + res.ListName + ": " + res.Rule
	case filter.ReasonListBlock:
		return res.ListName + ": " + res.Rule
	}
	return ""
}

func (s *Server) blockedResponse(r *dns.Msg, q dns.Question, opts *Options) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	ttl := opts.BlockedTTL
	if opts.BlockMode == config.BlockModeNXDomain {
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{fakeSOA(q.Name, ttl)}
		return m
	}
	hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: ttl}
	switch q.Qtype {
	case dns.TypeA:
		hdr.Rrtype = dns.TypeA
		m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4zero.To4()}}
	case dns.TypeAAAA:
		hdr.Rrtype = dns.TypeAAAA
		m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.IPv6unspecified}}
	default: // NODATA for HTTPS/SVCB/MX/TXT/...
		m.Ns = []dns.RR{fakeSOA(q.Name, ttl)}
	}
	return m
}

func fakeSOA(zone string, ttl uint32) dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      "fake-for-negative-caching.sinkhole.",
		Mbox:    "hostmaster.sinkhole.",
		Serial:  100500,
		Refresh: 1800,
		Retry:   900,
		Expire:  604800,
		Minttl:  ttl,
	}
}

// localAnswer handles names that must never leave the machine.
func (s *Server) localAnswer(r *dns.Msg, q dns.Question, name string, opts *Options) *dns.Msg {
	reply := func(rcode int, rrs ...dns.RR) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Rcode = rcode
		m.Answer = rrs
		return m
	}
	switch {
	case name == "localhost" || strings.HasSuffix(name, ".localhost"):
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: 3600}
		switch q.Qtype {
		case dns.TypeA:
			hdr.Rrtype = dns.TypeA
			return reply(dns.RcodeSuccess, &dns.A{Hdr: hdr, A: net.IPv4(127, 0, 0, 1).To4()})
		case dns.TypeAAAA:
			hdr.Rrtype = dns.TypeAAAA
			return reply(dns.RcodeSuccess, &dns.AAAA{Hdr: hdr, AAAA: net.IPv6loopback})
		}
		return reply(dns.RcodeSuccess)
	case opts.Protection && name == "use-application-dns.net":
		// Canary domain: tells Firefox not to enable DoH and bypass the sinkhole.
		m := reply(dns.RcodeNameError)
		m.Ns = []dns.RR{fakeSOA(q.Name, 300)}
		return m
	case q.Qtype == dns.TypePTR && (strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa")):
		ip := reverseIP(name)
		if ip == nil {
			return nil
		}
		if ip.IsLoopback() {
			return reply(dns.RcodeSuccess, &dns.PTR{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 3600},
				Ptr: "localhost.",
			})
		}
		if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			m := reply(dns.RcodeNameError)
			m.Ns = []dns.RR{fakeSOA(q.Name, 60)}
			return m
		}
	}
	return nil
}

func reverseIP(name string) net.IP {
	if strings.HasSuffix(name, ".in-addr.arpa") {
		parts := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
		if len(parts) != 4 {
			return nil
		}
		return net.ParseIP(parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0])
	}
	nibbles := strings.Split(strings.TrimSuffix(name, ".ip6.arpa"), ".")
	if len(nibbles) != 32 {
		return nil
	}
	var b strings.Builder
	for i := 31; i >= 0; i-- {
		b.WriteString(nibbles[i])
		if i%4 == 0 && i != 0 {
			b.WriteByte(':')
		}
	}
	return net.ParseIP(b.String())
}

// ---------------------------------------------------------------- helpers

func remoteIP(a net.Addr) (net.IP, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP, true
	case *net.TCPAddr:
		return v.IP, false
	}
	host, _, _ := net.SplitHostPort(a.String())
	return net.ParseIP(host), false
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isLocalClient(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip)
}

func stripOPT(m *dns.Msg) {
	out := m.Extra[:0]
	for _, rr := range m.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			out = append(out, rr)
		}
	}
	m.Extra = out
}

func typeString(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}

func summarize(m *dns.Msg) string {
	var parts []string
	for _, rr := range m.Answer {
		if len(parts) == 6 {
			parts = append(parts, "…")
			break
		}
		switch v := rr.(type) {
		case *dns.A:
			parts = append(parts, v.A.String())
		case *dns.AAAA:
			parts = append(parts, v.AAAA.String())
		case *dns.CNAME:
			parts = append(parts, "CNAME "+strings.TrimSuffix(v.Target, "."))
		case *dns.PTR:
			parts = append(parts, "PTR "+strings.TrimSuffix(v.Ptr, "."))
		default:
			parts = append(parts, typeString(rr.Header().Rrtype))
		}
	}
	if len(parts) == 0 {
		return dns.RcodeToString[m.Rcode]
	}
	return truncate(strings.Join(parts, ", "), 300)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
