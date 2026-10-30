// Package proxy provides a high-performance local HTTP and HTTPS MitM inspection proxy.
// It intercepts YouTube player API responses to strip video ads and injects cosmetic
// element-hiding stylesheets into web pages across all Windows browsers.
package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"sinkhole/src/server/ca"
	"sinkhole/src/server/content"
	"sinkhole/src/server/filter"
)

// InspectorEvent records an HTTP transaction observed by the proxy.
type InspectorEvent struct {
	TS        int64  `json:"ts"`
	Method    string `json:"method"`
	Host      string `json:"host"`
	Path      string `json:"path"`
	Action    string `json:"action"` // "bypassed" | "modified" | "injected" | "blocked" | "tunneled"
	Details   string `json:"details"`
	ClientIP  string `json:"client_ip"`
}

// Proxy is the local HTTPS inspection server.
type Proxy struct {
	addr      string
	ca        *ca.CA
	engine    *filter.Engine
	cosmetic  *content.CosmeticEngine
	youtube   content.YouTubeShield
	log       *slog.Logger
	listener  net.Listener
	enabled   bool
	mu        sync.RWMutex

	eventCh chan InspectorEvent
}

// New creates a Proxy instance.
func New(addr string, caInstance *ca.CA, engine *filter.Engine, cosmetic *content.CosmeticEngine, log *slog.Logger) *Proxy {
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	return &Proxy{
		addr:     addr,
		ca:       caInstance,
		engine:   engine,
		cosmetic: cosmetic,
		youtube:  content.DefaultYouTubeShield(),
		log:      log,
		enabled:  true,
		eventCh:  make(chan InspectorEvent, 500),
	}
}

// SetYouTubeShield configures the YouTube protection parameters.
func (p *Proxy) SetYouTubeShield(s content.YouTubeShield) {
	p.mu.Lock()
	p.youtube = s
	p.mu.Unlock()
}

// EventChannel returns the stream of inspector events.
func (p *Proxy) EventChannel() <-chan InspectorEvent { return p.eventCh }

func (p *Proxy) record(e InspectorEvent) {
	e.TS = time.Now().UnixMilli()
	select {
	case p.eventCh <- e:
	default:
	}
}

// Start begins listening on the configured proxy address.
func (p *Proxy) Start() error {
	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		return fmt.Errorf("listen proxy on %s: %w", p.addr, err)
	}
	p.listener = ln
	p.log.Info("HTTPS filtering proxy listening", "addr", p.addr)

	srv := &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		if err := srv.Serve(ln); err != nil && !strings.Contains(err.Error(), "closed") {
			p.log.Error("proxy server stopped", "err", err)
		}
	}()
	return nil
}

// Stop terminates the proxy listener.
func (p *Proxy) Stop() {
	if p.listener != nil {
		_ = p.listener.Close()
	}
}

// ServeHTTP handles both CONNECT tunneling and direct HTTP proxy requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// ---------------------------------------------------------------- CONNECT Handling

// defaultBypassDomains are certificate-pinned services, banking, software updaters,
// and high-speed video chunks that should never be decrypted.
var defaultBypassDomains = []string{
	"videoplayback", // High-speed YouTube media chunk stream
	"googlevideo.com",
	"microsoft.com",
	"windowsupdate.com",
	"live.com",
	"discord.com",
	"discord.gg",
	"steamcommunity.com",
	"steampowered.com",
	"apple.com",
	"icloud.com",
	"chase.com",
	"bankofamerica.com",
	"wellsfargo.com",
	"paypal.com",
}

func shouldBypass(host string) bool {
	h := strings.ToLower(host)
	for _, b := range defaultBypassDomains {
		if strings.Contains(h, b) {
			return true
		}
	}
	return false
}

func isTargetDomain(host string) bool {
	h := strings.ToLower(host)
	return strings.Contains(h, "youtube.com") ||
		strings.Contains(h, "youtu.be") ||
		strings.Contains(h, "doubleclick") ||
		strings.Contains(h, "googleads")
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	dest := r.Host
	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		host = dest
		port = "443"
		dest = net.JoinHostPort(host, port)
	}

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	// 1. Check DNS blocklist: if destination host is an ad server, sinkhole immediately
	if p.engine != nil {
		if res := p.engine.Match(host); res.Blocked {
			p.record(InspectorEvent{
				Method: "CONNECT", Host: host, Path: "/", Action: "blocked",
				Details: "Blocked by list: " + res.ListName, ClientIP: clientIP,
			})
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	// 2. High-speed raw tunnel for bypassed / pinned / non-target domains
	if shouldBypass(host) || (!isTargetDomain(host) && p.cosmetic.GenerateCSS(host) == "") {
		p.tunnelDirect(w, r, dest, host, clientIP)
		return
	}

	// 3. MitM Interception: Hijack client connection using minted CA certificate
	p.interceptTLS(w, r, dest, host, clientIP)
}

func (p *Proxy) tunnelDirect(w http.ResponseWriter, r *http.Request, dest, host, clientIP string) {
	outConn, err := net.DialTimeout("tcp", dest, 5*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer outConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking unsupported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Acknowledge CONNECT
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	p.record(InspectorEvent{
		Method: "CONNECT", Host: host, Path: "/", Action: "tunneled",
		Details: "Direct TCP tunnel (high-speed passthrough)", ClientIP: clientIP,
	})

	// Bidirectional zero-copy stream
	pipe(clientConn, outConn)
}

func (p *Proxy) interceptTLS(w http.ResponseWriter, r *http.Request, dest, host, clientIP string) {
	leafCert, err := p.ca.MintCertificate(host)
	if err != nil {
		p.log.Warn("mint leaf certificate failed", "host", host, "err", err)
		p.tunnelDirect(w, r, dest, host, clientIP)
		return
	}

	outConn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", dest, &tls.Config{
		ServerName: host,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer outConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking unsupported", http.StatusInternalServerError)
		return
	}

	clientRaw, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientRaw.Close()

	_, _ = clientRaw.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
	}
	clientTLS := tls.Server(clientRaw, tlsConfig)
	if err := clientTLS.Handshake(); err != nil {
		return
	}
	defer clientTLS.Close()

	p.serveMitMConnection(clientTLS, outConn, host, clientIP)
}

func (p *Proxy) serveMitMConnection(clientConn net.Conn, upstreamConn net.Conn, host, clientIP string) {
	clientReader := bufio.NewReader(clientConn)
	upstreamReader := bufio.NewReader(upstreamConn)

	for {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = host

		// Filter ad requests
		if p.engine != nil && p.engine.Match(req.URL.Hostname()).Blocked {
			resp := &http.Response{
				StatusCode: http.StatusNoContent,
				ProtoMajor: 1, ProtoMinor: 1,
				Header: make(http.Header),
			}
			_ = resp.Write(clientConn)
			p.record(InspectorEvent{
				Method: req.Method, Host: host, Path: req.URL.Path, Action: "blocked",
				Details: "Blocked by URL rule", ClientIP: clientIP,
			})
			continue
		}

		isYT := strings.Contains(host, "youtube.com") || strings.Contains(host, "youtu.be")
		if isYT {
			// Normalize Accept-Encoding to gzip, deflate so upstream sends formats we can inspect
			req.Header.Set("Accept-Encoding", "gzip, deflate")
		}

		// Forward to upstream
		if err := req.Write(upstreamConn); err != nil {
			return
		}

		resp, err := http.ReadResponse(upstreamReader, req)
		if err != nil {
			return
		}

		p.inspectAndWriteResponse(clientConn, resp, req, host, clientIP)
		if resp.Close {
			return
		}
	}
}

func (p *Proxy) inspectAndWriteResponse(clientConn net.Conn, resp *http.Response, req *http.Request, host, clientIP string) {
	defer resp.Body.Close()

	isYT := strings.Contains(host, "youtube.com") || strings.Contains(host, "youtu.be")

	// 1. YouTube Player API Ad Stripping
	if isYT && content.IsYouTubePlayerAPI(req.URL.Path) {
		encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
		var reader io.Reader = resp.Body
		var gzReader *gzip.Reader
		if strings.Contains(encoding, "gzip") {
			var err error
			gzReader, err = gzip.NewReader(resp.Body)
			if err == nil {
				defer gzReader.Close()
				reader = gzReader
			}
		}

		body, err := io.ReadAll(reader)
		if err == nil && len(body) > 0 {
			sanitized, stripped := content.SanitizePlayerJSON(body)
			if stripped {
				p.record(InspectorEvent{
					Method: req.Method, Host: host, Path: req.URL.Path, Action: "modified",
					Details: "YouTube video ads sanitized from player payload", ClientIP: clientIP,
				})
			}
			resp.Header.Del("Content-Encoding")
			resp.Body = io.NopCloser(bytes.NewReader(sanitized))
			resp.ContentLength = int64(len(sanitized))
			resp.Header.Set("Content-Length", strconv.Itoa(len(sanitized)))
			_ = resp.Write(clientConn)
			return
		}
	}

	// 2. HTML Injection (Cosmetic CSS & YouTube Scriptlets)
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") && resp.StatusCode == http.StatusOK {
		var reader io.Reader = resp.Body
		encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
		if strings.Contains(encoding, "gzip") {
			gz, err := gzip.NewReader(resp.Body)
			if err == nil {
				defer gz.Close()
				reader = gz
			}
		}

		body, err := io.ReadAll(reader)
		if err == nil && len(body) > 0 {
			modified := body
			if isYT {
				modified = content.InjectYouTubeAssets(modified)
				p.record(InspectorEvent{
					Method: req.Method, Host: host, Path: req.URL.Path, Action: "injected",
					Details: "Injected YouTube defuser & cosmetic styles", ClientIP: clientIP,
				})
			}

			// Also apply universal cosmetic rules if any exist for this domain
			if css := p.cosmetic.GenerateCSS(host); css != "" {
				modified = content.InjectCosmeticCSS(modified, css)
				p.record(InspectorEvent{
					Method: req.Method, Host: host, Path: req.URL.Path, Action: "injected",
					Details: "Injected website cosmetic element hiding CSS", ClientIP: clientIP,
				})
			}

			resp.Header.Del("Content-Encoding")
			resp.Body = io.NopCloser(bytes.NewReader(modified))
			resp.ContentLength = int64(len(modified))
			resp.Header.Set("Content-Length", strconv.Itoa(len(modified)))
			_ = resp.Write(clientConn)
			return
		}
	}

	// Default: write unmodified response
	_ = resp.Write(clientConn)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	tr := http.DefaultTransport
	resp, err := tr.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func pipe(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
	}
	go cp(c1, c2)
	go cp(c2, c1)
	wg.Wait()
}
