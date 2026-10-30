package tvshield

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	ssdpMulticastAddr = "239.255.255.250:1900"
	dialSearchTarget  = "urn:dial-multiscreen-org:service:dial:1"
)

var reScreenID = regexp.MustCompile(`(?i)<(?:\w+:)?screenId[^>]*>([^<\s]+)</(?:\w+:)?screenId>`)

// DiscoveredTV describes a Smart TV found on the local Wi-Fi/LAN via SSDP/DIAL.
type DiscoveredTV struct {
	Name          string `json:"name"`
	Manufacturer  string `json:"manufacturer"`
	Model         string `json:"model"`
	Platform      string `json:"platform"`
	IP            string `json:"ip"`
	DialAppURL    string `json:"dial_app_url"`
	ScreenID      string `json:"screen_id,omitempty"`
	AppState      string `json:"app_state,omitempty"`
	AlreadyPaired bool   `json:"already_paired"`
}

// DiscoverLAN broadcasts SSDP M-SEARCH packets across all active private IPv4
// interfaces to locate Google TV / Android TV and Samsung Tizen Smart TVs.
func DiscoverLAN(ctx context.Context, timeout time.Duration) ([]DiscoveredTV, error) {
	if timeout <= 0 {
		timeout = 3500 * time.Millisecond
	}

	localIPs := activePrivateIPv4s()
	if len(localIPs) == 0 {
		localIPs = []string{"0.0.0.0"}
	}

	type hit struct {
		location string
		senderIP string
	}
	hitsCh := make(chan hit, 64)
	var sockWG sync.WaitGroup

	dstAddr, err := net.ResolveUDPAddr("udp4", ssdpMulticastAddr)
	if err != nil {
		return nil, err
	}

	msearch := strings.Join([]string{
		"M-SEARCH * HTTP/1.1",
		"HOST: " + ssdpMulticastAddr,
		`MAN: "ssdp:discover"`,
		"MX: 3",
		"ST: " + dialSearchTarget,
		"USER-AGENT: Sinkhole/1.0 UPnP/1.1",
		"",
		"",
	}, "\r\n")

	deadline := time.Now().Add(timeout)

	for _, ipStr := range localIPs {
		bindAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(ipStr, "0"))
		if err != nil {
			continue
		}
		conn, err := net.ListenUDP("udp4", bindAddr)
		if err != nil {
			continue
		}

		sockWG.Add(1)
		go func(c *net.UDPConn) {
			defer sockWG.Done()
			defer c.Close()

			_ = c.SetDeadline(deadline)
			_, _ = c.WriteToUDP([]byte(msearch), dstAddr)

			// Re-send once after 350ms to guard against Wi-Fi multicast packet loss
			go func() {
				select {
				case <-ctx.Done():
					_ = c.Close()
				case <-time.After(350 * time.Millisecond):
					_, _ = c.WriteToUDP([]byte(msearch), dstAddr)
				}
			}()

			buf := make([]byte, 8192)
			for {
				n, raddr, rerr := c.ReadFromUDP(buf)
				if rerr != nil {
					return
				}
				loc := parseSSDPLocation(buf[:n])
				if loc != "" && raddr != nil && raddr.IP != nil {
					select {
					case hitsCh <- hit{location: loc, senderIP: raddr.IP.String()}:
					default:
					}
				}
			}
		}(conn)
	}

	go func() {
		sockWG.Wait()
		close(hitsCh)
	}()

	seenLoc := make(map[string]bool)
	var uniqueHits []hit
	for h := range hitsCh {
		key := h.senderIP + "|" + h.location
		if !seenLoc[key] {
			seenLoc[key] = true
			uniqueHits = append(uniqueHits, h)
		}
	}

	httpClient := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var (
		mu      sync.Mutex
		results []DiscoveredTV
		seenTV  = make(map[string]bool)
		probeWG sync.WaitGroup
	)

	for _, h := range uniqueHits {
		probeWG.Add(1)
		go func(loc, ip string) {
			defer probeWG.Done()
			tv, ok := inspectDIALDevice(ctx, httpClient, loc, ip)
			if !ok {
				return
			}
			dedupKey := tv.IP + "|" + tv.Name
			if tv.ScreenID != "" {
				dedupKey = "screen:" + tv.ScreenID
			}
			mu.Lock()
			if !seenTV[dedupKey] {
				seenTV[dedupKey] = true
				results = append(results, tv)
			}
			mu.Unlock()
		}(h.location, h.senderIP)
	}
	probeWG.Wait()

	return results, nil
}

func inspectDIALDevice(ctx context.Context, client *http.Client, locationURL, expectedIP string) (DiscoveredTV, bool) {
	if !urlMatchesIP(locationURL, expectedIP) {
		return DiscoveredTV{}, false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, locationURL, nil)
	if err != nil {
		return DiscoveredTV{}, false
	}
	resp, err := client.Do(req)
	if err != nil {
		return DiscoveredTV{}, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return DiscoveredTV{}, false
	}

	var desc struct {
		Device struct {
			FriendlyName string `xml:"friendlyName"`
			Manufacturer string `xml:"manufacturer"`
			ModelName    string `xml:"modelName"`
		} `xml:"device"`
	}
	_ = xml.Unmarshal(body, &desc)

	appURL := headerCaseInsensitive(resp.Header, "Application-URL")
	if appURL == "" || !urlMatchesIP(appURL, expectedIP) {
		return DiscoveredTV{}, false
	}

	name := strings.TrimSpace(desc.Device.FriendlyName)
	if name == "" {
		name = "Smart TV (" + expectedIP + ")"
	}
	mfg := strings.TrimSpace(desc.Device.Manufacturer)
	model := strings.TrimSpace(desc.Device.ModelName)
	platform := classifyTVPlatform(name, mfg, model, resp.Header.Get("Server"))

	ytURL := strings.TrimRight(appURL, "/") + "/YouTube"
	tv := DiscoveredTV{
		Name:         name,
		Manufacturer: mfg,
		Model:        model,
		Platform:     platform,
		IP:           expectedIP,
		DialAppURL:   ytURL,
	}

	// Passive query to /YouTube service endpoint
	ytReq, err := http.NewRequestWithContext(ctx, http.MethodGet, ytURL, nil)
	if err == nil {
		ytReq.Header.Set("Origin", "https://www.youtube.com")
		if ytResp, yerr := client.Do(ytReq); yerr == nil {
			ytBody, _ := io.ReadAll(io.LimitReader(ytResp.Body, 64*1024))
			ytResp.Body.Close()
			if ytResp.StatusCode == http.StatusOK {
				screenID, state := parseDIALYouTubeXML(ytBody)
				tv.ScreenID = screenID
				tv.AppState = state
			} else if ytResp.StatusCode == http.StatusNotFound {
				// Device speaks DIAL (e.g. router or non-YouTube speaker) without YouTube app
				return DiscoveredTV{}, false
			}
		}
	}

	return tv, true
}

// LaunchAndPairDIAL launches the YouTube app on a DIAL-capable TV (Google TV or Samsung Tizen)
// with a fresh 12-digit pairing code and completes Lounge pairing automatically.
func LaunchAndPairDIAL(ctx context.Context, dialYouTubeURL string, lounge *LoungeClient) (*PairResult, error) {
	u, err := url.Parse(strings.TrimSpace(dialYouTubeURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("invalid DIAL YouTube URL")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsPrivate() {
		return nil, errors.New("DIAL URL must point to a private LAN IP address")
	}

	httpClient := &http.Client{
		Timeout:   6 * time.Second,
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 1. First try passive screenId read in case YouTube is already open on the TV
	if getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil); err == nil {
		getReq.Header.Set("Origin", "https://www.youtube.com")
		if resp, err := httpClient.Do(getReq); err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				if screenID, _ := parseDIALYouTubeXML(b); screenID != "" {
					if res, rerr := lounge.RefreshAuth(ctx, screenID); rerr == nil {
						return res, nil
					}
				}
			}
		}
	}

	// 2. Active launch with generated 12-digit pairing code
	pairingCode := generate12DigitCode()
	form := url.Values{
		"pairingCode": {pairingCode},
		"theme":       {"cl"},
	}
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	postReq.Header.Set("Origin", "https://www.youtube.com")
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(postReq)
	if err != nil {
		return nil, fmt.Errorf("failed to contact TV via DIAL (%s): %w", u.Hostname(), err)
	}
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("TV refused DIAL YouTube launch (HTTP %d) — use the 12-digit TV code instead", resp.StatusCode)
	}

	// Poll YouTube Lounge pairing server while the TV launches the YouTube app
	for attempt := 0; attempt < 9; attempt++ {
		if res, perr := lounge.PairWithCode(ctx, pairingCode); perr == nil && res != nil {
			return res, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(1800 * time.Millisecond):
		}
	}

	return nil, errors.New("timed out waiting for TV YouTube app to register pairing — open YouTube on TV and use the 12-digit code")
}

func parseDIALYouTubeXML(data []byte) (screenID, state string) {
	var svc struct {
		State          string `xml:"state"`
		AdditionalData struct {
			ScreenID string `xml:"screenId"`
		} `xml:"additionalData"`
	}
	_ = xml.Unmarshal(data, &svc)
	screenID = strings.TrimSpace(svc.AdditionalData.ScreenID)
	state = strings.TrimSpace(svc.State)
	if screenID == "" {
		if m := reScreenID.FindSubmatch(data); len(m) == 2 {
			screenID = strings.TrimSpace(string(m[1]))
		}
	}
	return screenID, state
}

func parseSSDPLocation(pkt []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(pkt))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if len(line) >= 9 && strings.EqualFold(line[:9], "location:") {
			return strings.TrimSpace(line[9:])
		}
	}
	return ""
}

func headerCaseInsensitive(h http.Header, want string) string {
	if v := h.Get(want); v != "" {
		return strings.TrimSpace(v)
	}
	for k, vals := range h {
		if strings.EqualFold(k, want) && len(vals) > 0 {
			return strings.TrimSpace(vals[0])
		}
	}
	return ""
}

func urlMatchesIP(rawURL, expectedIP string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	uIP := net.ParseIP(u.Hostname())
	eIP := net.ParseIP(expectedIP)
	return uIP != nil && eIP != nil && uIP.Equal(eIP)
}

func classifyTVPlatform(name, mfg, model, serverHdr string) string {
	joined := strings.ToLower(name + " " + mfg + " " + model + " " + serverHdr)
	switch {
	case strings.Contains(joined, "samsung") || strings.Contains(joined, "tizen"):
		return "Samsung Tizen"
	case strings.Contains(joined, "google") || strings.Contains(joined, "chromecast") ||
		strings.Contains(joined, "android") || strings.Contains(joined, "bravia") ||
		strings.Contains(joined, "sony") || strings.Contains(joined, "tcl") ||
		strings.Contains(joined, "hisense") || strings.Contains(joined, "shield"):
		return "Google TV / Android TV"
	case strings.Contains(joined, "webos") || strings.Contains(joined, "lg"):
		return "LG webOS"
	default:
		return "Smart TV"
	}
}

func activePrivateIPv4s() []string {
	var out []string
	seen := make(map[string]bool)

	// Preferred outbound LAN IP first
	if conn, err := net.Dial("udp4", "10.254.254.254:1"); err == nil {
		if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil && ua.IP.IsPrivate() {
			ip := ua.IP.String()
			seen[ip] = true
			out = append(out, ip)
		}
		_ = conn.Close()
	}

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				ip4 := ipn.IP.To4()
				if ip4 != nil && ip4.IsPrivate() {
					s := ip4.String()
					if !seen[s] {
						seen[s] = true
						out = append(out, s)
					}
				}
			}
		}
	}
	return out
}

func generate12DigitCode() string {
	var b strings.Builder
	max := big.NewInt(10)
	for i := 0; i < 12; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			b.WriteByte('5')
		} else {
			b.WriteByte(byte('0' + n.Int64()))
		}
	}
	return b.String()
}
