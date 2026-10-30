package tvshield

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
)

const (
	loungeAPIBase    = "https://www.youtube.com/api/lounge"
	loungeAppName    = "ytios-phone-20.15.1"
	loungeClientName = "Sinkhole Shield"
)

var (
	// ErrTokenExpired indicates the lounge token returned 401 and must be refreshed.
	ErrTokenExpired = errors.New("lounge token expired")
	// ErrSessionGone indicates SID/gsession expired (400 Unknown SID / 410 Gone).
	ErrSessionGone = errors.New("lounge session gone")
	// ErrUnsupportedClient indicates a blacklisted TV client (e.g. YouTube Kids).
	ErrUnsupportedClient = errors.New("unsupported youtube client")
	// ErrDisconnected indicates the TV screen closed the session.
	ErrDisconnected = errors.New("lounge screen disconnected")
)

// PairResult holds the credentials returned when pairing with a Smart TV.
type PairResult struct {
	ScreenID    string `json:"screen_id"`
	Name        string `json:"name"`
	LoungeToken string `json:"lounge_token"`
}

// LoungeClient performs stateless pairing, token refresh, and creates active Sessions.
type LoungeClient struct {
	apiBase     string
	controlHTTP *http.Client
	streamHTTP  *http.Client
}

// NewLoungeClient initializes a YouTube Lounge client that bypasses any local HTTP proxy.
func NewLoungeClient() *LoungeClient {
	directDialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return &LoungeClient{
		apiBase: loungeAPIBase,
		controlHTTP: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				Proxy:               nil,
				DialContext:         directDialer.DialContext,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
		streamHTTP: &http.Client{
			Timeout: 0, // Long-polling stream; governed by context + watchdog
			Transport: &http.Transport{
				Proxy:                 nil,
				DialContext:           directDialer.DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 20 * time.Second,
			},
		},
	}
}

// NormalizePairingCode strips spaces, hyphens, and non-digit characters from a TV code.
func NormalizePairingCode(code string) string {
	var b strings.Builder
	for _, r := range code {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// PairWithCode exchanges a 12-digit YouTube TV pairing code for a permanent screenId and token.
func (c *LoungeClient) PairWithCode(ctx context.Context, code string) (*PairResult, error) {
	clean := NormalizePairingCode(code)
	if len(clean) < 6 {
		return nil, errors.New("pairing code must contain at least 6 digits (typically 12 digits)")
	}

	form := url.Values{"pairing_code": {clean}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiBase+"/pairing/get_screen", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.controlHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid or expired TV pairing code (HTTP %d)", resp.StatusCode)
	}

	var payload struct {
		Screen struct {
			ScreenID    string `json:"screenId"`
			Name        string `json:"name"`
			LoungeToken string `json:"loungeToken"`
		} `json:"screen"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode pairing response: %w", err)
	}
	if payload.Screen.ScreenID == "" {
		return nil, errors.New("pairing response missing screenId")
	}
	name := strings.TrimSpace(payload.Screen.Name)
	if name == "" {
		name = "Smart TV"
	}
	return &PairResult{
		ScreenID:    payload.Screen.ScreenID,
		Name:        name,
		LoungeToken: payload.Screen.LoungeToken,
	}, nil
}

// RefreshAuth exchanges a permanent screenId for a fresh loungeIdToken.
func (c *LoungeClient) RefreshAuth(ctx context.Context, screenID string) (*PairResult, error) {
	if strings.TrimSpace(screenID) == "" {
		return nil, errors.New("missing screenId")
	}
	form := url.Values{"screen_ids": {screenID}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiBase+"/pairing/get_lounge_token_batch", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.controlHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh lounge token failed (HTTP %d)", resp.StatusCode)
	}

	var payload struct {
		Screens []struct {
			ScreenID    string `json:"screenId"`
			Name        string `json:"name"`
			LoungeToken string `json:"loungeToken"`
		} `json:"screens"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode token batch: %w", err)
	}
	if len(payload.Screens) == 0 || payload.Screens[0].LoungeToken == "" {
		return nil, errors.New("no lounge token returned for screen")
	}
	sc := payload.Screens[0]
	return &PairResult{
		ScreenID:    sc.ScreenID,
		Name:        sc.Name,
		LoungeToken: sc.LoungeToken,
	}, nil
}

// IsAvailable checks whether the paired TV currently has YouTube open / reachable online.
func (c *LoungeClient) IsAvailable(ctx context.Context, loungeToken string) (bool, error) {
	if loungeToken == "" {
		return false, ErrTokenExpired
	}
	form := url.Values{"lounge_token": {loungeToken}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiBase+"/pairing/get_screen_availability", strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.controlHTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return false, ErrTokenExpired
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("availability check HTTP %d", resp.StatusCode)
	}

	var payload struct {
		Screens []struct {
			Status string `json:"status"`
		} `json:"screens"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, err
	}
	return len(payload.Screens) > 0 && payload.Screens[0].Status == "online", nil
}

// Session represents a bound BrowserChannel MDX session to a single Smart TV.
type Session struct {
	client      *LoungeClient
	ScreenID    string
	LoungeToken string
	ClientName  string

	mu          sync.RWMutex
	sid         string
	gsession    string
	lastEventID int64
	screenName  string
	deviceModel string

	cmdMu     sync.Mutex
	cmdOffset int
}

// NewSession constructs a Session for a paired Smart TV.
func (c *LoungeClient) NewSession(screenID, loungeToken string) *Session {
	return &Session{
		client:      c,
		ScreenID:    screenID,
		LoungeToken: loungeToken,
		ClientName:  loungeClientName,
		cmdOffset:   1,
	}
}

// Connected reports whether SID and gsessionid have been established.
func (s *Session) Connected() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sid != "" && s.gsession != ""
}

// ScreenInfo returns the screen name and hardware brand/model reported by the TV.
func (s *Session) ScreenInfo() (screenName, deviceModel string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.screenName, s.deviceModel
}

// EventHandler receives parsed BrowserChannel MDX events.
type EventHandler func(eventType string, args []json.RawMessage)

// Connect binds a new BrowserChannel MDX session with the TV.
func (s *Session) Connect(ctx context.Context, onEvent EventHandler) error {
	if s.LoungeToken == "" {
		return ErrTokenExpired
	}
	form := url.Values{
		"id":            {s.ScreenID},
		"mdx-version":   {"3"},
		"TYPE":          {"xmlhttp"},
		"theme":         {"cl"},
		"sessionSource": {"MDX_SESSION_SOURCE_UNKNOWN"},
		"connectParams": {`{"setStatesParams": "{"playbackSpeed":0}"}`},
		"RID":           {"1"},
		"CVER":          {"1"},
		"capabilities":  {"que,dsdtr,atp,vsp"},
		"ui":            {"false"},
		"app":           {loungeAppName},
		"pairing_type":  {"manual"},
		"VER":           {"8"},
		"loungeIdToken": {s.LoungeToken},
		"device":        {"REMOTE_CONTROL"},
		"name":          {s.ClientName},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.client.apiBase+"/bc/bind", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.controlHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return ErrTokenExpired
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("bind connect HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var procErr error
	err = ParseBrowserChannelStream(resp.Body, func(events [][]json.RawMessage) bool {
		if e := s.processEvents(events, onEvent); e != nil {
			procErr = e
			return false
		}
		return true
	})
	if procErr != nil {
		return procErr
	}
	if err != nil {
		return err
	}

	s.cmdMu.Lock()
	s.cmdOffset = 1
	s.cmdMu.Unlock()

	if !s.Connected() {
		return errors.New("bind succeeded without SID/gsessionid")
	}
	return nil
}

// Subscribe opens the long-lived BrowserChannel event stream with a 65s heartbeat watchdog.
func (s *Session) Subscribe(ctx context.Context, onEvent EventHandler) error {
	if !s.Connected() {
		return ErrSessionGone
	}

	subCtx, cancelSub := context.WithCancel(ctx)
	defer cancelSub()

	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	// Watchdog: YouTube sends a noop or state event at least every 30s.
	watchdogDone := make(chan struct{})
	go func() {
		defer close(watchdogDone)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-subCtx.Done():
				return
			case <-ticker.C:
				elapsed := time.Duration(time.Now().UnixNano() - lastActivity.Load())
				if elapsed > 65*time.Second {
					cancelSub()
					return
				}
			}
		}
	}()

	q := s.commonParams()
	q.Set("RID", "rpc")
	q.Set("CI", "0")
	q.Set("TYPE", "xmlhttp")

	reqURL := s.client.apiBase + "/bc/bind?" + q.Encode()
	req, err := http.NewRequestWithContext(subCtx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}

	resp, err := s.client.streamHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := s.checkHTTPStatus(resp.StatusCode, resp.Status); err != nil {
		return err
	}

	var procErr error
	streamErr := ParseBrowserChannelStream(resp.Body, func(events [][]json.RawMessage) bool {
		lastActivity.Store(time.Now().UnixNano())
		if e := s.processEvents(events, onEvent); e != nil {
			procErr = e
			return false
		}
		return s.Connected()
	})
	cancelSub()
	<-watchdogDone

	if procErr != nil {
		return procErr
	}
	return streamErr
}

func (s *Session) commonParams() url.Values {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return url.Values{
		"name":          {s.ClientName},
		"loungeIdToken": {s.LoungeToken},
		"SID":           {s.sid},
		"AID":           {strconv.FormatInt(s.lastEventID, 10)},
		"gsessionid":    {s.gsession},
		"device":        {"REMOTE_CONTROL"},
		"app":           {loungeAppName},
		"VER":           {"8"},
		"v":             {"2"},
	}
}

func (s *Session) checkHTTPStatus(code int, bodyOrReason string) error {
	if code == http.StatusUnauthorized {
		s.clearSession()
		return ErrTokenExpired
	}
	if code == http.StatusBadRequest || code == http.StatusGone {
		s.clearSession()
		return ErrSessionGone
	}
	if code < 200 || code >= 300 {
		return fmt.Errorf("lounge HTTP %d: %s", code, strings.TrimSpace(bodyOrReason))
	}
	return nil
}

func (s *Session) clearSession() {
	s.mu.Lock()
	s.sid = ""
	s.gsession = ""
	s.lastEventID = 0
	s.mu.Unlock()
}

func (s *Session) processEvents(events [][]json.RawMessage, onEvent EventHandler) error {
	for _, ev := range events {
		if len(ev) < 2 {
			continue
		}
		var eventID int64
		if err := json.Unmarshal(ev[0], &eventID); err == nil {
			s.mu.Lock()
			s.lastEventID = eventID
			s.mu.Unlock()
		}

		var payload []json.RawMessage
		if err := json.Unmarshal(ev[1], &payload); err != nil || len(payload) == 0 {
			continue
		}
		var eventType string
		if err := json.Unmarshal(payload[0], &eventType); err != nil {
			continue
		}
		args := payload[1:]

		switch eventType {
		case "c":
			if len(args) > 0 {
				var sid string
				if json.Unmarshal(args[0], &sid) == nil {
					s.mu.Lock()
					s.sid = sid
					s.mu.Unlock()
				}
			}
		case "S":
			if len(args) > 0 {
				var gsession string
				if json.Unmarshal(args[0], &gsession) == nil {
					s.mu.Lock()
					s.gsession = gsession
					s.mu.Unlock()
				}
			}
		case "loungeStatus":
			if err := s.handleLoungeStatus(args); err != nil {
				s.clearSession()
				return err
			}
			if onEvent != nil {
				onEvent(eventType, args)
			}
		case "loungeScreenDisconnected":
			if onEvent != nil {
				onEvent(eventType, args)
			}
			s.clearSession()
			return ErrDisconnected
		case "noop":
			// Heartbeat keep-alive
		default:
			if onEvent != nil {
				onEvent(eventType, args)
			}
		}
	}
	return nil
}

func (s *Session) handleLoungeStatus(args []json.RawMessage) error {
	if len(args) == 0 {
		return nil
	}
	var data struct {
		Devices string `json:"devices"`
	}
	if err := json.Unmarshal(args[0], &data); err != nil || data.Devices == "" {
		return nil
	}
	var devices []struct {
		Type       string `json:"type"`
		Name       string `json:"name"`
		DeviceInfo string `json:"deviceInfo"`
	}
	if err := json.Unmarshal([]byte(data.Devices), &devices); err != nil {
		return nil
	}
	for _, dev := range devices {
		if dev.Type != "LOUNGE_SCREEN" {
			continue
		}
		var info struct {
			Brand      string `json:"brand"`
			Model      string `json:"model"`
			ClientName string `json:"clientName"`
		}
		if dev.DeviceInfo != "" && dev.DeviceInfo != "null" {
			_ = json.Unmarshal([]byte(dev.DeviceInfo), &info)
		}
		if info.ClientName == "TVHTML5_FOR_KIDS" {
			return ErrUnsupportedClient
		}
		model := strings.TrimSpace(info.Brand + " " + info.Model)
		s.mu.Lock()
		if dev.Name != "" {
			s.screenName = dev.Name
		}
		if model != "" {
			s.deviceModel = model
		}
		s.mu.Unlock()
		break
	}
	return nil
}

// Command sends an MDX RPC command (such as skipAd, setVolume, seekTo) to the connected TV.
func (s *Session) Command(ctx context.Context, command string, params map[string]string) error {
	if !s.Connected() {
		return ErrSessionGone
	}

	s.cmdMu.Lock()
	defer s.cmdMu.Unlock()

	ofs := s.cmdOffset
	s.cmdOffset++
	rid := s.cmdOffset

	form := url.Values{
		"count":    {"1"},
		"ofs":      {strconv.Itoa(ofs)},
		"req0__sc": {command},
	}
	for k, v := range params {
		form.Set("req0_"+k, v)
	}

	q := s.commonParams()
	q.Set("RID", strconv.Itoa(rid))

	reqURL := s.client.apiBase + "/bc/bind?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.controlHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return s.checkHTTPStatus(resp.StatusCode, string(body))
}

// SkipAd instructs the TV to immediately skip a skippable YouTube video ad.
func (s *Session) SkipAd(ctx context.Context) error {
	return s.Command(ctx, "skipAd", nil)
}

// SetVolume updates the TV's YouTube volume (0-100) and mute state.
func (s *Session) SetVolume(ctx context.Context, volume int, muted bool) error {
	if volume < 0 {
		volume = 0
	} else if volume > 100 {
		volume = 100
	}
	muteStr := "false"
	if muted {
		muteStr = "true"
	}
	return s.Command(ctx, "setVolume", map[string]string{
		"volume": strconv.Itoa(volume),
		"muted":  muteStr,
	})
}

// SeekTo jumps playback to newTimeSeconds (used for SponsorBlock segments).
func (s *Session) SeekTo(ctx context.Context, newTimeSeconds float64) error {
	return s.Command(ctx, "seekTo", map[string]string{
		"newTime": strconv.FormatFloat(newTimeSeconds, 'f', 2, 64),
	})
}

// GetNowPlaying requests an immediate nowPlaying status update from the TV.
func (s *Session) GetNowPlaying(ctx context.Context) error {
	return s.Command(ctx, "getNowPlaying", nil)
}

// Disconnect cleanly terminates the remote control session with the TV.
func (s *Session) Disconnect(ctx context.Context) error {
	if !s.Connected() {
		return nil
	}
	s.cmdMu.Lock()
	rid := s.cmdOffset
	s.cmdMu.Unlock()

	form := url.Values{
		"ui":                     {""},
		"TYPE":                   {"terminate"},
		"clientDisconnectReason": {"MDX_SESSION_DISCONNECT_REASON_DISCONNECTED_BY_USER"},
	}
	q := s.commonParams()
	q.Set("CVER", "1")
	q.Set("RID", strconv.Itoa(rid))
	q.Set("auth_failure_option", "send_error")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.client.apiBase+"/bc/bind?"+q.Encode(), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.controlHTTP.Do(req)
	if err == nil {
		resp.Body.Close()
	}
	s.clearSession()
	return err
}

// ParseBrowserChannelStream parses Google BrowserChannel length-prefixed JSON chunks.
// It counts UTF-16 code units (JavaScript string length) and verifies JSON array validity
// so surrogate pairs (emojis in video/ad titles) or embedded newlines never lose framing.
func ParseBrowserChannelStream(r io.Reader, onChunk func(events [][]json.RawMessage) bool) error {
	br := bufio.NewReaderSize(r, 64*1024)
	chunkRemaining := 0
	var buf strings.Builder

	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			clean := strings.TrimRight(line, "\r\n")
			if chunkRemaining <= 0 {
				trimmed := strings.TrimSpace(clean)
				if trimmed != "" {
					if n, perr := strconv.Atoi(trimmed); perr == nil && n > 0 {
						chunkRemaining = n
						buf.Reset()
					}
				}
			} else {
				// If a previous chunk miscounted units and clean is actually the next chunk's length header
				if trimmed := strings.TrimSpace(clean); isDigitsOnly(trimmed) && buf.Len() > 0 && json.Valid([]byte(buf.String())) {
					if !emitChunk(buf.String(), onChunk) {
						return nil
					}
					n, _ := strconv.Atoi(trimmed)
					chunkRemaining = n
					buf.Reset()
				} else {
					if buf.Len() > 0 {
						buf.WriteByte('\n')
					}
					buf.WriteString(clean)
					// BrowserChannel length counts UTF-16 code units including trailing '\n'
					u16Len := len(utf16.Encode([]rune(clean))) + 1
					chunkRemaining -= u16Len

					if chunkRemaining <= 0 || (strings.HasPrefix(strings.TrimSpace(buf.String()), "[") && json.Valid([]byte(buf.String()))) {
						raw := buf.String()
						if json.Valid([]byte(raw)) {
							chunkRemaining = 0
							buf.Reset()
							if !emitChunk(raw, onChunk) {
								return nil
							}
						} else if chunkRemaining <= -16 {
							// Malformed frame guard: reset and await next length prefix
							chunkRemaining = 0
							buf.Reset()
						}
					}
				}
			}
		}

		if err != nil {
			if buf.Len() > 0 && json.Valid([]byte(buf.String())) {
				emitChunk(buf.String(), onChunk)
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func emitChunk(raw string, onChunk func(events [][]json.RawMessage) bool) bool {
	var events [][]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &events); err != nil || len(events) == 0 {
		return true
	}
	return onChunk(events)
}

func isDigitsOnly(s string) bool {
	if s == "" || len(s) > 9 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
