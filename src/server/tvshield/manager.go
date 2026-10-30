package tvshield

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sinkhole/src/config"
)

// TVEvent records an automated ad-skip, mute, or SponsorBlock jump on a Smart TV.
type TVEvent struct {
	TS         int64  `json:"ts"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Action     string `json:"action"` // "ad_skipped" | "ad_muted" | "ad_unmuted" | "sponsor_skipped" | "connected"
	Details    string `json:"details"`
}

// DeviceRuntimeStatus exposes real-time connection and protection metrics for one TV.
type DeviceRuntimeStatus struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	ScreenID          string `json:"screen_id"`
	Platform          string `json:"platform"`
	IP                string `json:"ip,omitempty"`
	Enabled           bool   `json:"enabled"`
	State             string `json:"state"` // "standby" | "connecting" | "connected" | "playing" | "ad_muted" | "disabled"
	ScreenName        string `json:"screen_name,omitempty"`
	DeviceModel       string `json:"device_model,omitempty"`
	NowPlayingVideoID string `json:"now_playing_video_id,omitempty"`
	AdsSkipped        int64  `json:"ads_skipped"`
	AdsMuted          int64  `json:"ads_muted"`
	SponsorsSkipped   int64  `json:"sponsors_skipped"`
	LastSeen          int64  `json:"last_seen,omitempty"`
	LastAction        string `json:"last_action,omitempty"`
}

// StatusSnapshot is returned by GET /api/tv/status.
type StatusSnapshot struct {
	Enabled              bool                  `json:"enabled"`
	SkipAds              bool                  `json:"skip_ads"`
	MuteAds              bool                  `json:"mute_ads"`
	SponsorBlock         bool                  `json:"sponsor_block"`
	Categories           []string              `json:"categories"`
	TotalAdsSkipped      int64                 `json:"total_ads_skipped"`
	TotalAdsMuted        int64                 `json:"total_ads_muted"`
	TotalSponsorsSkipped int64                 `json:"total_sponsors_skipped"`
	Devices              []DeviceRuntimeStatus `json:"devices"`
	RecentEvents         []TVEvent             `json:"recent_events"`
}

// Manager coordinates concurrent YouTube Lounge listeners across multiple Smart TVs.
type Manager struct {
	log     *slog.Logger
	lounge  *LoungeClient
	sb      *SponsorBlockClient
	onEvent func(TVEvent)

	mu      sync.RWMutex
	rootCtx context.Context
	cancel  context.CancelFunc
	cfg     config.TVShieldConfig
	workers map[string]*deviceWorker
	metrics map[string]*deviceMetrics
	events  []TVEvent

	totalAdsSkipped      atomic.Int64
	totalAdsMuted        atomic.Int64
	totalSponsorsSkipped atomic.Int64
}

type deviceMetrics struct {
	adsSkipped      atomic.Int64
	adsMuted        atomic.Int64
	sponsorsSkipped atomic.Int64
}

// NewManager creates a multi-TV YouTube Lounge & SponsorBlock manager.
func NewManager(log *slog.Logger, onEvent func(TVEvent)) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		log:     log,
		lounge:  NewLoungeClient(),
		sb:      NewSponsorBlockClient(),
		onEvent: onEvent,
		workers: make(map[string]*deviceWorker),
		metrics: make(map[string]*deviceMetrics),
	}
}

// Start begins monitoring all configured & enabled Smart TVs.
func (m *Manager) Start(parent context.Context, cfg config.TVShieldConfig) {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	m.rootCtx, m.cancel = context.WithCancel(parent)
	m.mu.Unlock()

	m.Configure(cfg)
}

// Stop disconnects all active Smart TV sessions cleanly.
func (m *Manager) Stop() {
	m.mu.Lock()
	cancel := m.cancel
	m.cancel = nil
	workers := make([]*deviceWorker, 0, len(m.workers))
	for _, w := range m.workers {
		workers = append(workers, w)
	}
	m.workers = make(map[string]*deviceWorker)
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	for _, w := range workers {
		w.stop()
	}
}

// Configure hot-reloads TV Shield settings and reconciles per-TV worker goroutines.
func (m *Manager) Configure(cfg config.TVShieldConfig) {
	m.mu.Lock()
	m.cfg = cfg
	rootCtx := m.rootCtx
	if rootCtx == nil {
		m.mu.Unlock()
		return
	}

	desired := make(map[string]config.TVDeviceConfig)
	if cfg.Enabled {
		for _, dev := range cfg.Devices {
			if dev.Enabled && dev.ScreenID != "" {
				id := dev.ID
				if id == "" {
					id = dev.ScreenID
					dev.ID = id
				}
				desired[id] = dev
			}
		}
	}

	var toStop []*deviceWorker
	for id, w := range m.workers {
		devCfg, ok := desired[id]
		if !ok || w.screenID != devCfg.ScreenID {
			toStop = append(toStop, w)
			delete(m.workers, id)
			continue
		}
		w.updateDeviceMeta(devCfg)
	}

	for id, devCfg := range desired {
		if _, exists := m.workers[id]; exists {
			continue
		}
		met, ok := m.metrics[id]
		if !ok {
			met = &deviceMetrics{}
			m.metrics[id] = met
		}
		w := newDeviceWorker(rootCtx, m, devCfg, met)
		m.workers[id] = w
		go w.run()
	}
	m.mu.Unlock()

	for _, w := range toStop {
		w.stop()
	}
}

// Discover scans the local Wi-Fi/LAN via SSDP/DIAL and annotates already-paired TVs.
func (m *Manager) Discover(ctx context.Context, paired []config.TVDeviceConfig) ([]DiscoveredTV, error) {
	found, err := DiscoverLAN(ctx, 3500*time.Millisecond)
	if err != nil {
		return nil, err
	}
	pairedScreens := make(map[string]bool)
	pairedIPs := make(map[string]bool)
	for _, p := range paired {
		if p.ScreenID != "" {
			pairedScreens[p.ScreenID] = true
		}
		if p.IP != "" {
			pairedIPs[p.IP] = true
		}
	}
	for i := range found {
		if (found[i].ScreenID != "" && pairedScreens[found[i].ScreenID]) ||
			(found[i].IP != "" && pairedIPs[found[i].IP] && found[i].ScreenID == "") {
			found[i].AlreadyPaired = true
		}
	}
	return found, nil
}

// PairByCode pairs a Smart TV using a 12-digit "Link with TV code" from the YouTube TV app.
func (m *Manager) PairByCode(ctx context.Context, code, customName, platform string) (config.TVDeviceConfig, error) {
	res, err := m.lounge.PairWithCode(ctx, code)
	if err != nil {
		return config.TVDeviceConfig{}, err
	}
	name := strings.TrimSpace(customName)
	if name == "" {
		name = res.Name
	}
	plat := strings.TrimSpace(platform)
	if plat == "" {
		plat = classifyTVPlatform(name, "", "", "")
	}
	return config.TVDeviceConfig{
		ID:          res.ScreenID,
		Name:        name,
		ScreenID:    res.ScreenID,
		LoungeToken: res.LoungeToken,
		Platform:    plat,
		Enabled:     true,
		AddedAt:     time.Now().UnixMilli(),
	}, nil
}

// PairByDIAL pairs a discovered Smart TV via its passive screenId or active DIAL app launch.
func (m *Manager) PairByDIAL(ctx context.Context, dialAppURL, screenID, customName, platform, ip string) (config.TVDeviceConfig, error) {
	var res *PairResult
	var err error

	if strings.TrimSpace(screenID) != "" {
		res, err = m.lounge.RefreshAuth(ctx, strings.TrimSpace(screenID))
	}
	if res == nil && strings.TrimSpace(dialAppURL) != "" {
		res, err = LaunchAndPairDIAL(ctx, dialAppURL, m.lounge)
	}
	if err != nil {
		return config.TVDeviceConfig{}, err
	}
	if res == nil {
		return config.TVDeviceConfig{}, errors.New("missing pairing target (provide pairing_code or dial_app_url)")
	}

	name := strings.TrimSpace(customName)
	if name == "" {
		name = res.Name
	}
	if name == "" {
		name = "Smart TV"
	}
	plat := strings.TrimSpace(platform)
	if plat == "" {
		plat = classifyTVPlatform(name, "", "", "")
	}
	return config.TVDeviceConfig{
		ID:          res.ScreenID,
		Name:        name,
		ScreenID:    res.ScreenID,
		LoungeToken: res.LoungeToken,
		Platform:    plat,
		IP:          strings.TrimSpace(ip),
		Enabled:     true,
		AddedAt:     time.Now().UnixMilli(),
	}, nil
}

// Status returns a live snapshot of all configured TVs, global counters, and recent actions.
func (m *Manager) Status(cfg config.TVShieldConfig) StatusSnapshot {
	m.mu.RLock()
	workers := make(map[string]*deviceWorker, len(m.workers))
	for k, v := range m.workers {
		workers[k] = v
	}
	metrics := make(map[string]*deviceMetrics, len(m.metrics))
	for k, v := range m.metrics {
		metrics[k] = v
	}
	evCopy := make([]TVEvent, len(m.events))
	copy(evCopy, m.events)
	m.mu.RUnlock()

	devs := make([]DeviceRuntimeStatus, 0, len(cfg.Devices))
	for _, d := range cfg.Devices {
		id := d.ID
		if id == "" {
			id = d.ScreenID
		}
		st := DeviceRuntimeStatus{
			ID:       id,
			Name:     d.Name,
			ScreenID: d.ScreenID,
			Platform: d.Platform,
			IP:       d.IP,
			Enabled:  d.Enabled,
			State:    "disabled",
		}
		if met, ok := metrics[id]; ok {
			st.AdsSkipped = met.adsSkipped.Load()
			st.AdsMuted = met.adsMuted.Load()
			st.SponsorsSkipped = met.sponsorsSkipped.Load()
		}
		if cfg.Enabled && d.Enabled {
			if w, ok := workers[id]; ok {
				w.fillStatus(&st)
			} else {
				st.State = "standby"
			}
		}
		devs = append(devs, st)
	}

	cats := cfg.Categories
	if cats == nil {
		cats = []string{}
	}
	if evCopy == nil {
		evCopy = []TVEvent{}
	}

	return StatusSnapshot{
		Enabled:              cfg.Enabled,
		SkipAds:              cfg.SkipAds,
		MuteAds:              cfg.MuteAds,
		SponsorBlock:         cfg.SponsorBlock,
		Categories:           cats,
		TotalAdsSkipped:      m.totalAdsSkipped.Load(),
		TotalAdsMuted:        m.totalAdsMuted.Load(),
		TotalSponsorsSkipped: m.totalSponsorsSkipped.Load(),
		Devices:              devs,
		RecentEvents:         evCopy,
	}
}

func (m *Manager) currentPolicy() (skipAds, muteAds, sponsorBlock bool, categories []string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cats := append([]string(nil), m.cfg.Categories...)
	return m.cfg.SkipAds, m.cfg.MuteAds, m.cfg.SponsorBlock, cats
}

func (m *Manager) recordEvent(ev TVEvent) {
	ev.TS = time.Now().UnixMilli()
	m.mu.Lock()
	m.events = append([]TVEvent{ev}, m.events...)
	if len(m.events) > 50 {
		m.events = m.events[:50]
	}
	cb := m.onEvent
	m.mu.Unlock()

	if cb != nil {
		cb(ev)
	}
}

// ---------------------------------------------------------------- per-TV worker

type deviceWorker struct {
	mgr      *Manager
	metrics  *deviceMetrics
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	id       string
	screenID string

	mu            sync.Mutex
	name          string
	platform      string
	ip            string
	loungeToken   string
	state         string
	screenName    string
	deviceModel   string
	currentVideo  string
	lastSeen      int64
	lastAction    string
	savedVolume   int
	tvMuted       bool
	mutedByShield bool
	adActive      bool
	playbackSpeed float64
	lastAdSkipAt  time.Time
	lastSeekKey   string
	lastSeekAt    time.Time
	seekTimer     *time.Timer
	adSkipTimer   *time.Timer
	activeSess    *Session
}

func newDeviceWorker(parent context.Context, mgr *Manager, dev config.TVDeviceConfig, met *deviceMetrics) *deviceWorker {
	ctx, cancel := context.WithCancel(parent)
	id := dev.ID
	if id == "" {
		id = dev.ScreenID
	}
	return &deviceWorker{
		mgr:           mgr,
		metrics:       met,
		ctx:           ctx,
		cancel:        cancel,
		done:          make(chan struct{}),
		id:            id,
		screenID:      dev.ScreenID,
		name:          dev.Name,
		platform:      dev.Platform,
		ip:            dev.IP,
		loungeToken:   dev.LoungeToken,
		state:         "connecting",
		savedVolume:   50,
		playbackSpeed: 1.0,
	}
}

func (w *deviceWorker) stop() {
	w.cancel()
	w.mu.Lock()
	w.clearTimersLocked()
	sess := w.activeSess
	w.mu.Unlock()
	if sess != nil {
		dctx, dcancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		_ = sess.Disconnect(dctx)
		dcancel()
	}
	<-w.done
}

func (w *deviceWorker) updateDeviceMeta(dev config.TVDeviceConfig) {
	w.mu.Lock()
	if dev.Name != "" {
		w.name = dev.Name
	}
	if dev.Platform != "" {
		w.platform = dev.Platform
	}
	if dev.IP != "" {
		w.ip = dev.IP
	}
	w.mu.Unlock()
}

func (w *deviceWorker) fillStatus(st *DeviceRuntimeStatus) {
	w.mu.Lock()
	defer w.mu.Unlock()
	st.State = w.state
	st.ScreenName = w.screenName
	st.DeviceModel = w.deviceModel
	st.NowPlayingVideoID = w.currentVideo
	st.LastSeen = w.lastSeen
	st.LastAction = w.lastAction
	if st.Platform == "" || st.Platform == "Smart TV" {
		if w.deviceModel != "" {
			st.Platform = classifyTVPlatform(w.name, "", w.deviceModel, "")
		}
	}
}

func (w *deviceWorker) clearTimersLocked() {
	if w.seekTimer != nil {
		w.seekTimer.Stop()
		w.seekTimer = nil
	}
	if w.adSkipTimer != nil {
		w.adSkipTimer.Stop()
		w.adSkipTimer = nil
	}
}

func (w *deviceWorker) run() {
	defer close(w.done)

	lastTokenRefresh := time.Now()

	for {
		if w.ctx.Err() != nil {
			return
		}

		w.mu.Lock()
		token := w.loungeToken
		w.mu.Unlock()

		if token == "" || time.Since(lastTokenRefresh) > 12*time.Hour {
			res, err := w.mgr.lounge.RefreshAuth(w.ctx, w.screenID)
			if err != nil {
				w.setState("standby", "Waiting to refresh YouTube TV token")
				if !w.sleep(10 * time.Second) {
					return
				}
				continue
			}
			token = res.LoungeToken
			lastTokenRefresh = time.Now()
			w.mu.Lock()
			w.loungeToken = token
			if w.screenName == "" && res.Name != "" {
				w.screenName = res.Name
			}
			w.mu.Unlock()
		}

		online, err := w.mgr.lounge.IsAvailable(w.ctx, token)
		if errors.Is(err, ErrTokenExpired) {
			w.mu.Lock()
			w.loungeToken = ""
			w.mu.Unlock()
			continue
		}
		if err != nil || !online {
			w.setState("standby", "TV YouTube app in standby")
			if !w.sleep(8 * time.Second) {
				return
			}
			continue
		}

		w.setState("connecting", "Connecting to YouTube on TV...")
		sess := w.mgr.lounge.NewSession(w.screenID, token)

		err = sess.Connect(w.ctx, func(evType string, args []json.RawMessage) {
			w.handleEvent(sess, evType, args)
		})
		if errors.Is(err, ErrTokenExpired) {
			w.mu.Lock()
			w.loungeToken = ""
			w.mu.Unlock()
			continue
		}
		if errors.Is(err, ErrUnsupportedClient) {
			w.setState("standby", "YouTube Kids profile active (unsupported)")
			if !w.sleep(20 * time.Second) {
				return
			}
			continue
		}
		if err != nil {
			w.setState("standby", "Waiting for TV session")
			if !w.sleep(8 * time.Second) {
				return
			}
			continue
		}

		scName, devModel := sess.ScreenInfo()
		w.mu.Lock()
		w.activeSess = sess
		if scName != "" {
			w.screenName = scName
		}
		if devModel != "" {
			w.deviceModel = devModel
		}
		if w.state == "connecting" || w.state == "standby" {
			w.state = "connected"
		}
		w.lastSeen = time.Now().UnixMilli()
		w.lastAction = "Connected & monitoring for ads"
		devDisplay := w.name
		w.mu.Unlock()

		w.mgr.log.Info("TV Shield connected", "tv", devDisplay, "model", devModel)
		w.mgr.recordEvent(TVEvent{
			DeviceID:   w.id,
			DeviceName: devDisplay,
			Action:     "connected",
			Details:    "Connected to YouTube Lounge session",
		})

		go func() {
			cctx, cancel := context.WithTimeout(w.ctx, 5*time.Second)
			defer cancel()
			_ = sess.GetNowPlaying(cctx)
		}()

		subErr := sess.Subscribe(w.ctx, func(evType string, args []json.RawMessage) {
			w.handleEvent(sess, evType, args)
		})

		w.mu.Lock()
		w.clearTimersLocked()
		w.activeSess = nil
		w.adActive = false
		if errors.Is(subErr, ErrTokenExpired) {
			w.loungeToken = ""
		}
		w.mu.Unlock()

		if w.ctx.Err() != nil {
			return
		}
		w.setState("standby", "Disconnected — awaiting TV activity")
		if !w.sleep(3 * time.Second) {
			return
		}
	}
}

func (w *deviceWorker) setState(state, action string) {
	w.mu.Lock()
	w.state = state
	if action != "" {
		w.lastAction = action
	}
	w.mu.Unlock()
}

func (w *deviceWorker) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-w.ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (w *deviceWorker) handleEvent(sess *Session, eventType string, args []json.RawMessage) {
	nowMs := time.Now().UnixMilli()
	w.mu.Lock()
	w.lastSeen = nowMs
	if scName, devModel := sess.ScreenInfo(); scName != "" || devModel != "" {
		if scName != "" {
			w.screenName = scName
		}
		if devModel != "" {
			w.deviceModel = devModel
		}
	}
	w.mu.Unlock()

	if len(args) == 0 {
		return
	}
	var data map[string]any
	if err := json.Unmarshal(args[0], &data); err != nil {
		return
	}

	skipAds, muteAds, sbEnabled, sbCats := w.mgr.currentPolicy()

	switch eventType {
	case "onVolumeChanged":
		vol := asInt(data["volume"], -1)
		muted := asBool(data["muted"])
		w.mu.Lock()
		w.tvMuted = muted
		if !muted {
			w.mutedByShield = false
		}
		if vol > 0 || (vol == 0 && !w.mutedByShield) {
			w.savedVolume = vol
		}
		w.mu.Unlock()

	case "onPlaybackSpeedChanged":
		if spd := asFloat(data["playbackSpeed"], 1.0); spd >= 0.25 && spd <= 4.0 {
			w.mu.Lock()
			w.playbackSpeed = spd
			w.mu.Unlock()
		}

	case "autoplayUpNext":
		if vid := asString(data["videoId"]); sbEnabled && vid != "" {
			go func() {
				pctx, cancel := context.WithTimeout(w.ctx, 8*time.Second)
				defer cancel()
				_, _ = w.mgr.sb.GetSegments(pctx, vid, sbCats)
			}()
		}

	case "adPlaying":
		contentVid := asString(data["contentVideoId"])
		if sbEnabled && contentVid != "" {
			go func() {
				pctx, cancel := context.WithTimeout(w.ctx, 8*time.Second)
				defer cancel()
				_, _ = w.mgr.sb.GetSegments(pctx, contentVid, sbCats)
			}()
		}

		skipEnabled := asBool(data["isSkipEnabled"])
		skippable := asBool(data["isSkippable"])
		adTitle := asString(data["adTitle"])

		w.mu.Lock()
		w.adActive = true
		if w.seekTimer != nil {
			w.seekTimer.Stop()
			w.seekTimer = nil
		}
		if w.adSkipTimer != nil {
			w.adSkipTimer.Stop()
			w.adSkipTimer = nil
		}
		if skipAds && !skipEnabled && skippable {
			// Fallback timer for Samsung Tizen / Google TV builds that delay onAdStateChange
			w.adSkipTimer = time.AfterFunc(5200*time.Millisecond, func() {
				w.mu.Lock()
				stillAd := w.adActive
				w.mu.Unlock()
				if stillAd {
					w.triggerSkipAd(sess, adTitle)
				}
			})
		}
		w.mu.Unlock()

		if skipAds && skipEnabled {
			go w.triggerSkipAd(sess, adTitle)
		} else if muteAds {
			go w.triggerMuteAd(sess, true, adTitle)
		}

	case "onAdStateChange":
		adState := asString(data["adState"])
		curTime := asString(data["currentTime"])
		skipEnabled := asBool(data["isSkipEnabled"])

		if adState == "0" && curTime != "0" && curTime != "" {
			w.mu.Lock()
			w.adActive = false
			if w.adSkipTimer != nil {
				w.adSkipTimer.Stop()
				w.adSkipTimer = nil
			}
			w.mu.Unlock()
			go w.triggerMuteAd(sess, false, "")
		} else if skipAds && skipEnabled {
			w.mu.Lock()
			if w.adSkipTimer != nil {
				w.adSkipTimer.Stop()
				w.adSkipTimer = nil
			}
			w.mu.Unlock()
			go w.triggerSkipAd(sess, "")
		} else if muteAds && adState != "0" {
			w.mu.Lock()
			w.adActive = true
			w.mu.Unlock()
			go w.triggerMuteAd(sess, true, "")
		}

	case "nowPlaying", "onStateChange":
		state := asString(data["state"])
		vid := asString(data["videoId"])
		curTime, hasTime := optionalFloat(data["currentTime"])
		eventReceived := time.Now()

		w.mu.Lock()
		if vid != "" {
			w.currentVideo = vid
		} else if eventType == "nowPlaying" {
			if _, exists := data["videoId"]; exists {
				w.currentVideo = ""
			}
		}
		activeVid := w.currentVideo
		if w.seekTimer != nil {
			w.seekTimer.Stop()
			w.seekTimer = nil
		}

		if state == "1" {
			w.adActive = false
			if w.adSkipTimer != nil {
				w.adSkipTimer.Stop()
				w.adSkipTimer = nil
			}
			w.state = "playing"
		} else if !w.adActive {
			w.state = "connected"
		}
		needUnmute := state == "1" && w.mutedByShield
		w.mu.Unlock()

		if needUnmute {
			go w.triggerMuteAd(sess, false, "")
		}
		if state == "1" && sbEnabled && activeVid != "" && hasTime {
			go w.scheduleSponsorSkip(sess, activeVid, curTime, sbCats, eventReceived)
		}
	}
}

func (w *deviceWorker) triggerSkipAd(sess *Session, adTitle string) {
	w.mu.Lock()
	if time.Since(w.lastAdSkipAt) < 900*time.Millisecond {
		w.mu.Unlock()
		return
	}
	w.lastAdSkipAt = time.Now()
	w.adActive = false
	needUnmute := w.mutedByShield
	vol := w.savedVolume
	if needUnmute {
		w.mutedByShield = false
		w.tvMuted = false
	}
	w.state = "playing"
	devName := w.name
	detail := "Auto-skipped YouTube TV ad"
	if adTitle != "" {
		detail = fmt.Sprintf("Auto-skipped ad (%s)", adTitle)
	}
	w.lastAction = detail
	w.mu.Unlock()

	cctx, cancel := context.WithTimeout(w.ctx, 5*time.Second)
	defer cancel()

	if err := sess.SkipAd(cctx); err != nil {
		w.mgr.log.Debug("skipAd failed", "tv", devName, "err", err)
		return
	}
	if needUnmute {
		_ = sess.SetVolume(cctx, vol, false)
	}

	w.metrics.adsSkipped.Add(1)
	w.mgr.totalAdsSkipped.Add(1)
	w.mgr.log.Info("Skipped YouTube TV ad", "tv", devName)
	w.mgr.recordEvent(TVEvent{
		DeviceID:   w.id,
		DeviceName: devName,
		Action:     "ad_skipped",
		Details:    detail,
	})
}

func (w *deviceWorker) triggerMuteAd(sess *Session, mute bool, adTitle string) {
	w.mu.Lock()
	devName := w.name
	vol := w.savedVolume
	if mute {
		if w.mutedByShield || w.tvMuted {
			w.mu.Unlock()
			return
		}
		w.mutedByShield = true
		w.tvMuted = true
		w.state = "ad_muted"
		detail := "Auto-muted unskippable ad"
		if adTitle != "" {
			detail = fmt.Sprintf("Auto-muted ad (%s)", adTitle)
		}
		w.lastAction = detail
		w.mu.Unlock()

		cctx, cancel := context.WithTimeout(w.ctx, 5*time.Second)
		defer cancel()
		if err := sess.SetVolume(cctx, vol, true); err == nil {
			w.metrics.adsMuted.Add(1)
			w.mgr.totalAdsMuted.Add(1)
			w.mgr.recordEvent(TVEvent{
				DeviceID:   w.id,
				DeviceName: devName,
				Action:     "ad_muted",
				Details:    detail,
			})
		}
		return
	}

	// Unmute only if Sinkhole muted it for an ad
	if !w.mutedByShield {
		w.mu.Unlock()
		return
	}
	w.mutedByShield = false
	w.tvMuted = false
	if w.state == "ad_muted" {
		w.state = "playing"
	}
	w.lastAction = fmt.Sprintf("Restored TV volume (%d%%) after ad", vol)
	w.mu.Unlock()

	cctx, cancel := context.WithTimeout(w.ctx, 5*time.Second)
	defer cancel()
	_ = sess.SetVolume(cctx, vol, false)
}

func (w *deviceWorker) scheduleSponsorSkip(sess *Session, videoID string, position float64, categories []string, eventAt time.Time) {
	sctx, cancel := context.WithTimeout(w.ctx, 8*time.Second)
	segs, err := w.mgr.sb.GetSegments(sctx, videoID, categories)
	cancel()
	if err != nil || len(segs) == 0 {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.currentVideo != videoID || w.adActive || w.state != "playing" {
		return
	}

	elapsed := time.Since(eventAt).Seconds() * w.playbackSpeed
	nowPos := position + elapsed

	var next *Segment
	for i := range segs {
		s := &segs[i]
		seekKey := fmt.Sprintf("%s:%.1f", videoID, s.End)
		if w.lastSeekKey == seekKey && time.Since(w.lastSeekAt) < 5*time.Second {
			continue
		}
		if (nowPos >= s.Start && nowPos < s.End-0.75) || s.Start > nowPos {
			next = s
			break
		}
	}
	if next == nil {
		return
	}

	delaySec := 0.05
	if next.Start > nowPos {
		delaySec = (next.Start - nowPos) / math.Max(w.playbackSpeed, 0.25)
	}
	targetEnd := next.End
	category := next.Category
	targetStart := next.Start

	if w.seekTimer != nil {
		w.seekTimer.Stop()
	}
	w.seekTimer = time.AfterFunc(time.Duration(delaySec*float64(time.Second)), func() {
		w.executeSponsorSeek(sess, videoID, targetStart, targetEnd, category)
	})
}

func (w *deviceWorker) executeSponsorSeek(sess *Session, videoID string, segStart, segEnd float64, category string) {
	seekKey := fmt.Sprintf("%s:%.1f", videoID, segEnd)
	w.mu.Lock()
	if w.currentVideo != videoID || w.adActive || w.state != "playing" {
		w.mu.Unlock()
		return
	}
	if w.lastSeekKey == seekKey && time.Since(w.lastSeekAt) < 5*time.Second {
		w.mu.Unlock()
		return
	}
	w.lastSeekKey = seekKey
	w.lastSeekAt = time.Now()
	devName := w.name
	detail := fmt.Sprintf("Skipped %s segment (%.0fs → %.0fs)", category, segStart, segEnd)
	w.lastAction = detail
	w.mu.Unlock()

	cctx, cancel := context.WithTimeout(w.ctx, 5*time.Second)
	defer cancel()
	if err := sess.SeekTo(cctx, segEnd); err == nil {
		w.metrics.sponsorsSkipped.Add(1)
		w.mgr.totalSponsorsSkipped.Add(1)
		w.mgr.log.Info("Skipped SponsorBlock segment on TV", "tv", devName, "video", videoID, "to", segEnd)
		w.mgr.recordEvent(TVEvent{
			DeviceID:   w.id,
			DeviceName: devName,
			Action:     "sponsor_skipped",
			Details:    detail,
		})
	}
}

// ---------------------------------------------------------------- JSON value helpers

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		if x {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func asBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(strings.TrimSpace(x), "true") || strings.TrimSpace(x) == "1"
	case float64:
		return x != 0
	default:
		return false
	}
}

func asInt(v any, def int) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return n
		}
		if f, err := strconv.ParseFloat(strings.TrimSpace(x), 64); err == nil {
			return int(f)
		}
	}
	return def
}

func asFloat(v any, def float64) float64 {
	if f, ok := optionalFloat(v); ok {
		return f
	}
	return def
}

func optionalFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(s, 64)
		return f, err == nil
	default:
		return 0, false
	}
}
