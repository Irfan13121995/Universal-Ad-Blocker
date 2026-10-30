package tvshield

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"sinkhole/src/config"
)

func formatBCChunk(body string) string {
	u16Len := len(utf16.Encode([]rune(body))) + 1
	return fmt.Sprintf("%d\n%s\n", u16Len, body)
}

func TestNormalizePairingCode(t *testing.T) {
	got := NormalizePairingCode(" 482-910 334-129 ")
	if got != "482910334129" {
		t.Fatalf("expected 482910334129, got %q", got)
	}
}

func TestHashPrefix(t *testing.T) {
	// SHA-256("dQw4w9WgXcQ") starts with "3f9a..." or deterministic 4-hex chars
	p := HashPrefix("dQw4w9WgXcQ")
	if len(p) != 4 {
		t.Fatalf("expected 4 hex chars, got %q", p)
	}
}

func TestMergeSegments(t *testing.T) {
	raw := []rawSBSegment{
		{Segment: [2]float64{10.0, 20.0}, UUID: "u1", Category: "sponsor", Locked: 1},
		{Segment: [2]float64{19.5, 30.0}, UUID: "u2", Category: "sponsor", Locked: 1},   // overlaps u1
		{Segment: [2]float64{30.6, 35.0}, UUID: "u3", Category: "selfpromo", Locked: 1}, // <1s apart -> merges
		{Segment: [2]float64{80.0, 80.2}, UUID: "u4", Category: "intro", Locked: 0},     // <0.5s -> dropped
		{Segment: [2]float64{90.0, 105.0}, UUID: "u5", Category: "outro", Locked: 1},
	}

	merged, locked := MergeSegments(raw, 0.5)
	if locked {
		t.Fatalf("expected locked=false due to u4")
	}
	if len(merged) != 2 {
		t.Fatalf("expected 2 merged segments, got %d: %+v", len(merged), merged)
	}
	if merged[0].Start != 10.0 || merged[0].End != 35.0 || len(merged[0].UUIDs) != 3 {
		t.Fatalf("unexpected first merged segment: %+v", merged[0])
	}
	if merged[1].Start != 90.0 || merged[1].End != 105.0 {
		t.Fatalf("unexpected second segment: %+v", merged[1])
	}
}

func TestParseBrowserChannelStreamWithEmojis(t *testing.T) {
	chunk1 := `[[0,["c","SID_ABC123","null",8]],[1,["S","GSESS_XYZ789"]]]`
	chunk2 := `[[2,["adPlaying",{"adTitle":"Mega Sale 🔥🚀🎉","contentVideoId":"vid123","isSkipEnabled":"true"}]]]`

	stream := formatBCChunk(chunk1) + formatBCChunk(chunk2)

	var gotTypes []string
	err := ParseBrowserChannelStream(strings.NewReader(stream), func(events [][]json.RawMessage) bool {
		for _, ev := range events {
			var payload []json.RawMessage
			_ = json.Unmarshal(ev[1], &payload)
			var typ string
			_ = json.Unmarshal(payload[0], &typ)
			gotTypes = append(gotTypes, typ)
		}
		return true
	})
	if err != nil {
		t.Fatalf("ParseBrowserChannelStream failed: %v", err)
	}
	want := []string{"c", "S", "adPlaying"}
	if len(gotTypes) != len(want) {
		t.Fatalf("expected %v, got %v", want, gotTypes)
	}
	for i := range want {
		if gotTypes[i] != want[i] {
			t.Fatalf("at %d: expected %q, got %q", i, want[i], gotTypes[i])
		}
	}
}

func TestDIALXMLAndPlatformClassify(t *testing.T) {
	xmlData := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<service xmlns="urn:dial-multiscreen-org:schemas:dial">
  <name>YouTube</name>
  <state>running</state>
  <additionalData>
    <yt:screenId>screen_tizen_999</yt:screenId>
  </additionalData>
</service>`)
	sid, state := parseDIALYouTubeXML(xmlData)
	if sid != "screen_tizen_999" || state != "running" {
		t.Fatalf("unexpected DIAL parse: sid=%q state=%q", sid, state)
	}

	if got := classifyTVPlatform("65\" QN90B", "Samsung Electronics", "QN65QN90BAFXZA", "Tizen"); got != "Samsung Tizen" {
		t.Fatalf("expected Samsung Tizen, got %q", got)
	}
	if got := classifyTVPlatform("Living Room TV", "Sony", "BRAVIA 4K VH2", ""); got != "Google TV / Android TV" {
		t.Fatalf("expected Google TV / Android TV, got %q", got)
	}
}

func TestEndToEndLoungeSkipMuteAndSponsorBlock(t *testing.T) {
	var (
		mu       sync.Mutex
		commands []string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pairing/get_screen":
			_ = r.ParseForm()
			if r.Form.Get("pairing_code") != "111222333444" {
				http.Error(w, "bad code", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"screen": map[string]string{
					"screenId":    "scr_1",
					"name":        "Samsung QLED 65",
					"loungeToken": "tok_1",
				},
			})

		case "/bc/bind":
			if r.Method == http.MethodPost && r.URL.Query().Get("SID") == "" {
				// Initial Connect()
				body := `[[0,["c","sid_live"]],[1,["S","gsess_live"]],[2,["onVolumeChanged",{"volume":"35","muted":"false"}]]]`
				_, _ = w.Write([]byte(formatBCChunk(body)))
				return
			}
			if r.Method == http.MethodPost {
				// Command()
				_ = r.ParseForm()
				sc := r.Form.Get("req0__sc")
				if sc == "setVolume" {
					sc = fmt.Sprintf("setVolume:%s:%s", r.Form.Get("req0_volume"), r.Form.Get("req0_muted"))
				} else if sc == "seekTo" {
					sc = fmt.Sprintf("seekTo:%s", r.Form.Get("req0_newTime"))
				} else if sc == "setPlaylist" {
					sc = fmt.Sprintf("setPlaylist:%s:%s", r.Form.Get("req0_videoId"), r.Form.Get("req0_currentTime"))
				}
				mu.Lock()
				commands = append(commands, sc)
				mu.Unlock()
				w.WriteHeader(http.StatusOK)
				return
			}

		case "/skipSegments/" + HashPrefix("vid_abc"):
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"videoID": "vid_abc",
					"segments": []map[string]any{
						{"segment": [2]float64{5.0, 25.0}, "UUID": "sb1", "category": "sponsor", "locked": 1},
					},
				},
			})
		}
	}))
	defer srv.Close()

	mgr := NewManager(nil, nil)
	mgr.lounge.apiBase = srv.URL
	mgr.sb.baseURL = srv.URL
	mgr.cfg = config.TVShieldConfig{
		Enabled:      true,
		SkipAds:      true,
		MuteAds:      true,
		SponsorBlock: true,
		Categories:   []string{"sponsor"},
	}

	ctx := context.Background()
	dev, err := mgr.PairByCode(ctx, "111-222-333-444", "", "")
	if err != nil {
		t.Fatalf("PairByCode failed: %v", err)
	}
	if dev.Platform != "Samsung Tizen" {
		t.Fatalf("expected Samsung Tizen platform auto-detection, got %q", dev.Platform)
	}

	met := &deviceMetrics{}
	w := newDeviceWorker(ctx, mgr, dev, met)
	defer w.cancel()

	sess := mgr.lounge.NewSession(dev.ScreenID, dev.LoungeToken)
	if err := sess.Connect(ctx, func(evType string, args []json.RawMessage) {
		w.handleEvent(sess, evType, args)
	}); err != nil {
		t.Fatalf("Session.Connect failed: %v", err)
	}

	// 1. Simulate unskippable ad starting -> should auto-mute at saved volume 35
	w.handleEvent(sess, "adPlaying", []json.RawMessage{
		json.RawMessage(`{"adTitle":"Unskippable Ad","contentVideoId":"vid_abc","isSkippable":"false","isSkipEnabled":"false"}`),
	})
	time.Sleep(80 * time.Millisecond)

	// 2. Simulate ad becoming skippable -> should skipAd and unmute back to 35
	w.handleEvent(sess, "onAdStateChange", []json.RawMessage{
		json.RawMessage(`{"adState":"1","currentTime":"5.0","isSkipEnabled":"true"}`),
	})
	w.handleEvent(sess, "onAdStateChange", []json.RawMessage{
		json.RawMessage(`{"adState":"0","currentTime":"5.0","isSkipEnabled":"false"}`),
	})
	time.Sleep(80 * time.Millisecond)

	// 3. Simulate content video playing right inside SponsorBlock segment (at 5.2s) -> should seekTo 25.00
	w.handleEvent(sess, "nowPlaying", []json.RawMessage{
		json.RawMessage(`{"videoId":"vid_abc","state":"1","currentTime":"5.2","duration":"300"}`),
	})
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	gotCmds := append([]string(nil), commands...)
	mu.Unlock()

	wantSub := []string{"setVolume:35:true", "skipAd", "setVolume:35:false", "seekTo:25.00"}
	joined := strings.Join(gotCmds, ",")
	for _, want := range wantSub {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected command %q in recorded commands %v", want, gotCmds)
		}
	}
}

func TestSamsungTizenUnskippableAdPodForceBypass(t *testing.T) {
	var (
		mu       sync.Mutex
		commands []string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bc/bind" {
			if r.Method == http.MethodPost && r.URL.Query().Get("SID") == "" {
				body := `[[0,["c","sid_tizen"]],[1,["S","gsess_tizen"]],[2,["onVolumeChanged",{"volume":"42","muted":"false"}]]]`
				_, _ = w.Write([]byte(formatBCChunk(body)))
				return
			}
			if r.Method == http.MethodPost {
				_ = r.ParseForm()
				sc := r.Form.Get("req0__sc")
				switch sc {
				case "setVolume":
					sc = fmt.Sprintf("setVolume:%s:%s", r.Form.Get("req0_volume"), r.Form.Get("req0_muted"))
				case "seekTo":
					sc = fmt.Sprintf("seekTo:%s", r.Form.Get("req0_newTime"))
				case "setPlaylist":
					sc = fmt.Sprintf("setPlaylist:%s:%s", r.Form.Get("req0_videoId"), r.Form.Get("req0_currentTime"))
				}
				mu.Lock()
				commands = append(commands, sc)
				mu.Unlock()
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	mgr := NewManager(nil, nil)
	mgr.lounge.apiBase = srv.URL
	mgr.sb.baseURL = srv.URL
	mgr.cfg = config.TVShieldConfig{
		Enabled:      true,
		SkipAds:      true,
		MuteAds:      true,
		SponsorBlock: false,
	}

	ctx := context.Background()
	dev := config.TVDeviceConfig{
		ID:          "tizen_1",
		Name:        "Samsung QN93AA 65 TV",
		ScreenID:    "tizen_1",
		LoungeToken: "tok_tizen",
		Platform:    "Samsung Tizen",
		Enabled:     true,
	}

	met := &deviceMetrics{}
	w := newDeviceWorker(ctx, mgr, dev, met)
	w.bypassWaitSec = 0.08 // Fast timer for deterministic unit test
	defer w.cancel()

	sess := mgr.lounge.NewSession(dev.ScreenID, dev.LoungeToken)
	if err := sess.Connect(ctx, func(evType string, args []json.RawMessage) {
		w.handleEvent(sess, evType, args)
	}); err != nil {
		t.Fatalf("Session.Connect failed: %v", err)
	}

	// 1. Content video playing at 120s of a 600s video
	w.handleEvent(sess, "nowPlaying", []json.RawMessage{
		json.RawMessage(`{"videoId":"vid_mid","state":"1","currentTime":"120.0","duration":"600.0"}`),
	})

	// 2. Unskippable 30s midroll ad starts on Samsung Tizen
	w.handleEvent(sess, "adPlaying", []json.RawMessage{
		json.RawMessage(`{"adTitle":"30s Commercial","contentVideoId":"vid_mid","currentTime":"0","duration":"30.0","isSkippable":"false","isSkipEnabled":"false"}`),
	})

	// 3. Tizen quirk: emits onStateChange(state="1", duration="30.0") for the playing ad!
	// Must NOT clear adActive, must NOT unmute, and must NOT cancel the force-bypass timer!
	w.handleEvent(sess, "onStateChange", []json.RawMessage{
		json.RawMessage(`{"state":"1","currentTime":"0.3","duration":"30.0"}`),
	})

	// Wait for fast bypassWaitSec (80ms) + skipAd settle (60ms) + setPlaylist execution
	time.Sleep(240 * time.Millisecond)

	if gotMuted := met.adsMuted.Load(); gotMuted != 1 {
		t.Fatalf("expected AdsMuted == 1 (no double-mute), got %d", gotMuted)
	}
	if gotSkipped := met.adsSkipped.Load(); gotSkipped != 1 {
		t.Fatalf("expected AdsSkipped == 1 via setPlaylist force-bypass, got %d", gotSkipped)
	}

	// 4. Reloaded content video starts playing on TV (initially reporting currentTime 0 before seek)
	w.handleEvent(sess, "nowPlaying", []json.RawMessage{
		json.RawMessage(`{"videoId":"vid_mid","state":"1","currentTime":"0.0","duration":"600.0"}`),
	})
	time.Sleep(80 * time.Millisecond)

	mu.Lock()
	gotCmds := append([]string(nil), commands...)
	mu.Unlock()
	joined := strings.Join(gotCmds, ",")

	for _, wantPrefix := range []string{"setVolume:42:true", "skipAd", "setPlaylist:vid_mid:120.", "setVolume:42:false", "seekTo:120."} {
		if !strings.Contains(joined, wantPrefix) {
			t.Fatalf("expected %q in commands, got %v", wantPrefix, gotCmds)
		}
	}
}
