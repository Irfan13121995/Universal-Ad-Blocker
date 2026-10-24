package content

import (
	"strings"
	"testing"
)

func TestSanitizePlayerJSON(t *testing.T) {
	sample := `{
		"responseContext": {"service": "CSI"},
		"adPlacements": [
			{"adPlacementRenderer": {"adTime": 0}}
		],
		"playerAds": [
			{"playerLegacyDesktopWatchAdsRenderer": {"adDuration": 15}}
		],
		"adSlots": [
			{"adSlotRenderer": {"slotType": "SLOT_TYPE_PLAYER_BYTE"}}
		],
		"playbackTracking": {
			"videostatsPlaybackUrl": "https://s.youtube.com/api/stats/playback",
			"qoeUrl": "https://s.youtube.com/api/stats/qoe"
		},
		"videoDetails": {
			"videoId": "dQw4w9WgXcQ",
			"title": "Rick Astley - Never Gonna Give You Up"
		}
	}`

	sanitized, modified := SanitizePlayerJSON([]byte(sample))
	if !modified {
		t.Fatal("expected player JSON to be modified")
	}

	sanitizedStr := string(sanitized)
	if strings.Contains(sanitizedStr, "adPlacements") {
		t.Error("adPlacements was not stripped")
	}
	if strings.Contains(sanitizedStr, "playerAds") {
		t.Error("playerAds was not stripped")
	}
	if strings.Contains(sanitizedStr, "adSlots") {
		t.Error("adSlots was not stripped")
	}
	if strings.Contains(sanitizedStr, "videostatsPlaybackUrl") {
		t.Error("videostatsPlaybackUrl was not stripped")
	}
	if !strings.Contains(sanitizedStr, "dQw4w9WgXcQ") {
		t.Error("videoDetails were corrupted")
	}
}

func TestInjectYouTubeAssets(t *testing.T) {
	html := `<!DOCTYPE html><html><head><title>YouTube</title></head><body><h1>Watch</h1></body></html>`
	injected := string(InjectYouTubeAssets([]byte(html)))

	if !strings.Contains(injected, "sinkhole-yt-defuser") {
		t.Error("YouTube defuser scriptlet was not injected")
	}
	if !strings.Contains(injected, "#masthead-ad") {
		t.Error("YouTube cosmetic CSS was not injected")
	}
	if !strings.Contains(injected, "</head>") {
		t.Error("HTML structure was broken")
	}
}
