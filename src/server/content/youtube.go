// Package content provides deep HTTP/HTTPS content filtering, including
// YouTube ad defusal, cosmetic element hiding, and scriptlet injection.
package content

import (
	"bytes"
	"encoding/json"
	"strings"
)

// YouTubeShield manages YouTube-specific ad elimination logic.
type YouTubeShield struct {
	Enabled       bool
	BlockPrerolls bool
	BlockBanners  bool
	BlockShorts   bool
}

// DefaultYouTubeShield returns recommended YouTube blocking configuration.
func DefaultYouTubeShield() YouTubeShield {
	return YouTubeShield{
		Enabled:       true,
		BlockPrerolls: true,
		BlockBanners:  true,
		BlockShorts:   false,
	}
}

// YouTubeCosmeticCSS returns CSS rules that hide YouTube ad elements, masthead promotions,
// and sponsored banners.
const YouTubeCosmeticCSS = `
/* Sinkhole YouTube Cosmetic Ad Removal */
#masthead-ad,
ytd-banner-promo-renderer,
ytd-ad-slot-renderer,
ytd-in-feed-ad-layout-renderer,
.ytd-companion-slot-renderer,
#player-ads,
.ytp-ad-module,
.ytp-ad-overlay-container,
.ytp-ad-message-container,
ytd-promoted-sparkles-web-renderer,
ytd-promoted-sparkles-text-search-renderer,
ytd-display-ad-renderer,
ytd-statement-banner-renderer,
.ytp-ad-preview-container,
.ytp-ad-skip-button-container {
  display: none !important;
  visibility: hidden !important;
  height: 0 !important;
  opacity: 0 !important;
  pointer-events: none !important;
}
`

// YouTubeScriptlet is injected into YouTube HTML documents. It intercepts the player
// configuration before player initialization, neutralizing ad queues in-browser.
const YouTubeScriptlet = `
<script id="sinkhole-yt-defuser">
(function() {
  'use strict';
  // Strip ads from initial player response object
  function sanitize(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    delete obj.adPlacements;
    delete obj.playerAds;
    delete obj.adSlots;
    if (obj.playbackTracking) {
      delete obj.playbackTracking.videostatsPlaybackUrl;
      delete obj.playbackTracking.videostatsDelayplayUrl;
      delete obj.playbackTracking.qoeUrl;
      delete obj.playbackTracking.atrUrl;
    }
    return obj;
  }

  // Hook ytInitialPlayerResponse
  let originalPlayerResponse = window.ytInitialPlayerResponse;
  Object.defineProperty(window, 'ytInitialPlayerResponse', {
    get: function() { return originalPlayerResponse; },
    set: function(val) { originalPlayerResponse = sanitize(val); },
    configurable: true
  });
  if (window.ytInitialPlayerResponse) {
    window.ytInitialPlayerResponse = sanitize(window.ytInitialPlayerResponse);
  }

  // Hook fetch for player API calls in Single-Page-App navigation
  const origFetch = window.fetch;
  window.fetch = async function(...args) {
    const res = await origFetch.apply(this, args);
    const url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url ? args[0].url : '');
    if (url.includes('/youtubei/v1/player')) {
      try {
        const clone = res.clone();
        const data = await clone.json();
        sanitize(data);
        return new Response(JSON.stringify(data), {
          status: res.status,
          statusText: res.statusText,
          headers: res.headers
        });
      } catch (e) {
        return res;
      }
    }
    return res;
  };
})();
</script>
`

// SanitizePlayerJSON takes a raw JSON payload from /youtubei/v1/player or /youtubei/v1/next
// and strips all ad placements, ad slots, and tracking parameters.
// Returns the modified JSON and a boolean indicating if ad objects were removed.
func SanitizePlayerJSON(body []byte) ([]byte, bool) {
	if len(body) == 0 {
		return body, false
	}

	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return body, false
	}

	removed := false

	// 1. Remove adPlacements
	if _, ok := root["adPlacements"]; ok {
		delete(root, "adPlacements")
		removed = true
	}

	// 2. Remove playerAds
	if _, ok := root["playerAds"]; ok {
		delete(root, "playerAds")
		removed = true
	}

	// 3. Remove adSlots
	if _, ok := root["adSlots"]; ok {
		delete(root, "adSlots")
		removed = true
	}

	// 4. Clean playback tracking telemetry
	if tracking, ok := root["playbackTracking"].(map[string]any); ok {
		delete(tracking, "videostatsPlaybackUrl")
		delete(tracking, "videostatsDelayplayUrl")
		delete(tracking, "qoeUrl")
		delete(tracking, "atrUrl")
	}

	if !removed {
		return body, false
	}

	modified, err := json.Marshal(root)
	if err != nil {
		return body, false
	}
	return modified, true
}

// IsYouTubePlayerAPI reports whether the request path matches YouTube's player API.
func IsYouTubePlayerAPI(path string) bool {
	return strings.Contains(path, "/youtubei/v1/player") ||
		strings.Contains(path, "/youtubei/v1/next") ||
		strings.Contains(path, "/get_video_info")
}

// InjectYouTubeAssets injects YouTube cosmetic styles and defuser scriptlets into an HTML stream.
func InjectYouTubeAssets(html []byte) []byte {
	toInject := YouTubeScriptlet + "\n<style>" + YouTubeCosmeticCSS + "</style>\n"
	
	// Inject before </head> if present
	if idx := bytes.Index(html, []byte("</head>")); idx >= 0 {
		var buf bytes.Buffer
		buf.Grow(len(html) + len(toInject))
		buf.Write(html[:idx])
		buf.WriteString(toInject)
		buf.Write(html[idx:])
		return buf.Bytes()
	}

	// Fallback to before <body or beginning
	if idx := bytes.Index(html, []byte("<body")); idx >= 0 {
		var buf bytes.Buffer
		buf.Grow(len(html) + len(toInject))
		buf.Write(html[:idx])
		buf.WriteString(toInject)
		buf.Write(html[idx:])
		return buf.Bytes()
	}

	return append([]byte(toInject), html...)
}
