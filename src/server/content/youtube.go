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
/* Sinkhole YouTube Comprehensive Cosmetic Ad Removal */
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
.ytp-ad-skip-button-container,
.ytp-ad-skip-button-modern,
.ytp-ad-survey,
.ytp-ad-image-overlay,
#rendering-content > ytd-ad-slot-renderer,
ytd-rich-item-renderer:has(ytd-ad-slot-renderer),
ytd-rich-section-renderer:has(ytd-statement-banner-renderer),
ytd-ad-break-service-renderer,
tp-yt-paper-dialog:has(ytd-enforcement-message-view-model),
ytd-enforcement-message-view-model {
  display: none !important;
  visibility: hidden !important;
  height: 0 !important;
  width: 0 !important;
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

  // Comprehensive ad payload stripper
  function sanitize(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    try {
      if (Array.isArray(obj)) {
        for (let i = 0; i < obj.length; i++) sanitize(obj[i]);
        return obj;
      }
      delete obj.adPlacements;
      delete obj.playerAds;
      delete obj.adSlots;
      delete obj.adBreakHeartbeatParams;
      delete obj.interstitial;
      delete obj.interstitials;
      delete obj.adBreakService;
      if (obj.playerConfig && obj.playerConfig.adConfig) {
        delete obj.playerConfig.adConfig;
      }
      if (obj.playbackTracking) {
        delete obj.playbackTracking.videostatsPlaybackUrl;
        delete obj.playbackTracking.videostatsDelayplayUrl;
        delete obj.playbackTracking.qoeUrl;
        delete obj.playbackTracking.atrUrl;
        delete obj.playbackTracking.ptrackingUrl;
        delete obj.playbackTracking.videostatsWatchtimeUrl;
      }
      for (const k of Object.keys(obj)) {
        if (k.toLowerCase().includes('adslot') || k.toLowerCase().includes('adplacement')) {
          delete obj[k];
        } else if (obj[k] && typeof obj[k] === 'object') {
          sanitize(obj[k]);
        }
      }
    } catch (e) {}
    return obj;
  }

  // Hook ytInitialPlayerResponse at the earliest moment
  let _ytInitialPlayerResponse = window.ytInitialPlayerResponse;
  Object.defineProperty(window, 'ytInitialPlayerResponse', {
    get: function() { return _ytInitialPlayerResponse; },
    set: function(val) { _ytInitialPlayerResponse = sanitize(val); },
    configurable: true
  });
  if (window.ytInitialPlayerResponse) {
    window.ytInitialPlayerResponse = sanitize(window.ytInitialPlayerResponse);
  }

  // Hook ytInitialData
  let _ytInitialData = window.ytInitialData;
  Object.defineProperty(window, 'ytInitialData', {
    get: function() { return _ytInitialData; },
    set: function(val) { _ytInitialData = sanitize(val); },
    configurable: true
  });
  if (window.ytInitialData) {
    window.ytInitialData = sanitize(window.ytInitialData);
  }

  // Hook window.fetch for Single-Page App navigation
  const origFetch = window.fetch;
  window.fetch = async function(...args) {
    const res = await origFetch.apply(this, args);
    const url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url ? args[0].url : '');
    if (url.includes('/youtubei/v1/player') || url.includes('/youtubei/v1/next')) {
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

  // Video element fast-skipper & ad auto-dismiss
  function skipVideoAds() {
    const video = document.querySelector('video.html5-main-video');
    const adShowing = document.querySelector('.ad-showing, .ad-interrupting, .ytp-ad-player-overlay');
    if (video && adShowing) {
      video.muted = true;
      video.playbackRate = 16.0;
      if (Number.isFinite(video.duration) && video.duration > 0) {
        video.currentTime = video.duration - 0.1;
      }
    }
    const skipBtn = document.querySelector('.ytp-ad-skip-button, .ytp-ad-skip-button-modern, .ytp-skip-ad-button, .ytp-ad-overlay-close-button');
    if (skipBtn) {
      try { skipBtn.click(); } catch (e) {}
    }
    // Dismiss anti-adblock modal if triggered
    const enforcement = document.querySelector('ytd-enforcement-message-view-model, tp-yt-paper-dialog:has(ytd-enforcement-message-view-model)');
    if (enforcement) {
      enforcement.remove();
      const backdrop = document.querySelector('tp-yt-iron-overlay-backdrop');
      if (backdrop) backdrop.remove();
      if (video && video.paused) {
        video.play().catch(() => {});
      }
    }
  }

  setInterval(skipVideoAds, 100);
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

	// 4. Remove adBreakHeartbeatParams
	if _, ok := root["adBreakHeartbeatParams"]; ok {
		delete(root, "adBreakHeartbeatParams")
		removed = true
	}

	// 5. Remove interstitials & adBreakService
	if _, ok := root["interstitial"]; ok {
		delete(root, "interstitial")
		removed = true
	}
	if _, ok := root["interstitials"]; ok {
		delete(root, "interstitials")
		removed = true
	}
	if _, ok := root["adBreakService"]; ok {
		delete(root, "adBreakService")
		removed = true
	}

	// 6. Clean playerConfig
	if pcfg, ok := root["playerConfig"].(map[string]any); ok {
		if _, hasAd := pcfg["adConfig"]; hasAd {
			delete(pcfg, "adConfig")
			removed = true
		}
	}

	// 7. Clean playback tracking telemetry
	if tracking, ok := root["playbackTracking"].(map[string]any); ok {
		delete(tracking, "videostatsPlaybackUrl")
		delete(tracking, "videostatsDelayplayUrl")
		delete(tracking, "qoeUrl")
		delete(tracking, "atrUrl")
		delete(tracking, "ptrackingUrl")
		delete(tracking, "videostatsWatchtimeUrl")
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

	lower := bytes.ToLower(html)
	if idx := bytes.Index(lower, []byte("<head>")); idx >= 0 {
		insertAt := idx + len("<head>")
		var buf bytes.Buffer
		buf.Grow(len(html) + len(toInject))
		buf.Write(html[:insertAt])
		buf.WriteString(toInject)
		buf.Write(html[insertAt:])
		return buf.Bytes()
	}

	if idx := bytes.Index(lower, []byte("<head ")); idx >= 0 {
		if endIdx := bytes.IndexByte(html[idx:], '>'); endIdx >= 0 {
			insertAt := idx + endIdx + 1
			var buf bytes.Buffer
			buf.Grow(len(html) + len(toInject))
			buf.Write(html[:insertAt])
			buf.WriteString(toInject)
			buf.Write(html[insertAt:])
			return buf.Bytes()
		}
	}

	// Fallback to before </head> if opening tag wasn't detected
	if idx := bytes.Index(lower, []byte("</head>")); idx >= 0 {
		var buf bytes.Buffer
		buf.Grow(len(html) + len(toInject))
		buf.Write(html[:idx])
		buf.WriteString(toInject)
		buf.Write(html[idx:])
		return buf.Bytes()
	}

	// Fallback to before <body or beginning
	if idx := bytes.Index(lower, []byte("<body")); idx >= 0 {
		var buf bytes.Buffer
		buf.Grow(len(html) + len(toInject))
		buf.Write(html[:idx])
		buf.WriteString(toInject)
		buf.Write(html[idx:])
		return buf.Bytes()
	}

	return append([]byte(toInject), html...)
}
