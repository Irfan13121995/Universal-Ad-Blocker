// Sinkhole YouTube Ad-Blocker Companion
// Runs at document_start in YouTube pages to eliminate all in-stream ads and telemetry.

(function() {
  'use strict';

  // Inject defuser into the page context (MAIN world)
  const script = document.createElement('script');
  script.id = 'sinkhole-extension-defuser';
  script.textContent = `
    (function() {
      'use strict';

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

      // Hook ytInitialPlayerResponse at the earliest millisecond
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

      // Hook window.fetch for Single-Page App navigations
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

      // Video element instant-skipper & anti-adblock auto-dismiss
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
  `;

  (document.head || document.documentElement).prepend(script);
})();
