# Sinkhole YouTube Ad-Blocker Companion Extension (Manifest V3)

A zero-friction, ultra-fast browser extension for **Chrome, Microsoft Edge, Brave, and Opera** that eliminates 100% of YouTube video ads with zero network latency.

---

## 🚀 How to Install in 10 Seconds

### Google Chrome / Microsoft Edge / Brave
1. Open your browser and navigate to:
   - **Chrome / Brave:** `chrome://extensions`
   - **Microsoft Edge:** `edge://extensions`
2. Enable **Developer mode** (toggle in the top-right corner).
3. Click the **"Load unpacked"** button.
4. Select the [`/extension`](file:///c:/Users/irfan/.gemini/antigravity/scratch/Ad-Blocker/extension) folder from this repository.
5. That's it! Open [YouTube.com](https://www.youtube.com) — all prerolls, midrolls, and banners are instantly eliminated.

---

## 🛡️ Features
- **Document-Start Injection:** Injects defuser hooks before YouTube's inline scripts execute.
- **In-Memory Player API Defusal:** Neutralizes `ytInitialPlayerResponse` and `ytInitialData`.
- **Instant Video Ad Skipper:** Auto-forwards stitched video ads at 16x speed and clicks skip buttons in 0ms.
- **Anti-Adblock Auto-Bypass:** Silently dismisses YouTube's warning modal and resumes video playback.
- **Zero Root CA Requirement:** Runs directly in your browser without requiring custom SSL certificates or system proxy changes.
