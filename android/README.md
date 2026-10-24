# Universal Ad-Blocker & Sinkhole — Android Client

Native Android mobile application companion and remote controller for the **Windows 11 Universal Network Ad & Tracker Sinkhole**.

---

## 🚀 Key Features

1. **Hardware-Accelerated Web Shell & Dashboard:**
   - Full edge-to-edge dark theme (`#0a0a0c`) matching the desktop experience.
   - Safe-area insets (`env(safe-area-inset-top)` / `bottom`) and zero-latency touch responses (`touch-action: manipulation`, `-webkit-tap-highlight-color: transparent`).
   - Native pull-to-refresh via `SwipeRefreshLayout`.
   - Android back-button navigation stack (`OnBackPressedCallback`).

2. **Native Android Hardware Bridge (`AndroidBridge`):**
   - **Haptics:** Native device vibration on tap (`VibrationEffect.createPredefined` with fallback).
   - **Private DNS Intent:** 1-Click launcher opening Android OS Settings directly to **Network & Internet > Private DNS**.
   - **Local Wi-Fi Diagnostics:** Reads client LAN IP and connection state.
   - **Native Toasts & Clipboard:** Seamless copying of DNS hostnames and LAN IPs.

3. **Remote LAN Server Switcher:**
   - Connects to any Sinkhole server on the local network (e.g. `http://192.168.1.150:3002`).
   - Supports Android emulator loopback (`http://10.0.2.2:3002`).
   - Offline fallback mode: Bundles `assets/index.html` so the UI is available anywhere, even when disconnected.

4. **Network Security Config:**
   - Cleartext HTTP allowed for private local network RFC1918 subnets (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `10.0.2.2`, `127.0.0.1`), strictly protecting against insecure public internet traffic.

---

## 🛠️ Project Structure

```
android/
├── app/
│   ├── build.gradle                          # App-level Gradle config (minSdk 26, targetSdk 34)
│   ├── proguard-rules.pro                   # R8 / Proguard rules for WebView JavaScript interfaces
│   └── src/main/
│       ├── AndroidManifest.xml              # Permissions, cleartext network config, hardware acceleration
│       ├── assets/
│       │   ├── index.html                   # Bundled offline dashboard shell
│       │   └── manifest.json                # PWA manifest
│       ├── java/com/sinkhole/adblocker/
│       │   ├── MainActivity.kt              # Edge-to-edge layout, WebView setup, SwipeRefresh, error fallback
│       │   └── AndroidBridge.kt             # @JavascriptInterface exposing haptics, Private DNS intent, clipboard
│       └── res/
│           ├── layout/activity_main.xml     # SwipeRefreshLayout + WebView layout
│           ├── values/                      # Colors, strings, dark themes
│           ├── drawable/                    # Vector adaptive icons
│           ├── mipmap-anydpi-v26/           # Adaptive launcher icons
│           └── xml/network_security_config.xml # LAN cleartext network permissions
├── gradle/wrapper/
│   └── gradle-wrapper.properties            # Gradle 8.2 distribution
├── build.gradle                             # Root build script
├── settings.gradle                          # Project configuration
├── gradlew & gradlew.bat                    # Cross-platform Gradle wrapper scripts
└── README.md                                # This documentation
```

---

## 📱 How to Open & Build in Android Studio

1. **Prerequisites:**
   - [Android Studio Iguana / Jellyfish / Ladybug (2023.2+)](https://developer.android.com/studio)
   - JDK 17 or higher
   - Android SDK Platform 34

2. **Open Project:**
   - Launch Android Studio.
   - Click **Open** and select the `/android` folder inside this repository.
   - Wait for Gradle sync to complete automatically.

3. **Run on Device or Emulator:**
   - Connect an Android device with **USB Debugging** enabled (or start an Android Virtual Device).
   - Click the green **Run ▶** button (or press `Shift + F10`).

4. **Build APK via Command Line:**
   - **Windows:**
     ```powershell
     cd android
     .\gradlew.bat assembleDebug
     ```
   - **macOS / Linux:**
     ```bash
     cd android
     ./gradlew assembleDebug
     ```
   - The generated APK will be at:
     `android/app/build/outputs/apk/debug/app-debug.apk`

---

## 🛡️ Setting up Android Private DNS (DoT)

To route all Android DNS queries (Wi-Fi and Cellular) through your Sinkhole server:

1. In the Android App, tap the top connection pill or navigate to **Adapters & Mobile**.
2. Tap **"Open Android Private DNS Settings"** (the app opens Android's native settings modal).
3. Select **Private DNS provider hostname**.
4. Enter your Sinkhole server's DoT hostname (or local DNS forwarder domain).
5. Tap **Save**. Your Android device is now protected system-wide!
