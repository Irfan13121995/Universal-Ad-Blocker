package com.sinkhole.adblocker

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.wifi.WifiManager
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.provider.Settings
import android.webkit.JavascriptInterface
import android.widget.Toast
import java.net.InetAddress
import java.nio.ByteOrder

/**
 * AndroidBridge exposes native Android hardware capabilities to the embedded web app:
 * - Haptics / Vibration
 * - 1-Click Launch of Android Private DNS (DoT) Settings
 * - Native Toasts & Clipboard
 * - Wi-Fi / LAN gateway information
 * - Server URL persistence
 */
class AndroidBridge(
    private val activity: MainActivity,
    private val onServerUrlChanged: (String) -> Unit
) {

    private val vibrator: Vibrator? by lazy {
        activity.getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
    }

    private val clipboard: ClipboardManager? by lazy {
        activity.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    }

    @JavascriptInterface
    fun triggerHaptic(type: String) {
        activity.runOnUiThread {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    val effect = when (type.lowercase()) {
                        "light" -> VibrationEffect.createPredefined(VibrationEffect.EFFECT_TICK)
                        "heavy" -> VibrationEffect.createPredefined(VibrationEffect.EFFECT_HEAVY_CLICK)
                        else -> VibrationEffect.createPredefined(VibrationEffect.EFFECT_CLICK)
                    }
                    vibrator?.vibrate(effect)
                } else {
                    @Suppress("DEPRECATION")
                    vibrator?.vibrate(12)
                }
            } catch (e: Exception) {
                // Ignore if device lacks vibrator
            }
        }
    }

    @JavascriptInterface
    fun openPrivateDNSSettings() {
        activity.runOnUiThread {
            try {
                triggerHaptic("heavy")
                // Try direct Network Operator / Private DNS settings (Android 9+)
                val intent = Intent("android.settings.NETWORK_OPERATOR_SETTINGS").apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                activity.startActivity(intent)
            } catch (e1: Exception) {
                try {
                    // Fallback to Wireless & Network Settings
                    val fallback = Intent(Settings.ACTION_WIRELESS_SETTINGS).apply {
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    activity.startActivity(fallback)
                } catch (e2: Exception) {
                    Toast.makeText(activity, "Open Settings > Network > Private DNS", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    @JavascriptInterface
    fun showToast(message: String) {
        activity.runOnUiThread {
            Toast.makeText(activity, message, Toast.LENGTH_SHORT).show()
        }
    }

    @JavascriptInterface
    fun copyToClipboard(label: String, text: String) {
        activity.runOnUiThread {
            val clip = ClipData.newPlainText(label, text)
            clipboard?.setPrimaryClip(clip)
            triggerHaptic("click")
            Toast.makeText(activity, "Copied $text to clipboard", Toast.LENGTH_SHORT).show()
        }
    }

    @JavascriptInterface
    fun getDeviceLANInfo(): String {
        return try {
            val wifiManager = activity.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            val ipInt = wifiManager?.connectionInfo?.ipAddress ?: 0
            if (ipInt != 0) {
                val ipBytes = if (ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN) {
                    byteArrayOf(
                        (ipInt and 0xff).toByte(),
                        (ipInt shr 8 and 0xff).toByte(),
                        (ipInt shr 16 and 0xff).toByte(),
                        (ipInt shr 24 and 0xff).toByte()
                    )
                } else {
                    byteArrayOf(
                        (ipInt shr 24 and 0xff).toByte(),
                        (ipInt shr 16 and 0xff).toByte(),
                        (ipInt shr 8 and 0xff).toByte(),
                        (ipInt and 0xff).toByte()
                    )
                }
                val ip = InetAddress.getByAddress(ipBytes).hostAddress ?: "127.0.0.1"
                "{\"ip\":\"$ip\",\"status\":\"connected\"}"
            } else {
                "{\"ip\":\"127.0.0.1\",\"status\":\"unknown\"}"
            }
        } catch (e: Exception) {
            "{\"ip\":\"127.0.0.1\",\"error\":\"${e.message}\"}"
        }
    }

    @JavascriptInterface
    fun saveServerUrl(url: String) {
        activity.getSharedPreferences("sinkhole_prefs", Context.MODE_PRIVATE)
            .edit()
            .putString("server_url", url)
            .apply()
        onServerUrlChanged(url)
    }

    @JavascriptInterface
    fun getServerUrl(): String {
        return activity.getSharedPreferences("sinkhole_prefs", Context.MODE_PRIVATE)
            .getString("server_url", "") ?: ""
    }
}
