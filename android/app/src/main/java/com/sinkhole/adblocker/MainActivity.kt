package com.sinkhole.adblocker

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.webkit.ConsoleMessage
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout

class MainActivity : AppCompatActivity() {

    private lateinit var swipeRefresh: SwipeRefreshLayout
    private lateinit var webView: WebView
    private lateinit var bridge: AndroidBridge

    private val defaultAssetUrl = "file:///android_asset/index.html"

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        setupEdgeToEdge()

        swipeRefresh = findViewById(R.id.swipeRefreshLayout)
        webView = findViewById(R.id.webView)

        bridge = AndroidBridge(this) { newUrl ->
            runOnUiThread {
                if (newUrl.isNotBlank()) {
                    webView.loadUrl(newUrl)
                } else {
                    webView.loadUrl(defaultAssetUrl)
                }
            }
        }

        setupWebView()
        setupSwipeRefresh()
        setupBackNavigation()

        loadInitialContent()
    }

    private fun setupEdgeToEdge() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            window.apply {
                clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS)
                addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS)
                statusBarColor = Color.parseColor("#0a0a0c")
                navigationBarColor = Color.parseColor("#0a0a0c")
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            // Keep dark status bar icons off (since our background is dark)
            val decor = window.decorView
            decor.systemUiVisibility = decor.systemUiVisibility and View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR.inv()
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun setupWebView() {
        webView.apply {
            setBackgroundColor(Color.parseColor("#0a0a0c"))

            settings.apply {
                javaScriptEnabled = true
                domStorageEnabled = true
                databaseEnabled = true
                allowFileAccess = true
                allowContentAccess = true
                allowFileAccessFromFileURLs = true
                allowUniversalAccessFromFileURLs = true
                cacheMode = WebSettings.LOAD_DEFAULT
                useWideViewPort = true
                loadWithOverviewMode = true
                setSupportZoom(false)
                builtInZoomControls = false
                displayZoomControls = false

                // Modern viewport & media settings
                mediaPlaybackRequiresUserGesture = false
            }

            addJavascriptInterface(bridge, "Android")
            addJavascriptInterface(bridge, "AndroidBridge")

            webChromeClient = object : WebChromeClient() {
                override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                    return super.onConsoleMessage(consoleMessage)
                }
            }

            webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                    val url = request?.url?.toString() ?: return false
                    
                    // Keep app URLs inside WebView
                    if (url.startsWith("file:///android_asset") ||
                        url.contains(":3002") ||
                        url.contains("localhost") ||
                        url.contains("127.0.0.1") ||
                        url.contains("10.0.2.2") ||
                        url.matches(Regex("https?://(192\\.168|10\\.|172\\.(1[6-9]|2[0-9]|3[0-1]))\\..*"))
                    ) {
                        return false
                    }

                    // Open external documentation/links in default browser
                    return try {
                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
                        startActivity(intent)
                        true
                    } catch (e: Exception) {
                        false
                    }
                }

                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    swipeRefresh.isRefreshing = false
                }

                override fun onReceivedError(
                    view: WebView?,
                    request: WebResourceRequest?,
                    error: WebResourceError?
                ) {
                    super.onReceivedError(view, request, error)
                    if (request?.isForMainFrame == true) {
                        swipeRefresh.isRefreshing = false
                        // If connection to server failed and we are not already on asset, fallback to offline asset
                        val current = request.url?.toString() ?: ""
                        if (!current.startsWith("file:///android_asset")) {
                            view?.loadUrl(defaultAssetUrl)
                            bridge.showToast("Server unavailable. Loaded offline controller.")
                        }
                    }
                }
            }
        }
    }

    private fun setupSwipeRefresh() {
        swipeRefresh.apply {
            setColorSchemeColors(Color.parseColor("#3b82f6"), Color.parseColor("#10b981"))
            setProgressBackgroundColorSchemeColor(Color.parseColor("#18181b"))

            setOnRefreshListener {
                bridge.triggerHaptic("light")
                webView.reload()
            }

            // Only allow swipe to refresh when WebView is scrolled to top
            viewTreeObserver.addOnScrollChangedListener {
                isEnabled = webView.scrollY == 0
            }
        }
    }

    private fun setupBackNavigation() {
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (webView.canGoBack()) {
                    webView.goBack()
                } else {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
                }
            }
        })
    }

    private fun loadInitialContent() {
        val prefs = getSharedPreferences("sinkhole_prefs", Context.MODE_PRIVATE)
        val savedServerUrl = prefs.getString("server_url", "")

        if (!savedServerUrl.isNullOrBlank()) {
            webView.loadUrl(savedServerUrl)
        } else {
            // By default load offline asset; user can specify LAN IP or test connection
            webView.loadUrl(defaultAssetUrl)
        }
    }

    override fun onDestroy() {
        webView.apply {
            removeJavascriptInterface("Android")
            removeJavascriptInterface("AndroidBridge")
            stopLoading()
            destroy()
        }
        super.onDestroy()
    }
}
