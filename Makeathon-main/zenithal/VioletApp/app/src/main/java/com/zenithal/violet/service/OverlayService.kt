package com.zenithal.violet.service

import android.animation.AnimatorSet
import android.animation.ObjectAnimator
import android.app.*
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import android.util.TypedValue
import android.view.*
import android.view.animation.OvershootInterpolator
import android.view.animation.AccelerateInterpolator
import android.view.animation.LinearInterpolator
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.app.NotificationCompat
import com.zenithal.violet.MainActivity
import com.zenithal.violet.R
import com.zenithal.violet.data.api.RetrofitClient
import com.zenithal.violet.data.local.HistoryStore
import com.zenithal.violet.data.models.HistoryEntry
import kotlinx.coroutines.*
import java.util.LinkedList

data class PendingAlert(
    val url: String?,
    val urls: List<String>?,
    val sourceApp: String,
    val senderTitle: String?,
    val fullText: String?,
    val linkCount: Int
)

/**
 * Overlay (Truecaller-style) floating banner that appears when a URL is
 * detected in a notification. Uses SYSTEM_ALERT_WINDOW / TYPE_APPLICATION_OVERLAY.
 *
 * Color-coded side bar:
 *   Red   — risky (score >= 70)
 *   Amber — unverified / pending (30–70)
 *   Green — safe (< 30)
 */
class OverlayService : Service() {

    companion object {
        const val EXTRA_URL = "extra_url"
        const val EXTRA_URLS = "extra_urls"
        const val EXTRA_LINK_COUNT = "extra_link_count"
        const val EXTRA_SOURCE_PACKAGE = "extra_source_package"
        const val EXTRA_SOURCE_APP = "extra_source_app"
        const val EXTRA_SENDER_TITLE = "extra_sender_title"
        const val EXTRA_FULL_TEXT = "extra_full_text"
        private const val TAG = "OverlayService"
        private const val CHANNEL_ID = "violet_overlay_channel"
        private const val NOTIFICATION_ID = 1001
        private const val AUTO_DISMISS_MS = 6000L
        private const val ANIM_DURATION_MS = 280L
    }

    private lateinit var windowManager: WindowManager
    private val handler = Handler(Looper.getMainLooper())
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Banner queue — only one banner visible at a time
    private val pendingAlerts = LinkedList<PendingAlert>()
    private var currentBannerView: View? = null
    private var isShowingBanner = false

    override fun onCreate() {
        super.onCreate()
        windowManager = getSystemService(WINDOW_SERVICE) as WindowManager
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildForegroundNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val url = intent?.getStringExtra(EXTRA_URL)
        val urls = intent?.getStringArrayListExtra(EXTRA_URLS)
        if (url == null && urls.isNullOrEmpty()) return START_NOT_STICKY
        
        val linkCount = urls?.size ?: 1
        val sourceApp = intent?.getStringExtra(EXTRA_SOURCE_APP) ?: "other"
        val senderTitle = intent?.getStringExtra(EXTRA_SENDER_TITLE)
        val fullText = intent?.getStringExtra(EXTRA_FULL_TEXT)
        
        val alert = PendingAlert(url, urls, sourceApp, senderTitle, fullText, linkCount)
        synchronized(pendingAlerts) {
            pendingAlerts.add(alert)
        }
        processQueue()
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        scope.cancel()
        removeBanner()
        super.onDestroy()
    }

    // ── Queue processing ────────────────────────────────────────────────────

    private fun processQueue() {
        if (isShowingBanner) return
        val alert: PendingAlert
        synchronized(pendingAlerts) {
            alert = pendingAlerts.poll() ?: run {
                stopSelf()
                return
            }
        }
        isShowingBanner = true
        fetchAndShowBanner(alert)
    }

    private fun fetchAndShowBanner(alert: PendingAlert) {
        if (alert.linkCount > 1 && !alert.urls.isNullOrEmpty()) {
            showMultiLinkBanner(alert)
            return
        }
        
        val url = alert.url ?: return
        scope.launch {
            val result = com.zenithal.violet.data.api.SafeApiCaller.call(
                maxRetries = 3, tag = "overlay/$url"
            ) {
                RetrofitClient.api.getReputation(url)
            }
            withContext(Dispatchers.Main) {
                when (result) {
                    is com.zenithal.violet.data.api.NetworkResult.Success -> {
                        val rep = result.data
                        
                        // Save full context to HistoryStore
                        val entry = HistoryEntry(
                            url = url,
                            domain = rep.domain,
                            riskScore = rep.fusedRiskScore,
                            verdict = rep.verdict,
                            status = rep.status,
                            sourceApp = alert.sourceApp,
                            senderTitle = alert.senderTitle,
                            fullText = alert.fullText
                        )
                        HistoryStore.add(entry)
                        
                        showBanner(entry, rep.fusedRiskScore, rep.status, rep.verdict, alert.linkCount)
                    }
                    else -> {
                        Log.e(TAG, "Reputation fetch failed for $url: ${result.errorMessage()}")
                        showErrorBanner(alert, result.errorMessage())
                    }
                }
            }
        }
    }

    // ── Banner UI ───────────────────────────────────────────────────────────

    private fun showBanner(entry: HistoryEntry, score: Double, status: String, verdict: String, linkCount: Int) {
        val url = entry.url
        val dp = { value: Int ->
            TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics
            ).toInt()
        }

        // Determine color + header text
        val sideBarColor: Int
        val headerText: String
        when {
            score >= 70 -> {
                sideBarColor = Color.parseColor("#DC2626")
                headerText = "⚠️ Risky Link Detected"
            }
            score < 30 -> {
                sideBarColor = Color.parseColor("#16A34A")
                headerText = "✓ Safe Link"
            }
            else -> {
                sideBarColor = Color.parseColor("#F59E0B")
                headerText = "❓ Unverified Link"
            }
        }
        
        val isDark = com.zenithal.violet.data.local.PreferencesManager.themePreferenceState.intValue != 1
        val bgColor = if (isDark) Color.parseColor("#252038") else Color.parseColor("#FFFFFF")
        val textColor = if (isDark) Color.parseColor("#F5F3FF") else Color.parseColor("#1A1625")
        val subTextColor = if (isDark) Color.parseColor("#A59FBB") else Color.parseColor("#6F6782")

        // ── Fire Native System Notification ──────────────────────────────────
        if (score >= 50) {
            val notifManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val channelId = "violet_alerts"
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val channel = NotificationChannel(
                    channelId,
                    "Violet Threat Alerts",
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = "Alerts for detected malicious URLs"
                }
                notifManager.createNotificationChannel(channel)
            }

            val launchIntent = Intent(this, com.zenithal.violet.MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                if (linkCount == 1) {
                    putExtra("navigate_to", "message_detail")
                    putExtra("entry_id", entry.id)
                }
            }
            val pendingIntent = PendingIntent.getActivity(
                this, (entry.id.hashCode() + url.hashCode()), launchIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            val builder = NotificationCompat.Builder(this, channelId)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(headerText)
                .setContentText("Violet detected a dangerous link: $url")
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_MESSAGE)
                .setColor(sideBarColor)
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)

            notifManager.notify(url.hashCode(), builder.build())
        }

        // Root container
        val container = FrameLayout(this)

        // Card background
        val cardBg = GradientDrawable().apply {
            setColor(bgColor)
            cornerRadius = dp(16).toFloat()
        }

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            background = cardBg
            elevation = dp(8).toFloat()
            setPadding(0, 0, dp(16), 0)
        }

        // Color side bar
        val sideBar = View(this).apply {
            val bg = GradientDrawable().apply {
                setColor(sideBarColor)
                cornerRadii = floatArrayOf(
                    dp(16).toFloat(), dp(16).toFloat(),
                    0f, 0f, 0f, 0f,
                    dp(16).toFloat(), dp(16).toFloat()
                )
            }
            background = bg
        }
        card.addView(sideBar, LinearLayout.LayoutParams(dp(6), LinearLayout.LayoutParams.MATCH_PARENT))

        // Text column
        val textCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(12), dp(8), dp(12))
        }

        val headerTv = TextView(this).apply {
            text = headerText
            setTextColor(textColor)
            textSize = 15f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        }
        textCol.addView(headerTv)

        val urlTv = TextView(this).apply {
            text = if (url.length > 55) url.take(55) + "..." else url
            setTextColor(subTextColor)
            textSize = 12f
            setPadding(0, dp(2), 0, 0)
        }
        textCol.addView(urlTv)

        val reasonTv = TextView(this).apply {
            text = when {
                score >= 70 -> "This link may be dangerous. Tap for details."
                score < 30 -> "No threats detected by community + AI."
                else -> "Not enough data yet. Tap to investigate."
            }
            setTextColor(subTextColor)
            textSize = 11f
            setPadding(0, dp(2), 0, 0)
        }
        textCol.addView(reasonTv)

        if (linkCount > 1) {
            val linkCountTv = TextView(this).apply {
                text = "$linkCount links detected."
                setTextColor(Color.parseColor("#3B82F6"))
                textSize = 12f
                setTypeface(typeface, android.graphics.Typeface.BOLD)
                setPadding(0, dp(4), 0, 0)
            }
            textCol.addView(linkCountTv)
        }

        card.addView(textCol, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))

        val cardWrapper = FrameLayout(this)
        cardWrapper.addView(card, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT))

        // Auto-dismiss progress bar
        val progressBar = View(this).apply {
            val progressBg = GradientDrawable().apply {
                setColor(sideBarColor)
                cornerRadii = floatArrayOf(
                    0f, 0f, 0f, 0f,
                    dp(16).toFloat(), dp(16).toFloat(),
                    dp(16).toFloat(), dp(16).toFloat()
                )
            }
            background = progressBg
            pivotX = 0f // Scale from left
        }
        val progressParams = FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, dp(4)).apply {
            gravity = Gravity.BOTTOM
        }
        cardWrapper.addView(progressBar, progressParams)

        val cardParams = FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            setMargins(dp(16), dp(8), dp(16), dp(8))
        }
        container.addView(cardWrapper, cardParams)

        // WindowManager layout params
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
            y = dp(32)
        }

        // Add to window
        windowManager.addView(container, params)
        currentBannerView = container

        // ── Slide-down + fade-in animation ──────────────────────────────
        container.translationY = -dp(120).toFloat()
        container.alpha = 0f
        AnimatorSet().apply {
            playTogether(
                ObjectAnimator.ofFloat(container, "translationY", 0f),
                ObjectAnimator.ofFloat(container, "alpha", 1f),
            )
            duration = ANIM_DURATION_MS
            interpolator = OvershootInterpolator(1.2f)
            start()
        }
        
        ObjectAnimator.ofFloat(progressBar, "scaleX", 1f, 0f).apply {
            duration = AUTO_DISMISS_MS
            interpolator = LinearInterpolator()
            start()
        }

        // ── Tap → open app to URL Result screen ────────────────────────
        container.setOnClickListener {
            dismissBanner(container)
            val launchIntent = Intent(this@OverlayService, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                putExtra("navigate_to", "message_detail")
                putExtra("entry_id", entry.id)
            }
            startActivity(launchIntent)
        }

        // ── Swipe-to-dismiss ────────────────────────────────────────────
        container.setOnTouchListener(SwipeDismissListener(container) {
            dismissBanner(container)
        })

        // ── Auto-dismiss after 6s ───────────────────────────────────────
        handler.postDelayed({
            if (currentBannerView == container) {
                dismissBanner(container)
            }
        }, AUTO_DISMISS_MS)
    }

    private fun showMultiLinkBanner(alert: PendingAlert) {
        val dp = { value: Int ->
            TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics
            ).toInt()
        }

        val sideBarColor = Color.parseColor("#3B82F6") // Blue tone
        val headerText = "Multiple Links Detected"
        
        val isDark = com.zenithal.violet.data.local.PreferencesManager.themePreferenceState.intValue != 1
        val bgColor = if (isDark) Color.parseColor("#252038") else Color.parseColor("#FFFFFF")
        val textColor = if (isDark) Color.parseColor("#F5F3FF") else Color.parseColor("#1A1625")
        val subTextColor = if (isDark) Color.parseColor("#A59FBB") else Color.parseColor("#6F6782")

        // ── Fire Native System Notification ──────────────────────────────────
        val notifManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channelId = "violet_alerts"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "Violet Threat Alerts",
                NotificationManager.IMPORTANCE_HIGH
            )
            notifManager.createNotificationChannel(channel)
        }

        val launchIntent = Intent(this, com.zenithal.violet.MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("navigate_to", "multi_link")
            putStringArrayListExtra("urls", ArrayList(alert.urls ?: emptyList()))
        }
        val pendingIntent = PendingIntent.getActivity(
            this, (alert.urls?.hashCode() ?: 0), launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(headerText)
            .setContentText("${alert.linkCount} links found. Tap to evaluate.")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setColor(sideBarColor)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)

        notifManager.notify(alert.urls.hashCode(), builder.build())

        // ── Banner UI ────────────────────────────────────────────────────────
        val container = FrameLayout(this)
        val cardBg = GradientDrawable().apply {
            setColor(bgColor)
            cornerRadius = dp(16).toFloat()
        }

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            background = cardBg
            elevation = dp(8).toFloat()
            setPadding(0, 0, dp(16), 0)
        }

        val sideBar = View(this).apply {
            val bg = GradientDrawable().apply {
                setColor(sideBarColor)
                cornerRadii = floatArrayOf(
                    dp(16).toFloat(), dp(16).toFloat(),
                    0f, 0f, 0f, 0f,
                    dp(16).toFloat(), dp(16).toFloat()
                )
            }
            background = bg
        }
        card.addView(sideBar, LinearLayout.LayoutParams(dp(6), LinearLayout.LayoutParams.MATCH_PARENT))

        val textCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(12), dp(8), dp(12))
        }

        val headerTv = TextView(this).apply {
            text = headerText
            setTextColor(textColor)
            textSize = 15f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        }
        textCol.addView(headerTv)

        val reasonTv = TextView(this).apply {
            text = "Tap to review ${alert.linkCount} extracted links individually."
            setTextColor(subTextColor)
            textSize = 12f
            setPadding(0, dp(2), 0, 0)
        }
        textCol.addView(reasonTv)

        card.addView(textCol, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))

        val cardWrapper = FrameLayout(this)
        cardWrapper.addView(card, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT))

        val progressBar = View(this).apply {
            val progressBg = GradientDrawable().apply {
                setColor(sideBarColor)
                cornerRadii = floatArrayOf(
                    0f, 0f, 0f, 0f,
                    dp(16).toFloat(), dp(16).toFloat(),
                    dp(16).toFloat(), dp(16).toFloat()
                )
            }
            background = progressBg
            pivotX = 0f
        }
        val progressParams = FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, dp(4)).apply {
            gravity = Gravity.BOTTOM
        }
        cardWrapper.addView(progressBar, progressParams)

        val cardParams = FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            setMargins(dp(16), dp(8), dp(16), dp(8))
        }
        container.addView(cardWrapper, cardParams)

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
            y = dp(32)
        }

        windowManager.addView(container, params)
        currentBannerView = container

        container.translationY = -dp(120).toFloat()
        container.alpha = 0f
        AnimatorSet().apply {
            playTogether(
                ObjectAnimator.ofFloat(container, "translationY", 0f),
                ObjectAnimator.ofFloat(container, "alpha", 1f),
            )
            duration = ANIM_DURATION_MS
            interpolator = OvershootInterpolator(1.2f)
            start()
        }
        
        ObjectAnimator.ofFloat(progressBar, "scaleX", 1f, 0f).apply {
            duration = AUTO_DISMISS_MS
            interpolator = LinearInterpolator()
            start()
        }

        container.setOnClickListener {
            dismissBanner(container)
            val intent = Intent(this@OverlayService, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                putExtra("navigate_to", "multi_link")
                putStringArrayListExtra("urls", ArrayList(alert.urls ?: emptyList()))
            }
            startActivity(intent)
        }

        container.setOnTouchListener(SwipeDismissListener(container) {
            dismissBanner(container)
        })

        handler.postDelayed({
            if (currentBannerView == container) {
                dismissBanner(container)
            }
        }, AUTO_DISMISS_MS)
    }

    // ── Error Banner (shown when API call fails) ────────────────────────
    private fun showErrorBanner(alert: PendingAlert, errorMsg: String) {
        val url = alert.url ?: return
        val dp = { value: Int ->
            TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics
            ).toInt()
        }

        val container = FrameLayout(this)
        val cardBg = GradientDrawable().apply {
            setColor(Color.parseColor("#1E1E2E"))
            cornerRadius = dp(16).toFloat()
        }
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            background = cardBg
            elevation = dp(8).toFloat()
            setPadding(0, 0, dp(16), 0)
        }
        // Grey side bar for error state
        val sideBar = View(this).apply {
            val bg = GradientDrawable().apply {
                setColor(Color.parseColor("#6B7280"))
                cornerRadii = floatArrayOf(
                    dp(16).toFloat(), dp(16).toFloat(),
                    0f, 0f, 0f, 0f,
                    dp(16).toFloat(), dp(16).toFloat()
                )
            }
            background = bg
        }
        card.addView(sideBar, LinearLayout.LayoutParams(dp(6), LinearLayout.LayoutParams.MATCH_PARENT))

        val textCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(12), dp(8), dp(12))
        }
        val headerTv = TextView(this).apply {
            text = "\u2753 Couldn't verify this link"
            setTextColor(Color.WHITE)
            textSize = 15f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        }
        textCol.addView(headerTv)
        val urlTv = TextView(this).apply {
            text = if (url.length > 55) url.take(55) + "..." else url
            setTextColor(Color.parseColor("#9CA3AF"))
            textSize = 12f
            setPadding(0, dp(2), 0, 0)
        }
        textCol.addView(urlTv)
        val reasonTv = TextView(this).apply {
            text = "Tap to retry — check server and Wi-Fi connection."
            setTextColor(Color.parseColor("#6B7280"))
            textSize = 11f
            setPadding(0, dp(2), 0, 0)
        }
        textCol.addView(reasonTv)
        card.addView(textCol, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))

        val cardParams = FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.WRAP_CONTENT
        ).apply { setMargins(dp(16), dp(8), dp(16), dp(8)) }
        container.addView(card, cardParams)

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
            y = dp(32)
        }

        windowManager.addView(container, params)
        currentBannerView = container

        container.translationY = -dp(120).toFloat()
        container.alpha = 0f
        AnimatorSet().apply {
            playTogether(
                ObjectAnimator.ofFloat(container, "translationY", 0f),
                ObjectAnimator.ofFloat(container, "alpha", 1f),
            )
            duration = ANIM_DURATION_MS
            start()
        }

        // Tap → retry the fetch
        container.setOnClickListener {
            dismissBanner(container)
            fetchAndShowBanner(alert)
        }

        container.setOnTouchListener(SwipeDismissListener(container) {
            dismissBanner(container)
        })

        handler.postDelayed({
            if (currentBannerView == container) {
                dismissBanner(container)
            }
        }, AUTO_DISMISS_MS)
    }

    private fun dismissBanner(view: View) {
        // Slide-up + fade-out
        AnimatorSet().apply {
            playTogether(
                ObjectAnimator.ofFloat(view, "translationY", -300f),
                ObjectAnimator.ofFloat(view, "alpha", 0f),
            )
            duration = ANIM_DURATION_MS
            interpolator = AccelerateInterpolator()
            start()
        }
        handler.postDelayed({
            try { windowManager.removeView(view) } catch (_: Exception) {}
            currentBannerView = null
            isShowingBanner = false
            processQueue()
        }, ANIM_DURATION_MS + 20)
    }

    private fun removeBanner() {
        currentBannerView?.let {
            try { windowManager.removeView(it) } catch (_: Exception) {}
        }
        currentBannerView = null
        isShowingBanner = false
    }

    // ── Foreground notification (required for FG service) ───────────────────

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID, "Violet Link Scanner",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Background link scanning service"
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun buildForegroundNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Violet is protecting you")
            .setContentText("Scanning links in notifications...")
            .setSmallIcon(R.drawable.ic_shield)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    // ── Swipe-to-dismiss touch listener ─────────────────────────────────────

    private inner class SwipeDismissListener(
        private val view: View,
        private val onDismiss: () -> Unit,
    ) : View.OnTouchListener {

        private var startY = 0f
        private var startRawY = 0f
        private val threshold = 100f

        override fun onTouch(v: View, event: MotionEvent): Boolean {
            when (event.action) {
                MotionEvent.ACTION_DOWN -> {
                    startY = view.translationY
                    startRawY = event.rawY
                    view.animate().scaleX(0.97f).scaleY(0.97f).setDuration(100).start()
                    return true
                }
                MotionEvent.ACTION_MOVE -> {
                    val delta = event.rawY - startRawY
                    if (delta < 0) { // swiping up
                        view.translationY = startY + delta
                        view.alpha = 1f - (-delta / 400f).coerceIn(0f, 1f)
                    }
                    return true
                }
                MotionEvent.ACTION_UP -> {
                    view.animate().scaleX(1f).scaleY(1f).setDuration(100).start()
                    if (startRawY - event.rawY > threshold) {
                        onDismiss()
                    } else if (Math.abs(startRawY - event.rawY) < 10f) {
                        // It was a tap
                        view.performClick()
                    } else {
                        view.animate().translationY(0f).alpha(1f).setDuration(150).start()
                    }
                    return true
                }
            }
            return false
        }
    }
}
