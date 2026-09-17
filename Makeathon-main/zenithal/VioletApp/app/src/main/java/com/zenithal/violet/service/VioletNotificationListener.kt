package com.zenithal.violet.service

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.content.Intent
import android.util.Log
import com.zenithal.violet.data.local.PreferencesManager

/**
 * Listens to all incoming notifications, extracts URLs, and triggers
 * the OverlayService to show a risk banner for each detected link.
 *
 * Filters by user-selected monitored apps (SMS, Gmail, Telegram, WhatsApp).
 * Requires the user to grant Notification Access in Settings.
 */
class VioletNotificationListener : NotificationListenerService() {

    companion object {
        private const val TAG = "VioletNotifListener"

        /**
         * Known package names for monitored apps.
         * Keys match the SharedPreferences toggle keys in PreferencesManager.
         */
        val MONITORED_PACKAGES = mapOf(
            "sms" to setOf(
                "com.google.android.apps.messaging",  // Google Messages
                "com.android.mms",                     // Default AOSP SMS
                "com.samsung.android.messaging",       // Samsung Messages
                "com.oneplus.mms",                     // OnePlus Messages
            ),
            "gmail" to setOf(
                "com.google.android.gm",
            ),
            "telegram" to setOf(
                "org.telegram.messenger",
                "org.thunderdog.challegram",           // Telegram X
            ),
            "whatsapp" to setOf(
                "com.whatsapp",
                "com.whatsapp.w4b",                    // WhatsApp Business
            ),
        )
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null) return
        // Skip our own notifications to avoid loops
        if (sbn.packageName == packageName) return
        // Check if overlay is active
        if (!PreferencesManager.isOverlayActive) return

        val sourcePackage = sbn.packageName
        val sourceApp = resolveSourceApp(sourcePackage)

        // If the app is one of our monitored apps, check if it's enabled
        if (sourceApp != null && !PreferencesManager.isAppMonitored(sourceApp)) {
            Log.d(TAG, "Skipping notification from $sourcePackage ($sourceApp) — monitoring disabled by user")
            return
        }

        val extras = sbn.notification?.extras ?: return
        val title = extras.getCharSequence("android.title")?.toString() ?: ""
        val text = extras.getCharSequence("android.text")?.toString() ?: ""
        val bigText = extras.getCharSequence("android.bigText")?.toString() ?: ""

        val combined = "$title $text $bigText"
        val urls = UrlExtractor.extract(combined).distinct()

        if (urls.isNotEmpty()) {
            Log.d(TAG, "Found ${urls.size} deduplicated URL(s) in notification from $sourcePackage")
            
            val intent = Intent(this, OverlayService::class.java).apply {
                putExtra(OverlayService.EXTRA_SOURCE_PACKAGE, sourcePackage)
                putExtra(OverlayService.EXTRA_SOURCE_APP, sourceApp ?: "other")
                putExtra(OverlayService.EXTRA_SENDER_TITLE, title)
                putExtra(OverlayService.EXTRA_FULL_TEXT, combined)
                
                if (urls.size == 1) {
                    putExtra(OverlayService.EXTRA_URL, urls[0])
                } else {
                    putStringArrayListExtra(OverlayService.EXTRA_URLS, ArrayList(urls))
                }
            }
            startForegroundService(intent)
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        // No action needed on removal
    }

    /**
     * Maps a package name to our internal app key (sms/gmail/telegram/whatsapp).
     * Returns null if the package isn't in our monitored list.
     */
    private fun resolveSourceApp(packageName: String): String? {
        for ((appKey, packages) in MONITORED_PACKAGES) {
            if (packageName in packages) return appKey
        }
        return null
    }
}
