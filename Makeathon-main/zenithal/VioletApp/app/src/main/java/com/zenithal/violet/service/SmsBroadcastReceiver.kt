package com.zenithal.violet.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log
import com.zenithal.violet.data.local.PreferencesManager

/**
 * Receives incoming SMS messages via the SMS_RECEIVED broadcast.
 * Scans the full message body (not just the notification preview) for URLs
 * and triggers the OverlayService for each detected link.
 *
 * Requires android.permission.RECEIVE_SMS and READ_SMS.
 */
class SmsBroadcastReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "SmsBroadcastReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        if (!PreferencesManager.isOverlayActive) return
        if (!PreferencesManager.isMonitorSms) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent) ?: return

        for (sms in messages) {
            val body = sms.messageBody ?: continue
            val sender = sms.displayOriginatingAddress ?: "unknown"
            val urls = UrlExtractor.extract(body).distinct()

            if (urls.isNotEmpty()) {
                Log.d(TAG, "Found ${urls.size} deduplicated URL(s) in SMS from $sender")
                
                val overlayIntent = Intent(context, OverlayService::class.java).apply {
                    putExtra(OverlayService.EXTRA_SOURCE_PACKAGE, "sms_broadcast")
                    putExtra(OverlayService.EXTRA_SOURCE_APP, "sms")
                    putExtra(OverlayService.EXTRA_SENDER_TITLE, sender)
                    putExtra(OverlayService.EXTRA_FULL_TEXT, body)
                    
                    if (urls.size == 1) {
                        putExtra(OverlayService.EXTRA_URL, urls[0])
                    } else {
                        putStringArrayListExtra(OverlayService.EXTRA_URLS, ArrayList(urls))
                    }
                }
                context.startForegroundService(overlayIntent)
            }
        }
    }
}
