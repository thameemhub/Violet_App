package com.zenithal.violet.data.local

import android.content.Context
import android.content.SharedPreferences
import androidx.compose.runtime.mutableIntStateOf
import java.util.UUID

/**
 * Manages the anonymous device_id (UUID generated on first launch),
 * the overlay-active toggle state, and per-app monitoring preferences.
 */
object PreferencesManager {

    private const val PREFS_NAME = "violet_prefs"
    private const val KEY_DEVICE_ID = "device_id"
    private const val KEY_OVERLAY_ACTIVE = "overlay_active"
    private const val KEY_THEME_PREF = "theme_pref"

    // Per-app monitoring keys
    private const val KEY_MONITOR_SMS = "monitor_sms"
    private const val KEY_MONITOR_GMAIL = "monitor_gmail"
    private const val KEY_MONITOR_TELEGRAM = "monitor_telegram"
    private const val KEY_MONITOR_WHATSAPP = "monitor_whatsapp"

    private lateinit var prefs: SharedPreferences

    // 0 = System, 1 = Light, 2 = Dark
    var themePreferenceState = mutableIntStateOf(0)

    fun init(context: Context) {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        themePreferenceState.intValue = prefs.getInt(KEY_THEME_PREF, 0)
    }

    /** Returns the persistent device UUID, creating one on first call. */
    fun getDeviceId(): String {
        var id = prefs.getString(KEY_DEVICE_ID, null)
        if (id == null) {
            id = UUID.randomUUID().toString()
            prefs.edit().putString(KEY_DEVICE_ID, id).apply()
        }
        return id
    }

    var isOverlayActive: Boolean
        get() = prefs.getBoolean(KEY_OVERLAY_ACTIVE, true)
        set(value) = prefs.edit().putBoolean(KEY_OVERLAY_ACTIVE, value).apply()

    fun setThemePreference(pref: Int) {
        prefs.edit().putInt(KEY_THEME_PREF, pref).apply()
        themePreferenceState.intValue = pref
    }

    // ── Per-app monitoring toggles (all ON by default) ──────────────────

    var isMonitorSms: Boolean
        get() = prefs.getBoolean(KEY_MONITOR_SMS, true)
        set(value) = prefs.edit().putBoolean(KEY_MONITOR_SMS, value).apply()

    var isMonitorGmail: Boolean
        get() = prefs.getBoolean(KEY_MONITOR_GMAIL, true)
        set(value) = prefs.edit().putBoolean(KEY_MONITOR_GMAIL, value).apply()

    var isMonitorTelegram: Boolean
        get() = prefs.getBoolean(KEY_MONITOR_TELEGRAM, true)
        set(value) = prefs.edit().putBoolean(KEY_MONITOR_TELEGRAM, value).apply()

    var isMonitorWhatsApp: Boolean
        get() = prefs.getBoolean(KEY_MONITOR_WHATSAPP, true)
        set(value) = prefs.edit().putBoolean(KEY_MONITOR_WHATSAPP, value).apply()

    /**
     * Returns whether a given app key (sms/gmail/telegram/whatsapp) is currently monitored.
     */
    fun isAppMonitored(appKey: String): Boolean = when (appKey) {
        "sms" -> isMonitorSms
        "gmail" -> isMonitorGmail
        "telegram" -> isMonitorTelegram
        "whatsapp" -> isMonitorWhatsApp
        else -> true // Unknown apps are allowed through by default
    }
}
