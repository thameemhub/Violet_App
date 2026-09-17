package com.zenithal.violet.data.local

import android.content.Context
import android.content.SharedPreferences
import androidx.compose.runtime.mutableStateListOf
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.zenithal.violet.data.models.HistoryEntry

object HistoryStore {
    private const val PREFS_NAME = "violet_history"
    private const val KEY_ENTRIES = "history_entries"

    private lateinit var prefs: SharedPreferences
    private val gson = Gson()
    
    // In-memory observable list for Compose
    val entries = mutableStateListOf<HistoryEntry>()

    fun init(context: Context) {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        load()
    }

    private fun load() {
        val json = prefs.getString(KEY_ENTRIES, null)
        if (json != null) {
            try {
                val type = object : TypeToken<List<HistoryEntry>>() {}.type
                val savedList: List<HistoryEntry> = gson.fromJson(json, type)
                entries.clear()
                entries.addAll(savedList)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    private fun save() {
        val json = gson.toJson(entries.toList())
        prefs.edit().putString(KEY_ENTRIES, json).apply()
    }

    fun add(entry: HistoryEntry) {
        entries.add(0, entry) // newest first
        if (entries.size > 200) entries.removeLast()
        save()
    }

    fun getById(id: String): HistoryEntry? {
        return entries.find { it.id == id }
    }
}
