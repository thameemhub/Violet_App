package com.zenithal.violet.data.api

import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Periodically checks backend reachability by hitting /api/v1/health.
 * Exposes a [ConnectionState] flow for the UI to observe.
 */
object ConnectionMonitor {

    private const val TAG = "ConnectionMonitor"
    private const val CHECK_INTERVAL_MS = 30_000L  // 30 seconds

    enum class ConnectionState {
        CONNECTED,
        CHECKING,
        DISCONNECTED,
        UNKNOWN,
    }

    private val _state = MutableStateFlow(ConnectionState.UNKNOWN)
    val state: StateFlow<ConnectionState> = _state.asStateFlow()

    private var monitorJob: Job? = null

    /** Start periodic health checks. Safe to call multiple times. */
    fun startMonitoring(scope: CoroutineScope) {
        if (monitorJob?.isActive == true) return
        monitorJob = scope.launch {
            while (isActive) {
                checkOnce()
                delay(CHECK_INTERVAL_MS)
            }
        }
    }

    /** Run a single health check now. */
    suspend fun checkOnce() {
        _state.value = ConnectionState.CHECKING
        val result = SafeApiCaller.call(maxRetries = 1, tag = "health-check") {
            // A simple GET to the root endpoint to check reachability
            RetrofitClient.api.healthCheck()
        }
        _state.value = if (result.isSuccess) {
            Log.d(TAG, "Backend reachable")
            ConnectionState.CONNECTED
        } else {
            Log.w(TAG, "Backend unreachable: ${result.errorMessage()}")
            ConnectionState.DISCONNECTED
        }
    }

    fun stop() {
        monitorJob?.cancel()
        monitorJob = null
    }
}
