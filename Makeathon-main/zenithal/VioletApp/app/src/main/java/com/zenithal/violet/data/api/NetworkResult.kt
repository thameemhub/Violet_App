package com.zenithal.violet.data.api

/**
 * Sealed hierarchy representing the possible outcomes of a network call.
 * Callers can pattern-match to show distinct UI for each failure mode.
 */
sealed class NetworkResult<out T> {

    data class Success<T>(val data: T) : NetworkResult<T>()

    /** Server returned a non-2xx HTTP status. */
    data class HttpError(val code: Int, val message: String) : NetworkResult<Nothing>()

    /** The connection attempt timed out. */
    data class Timeout(val message: String = "Connection timed out") : NetworkResult<Nothing>()

    /** Host unreachable — wrong IP, server not running, or different Wi-Fi network. */
    data class Unreachable(
        val message: String = "Can't reach the server — check that your phone and laptop are on the same Wi-Fi network and the server is running"
    ) : NetworkResult<Nothing>()

    /** Catch-all for unexpected errors. */
    data class Unknown(val message: String, val cause: Throwable? = null) : NetworkResult<Nothing>()

    val isSuccess: Boolean get() = this is Success

    fun getOrNull(): T? = (this as? Success)?.data

    /** Human-readable error message for UI display. */
    fun errorMessage(): String = when (this) {
        is Success -> ""
        is HttpError -> "Server error ($code): $message"
        is Timeout -> message
        is Unreachable -> message
        is Unknown -> message
    }
}
