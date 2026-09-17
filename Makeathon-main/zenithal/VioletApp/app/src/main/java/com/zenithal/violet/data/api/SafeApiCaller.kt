package com.zenithal.violet.data.api

import android.util.Log
import kotlinx.coroutines.delay
import retrofit2.HttpException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException

/**
 * Wraps any suspend Retrofit call with:
 *   • Typed error discrimination (timeout / unreachable / HTTP / unknown)
 *   • Retry with exponential backoff (default 3 attempts, 500 → 1000 → 2000 ms)
 *   • Logcat diagnostics on every attempt
 */
object SafeApiCaller {

    private const val TAG = "SafeApiCaller"

    suspend fun <T> call(
        maxRetries: Int = 3,
        initialDelayMs: Long = 500L,
        tag: String = "",
        block: suspend () -> T,
    ): NetworkResult<T> {
        var lastResult: NetworkResult<T> = NetworkResult.Unknown("No attempts made")
        var currentDelay = initialDelayMs

        repeat(maxRetries) { attempt ->
            Log.d(TAG, "[$tag] Attempt ${attempt + 1}/$maxRetries")

            lastResult = try {
                val data = block()
                Log.d(TAG, "[$tag] Success on attempt ${attempt + 1}")
                return NetworkResult.Success(data)
            } catch (e: SocketTimeoutException) {
                Log.w(TAG, "[$tag] Timeout on attempt ${attempt + 1}: ${e.message}")
                NetworkResult.Timeout("Connection timed out — the server may be slow or unreachable")
            } catch (e: ConnectException) {
                Log.w(TAG, "[$tag] ConnectException on attempt ${attempt + 1}: ${e.message}")
                NetworkResult.Unreachable(
                    "Can't reach the server — check that your phone and laptop are on the same Wi-Fi network and the server is running"
                )
            } catch (e: UnknownHostException) {
                Log.w(TAG, "[$tag] UnknownHostException on attempt ${attempt + 1}: ${e.message}")
                NetworkResult.Unreachable(
                    "Server not found — verify the server IP address is correct"
                )
            } catch (e: HttpException) {
                val code = e.code()
                val msg = e.message() ?: "HTTP error"
                Log.w(TAG, "[$tag] HTTP $code on attempt ${attempt + 1}: $msg")
                // Don't retry on client errors (4xx); only retry on server errors (5xx)
                if (code in 400..499) {
                    return NetworkResult.HttpError(code, msg)
                }
                NetworkResult.HttpError(code, msg)
            } catch (e: Exception) {
                Log.e(TAG, "[$tag] Unexpected error on attempt ${attempt + 1}", e)
                NetworkResult.Unknown(
                    e.localizedMessage ?: "An unexpected error occurred",
                    cause = e
                )
            }

            // Wait before next retry (skip delay after last attempt)
            if (attempt < maxRetries - 1) {
                Log.d(TAG, "[$tag] Retrying in ${currentDelay}ms...")
                delay(currentDelay)
                currentDelay *= 2  // exponential backoff
            }
        }

        Log.e(TAG, "[$tag] All $maxRetries attempts failed")
        return lastResult
    }
}
