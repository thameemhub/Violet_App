package com.zenithal.violet.service

/**
 * Extracts URLs from arbitrary text (notification body, messages, etc.)
 * using a lenient regex that catches http(s) links and common shorteners.
 */
object UrlExtractor {

    private val URL_REGEX = Regex(
        """(https?://[^\s<>"']+|(?:www\.|bit\.ly/|tinyurl\.com/)[^\s<>"']+)""",
        RegexOption.IGNORE_CASE
    )

    /** Returns all URLs found in [text]. */
    fun extract(text: String): List<String> =
        URL_REGEX.findAll(text)
            .map { match ->
                val url = match.value
                if ("://" in url) url else "http://$url"
            }
            .toList()
}
