package com.zenithal.violet.data.models

import com.google.gson.annotations.SerializedName

// ── Request Bodies ──────────────────────────────────────────────────────────

data class ReportRequest(
    @SerializedName("device_id") val deviceId: String,
    val url: String,
    val reason: String = "",
)

data class VoteRequest(
    @SerializedName("device_id") val deviceId: String,
    val url: String,
)

// ── Response Bodies ─────────────────────────────────────────────────────────

data class ReportResponse(
    val status: String,
    @SerializedName("report_id") val reportId: Int,
    val url: String,
    val domain: String,
    @SerializedName("report_count") val reportCount: Int,
    @SerializedName("community_risk_score") val communityRiskScore: Double,
    @SerializedName("url_status") val urlStatus: String,
    @SerializedName("user_trust_score") val userTrustScore: Double,
)

data class ReputationResponse(
    val url: String,
    val domain: String,
    @SerializedName("fused_risk_score") val fusedRiskScore: Double,
    val status: String,
    @SerializedName("ai_score") val aiScore: Double,
    @SerializedName("community_score") val communityScore: Double?,
    @SerializedName("report_count") val reportCount: Int,
    @SerializedName("safe_votes") val safeVotes: Int,
    @SerializedName("malicious_votes") val maliciousVotes: Int,
    val verdict: String,
    @SerializedName("threat_type") val threatType: String,
    val reasons: List<String>,
    @SerializedName("whois_intelligence") val whoisIntelligence: WhoisIntelligence? = null,
    @SerializedName("ssl_intelligence") val sslIntelligence: SslIntelligence? = null,
)

data class WhoisIntelligence(
    @SerializedName("creation_date") val creationDate: String?,
    @SerializedName("domain_age_days") val domainAgeDays: Int?,
    val registrar: String?,
    val country: String?,
)

data class SslIntelligence(
    @SerializedName("ssl_exists") val sslExists: Boolean,
    val issuer: String?,
    @SerializedName("certificate_age_days") val certificateAgeDays: Int?,
)

data class VoteResponse(
    val status: String,
    val url: String,
    @SerializedName("safe_votes") val safeVotes: Int,
    @SerializedName("malicious_votes") val maliciousVotes: Int,
    @SerializedName("community_risk_score") val communityRiskScore: Double,
    @SerializedName("url_status") val urlStatus: String,
)

// ── Local history entry (in-memory for now) ─────────────────────────────────

data class HistoryEntry(
    val id: String = java.util.UUID.randomUUID().toString(),
    val url: String,
    val domain: String,
    val riskScore: Double,
    val verdict: String,
    val status: String,
    val sourceApp: String? = null,
    val senderTitle: String? = null,
    val fullText: String? = null,
    val timestamp: Long = System.currentTimeMillis(),
)
