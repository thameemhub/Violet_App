package com.zenithal.violet.ui.screens

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zenithal.violet.data.api.RetrofitClient
import com.zenithal.violet.data.api.SafeApiCaller
import com.zenithal.violet.data.api.NetworkResult
import com.zenithal.violet.data.models.ReputationResponse
import com.zenithal.violet.ui.theme.*
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UrlResultScreen(
    url: String,
    onBack: () -> Unit,
    onVote: () -> Unit,
) {
    var reputation by remember { mutableStateOf<ReputationResponse?>(null) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    // Fetch function (reusable for retry)
    val fetchReputation: suspend () -> Unit = {
        loading = true
        error = null
        val result = SafeApiCaller.call(maxRetries = 3, tag = "reputation/$url") {
            RetrofitClient.api.getReputation(url)
        }
        when (result) {
            is NetworkResult.Success -> reputation = result.data
            else -> error = result.errorMessage()
        }
        loading = false
    }

    LaunchedEffect(url) {
        fetchReputation()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Scan Result") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                ),
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentAlignment = Alignment.Center,
        ) {
            when {
                loading -> {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        CircularProgressIndicator(color = VioletPrimary)
                        Spacer(Modifier.height(16.dp))
                        Text("Analyzing link...", style = MaterialTheme.typography.bodyMedium)
                    }
                }
                error != null -> {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        modifier = Modifier.padding(horizontal = 32.dp),
                    ) {
                        Icon(Icons.Outlined.CloudOff, null, tint = RiskHigh, modifier = Modifier.size(56.dp))
                        Spacer(Modifier.height(16.dp))
                        Text(
                            "Couldn't Analyze Link",
                            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.SemiBold),
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            error!!,
                            style = MaterialTheme.typography.bodySmall.copy(
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            ),
                            modifier = Modifier.padding(horizontal = 16.dp),
                        )
                        Spacer(Modifier.height(20.dp))
                        Button(
                            onClick = { scope.launch { fetchReputation() } },
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = VioletPrimary),
                        ) {
                            Icon(Icons.Outlined.Refresh, null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Retry")
                        }
                    }
                }
                reputation != null -> {
                    ResultContent(rep = reputation!!, url = url, onVote = onVote)
                }
            }
        }
    }
}

@Composable
private fun ResultContent(rep: ReputationResponse, url: String, onVote: () -> Unit) {
    val score = rep.fusedRiskScore
    val scoreColor = when {
        score >= 70 -> RiskHigh
        score < 30 -> SafeGreen
        else -> PendingAmber
    }
    val statusLabel = when (rep.status) {
        "verified_phishing" -> "VERIFIED PHISHING"
        "safe" -> "SAFE"
        else -> "UNVERIFIED"
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(8.dp))

        val animatedScore by animateFloatAsState(
            targetValue = score.toFloat(),
            animationSpec = tween(600, easing = FastOutSlowInEasing), label = "score"
        )

        // ── Risk Score Gauge ────────────────────────────────────────────
        Box(contentAlignment = Alignment.Center, modifier = Modifier.size(200.dp)) {
            RiskGauge(score = animatedScore, color = scoreColor)
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    text = "${animatedScore.toInt()}",
                    style = MaterialTheme.typography.displayLarge.copy(
                        fontWeight = FontWeight.Bold,
                        color = scoreColor,
                        fontSize = 56.sp,
                    ),
                )
                Text(
                    text = "Risk Score",
                    style = MaterialTheme.typography.bodySmall.copy(
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    ),
                )
            }
        }

        Spacer(Modifier.height(8.dp))

        // ── Status Chip ─────────────────────────────────────────────────
        SuggestionChip(
            onClick = {},
            label = {
                Text(
                    statusLabel,
                    style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.Bold),
                )
            },
            colors = SuggestionChipDefaults.suggestionChipColors(
                containerColor = scoreColor.copy(alpha = 0.12f),
                labelColor = scoreColor,
            ),
            border = SuggestionChipDefaults.suggestionChipBorder(enabled = true, borderColor = scoreColor.copy(alpha = 0.3f)),
        )

        Spacer(Modifier.height(4.dp))
        Text(
            text = rep.verdict,
            style = MaterialTheme.typography.titleSmall.copy(
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            ),
        )

        Spacer(Modifier.height(16.dp))

        // ── URL ─────────────────────────────────────────────────────────
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        ) {
            Text(
                text = url,
                modifier = Modifier.padding(14.dp),
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
            )
        }

        Spacer(Modifier.height(16.dp))

        // ── Source Breakdown ────────────────────────────────────────────
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("Source Breakdown", style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold))
                Spacer(Modifier.height(12.dp))
                BreakdownRow("AI Engine Score", "${rep.aiScore}")
                BreakdownRow("Community Score", "${rep.communityScore ?: "N/A"}")
                BreakdownRow("Reports", "${rep.reportCount}")
                BreakdownRow("Safe Votes", "${rep.safeVotes}")
                BreakdownRow("Malicious Votes", "${rep.maliciousVotes}")
                if (rep.threatType.isNotBlank()) {
                    BreakdownRow("Threat Type", rep.threatType)
                }
            }
        }

        Spacer(Modifier.height(12.dp))

        // ── Domain Intelligence (WHOIS) ─────────────────────────────────
        if (rep.whoisIntelligence != null) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Domain Intelligence", style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold))
                    Spacer(Modifier.height(12.dp))
                    
                    val creation = rep.whoisIntelligence.creationDate ?: "Unknown"
                    BreakdownRow("Creation Date", creation)
                    
                    if (rep.whoisIntelligence.domainAgeDays != null) {
                        BreakdownRow("Domain Age", "${rep.whoisIntelligence.domainAgeDays} days")
                    }
                    if (rep.whoisIntelligence.registrar != null) {
                        BreakdownRow("Registrar", rep.whoisIntelligence.registrar)
                    }
                    if (rep.whoisIntelligence.country != null) {
                        BreakdownRow("Country", rep.whoisIntelligence.country)
                    }
                }
            }
            Spacer(Modifier.height(12.dp))
        }

        // ── Reasons ─────────────────────────────────────────────────────
        if (rep.reasons.isNotEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Analysis Details", style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold))
                    Spacer(Modifier.height(8.dp))
                    rep.reasons.forEach { reason ->
                        Row(modifier = Modifier.padding(vertical = 4.dp)) {
                            Text("\u2022 ", style = MaterialTheme.typography.bodySmall.copy(color = VioletPrimary))
                            Text(reason, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }

        Spacer(Modifier.height(16.dp))

        // ── Vote Button ─────────────────────────────────────────────────
        Button(
            onClick = onVote,
            modifier = Modifier
                .fillMaxWidth()
                .height(50.dp),
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(containerColor = VioletPrimary),
        ) {
            Icon(Icons.Outlined.ThumbsUpDown, null, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(8.dp))
            Text("Confirm or Dispute", style = MaterialTheme.typography.labelLarge)
        }

        Spacer(Modifier.height(32.dp))
    }
}

@Composable
private fun BreakdownRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodySmall.copy(color = MaterialTheme.colorScheme.onSurfaceVariant))
        Text(value, style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Medium))
    }
}

@Composable
private fun RiskGauge(score: Float, color: Color) {
    val animatedSweep by animateFloatAsState(
        targetValue = (score / 100f) * 270f,
        animationSpec = tween(600, easing = FastOutSlowInEasing), label = "sweep"
    )

    Canvas(modifier = Modifier.fillMaxSize().padding(12.dp)) {
        val strokeWidth = 14.dp.toPx()
        val arcSize = Size(size.width - strokeWidth, size.height - strokeWidth)
        val offset = Offset(strokeWidth / 2, strokeWidth / 2)

        // Background track
        drawArc(
            color = color.copy(alpha = 0.12f),
            startAngle = 135f,
            sweepAngle = 270f,
            useCenter = false,
            topLeft = offset,
            size = arcSize,
            style = Stroke(width = strokeWidth, cap = StrokeCap.Round),
        )
        // Filled arc
        drawArc(
            color = color,
            startAngle = 135f,
            sweepAngle = animatedSweep,
            useCenter = false,
            topLeft = offset,
            size = arcSize,
            style = Stroke(width = strokeWidth, cap = StrokeCap.Round),
        )
    }
}
