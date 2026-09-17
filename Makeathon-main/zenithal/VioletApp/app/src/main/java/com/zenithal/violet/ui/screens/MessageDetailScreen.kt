package com.zenithal.violet.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import com.zenithal.violet.data.local.HistoryStore
import com.zenithal.violet.ui.theme.*
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MessageDetailScreen(
    entryId: String,
    onBack: () -> Unit,
    onVote: (String) -> Unit,
) {
    val entry = remember(entryId) { HistoryStore.getById(entryId) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Message Detail") },
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
        if (entry == null) {
            Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center,
            ) {
                Text("Message not found.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            return@Scaffold
        }

        val scoreColor = when {
            entry.riskScore >= 70 -> RiskHigh
            entry.riskScore < 30 -> SafeGreen
            else -> PendingAmber
        }

        val dateFormat = remember { SimpleDateFormat("MMM dd, yyyy \u2022 hh:mm a", Locale.getDefault()) }

        val animatedScore by androidx.compose.animation.core.animateFloatAsState(
            targetValue = entry.riskScore.toFloat(),
            animationSpec = androidx.compose.animation.core.tween(600, easing = androidx.compose.animation.core.FastOutSlowInEasing),
            label = "score"
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(padding)
                .padding(horizontal = 20.dp),
        ) {
            Spacer(Modifier.height(16.dp))

            // ── Verdict Header ──────────────────────────────────────────────
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = scoreColor.copy(alpha = 0.1f)),
                border = CardDefaults.outlinedCardBorder(true).copy(width = 1.dp, brush = androidx.compose.ui.graphics.SolidColor(scoreColor.copy(alpha = 0.3f)))
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        if (entry.riskScore >= 70) Icons.Filled.Warning else Icons.Outlined.Info,
                        contentDescription = null,
                        tint = scoreColor,
                        modifier = Modifier.size(28.dp)
                    )
                    Spacer(Modifier.width(16.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = if (entry.riskScore >= 70) "Risky Link Detected" else if (entry.riskScore < 30) "Safe Link" else "Unverified Link",
                            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold, color = scoreColor)
                        )
                        Text(
                            text = "Risk Score: ${animatedScore.toInt()}",
                            style = MaterialTheme.typography.bodySmall.copy(color = MaterialTheme.colorScheme.onSurfaceVariant)
                        )
                    }
                }
            }

            Spacer(Modifier.height(24.dp))

            // ── Message Context ─────────────────────────────────────────────
            Text("Original Message", style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold))
            Spacer(Modifier.height(8.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    // App and Sender
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        val iconRes = when (entry.sourceApp) {
                            "sms" -> Icons.Outlined.Sms
                            "gmail" -> Icons.Outlined.Email
                            "telegram" -> Icons.Outlined.Send
                            "whatsapp" -> Icons.Outlined.ChatBubbleOutline
                            else -> Icons.Outlined.Notifications
                        }
                        Icon(iconRes, null, modifier = Modifier.size(16.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = (entry.sourceApp?.uppercase() ?: "UNKNOWN") + " \u2022 " + (entry.senderTitle ?: "Unknown Sender"),
                            style = MaterialTheme.typography.labelMedium.copy(color = MaterialTheme.colorScheme.onSurfaceVariant)
                        )
                    }
                    
                    Spacer(Modifier.height(12.dp))
                    
                    // Full text with highlighted URL
                    val fullText = entry.fullText ?: entry.url
                    val urlIndex = fullText.indexOf(entry.url)
                    
                    val annotatedText = buildAnnotatedString {
                        if (urlIndex != -1) {
                            append(fullText.substring(0, urlIndex))
                            withStyle(style = SpanStyle(color = VioletPrimary, textDecoration = TextDecoration.Underline, fontWeight = FontWeight.Medium)) {
                                append(entry.url)
                            }
                            append(fullText.substring(urlIndex + entry.url.length))
                        } else {
                            append(fullText)
                            append("\n\n")
                            withStyle(style = SpanStyle(color = VioletPrimary, textDecoration = TextDecoration.Underline, fontWeight = FontWeight.Medium)) {
                                append(entry.url)
                            }
                        }
                    }

                    Text(
                        text = annotatedText,
                        style = MaterialTheme.typography.bodyMedium
                    )
                    
                    Spacer(Modifier.height(12.dp))
                    Text(
                        text = dateFormat.format(Date(entry.timestamp)),
                        style = MaterialTheme.typography.labelSmall.copy(color = MaterialTheme.colorScheme.onSurfaceVariant)
                    )
                }
            }

            Spacer(Modifier.height(24.dp))
            
            // ── Vote Actions ────────────────────────────────────────────────
            Button(
                onClick = { onVote(entry.url) },
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
}
