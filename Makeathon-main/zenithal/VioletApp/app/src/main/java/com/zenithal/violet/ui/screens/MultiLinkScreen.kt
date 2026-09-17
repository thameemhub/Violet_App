package com.zenithal.violet.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.zenithal.violet.data.api.RetrofitClient
import com.zenithal.violet.data.api.SafeApiCaller
import com.zenithal.violet.data.api.NetworkResult
import com.zenithal.violet.data.local.HistoryStore
import com.zenithal.violet.data.models.HistoryEntry
import com.zenithal.violet.data.models.ReputationResponse
import com.zenithal.violet.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class MultiLinkItemState(
    val url: String,
    val isLoading: Boolean = true,
    val result: ReputationResponse? = null,
    val error: String? = null
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MultiLinkScreen(
    urls: List<String>,
    onBack: () -> Unit,
    onUrlTap: (String) -> Unit
) {
    var itemStates by remember { mutableStateOf(urls.map { MultiLinkItemState(url = it) }) }

    LaunchedEffect(urls) {
        urls.forEachIndexed { index, url ->
            val result = SafeApiCaller.call(maxRetries = 2, tag = "multi_link/$url") {
                RetrofitClient.api.getReputation(url)
            }
            withContext(Dispatchers.Main) {
                val updatedStates = itemStates.toMutableList()
                when (result) {
                    is NetworkResult.Success -> {
                        val rep = result.data
                        updatedStates[index] = updatedStates[index].copy(
                            isLoading = false,
                            result = rep
                        )
                        // Save to history automatically so it appears in Scan History
                        HistoryStore.add(
                            HistoryEntry(
                                url = url,
                                domain = rep.domain,
                                riskScore = rep.fusedRiskScore,
                                verdict = rep.verdict,
                                status = rep.status,
                                sourceApp = "multi_link",
                                senderTitle = "Multiple Links",
                                fullText = null
                            )
                        )
                    }
                    else -> {
                        updatedStates[index] = updatedStates[index].copy(
                            isLoading = false,
                            error = result.errorMessage()
                        )
                    }
                }
                itemStates = updatedStates
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Multiple Links Detected") },
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
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
        ) {
            Text(
                "We found ${urls.size} links in this message. Tap any link to view its full threat report.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(vertical = 12.dp)
            )

            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(12.dp),
                contentPadding = PaddingValues(bottom = 24.dp)
            ) {
                itemsIndexed(itemStates, key = { _, state -> state.url }) { index, state ->
                    MultiLinkCard(state = state, index = index, onClick = { onUrlTap(state.url) })
                }
            }
        }
    }
}

@Composable
private fun MultiLinkCard(state: MultiLinkItemState, index: Int, onClick: () -> Unit) {
    var visible by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        kotlinx.coroutines.delay((index * 50L).coerceAtMost(500L))
        visible = true
    }

    androidx.compose.animation.AnimatedVisibility(
        visible = visible,
        enter = androidx.compose.animation.slideInVertically(
            initialOffsetY = { 50 },
            animationSpec = androidx.compose.animation.core.tween(300, easing = androidx.compose.animation.core.FastOutSlowInEasing)
        ) + androidx.compose.animation.fadeIn(animationSpec = androidx.compose.animation.core.tween(300)),
    ) {
        val score = state.result?.fusedRiskScore ?: 50.0
        val statusColor = when {
            state.isLoading -> Color.Gray
            state.error != null -> Color.Gray
            score >= 70 -> RiskHigh
            score < 30 -> SafeGreen
            else -> PendingAmber
        }
        
        val statusLabel = when {
            state.isLoading -> "SCANNING..."
            state.error != null -> "ERROR"
            state.result?.status == "verified_phishing" -> "PHISHING"
            state.result?.status == "safe" -> "SAFE"
            else -> "UNVERIFIED"
        }

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onClick),
            shape = RoundedCornerShape(14.dp),
            elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        ) {
            Row(
                modifier = Modifier.padding(14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    modifier = Modifier
                        .size(12.dp)
                        .clip(RoundedCornerShape(6.dp))
                        .background(statusColor)
                )
                Spacer(Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = state.result?.domain?.takeIf { it.isNotBlank() } ?: state.url,
                        style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Medium),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = state.url,
                        style = MaterialTheme.typography.bodySmall.copy(
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        ),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Spacer(Modifier.width(8.dp))
                
                if (state.isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.primary
                    )
                } else {
                    SuggestionChip(
                        onClick = onClick,
                        label = {
                            Text(
                                statusLabel,
                                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                            )
                        },
                        colors = SuggestionChipDefaults.suggestionChipColors(
                            containerColor = statusColor.copy(alpha = 0.12f),
                            labelColor = statusColor,
                        ),
                        border = null,
                        modifier = Modifier.height(24.dp),
                    )
                }
            }
        }
    }
}
