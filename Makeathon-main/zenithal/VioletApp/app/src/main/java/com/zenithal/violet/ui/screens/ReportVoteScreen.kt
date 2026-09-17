package com.zenithal.violet.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.Spring
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.zenithal.violet.data.api.RetrofitClient
import com.zenithal.violet.data.local.PreferencesManager
import com.zenithal.violet.data.models.VoteRequest
import com.zenithal.violet.ui.theme.*
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ReportVoteScreen(
    url: String,
    onBack: () -> Unit,
) {
    var submitting by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<String?>(null) }
    var reason by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    val deviceId = remember { PreferencesManager.getDeviceId() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Confirm or Dispute") },
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
                .padding(horizontal = 20.dp),
        ) {
            Spacer(Modifier.height(8.dp))

            // URL being voted on
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            ) {
                Text(
                    text = url,
                    modifier = Modifier.padding(14.dp),
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(Modifier.height(24.dp))

            Text(
                "Is this link safe?",
                style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.SemiBold),
            )
            Text(
                "Your vote helps the community. Verified users have more impact.",
                style = MaterialTheme.typography.bodySmall.copy(
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                ),
            )

            Spacer(Modifier.height(20.dp))

            // Optional reason
            OutlinedTextField(
                value = reason,
                onValueChange = { reason = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Reason (optional)") },
                placeholder = { Text("e.g. This is a known scam site...") },
                shape = RoundedCornerShape(14.dp),
                minLines = 2,
                maxLines = 4,
            )

            Spacer(Modifier.height(24.dp))

            if (result != null) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = SafeGreenContainer,
                    ),
                ) {
                    Text(
                        text = result!!,
                        modifier = Modifier.padding(16.dp),
                        style = MaterialTheme.typography.bodyMedium.copy(
                            color = SafeGreen,
                            fontWeight = FontWeight.Medium,
                        ),
                    )
                }
                Spacer(Modifier.height(16.dp))
            }

            // Vote buttons
            val safeInteractionSource = remember { MutableInteractionSource() }
            val safeIsPressed by safeInteractionSource.collectIsPressedAsState()
            val safeScale by animateFloatAsState(
                targetValue = if (safeIsPressed) 0.95f else 1f,
                animationSpec = spring(stiffness = Spring.StiffnessMediumLow), label = "safeScale"
            )

            val riskInteractionSource = remember { MutableInteractionSource() }
            val riskIsPressed by riskInteractionSource.collectIsPressedAsState()
            val riskScale by animateFloatAsState(
                targetValue = if (riskIsPressed) 0.95f else 1f,
                animationSpec = spring(stiffness = Spring.StiffnessMediumLow), label = "riskScale"
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                // SAFE vote
                Button(
                    onClick = {
                        scope.launch {
                            submitting = true
                            try {
                                val resp = RetrofitClient.api.voteSafe(VoteRequest(deviceId, url))
                                result = "Voted SAFE. Safe: ${resp.safeVotes}, Malicious: ${resp.maliciousVotes}"
                            } catch (e: Exception) {
                                result = "Error: ${e.message}"
                            }
                            submitting = false
                        }
                    },
                    modifier = Modifier
                        .weight(1f)
                        .height(52.dp)
                        .scale(safeScale),
                    interactionSource = safeInteractionSource,
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = SafeGreen),
                    enabled = !submitting,
                ) {
                    Icon(Icons.Filled.ThumbUp, null, modifier = Modifier.size(20.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Safe")
                }

                // MALICIOUS vote
                Button(
                    onClick = {
                        scope.launch {
                            submitting = true
                            try {
                                val resp = RetrofitClient.api.voteMalicious(VoteRequest(deviceId, url))
                                result = "Voted MALICIOUS. Safe: ${resp.safeVotes}, Malicious: ${resp.maliciousVotes}"
                            } catch (e: Exception) {
                                result = "Error: ${e.message}"
                            }
                            submitting = false
                        }
                    },
                    modifier = Modifier
                        .weight(1f)
                        .height(52.dp)
                        .scale(riskScale),
                    interactionSource = riskInteractionSource,
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = RiskHigh),
                    enabled = !submitting,
                ) {
                    Icon(Icons.Filled.ThumbDown, null, modifier = Modifier.size(20.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Risky")
                }
            }

            if (submitting) {
                Spacer(Modifier.height(16.dp))
                LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth(),
                    color = VioletPrimary,
                )
            }
        }
    }
}
