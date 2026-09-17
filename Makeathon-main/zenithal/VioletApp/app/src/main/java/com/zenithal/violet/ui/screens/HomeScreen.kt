package com.zenithal.violet.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import com.zenithal.violet.data.api.ConnectionMonitor
import com.zenithal.violet.data.local.PreferencesManager
import com.zenithal.violet.ui.theme.*
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    onNavigateToResult: (String) -> Unit,
    onNavigateToHistory: () -> Unit,
    onNavigateToPermissions: () -> Unit,
    onNavigateToMonitoredApps: (() -> Unit)? = null,
) {
    var urlInput by remember { mutableStateOf("") }
    var isActive by remember { mutableStateOf(PreferencesManager.isOverlayActive) }
    val focusManager = LocalFocusManager.current
    val scope = rememberCoroutineScope()

    // Connection monitoring
    val connectionState by ConnectionMonitor.state.collectAsState()
    LaunchedEffect(Unit) {
        ConnectionMonitor.startMonitoring(this)
    }

    val toggleColor by animateColorAsState(
        targetValue = if (isActive) SafeGreen else MaterialTheme.colorScheme.outline,
        animationSpec = tween(400), label = "toggleColor"
    )

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("\uD83D\uDEE1\uFE0F", style = MaterialTheme.typography.titleLarge)
                        Spacer(Modifier.width(8.dp))
                        Text("Violet", style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold))
                    }
                },
                actions = {
                    IconButton(onClick = onNavigateToPermissions) {
                        Icon(Icons.Outlined.Settings, "Settings")
                    }
                },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                ),
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
        ) {
            Spacer(Modifier.height(8.dp))

            // ── Connection Status Banner ─────────────────────────────────
            ConnectionStatusBanner(
                state = connectionState,
                onRetry = { scope.launch { ConnectionMonitor.checkOnce() } },
            )

            Spacer(Modifier.height(12.dp))

            // ── Protection Status Card ──────────────────────────────────
            val glowAlpha by rememberInfiniteTransition(label = "glow").animateFloat(
                initialValue = 0.2f,
                targetValue = 0.5f,
                animationSpec = infiniteRepeatable(tween(2000), RepeatMode.Reverse),
                label = "glowAlpha"
            )

            Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                if (isActive) {
                    Box(
                        modifier = Modifier
                            .matchParentSize()
                            .padding(top = 8.dp) // shift glow down slightly
                            .alpha(glowAlpha)
                            .background(VioletPrimary, RoundedCornerShape(20.dp))
                    )
                }
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = if (isActive) VioletPrimary else MaterialTheme.colorScheme.surfaceVariant,
                    ),
                    elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(24.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column {
                            Text(
                                text = if (isActive) "Protection Active" else "Protection Paused",
                                style = MaterialTheme.typography.titleMedium.copy(
                                    fontWeight = FontWeight.SemiBold,
                                    color = if (isActive) MaterialTheme.colorScheme.onPrimary
                                    else MaterialTheme.colorScheme.onSurface,
                                )
                            )
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = if (isActive) "Scanning links in real-time"
                                else "Tap toggle to resume scanning",
                                style = MaterialTheme.typography.bodySmall.copy(
                                    color = if (isActive) MaterialTheme.colorScheme.onPrimary.copy(alpha = 0.7f)
                                    else MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            )
                        }
                        Switch(
                            checked = isActive,
                            onCheckedChange = {
                                isActive = it
                                PreferencesManager.isOverlayActive = it
                            },
                            colors = SwitchDefaults.colors(
                                checkedTrackColor = SafeGreen,
                                checkedThumbColor = MaterialTheme.colorScheme.onPrimary,
                            ),
                        )
                    }
                }
            }

            Spacer(Modifier.height(24.dp))

            // ── Manual URL Check ────────────────────────────────────────
            Text(
                "Check a link",
                style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold),
                modifier = Modifier.padding(bottom = 8.dp),
            )
            OutlinedTextField(
                value = urlInput,
                onValueChange = { urlInput = it },
                modifier = Modifier.fillMaxWidth(),
                placeholder = { Text("Paste a URL to scan...") },
                leadingIcon = { Icon(Icons.Outlined.Link, null) },
                trailingIcon = {
                    if (urlInput.isNotBlank()) {
                        IconButton(onClick = {
                            focusManager.clearFocus()
                            onNavigateToResult(urlInput.trim())
                        }) {
                            Icon(Icons.Filled.Search, "Scan",
                                tint = VioletPrimary)
                        }
                    }
                },
                shape = RoundedCornerShape(16.dp),
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                keyboardActions = KeyboardActions(onSearch = {
                    if (urlInput.isNotBlank()) {
                        focusManager.clearFocus()
                        onNavigateToResult(urlInput.trim())
                    }
                }),
            )

            Spacer(Modifier.height(24.dp))

            // ── Quick Actions ───────────────────────────────────────────
            Text(
                "Quick Actions",
                style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold),
                modifier = Modifier.padding(bottom = 12.dp),
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                QuickActionCard(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Outlined.History,
                    label = "History",
                    subtitle = "View past scans",
                    onClick = onNavigateToHistory,
                )
                QuickActionCard(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Outlined.Shield,
                    label = "Permissions",
                    subtitle = "Manage access",
                    onClick = onNavigateToPermissions,
                )
            }

            // ── Monitored Apps quick action ──────────────────────────────
            if (onNavigateToMonitoredApps != null) {
                Spacer(Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    QuickActionCard(
                        modifier = Modifier.weight(1f),
                        icon = Icons.Outlined.Apps,
                        label = "Monitored Apps",
                        subtitle = "SMS, Gmail, WhatsApp...",
                        onClick = onNavigateToMonitoredApps,
                    )
                    Spacer(modifier = Modifier.weight(1f))
                }
            }

            Spacer(Modifier.height(24.dp))

            // ── Status indicator card ───────────────────────────────────
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(10.dp)
                                .clip(CircleShape)
                                .background(toggleColor)
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = if (isActive) "Notification scanner running" else "Scanner paused",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = "Links detected in notifications are automatically scanned against the community database and AI engine.",
                        style = MaterialTheme.typography.bodySmall.copy(
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        ),
                    )
                }
            }

            Spacer(Modifier.height(32.dp))
        }
    }
}

// ── Connection Status Banner ────────────────────────────────────────────────

@Composable
private fun ConnectionStatusBanner(
    state: ConnectionMonitor.ConnectionState,
    onRetry: () -> Unit,
) {
    val (bgColor, dotColor, text, icon) = when (state) {
        ConnectionMonitor.ConnectionState.CONNECTED -> Quad(
            SafeGreen.copy(alpha = 0.1f), SafeGreen,
            "Connected to server", Icons.Filled.CheckCircle,
        )
        ConnectionMonitor.ConnectionState.CHECKING -> Quad(
            PendingAmber.copy(alpha = 0.1f), PendingAmber,
            "Checking connection...", Icons.Filled.Sync,
        )
        ConnectionMonitor.ConnectionState.DISCONNECTED -> Quad(
            RiskHigh.copy(alpha = 0.1f), RiskHigh,
            "Can't reach server", Icons.Filled.CloudOff,
        )
        ConnectionMonitor.ConnectionState.UNKNOWN -> Quad(
            MaterialTheme.colorScheme.surfaceVariant, MaterialTheme.colorScheme.outline,
            "Server status unknown", Icons.Outlined.HelpOutline,
        )
    }

    // Pulsing dot for CHECKING state
    val pulseAlpha = if (state == ConnectionMonitor.ConnectionState.CHECKING) {
        val transition = rememberInfiniteTransition(label = "pulse")
        transition.animateFloat(
            initialValue = 0.3f, targetValue = 1f,
            animationSpec = infiniteRepeatable(tween(600), RepeatMode.Reverse),
            label = "pulseAlpha"
        ).value
    } else 1f

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = bgColor),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                icon, null,
                tint = dotColor,
                modifier = Modifier
                    .size(18.dp)
                    .alpha(pulseAlpha),
            )
            Spacer(Modifier.width(10.dp))
            Text(
                text = text,
                style = MaterialTheme.typography.bodySmall.copy(
                    fontWeight = FontWeight.Medium,
                    color = dotColor,
                ),
                modifier = Modifier.weight(1f),
            )
            if (state == ConnectionMonitor.ConnectionState.DISCONNECTED) {
                TextButton(
                    onClick = onRetry,
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                ) {
                    Text("Retry", style = MaterialTheme.typography.labelSmall)
                }
            }
        }
    }
}

private data class Quad<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)

@Composable
private fun QuickActionCard(
    modifier: Modifier = Modifier,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    subtitle: String,
    onClick: () -> Unit,
) {
    Card(
        modifier = modifier.clickable(onClick = onClick),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Icon(icon, null, tint = VioletPrimary, modifier = Modifier.size(28.dp))
            Spacer(Modifier.height(10.dp))
            Text(label, style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold))
            Text(subtitle, style = MaterialTheme.typography.bodySmall.copy(color = MaterialTheme.colorScheme.onSurfaceVariant))
        }
    }
}
