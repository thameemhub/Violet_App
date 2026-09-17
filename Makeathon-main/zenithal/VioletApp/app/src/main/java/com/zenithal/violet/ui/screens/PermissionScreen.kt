package com.zenithal.violet.ui.screens

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.text.TextUtils
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.zenithal.violet.service.VioletNotificationListener
import com.zenithal.violet.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PermissionScreen(onBack: () -> Unit) {
    val context = LocalContext.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Permissions") },
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

            Text(
                "Required Permissions",
                style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.SemiBold),
            )
            Text(
                "Violet needs these permissions to protect you from phishing links in real time.",
                style = MaterialTheme.typography.bodySmall.copy(
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                ),
            )

            Spacer(Modifier.height(20.dp))

            // ── Notification Access ─────────────────────────────────────
            PermissionCard(
                icon = Icons.Outlined.Notifications,
                title = "Notification Access",
                description = "Allows Violet to read incoming notifications so it can detect links in messages from SMS, Gmail, Telegram, and WhatsApp. You can control which apps are scanned from the Monitored Apps screen. Violet only looks at URLs — it does not store or transmit your message content.",
                isGranted = isNotificationListenerEnabled(context),
                onGrant = {
                    context.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                },
            )

            Spacer(Modifier.height(12.dp))

            // ── Display Over Other Apps ─────────────────────────────────
            PermissionCard(
                icon = Icons.Outlined.Layers,
                title = "Display Over Other Apps",
                description = "Lets Violet show a small banner on top of your screen when a risky link is detected — similar to how Truecaller shows caller ID. The banner auto-dismisses in 6 seconds.",
                isGranted = Settings.canDrawOverlays(context),
                onGrant = {
                    val intent = Intent(
                        Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                        Uri.parse("package:${context.packageName}")
                    )
                    context.startActivity(intent)
                },
            )

            Spacer(Modifier.height(24.dp))

            // Info note
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(
                    containerColor = VioletPrimaryContainer,
                ),
            ) {
                Row(modifier = Modifier.padding(14.dp)) {
                    Icon(
                        Icons.Outlined.Info, null,
                        tint = VioletPrimary,
                        modifier = Modifier.size(20.dp),
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(
                        "Violet is fully offline-capable. Your data stays on your device and is only sent to your own Zenithal backend server.",
                        style = MaterialTheme.typography.bodySmall.copy(
                            color = VioletPrimary,
                        ),
                    )
                }
            }
        }
    }
}

@Composable
private fun PermissionCard(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    description: String,
    isGranted: Boolean,
    onGrant: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, null, tint = VioletPrimary, modifier = Modifier.size(24.dp))
                Spacer(Modifier.width(10.dp))
                Text(title, style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold))
                Spacer(Modifier.weight(1f))
                if (isGranted) {
                    SuggestionChip(
                        onClick = {},
                        label = { Text("Granted", style = MaterialTheme.typography.labelSmall) },
                        colors = SuggestionChipDefaults.suggestionChipColors(
                            containerColor = SafeGreenContainer,
                            labelColor = SafeGreen,
                        ),
                        border = null,
                        modifier = Modifier.height(24.dp),
                    )
                }
            }
            Spacer(Modifier.height(8.dp))
            Text(
                description,
                style = MaterialTheme.typography.bodySmall.copy(
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                ),
            )
            if (!isGranted) {
                Spacer(Modifier.height(12.dp))
                Button(
                    onClick = onGrant,
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = VioletPrimary),
                ) {
                    Text("Grant Permission")
                }
            }
        }
    }
}

private fun isNotificationListenerEnabled(context: Context): Boolean {
    val flat = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners")
    if (TextUtils.isEmpty(flat)) return false
    val component = ComponentName(context, VioletNotificationListener::class.java)
    return flat.contains(component.flattenToString())
}
