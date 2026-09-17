package com.zenithal.violet.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Message
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.zenithal.violet.data.local.PreferencesManager
import com.zenithal.violet.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MonitoredAppsScreen(onBack: () -> Unit) {
    var smsEnabled by remember { mutableStateOf(PreferencesManager.isMonitorSms) }
    var gmailEnabled by remember { mutableStateOf(PreferencesManager.isMonitorGmail) }
    var telegramEnabled by remember { mutableStateOf(PreferencesManager.isMonitorTelegram) }
    var whatsappEnabled by remember { mutableStateOf(PreferencesManager.isMonitorWhatsApp) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
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

            // Explanation card
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = VioletPrimaryContainer),
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        "Link Scanning",
                        style = MaterialTheme.typography.titleSmall.copy(
                            fontWeight = FontWeight.SemiBold,
                            color = VioletPrimary,
                        ),
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Violet scans notifications from the apps below for links and checks them against community reports and AI analysis. Toggle individual apps on or off.",
                        style = MaterialTheme.typography.bodySmall.copy(
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        ),
                    )
                }
            }

            Spacer(Modifier.height(20.dp))

            // Theme Setting
            Text("App Theme", style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold))
            Spacer(Modifier.height(8.dp))
            var themePref by remember { mutableStateOf(PreferencesManager.themePreferenceState.intValue) }
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                SegmentedButton(
                    selected = themePref == 0,
                    onClick = { themePref = 0; PreferencesManager.setThemePreference(0) },
                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 3)
                ) { Text("System") }
                SegmentedButton(
                    selected = themePref == 1,
                    onClick = { themePref = 1; PreferencesManager.setThemePreference(1) },
                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 3)
                ) { Text("Light") }
                SegmentedButton(
                    selected = themePref == 2,
                    onClick = { themePref = 2; PreferencesManager.setThemePreference(2) },
                    shape = SegmentedButtonDefaults.itemShape(index = 2, count = 3)
                ) { Text("Dark") }
            }

            Spacer(Modifier.height(24.dp))
            Text("Monitored Apps", style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold))
            Spacer(Modifier.height(8.dp))
            AppToggleItem(
                icon = Icons.AutoMirrored.Filled.Message,
                appName = "SMS / Messages",
                description = "Google Messages, default SMS app",
                enabled = smsEnabled,
                onToggle = {
                    smsEnabled = it
                    PreferencesManager.isMonitorSms = it
                },
            )
            HorizontalDivider(modifier = Modifier.padding(horizontal = 8.dp))

            AppToggleItem(
                icon = Icons.Filled.Email,
                appName = "Gmail",
                description = "Google Gmail notifications",
                enabled = gmailEnabled,
                onToggle = {
                    gmailEnabled = it
                    PreferencesManager.isMonitorGmail = it
                },
            )
            HorizontalDivider(modifier = Modifier.padding(horizontal = 8.dp))

            AppToggleItem(
                icon = Icons.Filled.Send,
                appName = "Telegram",
                description = "Telegram Messenger notifications",
                enabled = telegramEnabled,
                onToggle = {
                    telegramEnabled = it
                    PreferencesManager.isMonitorTelegram = it
                },
            )
            HorizontalDivider(modifier = Modifier.padding(horizontal = 8.dp))

            AppToggleItem(
                icon = Icons.Filled.Chat,
                appName = "WhatsApp",
                description = "WhatsApp & WhatsApp Business",
                enabled = whatsappEnabled,
                onToggle = {
                    whatsappEnabled = it
                    PreferencesManager.isMonitorWhatsApp = it
                },
            )

            Spacer(Modifier.height(24.dp))

            // Info note
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant,
                ),
            ) {
                Row(
                    modifier = Modifier.padding(14.dp),
                    verticalAlignment = Alignment.Top,
                ) {
                    Icon(
                        Icons.Filled.Info,
                        null,
                        tint = VioletSecondary,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(
                        "Notification Access must be enabled for scanning to work. Links from other apps are also scanned when they send notifications containing URLs.",
                        style = MaterialTheme.typography.bodySmall.copy(
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        ),
                    )
                }
            }
        }
    }
}

@Composable
private fun AppToggleItem(
    icon: ImageVector,
    appName: String,
    description: String,
    enabled: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 14.dp, horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            icon, null,
            tint = if (enabled) VioletPrimary else MaterialTheme.colorScheme.outline,
            modifier = Modifier.size(28.dp),
        )
        Spacer(Modifier.width(16.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                appName,
                style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Medium),
            )
            Text(
                description,
                style = MaterialTheme.typography.bodySmall.copy(
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                ),
            )
        }
        Switch(
            checked = enabled,
            onCheckedChange = onToggle,
            colors = SwitchDefaults.colors(
                checkedTrackColor = VioletPrimary,
                checkedThumbColor = MaterialTheme.colorScheme.onPrimary,
            ),
        )
    }
}
