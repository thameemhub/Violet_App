package com.zenithal.violet

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.navigation.compose.rememberNavController
import com.zenithal.violet.data.local.PreferencesManager
import com.zenithal.violet.data.local.HistoryStore
import com.zenithal.violet.ui.navigation.Routes
import com.zenithal.violet.ui.navigation.VioletNavGraph
import com.zenithal.violet.ui.theme.VioletTheme

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        PreferencesManager.init(applicationContext)
        HistoryStore.init(applicationContext)

        // If launched from overlay tap or notification, determine start destination
        val navigateTo = intent?.getStringExtra("navigate_to")
        val deepLinkUrl = intent?.getStringExtra("url")
        val entryId = intent?.getStringExtra("entry_id")

        val startDest = when (navigateTo) {
            "message_detail" -> "message_detail/$entryId"
            "multi_link" -> {
                val urls = intent?.getStringArrayListExtra("urls")?.joinToString(",") ?: ""
                "multi_link/${java.net.URLEncoder.encode(urls, "UTF-8")}"
            }
            "url_result" -> deepLinkUrl?.let { Routes.urlResult(it) }
            else -> null
        }

        setContent {
            VioletTheme {
                val navController = rememberNavController()
                VioletNavGraph(
                    navController = navController,
                    startDestination = startDest,
                )
            }
        }
    }
}
