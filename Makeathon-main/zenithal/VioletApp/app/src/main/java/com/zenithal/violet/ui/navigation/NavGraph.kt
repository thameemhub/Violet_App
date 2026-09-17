package com.zenithal.violet.ui.navigation

import androidx.compose.animation.*
import androidx.compose.animation.core.tween
import androidx.compose.runtime.Composable
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.zenithal.violet.ui.screens.*

object Routes {
    const val SPLASH = "splash"
    const val HOME = "home"
    const val URL_RESULT = "url_result/{url}"
    const val HISTORY = "history"
    const val REPORT_VOTE = "report_vote/{url}"
    const val PERMISSIONS = "permissions"
    const val MONITORED_APPS = "monitored_apps"
    const val MULTI_LINK = "multi_link/{urls}"

    fun urlResult(url: String) = "url_result/${java.net.URLEncoder.encode(url, "UTF-8")}"
    fun reportVote(url: String) = "report_vote/${java.net.URLEncoder.encode(url, "UTF-8")}"
    fun multiLink(urls: List<String>) = "multi_link/${java.net.URLEncoder.encode(urls.joinToString(","), "UTF-8")}"
}

@Composable
fun VioletNavGraph(navController: NavHostController, startDestination: String? = null) {
    NavHost(
        navController = navController,
        startDestination = startDestination ?: Routes.SPLASH,
        enterTransition = { slideInHorizontally(tween(300)) { it } + fadeIn(tween(300)) },
        exitTransition = { slideOutHorizontally(tween(300)) { -it } + fadeOut(tween(300)) },
        popEnterTransition = { slideInHorizontally(tween(300)) { -it } + fadeIn(tween(300)) },
        popExitTransition = { slideOutHorizontally(tween(300)) { it } + fadeOut(tween(300)) },
    ) {
        composable(
            route = Routes.SPLASH,
            exitTransition = { fadeOut(animationSpec = tween(600)) }
        ) {
            SplashScreen(onFinished = {
                navController.navigate(Routes.HOME) {
                    popUpTo(Routes.SPLASH) { inclusive = true }
                }
            })
        }

        composable(
            route = Routes.HOME,
            enterTransition = {
                if (initialState.destination.route == Routes.SPLASH) {
                    fadeIn(animationSpec = tween(600))
                } else {
                    slideInHorizontally(tween(300)) { it } + fadeIn(tween(300))
                }
            }
        ) {
            HomeScreen(
                onNavigateToResult = { url -> navController.navigate(Routes.urlResult(url)) },
                onNavigateToHistory = { navController.navigate(Routes.HISTORY) },
                onNavigateToPermissions = { navController.navigate(Routes.PERMISSIONS) },
                onNavigateToMonitoredApps = { navController.navigate(Routes.MONITORED_APPS) },
            )
        }

        composable(
            Routes.URL_RESULT,
            arguments = listOf(navArgument("url") { type = NavType.StringType })
        ) { backStack ->
            val url = java.net.URLDecoder.decode(
                backStack.arguments?.getString("url") ?: "", "UTF-8"
            )
            UrlResultScreen(
                url = url,
                onBack = { navController.popBackStack() },
                onVote = { navController.navigate(Routes.reportVote(url)) },
            )
        }

        composable(Routes.HISTORY) {
            HistoryScreen(
                onBack = { navController.popBackStack() },
                onUrlTap = { url -> navController.navigate(Routes.urlResult(url)) },
            )
        }

        composable(
            Routes.REPORT_VOTE,
            arguments = listOf(navArgument("url") { type = NavType.StringType })
        ) { backStack ->
            val url = java.net.URLDecoder.decode(
                backStack.arguments?.getString("url") ?: "", "UTF-8"
            )
            ReportVoteScreen(
                url = url,
                onBack = { navController.popBackStack() },
            )
        }

        composable(Routes.PERMISSIONS) {
            PermissionScreen(onBack = { navController.popBackStack() })
        }

        composable(Routes.MONITORED_APPS) {
            MonitoredAppsScreen(onBack = { navController.popBackStack() })
        }

        composable(
            "message_detail/{id}",
            arguments = listOf(navArgument("id") { type = NavType.StringType })
        ) { backStack ->
            val id = backStack.arguments?.getString("id") ?: ""
            MessageDetailScreen(
                entryId = id,
                onBack = {
                    // Fallback to home if deep linked
                    if (!navController.popBackStack()) {
                        navController.navigate(Routes.HOME) {
                            popUpTo(0) { inclusive = true }
                        }
                    }
                },
                onVote = { url -> navController.navigate(Routes.reportVote(url)) }
            )
        }

        composable(
            "multi_link/{urls}",
            arguments = listOf(navArgument("urls") { type = NavType.StringType })
        ) { backStack ->
            val urlsStr = java.net.URLDecoder.decode(
                backStack.arguments?.getString("urls") ?: "", "UTF-8"
            )
            val urls = urlsStr.split(",").filter { it.isNotBlank() }
            MultiLinkScreen(
                urls = urls,
                onBack = {
                    if (!navController.popBackStack()) {
                        navController.navigate(Routes.HOME) {
                            popUpTo(0) { inclusive = true }
                        }
                    }
                },
                onUrlTap = { url -> navController.navigate(Routes.urlResult(url)) }
            )
        }
    }
}
