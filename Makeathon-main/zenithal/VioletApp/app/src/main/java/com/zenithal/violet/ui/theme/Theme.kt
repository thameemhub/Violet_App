package com.zenithal.violet.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
import com.zenithal.violet.data.local.PreferencesManager

private val LightColorScheme = lightColorScheme(
    primary              = VioletPrimary,
    onPrimary            = LightSurface,
    primaryContainer     = VioletPrimaryContainer,
    onPrimaryContainer   = VioletPrimary,
    secondary            = VioletSecondary,
    onSecondary          = LightSurface,
    tertiary             = VioletTertiary,
    background           = LightBackground,
    onBackground         = LightOnBackground,
    surface              = LightSurface,
    onSurface            = LightOnSurface,
    surfaceVariant       = LightSurfaceVariant,
    onSurfaceVariant     = LightOnSurfaceVariant,
    outline              = LightOutline,
    error                = RiskHigh,
    errorContainer       = RiskHighContainer,
)

private val DarkColorScheme = darkColorScheme(
    primary              = VioletSecondary,
    onPrimary            = DarkBackground,
    primaryContainer     = VioletPrimary,
    onPrimaryContainer   = VioletPrimaryContainer,
    secondary            = VioletTertiary,
    onSecondary          = DarkBackground,
    tertiary             = VioletPrimaryContainer,
    background           = DarkBackground,
    onBackground         = DarkOnBackground,
    surface              = DarkSurface,
    onSurface            = DarkOnSurface,
    surfaceVariant       = DarkSurfaceVariant,
    onSurfaceVariant     = DarkOnSurfaceVariant,
    outline              = DarkOutline,
    error                = RiskHigh,
    errorContainer       = RiskHighContainer,
)

@Composable
fun VioletTheme(
    content: @Composable () -> Unit
) {
    val themePref = PreferencesManager.themePreferenceState.intValue
    val darkTheme = when (themePref) {
        1 -> false // Light
        2 -> true  // Dark
        else -> isSystemInDarkTheme() // 0 = System
    }
    
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.background.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = !darkTheme
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = VioletTypography,
        content = content,
    )
}
