package com.gotohex.rdp.data.repository

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.*
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "hex_rdp_settings")

data class AppSettings(
    val isDarkMode: Boolean = true,
    val language: String = "system",
    val themeVariant: String = "space",
    val cursorStyle: String = "default",
    val cursorSize: Int = 24,
    val showCursorOnTouch: Boolean = true,
    val touchpadSensitivity: Float = 1.0f,
    val scrollSensitivity: Float = 1.0f,        // ✅ مُفعَّل الآن
    val showSubscribePopup: Boolean = true,
    val lastSubscribePromptTime: Long = 0L,
    val subscribePromptIntervalDays: Int = 3,
    val hasShownFirstLaunch: Boolean = false,
    val hapticFeedback: Boolean = true,
    val keepScreenOn: Boolean = true,            // ✅ مُفعَّل الآن
    val autoReconnect: Boolean = true,           // ✅ مُفعَّل الآن
    val autoReconnectAttempts: Int = 3,
    val compressionQuality: Int = 75,
    val showFpsCounter: Boolean = false,
    val defaultResolution: String = "auto",
    val sessionToolbarVisible: Boolean = true,
    val sessionExtraKeysVisible: Boolean = true,
    val runInBackground: Boolean = true,
    val soundEnabled: Boolean = true,
    val biometricLockEnabled: Boolean = false,   // ✅ جديد: قفل بالبصمة
    val pinLockEnabled: Boolean = false,         // ✅ جديد: قفل بالرمز
    val pinCode: String = "",                    // مُشفَّر
    val rightClickLongPress: Boolean = true,     // ✅ جديد: كليك أيمن بالضغط المطوّل
    val hasShownGestureHints: Boolean = false,   // UX-07: gesture overlay shown once
)

@Singleton
class AppSettingsRepository @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private object Keys {
        val IS_DARK_MODE            = booleanPreferencesKey("is_dark_mode")
        val LANGUAGE                = stringPreferencesKey("language")
        val THEME_VARIANT           = stringPreferencesKey("theme_variant")
        val CURSOR_STYLE            = stringPreferencesKey("cursor_style")
        val CURSOR_SIZE             = intPreferencesKey("cursor_size")
        val SHOW_CURSOR_ON_TOUCH    = booleanPreferencesKey("show_cursor_on_touch")
        val TOUCHPAD_SENSITIVITY    = floatPreferencesKey("touchpad_sensitivity")
        val SCROLL_SENSITIVITY      = floatPreferencesKey("scroll_sensitivity")
        val SHOW_SUBSCRIBE_POPUP    = booleanPreferencesKey("show_subscribe_popup")
        val LAST_SUBSCRIBE_PROMPT   = longPreferencesKey("last_subscribe_prompt")
        val SUBSCRIBE_INTERVAL_DAYS = intPreferencesKey("subscribe_interval_days")
        val HAS_SHOWN_FIRST_LAUNCH  = booleanPreferencesKey("has_shown_first_launch")
        val HAPTIC_FEEDBACK         = booleanPreferencesKey("haptic_feedback")
        val KEEP_SCREEN_ON          = booleanPreferencesKey("keep_screen_on")
        val AUTO_RECONNECT          = booleanPreferencesKey("auto_reconnect")
        val AUTO_RECONNECT_ATTEMPTS = intPreferencesKey("auto_reconnect_attempts")
        val COMPRESSION_QUALITY     = intPreferencesKey("compression_quality")
        val SHOW_FPS_COUNTER        = booleanPreferencesKey("show_fps_counter")
        val DEFAULT_RESOLUTION      = stringPreferencesKey("default_resolution")
        val SESSION_TOOLBAR_VISIBLE     = booleanPreferencesKey("session_toolbar_visible")
        val SESSION_EXTRA_KEYS_VISIBLE  = booleanPreferencesKey("session_extra_keys_visible")
        val RUN_IN_BACKGROUND       = booleanPreferencesKey("run_in_background")
        val SOUND_ENABLED           = booleanPreferencesKey("sound_enabled")
        val BIOMETRIC_LOCK_ENABLED  = booleanPreferencesKey("biometric_lock_enabled")
        val PIN_LOCK_ENABLED        = booleanPreferencesKey("pin_lock_enabled")
        val PIN_CODE                = stringPreferencesKey("pin_code")
        val RIGHT_CLICK_LONG_PRESS  = booleanPreferencesKey("right_click_long_press")
        val HAS_SHOWN_GESTURE_HINTS = booleanPreferencesKey("has_shown_gesture_hints")
    }

    val settingsFlow: Flow<AppSettings> = context.dataStore.data
        .catch { if (it is IOException) emit(emptyPreferences()) else throw it }
        .map { prefs ->
            AppSettings(
                isDarkMode              = prefs[Keys.IS_DARK_MODE] ?: true,
                language                = prefs[Keys.LANGUAGE] ?: "system",
                themeVariant            = prefs[Keys.THEME_VARIANT] ?: "space",
                cursorStyle             = prefs[Keys.CURSOR_STYLE] ?: "default",
                cursorSize              = prefs[Keys.CURSOR_SIZE] ?: 24,
                showCursorOnTouch       = prefs[Keys.SHOW_CURSOR_ON_TOUCH] ?: true,
                touchpadSensitivity     = prefs[Keys.TOUCHPAD_SENSITIVITY] ?: 1.0f,
                scrollSensitivity       = prefs[Keys.SCROLL_SENSITIVITY] ?: 1.0f,
                showSubscribePopup      = prefs[Keys.SHOW_SUBSCRIBE_POPUP] ?: true,
                lastSubscribePromptTime = prefs[Keys.LAST_SUBSCRIBE_PROMPT] ?: 0L,
                subscribePromptIntervalDays = prefs[Keys.SUBSCRIBE_INTERVAL_DAYS] ?: 3,
                hasShownFirstLaunch     = prefs[Keys.HAS_SHOWN_FIRST_LAUNCH] ?: false,
                hapticFeedback          = prefs[Keys.HAPTIC_FEEDBACK] ?: true,
                keepScreenOn            = prefs[Keys.KEEP_SCREEN_ON] ?: true,
                autoReconnect           = prefs[Keys.AUTO_RECONNECT] ?: true,
                autoReconnectAttempts   = prefs[Keys.AUTO_RECONNECT_ATTEMPTS] ?: 3,
                compressionQuality      = prefs[Keys.COMPRESSION_QUALITY] ?: 75,
                showFpsCounter          = prefs[Keys.SHOW_FPS_COUNTER] ?: false,
                defaultResolution       = prefs[Keys.DEFAULT_RESOLUTION] ?: "auto",
                sessionToolbarVisible   = prefs[Keys.SESSION_TOOLBAR_VISIBLE] ?: true,
                sessionExtraKeysVisible = prefs[Keys.SESSION_EXTRA_KEYS_VISIBLE] ?: true,
                runInBackground         = prefs[Keys.RUN_IN_BACKGROUND] ?: true,
                soundEnabled            = prefs[Keys.SOUND_ENABLED] ?: true,
                biometricLockEnabled    = prefs[Keys.BIOMETRIC_LOCK_ENABLED] ?: false,
                pinLockEnabled          = prefs[Keys.PIN_LOCK_ENABLED] ?: false,
                pinCode                 = prefs[Keys.PIN_CODE] ?: "",
                rightClickLongPress     = prefs[Keys.RIGHT_CLICK_LONG_PRESS] ?: true,
                hasShownGestureHints    = prefs[Keys.HAS_SHOWN_GESTURE_HINTS] ?: false,
            )
        }

    suspend fun updateDarkMode(v: Boolean)              = update { it[Keys.IS_DARK_MODE] = v }
    suspend fun updateLanguage(v: String)               = update { it[Keys.LANGUAGE] = v }
    suspend fun updateThemeVariant(v: String)           = update { it[Keys.THEME_VARIANT] = v }
    suspend fun updateCursorStyle(v: String)            = update { it[Keys.CURSOR_STYLE] = v }
    suspend fun updateCursorSize(v: Int)                = update { it[Keys.CURSOR_SIZE] = v }
    suspend fun updateTouchpadSensitivity(v: Float)     = update { it[Keys.TOUCHPAD_SENSITIVITY] = v }
    suspend fun updateScrollSensitivity(v: Float)       = update { it[Keys.SCROLL_SENSITIVITY] = v }   // ✅ جديد
    suspend fun updateHapticFeedback(v: Boolean)        = update { it[Keys.HAPTIC_FEEDBACK] = v }
    suspend fun updateKeepScreenOn(v: Boolean)          = update { it[Keys.KEEP_SCREEN_ON] = v }       // ✅ جديد
    suspend fun updateAutoReconnect(v: Boolean)         = update { it[Keys.AUTO_RECONNECT] = v }
    suspend fun updateAutoReconnectAttempts(v: Int)     = update { it[Keys.AUTO_RECONNECT_ATTEMPTS] = v }
    suspend fun updateCompressionQuality(v: Int)        = update {
        // BUG-CLAMP FIX: Bitmap.compress() requires quality in [0, 100].
        // A value outside this range throws IllegalArgumentException at runtime.
        // Clamp here so no caller can accidentally store an invalid value,
        // regardless of where the number originates (UI slider, .rdp file import, etc.).
        it[Keys.COMPRESSION_QUALITY] = v.coerceIn(0, 100)
    }
    suspend fun updateShowFps(v: Boolean)               = update { it[Keys.SHOW_FPS_COUNTER] = v }
    // FIX I1: Was missing — cursor visibility setting had no persist function
    suspend fun updateShowCursorOnTouch(v: Boolean)     = update { it[Keys.SHOW_CURSOR_ON_TOUCH] = v }
    suspend fun updateDefaultResolution(v: String)      = update { it[Keys.DEFAULT_RESOLUTION] = v }
    suspend fun updateSessionToolbarVisible(v: Boolean) = update { it[Keys.SESSION_TOOLBAR_VISIBLE] = v }
    suspend fun updateSessionExtraKeysVisible(v: Boolean) = update { it[Keys.SESSION_EXTRA_KEYS_VISIBLE] = v }
    suspend fun updateRunInBackground(v: Boolean)       = update { it[Keys.RUN_IN_BACKGROUND] = v }
    suspend fun updateSoundEnabled(v: Boolean)          = update { it[Keys.SOUND_ENABLED] = v }
    suspend fun updateBiometricLock(v: Boolean)         = update { it[Keys.BIOMETRIC_LOCK_ENABLED] = v } // ✅ جديد
    suspend fun updatePinLock(enabled: Boolean, pin: String = "") = update {
        it[Keys.PIN_LOCK_ENABLED] = enabled
        if (enabled && pin.isNotBlank()) {
            // Encrypt and store the new PIN
            it[Keys.PIN_CODE] = com.gotohex.rdp.security.CryptoHelper.encrypt(pin)
        } else if (!enabled) {
            // BUG 2 FIX (SECURITY): When PIN lock is disabled, wipe the stored
            // encrypted PIN from DataStore immediately. Previously the encrypted
            // PIN persisted indefinitely after the user turned the lock off,
            // meaning anyone with physical/ADB access to the DataStore file could
            // still retrieve the ciphertext. Clearing it here ensures the key
            // material and ciphertext are both gone once the feature is off.
            it[Keys.PIN_CODE] = ""
        }
    }
    suspend fun updateRightClickLongPress(v: Boolean)   = update { it[Keys.RIGHT_CLICK_LONG_PRESS] = v } // ✅ جديد
    suspend fun markGestureHintsShown()                 = update { it[Keys.HAS_SHOWN_GESTURE_HINTS] = true }
    suspend fun markSubscribePromptShown() = update { it[Keys.LAST_SUBSCRIBE_PROMPT] = System.currentTimeMillis() }
    suspend fun markFirstLaunchShown()    = update { it[Keys.HAS_SHOWN_FIRST_LAUNCH] = true }

    private suspend fun update(block: (MutablePreferences) -> Unit) {
        context.dataStore.edit(block)
    }
}
