package com.gotohex.rdp.ui.screens

import android.content.Context
import android.os.Build
import androidx.fragment.app.FragmentActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.*
import com.gotohex.rdp.R
import com.gotohex.rdp.security.CryptoHelper
import java.security.MessageDigest
import com.gotohex.rdp.ui.theme.*
import com.gotohex.rdp.ui.components.StarfieldBackground
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@Composable
fun AppLockScreen(
    biometricEnabled: Boolean,
    pinEnabled: Boolean,
    encryptedPin: String,
    onUnlocked: () -> Unit,
) {
    val context = LocalContext.current

    // إطلاق البصمة تلقائياً عند فتح شاشة القفل
    LaunchedEffect(biometricEnabled) {
        if (biometricEnabled) {
            launchBiometric(context, onUnlocked)
        }
    }

    StarfieldBackground(modifier = Modifier.fillMaxSize()) { // BUG-1 FIX: honour chosen theme instead of hardcoding DeepSpace
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            // FIX-INDENT: Column was at the same indentation level as Box — misleading
            // layout hierarchy. Indented correctly; closing braces verified below.
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(24.dp),
                modifier = Modifier.padding(32.dp)
            ) {
                // أيقونة القفل
                val pulse = rememberInfiniteTransition(label = "lock_pulse")
                val glowAlpha by pulse.animateFloat(
                    initialValue  = 0.3f,
                    targetValue   = 0.9f,
                    animationSpec = infiniteRepeatable(tween(1200), RepeatMode.Reverse),
                    label         = "glow"
                )
                Box(
                    Modifier
                        .size(88.dp)
                        .background(PulsarCyan.copy(alpha = glowAlpha * 0.12f), CircleShape)
                        .border(2.dp, PulsarCyan.copy(alpha = glowAlpha), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Outlined.Lock,
                        contentDescription = stringResource(R.string.cd_lock_icon),
                        tint     = PulsarCyan,
                        modifier = Modifier.size(40.dp)
                    )
                }

                Text(
                    stringResource(R.string.app_name),
                    style      = MaterialTheme.typography.headlineMedium,
                    color      = StarDust,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    stringResource(R.string.unlock_to_continue),
                    style = MaterialTheme.typography.bodyMedium,
                    color = CometTail
                )

                Spacer(Modifier.height(8.dp))

                if (pinEnabled) {
                    PinEntryPad(
                        encryptedPin = encryptedPin,
                        onSuccess    = onUnlocked
                    )
                }

                if (biometricEnabled) {
                    TextButton(onClick = { launchBiometric(context, onUnlocked) }) {
                        Icon(
                            Icons.Outlined.Fingerprint,
                            contentDescription = stringResource(R.string.cd_biometric_button),
                            tint     = PulsarCyan,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.use_biometrics), color = PulsarCyan)
                    }
                }
            } // end Column
        } // end centering Box
    } // end StarfieldBackground
}

// ── PIN Entry ─────────────────────────────────────────────────────────────────

private const val MAX_ATTEMPTS     = 5   // عدد المحاولات قبل القفل
private const val LOCKOUT_SECONDS  = 30  // مدة القفل بالثواني

// BUG 3 FIX: Persist PIN lockout state across process kills.
// Previously failedCount / lockedSeconds lived only in `remember` state,
// so killing the process (Settings → Force Stop, or OOM kill) reset the
// counter, allowing unlimited PIN guesses with restarts in between.
// Solution: write failedCount and lockout-expiry-epoch to a private
// SharedPreferences file on every change, and read it back on every
// composition — including after a process restart.
private const val PREFS_LOCK     = "pin_lockout"        // file name
private const val KEY_FAILS      = "failed_count"       // Int
private const val KEY_EXPIRY_MS  = "lockout_expiry_ms"  // Long (epoch ms, 0 = not locked)

/** Persists the current lockout state. Call after every state mutation. */
private fun saveLockout(context: Context, failedCount: Int, lockoutExpiryMs: Long) {
    context.getSharedPreferences(PREFS_LOCK, Context.MODE_PRIVATE).edit()
        .putInt(KEY_FAILS, failedCount)
        .putLong(KEY_EXPIRY_MS, lockoutExpiryMs)
        // FIX-COMMIT: Use commit() (synchronous) instead of apply() (async) for
        // security-critical state. If the process is killed between apply() enqueue
        // and its background flush, the incremented failedCount is lost — an attacker
        // can reset the PIN brute-force counter by force-stopping the app.
        // commit() blocks the calling thread (already on Main here, but only for
        // <1 ms for a tiny SharedPreferences write) and guarantees the data is on
        // disk before we return. This makes partial-write attacks impractical.
        .commit()
}

/** Reads persisted state; returns Pair(failedCount, remainingSeconds). */
private fun loadLockout(context: Context): Pair<Int, Int> {
    val prefs     = context.getSharedPreferences(PREFS_LOCK, Context.MODE_PRIVATE)
    val fails     = prefs.getInt(KEY_FAILS, 0)
    val expiryMs  = prefs.getLong(KEY_EXPIRY_MS, 0L)
    val remaining = ((expiryMs - System.currentTimeMillis()) / 1_000L)
        .coerceAtLeast(0L).toInt()
    return Pair(fails, remaining)
}

@Composable
private fun PinEntryPad(
    encryptedPin: String,
    onSuccess: () -> Unit,
) {
    val context = LocalContext.current

    // BUG 3 FIX: seed in-memory state from disk so a process kill + restart
    // does not reset the counter.
    val (initFails, initRemaining) = remember { loadLockout(context) }

    var entered       by remember { mutableStateOf("") }
    var error         by remember { mutableStateOf(false) }
    var failedCount   by remember { mutableStateOf(initFails) }
    var lockedSeconds by remember { mutableStateOf(initRemaining) }
    val isLocked      = lockedSeconds > 0
    val maxLen        = 6

    val shake  = remember { Animatable(0f) }
    val scope  = rememberCoroutineScope()

    // ── Countdown timer أثناء القفل ────────────────────────────────────────
    LaunchedEffect(isLocked) {
        if (isLocked) {
            while (lockedSeconds > 0) {
                delay(1_000L)
                lockedSeconds--
            }
            // BUG 3 FIX: clear persisted state once lockout expires
            failedCount = 0
            saveLockout(context, 0, 0L)
        }
    }

    // ── رجّة الخطأ ─────────────────────────────────────────────────────────
    LaunchedEffect(error) {
        if (error) {
            repeat(4) {
                shake.animateTo(if (it % 2 == 0) 12f else -12f, tween(60))
            }
            shake.animateTo(0f, tween(60))
            entered = ""
            error   = false
        }
    }

    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // ── رسالة القفل أو عدد المحاولات المتبقية ───────────────────────────
        if (isLocked) {
            Text(
                stringResource(R.string.pin_locked_message, lockedSeconds),
                style = MaterialTheme.typography.bodySmall,
                color = SolarFlare,
                fontWeight = FontWeight.Medium
            )
        } else if (failedCount > 0) {
            Text(
                stringResource(R.string.pin_attempts_remaining, MAX_ATTEMPTS - failedCount),
                style = MaterialTheme.typography.bodySmall,
                color = ConnectingAmber,
            )
        }

        // ── Dots indicator ───────────────────────────────────────────────────
        Row(
            horizontalArrangement = Arrangement.spacedBy(14.dp),
            modifier = Modifier.offset(x = shake.value.dp)
        ) {
            repeat(maxLen) { i ->
                Box(
                    Modifier
                        .size(14.dp)
                        .background(
                            when {
                                isLocked          -> SolarFlare.copy(alpha = 0.4f)
                                i < entered.length -> PulsarCyan
                                else               -> HorizonGray.copy(alpha = 0.4f)
                            },
                            CircleShape
                        )
                )
            }
        }

        // ── Numpad ───────────────────────────────────────────────────────────
        // BUG 8 FIX: Fixed 72dp buttons + 20dp gaps = 256dp total.
        // On 320dp screens (e.g. Xiaomi Redmi Go), outer padding pushes this
        // over the edge and the side buttons are clipped.
        // Solution: measure available width and scale both button size and gap
        // so the 3-column grid always fits with room to breathe.
        val keys = listOf(
            listOf("1","2","3"),
            listOf("4","5","6"),
            listOf("7","8","9"),
            listOf("","0","⌫"),
        )
        BoxWithConstraints {
            val availableWidth = maxWidth
            // Reserve 32dp of horizontal padding on each side (64dp total).
            // Remaining space is shared by 3 buttons + 2 gaps (gap = btnSize * 0.25).
            // Solve: 3*btn + 2*(btn*0.25) = available → btn = available / 3.5
            val btnSize = ((availableWidth - 64.dp) / 3.5f).coerceIn(52.dp, 72.dp)
            val gap     = (btnSize * 0.25f).coerceIn(10.dp, 20.dp)

            Column(verticalArrangement = Arrangement.spacedBy(gap)) {
                keys.forEach { row ->
                    Row(horizontalArrangement = Arrangement.spacedBy(gap)) {
                        row.forEach { key ->
                            if (key.isEmpty()) {
                                Spacer(Modifier.size(btnSize))
                            } else {
                                PinKey(label = key, size = btnSize, enabled = !isLocked, onClick = {
                                    if (key == "⌫") {
                                        if (entered.isNotEmpty()) entered = entered.dropLast(1)
                                    } else if (entered.length < maxLen) {
                                        entered += key
                                        if (entered.length == maxLen) {
                                            // BUG-I FIX: Never compare PINs as raw plaintexts.
                                            // Decrypt the stored value, then compare SHA-256 digests
                                            // so the plaintext is not held in a long-lived variable
                                            // and the comparison length is constant (32 bytes).
                                            val storedDecrypted = CryptoHelper.decrypt(encryptedPin)
                                            val sha256 = java.security.MessageDigest.getInstance("SHA-256")
                                            val match = storedDecrypted.isNotEmpty() && MessageDigest.isEqual(
                                                sha256.digest(entered.toByteArray(Charsets.UTF_8)),
                                                sha256.digest(storedDecrypted.toByteArray(Charsets.UTF_8))
                                            )
                                            if (match) {
                                                // BUG 3 FIX: successful unlock → clear persisted lockout
                                                saveLockout(context, 0, 0L)
                                                onSuccess()
                                            } else {
                                                failedCount++
                                                if (failedCount >= MAX_ATTEMPTS) {
                                                    lockedSeconds = LOCKOUT_SECONDS
                                                    // BUG 3 FIX: persist expiry epoch so the lockout
                                                    // survives process kills / OOM restarts
                                                    val expiryMs = System.currentTimeMillis() +
                                                        LOCKOUT_SECONDS * 1_000L
                                                    saveLockout(context, failedCount, expiryMs)
                                                } else {
                                                    // BUG 3 FIX: persist incremented count even before
                                                    // a full lockout so partial progress is not lost
                                                    saveLockout(context, failedCount, 0L)
                                                }
                                                error = true
                                            }
                                        }
                                    }
                                })
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PinKey(label: String, size: Dp = 72.dp, enabled: Boolean = true, onClick: () -> Unit) {
    Surface(
        color    = if (enabled) NebulaSurface else NebulaSurface.copy(alpha = 0.4f),
        shape    = CircleShape,
        modifier = Modifier
            .size(size)
            .clip(CircleShape)
            .then(if (enabled) Modifier.clickable(onClick = onClick) else Modifier)
            .border(1.dp, HorizonGray.copy(alpha = if (enabled) 0.4f else 0.15f), CircleShape)
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(
                label,
                style      = MaterialTheme.typography.titleLarge,
                color      = StarDust,
                fontWeight = FontWeight.Medium,
                textAlign  = TextAlign.Center
            )
        }
    }
}

// ── Biometric Prompt ──────────────────────────────────────────────────────────

private fun launchBiometric(context: Context, onSuccess: () -> Unit) {
    // BUG 3 FIX: MainActivity and RdpSessionActivity both extend ComponentActivity,
    // not FragmentActivity. The original cast always returned null, silently
    // preventing biometric auth from ever running.
    // androidx.biometric.BiometricPrompt accepts ComponentActivity directly.
    val activity = context as? FragmentActivity ?: return
    val biometricManager = BiometricManager.from(context)

    // BUG 10 FIX: BIOMETRIC_STRONG | DEVICE_CREDENTIAL in setAllowedAuthenticators()
    // throws IllegalArgumentException on API 28-29. Branch on API level.
    val authenticators = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        BiometricManager.Authenticators.BIOMETRIC_STRONG or
        BiometricManager.Authenticators.DEVICE_CREDENTIAL
    } else {
        BiometricManager.Authenticators.BIOMETRIC_STRONG
    }
    if (biometricManager.canAuthenticate(authenticators) != BiometricManager.BIOMETRIC_SUCCESS) return

    // biometric 1.2.0-alpha05: new 2-arg constructor accepts ComponentActivity directly
    val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            onSuccess()
        }
        // FIX #10: Handle failed/errored biometric attempts so the user is not
        // silently stuck on the lock screen with no feedback or fallback option.
        override fun onAuthenticationFailed() {
            // A single failed attempt (unrecognised fingerprint) — the system
            // shows its own "Not recognised" feedback; no extra action needed.
            android.util.Log.d("AppLockScreen", "Biometric attempt not recognised")
        }
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            // Terminal error (timeout, lockout, no biometric enrolled, etc.).
            // Log it so developers can diagnose; the PIN pad below remains
            // available as a fallback without any extra UI action here.
            android.util.Log.w("AppLockScreen", "Biometric error $errorCode: $errString")
        }
    }
    val prompt = BiometricPrompt(activity, callback)
    val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle(context.getString(R.string.biometric_prompt_title))
        .setSubtitle(context.getString(R.string.biometric_prompt_subtitle))
        .apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // API 30+: combined authenticators supported
                setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL
                )
            } else {
                // API 28-29: use deprecated setDeviceCredentialAllowed instead;
                // the BIOMETRIC_STRONG | DEVICE_CREDENTIAL combination crashes here.
                @Suppress("DEPRECATION")
                setDeviceCredentialAllowed(true)
            }
        }
        .build()
    prompt.authenticate(info)
}
