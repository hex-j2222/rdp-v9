package com.gotohex.rdp.security

import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * FIX #1 (Security): Replaces passing Quick Connect credentials as plain-text
 * Intent extras — which are visible via `adb shell dumpsys activity activities`
 * and appear in bug reports / battery stats dumps.
 *
 * Caller stores credentials here under a one-time UUID token, passes only
 * the token through the Intent, and the receiver calls [take] to retrieve
 * and atomically remove them. Credentials are never written to disk.
 *
 * BUG-TTL FIX: The original implementation had no expiry — if the target
 * Activity crashed before calling take(), the credential object (including
 * the password) remained in the singleton's ConcurrentHashMap for the entire
 * process lifetime. Fix: wrap each entry with a creation timestamp and evict
 * stale entries (older than TTL_MS) on every [put] call.  [take] also
 * rejects expired entries so a token that somehow survives past the window
 * cannot be replayed.
 */
object QuickConnectCache {

    /** Credentials are valid for 30 seconds — ample time for the Activity to start. */
    private const val TTL_MS = 30_000L

    private data class Entry(
        val host: String,
        val port: Int,
        val username: String,
        val password: String,
        val createdAt: Long = System.currentTimeMillis(),
    )

    private val store = ConcurrentHashMap<String, Entry>()

    /**
     * Stores credentials and returns a one-time token suitable for Intent extras.
     * The token is a random UUID — unguessable and single-use.
     * Evicts any previously stale entries as a side-effect.
     */
    fun put(host: String, port: Int, username: String, password: String): String {
        evictExpired()
        val token = UUID.randomUUID().toString()
        store[token] = Entry(host, port, username, password)
        return token
    }

    /**
     * Retrieves AND removes credentials associated with [token].
     * Returns null if the token is unknown, already consumed, or expired.
     */
    fun take(token: String): QuickConnectParams? {
        val entry = store.remove(token) ?: return null
        if (System.currentTimeMillis() - entry.createdAt > TTL_MS) return null   // expired
        return QuickConnectParams(entry.host, entry.port, entry.username, entry.password)
    }

    /** Removes all entries older than [TTL_MS]. Called automatically by [put]. */
    private fun evictExpired() {
        val cutoff = System.currentTimeMillis() - TTL_MS
        store.entries.removeIf { it.value.createdAt < cutoff }
    }
}

/** Immutable credential bundle returned by [QuickConnectCache.take]. */
data class QuickConnectParams(
    val host: String,
    val port: Int,
    val username: String,
    val password: String,
)
