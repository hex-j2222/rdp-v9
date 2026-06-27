package com.gotohex.rdp.ssh.protocol

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import com.gotohex.rdp.R
import com.gotohex.rdp.remote.*
import com.jcraft.jsch.ChannelShell
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.InputStream
import java.io.OutputStream

enum class SshAuthMode { PASSWORD, PRIVATE_KEY }

data class SshCredentials(
    val host: String,
    val port: Int = 22,
    val username: String,
    val authMode: SshAuthMode,
    val password: String = "",
    val privateKeyPem: String = "",
    val privateKeyPassphrase: String = "",
)

/**
 * SSH client backed by JSch, exposing an interactive shell (PTY) channel
 * through the same [RemoteSessionClient] surface used by RDP/VNC.
 *
 * Unlike RDP/VNC this is a *terminal*, not a framebuffer — [frameUpdates] is
 * never emitted; instead raw terminal bytes are surfaced via
 * [terminalOutput], and [sendText] (rather than scan-code key events) is the
 * primary input path, matching how [com.gotohex.rdp.ui.screens.terminal.TerminalScreen]
 * drives it.
 */
class SshClient(
    private val credentials: SshCredentials,
    private val termCols: Int = 100,
    private val termRows: Int = 32,
    // BUG-H FIX: Context needed to persist TOFU keys across app restarts.
    private val appContext: Context,
) : RemoteSessionClient {

    companion object {
        private const val TAG = "SshClient"
        private const val CONNECT_TIMEOUT_MS = 15_000
        private const val PREFS_TOFU = "hexrdp_tofu_ssh"
        // BUG-L1 FIX: tofuPendingKeys removed from companion object (was a shared
        // static map). When two SshClient instances connected simultaneously to the
        // same host, check() of client-2 overwrote client-1's pending entry, causing
        // add() of client-1 to persist client-2's key — wrong key stored permanently.
        // The map is now an instance field inside TofuHostKeyRepository.
    }

    /**
     * FIX #2: TOFU host-key repository that replaces StrictHostKeyChecking=no.
     *
     * - First connection to a host: key is accepted and remembered (TOFU).
     * - Subsequent connections: key is compared; a mismatch returns CHANGED
     *   and JSch aborts with an exception (MITM protection).
     */
    private inner class TofuHostKeyRepository : com.jcraft.jsch.HostKeyRepository {

        // BUG-L1 FIX: per-instance pending-key map (was companion object static).
        private val pendingKeys = java.util.concurrent.ConcurrentHashMap<String, String>()

        private fun hostMapKey(host: String): String {
            // JSch encodes non-default ports as "[host]:port"; normalise to "host:port".
            val bare = host.removePrefix("[").substringBefore("]")
            return if (':' in host) "$bare:${host.substringAfterLast(']').removePrefix(":")}"
            else "$bare:${credentials.port}"
        }

        private fun prefs(): SharedPreferences =
            appContext.getSharedPreferences(PREFS_TOFU, Context.MODE_PRIVATE)

        override fun check(host: String, key: ByteArray): Int {
            val mapKey = hostMapKey(host)
            val incomingB64 = android.util.Base64.encodeToString(key, android.util.Base64.NO_WRAP)
            // BUG-H FIX: read from persistent SharedPreferences instead of in-memory map
            val storedB64 = prefs().getString(mapKey, null)
            return if (storedB64 == null) {
                // First time — stash for add(), let accept-new mode proceed
                pendingKeys[mapKey] = incomingB64
                com.jcraft.jsch.HostKeyRepository.NOT_INCLUDED
            } else if (storedB64 == incomingB64) {
                com.jcraft.jsch.HostKeyRepository.OK
            } else {
                // Key has changed — likely MITM; JSch will throw JSchException
                Log.w(TAG, "SSH host key CHANGED for $mapKey — possible MITM!")
                com.jcraft.jsch.HostKeyRepository.CHANGED
            }
        }

        override fun add(hostkey: com.jcraft.jsch.HostKey, ui: com.jcraft.jsch.UserInfo?) {
            // Called by JSch after accept-new auto-accepts a NOT_INCLUDED key.
            // BUG-H FIX: write to SharedPreferences for persistence across restarts
            val mapKey = hostMapKey(hostkey.host)
            pendingKeys.remove(mapKey)?.let { key ->
                prefs().edit().putString(mapKey, key).apply()
            }
        }

        override fun remove(host: String?, type: String?) {
            // BUG-H FIX: remove from SharedPreferences
            if (host != null) prefs().edit().remove(hostMapKey(host)).apply()
        }
        override fun remove(host: String?, type: String?, key: ByteArray?) = remove(host, type)
        override fun getKnownHostsRepositoryID() = "hexrdp-tofu-ssh-prefs"
        override fun getHostKey() = emptyArray<com.jcraft.jsch.HostKey>()
        override fun getHostKey(host: String?, type: String?) = emptyArray<com.jcraft.jsch.HostKey>()
    }

    private val _sessionState = MutableStateFlow(RemoteSessionState.DISCONNECTED)
    override val sessionState: StateFlow<RemoteSessionState> = _sessionState.asStateFlow()

    private val _frameUpdates = MutableSharedFlow<RemoteFrameUpdate>(extraBufferCapacity = 1)
    override val frameUpdates: SharedFlow<RemoteFrameUpdate> = _frameUpdates.asSharedFlow()

    private val _terminalOutput = MutableSharedFlow<TerminalOutput>(extraBufferCapacity = 64)
    override val terminalOutput: SharedFlow<TerminalOutput> = _terminalOutput.asSharedFlow()

    private val _error = MutableSharedFlow<String>(extraBufferCapacity = 4)
    override val error: SharedFlow<String> = _error.asSharedFlow()

    override var latencyMs: Long = 0L
        private set

    private var session: Session? = null
    private var channel: ChannelShell? = null
    private var channelOut: OutputStream? = null
    private var channelIn: InputStream? = null
    @Volatile private var connected = false

    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        try {
            _sessionState.emit(RemoteSessionState.CONNECTING)

            val jsch = JSch()

            // FIX #2: Use TOFU host-key verification instead of StrictHostKeyChecking=no.
            // accept-new auto-accepts keys for genuinely new hosts (TOFU first use) but
            // rejects a connection when the stored key no longer matches (MITM detection).
            jsch.hostKeyRepository = TofuHostKeyRepository()

            if (credentials.authMode == SshAuthMode.PRIVATE_KEY && credentials.privateKeyPem.isNotBlank()) {
                jsch.addIdentity(
                    "hexrdp-key",
                    credentials.privateKeyPem.toByteArray(Charsets.UTF_8),
                    null,
                    credentials.privateKeyPassphrase.takeIf { it.isNotBlank() }?.toByteArray(Charsets.UTF_8)
                )
            }

            val sess = jsch.getSession(credentials.username, credentials.host, credentials.port)
            if (credentials.authMode == SshAuthMode.PASSWORD) {
                sess.setPassword(credentials.password)
            }
            // FIX #2: accept-new accepts new hosts automatically (TOFU) and rejects
            // changed keys — replacing the previous StrictHostKeyChecking=no which
            // made every SSH session fully vulnerable to Man-in-the-Middle attacks.
            sess.setConfig("StrictHostKeyChecking", "accept-new")
            sess.setConfig("PreferredAuthentications", "publickey,password,keyboard-interactive")
            sess.timeout = CONNECT_TIMEOUT_MS
            session = sess

            val connectStart = System.currentTimeMillis()
            sess.connect(CONNECT_TIMEOUT_MS)
            latencyMs = System.currentTimeMillis() - connectStart

            val ch = sess.openChannel("shell") as ChannelShell
            ch.setPtyType("xterm-256color", termCols, termRows, 0, 0)
            ch.setPty(true)
            channelIn = ch.inputStream
            channelOut = ch.outputStream
            ch.connect(CONNECT_TIMEOUT_MS)
            channel = ch

            connected = true
            _sessionState.emit(RemoteSessionState.CONNECTED)
            ioScope.launch { readLoop() }

            true
        } catch (e: Exception) {
            Log.e(TAG, "SSH connect failed", e)
            val authFailure = e.message?.contains("Auth", ignoreCase = true) == true ||
                e.message?.contains("authentication", ignoreCase = true) == true
            _error.emit(e.message ?: appContext.getString(R.string.error_ssh_connect_failed))
            _sessionState.emit(if (authFailure) RemoteSessionState.AUTH_FAILED else RemoteSessionState.ERROR)
            // BUG-SSHSCOPE FIX: ioScope was never cancelled on connect failure.
            // The SupervisorJob + Dispatchers.IO scope remained open indefinitely,
            // leaking one scope per failed connection attempt. Cancel it here,
            // matching the same pattern used in VncClient.connect() failure handling.
            ioScope.cancel()
            cleanup()
            false
        }
    }

    private suspend fun readLoop() {
        val buffer = ByteArray(8192)
        // BUG-UTF8 FIX: String(buffer, 0, n, Charsets.UTF_8) decodes each read()
        // independently. A multi-byte UTF-8 sequence (e.g. Arabic = 2 bytes, emoji = 4 bytes)
        // can be split across two consecutive read() calls, producing \uFFFD replacement
        // characters and garbled terminal output. Fix: use a stateful CharsetDecoder that
        // retains incomplete sequences between calls, emitting them only when the remaining
        // bytes arrive in the next read().
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPLACE)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPLACE)
        val inBuf  = java.nio.ByteBuffer.wrap(buffer)
        val outBuf = java.nio.CharBuffer.allocate(buffer.size * 2)
        try {
            val stream = channelIn ?: return
            while (connected) {
                val n = stream.read(buffer)
                if (n < 0) break
                inBuf.limit(n).position(0)
                outBuf.clear()
                decoder.decode(inBuf, outBuf, false)
                outBuf.flip()
                if (outBuf.hasRemaining()) {
                    _terminalOutput.emit(TerminalOutput(outBuf.toString()))
                }
            }
        } catch (e: Exception) {
            if (connected) {
                Log.e(TAG, "SSH read loop error", e)
                _error.emit(e.message ?: appContext.getString(R.string.error_connection_lost))
                _sessionState.emit(RemoteSessionState.ERROR)
            }
        } finally {
            connected = false
            _sessionState.emit(RemoteSessionState.DISCONNECTED)
        }
    }

    fun resizeTerminal(cols: Int, rows: Int) {
        try {
            channel?.setPtySize(cols, rows, cols * 8, rows * 16)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to resize PTY", e)
        }
    }

    // ── Input — terminal sessions take raw text, not framebuffer events ────

    override fun sendText(text: String) {
        // FIX-IO: write() and flush() are blocking calls. They must not run on
        // the Main/UI thread (which is where Compose event handlers fire).
        // ioScope is already pinned to Dispatchers.IO, so launch here is safe.
        ioScope.launch {
            try {
                channelOut?.write(text.toByteArray(Charsets.UTF_8))
                channelOut?.flush()
            } catch (e: Exception) {
                Log.w(TAG, "Failed to send terminal input", e)
            }
        }
    }

    /** Sends a single raw control byte, e.g. Ctrl+C = 0x03. */
    fun sendControlByte(byte: Int) {
        // FIX-IO: same reasoning as sendText — dispatch to IO thread.
        ioScope.launch {
            try {
                channelOut?.write(byte)
                channelOut?.flush()
            } catch (e: Exception) {
                Log.w(TAG, "Failed to send control byte", e)
            }
        }
    }

    override fun sendCtrlAltDel() { /* not meaningful over a terminal */ }
    override fun sendMouseMove(x: Int, y: Int) { /* terminal sessions don't use pointer input */ }
    override fun sendMouseClick(x: Int, y: Int, button: RemoteMouseButton, down: Boolean) { }
    override fun sendMouseScroll(x: Int, y: Int, delta: Int) { }
    override fun sendKeyEvent(scanCode: Int, down: Boolean, extended: Boolean) {
        // Only forward key-down for control keys relevant in a terminal —
        // see TerminalScreen's extra-keys row, which calls sendControlByte /
        // sendText directly for the keys it cares about. Scan-code based
        // input (hardware keyboard via the shared ExtraKeysBar) is mapped to
        // ANSI escape sequences here for the navigation/function keys.
        if (!down) return
        val seq = SshKeyMap.scanCodeToAnsiSequence(scanCode, extended) ?: return
        sendText(seq)
    }

    override fun disconnect() {
        connected = false
        ioScope.cancel()
        cleanup()
        _sessionState.tryEmit(RemoteSessionState.DISCONNECTED)
    }

    private fun cleanup() {
        try { channel?.disconnect() } catch (_: Exception) {}
        try { session?.disconnect() } catch (_: Exception) {}
        channel = null; session = null; channelIn = null; channelOut = null
    }
}
