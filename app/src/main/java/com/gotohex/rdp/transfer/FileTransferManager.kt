package com.gotohex.rdp.transfer

import android.content.Context
import android.content.SharedPreferences
import android.net.ConnectivityManager
import android.net.wifi.WifiManager
import java.security.SecureRandom
import android.os.Build
import android.os.Environment
import android.os.StatFs
import com.jcraft.jsch.ChannelSftp
import com.jcraft.jsch.JSch
import com.jcraft.jsch.SftpProgressMonitor
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.*
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.net.URLDecoder
import java.net.URLEncoder
import java.text.DecimalFormat
import java.util.concurrent.atomic.AtomicBoolean

// ─────────────────────────────────────────────────────────────────────────────
// Data Models
// ─────────────────────────────────────────────────────────────────────────────

data class HexFile(
    val name: String,
    val path: String,
    val isDirectory: Boolean,
    val size: Long,
    val lastModified: Long
) {
    val extension: String get() = if (isDirectory) "" else name.substringAfterLast('.', "").lowercase()
}

sealed class TransferProgress {
    object Idle : TransferProgress()
    data class Running(
        val fileName: String,
        val bytesDone: Long,
        val bytesTotal: Long,
        val isUpload: Boolean
    ) : TransferProgress() {
        val percent: Float = if (bytesTotal > 0) bytesDone.toFloat() / bytesTotal else 0f
    }
    data class Success(val fileName: String, val isUpload: Boolean) : TransferProgress()
    data class Failure(val error: String) : TransferProgress()
}

data class StorageSpace(
    val freeBytes: Long,
    val totalBytes: Long
) {
    val usedBytes: Long get() = totalBytes - freeBytes
    val freePercent: Float get() = if (totalBytes > 0) freeBytes.toFloat() / totalBytes else 0f
    // FIX #8: كانت "5 GB 32 GB free" — صُحِّح إلى "5 GB free of 32 GB"
    val label: String get() = "${formatBytes(freeBytes)} free of ${formatBytes(totalBytes)}"
}

fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val df = DecimalFormat("#.##")
    val kb = bytes / 1024.0
    if (kb < 1024) return "${df.format(kb)} KB"
    val mb = kb / 1024.0
    if (mb < 1024) return "${df.format(mb)} MB"
    val gb = mb / 1024.0
    return "${df.format(gb)} GB"
}

// ─────────────────────────────────────────────────────────────────────────────
// Phone File Browser
// ─────────────────────────────────────────────────────────────────────────────

object PhoneFileBrowser {

    /** Root directories exposed to the user. */
    fun rootPaths(): List<HexFile> = buildList {
        val ext = Environment.getExternalStorageDirectory()
        if (ext.exists()) add(toHexFile(ext, "Internal Storage"))

        val storageRoot = File("/storage")
        if (storageRoot.exists()) {
            storageRoot.listFiles()
                ?.filter { it.isDirectory && it.name != "emulated" && it.name != "self" }
                ?.forEach { add(toHexFile(it, it.name)) }
        }
    }

    fun listDir(path: String): List<HexFile> {
        val dir = File(path)
        if (!dir.exists() || !dir.isDirectory) return emptyList()
        return try {
            (dir.listFiles() ?: emptyArray())
                .sortedWith(compareByDescending<File> { it.isDirectory }.thenBy { it.name.lowercase() })
                .map { toHexFile(it) }
        } catch (_: SecurityException) {
            emptyList()
        }
    }

    fun storageSpace(path: String): StorageSpace {
        return try {
            val stat = StatFs(path)
            StorageSpace(
                freeBytes  = stat.availableBlocksLong * stat.blockSizeLong,
                totalBytes = stat.blockCountLong * stat.blockSizeLong
            )
        } catch (_: Exception) {
            StorageSpace(0L, 0L)
        }
    }

    fun phoneStorageSpace(): StorageSpace = storageSpace(
        Environment.getExternalStorageDirectory().absolutePath
    )

    private fun toHexFile(f: File, overrideName: String? = null) = HexFile(
        name         = overrideName ?: f.name,
        path         = f.absolutePath,
        isDirectory  = f.isDirectory,
        size         = if (f.isFile) f.length() else 0L,
        lastModified = f.lastModified()
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// SFTP Browser (SSH sessions)
// ─────────────────────────────────────────────────────────────────────────────

data class SftpConfig(
    val host: String,
    val port: Int,
    val username: String,
    val password: String,
    val privateKeyPem: String? = null,
    val privateKeyPassphrase: String? = null
)

class SftpFileBrowser(
    private val config: SftpConfig,
    // FIX-SFTP-TOFU: Context required to persist TOFU host keys across app restarts,
    // mirroring the same fix applied to SshClient and SshTunnelManager.
    private val appContext: Context,
) {

    companion object {
        private const val TAG = "SftpFileBrowser"
        private const val PREFS_TOFU_SFTP = "hexrdp_tofu_sftp"
    }

    // FIX-SFTP-TOFU: TOFU host-key repository replacing StrictHostKeyChecking=no.
    // SshClient and SshTunnelManager were already fixed; this brings SftpFileBrowser
    // to parity — without it, every SFTP file transfer was fully open to MITM attacks.
    private inner class TofuHostKeyRepository : com.jcraft.jsch.HostKeyRepository {

        private val pendingKeys = java.util.concurrent.ConcurrentHashMap<String, String>()

        private fun mapKey(host: String): String {
            val bare = host.removePrefix("[").substringBefore("]")
            return if (':' in host) "$bare:${host.substringAfterLast(']').removePrefix(":")}"
            else "$bare:${config.port}"
        }

        private fun prefs(): SharedPreferences =
            appContext.getSharedPreferences(PREFS_TOFU_SFTP, Context.MODE_PRIVATE)

        override fun check(host: String, key: ByteArray): Int {
            val mk = mapKey(host)
            val incoming = android.util.Base64.encodeToString(key, android.util.Base64.NO_WRAP)
            val stored = prefs().getString(mk, null)
            return when {
                stored == null -> {
                    pendingKeys[mk] = incoming
                    com.jcraft.jsch.HostKeyRepository.NOT_INCLUDED
                }
                stored == incoming -> com.jcraft.jsch.HostKeyRepository.OK
                else -> {
                    android.util.Log.w(TAG, "SFTP host key CHANGED for $mk — possible MITM!")
                    com.jcraft.jsch.HostKeyRepository.CHANGED
                }
            }
        }

        override fun add(hostkey: com.jcraft.jsch.HostKey, ui: com.jcraft.jsch.UserInfo?) {
            val mk = mapKey(hostkey.host)
            pendingKeys.remove(mk)?.let { key ->
                prefs().edit().putString(mk, key).apply()
            }
        }

        override fun remove(host: String?, type: String?) {
            if (host != null) prefs().edit().remove(mapKey(host)).apply()
        }
        override fun remove(host: String?, type: String?, key: ByteArray?) = remove(host, type)
        override fun getKnownHostsRepositoryID() = "hexrdp-sftp-tofu"
        override fun getHostKey() = emptyArray<com.jcraft.jsch.HostKey>()
        override fun getHostKey(h: String?, t: String?) = emptyArray<com.jcraft.jsch.HostKey>()
    }

    private var jschSession: com.jcraft.jsch.Session? = null
    private var channel: ChannelSftp? = null

    fun connect() {
        val jsch = JSch()
        // FIX-SFTP-TOFU: replace StrictHostKeyChecking=no with TOFU verification
        jsch.hostKeyRepository = TofuHostKeyRepository()
        config.privateKeyPem?.takeIf { it.isNotBlank() }?.let { pem ->
            val bytes = pem.toByteArray(Charsets.UTF_8)
            val pass  = config.privateKeyPassphrase?.takeIf { it.isNotBlank() }?.toByteArray()
            jsch.addIdentity("key", bytes, null, pass)
        }
        val sess = jsch.getSession(config.username, config.host, config.port)
        if (config.privateKeyPem.isNullOrBlank()) sess.setPassword(config.password)
        // FIX-SFTP-TOFU: accept-new = TOFU first-use auto-accept, mismatch = reject (MITM)
        sess.setConfig("StrictHostKeyChecking", "accept-new")
        sess.setConfig("server_host_key",
            "ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519")
        sess.connect(15_000)
        val ch = sess.openChannel("sftp") as ChannelSftp
        ch.connect(10_000)
        jschSession = sess
        channel    = ch
    }

    fun disconnect() {
        try { channel?.disconnect() } catch (_: Exception) {}
        try { jschSession?.disconnect() } catch (_: Exception) {}
        channel    = null
        jschSession = null
    }

    fun isConnected(): Boolean = channel?.isConnected == true

    fun homeDir(): String = try { channel?.home ?: "/" } catch (_: Exception) { "/" }

    fun listDir(path: String): List<HexFile> {
        val ch = channel ?: return emptyList()
        return try {
            @Suppress("UNCHECKED_CAST")
            val entries = ch.ls(path) as? java.util.Vector<ChannelSftp.LsEntry> ?: return emptyList()
            entries
                .filter { it.filename != "." && it.filename != ".." }
                .sortedWith(compareByDescending<ChannelSftp.LsEntry> { it.attrs.isDir }.thenBy { it.filename.lowercase() })
                .map { entry ->
                    HexFile(
                        name         = entry.filename,
                        path         = "${path.trimEnd('/')}/${entry.filename}",
                        isDirectory  = entry.attrs.isDir,
                        size         = entry.attrs.size,
                        lastModified = entry.attrs.mTime.toLong() * 1000L
                    )
                }
        } catch (_: Exception) {
            emptyList()
        }
    }

    /** Upload a local phone file to the remote server. */
    suspend fun uploadFile(
        localPath: String,
        remotePath: String,
        onProgress: (TransferProgress) -> Unit
    ) = withContext(Dispatchers.IO) {
        val ch = channel ?: throw IOException("SFTP not connected")
        val file = File(localPath)
        if (!file.exists()) throw IOException("Local file not found: $localPath")
        val total = file.length()
        var done  = 0L

        // FIX #1: currentCoroutineContext() هي دالة suspend ولا تُستدعى داخل count().
        // الحل: تخزين Job في متغير قبل الدخول إلى المراقب، ثم التحقق منه مباشرةً.
        val job = coroutineContext[Job]

        val monitor = object : SftpProgressMonitor {
            override fun init(op: Int, src: String, dest: String, max: Long) {}
            override fun count(count: Long): Boolean {
                done += count
                onProgress(TransferProgress.Running(file.name, done, total, isUpload = true))
                return job?.isActive != false // false = ألغي المهمة، أوقف النقل
            }
            override fun end() {}
        }
        onProgress(TransferProgress.Running(file.name, 0L, total, isUpload = true))
        ch.put(localPath, remotePath, monitor, ChannelSftp.OVERWRITE)
        onProgress(TransferProgress.Success(file.name, isUpload = true))
    }

    /** Download a remote file to the phone. */
    suspend fun downloadFile(
        remotePath: String,
        localDir: String,
        onProgress: (TransferProgress) -> Unit
    ) = withContext(Dispatchers.IO) {
        val ch         = channel ?: throw IOException("SFTP not connected")
        val fileName   = remotePath.substringAfterLast('/')
        val localFile  = File(localDir, fileName)
        localFile.parentFile?.mkdirs()

        // FIX-PARTIAL-DOWNLOAD: Write to a temp file first and rename atomically on
        // success. Previously ch.get() wrote directly to localFile — if the transfer
        // failed mid-way (network drop, cancellation, no space) a corrupt partial file
        // was left at the destination with no indication it was incomplete.
        val tempFile = File(localDir, "$fileName.hexrdp_tmp")

        val attrs = try { ch.stat(remotePath) } catch (_: Exception) { null }
        val total = attrs?.size ?: -1L
        var done  = 0L

        // FIX #9: كان يُعيد true دائماً → لا إمكانية إلغاء. نفس حل uploadFile.
        val job = coroutineContext[Job]

        val monitor = object : SftpProgressMonitor {
            override fun init(op: Int, src: String, dest: String, max: Long) {}
            override fun count(count: Long): Boolean {
                done += count
                onProgress(TransferProgress.Running(fileName, done, total, isUpload = false))
                return job?.isActive != false
            }
            override fun end() {}
        }
        try {
            onProgress(TransferProgress.Running(fileName, 0L, total, isUpload = false))
            ch.get(remotePath, tempFile.absolutePath, monitor, ChannelSftp.OVERWRITE)
            // Atomic rename to final destination (same filesystem → instantaneous)
            if (!tempFile.renameTo(localFile)) {
                // Cross-partition fallback: copy then delete temp
                tempFile.copyTo(localFile, overwrite = true)
                tempFile.delete()
            }
            onProgress(TransferProgress.Success(fileName, isUpload = false))
        } catch (e: Exception) {
            // FIX-PARTIAL-DOWNLOAD: clean up the temp file so no garbage is left behind
            tempFile.delete()
            throw e
        }
    }

    // FIX-REMOTE-STORAGE: Implement actual remote storage query via SFTP statVFS extension
    // (available on OpenSSH and most modern SFTP servers). Falls back to StorageSpace(0,0)
    // on servers that don't support the extension rather than crashing.
    fun remoteStorageSpace(remotePath: String = "/"): StorageSpace {
        return try {
            val ch = channel ?: return StorageSpace(0L, 0L)
            val vfs = ch.statVFS(remotePath)
            // JSch 0.2.x: الحقول bsize/bavail أصبحت private → نستخدم getters الصريحة
            // getBsize() = fundamental block size, getBavail() = blocks avail to non-root
            val blockSize = vfs.getBlockSize().coerceAtLeast(1L)
            StorageSpace(
                freeBytes  = vfs.getAvailForNonRoot() * blockSize,
                totalBytes = vfs.getBlocks() * blockSize
            )
        } catch (_: Exception) {
            // statVFS is an SSH extension — not all servers support it; degrade gracefully
            StorageSpace(0L, 0L)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP File Server (RDP / VNC sessions)
// ─────────────────────────────────────────────────────────────────────────────

class HttpFileServer(private val context: Context) {

    val port = 8765
    private var serverSocket: ServerSocket? = null
    private val running = AtomicBoolean(false)
    private var serverJob: Job? = null

    // FIX-SECURE-TOKEN: Use SecureRandom instead of kotlin.random.Random.Default.
    // kotlin.random is a pseudorandom generator (seeded from the clock) — its output
    // is predictable to an attacker who knows the approximate process start time.
    // SecureRandom uses the OS entropy pool (urandom) and is appropriate for tokens.
    val accessToken: String = buildString {
        val rng   = SecureRandom()
        val chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        repeat(12) { append(chars[rng.nextInt(chars.length)]) }  // 32^12 ≈ 1.15 × 10^18 combinations
    }

    // FIX #5 (جزئي): المسار الجذر المسموح به فقط
    private val allowedRoot: String by lazy {
        Environment.getExternalStorageDirectory().canonicalPath
    }

    fun start(scope: CoroutineScope): Boolean {
        if (running.get()) return true
        return try {
            // BUG-BIND FIX: ServerSocket(port) binds to 0.0.0.0, making the server
            // reachable from every network interface the device has (WiFi, mobile data,
            // USB tethering, VPNs, etc.).  This is wider than intended — the feature is
            // designed for LAN transfers over the active WiFi link only.
            // Fix: bind to the specific IPv4 address reported by phoneIp() so the server
            // is only reachable from that interface.  Fall back to 0.0.0.0 if we can't
            // resolve a local address (e.g. no WiFi), mirroring previous behaviour.
            val bindAddr: java.net.InetAddress? = try {
                val ip = phoneIp()
                if (ip == "unknown") null else java.net.InetAddress.getByName(ip)
            } catch (_: Exception) { null }

            val ss = ServerSocket()
            ss.reuseAddress = true
            if (bindAddr != null) {
                ss.bind(InetSocketAddress(bindAddr, port))
            } else {
                ss.bind(InetSocketAddress(port))
            }
            serverSocket = ss
            running.set(true)
            serverJob = scope.launch(Dispatchers.IO) {
                while (running.get()) {
                    try {
                        val client = ss.accept()
                        launch { handleClient(client) }
                    } catch (_: IOException) { break }
                }
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    fun stop() {
        running.set(false)
        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null
        serverJob?.cancel()
        serverJob = null
    }

    // FIX #7: استُبدل WifiManager.connectionInfo المهجور (API 31+)
    // بـ ConnectivityManager.getLinkProperties على الأجهزة الحديثة.
    fun phoneIp(): String {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val linkProps = cm.getLinkProperties(cm.activeNetwork)
                linkProps?.linkAddresses
                    ?.map { it.address }
                    ?.filterIsInstance<Inet4Address>()
                    ?.firstOrNull { !it.isLoopbackAddress }
                    ?.hostAddress ?: fallbackIp()
            } else {
                @Suppress("DEPRECATION")
                val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
                @Suppress("DEPRECATION")
                val ip = wm.connectionInfo.ipAddress
                if (ip == 0) fallbackIp()
                else String.format(
                    "%d.%d.%d.%d",
                    ip and 0xff, ip shr 8 and 0xff, ip shr 16 and 0xff, ip shr 24 and 0xff
                )
            }
        } catch (_: Exception) {
            fallbackIp()
        }
    }

    private fun fallbackIp(): String = try {
        NetworkInterface.getNetworkInterfaces()?.toList()
            ?.flatMap { it.inetAddresses.toList() }
            ?.firstOrNull { !it.isLoopbackAddress && it is Inet4Address }
            ?.hostAddress ?: "unknown"
    } catch (_: Exception) { "unknown" }

    // FIX #6: يتضمن الرمز الآن في الرابط المعروض للمستخدم
    fun serverUrl(): String = "http://${phoneIp()}:$port/?token=$accessToken"

    // ── معالجة طلب HTTP ──────────────────────────────────────────────────────

    private fun handleClient(socket: Socket) {
        // FIX-OUTPUT-SCOPE: أُعلن output خارج try حتى يكون متاحاً في catch
        var output: OutputStream? = null
        try {
            socket.soTimeout = 30_000
            // FIX #2: استُبدل BufferedReader بقراءة بايت-بايت لتفادي ابتلاع
            // بيانات الـ body داخل buffer الـ reader، مما كان يُفسد الملفات المرفوعة.
            val rawInput = socket.getInputStream()
            output       = socket.getOutputStream()

            val requestLine = readHttpLine(rawInput) ?: return
            val parts = requestLine.split(" ")
            if (parts.size < 2) return

            val method = parts[0]
            val rawUrl = parts[1]
            val (urlPath, queryString) = rawUrl.split("?", limit = 2).let {
                Pair(it[0], it.getOrElse(1) { "" })
            }

            val headers = mutableMapOf<String, String>()
            var line = readHttpLine(rawInput)
            while (!line.isNullOrBlank()) {
                val idx = line.indexOf(':')
                if (idx > 0) headers[line.substring(0, idx).lowercase().trim()] = line.substring(idx + 1).trim()
                line = readHttpLine(rawInput)
            }

            // FIX #6: التحقق من رمز الوصول قبل معالجة أي طلب
            val cookieHeader = headers["cookie"] ?: ""
            val queryToken   = queryParam(queryString, "token") ?: ""
            if (!isAuthorized(cookieHeader, queryToken)) {
                sendAuthChallenge(output)
                return
            }

            when {
                method == "GET"  && urlPath == "/"         -> sendFileListing(output, queryString)
                method == "GET"  && urlPath == "/download" -> sendFileDownload(output, queryString)
                // FIX #2: نمرر rawInput (المُعالَج بشكل صحيح) بدلاً من socket
                method == "POST" && urlPath == "/upload"   -> receiveFileUpload(rawInput, output, queryString, headers)
                else -> sendHttp(output, 404, "text/plain", "Not found".toByteArray())
            }
        } catch (e: Exception) {
            // BUG-500 FIX: previously exceptions were swallowed silently, leaving the
            // browser connection hanging with no response until the TCP timeout fired.
            // Now we attempt to send a 500 so the browser shows an error immediately.
            // We ignore any secondary exception from this write (e.g. if the socket is
            // already broken) so the original problem is not masked.
            try {
                output?.let { sendHttp(it, 500, "text/plain", "Internal server error".toByteArray()) }
            } catch (_: Exception) {}
        } finally {
            try { socket.close() } catch (_: Exception) {}
        }
    }

    /**
     * FIX #2: قراءة سطر HTTP بايت بايت من InputStream الخام.
     * يمنع BufferedReader من ابتلاع bytes تعود إلى body الطلب.
     */
    private fun readHttpLine(input: InputStream): String? {
        val sb = StringBuilder()
        var prev = -1
        while (true) {
            val b = input.read()
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            if (prev == '\r'.code && b == '\n'.code) {
                sb.deleteCharAt(sb.length - 1) // احذف الـ \r
                return sb.toString()
            }
            sb.append(b.toChar())
            prev = b
            if (sb.length > 8192) return sb.toString() // حماية من headers ضخمة
        }
    }

    // FIX #6: التحقق من الرمز عبر cookie أو query param
    private fun isAuthorized(cookie: String, queryToken: String): Boolean =
        queryToken == accessToken || cookie.contains("hx_token=$accessToken")

    private fun sendAuthChallenge(output: OutputStream) {
        val html = """<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>body{background:#0a0e1a;color:#e0e6ff;font-family:Arial;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0}
.box{background:#141827;border:1px solid #1e2840;border-radius:12px;padding:32px;
text-align:center;max-width:320px}h2{color:#ff4444;margin:0 0 16px}p{color:#aaa;margin:0}
</style></head><body><div class="box"><h2>🔒 Access Denied</h2>
<p>Open the URL shown in the HexRDP app to access file sharing.</p></div></body></html>"""
        val body   = html.toByteArray(Charsets.UTF_8)
        val header = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\n" +
            "Content-Length: ${body.size}\r\nConnection: close\r\n\r\n"
        output.write(header.toByteArray(Charsets.US_ASCII))
        output.write(body)
        output.flush()
    }

    // FIX #5: تحقق أن المسار المطلوب داخل نطاق التخزين المسموح به
    private fun safeSubPath(requested: String): String? {
        val canonical = try { File(requested).canonicalPath } catch (_: Exception) { return null }
        return if (canonical.startsWith(allowedRoot)) canonical else null
    }

    // ── عرض قائمة الملفات ────────────────────────────────────────────────────

    private fun sendFileListing(output: OutputStream, query: String) {
        val token   = queryParam(query, "token") ?: ""
        val rawPath = queryParam(query, "path") ?: Environment.getExternalStorageDirectory().absolutePath
        // FIX #5: رفض أي مسار خارج نطاق التخزين
        val path    = safeSubPath(rawPath) ?: Environment.getExternalStorageDirectory().absolutePath
        val dir     = File(path)
        val files   = if (dir.exists() && dir.isDirectory) {
            (dir.listFiles() ?: emptyArray())
                .sortedWith(compareByDescending<File> { it.isDirectory }.thenBy { it.name.lowercase() })
        } else emptyList()

        val extRoot = Environment.getExternalStorageDirectory().absolutePath
        // FIX #6: رمز الوصول يُضمَّن في كل رابط
        fun lnk(path: String) = "/?path=${enc(path)}&token=${enc(token)}"
        fun dlnk(path: String) = "/download?path=${enc(path)}&token=${enc(token)}"

        val sb = StringBuilder()
        sb.append("""<!DOCTYPE html><html lang="ar" dir="rtl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HexRDP File Share</title>
<style>
body{font-family:Arial,sans-serif;background:#0a0e1a;color:#e0e6ff;margin:0;padding:16px}
h2{color:#00e5ff;margin:0 0 8px}
.path{font-size:12px;color:#aaa;margin-bottom:16px;word-break:break-all}
.file-list{list-style:none;padding:0;margin:0}
.file-item{display:flex;align-items:center;padding:10px 12px;margin-bottom:4px;background:#141827;border-radius:8px;border:1px solid #1e2840}
.file-item a{color:#7eb8ff;text-decoration:none;flex:1;word-break:break-all}
.file-item .size{font-size:11px;color:#aaa;margin-right:12px}
.dir-icon::before{content:"📁 "}
.file-icon::before{content:"📄 "}
.upload-box{margin-top:24px;padding:16px;background:#141827;border-radius:8px;border:2px dashed #00e5ff30}
.upload-box h3{color:#00e5ff;margin:0 0 12px}
input[type=file]{color:#e0e6ff}
button{background:#00e5ff;color:#000;border:none;padding:8px 24px;border-radius:6px;font-weight:bold;cursor:pointer;margin-top:8px}
.back{color:#00e5ff;text-decoration:none;display:inline-block;margin-bottom:12px}
</style>
<script>document.cookie="hx_token=${token}; path=/; SameSite=Strict";</script>
</head><body>
<h2>📱 HexRDP File Share</h2>""")

        if (path != extRoot) {
            sb.append("""<a class="back" href="${lnk(dir.parent ?: extRoot)}">← Back</a>""")
        }
        sb.append("""<div class="path">$path</div>""")
        sb.append("""<ul class="file-list">""")
        files.forEach { f ->
            if (f.isDirectory) {
                sb.append("""<li class="file-item"><span class="dir-icon"></span>
<a href="${lnk(f.absolutePath)}">${htmlEsc(f.name)}</a></li>""")
            } else {
                val size = formatBytes(f.length())
                sb.append("""<li class="file-item"><span class="file-icon"></span>
<a href="${dlnk(f.absolutePath)}">${htmlEsc(f.name)}</a>
<span class="size">$size</span></li>""")
            }
        }
        sb.append("</ul>")
        sb.append("""
<div class="upload-box">
<h3>⬆ Upload to this folder</h3>
<form method="POST" action="/upload?path=${enc(path)}&token=${enc(token)}" enctype="multipart/form-data">
<input type="file" name="file" multiple><br>
<button type="submit">Upload</button>
</form>
</div>
</body></html>""")

        sendHttp(output, 200, "text/html; charset=utf-8", sb.toString().toByteArray(Charsets.UTF_8))
    }

    // ── تنزيل ملف ────────────────────────────────────────────────────────────

    private fun sendFileDownload(output: OutputStream, query: String) {
        val rawPath = queryParam(query, "path") ?: run {
            sendHttp(output, 400, "text/plain", "Missing path".toByteArray())
            return
        }
        // FIX #5: رفض أي مسار خارج نطاق التخزين (path traversal)
        val path = safeSubPath(rawPath) ?: run {
            sendHttp(output, 403, "text/plain", "Forbidden path".toByteArray())
            return
        }
        val file = File(path)
        if (!file.exists() || !file.isFile) {
            sendHttp(output, 404, "text/plain", "File not found".toByteArray())
            return
        }
        val encoded = URLEncoder.encode(file.name, "UTF-8").replace("+", "%20")
        val headers = "HTTP/1.1 200 OK\r\n" +
            "Content-Type: application/octet-stream\r\n" +
            "Content-Disposition: attachment; filename*=UTF-8''$encoded\r\n" +
            "Content-Length: ${file.length()}\r\n" +
            "Connection: close\r\n\r\n"
        output.write(headers.toByteArray(Charsets.US_ASCII))
        FileInputStream(file).use { it.copyTo(output, bufferSize = 64 * 1024) }
        output.flush()
    }

    // ── استقبال ملف مرفوع ────────────────────────────────────────────────────

    private fun receiveFileUpload(
        // FIX #2: يستقبل الآن InputStream الخام (المُعالَج بشكل صحيح)
        // بدلاً من Socket — لا يوجد خطر فقدان bytes بسبب BufferedReader.
        rawInput: InputStream,
        output: OutputStream,
        query: String,
        headers: Map<String, String>
    ) {
        val rawPath = queryParam(query, "path") ?: Environment.getExternalStorageDirectory().absolutePath
        // FIX #5: التحقق من المسار
        val destDir = safeSubPath(rawPath) ?: Environment.getExternalStorageDirectory().absolutePath
        val dir     = File(destDir).also { it.mkdirs() }

        val contentLength = headers["content-length"]?.toLongOrNull() ?: -1L
        val contentType   = headers["content-type"] ?: ""
        val boundary      = contentType.substringAfter("boundary=", "").trim()

        if (boundary.isEmpty() || contentLength <= 0L) {
            sendHttp(output, 400, "text/plain", "Bad request".toByteArray())
            return
        }

        // BUG-3 FIX: The previous strategy wrote the body to a temp file (good) but then
        // called tempFile.readBytes() which loads the ENTIRE body back into a ByteArray —
        // negating the on-disk strategy for large files. A 200 MB upload would attempt to
        // allocate a 200 MB ByteArray on the JVM heap → OOM / ActivityManager kill.
        //
        // Fix: write the body to a temp file as before, then stream-parse the multipart
        // boundary using a small sliding read window (~128 KB).  Each part's file content
        // is written directly to its destination file, so heap usage is bounded by the
        // window size regardless of upload size.
        val tempFile = File.createTempFile("hexrdp_upload_", ".tmp", context.cacheDir)
        var savedCount = 0
        try {
            // Step 1: stream raw body to disk (unchanged — already correct).
            FileOutputStream(tempFile).use { fos ->
                val buf = ByteArray(64 * 1024)
                var remaining = contentLength
                while (remaining > 0) {
                    val n = rawInput.read(buf, 0, minOf(buf.size.toLong(), remaining).toInt())
                    if (n < 0) break
                    fos.write(buf, 0, n)
                    remaining -= n
                }
            }

            // Step 2: stream-parse multipart without loading the whole file into RAM.
            savedCount = parseMultipartStreaming(tempFile, boundary, dir)
        } finally {
            tempFile.delete()
        }

        val html = """<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta http-equiv="refresh" content="2;url=/?path=${enc(destDir)}&token=${enc(queryParam(query, "token") ?: "")}">
<style>body{background:#0a0e1a;color:#e0e6ff;font-family:Arial;text-align:center;padding:40px}</style>
</head><body><h2 style="color:#00e5ff">✅ $savedCount file(s) uploaded</h2>
<p>Redirecting back...</p></body></html>"""
        sendHttp(output, 200, "text/html; charset=utf-8", html.toByteArray(Charsets.UTF_8))
    }

    // ── مساعدات ──────────────────────────────────────────────────────────────

    private fun sendHttp(output: OutputStream, code: Int, mime: String, body: ByteArray) {
        val status = when (code) { 200 -> "OK"; 400 -> "Bad Request"; 403 -> "Forbidden"; 404 -> "Not Found"; 500 -> "Internal Server Error"; else -> "Error" }
        val header = "HTTP/1.1 $code $status\r\nContent-Type: $mime\r\n" +
            "Content-Length: ${body.size}\r\nConnection: close\r\n\r\n"
        output.write(header.toByteArray(Charsets.US_ASCII))
        output.write(body)
        output.flush()
    }

    private fun queryParam(query: String, key: String): String? =
        query.split("&")
            .firstOrNull { it.startsWith("$key=") }
            ?.substringAfter("$key=")
            ?.let { URLDecoder.decode(it, "UTF-8") }

    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")
    private fun htmlEsc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    private fun indexOfBytes(haystack: ByteArray, needle: ByteArray, start: Int): Int {
        outer@ for (i in start..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }

    private fun ByteArray.endsWith(suffix: ByteArray): Boolean {
        if (this.size < suffix.size) return false
        val offset = this.size - suffix.size
        return suffix.indices.all { this[offset + it] == suffix[it] }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BUG-3 FIX: Streaming multipart parser (no full-body ByteArray in RAM)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Parses a multipart/form-data body stored in [tempFile] and writes each
 * uploaded part to a file inside [destDir].
 *
 * Key property: the file is read in a ~128 KB sliding window.  No single
 * ByteArray larger than the window is ever allocated, so a 2 GB upload
 * uses the same ~128 KB of heap as a 1 KB upload.
 *
 * Returns the number of files successfully saved.
 */
private fun parseMultipartStreaming(
    tempFile: File,
    boundary: String,
    destDir: File
): Int {
    val sep      = "--$boundary".toByteArray(Charsets.ISO_8859_1)
    val crlf     = "\r\n".toByteArray(Charsets.ISO_8859_1)
    val hdrEnd   = "\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
    var saved    = 0

    java.io.RandomAccessFile(tempFile, "r").use { raf ->
        val fileLen = raf.length()

        // Locate all boundary positions by reading the file in overlapping chunks.
        // Overlap by (sep.size - 1) bytes so a boundary is never split across windows.
        val windowSize = 128 * 1024
        val overlap    = sep.size - 1
        val positions  = mutableListOf<Long>()

        var fileOffset = 0L
        val window     = ByteArray(windowSize + overlap)
        var windowLen  = 0

        while (fileOffset < fileLen || (fileOffset == 0L && fileLen == 0L)) {
            // Fill window: overlap bytes from previous iteration + fresh bytes.
            val readStart = if (fileOffset == 0L) 0 else overlap
            raf.seek(fileOffset)
            val n = raf.read(window, readStart, windowSize)
            if (n <= 0) break
            windowLen = readStart + n

            // Search for boundary inside this window.
            var searchFrom = 0
            while (true) {
                var found = -1
                outer@ for (i in searchFrom..windowLen - sep.size) {
                    for (j in sep.indices) {
                        if (window[i + j] != sep[j]) continue@outer
                    }
                    found = i
                    break
                }
                if (found < 0) break
                // Convert window-relative index to file-absolute position.
                val absPos = fileOffset - (if (fileOffset == 0L) 0 else overlap) + found
                // Avoid duplicates at the overlap region.
                if (positions.isEmpty() || absPos > positions.last()) {
                    positions.add(absPos)
                }
                searchFrom = found + 1
            }

            // Advance file pointer; keep the last `overlap` bytes in the window.
            // BUG-OVERLAP FIX: if the file is smaller than `overlap` bytes (e.g. a
            // malformed or tiny multipart body), windowLen - overlap is negative →
            // System.arraycopy throws ArrayIndexOutOfBoundsException.
            // Guard: only copy when there are enough bytes; otherwise zero-fill the
            // overlap region so the next iteration starts clean.
            if (windowLen >= overlap) {
                System.arraycopy(window, windowLen - overlap, window, 0, overlap)
            } else {
                window.fill(0, 0, overlap)
            }
            fileOffset += n
        }

        // Each adjacent pair of boundary positions defines one part.
        for (i in 0 until positions.size - 1) {
            val partStart = positions[i] + sep.size   // skip "--boundary"
            val partEnd   = positions[i + 1]          // start of next "--boundary"

            // Skip the leading CRLF after the boundary line.
            val bodyStart = partStart + crlf.size     // skip \r\n after boundary

            // Read headers (everything up to \r\n\r\n), max 8 KB.
            val headerBuf = ByteArray(8192)
            raf.seek(bodyStart)
            val headerRead = raf.read(headerBuf, 0, headerBuf.size.coerceAtMost((partEnd - bodyStart).toInt()))
            if (headerRead < hdrEnd.size) continue

            // Find \r\n\r\n inside the header buffer.
            var hdrEndIdx = -1
            outer@ for (h in 0..headerRead - hdrEnd.size) {
                for (j in hdrEnd.indices) { if (headerBuf[h + j] != hdrEnd[j]) continue@outer }
                hdrEndIdx = h
                break
            }
            if (hdrEndIdx < 0) continue

            val headerStr = String(headerBuf, 0, hdrEndIdx, Charsets.ISO_8859_1)
            val fileName  = Regex("""filename="([^"]+)"""").find(headerStr)?.groupValues?.get(1)
            if (fileName.isNullOrBlank()) continue

            // File content: from (bodyStart + hdrEndIdx + 4) to (partEnd - \r\n).
            val contentStart = bodyStart + hdrEndIdx + hdrEnd.size
            var contentEnd   = partEnd
            // Strip trailing \r\n before the next boundary.
            if (contentEnd - contentStart >= crlf.size) contentEnd -= crlf.size

            val contentLen = contentEnd - contentStart
            if (contentLen <= 0) continue

            // Stream content directly to destination — no large heap allocation.
            val dest = File(destDir, File(fileName).name)
            raf.seek(contentStart)
            FileOutputStream(dest).use { out ->
                val copyBuf  = ByteArray(64 * 1024)
                var remaining = contentLen
                while (remaining > 0) {
                    val toRead = copyBuf.size.toLong().coerceAtMost(remaining).toInt()
                    val rd     = raf.read(copyBuf, 0, toRead)
                    if (rd < 0) break
                    out.write(copyBuf, 0, rd)
                    remaining -= rd
                }
            }
            saved++
        }
    }
    return saved
}
