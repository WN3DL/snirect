package com.xihale.snirect.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import com.xihale.snirect.BuildConfig
import com.xihale.snirect.data.model.LogLevel
import com.xihale.snirect.data.repository.ConfigRepository
import com.xihale.snirect.ktlib.EngineState
import com.xihale.snirect.ktlib.SnirectClient
import com.xihale.snirect.ktlib.SnirectEngineConfig
import com.xihale.snirect.ktlib.SnirectEngineCallbacks
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

import java.lang.reflect.Method
import java.net.InetAddress
import java.net.InetSocketAddress
import com.xihale.snirect.util.AppLogger
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

class SnirectVpnService : VpnService(), SnirectEngineCallbacks {

    companion object {
        const val ACTION_START = "com.xihale.snirect.START"
        const val ACTION_STOP = "com.xihale.snirect.STOP"
        private const val ACTION_DEBUG_AUTO_EXCLUDE = "com.xihale.snirect.debug.AUTO_EXCLUDE"

        /** Startup watchdog: engine must be Running within this window. */
        private const val STARTUP_TIMEOUT_MS = 15_000L

        /**
         * Auto-exclusion policy: a package that aborts the MITM handshake
         * this many times within the window is treated as certificate-pinned
         * and removed from the VPN's capture set (with an immediate restart).
         */
        private const val CERT_REJECT_THRESHOLD = 3
        private const val CERT_REJECT_WINDOW_MS = 120_000L

        var isServiceRunning = false
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private var isDestroyed = false
    private var teardownJob: Job? = null
    private var startJob: Job? = null

    // Per-package timestamps of client certificate rejections (sliding window).
    private val certRejectStrikes = ConcurrentHashMap<String, MutableList<Long>>()

    // A START that arrived while a teardown was still unwinding. Set under
    // lifecycleLock; cleared by any new teardown (STOP or engine death), so
    // the user's last intent wins. The teardown coroutine honors it at its
    // tail — after every slow step — instead of stopSelf-ing.
    private val lifecycleLock = Any()
    private var deferredStart = false

    // Latest delivered startId. stopSelf(id) only stops the service when id
    // is still the most recent delivery, so a START that arrives anywhere
    // during the teardown automatically neutralizes our stopSelf — the
    // service (and its coroutine scope) survives for the restart.
    @Volatile private var lastStartId = 0
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var repository: ConfigRepository
    private lateinit var snirectClient: SnirectClient

    override fun onCreate() {
        super.onCreate()
        snirectClient = SnirectClient.from(this)
        repository = ConfigRepository(this)
        VpnStatusManager.attach(snirectClient)
        AppLogger.init(this)
        isServiceRunning = true
        observeEngineState()
        registerDebugHook()
    }

    /**
     * Debug-builds-only test lever: `adb shell am broadcast -a
     * com.xihale.snirect.debug.AUTO_EXCLUDE -e pkg <package>` drives the same
     * autoExcludePackage path a real cert-reject strike would take (persist,
     * restart, re-filter). Lets the exclusion pipeline be exercised on a ROM
     * whose unrooted attribution is blocked (e.g. EMUI 10) without shipping
     * any test scaffolding in release builds.
     */
    private var debugReceiver: BroadcastReceiver? = null

    private fun registerDebugHook() {
        if (!BuildConfig.DEBUG) return
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action != ACTION_DEBUG_AUTO_EXCLUDE) return
                val pkg = intent.getStringExtra("pkg") ?: return
                if (pkg == "clear") {
                    AppLogger.w("DEBUG hook: clearing auto-excluded set")
                    serviceScope.launch { repository.setAutoExcludedPackages(emptySet()) }
                    return
                }
                AppLogger.w("DEBUG hook: auto-excluding $pkg")
                serviceScope.launch { autoExcludePackage(pkg) }
            }
        }
        registerReceiver(receiver, IntentFilter(ACTION_DEBUG_AUTO_EXCLUDE))
        debugReceiver = receiver
    }

    override fun onDestroy() {
        isDestroyed = true
        isServiceRunning = false
        debugReceiver?.let { runCatching { unregisterReceiver(it) } }
        debugReceiver = null
        // Close the TUN promptly. The engine stop is best-effort off the main
        // thread: NonCancellable keeps the blocking call running to completion
        // on its IO thread even after serviceScope is cancelled below.
        closeTun()
        val engineAlive = snirectClient.engineState.value.let {
            it is EngineState.Starting || it is EngineState.Running
        }
        // Never call the process-global stopEngine from onDestroy if a
        // teardown already owns it — a late stopEngine here can kill a
        // START that just reused this process.
        if (teardownJob?.isActive != true && startJob?.isActive != true && engineAlive) {
            serviceScope.launch {
                withContext(NonCancellable + Dispatchers.IO) {
                    try {
                        snirectClient.stopEngine()
                    } catch (e: Exception) {
                        AppLogger.e("Stop Core Error", e)
                    }
                }
            }
        }
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId = startId
        AppLogger.i("VPN Service: onStartCommand called, action=${intent?.action}")
        // A START_STICKY restart after a system kill delivers a null intent —
        // recover by re-establishing the VPN instead of idling as "unknown".
        when (intent?.action ?: ACTION_START) {
            ACTION_STOP -> {
                AppLogger.i("VPN Service: Received STOP action")
                stopVpn()
            }
            ACTION_START -> {
                AppLogger.i("VPN Service: Received START action, isRunning=$isRunning")
                if (isRunning) {
                    AppLogger.w("VPN Service: Already running, ignoring START")
                    return START_STICKY
                }
                if (teardownJob?.isActive != true) {
                    startVpn()
                } else {
                    // A stop is still unwinding. The teardown honors the flag
                    // at its tail — this closes the window where a START
                    // landing between the teardown's decision point and
                    // stopSelf() was silently dropped.
                    synchronized(lifecycleLock) { deferredStart = true }
                    AppLogger.i("VPN Service: Teardown in progress, restart deferred")
                }
            }
            else -> AppLogger.w("VPN Service: Unknown action: ${intent?.action}")
        }
        return START_STICKY
    }

    /**
     * Reacts to runtime engine death via ktlib's engine state flow (the
     * single source of truth, mirrored to the UI by VpnStatusManager).
     */
    private fun observeEngineState() {
        serviceScope.launch {
            // StateFlow replays the current value to a new collector. A leftover
            // Stopped/Failed from a previous service instance must not tear
            // this one down — that raced a fresh START and closed its TUN.
            var first = true
            snirectClient.engineState.collect { state ->
                if (isDestroyed) return@collect
                if (first) {
                    first = false
                    when (state) {
                        is EngineState.Stopped, EngineState.Idle -> return@collect
                        is EngineState.Failed -> return@collect
                        else -> Unit
                    }
                }
                when (state) {
                    is EngineState.Failed -> {
                        // Startup failure or runtime death; VpnStatusManager
                        // already holds the terminal FAILED:<reason>.
                        // The engine is already dead — tear down the TUN and
                        // the service, but do NOT call stopEngine again.
                        beginTeardown(callStopEngine = false)
                    }
                    is EngineState.Stopped -> {
                        // Only tear down a session this instance actually
                        // started. A late Stopped from the previous generation
                        // (or the StateFlow replay) must not close a new TUN.
                        if (isRunning || startJob?.isActive == true) {
                            beginTeardown(callStopEngine = false)
                        }
                    }
                    else -> Unit
                }
            }
        }
    }

    private fun startVpn() {
        AppLogger.i("Starting VPN Service...")

        startJob?.cancel()
        startJob = serviceScope.launch {
            try {
                setupVpn()
                // startEngine is non-blocking: wait for the actual outcome
                // (with a startup watchdog) instead of trusting the return.
                val outcome = snirectClient.awaitStartup(STARTUP_TIMEOUT_MS)
                if (outcome is EngineState.Running) {
                    AppLogger.i("VPN Setup Complete: engine running")
                    isRunning = true
                } else {
                    throw IllegalStateException("engine startup did not complete: $outcome")
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                AppLogger.e("VPN Start Failed", e)
                // Engine-reported failures are already reflected by the state
                // collector; only local failures (TUN, JNI throw) set it here.
                if (snirectClient.engineState.value !is EngineState.Failed) {
                    VpnStatusManager.updateStatus(false, "FAILED:${e.message}")
                }
                beginTeardown(callStopEngine = true)
            }
        }
    }

    /** User- or system-initiated stop; the heavy parts run on serviceScope (IO). */
    private fun stopVpn() {
        AppLogger.i("Stopping VPN Service...")
        beginTeardown(callStopEngine = true)
    }

    /**
     * Idempotent teardown: only one teardown job runs at a time. Never call
     * stopEngine for an engine that already died (the observeEngineState
     * collector passes [callStopEngine] = false for that case). Any new
     * teardown clears a deferred START, so the last intent always wins; a
     * deferred START that survives is honored at the tail of this coroutine.
     */
    private fun beginTeardown(callStopEngine: Boolean) {
        synchronized(lifecycleLock) {
            // A Stopped/Failed event arriving while a teardown is already
            // running must NOT wipe a START the user issued in the meantime.
            if (teardownJob?.isActive == true) return
            deferredStart = false
            teardownJob = serviceScope.launch { runTeardown(callStopEngine) }
        }
    }

    private suspend fun runTeardown(callStopEngine: Boolean) {
        isRunning = false
        isServiceRunning = false
        startJob?.cancel()
        startJob = null
        if (callStopEngine) {
            try {
                snirectClient.stopEngine()
            } catch (e: Exception) {
                AppLogger.e("Stop Core Error", e)
            }
        }
        closeTun()

        // Decide LAST, after every slow step, so a START that landed anywhere
        // during the unwind is seen. Capturing lastStartId inside the same
        // lock pairs with onStartCommand: any START delivered from here on
        // has a newer id, which neutralizes stopSelf(id) below — the service
        // and its scope survive, so the post-stopSelf restart is safe (no
        // JobCancellationException).
        val (restart, stopId) = synchronized(lifecycleLock) {
            val wants = deferredStart && !isDestroyed
            deferredStart = false
            wants to lastStartId
        }
        if (restart) {
            AppLogger.i("VPN Service: Restarting (START arrived during teardown)")
            isServiceRunning = true
            startVpn()
            return
        }

        // Only publish DISCONNECTED when we are actually going idle. A
        // deferred START already set STARTING; overwriting it here made
        // the UI look disconnected while the engine was coming back up.
        VpnStatusManager.updateStatus(false, "DISCONNECTED")

        stopSelf(stopId)

        // If a START interleaved between the decision above and stopSelf(),
        // its newer startId voided the stop, so this scope is alive: a direct
        // startVpn is safe here.
        if (synchronized(lifecycleLock) { val r = deferredStart && !isDestroyed; deferredStart = false; r }) {
            AppLogger.i("VPN Service: START raced teardown tail, restarting")
            isServiceRunning = true
            startVpn()
        }
    }

    private fun closeTun() {
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            AppLogger.w("TUN close failed: ${e.message}")
        }
        vpnInterface = null
    }

    private suspend fun setupVpn() {
        if (vpnInterface != null) return

        AppLogger.i("VPN Setup: Loading configuration...")
        val nameservers = repository.nameservers.first()
        val bootstrapDns = repository.bootstrapDns.first()
        val checkHostname = repository.checkHostname.first()
        val mtuValue = repository.mtu.first()
        val ipv6Mode = repository.ipv6Mode.first()
        val logLvl = repository.logLevel.first()
        val filterMode = repository.filterMode.first()
        val whitelistPackages = repository.whitelistPackages.first()
        val autoExcluded = repository.autoExcludedPackages.first()
        val bypassLan = repository.bypassLan.first()
        val blockIpv6 = ipv6Mode == ConfigRepository.IPV6_MODE_ONLY_V4
        val ipv6Enabled = ipv6Mode == ConfigRepository.IPV6_MODE_FULL_V6

        AppLogger.i("VPN Setup: Config loaded - MTU=$mtuValue, IPv6Mode=$ipv6Mode, LogLevel=$logLvl, FilterMode=$filterMode, BypassLAN=$bypassLan, Bootstrap=$bootstrapDns, Nameservers=$nameservers")

        val builder = Builder()
            .setSession("Snirect")
            .setMtu(mtuValue)
            .addAddress("10.0.0.1", 24)
            .addDnsServer("10.0.0.2")

        addIpv4Routes(builder, bypassLan)

        // Handle IPv6
        if (!blockIpv6) {
            addIpv6Routes(builder, bypassLan)
        } else {
            AppLogger.i("VPN Setup: IPv6 Blocked")
        }

        applyAppFiltering(builder, filterMode, whitelistPackages, autoExcluded)

        AppLogger.i("VPN Setup: Establishing TUN interface...")
        vpnInterface = builder.establish()
            ?: throw IllegalStateException("Failed to establish TUN interface")
        AppLogger.d("VPN Setup: TUN interface established")

        val fd = vpnInterface!!.fd
        val config = SnirectEngineConfig.Builder()
            .nameservers(nameservers)
            .bootstrapDns(bootstrapDns)
            .checkHostname(checkHostname)
            .mtu(mtuValue)
            .enableIpv6(ipv6Enabled)
            .logLevel(logLvl)
            .build()
        AppLogger.i("VPN Setup: Starting core engine...")

        // Non-blocking suspend call; the outcome arrives via engineState and
        // is awaited in startVpn() with a watchdog.
        snirectClient.startEngine(fd.toLong(), config, this)
        AppLogger.i("VPN Setup: SnirectClient.startEngine() request submitted")
    }

    /**
     * Android's VpnService.Builder forbids mixing addAllowedApplication with
     * addDisallowedApplication (it throws IllegalArgumentException), so the two
     * modes must stay mutually exclusive. Auto-excluded packages (cert-pinned
     * apps, see onCertRejected) are merged into whichever list expresses
     * "bypass": removed from the whitelist set, or added to the disallow list.
     *
     * - Whitelist mode uses ONLY the allow-list. Everything not listed —
     *   including this app's own package, which is deliberately never added —
     *   already bypasses the VPN, so no addDisallowedApplication call is made.
     * - Blacklist/global mode uses ONLY disallowed entries: the app itself
     *   (loop prevention), the system download provider (kept from the
     *   original VPN setup for behavioral parity), user blacklist entries, and
     *   auto-excluded packages.
     */
    private fun applyAppFiltering(
        builder: Builder,
        filterMode: Int,
        whitelistPackages: Set<String>,
        autoExcluded: Set<String>,
    ) {
        val effectiveWhitelist = whitelistPackages - autoExcluded
        val useWhitelist = filterMode == ConfigRepository.FILTER_MODE_WHITELIST &&
            effectiveWhitelist.isNotEmpty()

        if (useWhitelist) {
            for (pkg in effectiveWhitelist) {
                if (pkg == packageName) continue // never tunnel ourselves
                try {
                    builder.addAllowedApplication(pkg)
                } catch (e: Exception) {
                    AppLogger.w("Whitelist add failed: $pkg")
                }
            }
            if (autoExcluded.isNotEmpty()) {
                AppLogger.i("VPN Setup: Whitelist mode with ${effectiveWhitelist.size} apps (${autoExcluded.size} auto-excluded)")
            } else {
                AppLogger.i("VPN Setup: Whitelist mode with ${effectiveWhitelist.size} apps")
            }
            return
        }

        // Global / blacklist mode (an empty effective whitelist also degrades to global).
        builder.addDisallowedApplication(packageName) // Always bypass self
        builder.addDisallowedApplication("com.android.providers.downloads")
        if (filterMode == ConfigRepository.FILTER_MODE_BLACKLIST && whitelistPackages.isNotEmpty()) {
            for (pkg in whitelistPackages) {
                try {
                    builder.addDisallowedApplication(pkg)
                } catch (e: Exception) {
                    AppLogger.w("Blacklist add failed: $pkg")
                }
            }
            AppLogger.i("VPN Setup: Blacklist mode with ${whitelistPackages.size} apps")
        } else {
            AppLogger.i("VPN Setup: Global mode (No filtering)")
        }
        for (pkg in autoExcluded) {
            if (pkg == packageName) continue
            try {
                builder.addDisallowedApplication(pkg)
            } catch (e: Exception) {
                AppLogger.w("Auto-exclude add failed: $pkg")
            }
        }
        if (autoExcluded.isNotEmpty()) {
            AppLogger.i("VPN Setup: ${autoExcluded.size} auto-excluded packages bypass the VPN")
        }
    }

    private fun addIpv4Routes(builder: Builder, bypassLan: Boolean) {
        if (!bypassLan) {
            builder.addRoute("0.0.0.0", 0)
            return
        }

        listOf(
            "1.0.0.0" to 8,
            "2.0.0.0" to 7,
            "4.0.0.0" to 6,
            "8.0.0.0" to 7,
            "11.0.0.0" to 8,
            "12.0.0.0" to 6,
            "16.0.0.0" to 4,
            "32.0.0.0" to 3,
            "64.0.0.0" to 3,
            "96.0.0.0" to 6,
            "100.0.0.0" to 10,
            "100.128.0.0" to 9,
            "101.0.0.0" to 8,
            "102.0.0.0" to 7,
            "104.0.0.0" to 5,
            "112.0.0.0" to 5,
            "120.0.0.0" to 6,
            "124.0.0.0" to 7,
            "126.0.0.0" to 8,
            "128.0.0.0" to 3,
            "160.0.0.0" to 5,
            "168.0.0.0" to 8,
            "169.0.0.0" to 9,
            "169.128.0.0" to 10,
            "169.192.0.0" to 11,
            "169.224.0.0" to 12,
            "169.240.0.0" to 13,
            "169.248.0.0" to 14,
            "169.252.0.0" to 15,
            "169.255.0.0" to 16,
            "170.0.0.0" to 7,
            "172.0.0.0" to 12,
            "172.32.0.0" to 11,
            "172.64.0.0" to 10,
            "172.128.0.0" to 9,
            "173.0.0.0" to 8,
            "174.0.0.0" to 7,
            "176.0.0.0" to 4,
            "192.0.0.0" to 9,
            "192.128.0.0" to 11,
            "192.160.0.0" to 13,
            "192.169.0.0" to 16,
            "192.170.0.0" to 15,
            "192.172.0.0" to 14,
            "192.176.0.0" to 12,
            "192.192.0.0" to 10,
            "193.0.0.0" to 8,
            "194.0.0.0" to 7,
            "196.0.0.0" to 6,
            "200.0.0.0" to 5,
            "208.0.0.0" to 4
        ).forEach { (address, prefix) -> builder.addRoute(address, prefix) }
    }

    private fun addIpv6Routes(builder: Builder, bypassLan: Boolean) {
        builder.addAddress("fd00::1", 128)
        if (!bypassLan) {
            builder.addRoute("::", 0)
            return
        }

        builder.addRoute("2000::", 3)
    }

    override fun onStatusChanged(status: String?) {
        if (isDestroyed) return

        status?.let { msg ->
            val level = when {
                msg.contains("[ERROR]") -> LogLevel.ERROR
                msg.contains("[WARN]") -> LogLevel.WARN
                msg.contains("[DEBUG]") -> LogLevel.DEBUG
                else -> LogLevel.INFO
            }

            val cleanMsg = msg
                .replace("[ERROR]", "")
                .replace("[WARN]", "")
                .replace("[DEBUG]", "")
                .replace("[INFO]", "")
                .trim()

            when (level) {
                LogLevel.ERROR -> AppLogger.e(cleanMsg)
                LogLevel.WARN -> AppLogger.w(cleanMsg)
                LogLevel.DEBUG -> AppLogger.d(cleanMsg)
                LogLevel.INFO -> AppLogger.i(cleanMsg)
            }
            // UI state and notifications are driven exclusively by the engine
            // state flow (observeEngineState) — no log-substring guessing.
        }
    }

    override fun protect(fd: Long): Boolean {
        val success = protect(fd.toInt())
        if (!success) {
            AppLogger.e("VPN: Failed to protect socket")
        }
        return success
    }

    // Reflection handle for ConnectivityManager.getConnectionOwnerUid. Hidden
    // (SystemApi) but callable from apps — NetGuard/PCAPdroid rely on it for
    // unrooted per-app attribution on Android 10+, where SELinux denies both
    // /proc/net and the app-side netlink sock_diag (verified on EMUI 10).
    private val connOwnerUidMethod: Method? by lazy {
        runCatching {
            val cm = applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.javaClass.methods.firstOrNull { m ->
                m.name == "getConnectionOwnerUid" &&
                    m.parameterTypes.size == 3 &&
                    m.parameterTypes[0] == Int::class.javaPrimitiveType &&
                    m.parameterTypes[1] == InetSocketAddress::class.java &&
                    m.parameterTypes[2] == InetSocketAddress::class.java
            }
        }.getOrNull()
    }

    @Volatile private var connOwnerUidBroken = false

    override fun lookupUID(srcIP: String, srcPort: Int, dstIP: String, dstPort: Int): Int =
        resolveUidOwner(srcIP, srcPort, dstIP, dstPort)

    /**
     * Resolves the uid owning a TCP socket via the hidden
     * ConnectivityManager.getConnectionOwnerUid. Only meaningful for sockets
     * in the ESTABLISHED state (netd's diag query misses SYN_SENT): called
     * once per :443 flow at relay time (wins the race on some flows) and
     * again at certificate-rejection time, when the socket was certainly
     * established.
     */
    private fun resolveUidOwner(srcIP: String, srcPort: Int, dstIP: String, dstPort: Int): Int {
        if (connOwnerUidBroken) return 0
        val method = connOwnerUidMethod ?: run {
            connOwnerUidBroken = true
            AppLogger.w("sockdiag fallback: getConnectionOwnerUid unavailable; app attribution stays anonymous")
            return 0
        }
        return try {
            val cm = applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val uid = method.invoke(
                cm,
                OsConstants.IPPROTO_TCP,
                InetSocketAddress(InetAddress.getByName(srcIP), srcPort),
                InetSocketAddress(InetAddress.getByName(dstIP), dstPort)
            ) as? Int ?: 0
            AppLogger.d("resolveUidOwner $srcIP:$srcPort -> $dstIP:$dstPort = $uid")
            if (uid > 0) uid else 0
        } catch (e: Exception) {
            AppLogger.d("resolveUidOwner failed: ${e.message}")
            0
        }
    }

    /**
     * Core reported a client that aborted the MITM handshake after our leaf
     * cert was delivered (pinning). Resolves the uid to a package and, when
     * the auto-blacklist is enabled, counts strikes: at [CERT_REJECT_THRESHOLD]
     * within [CERT_REJECT_WINDOW_MS] the package is persisted as auto-excluded
     * and the VPN restarts to apply the new capture set.
     */
    override fun onCertRejected(payload: String) {
        if (isDestroyed || payload.isEmpty()) return
        serviceScope.launch { handleCertRejected(payload) }
    }

    private suspend fun handleCertRejected(payload: String) {
        val json = runCatching { JSONObject(payload) }.getOrNull() ?: return
        var uid = json.optInt("uid", 0)
        val host = json.optString("host", "?")
        val src = json.optString("src", "")

        // The core only attributes at flow start (native netlink), where the
        // socket is SYN_SENT and EMUI's getConnectionOwnerUid can't see it
        // either. Resolve now instead: the just-rejected socket was
        // established, so the diag query can still find it.
        if (uid <= 0 && src.isNotEmpty()) {
            val srcIP: String?
            val srcPort: Int
            try {
                val colon = src.lastIndexOf(':')
                srcIP = src.substring(0, colon)
                srcPort = src.substring(colon + 1).toInt()
            } catch (_: Exception) {
                return
            }
            uid = resolveUidOwner(srcIP, srcPort, host, 443)
        }
        if (uid < 10_000) {
            AppLogger.d("cert-reject event unattributed: uid=$uid")
            return
        }

        val pkg = packageManager.getPackagesForUid(uid)?.firstOrNull() ?: return
        if (pkg == packageName || pkg == "android" || pkg.startsWith("com.android.")) return

        val enabled = repository.autoBlacklistEnabled.first()
        AppLogger.d("Cert reject: $pkg -> $host${if (enabled) "" else " (auto-blacklist off)"}")
        if (!enabled) return

        val now = System.currentTimeMillis()
        val strikes = certRejectStrikes.getOrPut(pkg) {
            Collections.synchronizedList(mutableListOf<Long>())
        }
        var triggered = false
        synchronized(strikes) {
            strikes.removeAll { it < now - CERT_REJECT_WINDOW_MS }
            strikes.add(now)
            if (strikes.size >= CERT_REJECT_THRESHOLD) {
                strikes.clear()
                triggered = true
            }
        }
        if (!triggered) return
        autoExcludePackage(pkg)
    }

    /** Persists the exclusion (idempotent) and restarts the VPN to apply it. */
    private suspend fun autoExcludePackage(pkg: String) {
        val current = repository.autoExcludedPackages.first()
        if (pkg in current) return
        repository.setAutoExcludedPackages(current + pkg)
        AppLogger.w("Auto-excluded $pkg: it kept rejecting the proxy certificate (pinning). VPN restarts to apply.")
        restartVpn()
    }

    /**
     * Restart the VPN so applyAppFiltering picks up the updated auto-exclusion
     * set. Reuses the supported stop→(deferred)start path: beginTeardown owns
     * the teardown, and a re-delivered START either defers (its tail restarts
     * the VPN) or starts fresh if the teardown somehow already finished. The
     * ~1-2s all-app network blip is the price of VpnService filtering being
     * establish-time-only.
     */
    private fun restartVpn() {
        AppLogger.i("VPN Service: restarting to apply auto-exclusion")
        certRejectStrikes.clear()
        stopVpn()
        try {
            startService(Intent(this, SnirectVpnService::class.java).setAction(ACTION_START))
        } catch (e: Exception) {
            // Background start restriction: fall back to the teardown's
            // deferred-start flag, which the teardown tail honors the same way.
            synchronized(lifecycleLock) { deferredStart = true }
        }
    }
}
