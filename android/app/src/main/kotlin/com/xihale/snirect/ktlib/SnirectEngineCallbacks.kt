package com.xihale.snirect.ktlib

/**
 * Host callbacks for the Snirect engine.
 *
 * Implementations only need to override what they use: the three engine
 * lifecycle callbacks have no-op defaults, and their information is also
 * reflected in [SnirectClient.engineState] — most hosts should watch the
 * state flow instead of overriding them.
 *
 * All methods may be invoked from arbitrary Go runtime threads.
 */
interface SnirectEngineCallbacks {
    /** A log line from the engine. */
    fun onStatusChanged(status: String?)

    /**
     * Asks the host to route an outbound socket outside the VPN
     * (Android: `VpnService.protect(fd)`).
     */
    fun protect(fd: Long): Boolean

    /** Fired once when the whole engine is ready. Default: no-op. */
    fun onEngineStarted() {}

    /** Fired once on startup failure or terminal runtime engine death. Default: no-op. */
    fun onEngineError(reason: String) {}

    /** Fired once after an explicit stop of a running engine. Default: no-op. */
    fun onEngineStopped(reason: String) {}

    /**
     * An app aborted the MITM TLS handshake after our leaf certificate was
     * delivered — the signature of certificate pinning. [payload] is a JSON
     * object: `{"uid":10123,"src":"10.0.0.1:38428","host":"20.205.243.168","err":"EOF"}`
     * — uid is the flow attribution when the core's native netlink lookup
     * resolved it (0 otherwise), src is the flow's TUN-side source tuple and
     * host the (IP-literal) destination, letting the host resolve the uid
     * after the fact. May fire many times per session.
     * Default: no-op.
     */
    fun onCertRejected(payload: String) {}

    /**
     * Resolves the uid owning a TCP socket via
     * `ConnectivityManager.getConnectionOwnerUid` (a system_server binder call
     * that works even where the app's own netlink/proc access is
     * SELinux-denied). The core calls this for :443 flows whose native netlink
     * lookup came up empty; the socket may still be mid-handshake (SYN_SENT),
     * in which case 0 is expected and the core retries at certificate-
     * rejection time via the X-Snirect-Src tuple. Default: no-op (0).
     */
    fun lookupUID(srcIP: String, srcPort: Int, dstIP: String, dstPort: Int): Int = 0
}
