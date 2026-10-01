package app.guard.parent.approval

import app.guard.parent.protocol.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import java.io.IOException
import java.net.CookieHandler
import java.net.Proxy
import java.net.URL
import java.time.Clock
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.HttpsURLConnection
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

internal data class NativeRequestPage(val requests: List<VerifiedNativeRequest>, val nextCursor: Long, val frameCount: Int,
    val receipts: List<VerifiedNativeReceipt>)

internal class VerifiedNativeReceipt private constructor(private val frame: ByteArray, private val canonical: ByteArray) {
    val receipt: CommandReceipt get() = GuardWire.decodeCommandReceipt(canonical)
    fun frameBytes() = frame.copyOf()
    companion object {
        fun verify(raw: ByteArray, recipient: RelayRecipient, trust: RelayDeviceTrust, now: Long): VerifiedNativeReceipt {
            val frozen = raw.copyOf()
            return VerifiedNativeReceipt(frozen, GuardWire.encodeCommandReceipt(RelayReceive.receiveReceipt(frozen, recipient, trust, now).receipt))
        }
    }
}

/** Retain the exact authenticated frame, not caller-mutable display data, for a later explicit decision. */
internal class VerifiedNativeRequest private constructor(private val frame: ByteArray, private val canonical: ByteArray) {
    val snapshot: RequestSnapshot get() = GuardWire.decodeRequestSnapshot(canonical)
    val expiryUnixMillis: Long get() = minOf(snapshot.pendingExpiryUnixMillis, RelayReceive.decodeFrame(frame).aad.expiryUnixMillis)
    fun reverify(recipient: RelayRecipient, trust: RelayDeviceTrust, now: Long) {
        require(GuardWire.encodeRequestSnapshot(RelayReceive.receiveRequest(frame, recipient, trust, now).snapshot)
            .contentEquals(canonical)) { "request changed" }
    }
    companion object {
        fun verify(raw: ByteArray, recipient: RelayRecipient, trust: RelayDeviceTrust, now: Long): VerifiedNativeRequest {
            val frozen = raw.copyOf()
            val snapshot = RelayReceive.receiveRequest(frozen, recipient, trust, now).snapshot
            return VerifiedNativeRequest(frozen, GuardWire.encodeRequestSnapshot(snapshot))
        }
    }
}

/** Keep signed evidence unchanged internally; make invisible direction/control characters visible in display-only text. */
internal fun requestDisplayText(value: String): String = buildString {
    var offset = 0
    while (offset < value.length) {
        val code = value.codePointAt(offset); offset += Character.charCount(code)
        if (Character.isISOControl(code) || Character.getType(code) in listOf(Character.FORMAT.toInt(),
                Character.LINE_SEPARATOR.toInt(), Character.PARAGRAPH_SEPARATOR.toInt()))
            append("\\u{" + code.toString(16).uppercase() + "}")
        else appendCodePoint(code)
    }
}

/** Read-only session from existing confirmed enrollment. Never signs, acknowledges, retires or persists relay frames. */
internal class NativeRequestInbox(
    offer: EnrollmentOffer, claim: EnrollmentKeyClaim, key: RelayEncryptionKey,
    private val profile: NativeRelayProfile, private val beforeUse: () -> Unit,
    private val clock: Clock = Clock.systemUTC(),
    private val connect: (URL) -> HttpsURLConnection = { it.openConnection(Proxy.NO_PROXY) as HttpsURLConnection }
) : AutoCloseable {
    private val recipient = RelayRecipient(offer.mailboxId, claim.encryptionKeyId, offer.authorityEpoch, key)
    private val trust = RelayDeviceTrust(offer.deviceId, offer.deviceEpoch, offer.authorityEpoch, offer.signingKeyId, offer.signingKey())
    private val base: String
    private val started = AtomicBoolean(false)
    private var observed = profile.preparedUnixMillis
    init {
        require(EnrollmentWire.offerHash(offer).contentEquals(claim.offerHash()) && key.publicKeySec1().contentEquals(claim.encryptionKey()))
        EnrollmentWire.encodeClaimForSignature(claim)
        base = offer.relayEndpoint + "/v1/mailboxes/" + recipient.mailboxId + "/poll?recipient=" + recipient.keyId
    }

    private fun requireCurrent(): Long {
        val now = clock.millis()
        require(now >= observed) { "inbox clock rollback" }; profile.requireCurrent(now); observed = now
        return now
    }

    suspend fun read(after: Long = 0): NativeRequestPage = readPage(after, false)
    // Receipt lookup must not be blocked by an already expired request inside a still-live transport frame.
    suspend fun readReceipts(after: Long = 0): NativeRequestPage = readPage(after, true)

    private suspend fun readPage(after: Long, receiptsOnly: Boolean): NativeRequestPage = withTimeout(20_000) {
        require(after in 0..NativeInboxPageCodec.MAX_CURSOR)
        check(started.compareAndSet(false, true)) { "one inbox read per session" }
        suspendCancellableCoroutine { continuation ->
            val active = AtomicReference<HttpsURLConnection?>()
            continuation.invokeOnCancellation { active.getAndSet(null)?.disconnect() }
            Dispatchers.IO.dispatch(continuation.context, Runnable {
                try {
                    fun checkActive() { check(continuation.isActive) { "inbox cancelled" } }
                    checkActive(); beforeUse(); requireCurrent(); checkActive()
                    check(CookieHandler.getDefault() == null) { "ambient cookies unsupported" }
                    val connection = connect(URL(base + "&after=" + after + "&limit=" + NativeInboxPageCodec.PAGE_SIZE))
                    active.set(connection)
                    val page = try {
                        checkActive(); beforeUse(); requireCurrent(); checkActive()
                        connection.instanceFollowRedirects = false; connection.useCaches = false
                        connection.connectTimeout = 5000; connection.readTimeout = 20000
                        connection.requestMethod = "GET"
                        connection.setRequestProperty("Authorization", "Bearer " + profile.accessToken())
                        connection.setRequestProperty("Accept", "application/json")
                        connection.setRequestProperty("Accept-Encoding", "identity")
                        requireCurrent(); checkActive()
                        require(connection.responseCode == 200) { "inbox status" }
                        require(connection.contentType in listOf("application/json", "application/json; charset=utf-8") &&
                            connection.contentLengthLong <= NativeInboxPageCodec.MAX_BYTES &&
                            connection.getHeaderField("Content-Encoding")?.let { it != "identity" } != true) { "inbox headers" }
                        val raw = connection.inputStream.use { input ->
                            val buffer = ByteArray(NativeInboxPageCodec.MAX_BYTES + 1); var count = 0
                            while (count < buffer.size) {
                                checkActive()
                                val size = input.read(buffer, count, buffer.size - count)
                                if (size < 0) break
                                require(size > 0); count += size
                            }
                            require(count <= NativeInboxPageCodec.MAX_BYTES) { "inbox response size" }
                            buffer.copyOf(count)
                        }
                        checkActive()
                        val decoded = NativeInboxPageCodec.decode(raw, recipient, after)
                        val receipts = ArrayList<VerifiedNativeReceipt>()
                        val requests = decoded.first.mapNotNull { bytes ->
                            checkActive(); val now = requireCurrent()
                            if (RelayReceive.decodeFrame(bytes).aad.kind == 1)
                                if (receiptsOnly) null else VerifiedNativeRequest.verify(bytes, recipient, trust, now)
                            else {
                                receipts += VerifiedNativeReceipt.verify(bytes, recipient, trust, now); null
                            }
                        }
                        checkActive(); beforeUse(); val now = requireCurrent(); checkActive()
                        require(requests.all { val snapshot = it.snapshot; now in snapshot.createdUnixMillis until snapshot.pendingExpiryUnixMillis }) { "request expired during verification" }
                        require(decoded.first.all { val aad = RelayReceive.decodeFrame(it).aad
                            receiptsOnly && aad.kind == 1 || now in aad.createdUnixMillis until aad.expiryUnixMillis }) { "frame expired during verification" }
                        checkActive()
                        NativeRequestPage(requests, decoded.second, decoded.first.size, receipts)
                    } finally { active.compareAndSet(connection, null); connection.disconnect() }
                    continuation.resume(page)
                } catch (_: Exception) {
                    // Do not expose URLs, credentials, provider diagnostics or decrypted request bodies in errors.
                    continuation.resumeWithException(IOException("verified inbox unavailable"))
                }
            })
        }
    }

    override fun close() { profile.close() }
}

/** Strict small JSON grammar for the Worker's poll response, not a general JSON parser or authority/replay floor. */
internal object NativeInboxPageCodec {
    const val PAGE_SIZE = 16
    const val MAX_CURSOR = 9_007_199_254_740_991L
    const val MAX_FRAME_TEXT = ((65536 + 2) / 3) * 4
    const val MAX_BYTES = PAGE_SIZE * (MAX_FRAME_TEXT + 4) + 128
    private val space = "[ \\t\\r\\n]*"
    // Worker emits canonical unescaped base64/field names. Accept field reordering and JSON whitespace, not aliases/duplicates.
    private val framesFirst = Regex("\\{$space\"frames\"$space:$space\\[([^\\[\\]]*)]$space,$space\"nextCursor\"$space:$space(0|[1-9][0-9]{0,15})$space}")
    private val cursorFirst = Regex("\\{$space\"nextCursor\"$space:$space(0|[1-9][0-9]{0,15})$space,$space\"frames\"$space:$space\\[([^\\[\\]]*)]$space}")
    private fun String.jsonTrim() = trim(' ', '\t', '\r', '\n')

    fun decode(raw: ByteArray, recipient: RelayRecipient, after: Long): Pair<List<ByteArray>, Long> {
        require(after in 0..MAX_CURSOR && raw.size <= MAX_BYTES && raw.all { it.toInt() in 0..127 }) { "inbox JSON encoding/size" }
        val json = raw.toString(Charsets.US_ASCII).jsonTrim()
        val forward = framesFirst.matchEntire(json)
        val reverse = if (forward == null) cursorFirst.matchEntire(json) else null
        require(forward != null || reverse != null) { "inbox JSON schema" }
        val list = (forward?.groupValues?.get(1) ?: reverse!!.groupValues[2]).jsonTrim()
        val hint = (forward?.groupValues?.get(2) ?: reverse!!.groupValues[1]).toLong()
        require(hint in 0..MAX_CURSOR)
        val elements = if (list.isEmpty()) emptyList() else list.split(',', limit = PAGE_SIZE + 1)
        require(elements.size <= PAGE_SIZE) { "inbox page limit" }
        var cursor = after
        val frames = elements.map { element ->
            val quoted = element.jsonTrim()
            require(quoted.length in 3..MAX_FRAME_TEXT + 2 && quoted.first() == '"' && quoted.last() == '"') { "inbox base64" }
            val text = quoted.substring(1, quoted.lastIndex)
            val bytes = Base64.getDecoder().decode(text)
            require(Base64.getEncoder().encodeToString(bytes) == text) { "noncanonical inbox base64" }
            val aad = RelayReceive.decodeFrame(bytes).aad
            require(aad.kind in listOf(1, 3) && aad.mailboxId == recipient.mailboxId && aad.recipientKeyId == recipient.keyId &&
                aad.cursor in (cursor + 1)..MAX_CURSOR && aad.ack <= MAX_CURSOR) { "inbox frame binding/order" }
            cursor = aad.cursor; bytes
        }
        require(hint == cursor) { "inbox cursor hint" }
        return frames to cursor
    }
}
