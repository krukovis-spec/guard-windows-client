package app.guard.parent.approval

import app.guard.parent.protocol.*
import app.guard.parent.security.FileApprovalOutbox
import app.guard.parent.security.PendingSignedEnvelope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import java.io.IOException
import java.net.CookieHandler
import java.net.Proxy
import java.net.URL
import java.time.Clock
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.HttpsURLConnection
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** One foreground pass: save reservation input, save ciphertext, publish exact bytes. Never signs or completes an approval. */
internal class NativeApprovalDelivery(
    private val offer: EnrollmentOffer, private val claim: EnrollmentKeyClaim,
    private val pending: PendingSignedEnvelope, private val outbox: FileApprovalOutbox,
    private val profile: NativeRelayProfile, private val beforeUse: () -> Unit,
    private val clock: Clock = Clock.systemUTC(),
    private val connect: (URL) -> HttpsURLConnection = { it.openConnection(Proxy.NO_PROXY) as HttpsURLConnection }
) : AutoCloseable {
    private val started = AtomicBoolean(false)
    private var observed = profile.preparedUnixMillis

    suspend fun publish(): Unit = withTimeout(20_000) {
        check(started.compareAndSet(false, true)) { "one delivery pass per session" }
        suspendCancellableCoroutine { continuation ->
            val active = AtomicReference<HttpsURLConnection?>()
            continuation.invokeOnCancellation { active.getAndSet(null)?.disconnect() }
            Dispatchers.IO.dispatch(continuation.context, Runnable {
                try {
                    var attempt = outbox.delivery(pending)
                    fun checkActive() { check(continuation.isActive) { "delivery cancelled" } }
                    fun guard(allowExpiredAttempt: Boolean = false): Long {
                        checkActive(); beforeUse(); checkActive()
                        val now = clock.millis()
                        require(now >= maxOf(observed, attempt?.observed ?: 0)) { "delivery clock rollback" }
                        profile.requireCurrent(now); observed = now
                        attempt?.let { require(allowExpiredAttempt || now < it.expiry); it.requireBinding(pending, offer, claim) }
                        require(outbox.delivery(pending)?.encode().let { current ->
                            if (attempt == null) current == null else current?.contentEquals(attempt!!.encode()) == true
                        }) { "delivery changed" }
                        val afterValidation = clock.millis()
                        require(afterValidation >= observed && (allowExpiredAttempt || attempt == null || afterValidation < attempt!!.expiry))
                        profile.requireCurrent(afterValidation); observed = afterValidation
                        checkActive(); return afterValidation
                    }
                    fun save(next: NativeApprovalAttempt, allowExpiredAttempt: Boolean = false) {
                        outbox.saveDelivery(pending, attempt, next) {
                            val commitTime = guard(allowExpiredAttempt)
                            require(commitTime >= next.observed && commitTime < next.expiry)
                        }
                        attempt = next
                    }
                    fun call(reserve: Boolean): Pair<Int, ByteArray> {
                        guard()
                        val saved = requireNotNull(attempt)
                        val body = if (reserve) saved.reservationBody(offer) else saved.frameBytes().also { require(it.isNotEmpty()) }
                        check(CookieHandler.getDefault() == null) { "ambient cookies unsupported" }
                        val connection = connect(URL(offer.relayEndpoint + "/v1/mailboxes/" + offer.mailboxId +
                            if (reserve) "/frames/reserve" else "/frames"))
                        active.set(connection)
                        try {
                            guard()
                            connection.instanceFollowRedirects = false; connection.useCaches = false
                            connection.connectTimeout = 5000; connection.readTimeout = 20000
                            connection.requestMethod = "POST"; connection.doOutput = true
                            connection.setRequestProperty("Authorization", "Bearer " + profile.accessToken())
                            connection.setRequestProperty("Accept", "application/json")
                            connection.setRequestProperty("Accept-Encoding", "identity")
                            connection.setRequestProperty("Content-Type", if (reserve) "application/json" else "application/octet-stream")
                            connection.setFixedLengthStreamingMode(body.size)
                            guard() // After slow key/storage checks, immediately before dispatch.
                            connection.outputStream.use { output -> checkActive(); output.write(body) }
                            val status = connection.responseCode
                            require(status in listOf(200, 201, 400, 409, 410)) { "delivery status" }
                            require(connection.contentType in listOf("application/json", "application/json; charset=utf-8") &&
                                connection.contentLengthLong <= 1024 &&
                                connection.getHeaderField("Content-Encoding")?.let { it != "identity" } != true) { "delivery headers" }
                            val raw = requireNotNull(if (status < 400) connection.inputStream else connection.errorStream).use { input ->
                                val buffer = ByteArray(1025); var count = 0
                                while (count < buffer.size) {
                                    checkActive()
                                    val size = input.read(buffer, count, buffer.size - count)
                                    if (size < 0) break
                                    require(size > 0); count += size
                                }
                                require(count <= 1024); buffer.copyOf(count)
                            }
                            guard(); return status to raw
                        } finally { active.compareAndSet(connection, null); connection.disconnect() }
                    }
                    val now = guard(allowExpiredAttempt = true)
                    // Once the outer frame expires it cannot be accepted, even if an earlier POST succeeded.
                    // Keep the exact signed command: Windows alone decides Expired or returns its signed history.
                    var replaced = attempt?.let { now >= it.expiry } == true
                    if (attempt == null || replaced)
                        save(NativeApprovalAttempt.prepare(pending, offer, claim, now, profile.expiryUnixMillis), replaced)
                    // At most one outer replacement per user action. Ambiguous live attempts retain exact bytes.
                    while (true) {
                        val saved = requireNotNull(attempt)
                        val reserve = saved.frameBytes().isEmpty()
                        val (status, raw) = call(reserve)
                        val expiredLease = (reserve && status == 410 && raw.contentEquals("{\"error\":\"frame_reservation_expired\"}".toByteArray())) ||
                            (reserve && status == 400 && raw.contentEquals("{\"error\":\"frame_reservation_clock\"}".toByteArray())) ||
                            (!reserve && status == 409 && raw.contentEquals("{\"error\":\"frame_reservation_required\"}".toByteArray()))
                        if (expiredLease && !saved.published && !replaced) {
                            val current = guard()
                            save(NativeApprovalAttempt.prepare(pending, offer, claim, current, profile.expiryUnixMillis))
                            replaced = true; continue
                        }
                        if (reserve) save(saved.seal(pending, offer, claim, raw, status, guard()))
                        else {
                            save(saved.markPublished(raw, status, guard()))
                            break // Server storage only. A matching device-signed receipt is still required.
                        }
                    }
                    checkActive(); continuation.resume(Unit)
                } catch (_: Exception) {
                    // No credentials, URLs, ciphertext, signed decisions or provider diagnostics in errors.
                    continuation.resumeWithException(IOException("approval delivery unavailable"))
                }
            })
        }
    }

    override fun close() { profile.close() }
}
