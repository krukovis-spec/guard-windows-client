package app.guard.parent.enrollment

import app.guard.parent.protocol.EnrollmentExchange
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import java.io.IOException
import java.net.Proxy
import java.net.URL
import java.net.CookieHandler
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.HttpsURLConnection
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Ordinary platform TLS, fixed offer-pinned destination, no redirects/cookies/proxy or error-body logging. */
internal class EnrollmentHttpTransport(private val connect: (URL) -> HttpsURLConnection = {
    it.openConnection(Proxy.NO_PROXY) as HttpsURLConnection
}) {
    suspend fun exchange(state: PendingEnrollment, beforeIo: () -> Unit): ByteArray? = withTimeout(20000) {
        val request = state.request()
        val nonce = EnrollmentExchange.requestMetadata(request, state.offer, requireNotNull(state.claim)).second
        val capability = state.capability(); require(capability.size == 32)
        val token = capability.hex(); capability.fill(0)
        val base = state.offer.relayEndpoint + "/v1/mailboxes/" + state.offer.mailboxId + "/enrollments/" + offerId(state.offer)
        suspendCancellableCoroutine { continuation ->
                val active = AtomicReference<HttpsURLConnection?>()
                continuation.invokeOnCancellation { active.getAndSet(null)?.disconnect() }
                Dispatchers.IO.dispatch(continuation.context, Runnable {
                    fun call(suffix: String, body: ByteArray?): ByteArray? {
                        if (!continuation.isActive) throw IOException("enrollment request cancelled")
                        beforeIo()
                        check(CookieHandler.getDefault() == null) { "ambient cookies unsupported" }
                        val connection = connect(URL(base + suffix))
                        active.set(connection)
                        try {
                            if (!continuation.isActive) throw IOException("enrollment request cancelled")
                            connection.instanceFollowRedirects = false
                            connection.useCaches = false
                            connection.connectTimeout = 20000; connection.readTimeout = 20000
                            connection.requestMethod = if (body == null) "GET" else "POST"
                            connection.setRequestProperty("Authorization", "Bearer " + token)
                            connection.setRequestProperty("Accept", "application/octet-stream")
                            connection.setRequestProperty("Accept-Encoding", "identity")
                            if (body != null) {
                                connection.doOutput = true
                                connection.setRequestProperty("Content-Type", "application/octet-stream")
                                connection.setFixedLengthStreamingMode(body.size)
                                connection.outputStream.use { it.write(body) }
                            }
                            val status = connection.responseCode
                            if (body != null) {
                                if (status != 200 && status != 201) throw IOException("enrollment relay status $status")
                                return null // Delivery acknowledgment is never an ownership acknowledgment.
                            }
                            if (status == 204) return null
                            if (status != 200) throw IOException("enrollment relay status $status")
                            if (connection.contentType != "application/octet-stream" || connection.contentLengthLong > 414 ||
                                connection.getHeaderField("Content-Encoding")?.let { it != "identity" } == true)
                                throw IOException("invalid enrollment response")
                            return connection.inputStream.use { input ->
                                val buffer = ByteArray(415); var count = 0
                                while (count < buffer.size) {
                                    if (!continuation.isActive) throw IOException("enrollment request cancelled")
                                    val n = input.read(buffer, count, buffer.size - count); if (n < 0) break; count += n
                                }
                                if (count !in 193..414) throw IOException("invalid enrollment response size")
                                buffer.copyOf(count)
                            }
                        } finally { active.compareAndSet(connection, null); connection.disconnect() }
                    }
                    try {
                        call("/requests", request)
                        val response = call("/replies/" + nonce.hex(), null)
                        continuation.resume(response)
                    } catch (_: Exception) {
                        // Never propagate URL/headers/body/provider exceptions that could include capabilities.
                        continuation.resumeWithException(IOException("enrollment exchange unavailable"))
                    }
                })
        }
    }
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
}
