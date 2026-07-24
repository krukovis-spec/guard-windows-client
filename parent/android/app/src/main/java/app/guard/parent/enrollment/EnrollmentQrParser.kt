package app.guard.parent.enrollment

import java.util.Base64
import app.guard.parent.security.parseQuery
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest

data class EnrollmentTranscript(val relayEndpoint: String, val enrollmentId: String, val challenge: ByteArray, val transcriptHash: ByteArray)
data class EnrollmentRelayBinding(val canonicalRelayEndpoint: String) {
    init { require(canonicalRelayEndpoint.matches(Regex("^https://[a-z0-9.-]+(?:/[-a-z0-9._~]*)?$"))) }
}

/** Scanner adapters pass decoded text here. The QR payload is native-only and never interpreted by web UI. */
object EnrollmentQrParser {
    private val token = Regex("^[A-Za-z0-9._~-]{16,256}$")
    fun parse(text: String, binding: EnrollmentRelayBinding): EnrollmentTranscript {
        val uri = java.net.URI(text)
        require(uri.scheme == "guard-enroll" && uri.host == "v1") { "enrollment scheme" }
        val query = parseQuery(uri.rawQuery)
        require(query.keys == setOf("relay", "id", "challenge", "transcript") && query.values.all { it.size == 1 }) { "fields" }
        fun field(name: String) = query[name]!!.single()
        val endpoint = field("relay")
        require(endpoint == binding.canonicalRelayEndpoint) { "unbound relay" }
        val id = field("id"); require(token.matches(id))
        fun b64(name: String): ByteArray = Base64.getUrlDecoder().decode(field(name))
        val challenge = b64("challenge").also { require(it.size in 16..128) }
        val transcript = b64("transcript").also { require(it.size == 32) }
        require(MessageDigest.getInstance("SHA-256").digest(transcriptBytes(endpoint, id, challenge)).contentEquals(transcript)) { "transcript mismatch" }
        return EnrollmentTranscript(endpoint, id, challenge, transcript)
    }
    /** Exact enrollment transcript: `GREN`, version int32, relay text, enrollment id text, challenge bytes. */
    private fun transcriptBytes(endpoint: String, id: String, challenge: ByteArray): ByteArray = ByteArrayOutputStream().apply {
        write("GREN".toByteArray(Charsets.US_ASCII)); write(ByteBuffer.allocate(4).putInt(1).array())
        fun text(value: String) { val b = value.toByteArray(Charsets.UTF_8); write(ByteBuffer.allocate(4).putInt(b.size).array()); write(b) }
        text(endpoint); text(id); write(ByteBuffer.allocate(4).putInt(challenge.size).array()); write(challenge)
    }.toByteArray()
}
