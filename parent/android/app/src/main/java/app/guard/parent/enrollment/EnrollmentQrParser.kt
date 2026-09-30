package app.guard.parent.enrollment

import app.guard.parent.protocol.*
import java.security.MessageDigest
import java.util.Base64

class EnrollmentRelayBinding(val canonicalRelayEndpoint: String) {
    init { EnrollmentWire.requireRelay(canonicalRelayEndpoint) }
}

/** Native-only QR possession. This is NOT a completed/attested parent enrollment. */
class EnrollmentTranscript internal constructor(val offer: EnrollmentOffer, secret: ByteArray) : AutoCloseable {
    private val setupSecret = secret.copyOf()
    private var closed = false
    @Synchronized fun proofFor(claim: EnrollmentKeyClaim): ByteArray {
        check(!closed) { "closed enrollment" }
        require(MessageDigest.isEqual(claim.offerHash(), EnrollmentWire.offerHash(offer))) { "different offer" }
        val proofKey = GuardWire.sha256(setupSecret)
        return try { EnrollmentWire.claimProof(proofKey, claim) } finally { proofKey.fill(0) }
    }
    @Synchronized fun relayCapability(): ByteArray {
        check(!closed) { "closed enrollment" }
        val proofKey = GuardWire.sha256(setupSecret)
        return try { EnrollmentWire.relayCapability(proofKey, offer) } finally { proofKey.fill(0) }
    }
    @Synchronized override fun close() { setupSecret.fill(0); closed = true }
    // No data-class toString/copy that could disclose the secret.
}

/** No web navigation, URI normalization, duplicate fields or legacy weak GREN v1 transcript. */
object EnrollmentQrParser {
    fun parse(text: String, binding: EnrollmentRelayBinding, nowUnixMillis: Long): EnrollmentTranscript {
        require(text.length <= 2200 && text.startsWith("guard-enroll://v2?offer=")) { "enrollment QR" }
        val parts = text.removePrefix("guard-enroll://v2?offer=").split("&secret=")
        require(parts.size == 2) { "fields" }
        fun decode(value: String, max: Int): ByteArray {
            require(value.isNotEmpty() && value.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' || it == '_' }) { "base64url" }
            return Base64.getUrlDecoder().decode(value).also {
                require(it.size <= max && Base64.getUrlEncoder().withoutPadding().encodeToString(it) == value) { "canonical base64url" }
            }
        }
        val offer = EnrollmentWire.decodeOffer(decode(parts[0], 1536))
        require(offer.relayEndpoint == binding.canonicalRelayEndpoint) { "unbound relay" }
        require(nowUnixMillis >= offer.createdUnixMillis && nowUnixMillis < offer.expiryUnixMillis) { "expired enrollment" }
        val secret = decode(parts[1], 32)
        try {
            require(secret.size == 32)
            val proofKey = GuardWire.sha256(secret)
            try { require(!MessageDigest.isEqual(secret, offer.challenge()) && !MessageDigest.isEqual(proofKey, offer.challenge())) { "public secret" } }
            finally { proofKey.fill(0) }
            return EnrollmentTranscript(offer, secret)
        }
        finally { secret.fill(0) }
    }
}
