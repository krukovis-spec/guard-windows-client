package app.guard.parent.protocol

import java.nio.ByteBuffer
import java.security.MessageDigest

/** Transport only, never ownership/approval authority. Existing confirmed enrollment supplies all trust. */
class NativeRelayProfile private constructor(val preparedUnixMillis: Long, val expiryUnixMillis: Long, credential: ByteArray) : AutoCloseable {
    private val token = credential.copyOf()
    private var closed = false
    @Synchronized internal fun accessToken(): String { check(!closed); return token.toString(Charsets.US_ASCII) }
    @Synchronized internal fun sameAs(other: NativeRelayProfile): Boolean = !closed && !other.closed &&
        preparedUnixMillis == other.preparedUnixMillis && expiryUnixMillis == other.expiryUnixMillis && MessageDigest.isEqual(token, other.token)
    @Synchronized fun requireCurrent(now: Long) { check(!closed); require(now in preparedUnixMillis until expiryUnixMillis) { "native transport expiry/clock" } }
    @Synchronized override fun close() { token.fill(0); closed = true }

    companion object {
        const val FILE_BYTES = 233
        private val info = "Guard.v2.native-relay.install.hpke.v1".toByteArray(Charsets.US_ASCII)
        fun open(envelope: ByteArray, offer: EnrollmentOffer, claim: EnrollmentKeyClaim, key: RelayEncryptionKey,
            independentlyTrustedSha256: String, now: Long): NativeRelayProfile {
            require(envelope.size == FILE_BYTES) { "native profile size" }
            val raw = envelope.copyOf()
            require(independentlyTrustedSha256.matches(Regex("[0-9A-Fa-f]{64}"))) { "independent profile commitment required" }
            val expected = independentlyTrustedSha256.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            require(MessageDigest.isEqual(GuardWire.sha256(raw), expected)) { "native profile commitment" }
            val offerHash = EnrollmentWire.offerHash(offer); val claimHash = EnrollmentWire.claimHash(claim)
            require(offer.deviceEpoch == 1L && offer.authorityEpoch == 1L && offerHash.contentEquals(claim.offerHash()) &&
                key.publicKeySec1().contentEquals(claim.encryptionKey())) { "native profile enrollment" }
            val header = "GNI1".toByteArray(Charsets.US_ASCII) + offerHash + claimHash
            require(raw.copyOfRange(0, 68).contentEquals(header)) { "native profile recipient" }
            val plain = HpkeP256.decrypt(key, raw.copyOfRange(68, 133), raw.copyOfRange(133, FILE_BYTES), header, info + header)
            try {
                require(plain.size == 84 && plain.copyOfRange(0, 4).contentEquals("GNP1".toByteArray(Charsets.US_ASCII))) { "native profile version" }
                val prepared = ByteBuffer.wrap(plain, 4, 8).long; val expiry = ByteBuffer.wrap(plain, 12, 8).long
                require(prepared >= offer.createdUnixMillis && prepared < Math.addExact(offer.expiryUnixMillis, 86_400_000L) &&
                    expiry > prepared && expiry <= 253402300799999L) { "native profile lifetime" }
                val credential = plain.copyOfRange(20, 84)
                try {
                    require(credential.all { it.toInt() in 48..57 || it.toInt() in 65..70 }) { "native profile credential" }
                    require(now in prepared until expiry) { "native profile expiry/clock" }
                    return NativeRelayProfile(prepared, expiry, credential)
                } finally { credential.fill(0) }
            } finally { plain.fill(0) }
        }
    }
}
