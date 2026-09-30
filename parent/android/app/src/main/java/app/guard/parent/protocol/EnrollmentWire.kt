package app.guard.parent.protocol

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class EnrollmentOffer(
    val relayEndpoint: String, val enrollmentId: String, val deviceId: String, val deviceLabel: String,
    val deviceEpoch: Long, val authorityEpoch: Long, val mailboxId: String, val signingKeyId: String,
    signingKey: ByteArray, val encryptionKeyId: String, encryptionKey: ByteArray,
    val createdUnixMillis: Long, val expiryUnixMillis: Long, challenge: ByteArray
) {
    private val signing = signingKey.copyOf(); private val encryption = encryptionKey.copyOf(); private val nonce = challenge.copyOf()
    fun signingKey() = signing.copyOf()
    fun encryptionKey() = encryption.copyOf()
    fun challenge() = nonce.copyOf()
}

/** Signature input only, never a verified identity or authority to enroll. */
class EnrollmentKeyClaim(offerHash: ByteArray, val approvalKeyId: String, approvalKeySpki: ByteArray,
    val encryptionKeyId: String, encryptionKey: ByteArray) {
    private val hash = offerHash.copyOf(); private val approval = approvalKeySpki.copyOf(); private val encryption = encryptionKey.copyOf()
    fun offerHash() = hash.copyOf()
    fun approvalKey() = approval.copyOf()
    fun encryptionKey() = encryption.copyOf()
}

object EnrollmentWire {
    private val spkiPrefix = byteArrayOf(0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(), 0x48,
        0xce.toByte(), 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00)

    fun encodeOffer(offer: EnrollmentOffer): ByteArray = Writer("GREO").apply {
        requireRelay(offer.relayEndpoint)
        GuardWire.requireLifetime(offer.createdUnixMillis, offer.expiryUnixMillis, 10 * 60 * 1000L)
        require(offer.createdUnixMillis >= 0)
        val signing = offer.signingKey(); val encryption = offer.encryptionKey()
        pointEncoding(signing); pointEncoding(encryption)
        require(offer.signingKeyId != offer.encryptionKeyId && !signing.contentEquals(encryption)) { "separate device keys" }
        text(offer.relayEndpoint, 256, false); id(offer.enrollmentId); id(offer.deviceId); text(offer.deviceLabel, 96, false)
        positive(offer.deviceEpoch); positive(offer.authorityEpoch); id(offer.mailboxId); id(offer.signingKeyId)
        fixed(signing, 65); id(offer.encryptionKeyId); fixed(encryption, 65)
        i64(offer.createdUnixMillis); i64(offer.expiryUnixMillis); fixed(offer.challenge(), 32)
    }.finish().also { require(it.size <= 1536) { "offer size" } }

    fun decodeOffer(encoded: ByteArray): EnrollmentOffer {
        require(encoded.size <= 1536)
        return Reader(encoded, "GREO").run {
            val offer = EnrollmentOffer(text(256, false), id(), id(), text(96, false), positive(), positive(), id(),
                id(), fixed(65), id(), fixed(65), nonNegative(), nonNegative(), fixed(32))
            done(); encodeOffer(offer); offer
        }
    }
    fun offerHash(offer: EnrollmentOffer) = GuardWire.sha256(encodeOffer(offer))

    fun encodeClaimForSignature(claim: EnrollmentKeyClaim): ByteArray = Writer("GREC").apply {
        val approval = claim.approvalKey(); val encryption = claim.encryptionKey()
        require(approval.size == 91 && approval.copyOfRange(0, 26).contentEquals(spkiPrefix)) { "P-256 SPKI" }
        val approvalPoint = approval.copyOfRange(26, 91)
        pointEncoding(approvalPoint); pointEncoding(encryption)
        require(claim.approvalKeyId != claim.encryptionKeyId && !approvalPoint.contentEquals(encryption)) { "separate parent keys" }
        fixed(claim.offerHash(), 32); id(claim.approvalKeyId); fixed(approval, 91); id(claim.encryptionKeyId); fixed(encryption, 65)
    }.finish()

    fun decodeClaimForSignature(encoded: ByteArray): EnrollmentKeyClaim {
        require(encoded.size <= 460)
        return Reader(encoded, "GREC").run {
            val claim = EnrollmentKeyClaim(fixed(32), id(), fixed(91), id(), fixed(65))
            done(); encodeClaimForSignature(claim); claim
        }
    }
    fun claimHash(claim: EnrollmentKeyClaim) = GuardWire.sha256(encodeClaimForSignature(claim))

    // QR proofKey = SHA256(secret), never sent in offer/attestation/relay. A MAC is NOT parent authentication.
    fun claimProof(proofKey: ByteArray, claim: EnrollmentKeyClaim): ByteArray {
        require(proofKey.size == 32)
        return Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(proofKey, "HmacSHA256")) }
            .doFinal("guard-enrollment-possession-v1".toByteArray(Charsets.US_ASCII) + claimHash(claim))
    }

    /** Key possession only: this response never authorizes ownership or any app/site permission. */
    fun answerKeyConfirmation(claim: EnrollmentKeyClaim, key: RelayEncryptionKey, encapsulatedKey: ByteArray, ciphertext: ByteArray): ByteArray {
        require(key.publicKeySec1().contentEquals(claim.encryptionKey())) { "different enrollment key" }
        require(encapsulatedKey.size == 65 && ciphertext.size == 48) { "key challenge size" }
        val hash = claimHash(claim)
        val witness = HpkeP256.decrypt(key, encapsulatedKey.copyOf(), ciphertext.copyOf(), hash,
            "guard-enrollment-decryption-hpke-v1".toByteArray(Charsets.US_ASCII) + hash)
        try {
            require(witness.size == 32)
            return Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(witness, "HmacSHA256")) }
                .doFinal("guard-enrollment-decryption-proof-v1".toByteArray(Charsets.US_ASCII) + hash)
        } finally { witness.fill(0) }
    }

    fun requireRelay(endpoint: String) {
        require(endpoint.length <= 256 && endpoint.matches(Regex(
            "https://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?(?:/[a-z0-9_-]+)*"))) { "canonical HTTPS relay" }
    }
    // Shape only: real native point import/attestation is mandatory before accepting any key.
    private fun pointEncoding(key: ByteArray) { require(key.size == 65 && key[0].toInt() == 4) { "P-256 point encoding" } }
}
