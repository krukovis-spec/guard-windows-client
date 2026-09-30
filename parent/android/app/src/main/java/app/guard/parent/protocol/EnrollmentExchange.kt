package app.guard.parent.protocol

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.security.SecureRandom

/** Evidence of the enrollment step only, never permission to enable protection or approve an action. */
class EnrollmentResult internal constructor(val outcome: Int, val stateVersion: Long, val issuedUnixMillis: Long,
    val expiryUnixMillis: Long, enc: ByteArray, cipher: ByteArray) {
    private val encapsulated = enc.copyOf(); private val encrypted = cipher.copyOf()
    fun encapsulatedKey() = encapsulated.copyOf()
    fun encryptedChallenge() = encrypted.copyOf()
}

/** GREX is separate from ordinary 64 KiB GRF1, to carry the bounded attestation chain. */
object EnrollmentExchange {
    const val MAX_BYTES = 70 * 1024
    const val NEEDS_PHONE_PROOF = 1
    const val NEEDS_LOCAL_CONFIRMATION = 2
    const val CONFIRMED = 3
    private const val HEADER_BYTES = 108
    private val info = "guard-enrollment-exchange-hpke-v1".toByteArray(Charsets.US_ASCII)
    private val signingDomain = "guard-enrollment-result-v1".toByteArray(Charsets.US_ASCII)

    fun newNonce(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    fun claim(offer: EnrollmentOffer, claim: EnrollmentKeyClaim, chain: List<ByteArray>, mac: ByteArray, signature: ByteArray, nonce: ByteArray): ByteArray {
        require(MessageDigest.isEqual(EnrollmentWire.offerHash(offer), claim.offerHash()))
        val body = encode("GREK") {
            bytes(EnrollmentWire.encodeClaimForSignature(claim)); require(chain.size in 2..8 && chain.sumOf { it.size.toLong() } <= 65536)
            writeInt(chain.size); chain.forEach { require(it.size in 1..16384); bytes(it) }
            fixed(mac, 32); fixed(signature, 64)
        }
        return try { seal(1, offer, claim, nonce, body) } finally { body.fill(0) }
    }
    fun keyProof(offer: EnrollmentOffer, claim: EnrollmentKeyClaim, proof: ByteArray, nonce: ByteArray): ByteArray {
        require(proof.size == 32)
        val copy = proof.copyOf()
        return try { seal(2, offer, claim, nonce, copy) } finally { copy.fill(0) }
    }
    fun query(offer: EnrollmentOffer, claim: EnrollmentKeyClaim, nonce: ByteArray): ByteArray = seal(3, offer, claim, nonce, byteArrayOf())

    fun receive(raw: ByteArray, offer: EnrollmentOffer, claim: EnrollmentKeyClaim, key: RelayEncryptionKey,
        expectedNonce: ByteArray, nowUnixMillis: Long): EnrollmentResult {
        require(raw.size <= 414 && expectedNonce.size == 32) // Reply has no certificate chain; at most 221 signed plaintext bytes.
        require(MessageDigest.isEqual(EnrollmentWire.offerHash(offer), claim.offerHash()) && key.publicKeySec1().contentEquals(claim.encryptionKey()))
        val r = Input(raw.copyOf(), "GREX")
        require(r.readInt() == 4) { "enrollment direction" }
        require(MessageDigest.isEqual(r.fixed(32), EnrollmentWire.offerHash(offer)) && MessageDigest.isEqual(r.fixed(32), EnrollmentWire.claimHash(claim))) { "enrollment binding" }
        require(MessageDigest.isEqual(r.fixed(32), expectedNonce)) { "different enrollment request" }
        val header = header(4, offer, claim, expectedNonce)
        val enc = r.fixed(65); val cipher = r.bytes(MAX_BYTES - HEADER_BYTES - 69); require(cipher.size >= 16); r.done()
        val plain = HpkeP256.decrypt(key, enc, cipher, header, info + header)
        try {
            require(plain.size >= 64)
            val unsigned = plain.copyOfRange(0, plain.size - 64)
            require(RelayReceive.P256DeviceSignatureVerifier.verify(offer.signingKey(), GuardWire.sha256(signingDomain + header + unsigned), plain.takeLast(64).toByteArray())) { "device enrollment signature" }
            val result = Input(unsigned, "GRES")
            val outcome = result.readInt().also { require(it in NEEDS_PHONE_PROOF..CONFIRMED) }
            val version = result.readLong().also { require(it > 0) }
            val issued = result.readLong(); val expires = result.readLong()
            require(issued >= offer.createdUnixMillis); GuardWire.requireLifetime(issued, expires, 60000)
            require(nowUnixMillis in issued until expires) { "stale enrollment result" }
            if (outcome != CONFIRMED) require(nowUnixMillis in offer.createdUnixMillis until offer.expiryUnixMillis && expires <= offer.expiryUnixMillis)
            val keyEnc = result.bytes(65, true); val keyCipher = result.bytes(48, true); result.done()
            require(keyEnc.size == (if (outcome == NEEDS_PHONE_PROOF) 65 else 0) && keyCipher.size == (if (outcome == NEEDS_PHONE_PROOF) 48 else 0))
            return EnrollmentResult(outcome, version, issued, expires, keyEnc, keyCipher)
        } finally { plain.fill(0) }
    }

    private fun header(kind: Int, offer: EnrollmentOffer, claim: EnrollmentKeyClaim, nonce: ByteArray) = encode("GREX") {
        writeInt(kind); fixed(EnrollmentWire.offerHash(offer), 32); fixed(EnrollmentWire.claimHash(claim), 32); fixed(nonce, 32)
    }
    private fun seal(kind: Int, offer: EnrollmentOffer, claim: EnrollmentKeyClaim, nonce: ByteArray, body: ByteArray): ByteArray {
        require(MessageDigest.isEqual(EnrollmentWire.offerHash(offer), claim.offerHash()))
        val header = header(kind, offer, claim, nonce)
        val (enc, cipher) = HpkeP256.encrypt(offer.encryptionKey(), body, header, info + header)
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { it.write(header); it.fixed(enc, 65); it.bytes(cipher) }
        return output.toByteArray().also { require(it.size <= MAX_BYTES) }
    }
    private fun encode(magic: String, write: DataOutputStream.() -> Unit): ByteArray = ByteArrayOutputStream().apply {
        DataOutputStream(this).use { it.write(magic.toByteArray(Charsets.US_ASCII)); it.writeInt(1); it.write() }
    }.toByteArray().also { require(it.size <= MAX_BYTES) }
    private fun DataOutputStream.fixed(value: ByteArray, size: Int) { require(value.size == size); write(value) }
    private fun DataOutputStream.bytes(value: ByteArray) { writeInt(value.size); write(value) }
    private class Input(raw: ByteArray, magic: String) : DataInputStream(ByteArrayInputStream(raw)) {
        init { require(raw.size <= MAX_BYTES && String(fixed(4), Charsets.US_ASCII) == magic && readInt() == 1) }
        fun fixed(n: Int): ByteArray { require(n >= 0 && n <= available()); return ByteArray(n).also(::readFully) }
        fun bytes(max: Int, empty: Boolean = false): ByteArray { val n = readInt(); require(n in (if (empty) 0 else 1)..max); return fixed(n) }
        fun done() { require(available() == 0) }
    }
}
