package app.guard.parent

import app.guard.parent.protocol.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.File
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.util.Properties

/** Public synthetic .NET ceremony; real JCA/HPKE/signatures, not physical Android attestation. */
class EnrollmentExchangeTest {
    private val values = Properties().apply {
        requireNotNull(EnrollmentExchangeTest::class.java.getResourceAsStream("/enrollment-exchange-v1.properties")).use { load(it) }
    }
    private fun bytes(name: String) = values.getProperty(name).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val offer = EnrollmentWire.decodeOffer(bytes("offer"))
    private val claim = EnrollmentWire.decodeClaimForSignature(bytes("claim"))
    private val nonce = bytes("nonce")
    private val now = values.getProperty("now").toLong()
    private fun key(private: ByteArray, public: ByteArray) = object : RelayEncryptionKey {
        override fun publicKeySec1() = public.copyOf()
        override fun privateKey(): java.security.PrivateKey {
            val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
            return KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, private), parameters))
        }
    }
    private val phone = key(bytes("phone.private"), claim.encryptionKey())
    private val device = key(bytes("device.private"), offer.encryptionKey())
    private val hpkeInfo = "guard-enrollment-exchange-hpke-v1".toByteArray(Charsets.US_ASCII)
    private fun open(raw: ByteArray, key: RelayEncryptionKey): ByteArray {
        val header = raw.copyOfRange(0, 108)
        return HpkeP256.decrypt(key, raw.copyOfRange(108, 173), raw.copyOfRange(177, raw.size), header, hpkeInfo + header)
    }
    private fun reseal(header: ByteArray, plain: ByteArray): ByteArray {
        val (enc, cipher) = HpkeP256.encrypt(phone.publicKeySec1(), plain, header, hpkeInfo + header)
        return header + enc + ByteBuffer.allocate(4).putInt(cipher.size).array() + cipher
    }

    @Test fun `actual dotnet staged and committed results verify with different meanings`() {
        val pending = EnrollmentExchange.receive(bytes("reply.pending"), offer, claim, phone, nonce, now)
        assertEquals(EnrollmentExchange.NEEDS_PHONE_PROOF, pending.outcome)
        assertEquals(65, pending.encapsulatedKey().size); assertEquals(48, pending.encryptedChallenge().size)
        assertEquals(32, EnrollmentWire.answerKeyConfirmation(claim, phone, pending.encapsulatedKey(), pending.encryptedChallenge()).size)
        val complete = EnrollmentExchange.receive(bytes("reply.confirmed"), offer, claim, phone, nonce, now)
        assertEquals(EnrollmentExchange.CONFIRMED, complete.outcome)
        assertTrue(complete.stateVersion > pending.stateVersion)
        assertTrue(complete.encapsulatedKey().isEmpty() && complete.encryptedChallenge().isEmpty())
    }

    @Test fun `Kotlin encrypts complete claim proof and query for independent dotnet verification`() {
        val submissions = listOf(
            EnrollmentExchange.claim(offer, claim, listOf(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 3)), bytes("mac"), bytes("signature"), nonce),
            EnrollmentExchange.keyProof(offer, claim, ByteArray(32) { 7 }, nonce),
            EnrollmentExchange.query(offer, claim, nonce))
        assertTrue(open(submissions[0], device).copyOfRange(0, 4).contentEquals("GREK".toByteArray()))
        assertArrayEquals(ByteArray(32) { 7 }, open(submissions[1], device))
        assertTrue(open(submissions[2], device).isEmpty())
        val output = File("build/test-interop/android-enrollment-exchange.txt")
        requireNotNull(output.parentFile).mkdirs()
        output.writeText(submissions.joinToString("\n") { bytes -> bytes.joinToString("") { "%02x".format(it) } })
        val large = EnrollmentExchange.claim(offer, claim, List(4) { ByteArray(16384) }, bytes("mac"), bytes("signature"), nonce)
        assertTrue(large.size in 65537..EnrollmentExchange.MAX_BYTES)
        assertTrue(open(large, device).size > 65536)
        assertThrows(IllegalArgumentException::class.java) {
            EnrollmentExchange.claim(offer, claim, List(5) { ByteArray(16384) }, bytes("mac"), bytes("signature"), nonce)
        }
    }

    @Test fun `reply rejects every changed byte truncation stale time and wrong correlation`() {
        val raw = bytes("reply.confirmed")
        for (i in raw.indices) {
            assertThrows(Exception::class.java) { EnrollmentExchange.receive(raw.copyOf(i), offer, claim, phone, nonce, now) }
            val changed = raw.copyOf().apply { this[i] = (this[i].toInt() xor 1).toByte() }
            assertThrows(Exception::class.java) { EnrollmentExchange.receive(changed, offer, claim, phone, nonce, now) }
        }
        for (invalid in listOf(raw + byteArrayOf(0), ByteArray(EnrollmentExchange.MAX_BYTES + 1)))
            assertThrows(IllegalArgumentException::class.java) { EnrollmentExchange.receive(invalid, offer, claim, phone, nonce, now) }
        for (time in listOf(now - 1, now + 60000, Long.MAX_VALUE))
            assertThrows(IllegalArgumentException::class.java) { EnrollmentExchange.receive(raw, offer, claim, phone, nonce, time) }
        assertThrows(IllegalArgumentException::class.java) { EnrollmentExchange.receive(raw, offer, claim, phone, ByteArray(32), now) }
        assertThrows(IllegalArgumentException::class.java) { EnrollmentExchange.receive(raw, offer, claim, device, nonce, now) }
        val other = EnrollmentKeyClaim(claim.offerHash(), "other-key-0000001", claim.approvalKey(), claim.encryptionKeyId, claim.encryptionKey())
        assertThrows(IllegalArgumentException::class.java) { EnrollmentExchange.receive(raw, offer, other, phone, nonce, now) }
    }

    @Test fun `valid HPKE without the device signature cannot confirm or reuse a response for a new nonce`() {
        val raw = bytes("reply.confirmed"); val header = raw.copyOfRange(0, 108); val plain = open(raw, phone)
        val forged = plain.copyOf().apply { fill(0, size - 64, size) }
        assertThrows(IllegalArgumentException::class.java) { EnrollmentExchange.receive(reseal(header, forged), offer, claim, phone, nonce, now) }
        val changedNonce = nonce.copyOf().apply { this[0] = (this[0].toInt() xor 1).toByte() }
        changedNonce.copyInto(header, 76)
        assertThrows(IllegalArgumentException::class.java) { EnrollmentExchange.receive(reseal(header, plain), offer, claim, phone, changedNonce, now) }
    }
}
