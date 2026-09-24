package app.guard.parent

import app.guard.parent.protocol.*
import app.guard.parent.security.EcdsaP1363
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.File
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.util.Properties

/** Shared with the .NET harness; all key material is public, test-only data. */
internal object ExchangeVector {
    private val values = Properties().apply {
        requireNotNull(ExchangeVector::class.java.getResourceAsStream("/relay-exchange-v1.properties")).use { load(it) }
    }
    fun bytes(name: String): ByteArray = values.getProperty(name).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    val now = values.getProperty("now").toLong()
    val key = object : RelayEncryptionKey {
        override fun privateKey(): java.security.PrivateKey {
            val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
            return KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, bytes("recipient.private")), parameters))
        }
        override fun publicKeySec1() = bytes("recipient.public")
    }
    val recipient = RelayRecipient("mailbox-alpha-0001", "recipient-key-0001", 4, key)
    val trust = RelayDeviceTrust("device-alpha-0001", 2, 4, "device-signing-0001", bytes("device.public"))
    fun approval() = GuardWire.decodeSignedApproval(bytes("approval.input") + byteArrayOf(0, 0, 0, 64) + bytes("approval.signature"))
}

class RelayReceiveTest {
    private val raw = ExchangeVector.bytes("request.frame")
    private val recipient = ExchangeVector.recipient
    private val trust = ExchangeVector.trust
    private val now = ExchangeVector.now

    @Test fun `decrypts and verifies a real dotnet request without a fake verifier`() {
        val signed = RelayReceive.receiveRequest(raw, recipient, trust, now)
        val expected = RelayReceive.decodeDeviceSignedRequest(ExchangeVector.bytes("request.plaintext"))
        assertArrayEquals(expected.signatureInput, signed.signatureInput)
        assertEquals("https://example.test/path", signed.snapshot.targetIdentity)
        assertEquals("homework", signed.snapshot.reason)
    }

    @Test fun `rejects corrupt frames invalid curve points and the old synthetic key`() {
        assertThrows(IllegalArgumentException::class.java) { RelayReceive.decodeFrame(raw + byteArrayOf(0)) }
        assertThrows(IllegalArgumentException::class.java) { RelayReceive.decodeFrame(raw.copyOf(raw.size - 1)) }
        val offset = GuardWire.encodeRelayFrameAssociatedData(RelayReceive.decodeFrame(raw).aad).size + 4
        val offCurve = raw.copyOf(); offCurve.fill(0, offset + 1, offset + 65)
        assertThrows(IllegalArgumentException::class.java) { RelayReceive.decodeFrame(offCurve) }
        val synthetic = raw.copyOf(); repeat(65) { synthetic[offset + it] = (it + 1).toByte() }
        assertThrows(IllegalArgumentException::class.java) { RelayReceive.decodeFrame(synthetic) }
        val corrupt = raw.copyOf(); corrupt[corrupt.lastIndex] = (corrupt.last().toInt() xor 1).toByte()
        assertThrows(java.security.GeneralSecurityException::class.java) { RelayReceive.receiveRequest(corrupt, recipient, trust, now) }
    }

    @Test fun `rejects wrong device key epoch recipient and expiration boundary`() {
        for (bad in listOf(trust.copy(deviceKeyId = "different-key-0001"), trust.copy(deviceEpoch = 3), trust.copy(authorityEpoch = 5), trust.copy(devicePublicKeySec1 = ExchangeVector.bytes("recipient.public")))) {
            assertThrows(IllegalArgumentException::class.java) { RelayReceive.receiveRequest(raw, recipient, bad, now) }
        }
        assertThrows(IllegalArgumentException::class.java) { RelayReceive.receiveRequest(raw, recipient.copy(mailboxId = "other-mailbox-0001"), trust, now) }
        assertThrows(IllegalArgumentException::class.java) { RelayReceive.receiveRequest(raw, recipient, trust, RelayReceive.decodeFrame(raw).aad.expiryUnixMillis) }
        assertThrows(IllegalArgumentException::class.java) { GuardWire.requireLifetime(Long.MIN_VALUE, Long.MAX_VALUE, 1000) }
    }

    @Test fun `verifies signed receipt but does not call pending reconciliation applied`() {
        val signed = RelayReceive.receiveReceipt(ExchangeVector.bytes("receipt.frame"), recipient, trust, now + 1000)
        assertEquals(ReceiptStatus.ACCEPTED_PENDING_RECONCILIATION, signed.receipt.status)
        assertEquals(2, signed.receipt.reconciliation)
        assertArrayEquals(GuardWire.sha256(ExchangeVector.bytes("approval.input")), signed.receipt.approvalHash)
        assertThrows(IllegalArgumentException::class.java) { RelayReceive.receiveReceipt(raw, recipient, trust, now) }
    }

    @Test fun `signs an exact approval that dotnet can independently verify`() {
        val unsigned = ExchangeVector.approval()
        val signature = Signature.getInstance("SHA256withECDSA").apply { initSign(ExchangeVector.key.privateKey()); update(GuardWire.encodeApprovalSignatureInput(unsigned)) }
        val signed = unsigned.copy(signatureP1363 = EcdsaP1363.fromDer(signature.sign()))
        assertTrue(RelayReceive.P256DeviceSignatureVerifier.verify(ExchangeVector.bytes("recipient.public"), GuardWire.sha256(GuardWire.encodeApprovalSignatureInput(signed)), signed.signatureP1363))
        val output = File("build/test-interop/android-approval.hex")
        requireNotNull(output.parentFile).mkdirs(); output.writeText(GuardWire.encodeSignedApproval(signed).joinToString("") { "%02x".format(it) })
    }
}
