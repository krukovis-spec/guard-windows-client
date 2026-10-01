package app.guard.parent

import app.guard.parent.protocol.*
import app.guard.parent.protocol.Writer
import app.guard.parent.security.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.*
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.CancellationException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger

/** Existing .NET frames plus real JCA/HPKE and temporary atomic files. No live phone/Windows actions. */
class ApprovalReceiptTest {
    @TempDir lateinit var directory: File
    private val now = ExchangeVector.now + 2000
    private val approval = ExchangeVector.approval()
    private val pending = PendingSignedEnvelope(approval.keyId, 1, GuardWire.encodeSignedApproval(approval))
    private val recipient = ExchangeVector.recipient
    private val signing = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val trust = ExchangeVector.trust.copy(devicePublicKeySec1 = signing.public.encoded.takeLast(65).toByteArray())
    private fun store() = FileApprovalOutbox(directory)
    private fun receipt(status: ReceiptStatus = ReceiptStatus.APPLIED, envelope: PendingSignedEnvelope = pending): CommandReceipt {
        val a = GuardWire.decodeSignedApproval(envelope.exactBytes)
        return CommandReceipt(a.deviceId, a.deviceEpoch, a.authorityEpoch, a.keyId, a.sequence, a.commandId, a.requestId,
            a.requestRevision, status, now, GuardWire.sha256(GuardWire.encodeApprovalSignatureInput(a)), a.policyRevision + 1,
            if (status == ReceiptStatus.APPLIED) 3 else if (status == ReceiptStatus.ACCEPTED_PENDING_RECONCILIATION) 2 else 1,
            "receipt-test-0001")
    }
    private fun frame(value: CommandReceipt = receipt()): ByteArray {
        val unsigned = Writer("GRDC").apply { bytes(GuardWire.encodeCommandReceipt(value), 65536, false); id(trust.deviceKeyId) }.finish()
        val signature = Signature.getInstance("SHA256withECDSA").apply { initSign(signing.private); update(unsigned) }.sign()
        val plaintext = unsigned + ByteBuffer.allocate(4).putInt(64).array() + EcdsaP1363.fromDer(signature)
        val aad = GuardWire.encodeRelayFrameAssociatedData(RelayFrameAad(3, recipient.mailboxId, recipient.keyId,
            "receipt-frame-001", 3, 0, now - 2000, now + 60000))
        val (enc, cipher) = HpkeP256.encrypt(recipient.privateKey.publicKeySec1(), plaintext, aad,
            "guard-relay-receipt-hpke-v1".toByteArray() + aad)
        return aad + ByteBuffer.allocate(4).putInt(enc.size).array() + enc + ByteBuffer.allocate(4).putInt(cipher.size).array() + cipher
    }
    private fun savedBytes() = directory.listFiles()!!.single { it.extension == "bin" }.readBytes()
    private fun assertPending() {
        assertEquals(1L, store().nextSequence(pending.keyId))
        assertArrayEquals(pending.exactBytes, store().load(pending.keyId)!!.exactBytes)
    }

    @Test fun `dotnet interim then applied survives restart and remains historical after transport expiry`() {
        store().save(pending)
        val intermediate = ExchangeVector.bytes("receipt.frame")
        assertEquals(ReceiptStatus.ACCEPTED_PENDING_RECONCILIATION,
            store().acceptReceipt(intermediate, recipient, ExchangeVector.trust, now).status)
        assertPending()
        val saved = store().lastReceipt(pending.keyId)!!; intermediate.fill(0)
        assertEquals(ReceiptStatus.ACCEPTED_PENDING_RECONCILIATION, saved.verify(recipient, ExchangeVector.trust, now).status)
        assertEquals(ReceiptStatus.APPLIED, store().acceptReceipt(ExchangeVector.bytes("applied.frame"), recipient, ExchangeVector.trust, now).status)
        assertNull(store().load(pending.keyId)); assertEquals(2L, store().nextSequence(pending.keyId))
        val durable = store().lastReceipt(pending.keyId)!!
        assertEquals(ReceiptStatus.APPLIED, durable.verify(recipient, ExchangeVector.trust, now + 8 * 86400000).status)
        assertArrayEquals(pending.exactBytes, durable.pending.exactBytes)
        assertThrows(Exception::class.java) { durable.verify(recipient, ExchangeVector.trust, now - 1) }
        assertThrows(Exception::class.java) { durable.verify(recipient, trust, now) }
        val tampered = durable.encode().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
        assertThrows(Exception::class.java) { SavedApprovalReceipt.decode(tampered).verify(recipient, ExchangeVector.trust, now) }
    }

    @Test fun `every terminal status advances once and preserves original decision without implying allowed access`() {
        for (status in ReceiptStatus.entries.filter { it != ReceiptStatus.ACCEPTED_PENDING_RECONCILIATION }) {
            val outbox = FileApprovalOutbox(File(directory, status.name)); outbox.save(pending)
            outbox.acceptReceipt(frame(receipt(status)), recipient, trust, now)
            assertNull(outbox.load(pending.keyId)); assertEquals(2L, outbox.nextSequence(pending.keyId))
            assertEquals(status, outbox.lastReceipt(pending.keyId)!!.verify(recipient, trust, now).status)
            // A newly encrypted copy of the same signed receipt is idempotent too.
            outbox.acceptReceipt(frame(receipt(status)), recipient, trust, now)
            assertEquals(2L, outbox.nextSequence(pending.keyId))
        }
    }

    @Test fun `wrong signature context hash identity and time never retire a command`() {
        store().save(pending); val original = savedBytes(); val good = receipt()
        val bad = listOf(good.copy(keyId = "wrong-parent-001"), good.copy(sequence = 2), good.copy(commandId = "wrong-command-001"),
            good.copy(requestId = "wrong-request-001"), good.copy(requestRevision = good.requestRevision + 1),
            good.copy(approvalHash = ByteArray(32)), good.copy(deviceId = "wrong-device-0001"), good.copy(deviceEpoch = 99),
            good.copy(authorityEpoch = 99), good.copy(processedUnixMillis = approval.issuedUnixMillis - 1),
            good.copy(processedUnixMillis = now + 1))
        for (value in bad) assertThrows(Exception::class.java) { store().acceptReceipt(frame(value), recipient, trust, now) }
        assertThrows(Exception::class.java) { store().acceptReceipt(frame(), recipient, ExchangeVector.trust, now) }
        assertThrows(Exception::class.java) { store().acceptReceipt(frame(), recipient.copy(keyId = "wrong-recipient1"), trust, now) }
        assertThrows(Exception::class.java) { store().acceptReceipt(frame(), recipient, trust, now + 60000) }
        assertArrayEquals(original, savedBytes()); assertNull(store().lastReceipt(pending.keyId)); assertPending()
    }

    @Test fun `late interim duplicate and conflicting terminal cannot affect next pending decision`() {
        store().save(pending); store().acceptReceipt(frame(), recipient, trust, now)
        val nextApproval = approval.copy(sequence = 2, commandId = "command-alpha-002", issuedUnixMillis = now)
        val next = PendingSignedEnvelope(pending.keyId, 2, GuardWire.encodeSignedApproval(nextApproval))
        store().save(next); val stable = savedBytes()
        assertEquals(ReceiptStatus.APPLIED, store().acceptReceipt(frame(receipt(ReceiptStatus.ACCEPTED_PENDING_RECONCILIATION)), recipient, trust, now).status)
        store().acceptReceipt(frame(), recipient, trust, now)
        assertThrows(Exception::class.java) { store().acceptReceipt(frame(receipt(ReceiptStatus.REJECTED)), recipient, trust, now) }
        assertArrayEquals(stable, savedBytes()); assertArrayEquals(next.exactBytes, store().load(pending.keyId)!!.exactBytes)
        assertEquals(2L, store().nextSequence(pending.keyId))
        assertNull(store().delivery(next))
    }

    @Test fun `cancel before atomic commit leaves pending while lost result after commit keeps durable evidence`() {
        store().save(pending); val original = savedBytes()
        assertThrows(CancellationException::class.java) {
            store().acceptReceipt(frame(), recipient, trust, now) { throw CancellationException() }
        }
        assertArrayEquals(original, savedBytes()); assertPending(); assertNull(store().lastReceipt(pending.keyId))
        assertEquals(1, directory.listFiles()!!.size)
        store().acceptReceipt(frame(receipt(ReceiptStatus.ACCEPTED_PENDING_RECONCILIATION)), recipient, trust, now)
        val interim = savedBytes()
        assertThrows(CancellationException::class.java) {
            store().acceptReceipt(frame(), recipient, trust, now) { throw CancellationException() }
        }
        assertArrayEquals(interim, savedBytes()); assertPending()
        assertThrows(CancellationException::class.java) {
            store().acceptReceipt(frame(), recipient, trust, now)
            throw CancellationException() // UI result lost after the file commit, not a storage rollback.
        }
        assertEquals(2L, store().nextSequence(pending.keyId))
        assertEquals(ReceiptStatus.APPLIED, store().lastReceipt(pending.keyId)!!.verify(recipient, trust, now).status)
    }

    @Test fun `GOB2 receipt migration corruption and rollback fail closed`() {
        store().save(pending); val path = directory.listFiles()!!.single()
        val old = ByteArrayOutputStream().apply { DataOutputStream(this).apply {
            writeInt(0x474f4232); writeLong(1); writeInt(pending.exactBytes.size); write(pending.exactBytes); writeInt(0)
        } }.toByteArray()
        path.writeBytes(old + GuardWire.sha256(old)); assertPending(); assertNull(store().lastReceipt(pending.keyId))
        store().acceptReceipt(frame(), recipient, trust, now)
        assertEquals(0x474f4233, ByteBuffer.wrap(path.readBytes()).int)
        assertThrows(Exception::class.java) { store().save(PendingSignedEnvelope(pending.keyId, 2,
            GuardWire.encodeSignedApproval(approval.copy(sequence = 2)))) }
        assertThrows(Exception::class.java) { store().acceptReceipt(frame(receipt().copy(processedUnixMillis = now - 1)), recipient, trust, now - 1) }
        val valid = savedBytes(); path.writeBytes(valid.apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() })
        assertThrows(Exception::class.java) { store().nextSequence(pending.keyId) }
        assertThrows(Exception::class.java) { store().lastReceipt(pending.keyId) }
    }

    @Test fun `parallel matching receipts commit terminal and sequence only once`() {
        store().save(pending); val raw = frame(); val start = CountDownLatch(1); val successful = AtomicInteger()
        val threads = List(4) { Thread {
            start.await()
            store().acceptReceipt(raw, recipient, trust, now); successful.incrementAndGet()
        }.apply { start() } }
        start.countDown(); threads.forEach { it.join(5000); assertFalse(it.isAlive) }
        assertEquals(4, successful.get()); assertEquals(2L, store().nextSequence(pending.keyId)); assertNull(store().load(pending.keyId))
        assertEquals(ReceiptStatus.APPLIED, store().lastReceipt(pending.keyId)!!.verify(recipient, trust, now).status)
    }

    @Test fun `old interim is ignored on polling restart but terminal cannot regress policy version`() {
        store().save(pending)
        val first = receipt(ReceiptStatus.ACCEPTED_PENDING_RECONCILIATION)
        store().acceptReceipt(frame(first), recipient, trust, now)
        val original = savedBytes()
        for (older in listOf(first.copy(processedUnixMillis = now - 1), first.copy(committedPolicyRevision = first.committedPolicyRevision - 1)))
            assertEquals(first, store().acceptReceipt(frame(older), recipient, trust, now).copy(approvalHash = first.approvalHash))
        assertThrows(Exception::class.java) { store().acceptReceipt(frame(receipt().copy(committedPolicyRevision = first.committedPolicyRevision - 1)), recipient, trust, now) }
        assertArrayEquals(original, savedBytes()); assertPending()
        store().acceptReceipt(frame(), recipient, trust, now)
        assertEquals(2L, store().nextSequence(pending.keyId)); assertNull(store().load(pending.keyId))
    }
}
