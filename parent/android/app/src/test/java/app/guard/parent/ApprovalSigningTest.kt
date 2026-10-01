package app.guard.parent

import app.guard.parent.approval.*
import app.guard.parent.protocol.*
import app.guard.parent.security.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.security.Signature
import java.time.*
import java.util.concurrent.CancellationException

/** Real device-signed .NET frame, JCA approval signature and atomic files; not physical Keystore/biometry acceptance. */
class ApprovalSigningTest {
    @TempDir lateinit var directory: File
    private val clock = TestClock(ExchangeVector.now)
    private val keyId = "parent-key-alpha1"
    private val raw = ExchangeVector.bytes("request.frame")
    private val request = VerifiedNativeRequest.verify(raw, ExchangeVector.recipient, ExchangeVector.trust, clock.millis())
    private fun queue(path: File = directory) = StopAndWaitApprovals(FileApprovalOutbox(path))
    private fun signature() = Signature.getInstance("SHA256withECDSA").apply { initSign(ExchangeVector.key.privateKey()) }
    private fun begin(choice: ApprovalChoice = ApprovalChoice(ApprovalDecision.DENY, 0),
        outbox: StopAndWaitApprovals = queue(), guard: (Long) -> Unit = {}, create: () -> Signature = ::signature,
        profileExpiry: Long = Long.MAX_VALUE) =
        ApprovalSigningOperation(request, keyId, choice, profileExpiry, outbox, create, { now ->
            request.reverify(ExchangeVector.recipient, ExchangeVector.trust, now); guard(now)
        }, clock)

    @Test fun `all choices bind exact request and durable sequence before any transport`() {
        for (decision in ApprovalDecision.entries) {
            val path = File(directory, decision.name)
            val choice = ApprovalChoice(decision, if (decision in listOf(ApprovalDecision.ALLOW_TEMPORARY, ApprovalDecision.ALLOW_DAILY_QUOTA)) 15 else 0)
            val operation = begin(choice, queue(path))
            val pending = operation.finish(operation.signature)
            val approval = GuardWire.decodeSignedApproval(pending.exactBytes)
            val snapshot = request.snapshot
            assertEquals(decision, approval.decision); assertEquals(choice.minutes, approval.minutes)
            assertEquals(1L, approval.sequence); assertEquals(keyId, approval.keyId)
            assertEquals(snapshot.deviceId, approval.deviceId); assertEquals(snapshot.deviceEpoch, approval.deviceEpoch)
            assertEquals(snapshot.authorityEpoch, approval.authorityEpoch); assertEquals(snapshot.requestId, approval.requestId)
            assertEquals(snapshot.requestRevision, approval.requestRevision); assertEquals(snapshot.policyRevision, approval.policyRevision)
            assertEquals(snapshot.targetIdentity, approval.targetIdentity); assertEquals(snapshot.targetKind, approval.targetKind)
            assertArrayEquals(snapshot.challenge, approval.challenge)
            assertArrayEquals(GuardWire.sha256(GuardWire.encodeRequestSnapshot(snapshot)), approval.snapshotHash)
            assertEquals(clock.millis(), approval.issuedUnixMillis)
            assertEquals(minOf(clock.millis() + 900000, request.expiryUnixMillis), approval.expiryUnixMillis)
            assertTrue(RelayReceive.P256DeviceSignatureVerifier.verify(ExchangeVector.key.publicKeySec1(),
                GuardWire.sha256(GuardWire.encodeApprovalSignatureInput(approval)), approval.signatureP1363))
            assertArrayEquals(pending.exactBytes, queue(path).getPending(keyId)!!.exactBytes)
            assertEquals(1L, queue(path).nextSequence(keyId))
            operation.cancel() // Cancellation after commit never deletes a signed command.
            assertNotNull(queue(path).getPending(keyId))
            assertThrows(IllegalStateException::class.java) { operation.finish(operation.signature) }
            assertThrows(IllegalArgumentException::class.java) { begin(choice, queue(path)) }
        }
    }

    @Test fun `caller cannot mutate verified display evidence or committed envelope`() {
        val canonical = GuardWire.encodeRequestSnapshot(request.snapshot)
        raw.fill(0); request.snapshot.challenge.fill(0)
        (request.snapshot.evidence as? MutableList)?.clear()
        assertArrayEquals(canonical, GuardWire.encodeRequestSnapshot(request.snapshot))
        val operation = begin()
        val pending = operation.finish(operation.signature)
        val original = pending.exactBytes
        pending.exactBytes.fill(0)
        val constructorBytes = original.copyOf()
        val immutable = PendingSignedEnvelope(pending.keyId, pending.sequence, constructorBytes)
        constructorBytes.fill(0)
        assertArrayEquals(original, immutable.exactBytes)
        assertArrayEquals(original, queue().getPending(keyId)!!.exactBytes)
    }

    @Test fun `wrong signature cancelled or repeated callback never signs`() {
        val wrong = begin()
        assertThrows(IllegalArgumentException::class.java) { wrong.finish(signature()) }
        assertThrows(IllegalStateException::class.java) { wrong.finish(wrong.signature) }
        val cancelled = begin(); cancelled.cancel()
        assertThrows(IllegalStateException::class.java) { cancelled.finish(cancelled.signature) }
        val lostJob = begin()
        assertThrows(CancellationException::class.java) { lostJob.finish(lostJob.signature) { throw CancellationException() } }
        assertNull(queue().getPending(keyId)); assertEquals(1L, queue().nextSequence(keyId))
    }

    @Test fun `expired or changed trust and backwards time refuse before signature and atomic commit`() {
        var authorized = true
        val revoked = begin(guard = { check(authorized) }); authorized = false
        assertThrows(IllegalStateException::class.java) { revoked.finish(revoked.signature) }
        val backward = begin(); clock.time--
        assertThrows(IllegalArgumentException::class.java) { backward.finish(backward.signature) }
        clock.time = ExchangeVector.now
        val expired = begin(); clock.time = request.expiryUnixMillis
        assertThrows(IllegalArgumentException::class.java) { expired.finish(expired.signature) }
        assertThrows(IllegalArgumentException::class.java) { begin() }
        clock.time = ExchangeVector.now
        val late = begin(guard = {
            // This runs again after fd.sync, immediately before replacing the durable file.
            if (directory.listFiles()!!.any { it.extension == "tmp" }) clock.time = request.expiryUnixMillis
        })
        assertThrows(IllegalArgumentException::class.java) { late.finish(late.signature) }
        assertNull(queue().getPending(keyId)); assertEquals(1L, queue().nextSequence(keyId))
        assertTrue(directory.listFiles()!!.isEmpty())
        clock.time = ExchangeVector.now
        val profileExpiry = clock.time + 1
        val profileExpired = begin(profileExpiry = profileExpiry)
        clock.time = profileExpiry
        assertThrows(IllegalArgumentException::class.java) { profileExpired.finish(profileExpired.signature) }
    }

    @Test fun `cancellation in validation or final commit guard leaves no pending file`() {
        lateinit var stopped: ApprovalSigningOperation
        var stop = false
        stopped = begin(guard = { if (stop) stopped.cancel() }); stop = true
        assertThrows(IllegalStateException::class.java) { stopped.finish(stopped.signature) }
        val operation = begin()
        var calls = 0
        assertThrows(CancellationException::class.java) {
            operation.finish(operation.signature) { if (++calls == 2) throw CancellationException() }
        }
        assertEquals(2, calls); assertTrue(directory.listFiles()!!.isEmpty())
        assertNull(queue().getPending(keyId))
    }

    @Test fun `another committed decision cannot be overwritten by an already prepared prompt`() {
        val first = begin(); val stale = begin(ApprovalChoice(ApprovalDecision.ALLOW_ALWAYS, 0))
        val saved = first.finish(first.signature)
        assertThrows(IllegalArgumentException::class.java) { stale.finish(stale.signature) }
        assertArrayEquals(saved.exactBytes, queue().getPending(keyId)!!.exactBytes)
    }

    private class TestClock(var time: Long) : Clock() {
        override fun millis() = time
        override fun instant() = Instant.ofEpochMilli(time)
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = this
    }
}
