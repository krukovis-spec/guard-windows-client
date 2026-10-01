package app.guard.parent.approval

import app.guard.parent.protocol.ApprovalDecision
import app.guard.parent.protocol.GuardWire
import app.guard.parent.protocol.RequestSnapshot
import app.guard.parent.protocol.SignedApproval
import app.guard.parent.security.EcdsaP1363
import app.guard.parent.security.PendingSignedEnvelope
import app.guard.parent.security.StopAndWaitApprovals
import java.util.UUID
import java.security.Signature
import java.time.Clock
import java.util.concurrent.atomic.AtomicBoolean

data class ApprovalChoice(val decision: ApprovalDecision, val minutes: Int) {
    init { val timed = decision == ApprovalDecision.ALLOW_TEMPORARY || decision == ApprovalDecision.ALLOW_DAILY_QUOTA; require(if (timed) minutes in 1..1440 else minutes == 0) }
}
/** One exact request/choice/sequence/Signature, frozen BEFORE BiometricPrompt. No network or automatic re-signing. */
internal class ApprovalSigningOperation(
    request: VerifiedNativeRequest, keyId: String, choice: ApprovalChoice, profileExpiryUnixMillis: Long,
    private val outbox: StopAndWaitApprovals, createSignature: () -> Signature,
    private val verifyCurrent: (Long) -> Unit, private val clock: Clock = Clock.systemUTC()
) {
    private val used = AtomicBoolean(false)
    private val cancelled = AtomicBoolean(false)
    private var observed = clock.millis()
    private val unsigned: SignedApproval
    val signature: Signature

    init {
        val snapshot = request.snapshot
        require(observed in snapshot.createdUnixMillis until snapshot.pendingExpiryUnixMillis) { "request lifetime" }
        require(outbox.getPending(keyId) == null) { "terminal receipt required" }
        val sequence = outbox.nextSequence(keyId)
        require(sequence in 1 until Long.MAX_VALUE)
        unsigned = SignedApproval(snapshot.authorityEpoch, keyId, sequence, UUID.randomUUID().toString(), UUID.randomUUID().toString(),
            observed, minOf(Math.addExact(observed, 15 * 60_000L), request.expiryUnixMillis, profileExpiryUnixMillis),
            snapshot.deviceId, snapshot.deviceEpoch, snapshot.requestId, snapshot.requestRevision,
            GuardWire.sha256(GuardWire.encodeRequestSnapshot(snapshot)), snapshot.challenge,
            snapshot.targetKind, snapshot.targetIdentity, snapshot.policyRevision, choice.decision, choice.minutes, ByteArray(64))
        GuardWire.validateApproval(unsigned)
        checkCurrent()
        signature = createSignature()
        checkCurrent()
    }

    fun cancel() { cancelled.set(true) }

    private fun checkCurrent() {
        check(!cancelled.get()) { "approval cancelled" }
        val before = clock.millis()
        require(before >= observed && before < unsigned.expiryUnixMillis) { "approval clock/lifetime" }
        verifyCurrent(before) // Existing owner, keys, profile and original signed frame, not UI parameters.
        val after = clock.millis()
        require(after >= before && after < unsigned.expiryUnixMillis) { "approval expired during validation" }
        observed = after
        check(!cancelled.get()) { "approval cancelled" }
    }

    /** Caller checks TYPE_BIOMETRIC. CryptoObject must contain this exact per-operation Signature. */
    fun finish(authenticatedSignature: Signature, beforeCommit: () -> Unit = {}): PendingSignedEnvelope {
        check(used.compareAndSet(false, true)) { "biometric operation already consumed" }
        require(authenticatedSignature === signature) { "different biometric operation" }
        beforeCommit(); checkCurrent()
        require(outbox.getPending(unsigned.keyId) == null && outbox.nextSequence(unsigned.keyId) == unsigned.sequence) { "approval queue changed" }
        signature.update(GuardWire.encodeApprovalSignatureInput(unsigned))
        val signed = unsigned.copy(signatureP1363 = EcdsaP1363.fromDer(signature.sign()))
        val pending = PendingSignedEnvelope(signed.keyId, signed.sequence, GuardWire.encodeSignedApproval(signed))
        outbox.persistBeforeSend(pending) { checkCurrent(); beforeCommit() }
        // After commit never erase/re-sign on cancellation or a lost UI result. Reopen the durable outbox.
        return pending
    }
}

object AuthorityEpochBinding {
    fun requireMatch(snapshot: RequestSnapshot, authorityEpoch: Long) {
        require(snapshot.authorityEpoch == authorityEpoch) { "authority epoch mismatch" }
    }
}
