package app.guard.parent.approval

import androidx.biometric.BiometricPrompt
import app.guard.parent.protocol.ApprovalDecision
import app.guard.parent.protocol.GuardWire
import app.guard.parent.protocol.RequestSnapshot
import app.guard.parent.protocol.SignedApproval
import app.guard.parent.security.AndroidApprovalKeyStore
import app.guard.parent.security.EcdsaP1363
import app.guard.parent.security.PendingSignedEnvelope
import app.guard.parent.security.StopAndWaitApprovals
import java.util.UUID

data class ApprovalChoice(val decision: ApprovalDecision, val minutes: Int) {
    init { val timed = decision == ApprovalDecision.ALLOW_TEMPORARY || decision == ApprovalDecision.ALLOW_DAILY_QUOTA; require(if (timed) minutes in 1..1440 else minutes == 0) }
}
/** The sole signing entry point. Call only from BiometricPrompt's success callback. */
class ApprovalCoordinator(private val keyStore: AndroidApprovalKeyStore, private val outbox: StopAndWaitApprovals) {
    fun cryptoObject(): BiometricPrompt.CryptoObject = BiometricPrompt.CryptoObject(keyStore.biometricSignature())

    fun signAfterStrongBiometric(
        authenticated: BiometricPrompt.CryptoObject, snapshot: RequestSnapshot, authorityEpoch: Long, keyId: String,
        sequence: Long, issued: Long, expiry: Long, choice: ApprovalChoice
    ): PendingSignedEnvelope {
        require(outbox.getPending(keyId) == null) { "terminal receipt required" }
        AuthorityEpochBinding.requireMatch(snapshot, authorityEpoch)
        val unsigned = SignedApproval(authorityEpoch, keyId, sequence, UUID.randomUUID().toString(), UUID.randomUUID().toString(), issued, expiry,
            snapshot.deviceId, snapshot.deviceEpoch, snapshot.requestId, snapshot.requestRevision, GuardWire.sha256(GuardWire.encodeRequestSnapshot(snapshot)),
            snapshot.challenge, snapshot.targetKind, snapshot.targetIdentity, snapshot.policyRevision, choice.decision, choice.minutes, ByteArray(64))
        GuardWire.validateApproval(unsigned)
        val signature = authenticated.signature ?: throw SecurityException("missing biometric signature")
        signature.update(GuardWire.encodeApprovalSignatureInput(unsigned))
        val final = unsigned.copy(signatureP1363 = EcdsaP1363.fromDer(signature.sign()))
        return PendingSignedEnvelope(keyId, sequence, GuardWire.encodeSignedApproval(final)).also(outbox::persistBeforeSend)
    }
}

object AuthorityEpochBinding {
    fun requireMatch(snapshot: RequestSnapshot, authorityEpoch: Long) {
        require(snapshot.authorityEpoch == authorityEpoch) { "authority epoch mismatch" }
    }
}
