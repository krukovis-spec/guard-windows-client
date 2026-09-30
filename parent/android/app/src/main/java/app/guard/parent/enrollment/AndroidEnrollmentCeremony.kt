package app.guard.parent.enrollment

import android.content.Context
import app.guard.parent.protocol.*
import app.guard.parent.security.AndroidApprovalKeyStore
import app.guard.parent.security.AndroidRelayEncryptionKey
import app.guard.parent.security.EcdsaP1363
import java.io.File
import java.security.Signature
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean

/** Supply signature to BiometricPrompt.CryptoObject; finish only with that exact success-callback signature. */
class EnrollmentSigningOperation internal constructor(private val store: PendingEnrollmentStore,
    private val pending: PendingEnrollment, val signature: Signature) {
    private val used = AtomicBoolean(false)
    fun cancel() { used.set(true) }
    fun finish(authenticatedSignature: Signature): PendingEnrollment {
        check(used.compareAndSet(false, true)) { "biometric operation already consumed" }
        require(authenticatedSignature === signature) { "different biometric operation" }
        store.requireUsable(pending)
        val current = requireNotNull(store.load(pending.offer))
        store.requireUsable(current)
        val claim = requireNotNull(pending.claim)
        require(current.claim?.let(EnrollmentWire::claimHash)?.contentEquals(EnrollmentWire.claimHash(claim)) == true && !current.isSigned) { "pending claim changed" }
        signature.update(EnrollmentWire.encodeClaimForSignature(claim))
        val signed = EcdsaP1363.fromDer(signature.sign())
        // No transport may see a signature until the exact claim/chain/proof/signature is durable.
        return store.saveSignature(pending.offer, EnrollmentWire.claimHash(claim), signed)
    }
}

/** Windows alone performs attestation/final owner CAS; this client retains its signed acknowledgment. */
class AndroidEnrollmentCeremony(context: Context) {
    private val store = PendingEnrollmentStore(File(context.noBackupFilesDir, "enrollment"))
    fun listPending() = store.list()

    fun prepare(transcript: EnrollmentTranscript): PendingEnrollment {
        store.prepare(transcript.offer) // persisted BEFORE the first non-exportable key is created
        val capability = transcript.relayCapability()
        val state = try { store.saveCapability(transcript.offer, capability) } finally { capability.fill(0) }
        if (state.claim != null) {
            checkKeys(state)
            require(state.possessionProof().contentEquals(transcript.proofFor(state.claim))) { "different QR secret" }
            store.requireUsable(state)
            return state
        }
        val material = AndroidApprovalKeyStore(state.approvalAlias).loadOrEnroll(EnrollmentWire.offerHash(state.offer))
        val encryption = AndroidRelayEncryptionKey.createIfAbsent(state.encryptionAlias)
        val approvalId = "p256:" + Base64.getUrlEncoder().withoutPadding().encodeToString(GuardWire.sha256(material.publicKeySpki))
        val encryptionId = "p256:" + Base64.getUrlEncoder().withoutPadding().encodeToString(GuardWire.sha256(encryption.publicKeySec1()))
        val claim = EnrollmentKeyClaim(EnrollmentWire.offerHash(state.offer), approvalId, material.publicKeySpki, encryptionId, encryption.publicKeySec1())
        return store.saveClaim(state.offer, claim, material.certificateChain, transcript.proofFor(claim))
    }

    /** READY/SIGNED records resume without retaining the QR secret; PREPARED needs the same QR again. */
    fun resume(offer: EnrollmentOffer): PendingEnrollment = requireNotNull(store.load(offer)).also {
        store.requireUsable(it); requireNotNull(it.claim) { "scan original QR again" }; checkKeys(it); store.requireUsable(it)
    }

    fun startBiometric(offer: EnrollmentOffer): EnrollmentSigningOperation {
        val state = resume(offer)
        check(!state.isSigned) { "resend persisted signature" }
        val signature = AndroidApprovalKeyStore(state.approvalAlias).biometricSignature()
        store.requireUsable(state)
        return EnrollmentSigningOperation(store, state, signature)
    }

    /** One bounded exchange, not a background polling loop. Null means no signed reply yet. */
    suspend fun synchronize(offer: EnrollmentOffer): EnrollmentResult? {
        val state = requireNotNull(store.load(offer)); require(state.isSigned); checkKeys(state)
        val key = AndroidRelayEncryptionKey.openExisting(state.encryptionAlias)
        store.lastResult(offer, key)?.let { if (it.outcome == EnrollmentExchange.CONFIRMED) return it }
        val delivery = store.nextRequest(offer, key)
        val raw = EnrollmentHttpTransport().exchange(delivery) {
            val current = requireNotNull(store.load(offer))
            check(current.request().contentEquals(delivery.request())) { "enrollment delivery changed" }
            store.requireSendable(current)
        } ?: return store.lastResult(offer, key)
        checkKeys(requireNotNull(store.load(offer)))
        return store.acceptReply(offer, raw, key)
    }

    /** Confirmed enrollment only, NOT current permission, recovery readiness or protection status. */
    fun confirmedEnrollment(offer: EnrollmentOffer): PendingEnrollment? {
        val state = requireNotNull(store.load(offer)); checkKeys(state)
        return if (store.lastResult(offer, AndroidRelayEncryptionKey.openExisting(state.encryptionAlias))?.outcome == EnrollmentExchange.CONFIRMED)
            state else null
    }

    fun abandon(offer: EnrollmentOffer) = store.abandon(offer)

    private fun checkKeys(state: PendingEnrollment) {
        val claim = requireNotNull(state.claim)
        val material = AndroidApprovalKeyStore(state.approvalAlias).material()
        val encryption = AndroidRelayEncryptionKey.openExisting(state.encryptionAlias)
        val saved = state.certificateChain()
        check(material.publicKeySpki.contentEquals(claim.approvalKey()) && encryption.publicKeySec1().contentEquals(claim.encryptionKey()) &&
            saved.size == material.certificateChain.size && saved.indices.all { saved[it].contentEquals(material.certificateChain[it]) }) { "enrollment key lost or changed; recovery required" }
    }
}
