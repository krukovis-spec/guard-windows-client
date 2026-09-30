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

/** No network/ownership transition here. Actual attestation and final owner CAS belong to Windows. */
class AndroidEnrollmentCeremony(context: Context) {
    private val store = PendingEnrollmentStore(File(context.noBackupFilesDir, "enrollment"))
    fun listPending() = store.list()

    fun prepare(transcript: EnrollmentTranscript): PendingEnrollment {
        val state = store.prepare(transcript.offer) // persisted BEFORE the first non-exportable key is created
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

    fun forSend(offer: EnrollmentOffer): PendingEnrollment {
        resume(offer)
        return store.forSend(offer)
    }

    fun answerKeyConfirmation(offer: EnrollmentOffer, enc: ByteArray, cipher: ByteArray): ByteArray {
        val state = forSend(offer)
        val proof = EnrollmentWire.answerKeyConfirmation(requireNotNull(state.claim), AndroidRelayEncryptionKey.openExisting(state.encryptionAlias), enc, cipher)
        try { store.forSend(offer); return proof } catch (error: Exception) { proof.fill(0); throw error }
    }

    fun encryptedClaim(offer: EnrollmentOffer, nonce: ByteArray): ByteArray {
        val state = forSend(offer)
        val encoded = EnrollmentExchange.claim(offer, requireNotNull(state.claim), state.certificateChain(), state.possessionProof(), state.signature(), nonce)
        store.forSend(offer) // expiry during HPKE must not release a new submission
        return encoded
    }

    fun encryptedKeyProof(offer: EnrollmentOffer, result: EnrollmentResult, nonce: ByteArray): ByteArray {
        require(result.outcome == EnrollmentExchange.NEEDS_PHONE_PROOF)
        val state = forSend(offer)
        val proof = answerKeyConfirmation(offer, result.encapsulatedKey(), result.encryptedChallenge())
        return try {
            EnrollmentExchange.keyProof(offer, requireNotNull(state.claim), proof, nonce).also { store.forSend(offer) }
        } finally { proof.fill(0) }
    }

    /** A post-timeout query is allowed, but cannot generate/replace keys or assert local ownership. */
    fun encryptedStatusQuery(offer: EnrollmentOffer, nonce: ByteArray): ByteArray {
        val state = requireNotNull(store.load(offer)); require(state.isSigned); checkKeys(state)
        return EnrollmentExchange.query(offer, requireNotNull(state.claim), nonce)
    }

    fun receiveExchangeResult(offer: EnrollmentOffer, raw: ByteArray, expectedNonce: ByteArray): EnrollmentResult {
        val state = requireNotNull(store.load(offer)); require(state.isSigned); checkKeys(state)
        check(System.currentTimeMillis() >= state.observedUnixMillis) { "clock rollback" }
        val result = EnrollmentExchange.receive(raw, offer, requireNotNull(state.claim),
            AndroidRelayEncryptionKey.openExisting(state.encryptionAlias), expectedNonce, System.currentTimeMillis())
        check(System.currentTimeMillis() in result.issuedUnixMillis until result.expiryUnixMillis)
        return result // Not active-owner promotion; durable reconciliation must consume the outstanding nonce.
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
