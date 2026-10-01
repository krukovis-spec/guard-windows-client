package app.guard.parent.enrollment

import android.content.Context
import app.guard.parent.BuildConfig
import app.guard.parent.approval.NativeRequestInbox
import app.guard.parent.approval.NativeApprovalDelivery
import app.guard.parent.approval.ApprovalChoice
import app.guard.parent.approval.ApprovalSigningOperation
import app.guard.parent.approval.VerifiedNativeRequest
import app.guard.parent.protocol.*
import app.guard.parent.security.AndroidApprovalKeyStore
import app.guard.parent.security.AndroidRelayEncryptionKey
import app.guard.parent.security.EcdsaP1363
import app.guard.parent.security.FileApprovalOutbox
import app.guard.parent.security.StopAndWaitApprovals
import app.guard.parent.security.PendingSignedEnvelope
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
    private val nativeProfiles = NativeRelayProfileStore(File(context.noBackupFilesDir, "native-transport"))
    private val approvalStore = FileApprovalOutbox(File(context.noBackupFilesDir, "approvals"))
    private val approvals = StopAndWaitApprovals(approvalStore)
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
        val (state, result) = inspect(offer)
        return if (result?.outcome == EnrollmentExchange.CONFIRMED) state else null
    }

    /** Caller must get the checksum independently from the trusted off-PC operator, not from the imported file/relay. */
    fun importNativeProfile(offer: EnrollmentOffer, envelope: ByteArray, independentlyTrustedSha256: String, beforeCommit: () -> Unit = {}) {
        beforeCommit()
        val state = nativeProfileOwner(offer)
        nativeProfiles.install(offer, requireNotNull(state.claim), AndroidRelayEncryptionKey.openExisting(state.encryptionAlias),
            envelope, independentlyTrustedSha256, beforeCommit)
        nativeProfileOwner(offer) // Do not report success if local enrollment/keys changed during storage.
    }

    /** No creation or trust from a profile. Caller owns/clears the short-lived decrypted credential. */
    fun openNativeProfile(offer: EnrollmentOffer): NativeRelayProfile? {
        val state = nativeProfileOwner(offer)
        return nativeProfiles.open(offer, requireNotNull(state.claim), AndroidRelayEncryptionKey.openExisting(state.encryptionAlias))
    }

    /** No locator or caller-supplied endpoint/key. Keep this session only for one explicit bounded foreground read. */
    internal fun openNativeInbox(offer: EnrollmentOffer): NativeRequestInbox {
        val state = nativeProfileOwner(offer)
        val claim = requireNotNull(state.claim)
        val key = AndroidRelayEncryptionKey.openExisting(state.encryptionAlias)
        val profile = requireNotNull(nativeProfiles.open(offer, claim, key)) { "native profile required" }
        try {
            return NativeRequestInbox(offer, claim, key, profile, { nativeProfileOwner(offer); Unit })
        } catch (error: Exception) { profile.close(); throw error }
    }

    internal fun verifyRequest(offer: EnrollmentOffer, request: VerifiedNativeRequest, now: Long = System.currentTimeMillis()) {
        val state = nativeProfileOwner(offer)
        val claim = requireNotNull(state.claim)
        val key = AndroidRelayEncryptionKey.openExisting(state.encryptionAlias)
        requireNotNull(nativeProfiles.open(offer, claim, key)).use { it.requireCurrent(now) }
        request.reverify(RelayRecipient(offer.mailboxId, claim.encryptionKeyId, offer.authorityEpoch, key),
            RelayDeviceTrust(offer.deviceId, offer.deviceEpoch, offer.authorityEpoch, offer.signingKeyId, offer.signingKey()), now)
    }

    internal fun startApproval(offer: EnrollmentOffer, request: VerifiedNativeRequest, choice: ApprovalChoice): ApprovalSigningOperation {
        val state = nativeProfileOwner(offer)
        val claim = requireNotNull(state.claim)
        val expiry = requireNotNull(nativeProfiles.open(offer, claim, AndroidRelayEncryptionKey.openExisting(state.encryptionAlias)))
            .use { it.expiryUnixMillis }
        return ApprovalSigningOperation(request, claim.approvalKeyId, choice, expiry, approvals,
            { AndroidApprovalKeyStore(state.approvalAlias).biometricSignature() },
            { now -> verifyRequest(offer, request, now) })
    }

    /** Available even after transport expiry: show the exact saved command, never silently reset its sequence. */
    internal fun pendingApproval(offer: EnrollmentOffer): PendingSignedEnvelope? {
        val state = nativeProfileOwner(offer)
        return approvals.getPending(requireNotNull(state.claim).approvalKeyId)
    }

    /** Reuses the saved signature; no new biometric operation or caller-supplied destination. */
    internal fun openApprovalDelivery(offer: EnrollmentOffer): NativeApprovalDelivery {
        val state = nativeProfileOwner(offer)
        val claim = requireNotNull(state.claim)
        val pending = requireNotNull(approvals.getPending(claim.approvalKeyId)) { "pending approval required" }
        val profile = requireNotNull(nativeProfiles.open(offer, claim, AndroidRelayEncryptionKey.openExisting(state.encryptionAlias)))
        try {
            return NativeApprovalDelivery(offer, claim, pending, approvalStore, profile, { nativeProfileOwner(offer); Unit })
        } catch (error: Exception) { profile.close(); throw error }
    }

    private fun nativeProfileOwner(offer: EnrollmentOffer): PendingEnrollment {
        require(offer.relayEndpoint == EnrollmentRelayBinding(BuildConfig.ENROLLMENT_RELAY).canonicalRelayEndpoint) { "unbound deployment" }
        return requireNotNull(confirmedEnrollment(offer)) { "confirmed enrollment required" }.also { check(!it.abandoned) { "abandoned enrollment" } }
    }

    /** UI reads only locally reverified evidence. A stored flag or an HTTP status is not confirmation. */
    fun inspect(offer: EnrollmentOffer): Pair<PendingEnrollment, EnrollmentResult?> {
        val state = requireNotNull(store.load(offer))
        if (state.claim == null) return state to null
        checkKeys(state)
        return state to store.lastResult(offer, AndroidRelayEncryptionKey.openExisting(state.encryptionAlias))
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
