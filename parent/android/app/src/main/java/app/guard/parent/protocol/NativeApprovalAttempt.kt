package app.guard.parent.protocol

import app.guard.parent.security.PendingSignedEnvelope
import java.nio.ByteBuffer
import java.util.UUID

/** Durable transport metadata, never approval authority. Exact GRAP bytes remain in the approval outbox. */
internal class NativeApprovalAttempt private constructor(
    private val binding: ByteArray, val frameId: String, val created: Long, val expiry: Long,
    val observed: Long, val cursor: Long, val leaseExpiry: Long, private val frame: ByteArray, val published: Boolean
) {
    fun frameBytes() = frame.copyOf()
    fun encode(): ByteArray = Writer("GAD1").apply {
        fixed(binding, 96); id(frameId); i64(created); i64(expiry); i64(observed); i64(cursor); i64(leaseExpiry)
        bytes(frame, 60 * 1024, true); i32(if (published) 1 else 0)
    }.finish()

    fun requirePending(pending: PendingSignedEnvelope) {
        require(binding.copyOfRange(64, 96).contentEquals(GuardWire.sha256(pending.exactBytes))) { "different pending approval" }
    }
    fun requireBinding(pending: PendingSignedEnvelope, offer: EnrollmentOffer, claim: EnrollmentKeyClaim) {
        requirePending(pending)
        require(binding.copyOfRange(0, 64).contentEquals(EnrollmentWire.offerHash(offer) + EnrollmentWire.claimHash(claim))) { "delivery enrollment changed" }
        val approval = GuardWire.decodeSignedApproval(pending.exactBytes)
        require(approval.keyId == claim.approvalKeyId && approval.keyId == pending.keyId && approval.sequence == pending.sequence &&
            approval.authorityEpoch == offer.authorityEpoch && approval.deviceId == offer.deviceId && approval.deviceEpoch == offer.deviceEpoch &&
            claim.offerHash().contentEquals(EnrollmentWire.offerHash(offer))) { "delivery approval binding" }
        require(RelayReceive.P256DeviceSignatureVerifier.verify(claim.approvalKey().takeLast(65).toByteArray(),
            GuardWire.sha256(GuardWire.encodeApprovalSignatureInput(approval)), approval.signatureP1363)) { "stored approval signature" }
        if (frame.isNotEmpty()) require(RelayReceive.decodeFrame(frame).aad == aad(offer)) { "delivery frame binding" }
    }
    fun reservationBody(offer: EnrollmentOffer): ByteArray =
        "{\"frameId\":\"$frameId\",\"recipientKeyId\":\"${offer.encryptionKeyId}\",\"createdAt\":$created,\"expiresAt\":$expiry}".toByteArray(Charsets.US_ASCII)
    private fun aad(offer: EnrollmentOffer) = RelayFrameAad(2, offer.mailboxId, offer.encryptionKeyId, frameId, cursor, 0, created, expiry)

    fun seal(pending: PendingSignedEnvelope, offer: EnrollmentOffer, claim: EnrollmentKeyClaim,
        response: ByteArray, status: Int, now: Long): NativeApprovalAttempt {
        require(frame.isEmpty() && !published && now >= observed && now < expiry)
        requireBinding(pending, offer, claim)
        val prefix = "{\"frameId\":\"$frameId\",\"recipientKeyId\":\"${offer.encryptionKeyId}\",\"cursor\":"
        val pattern = Regex(Regex.escape(prefix) + "([1-9][0-9]{0,15})," +
            Regex.escape("\"createdAt\":$created,\"expiresAt\":$expiry,\"leaseExpiresAt\":") +
            "([1-9][0-9]{0,15}),\"status\":\"reserved\",\"nonAuthoritative\":true\\}")
        // Exact canonical shape emitted by the pinned Worker; no duplicate fields, aliases or permissive JSON coercions.
        require(status == 200 || status == 201)
        require(response.size <= 1024 && response.all { it.toInt() in 0..127 })
        val match = requireNotNull(pattern.matchEntire(response.toString(Charsets.US_ASCII))) { "reservation response" }
        val allocated = match.groupValues[1].toLong(); val lease = match.groupValues[2].toLong()
        require(allocated in 1..9_007_199_254_740_991L && lease > now && lease <= expiry && lease <= now + 60000) { "reservation range" }
        val reserved = NativeApprovalAttempt(binding, frameId, created, expiry, now, allocated, lease, ByteArray(0), false)
        val aad = GuardWire.encodeRelayFrameAssociatedData(reserved.aad(offer))
        val (enc, cipher) = HpkeP256.encrypt(offer.encryptionKey(), pending.exactBytes, aad,
            "guard-relay-approval-hpke-v1".toByteArray(Charsets.US_ASCII) + aad)
        val sealed = aad + ByteBuffer.allocate(4).putInt(enc.size).array() + enc + ByteBuffer.allocate(4).putInt(cipher.size).array() + cipher
        return NativeApprovalAttempt(binding, frameId, created, expiry, now, allocated, lease, sealed, false)
            .also { it.requireBinding(pending, offer, claim); it.encode() }
    }

    fun markPublished(response: ByteArray, status: Int, now: Long): NativeApprovalAttempt {
        require(frame.isNotEmpty() && now >= observed && now < expiry && status in listOf(200, 201))
        val expected = "{\"frameId\":\"$frameId\",\"duplicate\":${status == 200}}".toByteArray(Charsets.US_ASCII)
        require(response.contentEquals(expected)) { "publication response" }
        return NativeApprovalAttempt(binding, frameId, created, expiry, now, cursor, leaseExpiry, frame, true)
    }

    companion object {
        fun prepare(pending: PendingSignedEnvelope, offer: EnrollmentOffer, claim: EnrollmentKeyClaim, now: Long, profileExpiry: Long): NativeApprovalAttempt {
            val approval = GuardWire.decodeSignedApproval(pending.exactBytes)
            // An expired inner command can still be delivered for a signed Expired receipt, never re-signed.
            require(now >= approval.issuedUnixMillis && now >= offer.createdUnixMillis && now < profileExpiry)
            val end = minOf(Math.addExact(now, 7 * 86400000L), profileExpiry)
            val binding = EnrollmentWire.offerHash(offer) + EnrollmentWire.claimHash(claim) + GuardWire.sha256(pending.exactBytes)
            return NativeApprovalAttempt(binding, UUID.randomUUID().toString(), now, end, now, 0, 0, ByteArray(0), false)
                .also { it.requireBinding(pending, offer, claim); it.encode() }
        }
        fun decode(raw: ByteArray): NativeApprovalAttempt = Reader(raw, "GAD1").run {
            val binding = fixed(96); val id = id(); val created = nonNegative(); val expiry = nonNegative()
            val observed = nonNegative(); val cursor = nonNegative(); val lease = nonNegative(); val frame = bytes(60 * 1024, true)
            val status = i32(); require(status in 0..1); done()
            GuardWire.requireLifetime(created, expiry, 7 * 86400000L); require(observed in created until expiry)
            require(if (frame.isEmpty()) cursor == 0L && lease == 0L && status == 0 else
                cursor in 1..9_007_199_254_740_991L && lease in (created + 1)..expiry)
            NativeApprovalAttempt(binding, id, created, expiry, observed, cursor, lease, frame, status == 1)
                .also { require(it.encode().contentEquals(raw)) }
        }
    }
}
