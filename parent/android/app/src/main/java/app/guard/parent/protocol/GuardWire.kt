package app.guard.parent.protocol

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.text.Normalizer
import java.util.UUID

private const val VERSION = 1
private const val MAX_IDENTIFIER_BYTES = 128
private const val MAX_IDENTITY_BYTES = 2048
private const val MAX_EVIDENCE_NAME_BYTES = 48
private const val MAX_EVIDENCE_VALUE_BYTES = 512
private const val MAX_REASON_BYTES = 280
private const val MAX_EVIDENCE = 8
private const val MAX_BYTES = 64 * 1024
private const val DAY_MILLIS = 24L * 60 * 60 * 1000

enum class TargetKind(val wire: Int) { WEBSITE(1), APPLICATION(2);
    companion object { fun from(value: Int) = entries.singleOrNull { it.wire == value } ?: throw WireException("target kind") }
}
enum class ApprovalDecision(val wire: Int) { ALLOW_ALWAYS(1), ALLOW_TEMPORARY(2), ALLOW_DAILY_QUOTA(3), DENY(4);
    companion object { fun from(value: Int) = entries.singleOrNull { it.wire == value } ?: throw WireException("decision") }
}
enum class ReceiptStatus(val wire: Int) { APPLIED(1), ALREADY_RESOLVED(2), REJECTED(3), EXPIRED(4), ACCEPTED_PENDING_RECONCILIATION(5);
    companion object { fun from(value: Int) = entries.singleOrNull { it.wire == value } ?: throw WireException("receipt status") }
}

class WireException(message: String) : IllegalArgumentException(message)

data class Evidence(val name: String, val value: String)
data class RequestSnapshot(
    val deviceId: String, val deviceEpoch: Long, val deviceEventId: String,
    val requestId: String, val requestRevision: Long, val targetKind: TargetKind,
    val targetIdentity: String, val evidence: List<Evidence>, val reason: String,
    val createdUnixMillis: Long, val pendingExpiryUnixMillis: Long,
    val challenge: ByteArray, val policyRevision: Long
)

data class SignedApproval(
    val authorityEpoch: Long, val keyId: String, val sequence: Long,
    val commandId: String, val nonce: String, val issuedUnixMillis: Long, val expiryUnixMillis: Long,
    val deviceId: String, val deviceEpoch: Long, val requestId: String, val requestRevision: Long,
    val snapshotHash: ByteArray, val challenge: ByteArray, val targetKind: TargetKind,
    val targetIdentity: String, val policyRevision: Long, val decision: ApprovalDecision,
    val minutes: Int, val signatureP1363: ByteArray
)

data class CommandReceipt(
    val deviceId: String, val deviceEpoch: Long, val keyId: String, val sequence: Long,
    val commandId: String, val requestId: String, val requestRevision: Long, val status: ReceiptStatus,
    val processedUnixMillis: Long, val approvalHash: ByteArray, val committedPolicyRevision: Long,
    val reconciliation: Int, val detailCode: String
)

data class RelayFrameAad(
    val kind: Int, val mailboxId: String, val recipientKeyId: String, val frameId: String,
    val cursor: Long, val ack: Long, val createdUnixMillis: Long, val expiryUnixMillis: Long
)

object GuardWire {
    fun encodeRequestSnapshot(value: RequestSnapshot): ByteArray = Writer("GRRQ").apply {
        id(value.deviceId); positive(value.deviceEpoch); id(value.deviceEventId); id(value.requestId); positive(value.requestRevision)
        i32(value.targetKind.wire); text(value.targetIdentity, MAX_IDENTITY_BYTES, false); i32(value.evidence.size.also { require(it <= MAX_EVIDENCE) })
        value.evidence.forEach { text(it.name, MAX_EVIDENCE_NAME_BYTES, false); text(it.value, MAX_EVIDENCE_VALUE_BYTES, true) }; text(value.reason, MAX_REASON_BYTES, true)
        i64(value.createdUnixMillis); i64(value.pendingExpiryUnixMillis); fixed(value.challenge, 32); i64(value.policyRevision)
    }.finish()

    fun decodeRequestSnapshot(encoded: ByteArray): RequestSnapshot = Reader(encoded, "GRRQ").run {
        val value = RequestSnapshot(id(), positive(), id(), id(), positive(), TargetKind.from(i32()), text(MAX_IDENTITY_BYTES, false),
            List(i32().bounded(0, MAX_EVIDENCE)) { Evidence(text(MAX_EVIDENCE_NAME_BYTES, false), text(MAX_EVIDENCE_VALUE_BYTES, true)) }, text(MAX_REASON_BYTES, true), i64(), i64(), fixed(32), nonNegative())
        done(); validateSnapshot(value); value
    }

    fun encodeApprovalSignatureInput(value: SignedApproval): ByteArray = Writer("GRAP").apply {
        positive(value.authorityEpoch); id(value.keyId); positive(value.sequence); id(value.commandId); id(value.nonce)
        i64(value.issuedUnixMillis); i64(value.expiryUnixMillis); lifetime(value.issuedUnixMillis, value.expiryUnixMillis, 15 * 60 * 1000L)
        id(value.deviceId); positive(value.deviceEpoch); id(value.requestId); positive(value.requestRevision); fixed(value.snapshotHash, 32); fixed(value.challenge, 32)
        i32(value.targetKind.wire); text(value.targetIdentity, MAX_IDENTITY_BYTES, false); nonNegative(value.policyRevision); i32(value.decision.wire); i32(value.minutes)
    }.finish()

    fun encodeSignedApproval(value: SignedApproval): ByteArray {
        val input = encodeApprovalSignatureInput(value); require(value.signatureP1363.size == 64)
        return input + ByteBuffer.allocate(4).putInt(64).array() + value.signatureP1363
    }

    fun decodeSignedApproval(encoded: ByteArray): SignedApproval = Reader(encoded, "GRAP").run {
        val base = SignedApproval(positive(), id(), positive(), id(), id(), i64(), i64(), id(), positive(), id(), positive(), fixed(32), fixed(32),
            TargetKind.from(i32()), text(MAX_IDENTITY_BYTES, false), nonNegative(), ApprovalDecision.from(i32()), i32(), bytes(64, false))
        done(); validateApproval(base); base
    }

    fun encodeCommandReceipt(value: CommandReceipt): ByteArray = Writer("GRRC").apply {
        id(value.deviceId); positive(value.deviceEpoch); id(value.keyId); positive(value.sequence); id(value.commandId)
        id(value.requestId); positive(value.requestRevision); i32(value.status.wire); i64(value.processedUnixMillis)
        fixed(value.approvalHash, 32); nonNegative(value.committedPolicyRevision); i32(value.reconciliation); id(value.detailCode)
    }.finish()

    fun encodeRelayFrameAssociatedData(value: RelayFrameAad): ByteArray = Writer("GRF1").apply {
        require(value.kind in 1..4 && value.cursor >= 0 && value.ack >= 0 && value.ack <= value.cursor)
        i32(value.kind); id(value.mailboxId); id(value.recipientKeyId); id(value.frameId); i64(value.cursor); i64(value.ack)
        i64(value.createdUnixMillis); i64(value.expiryUnixMillis); lifetime(value.createdUnixMillis, value.expiryUnixMillis, 7 * DAY_MILLIS)
    }.finish()

    fun sha256(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)

    private fun validateSnapshot(value: RequestSnapshot) {
        require(value.deviceEpoch > 0 && value.requestRevision > 0 && value.policyRevision >= 0)
        lifetime(value.createdUnixMillis, value.pendingExpiryUnixMillis, 7 * DAY_MILLIS)
    }
    fun validateApproval(value: SignedApproval) {
        require(value.authorityEpoch > 0 && value.sequence > 0 && value.deviceEpoch > 0 && value.requestRevision > 0 && value.policyRevision >= 0)
        lifetime(value.issuedUnixMillis, value.expiryUnixMillis, 15 * 60 * 1000L)
        val timed = value.decision == ApprovalDecision.ALLOW_TEMPORARY || value.decision == ApprovalDecision.ALLOW_DAILY_QUOTA
        require(if (timed) value.minutes in 1..1440 else value.minutes == 0)
    }
    private fun lifetime(start: Long, end: Long, max: Long) { require(end > start && end - start <= max) { "lifetime" } }
}

private class Writer(magic: String) {
    private val out = ByteArrayOutputStream()
    init { out.write(magic.toByteArray(Charsets.US_ASCII)); i32(VERSION) }
    fun i32(value: Int) { out.write(ByteBuffer.allocate(4).putInt(value).array()) }
    fun i64(value: Long) { out.write(ByteBuffer.allocate(8).putLong(value).array()) }
    fun id(value: String) { require(canonicalId(value)); text(value, MAX_IDENTIFIER_BYTES, false) }
    fun text(value: String, maxBytes: Int, empty: Boolean) { val bytes = canonicalText(value, empty).toByteArray(Charsets.UTF_8); require(bytes.size <= maxBytes); i32(bytes.size); out.write(bytes) }
    fun positive(value: Long) { require(value > 0); i64(value) }
    fun nonNegative(value: Long) { require(value >= 0); i64(value) }
    fun fixed(value: ByteArray, expected: Int) { require(value.size == expected); out.write(value) }
    fun bytes(value: ByteArray, max: Int, empty: Boolean) { require(value.size <= max && (empty || value.isNotEmpty())); i32(value.size); out.write(value) }
    fun finish(): ByteArray = out.toByteArray().also { require(it.size <= MAX_BYTES) { "oversized relay message" } }
}

private class Reader(private val raw: ByteArray, magic: String) {
    private var position = 0
    init { require(raw.size <= MAX_BYTES); require(String(take(4), Charsets.US_ASCII) == magic); require(i32() == VERSION) }
    fun i32(): Int = ByteBuffer.wrap(take(4)).int
    fun i64(): Long = ByteBuffer.wrap(take(8)).long
    fun text(maxBytes: Int, empty: Boolean): String { val size = i32().bounded(if (empty) 0 else 1, maxBytes); val data = take(size); return decodeStrictUtf8(data).also { require(it == canonicalText(it, empty)) } }
    fun id(): String = text(MAX_IDENTIFIER_BYTES, false).also { require(canonicalId(it)) }
    fun positive(): Long = i64().also { require(it > 0) }
    fun nonNegative(): Long = i64().also { require(it >= 0) }
    fun fixed(length: Int): ByteArray = take(length)
    fun bytes(max: Int, empty: Boolean): ByteArray { val size = i32().bounded(if (empty) 0 else 1, max); return take(size) }
    fun done() { require(position == raw.size) { "trailing bytes" } }
    private fun take(length: Int): ByteArray { require(length >= 0 && position + length <= raw.size) { "truncated" }; return raw.copyOfRange(position, position + length).also { position += length } }
}

private fun Int.bounded(minimum: Int, maximum: Int): Int { require(this in minimum..maximum) { "length" }; return this }
private fun canonicalText(value: String, empty: Boolean): String {
    require((empty || value.isNotEmpty()) && value.none { it.code < 0x20 || it == '\u007f' }) { "text" }
    return Normalizer.normalize(value, Normalizer.Form.NFC)
}
private fun canonicalId(value: String): Boolean = value.length in 16..128 && value.all { it.isAsciiLetterOrDigit() || it == '-' || it == '_' || it == '.' || it == ':' }
private fun Char.isAsciiLetterOrDigit() = this in 'a'..'z' || this in 'A'..'Z' || this in '0'..'9'
private fun decodeStrictUtf8(bytes: ByteArray): String = try {
    Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
} catch (_: CharacterCodingException) { throw WireException("utf8") }
