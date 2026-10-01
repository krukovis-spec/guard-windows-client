package app.guard.parent.security

import app.guard.parent.protocol.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/** Construct under Context.noBackupFilesDir, never shared/external storage. No signing keys are exported. */
class FileApprovalOutbox(private val directory: File) : ApprovalOutbox {
    // ponytail: one process-wide lock; use an OS file lock if the app ever gains multiple processes.
    private companion object { val storageLock = Any() }
    private data class State(val next: Long = 1, val pending: PendingSignedEnvelope? = null,
        val delivery: NativeApprovalAttempt? = null, val receipt: SavedApprovalReceipt? = null)
    init { check(directory.isDirectory || directory.mkdirs()) { "approval storage unavailable" } }

    override fun load(keyId: String): PendingSignedEnvelope? = synchronized(storageLock) { read(keyId).pending }
    override fun nextSequence(keyId: String): Long = synchronized(storageLock) { read(keyId).next }
    override fun lastReceipt(keyId: String): SavedApprovalReceipt? = synchronized(storageLock) { read(keyId).receipt }

    internal fun delivery(pending: PendingSignedEnvelope): NativeApprovalAttempt? = synchronized(storageLock) {
        val state = read(pending.keyId)
        require(state.pending?.exactBytes?.contentEquals(pending.exactBytes) == true) { "pending approval changed" }
        state.delivery
    }

    internal fun saveDelivery(pending: PendingSignedEnvelope, expected: NativeApprovalAttempt?, next: NativeApprovalAttempt,
        beforeCommit: () -> Unit): Unit = synchronized(storageLock) {
        val state = read(pending.keyId)
        require(state.pending?.exactBytes?.contentEquals(pending.exactBytes) == true) { "pending approval changed" }
        require(if (expected == null) state.delivery == null else state.delivery?.encode()?.contentEquals(expected.encode()) == true) { "delivery changed" }
        next.requirePending(pending)
        write(pending.keyId, state.copy(delivery = next), beforeCommit)
    }

    override fun save(envelope: PendingSignedEnvelope, beforeCommit: () -> Unit): Unit = synchronized(storageLock) {
        val state = read(envelope.keyId)
        require(envelope.sequence == state.next && envelope.sequence < Long.MAX_VALUE) { "sequence" }
        val decoded = GuardWire.decodeSignedApproval(envelope.exactBytes)
        require(decoded.keyId == envelope.keyId && decoded.sequence == envelope.sequence) { "envelope metadata" }
        require(state.pending == null || state.pending.exactBytes.contentEquals(envelope.exactBytes)) { "pending approval differs" }
        if (state.pending == null) require(decoded.issuedUnixMillis >= (state.receipt?.observed ?: 0)) { "approval clock rollback" }
        if (state.pending == null) write(envelope.keyId, state.copy(pending = envelope), beforeCommit) else beforeCommit()
    }

    override fun acceptReceipt(rawFrame: ByteArray, recipient: RelayRecipient, trust: RelayDeviceTrust, now: Long,
        beforeCommit: () -> Unit): CommandReceipt = synchronized(storageLock) {
        val raw = rawFrame.copyOf()
        val incoming = RelayReceive.receiveReceipt(raw, recipient, trust, now).receipt
        val state = read(incoming.keyId)
        val previous = state.receipt
        require(now >= (previous?.observed ?: 0)) { "receipt clock rollback" }
        val pending = state.pending?.takeIf { it.sequence == incoming.sequence }
            ?: previous?.pending?.takeIf { it.sequence == incoming.sequence } ?: error("no matching approval")
        val record = SavedApprovalReceipt.receive(raw, pending, recipient, trust, now)
        val receipt = incoming // Same immutable raw bytes were bound to this pending command by receive().
        if (previous != null && previous.pending.sequence == pending.sequence) {
            val old = previous.verify(recipient, trust, now)
            val equal = GuardWire.encodeCommandReceipt(old).contentEquals(GuardWire.encodeCommandReceipt(receipt))
            if (old.status != ReceiptStatus.ACCEPTED_PENDING_RECONCILIATION) {
                // Late interim delivery cannot undo a terminal receipt or affect a newer queued approval.
                require(equal || receipt.status == ReceiptStatus.ACCEPTED_PENDING_RECONCILIATION) { "conflicting terminal receipt" }
                beforeCommit(); return@synchronized old
            }
            if (equal) { beforeCommit(); return@synchronized old }
            if (receipt.status == ReceiptStatus.ACCEPTED_PENDING_RECONCILIATION &&
                (receipt.processedUnixMillis < old.processedUnixMillis || receipt.committedPolicyRevision < old.committedPolicyRevision)) {
                // Polling restarts from zero after Activity/process loss; historical interim frames must not block a later terminal one.
                beforeCommit(); return@synchronized old
            }
            require(receipt.processedUnixMillis >= old.processedUnixMillis &&
                receipt.committedPolicyRevision >= old.committedPolicyRevision) { "receipt regression" }
        }
        require(state.pending?.exactBytes?.contentEquals(pending.exactBytes) == true) { "pending approval changed" }
        val next = if (receipt.status == ReceiptStatus.ACCEPTED_PENDING_RECONCILIATION) state.copy(receipt = record)
            else State(Math.addExact(pending.sequence, 1), receipt = record)
        write(pending.keyId, next, beforeCommit)
        receipt
    }

    private fun file(keyId: String): File {
        require(keyId.matches(Regex("[A-Za-z0-9._:-]{16,128}"))) { "key id" }
        return File(directory, GuardWire.sha256(keyId.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) } + ".bin")
    }

    private fun read(keyId: String): State {
        val path = file(keyId)
        if (!path.exists()) return State()
        require(path.length() in 48..(3 * 65536 + 56)) { "approval storage size" }
        val all = path.readBytes()
        val body = all.copyOfRange(0, all.size - 32)
        // Corruption detection, not an authentication boundary; Android's app sandbox owns this directory.
        require(java.security.MessageDigest.isEqual(GuardWire.sha256(body), all.copyOfRange(body.size, all.size))) { "approval storage corrupt" }
        return DataInputStream(ByteArrayInputStream(body)).use { input ->
            val version = input.readInt(); require(version in 0x474f4231..0x474f4233) { "approval storage version" }
            val next = input.readLong(); require(next > 0)
            val size = input.readInt(); require(size in 0..65536 && input.available() >= size)
            val bytes = ByteArray(size).also(input::readFully)
            val pending = if (size == 0) null else {
                val decoded = GuardWire.decodeSignedApproval(bytes)
                require(decoded.keyId == keyId && decoded.sequence == next) { "approval storage binding" }
                PendingSignedEnvelope(keyId, next, bytes)
            }
            val delivery = if (version >= 0x474f4232) {
                val length = input.readInt(); require(length in 0..65536 && input.available() >= length)
                if (length == 0) null else NativeApprovalAttempt.decode(ByteArray(length).also(input::readFully))
                    .also { it.requirePending(requireNotNull(pending)) }
            } else null
            val receipt = if (version == 0x474f4233) {
                val length = input.readInt(); require(length in 0..65536 && input.available() == length)
                if (length == 0) null else SavedApprovalReceipt.decode(ByteArray(length).also(input::readFully)).also {
                    require(it.pending.keyId == keyId && (it.pending.sequence == next - 1 ||
                        it.pending.sequence == next && pending?.exactBytes?.contentEquals(it.pending.exactBytes) == true)) { "saved receipt binding" }
                }
            } else null
            require(input.available() == 0)
            State(next, pending, delivery, receipt)
        }
    }

    private fun write(keyId: String, state: State, beforeCommit: () -> Unit = {}) {
        val bytes = ByteArrayOutputStream().apply {
            DataOutputStream(this).apply {
                writeInt(0x474f4233); writeLong(state.next)
                val pending = state.pending?.exactBytes ?: ByteArray(0)
                writeInt(pending.size); write(pending)
                val delivery = state.delivery?.encode() ?: ByteArray(0)
                writeInt(delivery.size); write(delivery)
                val receipt = state.receipt?.encode() ?: ByteArray(0)
                writeInt(receipt.size); write(receipt)
            }
        }.toByteArray()
        val target = file(keyId)
        val temporary = File.createTempFile("pending-", ".tmp", directory)
        try {
            FileOutputStream(temporary).use { it.write(bytes); it.write(GuardWire.sha256(bytes)); it.fd.sync() }
            beforeCommit()
            // No non-atomic fallback: a storage failure must not reset the signing sequence.
            Files.move(temporary.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } finally { temporary.delete() }
    }
}
