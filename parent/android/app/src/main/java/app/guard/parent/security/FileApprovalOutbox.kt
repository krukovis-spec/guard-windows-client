package app.guard.parent.security

import app.guard.parent.protocol.GuardWire
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
    private data class State(val next: Long = 1, val pending: PendingSignedEnvelope? = null)
    init { check(directory.isDirectory || directory.mkdirs()) { "approval storage unavailable" } }

    override fun load(keyId: String): PendingSignedEnvelope? = synchronized(storageLock) { read(keyId).pending }
    override fun nextSequence(keyId: String): Long = synchronized(storageLock) { read(keyId).next }

    override fun save(envelope: PendingSignedEnvelope): Unit = synchronized(storageLock) {
        val state = read(envelope.keyId)
        require(envelope.sequence == state.next && envelope.sequence < Long.MAX_VALUE) { "sequence" }
        val decoded = GuardWire.decodeSignedApproval(envelope.exactBytes)
        require(decoded.keyId == envelope.keyId && decoded.sequence == envelope.sequence) { "envelope metadata" }
        require(state.pending == null || state.pending.exactBytes.contentEquals(envelope.exactBytes)) { "pending approval differs" }
        if (state.pending == null) write(envelope.keyId, State(state.next, envelope))
    }

    override fun complete(envelope: PendingSignedEnvelope): Unit = synchronized(storageLock) {
        val state = read(envelope.keyId)
        require(state.pending?.sequence == envelope.sequence && state.pending.exactBytes.contentEquals(envelope.exactBytes)) { "pending approval differs" }
        write(envelope.keyId, State(Math.addExact(envelope.sequence, 1)))
    }

    private fun file(keyId: String): File {
        require(keyId.matches(Regex("[A-Za-z0-9._:-]{16,128}"))) { "key id" }
        return File(directory, GuardWire.sha256(keyId.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) } + ".bin")
    }

    private fun read(keyId: String): State {
        val path = file(keyId)
        if (!path.exists()) return State()
        require(path.length() in 48..(65536 + 48)) { "approval storage size" }
        val all = path.readBytes()
        val body = all.copyOfRange(0, all.size - 32)
        // Corruption detection, not an authentication boundary; Android's app sandbox owns this directory.
        require(java.security.MessageDigest.isEqual(GuardWire.sha256(body), all.copyOfRange(body.size, all.size))) { "approval storage corrupt" }
        return DataInputStream(ByteArrayInputStream(body)).use { input ->
            require(input.readInt() == 0x474f4231) { "approval storage version" }
            val next = input.readLong(); require(next > 0)
            val size = input.readInt(); require(size in 0..65536 && input.available() == size)
            val bytes = ByteArray(size).also(input::readFully)
            val pending = if (size == 0) null else {
                val decoded = GuardWire.decodeSignedApproval(bytes)
                require(decoded.keyId == keyId && decoded.sequence == next) { "approval storage binding" }
                PendingSignedEnvelope(keyId, next, bytes)
            }
            State(next, pending)
        }
    }

    private fun write(keyId: String, state: State) {
        val bytes = ByteArrayOutputStream().apply {
            DataOutputStream(this).apply {
                writeInt(0x474f4231); writeLong(state.next)
                val pending = state.pending?.exactBytes ?: ByteArray(0)
                writeInt(pending.size); write(pending)
            }
        }.toByteArray()
        val target = file(keyId)
        val temporary = File.createTempFile("pending-", ".tmp", directory)
        try {
            FileOutputStream(temporary).use { it.write(bytes); it.write(GuardWire.sha256(bytes)); it.fd.sync() }
            // No non-atomic fallback: a storage failure must not reset the signing sequence.
            Files.move(temporary.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } finally { temporary.delete() }
    }
}
