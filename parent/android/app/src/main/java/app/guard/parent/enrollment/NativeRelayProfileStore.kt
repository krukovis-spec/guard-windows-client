package app.guard.parent.enrollment

import app.guard.parent.protocol.*
import java.io.*
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.time.Clock

/** App-private no-backup storage of HPKE ciphertext ONLY. Ceremony rechecks confirmed ownership/keys on every entry. */
internal class NativeRelayProfileStore(private val directory: File, private val clock: Clock = Clock.systemUTC()) {
    private companion object {
        // ponytail: same single Android process/eight-enrollment ceiling as PendingEnrollmentStore.
        val lock = Any()
        const val STORED_BYTES = 4 + 8 + 32 + NativeRelayProfile.FILE_BYTES
    }
    init { check(directory.isDirectory || directory.mkdirs()) { "native profile storage unavailable" } }

    fun install(offer: EnrollmentOffer, claim: EnrollmentKeyClaim, key: RelayEncryptionKey, bytes: ByteArray, trustedSha256: String): Unit = synchronized(lock) {
        val raw = bytes.copyOf(); val imported = clock.millis()
        NativeRelayProfile.open(raw, offer, claim, key, trustedSha256, imported).use { incoming ->
            open(offer, claim, key)?.use { existing ->
                require(existing.sameAs(incoming)) { "native profile already installed; explicit recovery required" }
                return@synchronized // Keep the first verified ciphertext, even if the same plaintext is re-encrypted.
            }
            check(requireNotNull(directory.listFiles()).count { it.extension == "bin" } < 8) { "native profile limit" }
            val stored = "GNS1".toByteArray(Charsets.US_ASCII) + ByteBuffer.allocate(8).putLong(imported).array() + GuardWire.sha256(raw) + raw
            val temporary = File.createTempFile("native-", ".tmp", directory)
            try {
                FileOutputStream(temporary).use { it.write(stored); it.fd.sync() }
                val now = clock.millis(); require(now >= imported) { "native profile clock rollback" }; incoming.requireCurrent(now)
                // One process lock and immutable target. No non-atomic fallback, replace, delete or auto-rekey.
                Files.move(temporary.toPath(), file(offer).toPath(), StandardCopyOption.ATOMIC_MOVE)
            } finally { temporary.delete() }
        }
    }

    fun open(offer: EnrollmentOffer, claim: EnrollmentKeyClaim, key: RelayEncryptionKey): NativeRelayProfile? = synchronized(lock) {
        val path = file(offer); if (!path.exists()) return@synchronized null
        require(path.length() == STORED_BYTES.toLong()) { "native profile storage size" }
        val raw = FileInputStream(path).use { stream ->
            ByteArray(STORED_BYTES).also { DataInputStream(stream).readFully(it); require(stream.read() == -1) { "native profile storage changed" } }
        }
        require(raw.copyOfRange(0, 4).contentEquals("GNS1".toByteArray(Charsets.US_ASCII))) { "native profile storage version" }
        val imported = ByteBuffer.wrap(raw, 4, 8).long; val now = clock.millis()
        require(imported >= offer.createdUnixMillis && now >= imported) { "native profile clock rollback" }
        // The digest is retained from explicit trusted import; the Android sandbox is its storage boundary.
        val digest = raw.copyOfRange(12, 44).joinToString("") { "%02x".format(it) }
        val result = NativeRelayProfile.open(raw.copyOfRange(44, raw.size), offer, claim, key, digest, now)
        try { require(imported >= result.preparedUnixMillis); val after = clock.millis(); require(after >= imported); result.requireCurrent(after); result }
        catch (error: Exception) { result.close(); throw error }
    }
    private fun file(offer: EnrollmentOffer) = File(directory, offerId(offer) + ".bin")
}
