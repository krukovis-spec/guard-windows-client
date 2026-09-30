package app.guard.parent.enrollment

import app.guard.parent.protocol.*
import java.io.*
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.time.Clock
import java.util.Base64

/** Local pending work, NEVER evidence that Windows accepted an owner. No QR secret/private key. */
class PendingEnrollment internal constructor(val offer: EnrollmentOffer, val claim: EnrollmentKeyClaim?,
    chain: List<ByteArray>, proof: ByteArray, signature: ByteArray, val abandoned: Boolean, val observedUnixMillis: Long) {
    private val certificates = chain.map { it.copyOf() }
    private val possession = proof.copyOf()
    private val signed = signature.copyOf()
    fun certificateChain() = certificates.map { it.copyOf() }
    fun possessionProof() = possession.copyOf()
    fun signature() = signed.copyOf()
    val isSigned get() = signed.size == 64
    val approvalAlias get() = "guard.parent.approval." + offerId(offer)
    val encryptionAlias get() = "guard.parent.encryption." + offerId(offer)

    init {
        EnrollmentWire.encodeOffer(offer)
        require(observedUnixMillis >= offer.createdUnixMillis)
        if (claim == null) require(certificates.isEmpty() && possession.isEmpty() && signed.isEmpty())
        else {
            EnrollmentWire.encodeClaimForSignature(claim)
            require(MessageDigest.isEqual(claim.offerHash(), EnrollmentWire.offerHash(offer))) { "offer binding" }
            val expectedId = "p256:" + Base64.getUrlEncoder().withoutPadding().encodeToString(GuardWire.sha256(claim.approvalKey()))
            require(claim.approvalKeyId == expectedId) { "approval key id" }
            require(setOf(offer.signingKeyId, offer.encryptionKeyId, claim.approvalKeyId, claim.encryptionKeyId).size == 4) { "key roles" }
            val points = listOf(offer.signingKey(), offer.encryptionKey(), claim.approvalKey().copyOfRange(26, 91), claim.encryptionKey())
            require(points.indices.all { a -> (0 until a).none { b -> points[a].contentEquals(points[b]) } }) { "key reuse" }
            require(certificates.size in 2..8 && certificates.all { it.size in 1..16384 } && certificates.sumOf { it.size } <= 65536)
            require(possession.size == 32 && (signed.isEmpty() || signed.size == 64))
            if (signed.isNotEmpty()) require(RelayReceive.P256DeviceSignatureVerifier.verify(points[2], EnrollmentWire.claimHash(claim), signed)) { "claim signature" }
        }
    }
}

internal fun offerId(offer: EnrollmentOffer) = EnrollmentWire.offerHash(offer).joinToString("") { "%02x".format(it) }

/** Production path: Context.noBackupFilesDir/enrollment. One Android process; no automatic pruning. */
class PendingEnrollmentStore(private val directory: File, private val clock: Clock = Clock.systemUTC()) {
    private companion object {
        // ponytail: bounded eight ceremonies and one process lock; signed reconciliation must precede future pruning.
        val lock = Any()
        const val MAX_BYTES = 70 * 1024
    }
    init { check(directory.isDirectory || directory.mkdirs()) { "enrollment storage unavailable" } }

    fun list(): List<PendingEnrollment> = synchronized(lock) {
        files().map { read(it).also { state -> require(it.name == offerId(state.offer) + ".bin") { "storage binding" } } }
    }

    fun load(offer: EnrollmentOffer): PendingEnrollment? = synchronized(lock) {
        val file = file(offer)
        if (!file.exists()) null else read(file).also {
            require(EnrollmentWire.encodeOffer(it.offer).contentEquals(EnrollmentWire.encodeOffer(offer))) { "storage binding" }
        }
    }

    fun prepare(offer: EnrollmentOffer): PendingEnrollment = synchronized(lock) {
        load(offer)?.let { requireUsable(it); return@synchronized it }
        // Read all existing records: corruption is not permission to start over and strand an old key.
        check(list().size < 8) { "enrollment reconciliation required" }
        val state = PendingEnrollment(offer, null, emptyList(), byteArrayOf(), byteArrayOf(), false, clock.millis())
        write(state); state
    }

    fun saveClaim(offer: EnrollmentOffer, claim: EnrollmentKeyClaim, chain: List<ByteArray>, proof: ByteArray): PendingEnrollment = synchronized(lock) {
        val old = requireNotNull(load(offer)); requireUsable(old)
        val next = PendingEnrollment(offer, claim, chain, proof, byteArrayOf(), false, clock.millis())
        require(next.observedUnixMillis >= old.observedUnixMillis) { "clock rollback" }
        if (old.claim != null) {
            require(EnrollmentWire.encodeClaimForSignature(old.claim).contentEquals(EnrollmentWire.encodeClaimForSignature(claim)) &&
                old.possessionProof().contentEquals(next.possessionProof()) && sameChain(old.certificateChain(), next.certificateChain())) { "pending claim differs" }
            requireUsable(old); return@synchronized old
        }
        write(next); next
    }

    fun saveSignature(offer: EnrollmentOffer, expectedClaimHash: ByteArray, signature: ByteArray): PendingEnrollment = synchronized(lock) {
        val old = requireNotNull(load(offer)); requireUsable(old)
        val claim = requireNotNull(old.claim)
        require(MessageDigest.isEqual(expectedClaimHash, EnrollmentWire.claimHash(claim))) { "different biometric operation" }
        if (old.isSigned) {
            require(old.signature().contentEquals(signature)) { "already signed; resend exact bytes" }
            requireUsable(old); return@synchronized old
        }
        val next = PendingEnrollment(offer, claim, old.certificateChain(), old.possessionProof(), signature, false, clock.millis())
        require(next.observedUnixMillis >= old.observedUnixMillis) { "clock rollback" }
        require(next.isSigned)
        write(next); next
    }

    fun requireUsable(state: PendingEnrollment) {
        val now = clock.millis()
        check(!state.abandoned && now >= state.observedUnixMillis && now in state.offer.createdUnixMillis until state.offer.expiryUnixMillis) { "expired, abandoned or clock rollback" }
    }

    fun forSend(offer: EnrollmentOffer): PendingEnrollment = synchronized(lock) {
        requireNotNull(load(offer)).also { requireUsable(it); check(it.isSigned) { "fresh biometric signature required" } }
    }

    /** Local stop only. Windows might already have committed: never delete keys or claim remote revocation. */
    fun abandon(offer: EnrollmentOffer): Unit = synchronized(lock) {
        val old = requireNotNull(load(offer))
        if (!old.abandoned) write(PendingEnrollment(offer, old.claim, old.certificateChain(), old.possessionProof(), old.signature(),
            true, maxOf(old.observedUnixMillis, clock.millis())), enforceDeadline = false)
    }

    private fun files(): List<File> {
        val result = requireNotNull(directory.listFiles { _, name -> name.endsWith(".bin") }).toList()
        require(result.size <= 8) { "enrollment storage count" }
        return result
    }
    private fun file(offer: EnrollmentOffer) = File(directory, offerId(offer) + ".bin")
    private fun sameChain(a: List<ByteArray>, b: List<ByteArray>) = a.size == b.size && a.indices.all { a[it].contentEquals(b[it]) }

    private fun read(file: File): PendingEnrollment {
        // Bound the actual read too, not only a racy stat. Android's sandbox, not this checksum, is the boundary.
        val all = FileInputStream(file).use { input ->
            val buffer = ByteArray(MAX_BYTES + 1); var count = 0
            while (count < buffer.size) { val n = input.read(buffer, count, buffer.size - count); if (n < 0) break; count += n }
            buffer.copyOf(count)
        }
        require(all.size in 64..MAX_BYTES) { "enrollment storage size" }
        val body = all.copyOfRange(0, all.size - 32)
        require(MessageDigest.isEqual(GuardWire.sha256(body), all.copyOfRange(body.size, all.size))) { "enrollment storage corrupt" }
        return DataInputStream(ByteArrayInputStream(body)).use { input ->
            fun bytes(max: Int): ByteArray {
                val n = input.readInt(); require(n in 0..max && n <= input.available())
                return ByteArray(n).also(input::readFully)
            }
            require(input.readInt() == 0x47454e31) { "enrollment storage version" }
            val offer = EnrollmentWire.decodeOffer(bytes(1536))
            val observed = input.readLong()
            val abandoned = input.readUnsignedByte().also { require(it in 0..1) } == 1
            val claimBytes = bytes(460)
            val count = input.readInt(); require(count in 0..8)
            val chain = List(count) { bytes(16384) }
            val proof = bytes(32); val signature = bytes(64)
            require(input.available() == 0) { "trailing enrollment storage" }
            PendingEnrollment(offer, if (claimBytes.isEmpty()) null else EnrollmentWire.decodeClaimForSignature(claimBytes), chain, proof, signature, abandoned, observed)
        }
    }

    private fun write(state: PendingEnrollment, enforceDeadline: Boolean = true) {
        val body = ByteArrayOutputStream().apply {
            DataOutputStream(this).apply {
                fun bytes(value: ByteArray) { writeInt(value.size); write(value) }
                writeInt(0x47454e31); bytes(EnrollmentWire.encodeOffer(state.offer)); writeLong(state.observedUnixMillis)
                writeByte(if (state.abandoned) 1 else 0)
                bytes(state.claim?.let(EnrollmentWire::encodeClaimForSignature) ?: byteArrayOf())
                val chain = state.certificateChain(); writeInt(chain.size); chain.forEach(::bytes)
                bytes(state.possessionProof()); bytes(state.signature())
            }
        }.toByteArray()
        require(body.size + 32 <= MAX_BYTES)
        if (enforceDeadline) requireUsable(state)
        val temporary = File.createTempFile("enrollment-", ".tmp", directory)
        try {
            FileOutputStream(temporary).use { it.write(body); it.write(GuardWire.sha256(body)); it.fd.sync() }
            if (enforceDeadline) requireUsable(state)
            Files.move(temporary.toPath(), file(state.offer).toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } finally { temporary.delete() }
    }
}
