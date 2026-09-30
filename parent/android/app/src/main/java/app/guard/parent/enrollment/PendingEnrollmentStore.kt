package app.guard.parent.enrollment

import app.guard.parent.protocol.*
import java.io.*
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.time.Clock
import java.util.Base64

/** Local work/evidence; raw fields NEVER establish ownership without signature verification. No QR secret/private key. */
class PendingEnrollment internal constructor(val offer: EnrollmentOffer, val claim: EnrollmentKeyClaim?,
    chain: List<ByteArray>, proof: ByteArray, signature: ByteArray, val abandoned: Boolean, val observedUnixMillis: Long,
    capability: ByteArray = byteArrayOf(), request: ByteArray = byteArrayOf(), val queuedUnixMillis: Long = 0,
    reply: ByteArray = byteArrayOf(), replyNonce: ByteArray = byteArrayOf(), val receivedUnixMillis: Long = 0) {
    private val certificates = chain.map { it.copyOf() }
    private val possession = proof.copyOf()
    private val signed = signature.copyOf()
    private val transportToken = capability.copyOf()
    private val outgoing = request.copyOf()
    private val incoming = reply.copyOf()
    private val incomingNonce = replyNonce.copyOf()
    fun certificateChain() = certificates.map { it.copyOf() }
    fun possessionProof() = possession.copyOf()
    fun signature() = signed.copyOf()
    internal fun capability() = transportToken.copyOf()
    internal fun request() = outgoing.copyOf()
    internal fun reply() = incoming.copyOf()
    internal fun replyNonce() = incomingNonce.copyOf()
    val isSigned get() = signed.size == 64
    val approvalAlias get() = "guard.parent.approval." + offerId(offer)
    val encryptionAlias get() = "guard.parent.encryption." + offerId(offer)

    init {
        EnrollmentWire.encodeOffer(offer)
        require(observedUnixMillis >= offer.createdUnixMillis)
        require(transportToken.isEmpty() || transportToken.size == 32)
        require(outgoing.size <= EnrollmentExchange.MAX_BYTES && incoming.size <= 414)
        if (outgoing.isEmpty()) require(queuedUnixMillis == 0L)
        else {
            require(isSigned && transportToken.size == 32 && queuedUnixMillis in offer.createdUnixMillis..observedUnixMillis)
            EnrollmentExchange.requestMetadata(outgoing, offer, requireNotNull(claim))
        }
        if (incoming.isEmpty()) require(incomingNonce.isEmpty() && receivedUnixMillis == 0L)
        else require(isSigned && incomingNonce.size == 32 && receivedUnixMillis in offer.createdUnixMillis..observedUnixMillis)
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

    internal fun withDelivery(observed: Long, capability: ByteArray = capability(), request: ByteArray = request(),
        queued: Long = queuedUnixMillis, reply: ByteArray = reply(), nonce: ByteArray = replyNonce(), received: Long = receivedUnixMillis,
        abandoned: Boolean = this.abandoned) = PendingEnrollment(offer, claim, certificateChain(), possessionProof(), signature(),
            abandoned, observed, capability, request, queued, reply, nonce, received)
}

internal fun offerId(offer: EnrollmentOffer) = EnrollmentWire.offerHash(offer).joinToString("") { "%02x".format(it) }

/** Production path: Context.noBackupFilesDir/enrollment. One Android process; no automatic pruning. */
class PendingEnrollmentStore(private val directory: File, private val clock: Clock = Clock.systemUTC()) {
    private companion object {
        // ponytail: bounded eight ceremonies and one process lock; signed reconciliation must precede future pruning.
        val lock = Any()
        const val MAX_BYTES = 144 * 1024 // claim/certificates plus one sealed request, never an unbounded queue
        const val RETENTION_MILLIS = 24 * 60 * 60 * 1000L
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
        val next = PendingEnrollment(offer, claim, chain, proof, byteArrayOf(), false, clock.millis(), old.capability())
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
        val next = PendingEnrollment(offer, claim, old.certificateChain(), old.possessionProof(), signature, false, clock.millis(), old.capability())
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

    internal fun saveCapability(offer: EnrollmentOffer, capability: ByteArray): PendingEnrollment = synchronized(lock) {
        require(capability.size == 32)
        val old = requireNotNull(load(offer)); requireUsable(old)
        if (old.capability().isNotEmpty()) {
            require(MessageDigest.isEqual(old.capability(), capability)) { "different relay capability" }
            return@synchronized old
        }
        old.withDelivery(clock.millis(), capability = capability).also {
            require(it.observedUnixMillis >= old.observedUnixMillis) { "clock rollback" }
            write(it)
        }
    }

    /** Reverify stored evidence at its original verification time, not at today's expired reply deadline. */
    private fun verifiedResult(state: PendingEnrollment, key: RelayEncryptionKey): EnrollmentResult? {
        check(clock.millis() >= state.observedUnixMillis) { "clock rollback" }
        require(key.publicKeySec1().contentEquals(requireNotNull(state.claim).encryptionKey())) { "enrollment key changed" }
        if (state.reply().isEmpty()) return null
        val result = EnrollmentExchange.receive(state.reply(), state.offer, state.claim, key, state.replyNonce(), state.receivedUnixMillis)
        check(clock.millis() >= state.observedUnixMillis) { "clock rollback during verification" }
        return result
    }

    internal fun lastResult(offer: EnrollmentOffer, key: RelayEncryptionKey): EnrollmentResult? = synchronized(lock) {
        verifiedResult(requireNotNull(load(offer)), key)
    }

    /** Persist BEFORE HTTP. Exact bytes are retried; a new request always gets a new nonce. */
    internal fun nextRequest(offer: EnrollmentOffer, key: RelayEncryptionKey): PendingEnrollment = synchronized(lock) {
        val old = requireNotNull(load(offer)); check(old.isSigned)
        check(old.capability().size == 32) { "scan original live QR or recover; transport credential missing" }
        val result = verifiedResult(old, key)
        check(result?.outcome != EnrollmentExchange.CONFIRMED) { "enrollment already confirmed" }
        val now = clock.millis()
        check(now >= old.observedUnixMillis && now - offer.expiryUnixMillis < RETENTION_MILLIS) { "enrollment reconciliation required" }
        val active = !old.abandoned && now < offer.expiryUnixMillis
        if (old.request().isNotEmpty()) {
            val kind = EnrollmentExchange.requestMetadata(old.request(), offer, requireNotNull(old.claim)).first
            if (now - old.queuedUnixMillis < 60000 && (kind == 3 || active)) return@synchronized old
        }
        val claim = requireNotNull(old.claim); val nonce = EnrollmentExchange.newNonce()
        val raw = when {
            !active -> EnrollmentExchange.query(offer, claim, nonce)
            result == null -> EnrollmentExchange.claim(offer, claim, old.certificateChain(), old.possessionProof(), old.signature(), nonce)
            result.outcome == EnrollmentExchange.NEEDS_PHONE_PROOF && now < result.expiryUnixMillis -> {
                val proof = EnrollmentWire.answerKeyConfirmation(claim, key, result.encapsulatedKey(), result.encryptedChallenge())
                try { EnrollmentExchange.keyProof(offer, claim, proof, nonce) } finally { proof.fill(0) }
            }
            else -> EnrollmentExchange.query(offer, claim, nonce)
        }
        val next = old.withDelivery(now, request = raw, queued = now)
        write(next, enforceDeadline = false) { requireSendable(next) }; next
    }

    /** Transport calls this again immediately before I/O; local abandon cannot mint another claim. */
    internal fun requireSendable(state: PendingEnrollment) {
        val now = clock.millis()
        check(now >= state.observedUnixMillis && now - state.queuedUnixMillis < 60000 &&
            now - state.offer.expiryUnixMillis < RETENTION_MILLIS) { "stale enrollment delivery" }
        val kind = EnrollmentExchange.requestMetadata(state.request(), state.offer, requireNotNull(state.claim)).first
        if (kind != 3) requireUsable(state)
    }

    /** Only exact outstanding nonce + device signature can publish a result; HTTP success cannot. */
    internal fun acceptReply(offer: EnrollmentOffer, raw: ByteArray, key: RelayEncryptionKey): EnrollmentResult = synchronized(lock) {
        require(raw.size in 193..414)
        val reply = raw.copyOf()
        val old = requireNotNull(load(offer)); check(old.isSigned)
        val previous = verifiedResult(old, key)
        if (reply.contentEquals(old.reply()) && previous != null) return@synchronized previous
        check(old.request().isNotEmpty()) { "no outstanding enrollment request" }
        val nonce = EnrollmentExchange.requestMetadata(old.request(), offer, requireNotNull(old.claim)).second
        val now = clock.millis(); check(now >= old.observedUnixMillis) { "clock rollback" }
        val result = EnrollmentExchange.receive(reply, offer, old.claim, key, nonce, now)
        if (previous != null) {
            require(result.stateVersion >= previous.stateVersion && result.outcome >= previous.outcome) { "enrollment result regression" }
            if (result.stateVersion == previous.stateVersion) require(result.outcome == previous.outcome &&
                result.encapsulatedKey().contentEquals(previous.encapsulatedKey()) &&
                result.encryptedChallenge().contentEquals(previous.encryptedChallenge())) { "same version changed" }
        }
        val next = old.withDelivery(now, request = byteArrayOf(), queued = 0, reply = reply, nonce = nonce, received = now)
        write(next, enforceDeadline = false) {
            check(clock.millis() in maxOf(now, result.issuedUnixMillis) until result.expiryUnixMillis) { "reply expired during commit" }
        }
        result
    }

    /** Local stop only. Windows might already have committed: never delete keys or claim remote revocation. */
    fun abandon(offer: EnrollmentOffer): Unit = synchronized(lock) {
        val old = requireNotNull(load(offer))
        if (!old.abandoned) write(old.withDelivery(maxOf(old.observedUnixMillis, clock.millis()),
            request = byteArrayOf(), queued = 0, abandoned = true), enforceDeadline = false)
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
            val version = input.readInt(); require(version == 0x47454e31 || version == 0x47454e32) { "enrollment storage version" }
            val offer = EnrollmentWire.decodeOffer(bytes(1536))
            val observed = input.readLong()
            val abandoned = input.readUnsignedByte().also { require(it in 0..1) } == 1
            val claimBytes = bytes(460)
            val count = input.readInt(); require(count in 0..8)
            val chain = List(count) { bytes(16384) }
            val proof = bytes(32); val signature = bytes(64)
            val capability = if (version == 0x47454e32) bytes(32) else byteArrayOf()
            val request = if (version == 0x47454e32) bytes(EnrollmentExchange.MAX_BYTES) else byteArrayOf()
            val queued = if (version == 0x47454e32) input.readLong() else 0
            val reply = if (version == 0x47454e32) bytes(414) else byteArrayOf()
            val nonce = if (version == 0x47454e32) bytes(32) else byteArrayOf()
            val received = if (version == 0x47454e32) input.readLong() else 0
            require(input.available() == 0) { "trailing enrollment storage" }
            PendingEnrollment(offer, if (claimBytes.isEmpty()) null else EnrollmentWire.decodeClaimForSignature(claimBytes), chain, proof, signature,
                abandoned, observed, capability, request, queued, reply, nonce, received)
        }
    }

    private fun write(state: PendingEnrollment, enforceDeadline: Boolean = true, guard: () -> Unit = {}) {
        val body = ByteArrayOutputStream().apply {
            DataOutputStream(this).apply {
                fun bytes(value: ByteArray) { writeInt(value.size); write(value) }
                writeInt(0x47454e32); bytes(EnrollmentWire.encodeOffer(state.offer)); writeLong(state.observedUnixMillis)
                writeByte(if (state.abandoned) 1 else 0)
                bytes(state.claim?.let(EnrollmentWire::encodeClaimForSignature) ?: byteArrayOf())
                val chain = state.certificateChain(); writeInt(chain.size); chain.forEach(::bytes)
                bytes(state.possessionProof()); bytes(state.signature())
                bytes(state.capability()); bytes(state.request()); writeLong(state.queuedUnixMillis)
                bytes(state.reply()); bytes(state.replyNonce()); writeLong(state.receivedUnixMillis)
            }
        }.toByteArray()
        require(body.size + 32 <= MAX_BYTES)
        if (enforceDeadline) requireUsable(state)
        guard()
        val temporary = File.createTempFile("enrollment-", ".tmp", directory)
        try {
            FileOutputStream(temporary).use { it.write(body); it.write(GuardWire.sha256(body)); it.fd.sync() }
            if (enforceDeadline) requireUsable(state)
            guard()
            Files.move(temporary.toPath(), file(state.offer).toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } finally { temporary.delete() }
    }
}
