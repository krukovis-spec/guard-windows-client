package app.guard.parent

import app.guard.parent.enrollment.*
import app.guard.parent.protocol.*
import app.guard.parent.security.EcdsaP1363
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.security.*
import java.time.*
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*

/** Real files and JCA signatures, NOT Android hardware/attestation/biometric evidence. */
class EnrollmentLifecycleTest {
    @TempDir lateinit var directory: File
    private val start = 1790769600000L
    private val clock = TestClock(start)
    private val store get() = PendingEnrollmentStore(directory, clock)
    private val generator = hex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    private val encryption = hex("04c06b4f6bebc7bb495cb797ab753f911aff80aefb86fd8b6fcc35525f3ab5f03e0b21bd31a86c6048af3cb2d98e0d3bf01da5cc4c39ff5370d331a4f1f7d5a4e0")
    private fun offer(id: String = "enrollment-alpha1") = EnrollmentOffer("https://relay.example.test", id, "device-alpha-0001", "Тестовый ПК",
        2, 4, "mailbox-alpha-0001", "device-signing-0001", ExchangeVector.bytes("device.public"), "device-encrypt-001", generator,
        start, start + 300000, GuardWire.sha256("independent public enrollment challenge".toByteArray()))
    private val secret = ByteArray(32) { (it + 1).toByte() }
    private fun qr(offer: EnrollmentOffer) = "guard-enroll://v2?offer=" + b64(EnrollmentWire.encodeOffer(offer)) + "&secret=" + b64(secret)
    private fun ready(offer: EnrollmentOffer = offer()): PendingEnrollment {
        store.prepare(offer)
        val spki = hex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + ExchangeVector.bytes("recipient.public")
        val claim = EnrollmentKeyClaim(EnrollmentWire.offerHash(offer), "p256:" + b64(GuardWire.sha256(spki)), spki, "parent-encrypt-01", encryption)
        val proof = EnrollmentQrParser.parse(qr(offer), EnrollmentRelayBinding(offer.relayEndpoint), clock.millis()).use { it.proofFor(claim) }
        // Certificate bytes are deliberately not attested: Android persistence is not the Windows verifier.
        return store.saveClaim(offer, claim, listOf(byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6)), proof)
    }
    private fun signature() = Signature.getInstance("SHA256withECDSA").apply { initSign(ExchangeVector.key.privateKey()) }
    private fun signed(state: PendingEnrollment): PendingEnrollment {
        val operation = EnrollmentSigningOperation(store, state, signature())
        return operation.finish(operation.signature)
    }

    @Test fun `restart retains prepared claim and exact signed retry without persisting QR secret`() {
        val offer = offer()
        val prepared = store.prepare(offer)
        assertNull(store.load(offer)!!.claim)
        assertFalse(prepared.approvalAlias == "guard.parent.approval.v1")
        val ready = ready(offer)
        assertThrows(IllegalStateException::class.java) { store.forSend(offer) }
        val completed = signed(ready)
        val resumed = store.forSend(offer)
        assertArrayEquals(completed.signature(), resumed.signature())
        assertArrayEquals(completed.possessionProof(), resumed.possessionProof())
        assertArrayEquals(EnrollmentWire.encodeClaimForSignature(completed.claim!!), EnrollmentWire.encodeClaimForSignature(resumed.claim!!))
        assertArrayEquals(completed.signature(), store.prepare(offer).signature())
        resumed.signature().fill(0); resumed.possessionProof().fill(0); resumed.certificateChain()[0].fill(0)
        assertArrayEquals(completed.signature(), store.forSend(offer).signature())
        val bytes = directory.listFiles()!!.single().readBytes()
        assertFalse(bytes.toList().windowed(secret.size).any { it == secret.toList() })
        assertFalse(bytes.toList().windowed(32).any { it == GuardWire.sha256(secret).toList() })
    }

    @Test fun `no key claim substitution resigner or unsigned send across store instances`() {
        val ready = ready(); val claim = ready.claim!!
        val other = EnrollmentKeyClaim(claim.offerHash(), claim.approvalKeyId, claim.approvalKey(), "parent-encrypt-02", encryption)
        assertThrows(IllegalArgumentException::class.java) { store.saveClaim(ready.offer, other, ready.certificateChain(), ready.possessionProof()) }
        assertThrows(IllegalArgumentException::class.java) { store.saveClaim(ready.offer, claim, ready.certificateChain(), ByteArray(32)) }
        assertThrows(IllegalArgumentException::class.java) { store.saveSignature(ready.offer, ByteArray(32), ByteArray(64)) }
        assertThrows(IllegalArgumentException::class.java) { store.saveSignature(ready.offer, EnrollmentWire.claimHash(claim), ByteArray(64)) }
        assertFalse(store.load(ready.offer)!!.isSigned)
        val first = EnrollmentSigningOperation(store, ready, signature())
        val second = EnrollmentSigningOperation(store, ready, signature())
        val persisted = first.finish(first.signature)
        assertThrows(IllegalStateException::class.java) { first.finish(first.signature) }
        assertThrows(IllegalArgumentException::class.java) { second.finish(second.signature) }
        assertArrayEquals(persisted.signature(), store.forSend(ready.offer).signature())
        assertArrayEquals(persisted.signature(), store.saveSignature(ready.offer, EnrollmentWire.claimHash(claim), persisted.signature()).signature())
    }

    @Test fun `cancelled wrong callback and local abandonment never complete enrollment`() {
        val ready = ready()
        val cancelled = EnrollmentSigningOperation(store, ready, signature()); cancelled.cancel()
        assertThrows(IllegalStateException::class.java) { cancelled.finish(cancelled.signature) }
        val switched = EnrollmentSigningOperation(store, ready, signature())
        assertThrows(IllegalArgumentException::class.java) { switched.finish(signature()) }
        assertThrows(IllegalStateException::class.java) { switched.finish(switched.signature) }
        val racing = EnrollmentSigningOperation(store, ready, signature())
        store.abandon(ready.offer)
        assertThrows(IllegalStateException::class.java) { racing.finish(racing.signature) }
        assertThrows(IllegalStateException::class.java) { store.prepare(ready.offer) }
        assertThrows(IllegalStateException::class.java) { store.forSend(ready.offer) }
        val retained = store.load(ready.offer)!!
        assertTrue(retained.abandoned); assertNotNull(retained.claim)
        assertEquals(ready.approvalAlias, retained.approvalAlias)
        val replacement = store.prepare(offer("enrollment-alpha2"))
        assertNotEquals(ready.approvalAlias, replacement.approvalAlias)
        assertNotEquals(ready.encryptionAlias, replacement.encryptionAlias)
        assertEquals(2, store.list().size)
    }

    @Test fun `expiry and clock rollback before after biometric and before publication fail closed`() {
        val ready = ready()
        val signing = DelayedSignature(signature()) { clock.time = ready.offer.expiryUnixMillis }
        val operation = EnrollmentSigningOperation(store, ready, signing)
        assertThrows(IllegalStateException::class.java) { operation.finish(signing) }
        assertFalse(store.load(ready.offer)!!.isSigned)
        assertThrows(IllegalStateException::class.java) { store.prepare(ready.offer) }
        clock.time = start + 1000
        val hash = EnrollmentWire.claimHash(ready.claim!!)
        val sig = signature().run { update(EnrollmentWire.encodeClaimForSignature(ready.claim)); EcdsaP1363.fromDer(sign()) }
        // Fourth clock read is after temp fsync, immediately before atomic move.
        var calls = 0
        clock.read = { if (++calls == 4) ready.offer.expiryUnixMillis else start + 1000 }
        assertThrows(IllegalStateException::class.java) { store.saveSignature(ready.offer, hash, sig) }
        assertFalse(store.load(ready.offer)!!.isSigned)
        assertEquals(1, directory.listFiles()!!.size)
        clock.read = null
        store.saveSignature(ready.offer, hash, sig)
        clock.time = start + 999
        assertThrows(IllegalStateException::class.java) { store.forSend(ready.offer) }
        clock.time = start + 300000
        assertThrows(IllegalStateException::class.java) { store.forSend(ready.offer) }
        store.abandon(ready.offer) // possible after expiry, retains signed bytes for reconciliation
        assertArrayEquals(sig, store.load(ready.offer)!!.signature())
    }

    @Test fun `concurrent signatures commit once and every loser preserves winner`() {
        val ready = ready(); val gate = CountDownLatch(1); val pool = Executors.newFixedThreadPool(2)
        try {
            val futures = List(2) {
                pool.submit<Boolean> {
                    val op = EnrollmentSigningOperation(store, ready, signature()); gate.await()
                    try { op.finish(op.signature); true } catch (_: IllegalArgumentException) { false }
                }
            }
            gate.countDown()
            assertEquals(1, futures.count { it.get() })
            assertTrue(store.forSend(ready.offer).isSigned)
        } finally { pool.shutdownNow() }
    }

    @Test fun `corrupt oversized swapped and unknown storage never silently resets`() {
        val ready = ready(); val file = directory.listFiles()!!.single(); val original = file.readBytes()
        for (bad in listOf(byteArrayOf(), original.copyOf(original.size - 1), original + byteArrayOf(0), ByteArray(72 * 1024),
            original.copyOf().apply { this[20] = (this[20].toInt() xor 1).toByte() })) {
            file.writeBytes(bad)
            assertThrows(IllegalArgumentException::class.java) { store.prepare(ready.offer) }
            assertThrows(IllegalArgumentException::class.java) { store.prepare(offer("enrollment-alpha2")) }
            assertArrayEquals(bad, file.readBytes())
        }
        file.writeBytes(original)
        val other = offer("enrollment-alpha2"); store.prepare(other)
        val otherFile = directory.listFiles()!!.single { it != file }; otherFile.writeBytes(original)
        assertThrows(IllegalArgumentException::class.java) { store.load(other) }
        assertThrows(IllegalArgumentException::class.java) { store.list() }
    }

    @Test fun `bounded retained ceremonies never prune possibly committed keys`() {
        repeat(8) { index -> val offer = offer("enrollment-alpha$index"); store.prepare(offer); store.abandon(offer) }
        assertThrows(IllegalStateException::class.java) { store.prepare(offer("enrollment-alpha9")) }
        assertEquals(8, store.list().size)
        assertTrue(store.list().all { it.abandoned })
    }

    @Test fun `screen preserves every comparison bit and never promotes signed upload to confirmed`() {
        val state = ready()
        assertEquals(EnrollmentStage.BIOMETRIC, enrollmentStage(state, null, start))
        val displayed = enrollmentComparison(state)
        assertEquals(8, displayed.lines().size)
        assertTrue(displayed.lines().all { it.matches(Regex("[0-9a-f]{8}")) })
        assertArrayEquals(EnrollmentWire.claimHash(state.claim!!), hex(displayed.replace("\n", "")))
        store.saveCapability(state.offer, ByteArray(32) { 3 })
        val completed = signed(store.load(state.offer)!!)
        assertEquals(EnrollmentStage.WAITING, enrollmentStage(completed, null, start))
        assertTrue(enrollmentStage(completed, null, start).canSynchronize)
        val proof = EnrollmentResult(EnrollmentExchange.NEEDS_PHONE_PROOF, 1, start, start + 60000, byteArrayOf(), byteArrayOf())
        assertEquals(EnrollmentStage.WAITING, enrollmentStage(completed, proof, start))
        val compare = EnrollmentResult(EnrollmentExchange.NEEDS_LOCAL_CONFIRMATION, 2, start, start + 60000, byteArrayOf(), byteArrayOf())
        assertEquals(EnrollmentStage.COMPARE, enrollmentStage(completed, compare, start))
        val confirmed = EnrollmentResult(EnrollmentExchange.CONFIRMED, 3, start, start + 60000, byteArrayOf(), byteArrayOf())
        assertEquals(EnrollmentStage.CONFIRMED, enrollmentStage(completed, confirmed, start + 2 * 86_400_000))
        assertFalse(enrollmentStage(completed, confirmed, start).canSynchronize)
        assertEquals(EnrollmentStage.RECOVERY, enrollmentStage(completed, confirmed, start - 1))
    }

    @Test fun `screen only reconciles expired or stopped signed attempt and requires missing QR`() {
        val state = ready()
        assertEquals(EnrollmentStage.EXPIRED, enrollmentStage(state, null, state.offer.expiryUnixMillis))
        val completed = signed(state)
        assertEquals(EnrollmentStage.RESCAN, enrollmentStage(completed, null, start))
        assertEquals(EnrollmentStage.RECOVERY, enrollmentStage(completed, null, state.offer.expiryUnixMillis))
        store.saveCapability(state.offer, ByteArray(32) { 3 })
        store.abandon(state.offer)
        val stopped = store.load(state.offer)!!
        assertEquals(EnrollmentStage.QUERY_ONLY, enrollmentStage(stopped, null, start))
        assertEquals(EnrollmentStage.QUERY_ONLY, enrollmentStage(stopped, null, state.offer.expiryUnixMillis + 86_399_999))
        assertEquals(EnrollmentStage.RECOVERY, enrollmentStage(stopped, null, state.offer.expiryUnixMillis + 86_400_000))
        assertTrue(stopped.isSigned)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test fun `foreground waiting backs off network failures then follows verified comparison and confirmation`() = runTest {
        val ready = ready(); store.saveCapability(ready.offer, ByteArray(32) { 3 })
        val completed = signed(store.load(ready.offer)!!)
        var result: EnrollmentResult? = null
        var calls = 0
        val stages = mutableListOf<Pair<EnrollmentStage, Boolean>>()
        val polling = launch {
            awaitEnrollment(inspect = { completed to result }, exchange = {
                when (++calls) {
                    1, 2 -> throw EnrollmentExchangeUnavailable()
                    3 -> result = EnrollmentResult(EnrollmentExchange.NEEDS_LOCAL_CONFIRMATION, 2, start, start + 60000, byteArrayOf(), byteArrayOf())
                    4 -> result = EnrollmentResult(EnrollmentExchange.CONFIRMED, 3, start, start + 60000, byteArrayOf(), byteArrayOf())
                    else -> error("polling continued after confirmed result")
                }
            }, display = { state, verified, retrying -> stages += enrollmentStage(state, verified, start + testScheduler.currentTime) to retrying },
                now = { start + testScheduler.currentTime })
        }
        runCurrent(); assertEquals(1, calls); assertEquals(EnrollmentStage.WAITING to true, stages.last())
        advanceTimeBy(1999); runCurrent(); assertEquals(1, calls)
        advanceTimeBy(1); runCurrent(); assertEquals(2, calls)
        advanceTimeBy(3999); runCurrent(); assertEquals(2, calls)
        advanceTimeBy(1); runCurrent(); assertEquals(3, calls); assertEquals(EnrollmentStage.COMPARE to false, stages.last())
        advanceTimeBy(2000); runCurrent(); assertEquals(4, calls)
        assertEquals(EnrollmentStage.CONFIRMED to false, stages.last()); assertTrue(polling.isCompleted)
        advanceTimeBy(60000); runCurrent(); assertEquals(4, calls)
        assertArrayEquals(completed.signature(), store.load(ready.offer)!!.signature())
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test fun `polling stops on screen cancellation and distinguishes deadline from integrity failure`() = runTest {
        val ready = ready(); store.saveCapability(ready.offer, ByteArray(32) { 3 })
        val completed = signed(store.load(ready.offer)!!)
        var calls = 0; var displays = 0
        val polling = launch {
            awaitEnrollment(inspect = { completed to null }, exchange = {
                calls++
                withTimeout(10) { delay(20) }
            }, display = { _, _, _ -> displays++ }, now = { start + testScheduler.currentTime })
        }
        runCurrent(); advanceTimeBy(10); runCurrent()
        assertEquals(1, calls); assertTrue(polling.isActive) // timeout retries instead of silently stopping
        advanceTimeBy(2000); runCurrent(); assertEquals(2, calls)
        polling.cancelAndJoin()
        val stoppedDisplays = displays
        advanceTimeBy(60000); runCurrent()
        assertEquals(2, calls); assertEquals(stoppedDisplays, displays)
        for (failure in listOf(GeneralSecurityException("synthetic bad signature"), java.io.IOException("synthetic disk failure"))) {
            var attempts = 0
            try {
                awaitEnrollment(inspect = { completed to null }, exchange = { attempts++; throw failure },
                    display = { _, _, _ -> }, now = { start })
                fail("integrity/storage failure became a retry loop")
            } catch (actual: Exception) { assertSame(failure, actual) }
            assertEquals(1, attempts)
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test fun `query-only polling stays sparse and repeated failures have a bounded backoff`() = runTest {
        val ready = ready(); store.saveCapability(ready.offer, ByteArray(32) { 3 })
        signed(store.load(ready.offer)!!); store.abandon(ready.offer)
        val stopped = store.load(ready.offer)!!
        var calls = 0
        val polling = launch {
            awaitEnrollment(inspect = { stopped to null }, exchange = { calls++; throw EnrollmentExchangeUnavailable() },
                display = { _, _, _ -> }, now = { start + testScheduler.currentTime })
        }
        runCurrent(); assertEquals(1, calls)
        for ((index, pause) in listOf(10000L, 10000L, 10000L, 16000L, 30000L, 30000L).withIndex()) {
            advanceTimeBy(pause - 1); runCurrent(); assertEquals(index + 1, calls)
            advanceTimeBy(1); runCurrent(); assertEquals(index + 2, calls)
        }
        polling.cancelAndJoin()
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test fun `polling never signs and only observes queryable or terminal durable states`() = runTest {
        val ready = ready()
        var calls = 0
        var displayed: EnrollmentStage? = null
        suspend fun run(state: PendingEnrollment, now: Long) = awaitEnrollment(inspect = { state to null },
            exchange = { calls++; throw IllegalStateException("unexpected exchange") },
            display = { current, verified, _ -> displayed = enrollmentStage(current, verified, now) }, now = { now })
        run(ready, start); assertEquals(EnrollmentStage.BIOMETRIC, displayed); assertEquals(0, calls)
        run(ready, ready.offer.expiryUnixMillis); assertEquals(EnrollmentStage.EXPIRED, displayed); assertEquals(0, calls)
        store.saveCapability(ready.offer, ByteArray(32) { 3 }); signed(store.load(ready.offer)!!)
        store.abandon(ready.offer)
        val stopped = store.load(ready.offer)!!
        var state = stopped
        val polling = launch {
            awaitEnrollment(inspect = { state to null }, exchange = {
                assertEquals(EnrollmentStage.QUERY_ONLY, enrollmentStage(state, null, start))
                calls++
                // Simulate retention ending: next inspection must stop, not sign or create another attempt.
                state = PendingEnrollmentStore(directory, TestClock(start)).load(ready.offer)!!
            }, display = { current, verified, _ -> displayed = enrollmentStage(current, verified,
                if (calls == 0) start else ready.offer.expiryUnixMillis + 86_400_000) },
                now = { if (calls == 0) start else ready.offer.expiryUnixMillis + 86_400_000 })
        }
        runCurrent()
        assertEquals(1, calls); assertEquals(EnrollmentStage.RECOVERY, displayed); assertTrue(polling.isCompleted)
        assertEquals(stopped.approvalAlias, store.load(ready.offer)!!.approvalAlias)
    }

    private class TestClock(var time: Long) : Clock() {
        var read: (() -> Long)? = null
        override fun millis() = read?.invoke() ?: time
        override fun instant(): Instant = Instant.ofEpochMilli(millis())
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = this
    }
    private class DelayedSignature(private val delegate: Signature, private val after: () -> Unit) : Signature("SHA256withECDSA") {
        init { state = SIGN }
        override fun engineInitVerify(key: PublicKey) = delegate.initVerify(key)
        override fun engineInitSign(key: PrivateKey) = delegate.initSign(key)
        override fun engineUpdate(b: Byte) = delegate.update(b)
        override fun engineUpdate(b: ByteArray, off: Int, len: Int) = delegate.update(b, off, len)
        override fun engineSign(): ByteArray = delegate.sign().also { after() }
        override fun engineVerify(sig: ByteArray) = delegate.verify(sig)
        @Deprecated("test only") override fun engineSetParameter(param: String, value: Any) = Unit
        @Deprecated("test only") override fun engineGetParameter(param: String): Any = error("unused")
    }
    private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun b64(bytes: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}
