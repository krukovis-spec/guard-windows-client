package app.guard.parent

import app.guard.parent.approval.NativeApprovalDelivery
import app.guard.parent.protocol.*
import app.guard.parent.security.*
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.*
import java.net.URL
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection

/** Real signatures/HPKE/atomic files and controlled HTTPS; no network, device Keystore or biometric claims. */
@OptIn(ExperimentalCoroutinesApi::class)
class NativeApprovalDeliveryTest {
    @TempDir lateinit var directory: File
    private val now = ExchangeVector.now
    private val clock = TestClock(now)
    private fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val phone = pair(); private val approvalKey = pair()
    private val offer = EnrollmentOffer("https://relay.example.test", "enrollment-alpha1", "device-alpha-0001", "Тестовый ПК",
        1, 1, "mailbox-alpha-0001", "device-signing-0001", ExchangeVector.bytes("device.public"),
        "device-encryption1", ExchangeVector.key.publicKeySec1(), now - 1000, now + 300000, ByteArray(32) { 9 })
    private val claim = EnrollmentKeyClaim(EnrollmentWire.offerHash(offer), "phone-approval-001", approvalKey.public.encoded,
        "phone-encryption1", phone.public.encoded.takeLast(65).toByteArray())
    private val snapshot = RelayReceive.decodeDeviceSignedRequest(ExchangeVector.bytes("request.plaintext")).snapshot.copy(deviceEpoch = 1, authorityEpoch = 1)
    private val signed = ExchangeVector.approval().copy(authorityEpoch = 1, deviceEpoch = 1, keyId = claim.approvalKeyId,
        snapshotHash = GuardWire.sha256(GuardWire.encodeRequestSnapshot(snapshot))).let {
        val signature = Signature.getInstance("SHA256withECDSA").apply { initSign(approvalKey.private); update(GuardWire.encodeApprovalSignatureInput(it)) }.sign()
        it.copy(signatureP1363 = EcdsaP1363.fromDer(signature))
    }
    private val pending = PendingSignedEnvelope(claim.approvalKeyId, 1, GuardWire.encodeSignedApproval(signed))
    private fun store() = FileApprovalOutbox(directory)
    private fun prepared() = NativeApprovalAttempt.prepare(pending, offer, claim, clock.time, now + 86400000)
    private fun reservation(attempt: NativeApprovalAttempt, cursor: Long = 7) =
        "{\"frameId\":\"${attempt.frameId}\",\"recipientKeyId\":\"${offer.encryptionKeyId}\",\"cursor\":$cursor,\"createdAt\":${attempt.created},\"expiresAt\":${attempt.expiry},\"leaseExpiresAt\":${clock.time + 60000},\"status\":\"reserved\",\"nonAuthoritative\":true}".toByteArray()
    private fun publication(attempt: NativeApprovalAttempt, duplicate: Boolean = false) =
        "{\"frameId\":\"${attempt.frameId}\",\"duplicate\":$duplicate}".toByteArray()
    private fun error(code: String) = "{\"error\":\"$code\"}".toByteArray()
    private fun profile(): NativeRelayProfile {
        val key = object : RelayEncryptionKey {
            override fun publicKeySec1() = claim.encryptionKey()
            override fun privateKey() = phone.private
        }
        val header = "GNI1".toByteArray() + EnrollmentWire.offerHash(offer) + EnrollmentWire.claimHash(claim)
        val plain = "GNP1".toByteArray() + ByteBuffer.allocate(16).putLong(now).putLong(now + 86400000).array() + "A".repeat(64).toByteArray()
        val (enc, cipher) = HpkeP256.encrypt(key.publicKeySec1(), plain, header, "Guard.v2.native-relay.install.hpke.v1".toByteArray() + header)
        val raw = header + enc + cipher
        return NativeRelayProfile.open(raw, offer, claim, key, GuardWire.sha256(raw).hex(), now)
    }
    private fun session(guard: () -> Unit = {}, connect: (URL) -> HttpsURLConnection) =
        NativeApprovalDelivery(offer, claim, pending, store(), profile(), guard, clock, connect)
    private suspend fun refused(session: NativeApprovalDelivery) {
        try { session.publish(); fail("unverified delivery succeeded") }
        catch (error: IOException) { assertEquals("approval delivery unavailable", error.message) }
    }
    private fun unchanged() {
        assertArrayEquals(pending.exactBytes, store().load(pending.keyId)!!.exactBytes)
        assertEquals(1L, store().nextSequence(pending.keyId))
    }

    @Test fun `exact persisted reservation and ciphertext precede HTTP and decrypt in dotnet`() = runBlocking {
        store().save(pending)
        val connections = mutableListOf<Connection>()
        session { url ->
            val saved = store().delivery(pending)!! // Reads a fresh store before either HTTP dispatch.
            Connection(url, if (url.path.endsWith("reserve")) reservation(saved) else publication(saved)).also {
                connections += it
                it.onWrite = { bytes ->
                    assertArrayEquals(if (url.path.endsWith("reserve")) saved.reservationBody(offer) else saved.frameBytes(), bytes)
                }
            }
        }.use { it.publish(); assertThrows(IllegalStateException::class.java) { runBlocking { it.publish() } } }
        assertEquals(2, connections.size)
        for (c in connections) {
            assertEquals("POST", c.requestMethod); assertFalse(c.instanceFollowRedirects); assertFalse(c.useCaches)
            assertEquals("Bearer " + "A".repeat(64), c.getRequestProperty("Authorization")); assertEquals("identity", c.getRequestProperty("Accept-Encoding"))
            assertTrue(c.closed); assertTrue(c.url.toString().startsWith("https://relay.example.test/v1/mailboxes/mailbox-alpha-0001/frames"))
        }
        assertEquals("application/json", connections[0].getRequestProperty("Content-Type"))
        assertEquals("application/octet-stream", connections[1].getRequestProperty("Content-Type"))
        val saved = store().delivery(pending)!!; assertTrue(saved.published); unchanged()
        val frame = RelayReceive.decodeFrame(saved.frameBytes()); val aad = GuardWire.encodeRelayFrameAssociatedData(frame.aad)
        assertArrayEquals(pending.exactBytes, HpkeP256.decrypt(ExchangeVector.key, frame.encapsulatedKey, frame.ciphertext, aad,
            "guard-relay-approval-hpke-v1".toByteArray() + aad))
        val root = File(System.getProperty("user.dir"), "build/test-interop").apply { mkdirs() }
        File(root, "android-approval-frame.txt").writeText(listOf(
            "offer=" + EnrollmentWire.encodeOffer(offer).hex(), "claim=" + EnrollmentWire.encodeClaimForSignature(claim).hex(),
            "snapshot=" + GuardWire.encodeRequestSnapshot(snapshot).hex(), "approval=" + pending.exactBytes.hex(), "frame=" + saved.frameBytes().hex()).joinToString("\n"))
    }

    @Test fun `lost reservation and publication replies retry exact bytes after process reconstruction`() = runBlocking {
        store().save(pending)
        var reservationBytes: ByteArray? = null
        session { url -> Connection(url, byteArrayOf()).apply { onWrite = { reservationBytes = it }; failRead = true } }.use { refused(it) }
        val original = store().delivery(pending)!!; assertTrue(original.frameBytes().isEmpty())
        var ciphertext: ByteArray? = null
        session { url ->
            val reserve = url.path.endsWith("reserve"); val saved = store().delivery(pending)!!
            Connection(url, if (reserve) reservation(saved) else publication(saved), if (reserve) 200 else 201).apply {
                failRead = !reserve
                onWrite = { if (reserve) assertArrayEquals(reservationBytes, it) else ciphertext = it }
            }
        }.use { refused(it) }
        assertFalse(store().delivery(pending)!!.published)
        clock.time += 60001 // Lease expired, but publication may have succeeded and been acknowledged by the computer.
        var calls = 0
        session { url ->
            calls++; assertFalse(url.path.endsWith("reserve"))
            Connection(url, publication(store().delivery(pending)!!, true), 200).apply { onWrite = { assertArrayEquals(ciphertext, it) } }
        }.use { it.publish() }
        assertEquals(1, calls); assertTrue(store().delivery(pending)!!.published); unchanged()
    }

    @Test fun `explicit expired lease renews only outer frame and never the signature or sequence`() = runBlocking {
        store().save(pending)
        val original = prepared(); val sealed = original.seal(pending, offer, claim, reservation(original), 201, now)
        store().saveDelivery(pending, null, sealed) {}
        clock.time += 60001
        var calls = 0
        session { url ->
            calls++; val current = store().delivery(pending)!!
            if (calls == 1) Connection(url, error("frame_reservation_required"), 409)
            else if (url.path.endsWith("reserve")) {
                assertNotEquals(sealed.frameId, current.frameId); Connection(url, reservation(current, 8))
            } else Connection(url, publication(current))
        }.use { it.publish() }
        assertEquals(3, calls); assertEquals(8L, store().delivery(pending)!!.cursor); unchanged()
        // Expired GRAP is still delivered for a signed Expired receipt, without recreating approval authority.
        clock.time = signed.expiryUnixMillis + 1
        assertDoesNotThrow { prepared() }; unchanged()
    }

    @Test fun `malformed ambiguous or hostile HTTP preserves pending and bounded pass never loops`() = runBlocking {
        store().save(pending)
        for ((status, raw) in listOf(302 to byteArrayOf(), 401 to error("authentication_required"), 200 to "{}".toByteArray(),
            409 to error("recipient_reserved"), 429 to error("reservation_quota_exceeded"), 200 to ByteArray(1025))) {
            session { Connection(it, raw, status) }.use { refused(it) }; unchanged()
            assertTrue(store().delivery(pending)!!.frameBytes().isEmpty())
        }
        session { Connection(it, reservation(store().delivery(pending)!!)).apply { content = "text/html" } }.use { refused(it) }
        session { Connection(it, reservation(store().delivery(pending)!!)).apply { encoding = "gzip" } }.use { refused(it) }
        var calls = 0
        session { url -> calls++; Connection(url, error("frame_reservation_expired"), 410) }.use { refused(it) }
        assertEquals(2, calls); unchanged()
    }

    @Test fun `codec rejects changed binding signatures noncanonical receipts and mutable callers`() {
        val prepared = prepared()
        for (raw in listOf(reservation(prepared).toString(Charsets.UTF_8).replace("\"reserved\"", "\"published\"").toByteArray(),
            reservation(prepared, 0), reservation(prepared, 9007199254740992), reservation(prepared) + 0,
            reservation(prepared).toString(Charsets.UTF_8).replace("\"nonAuthoritative\":true", "\"nonAuthoritative\":false").toByteArray()))
            assertThrows(Exception::class.java) { prepared.seal(pending, offer, claim, raw, 200, now) }
        val bad = PendingSignedEnvelope(pending.keyId, 1, pending.exactBytes.apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() })
        assertThrows(Exception::class.java) { NativeApprovalAttempt.prepare(bad, offer, claim, now, now + 86400000) }
        assertThrows(Exception::class.java) { prepared.requireBinding(pending, offer,
            EnrollmentKeyClaim(claim.offerHash(), claim.approvalKeyId, pair().public.encoded, claim.encryptionKeyId, claim.encryptionKey())) }
        val sealed = prepared.seal(pending, offer, claim, reservation(prepared), 201, now)
        val original = sealed.encode(); sealed.frameBytes().fill(0); sealed.encode().fill(0)
        assertArrayEquals(original, sealed.encode()); assertArrayEquals(original, NativeApprovalAttempt.decode(original).encode())
        assertThrows(Exception::class.java) { NativeApprovalAttempt.decode(original + 0) }
        assertThrows(Exception::class.java) { sealed.markPublished(publication(sealed, true), 201, now) }
        assertThrows(Exception::class.java) { sealed.markPublished(publication(sealed), 201, sealed.expiry) }
    }

    @Test fun `GOB1 migrates atomically while cancellation corruption stale writers and terminal receipt cannot reset it`() {
        val path = File(directory, GuardWire.sha256(pending.keyId.toByteArray()).hex() + ".bin")
        val legacy = ByteArrayOutputStream().apply { DataOutputStream(this).apply {
            writeInt(0x474f4231); writeLong(1); writeInt(pending.exactBytes.size); write(pending.exactBytes)
        } }.toByteArray()
        path.writeBytes(legacy + GuardWire.sha256(legacy))
        unchanged(); assertNull(store().delivery(pending))
        val prepared = prepared()
        assertThrows(CancellationException::class.java) { store().saveDelivery(pending, null, prepared) { throw CancellationException() } }
        assertArrayEquals(legacy + GuardWire.sha256(legacy), path.readBytes())
        store().saveDelivery(pending, null, prepared) {}
        assertEquals(0x474f4232, ByteBuffer.wrap(path.readBytes()).int)
        assertThrows(Exception::class.java) { store().saveDelivery(pending, null, prepared()) {} }
        assertArrayEquals(prepared.encode(), store().delivery(pending)!!.encode())
        val clean = path.readBytes(); path.writeBytes(clean.apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() })
        assertThrows(Exception::class.java) { store().nextSequence(pending.keyId) }
        path.writeBytes(legacy + GuardWire.sha256(legacy)); store().saveDelivery(pending, null, prepared) {}
        store().complete(pending) // Only the existing verified-receipt path calls this in production.
        assertNull(store().load(pending.keyId)); assertEquals(2L, store().nextSequence(pending.keyId))
        assertThrows(Exception::class.java) { store().saveDelivery(pending, prepared, prepared) {} }
    }

    @Test fun `stale ownership clock cancellation and expiry guard prevent dispatch or publication commit`() = runBlocking {
        store().save(pending)
        var calls = 0
        session({ throw IllegalStateException("owner changed") }) { calls++; Connection(it, byteArrayOf()) }.use { refused(it) }
        assertEquals(0, calls); assertNull(store().delivery(pending))
        clock.time = now - 1
        session { calls++; Connection(it, byteArrayOf()) }.use { refused(it) }
        assertEquals(0, calls)
        clock.time = now
        session { url -> Connection(url, reservation(store().delivery(pending)!!)).apply { onRead = { clock.time = now + 86400000 } } }.use { refused(it) }
        assertTrue(store().delivery(pending)!!.frameBytes().isEmpty()); unchanged()
        clock.time = now
        var writes = 0
        session({ if (directory.listFiles()!!.any { it.extension == "tmp" }) throw CancellationException() }) { url ->
            Connection(url, reservation(store().delivery(pending)!!)).apply { onWrite = { writes++ } }
        }.use { refused(it) }
        assertEquals(1, writes); assertTrue(store().delivery(pending)!!.frameBytes().isEmpty()); unchanged()
    }

    @Test fun `twenty second timeout disconnects and late response cannot replace persisted bytes`() = runTest {
        store().save(pending)
        val entered = CountDownLatch(1); val disconnected = CountDownLatch(1); val drained = CountDownLatch(1)
        session { url -> Connection(url, reservation(store().delivery(pending)!!)).apply {
            onRead = { entered.countDown(); check(disconnected.await(3, TimeUnit.SECONDS)) }
            onClose = { disconnected.countDown(); drained.countDown() }
        } }.use { session ->
            val operation = async { session.publish() }; runCurrent(); assertTrue(entered.await(2, TimeUnit.SECONDS))
            advanceTimeBy(20001); runCurrent()
            try { operation.await(); fail("late delivery succeeded") } catch (_: TimeoutCancellationException) { }
            assertTrue(drained.await(2, TimeUnit.SECONDS))
        }
        assertTrue(store().delivery(pending)!!.frameBytes().isEmpty()); unchanged()
    }

    @Test fun `competing saved ciphertext cancels stale sender and lost publication commit preserves exact retry`() = runBlocking {
        store().save(pending)
        var calls = 0
        var winningBytes = byteArrayOf()
        session { url ->
            calls++; val current = store().delivery(pending)!!
            Connection(url, reservation(current)).apply {
                onRead = {
                    val winner = current.seal(pending, offer, claim, reservation(current), 201, now)
                    store().saveDelivery(pending, current, winner) {}; winningBytes = winner.frameBytes()
                }
            }
        }.use { refused(it) }
        assertEquals(1, calls); assertArrayEquals(winningBytes, store().delivery(pending)!!.frameBytes())
        // Server receives it, but cancellation before local published-flag commit leaves the already-saved ciphertext intact.
        session({ if (directory.listFiles()!!.any { it.extension == "tmp" }) throw CancellationException() }) { url ->
            Connection(url, publication(store().delivery(pending)!!)).apply { onWrite = { assertArrayEquals(winningBytes, it) } }
        }.use { refused(it) }
        assertFalse(store().delivery(pending)!!.published)
        session { url -> Connection(url, publication(store().delivery(pending)!!, true), 200).apply {
            onWrite = { assertArrayEquals(winningBytes, it) }
        } }.use { it.publish() }
        assertTrue(store().delivery(pending)!!.published); unchanged()
    }

    @Test fun `cancellation during slow owner check cannot dispatch after the foreground session ends`() = runBlocking {
        store().save(pending)
        val entered = CountDownLatch(1); val released = CountDownLatch(1); val drained = CountDownLatch(1)
        var connections = 0; var writes = 0
        session({ if (connections > 0) { entered.countDown(); check(released.await(3, TimeUnit.SECONDS)) } }) { url ->
            connections++; Connection(url, reservation(store().delivery(pending)!!)).apply {
                onWrite = { writes++ }; onClose = { if (released.count == 0L) drained.countDown() }
            }
        }.use { session ->
            val operation = async(Dispatchers.Default) { session.publish() }
            assertTrue(entered.await(2, TimeUnit.SECONDS)); operation.cancelAndJoin(); released.countDown()
            assertTrue(drained.await(2, TimeUnit.SECONDS))
        }
        assertEquals(1, connections); assertEquals(0, writes)
        assertTrue(store().delivery(pending)!!.frameBytes().isEmpty()); unchanged()
    }

    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
    private class TestClock(var time: Long) : Clock() {
        override fun millis() = time
        override fun instant() = Instant.ofEpochMilli(time)
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = this
    }
    private class Connection(url: URL, private val body: ByteArray, private val status: Int = 201) : HttpsURLConnection(url) {
        var content = "application/json; charset=utf-8"; var encoding: String? = null
        var failRead = false; @Volatile var closed = false
        var onWrite: ((ByteArray) -> Unit)? = null; var onRead: (() -> Unit)? = null; var onClose: (() -> Unit)? = null
        override fun connect() = Unit
        override fun disconnect() { closed = true; onClose?.invoke() }
        override fun usingProxy() = false
        override fun getOutputStream(): OutputStream = object : ByteArrayOutputStream() {
            override fun close() { onWrite?.invoke(toByteArray()); super.close() }
        }
        override fun getResponseCode() = status
        override fun getContentType() = content
        override fun getContentLengthLong() = -1L
        override fun getHeaderField(name: String?) = if (name == "Content-Encoding") encoding else null
        override fun getInputStream(): InputStream { onRead?.invoke(); if (failRead) throw IOException("lost reply"); return ByteArrayInputStream(body) }
        override fun getErrorStream() = inputStream
        override fun getCipherSuite() = "TLS_TEST"
        override fun getLocalCertificates(): Array<java.security.cert.Certificate>? = null
        override fun getServerCertificates(): Array<java.security.cert.Certificate> = emptyArray()
    }
}
