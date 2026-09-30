package app.guard.parent

import app.guard.parent.enrollment.*
import app.guard.parent.protocol.*
import app.guard.parent.security.EcdsaP1363
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.*
import java.net.URL
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.time.*
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection

/** Real files/JCA, synthetic device keys. HTTP fake controls I/O, never cryptographic acceptance. */
class EnrollmentDeliveryTest {
    @TempDir lateinit var directory: File
    private val start = 1790769600000L
    private val clock = TestClock(start)
    private val store get() = PendingEnrollmentStore(directory, clock)
    private fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val deviceSigning = pair(); private val deviceEncryption = pair(); private val approval = pair(); private val phone = pair()
    private fun point(pair: KeyPair) = pair.public.encoded.takeLast(65).toByteArray()
    private fun key(pair: KeyPair) = object : RelayEncryptionKey {
        override fun publicKeySec1() = point(pair)
        override fun privateKey() = pair.private
    }
    private val phoneKey = key(phone)
    private val offer = EnrollmentOffer("https://relay.example.test", "enrollment-alpha1", "device-alpha-0001", "Тестовый ПК",
        2, 4, "mailbox-alpha-0001", "device-signing-0001", point(deviceSigning), "device-encrypt-001", point(deviceEncryption),
        start, start + 300000, ByteArray(32) { 9 })
    private val secret = ByteArray(32) { (it + 1).toByte() }
    private val capability = EnrollmentWire.relayCapability(GuardWire.sha256(secret), offer)
    private val claim = EnrollmentKeyClaim(EnrollmentWire.offerHash(offer),
        "p256:" + Base64.getUrlEncoder().withoutPadding().encodeToString(GuardWire.sha256(approval.public.encoded)),
        approval.public.encoded, "parent-encrypt-01", point(phone))
    private val witness = ByteArray(32) { 7 }
    private val challenge by lazy { HpkeP256.encrypt(point(phone), witness, EnrollmentWire.claimHash(claim),
        "guard-enrollment-decryption-hpke-v1".toByteArray() + EnrollmentWire.claimHash(claim)) }

    private fun ready(large: Boolean = false): PendingEnrollment {
        store.prepare(offer); store.saveCapability(offer, capability)
        store.saveClaim(offer, claim, if (large) List(4) { ByteArray(16384) { 1 } } else List(2) { byteArrayOf(1, 2, 3) },
            EnrollmentWire.claimProof(GuardWire.sha256(secret), claim))
        return store.saveSignature(offer, EnrollmentWire.claimHash(claim), sign(approval, EnrollmentWire.encodeClaimForSignature(claim)))
    }
    private fun sign(pair: KeyPair, raw: ByteArray) = Signature.getInstance("SHA256withECDSA").run {
        initSign(pair.private); update(raw); EcdsaP1363.fromDer(sign())
    }
    private fun encode(block: DataOutputStream.() -> Unit) = ByteArrayOutputStream().apply { DataOutputStream(this).use(block) }.toByteArray()
    private fun DataOutputStream.bytes(raw: ByteArray) { writeInt(raw.size); write(raw) }
    private fun response(state: PendingEnrollment, outcome: Int, version: Long, nonce: ByteArray? = null): ByteArray {
        val header = encode {
            writeBytes("GREX"); writeInt(1); writeInt(4); write(EnrollmentWire.offerHash(offer)); write(EnrollmentWire.claimHash(claim))
            write(nonce ?: EnrollmentExchange.requestMetadata(state.request(), offer, claim).second)
        }
        val plain = encode {
            writeBytes("GRES"); writeInt(1); writeInt(outcome); writeLong(version); writeLong(clock.time)
            writeLong(if (outcome == 3) clock.time + 60000 else minOf(clock.time + 60000, offer.expiryUnixMillis))
            bytes(if (outcome == 1) challenge.first else byteArrayOf()); bytes(if (outcome == 1) challenge.second else byteArrayOf())
        }
        val signature = sign(deviceSigning, "guard-enrollment-result-v1".toByteArray() + header + plain)
        val (enc, cipher) = HpkeP256.encrypt(point(phone), plain + signature, header, "guard-enrollment-exchange-hpke-v1".toByteArray() + header)
        return encode { write(header); write(enc); bytes(cipher) }
    }
    private fun kind(state: PendingEnrollment) = EnrollmentExchange.requestMetadata(state.request(), offer, claim).first
    private fun sealedBody(state: PendingEnrollment): ByteArray {
        val raw = state.request(); val header = raw.copyOfRange(0, 108)
        return HpkeP256.decrypt(key(deviceEncryption), raw.copyOfRange(108, 173), raw.copyOfRange(177, raw.size),
            header, "guard-enrollment-exchange-hpke-v1".toByteArray() + header)
    }

    @Test fun `durable claim proof query and signed confirmation survive restart and reply expiry`() {
        ready(large = true)
        val first = store.nextRequest(offer, phoneKey)
        assertEquals(1, kind(first)); assertTrue(first.request().size > 65536)
        assertArrayEquals(first.request(), store.nextRequest(offer, phoneKey).request())
        first.request().fill(0); first.capability().fill(0)
        assertArrayEquals(capability, store.load(offer)!!.capability())
        assertNull(store.lastResult(offer, phoneKey))
        val pending = response(first, 1, 2)
        assertEquals(1, store.acceptReply(offer, pending, phoneKey).outcome)
        val proof = store.nextRequest(offer, phoneKey)
        assertEquals(2, kind(proof))
        assertArrayEquals(EnrollmentWire.answerKeyConfirmation(claim, phoneKey, challenge.first, challenge.second), sealedBody(proof))
        // Duplicated old reply cannot consume the new outstanding proof.
        assertEquals(1, store.acceptReply(offer, pending, phoneKey).outcome)
        assertArrayEquals(proof.request(), store.load(offer)!!.request())
        store.acceptReply(offer, response(proof, 2, 3), phoneKey)
        val query = store.nextRequest(offer, phoneKey)
        assertEquals(3, kind(query)); assertTrue(sealedBody(query).isEmpty())
        store.acceptReply(offer, response(query, 3, 4), phoneKey)
        assertTrue(store.load(offer)!!.request().isEmpty())
        clock.time += 26 * 60 * 60 * 1000
        assertEquals(3, store.lastResult(offer, phoneKey)!!.outcome)
        assertThrows(IllegalStateException::class.java) { store.nextRequest(offer, phoneKey) }
        store.abandon(offer) // Local stop is NOT a remote revocation, including after success.
        assertEquals(3, store.lastResult(offer, phoneKey)!!.outcome)
        val raw = directory.listFiles()!!.single().readBytes().toList()
        assertFalse(raw.windowed(32).any { it == secret.toList() || it == GuardWire.sha256(secret).toList() })
    }

    @Test fun `wrong nonce forgery version regression and expiry during commit preserve outstanding request`() {
        ready(); val first = store.nextRequest(offer, phoneKey)
        val valid = response(first, 2, 5)
        val file = directory.listFiles()!!.single(); val before = file.readBytes()
        for (bad in listOf(response(first, 3, 6, ByteArray(32)), valid.copyOf().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() })) {
            assertThrows(Exception::class.java) { store.acceptReply(offer, bad, phoneKey) }
            assertArrayEquals(before, file.readBytes())
        }
        var calls = 0
        clock.read = { if (++calls == 4) start + 60000 else start }
        assertThrows(IllegalStateException::class.java) { store.acceptReply(offer, valid, phoneKey) }
        assertArrayEquals(before, file.readBytes()); assertEquals(1, directory.listFiles()!!.size)
        clock.read = null
        store.acceptReply(offer, valid, phoneKey)
        val query = store.nextRequest(offer, phoneKey)
        for (bad in listOf(response(query, 1, 6), response(query, 3, 4), response(query, 3, 5)))
            assertThrows(IllegalArgumentException::class.java) { store.acceptReply(offer, bad, phoneKey) }
        assertArrayEquals(query.request(), store.load(offer)!!.request())
        clock.time++
        store.acceptReply(offer, response(query, 3, 6), phoneKey)
        clock.time--
        assertThrows(IllegalStateException::class.java) { store.lastResult(offer, phoneKey) }
    }

    @Test fun `timeout rotates nonce and expired or abandoned attempts only reconcile without new keys`() {
        val signed = ready(); val first = store.nextRequest(offer, phoneKey)
        clock.time += 60000
        val second = store.nextRequest(offer, phoneKey)
        assertEquals(1, kind(second)); assertFalse(first.request().contentEquals(second.request()))
        assertThrows(IllegalArgumentException::class.java) { store.acceptReply(offer, response(first, 3, 5), phoneKey) }
        store.abandon(offer)
        val query = store.nextRequest(offer, phoneKey)
        assertEquals(3, kind(query)); assertArrayEquals(signed.signature(), query.signature())
        clock.time = offer.expiryUnixMillis + 1
        val late = store.nextRequest(offer, phoneKey)
        assertEquals(3, kind(late))
        store.acceptReply(offer, response(late, 3, 7), phoneKey)
        assertTrue(store.load(offer)!!.abandoned)
        assertEquals(3, store.lastResult(offer, phoneKey)!!.outcome)
    }

    @Test fun `legacy file keeps signed keys and needs same live capability instead of reset`() {
        val signed = ready()
        val legacy = encode {
            writeInt(0x47454e31); bytes(EnrollmentWire.encodeOffer(offer)); writeLong(start + 1000); writeByte(0)
            bytes(EnrollmentWire.encodeClaimForSignature(claim)); writeInt(2); signed.certificateChain().forEach { bytes(it) }
            bytes(signed.possessionProof()); bytes(signed.signature())
        }
        directory.listFiles()!!.single().writeBytes(legacy + GuardWire.sha256(legacy))
        clock.time = start + 1000
        assertArrayEquals(signed.signature(), store.load(offer)!!.signature())
        assertThrows(IllegalStateException::class.java) { store.nextRequest(offer, phoneKey) }
        var reads = 0
        clock.read = { if (++reads == 1) start + 1000 else start + 999 }
        assertThrows(IllegalArgumentException::class.java) { store.saveCapability(offer, capability) }
        assertArrayEquals(legacy + GuardWire.sha256(legacy), directory.listFiles()!!.single().readBytes())
        clock.read = null
        store.saveCapability(offer, capability)
        assertThrows(IllegalArgumentException::class.java) { store.saveCapability(offer, ByteArray(32)) }
        assertEquals(1, kind(store.nextRequest(offer, phoneKey)))
        clock.time = offer.expiryUnixMillis + 24 * 60 * 60 * 1000
        assertThrows(IllegalStateException::class.java) { store.nextRequest(offer, phoneKey) }
        assertArrayEquals(signed.signature(), store.load(offer)!!.signature())
    }

    @Test fun `HTTP sends exact persisted bytes pinned paths bearer and bounded binary reply`() = runBlocking {
        ready(); val state = store.nextRequest(offer, phoneKey); val reply = response(state, 1, 2)
        val connections = mutableListOf<FakeConnection>()
        val transport = EnrollmentHttpTransport { url ->
            FakeConnection(url, if (connections.isEmpty()) 201 else 200, reply).also { connections.add(it) }
        }
        var checks = 0
        val received = transport.exchange(state) { store.requireSendable(state); checks++ }
        assertArrayEquals(reply, received); assertEquals(2, checks)
        assertArrayEquals(state.request(), connections[0].sent.toByteArray())
        assertEquals("POST", connections[0].requestMethod); assertEquals("GET", connections[1].requestMethod)
        val base = offer.relayEndpoint + "/v1/mailboxes/" + offer.mailboxId + "/enrollments/" + offerId(offer)
        assertEquals(base + "/requests", connections[0].url.toString())
        assertEquals(base + "/replies/" + EnrollmentExchange.requestMetadata(state.request(), offer, claim).second.hex(), connections[1].url.toString())
        for (connection in connections) {
            assertEquals("Bearer " + capability.hex(), connection.getRequestProperty("Authorization"))
            assertFalse(connection.instanceFollowRedirects); assertFalse(connection.useCaches); assertTrue(connection.closed)
        }
        assertNull(store.lastResult(offer, phoneKey)) // HTTP 201/200 alone cannot mark confirmed.
        assertEquals(1, store.acceptReply(offer, received!!, phoneKey).outcome)
    }

    @Test fun `HTTP rejects redirects overflow wrong content and cancellation closes in flight socket`() = runBlocking {
        ready(); val state = store.nextRequest(offer, phoneKey)
        for ((status, size, content) in listOf(Triple(302, 200, "application/octet-stream"), Triple(200, 415, "application/octet-stream"),
            Triple(200, 192, "application/octet-stream"), Triple(200, 200, "text/html"))) {
            var calls = 0
            val transport = EnrollmentHttpTransport { url ->
                FakeConnection(url, if (++calls == 1) 201 else status, ByteArray(size), content)
            }
            try { transport.exchange(state) {}; fail("accepted bad transport") } catch (_: IOException) { }
            assertEquals(2, calls); assertArrayEquals(state.request(), store.load(offer)!!.request())
        }
        val waiting = CountDownLatch(1)
        val entered = CountDownLatch(1)
        lateinit var blocked: FakeConnection
        var count = 0
        val transport = EnrollmentHttpTransport { url ->
            FakeConnection(url, if (++count == 1) 201 else 200, ByteArray(200)).also {
                if (count == 2) { blocked = it; it.waitForDisconnect = waiting; it.entered = entered }
            }
        }
        val request = async(Dispatchers.Default) { transport.exchange(state) {} }
        assertTrue(entered.await(2, TimeUnit.SECONDS))
        request.cancelAndJoin()
        assertTrue(blocked.closed); assertTrue(waiting.await(2, TimeUnit.SECONDS))
        assertArrayEquals(state.request(), store.load(offer)!!.request())
    }

    @Test fun `HTTP pending unauthorized and local cancellation never mark enrollment complete`() = runBlocking {
        ready(); val state = store.nextRequest(offer, phoneKey)
        var calls = 0
        val pending = EnrollmentHttpTransport { url -> FakeConnection(url, if (++calls == 1) 201 else 204, byteArrayOf()) }
        assertNull(pending.exchange(state) {}); assertEquals(2, calls)
        calls = 0
        val denied = EnrollmentHttpTransport { url -> calls++; FakeConnection(url, 401, byteArrayOf()) }
        try { denied.exchange(state) {}; fail("accepted 401") } catch (_: IOException) { }
        assertEquals(1, calls); assertNull(store.lastResult(offer, phoneKey))
        calls = 0
        store.abandon(offer)
        try { denied.exchange(state) { store.requireSendable(store.load(offer)!!) }; fail("sent abandoned request") }
        catch (_: IOException) { }
        assertEquals(0, calls)
        assertEquals(3, kind(store.nextRequest(offer, phoneKey)))
    }

    private class TestClock(var time: Long) : Clock() {
        var read: (() -> Long)? = null
        override fun millis() = read?.invoke() ?: time
        override fun instant() = Instant.ofEpochMilli(millis())
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = this
    }
    private class FakeConnection(url: URL, private val status: Int, private val body: ByteArray,
        private val content: String = "application/octet-stream") : HttpsURLConnection(url) {
        val sent = ByteArrayOutputStream()
        @Volatile var closed = false
        var waitForDisconnect: CountDownLatch? = null
        var entered: CountDownLatch? = null
        override fun connect() = Unit
        override fun disconnect() { closed = true; waitForDisconnect?.countDown() }
        override fun usingProxy() = false
        override fun getResponseCode() = status
        override fun getContentType() = content
        override fun getContentLengthLong() = -1L // Exercise actual streaming bound, not only Content-Length.
        override fun getHeaderField(name: String?) = null
        override fun getOutputStream(): OutputStream = sent
        override fun getInputStream(): InputStream {
            entered?.countDown()
            waitForDisconnect?.await(3, TimeUnit.SECONDS)
            return ByteArrayInputStream(body)
        }
        override fun getCipherSuite() = "TLS_TEST"
        override fun getLocalCertificates(): Array<java.security.cert.Certificate>? = null
        override fun getServerCertificates(): Array<java.security.cert.Certificate> = emptyArray()
    }
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
}
