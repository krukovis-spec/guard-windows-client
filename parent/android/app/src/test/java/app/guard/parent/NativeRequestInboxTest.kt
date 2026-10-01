package app.guard.parent

import app.guard.parent.approval.*
import app.guard.parent.protocol.*
import app.guard.parent.protocol.Reader
import app.guard.parent.protocol.Writer
import app.guard.parent.security.EcdsaP1363
import kotlinx.coroutines.*
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.*
import java.net.URL
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.*
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.HttpsURLConnection

/** Controlled HTTP, real JCA signatures/HPKE and existing .NET ciphertext; no physical Keystore/biometry claims. */
@OptIn(ExperimentalCoroutinesApi::class)
class NativeRequestInboxTest {
    private val now = ExchangeVector.now
    private fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun point(pair: KeyPair) = pair.public.encoded.takeLast(65).toByteArray()
    private val signing = pair(); private val encryption = pair(); private val phone = pair(); private val approval = pair()
    private val key = object : RelayEncryptionKey {
        override fun publicKeySec1() = point(phone)
        override fun privateKey() = phone.private
    }
    private val offer = EnrollmentOffer("https://relay.example.test", "enrollment-alpha1", "device-alpha-0001", "Тестовый ПК",
        1, 1, "mailbox-alpha-0001", "device-signing-0001", point(signing), "device-encryption1", point(encryption),
        now - 1000, now + 300000, ByteArray(32) { 9 })
    private val claim = EnrollmentKeyClaim(EnrollmentWire.offerHash(offer), "phone-approval-001", approval.public.encoded,
        "phone-encryption1", point(phone))
    private val recipient = RelayRecipient(offer.mailboxId, claim.encryptionKeyId, 1, key)
    private val clock = TestClock(now)
    private val snapshot = RelayReceive.decodeDeviceSignedRequest(ExchangeVector.bytes("request.plaintext")).snapshot.copy(
        deviceEpoch = 1, authorityEpoch = 1, createdUnixMillis = now, pendingExpiryUnixMillis = now + 60000)

    private fun profile(): NativeRelayProfile {
        val header = "GNI1".toByteArray() + EnrollmentWire.offerHash(offer) + EnrollmentWire.claimHash(claim)
        val plain = "GNP1".toByteArray() + ByteBuffer.allocate(16).putLong(now).putLong(now + 86400000).array() + "A".repeat(64).toByteArray()
        val (enc, cipher) = HpkeP256.encrypt(key.publicKeySec1(), plain, header, "Guard.v2.native-relay.install.hpke.v1".toByteArray() + header)
        val raw = header + enc + cipher
        return NativeRelayProfile.open(raw, offer, claim, key, GuardWire.sha256(raw).joinToString("") { "%02x".format(it) }, now)
    }
    private fun signed(input: ByteArray, pair: KeyPair = signing): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA").apply { initSign(pair.private); update(input) }.sign()
        return input + ByteBuffer.allocate(4).putInt(64).array() + EcdsaP1363.fromDer(signature)
    }
    private fun frame(cursor: Long = 1, request: RequestSnapshot = snapshot, receipt: Boolean = false,
        wrongSigner: Boolean = false, end: Long = now + 60000): ByteArray {
        val inner = if (receipt) Writer("GRDC").apply {
            val received = GuardWire.decodeCommandReceipt(ExchangeVector.bytes("applied.plaintext").let {
                // GRDC wraps the existing GRRC receipt.
                Reader(it, "GRDC").bytes(65536, false)
            }).copy(deviceEpoch = 1, authorityEpoch = 1, processedUnixMillis = now)
            bytes(GuardWire.encodeCommandReceipt(received), 65536, false); id(offer.signingKeyId)
        }.finish() else Writer("GRDE").apply {
            bytes(GuardWire.encodeRequestSnapshot(request), 65536, false); id(offer.signingKeyId)
        }.finish()
        val aad = RelayFrameAad(if (receipt) 3 else 1, offer.mailboxId, claim.encryptionKeyId, "frame-alpha-0000$cursor", cursor, 0, now, end)
        val bytes = GuardWire.encodeRelayFrameAssociatedData(aad)
        val label = if (receipt) "guard-relay-receipt-hpke-v1" else "guard-relay-request-hpke-v1"
        val (enc, cipher) = HpkeP256.encrypt(key.publicKeySec1(), signed(inner, if (wrongSigner) encryption else signing), bytes, label.toByteArray() + bytes)
        return bytes + ByteBuffer.allocate(4).putInt(enc.size).array() + enc + ByteBuffer.allocate(4).putInt(cipher.size).array() + cipher
    }
    private fun json(frames: List<ByteArray>, cursor: Long) = ("{\"frames\":[" + frames.joinToString(",") {
        "\"" + Base64.getEncoder().encodeToString(it) + "\""
    } + "],\"nextCursor\":" + cursor + "}").toByteArray()
    private fun inbox(before: () -> Unit = {}, connection: (URL) -> HttpsURLConnection) =
        NativeRequestInbox(offer, claim, key, profile(), before, clock, connection)

    @Test fun `page grammar accepts actual dotnet frame and only exact bounded monotonic metadata`() {
        val raw = ExchangeVector.bytes("request.frame")
        val cursor = RelayReceive.decodeFrame(raw).aad.cursor
        val body = json(listOf(raw), cursor)
        val page = NativeInboxPageCodec.decode(body, ExchangeVector.recipient, 0)
        assertArrayEquals(raw, page.first.single()); assertEquals(cursor, page.second)
        val encoded = Base64.getEncoder().encodeToString(raw)
        assertEquals(cursor, NativeInboxPageCodec.decode((" \n {\"nextCursor\":$cursor,\"frames\":[\"$encoded\"]} \r").toByteArray(), ExchangeVector.recipient, 0).second)
        assertTrue(NativeInboxPageCodec.decode(json(emptyList(), cursor), ExchangeVector.recipient, cursor).first.isEmpty())
        val invalid = listOf("{}", "{\"frames\":[],\"nextCursor\":0,\"nextCursor\":0}", "{\"frames\":[],\"nextCursor\":0,\"other\":0}",
            "{\"frames\":[null],\"nextCursor\":0}", "{\"frames\":[],\"nextCursor\":00}", "{\"frames\":[],\"nextCursor\":1e0}",
            "{\"frames\":[],\"nextCursor\":-1}", "{\"frames\":[],\"nextCursor\":9007199254740992}",
            "{\"frames\":[\"$encoded\",],\"nextCursor\":$cursor}", String(body) + "{}", String(body).replace(encoded.take(8), "!!!!!!!!"))
        for (text in invalid) assertThrows(Exception::class.java) { NativeInboxPageCodec.decode(text.toByteArray(), ExchangeVector.recipient, 0) }
        for (bad in listOf(json(listOf(raw), cursor + 1), json(listOf(raw, raw), cursor), json(List(17) { raw }, cursor),
            ByteArray(NativeInboxPageCodec.MAX_BYTES + 1), byteArrayOf(0xff.toByte())))
            assertThrows(Exception::class.java) { NativeInboxPageCodec.decode(bad, ExchangeVector.recipient, 0) }
        assertThrows(Exception::class.java) { NativeInboxPageCodec.decode(body, ExchangeVector.recipient, cursor) }
        assertThrows(Exception::class.java) { NativeInboxPageCodec.decode(body, ExchangeVector.recipient.copy(keyId = "different-key-0001"), 0) }
        assertThrows(Exception::class.java) { NativeInboxPageCodec.decode(body, ExchangeVector.recipient.copy(mailboxId = "different-box-0001"), 0) }
    }

    @Test fun `real encrypted request is shown only after verification while receipt does not become a decision`() = runBlocking {
        val body = json(listOf(frame(), frame(2, receipt = true)), 2)
        lateinit var connection: Connection; var checks = 0
        inbox({ checks++ }) { url -> Connection(url, body).also { connection = it } }.use { session ->
            val page = session.read()
            assertEquals(snapshot, page.requests.single().snapshot.copy(challenge = snapshot.challenge))
            assertArrayEquals(snapshot.challenge, page.requests.single().snapshot.challenge)
            assertEquals(2, page.frameCount); assertEquals(2L, page.nextCursor); assertEquals(3, checks)
            try { session.read(); fail("reused a single-use read session") } catch (_: IllegalStateException) { }
        }
        assertEquals("https://relay.example.test/v1/mailboxes/mailbox-alpha-0001/poll?recipient=phone-encryption1&after=0&limit=16", connection.url.toString())
        assertEquals("GET", connection.requestMethod); assertEquals("Bearer " + "A".repeat(64), connection.getRequestProperty("Authorization"))
        assertEquals("identity", connection.getRequestProperty("Accept-Encoding")); assertFalse(connection.instanceFollowRedirects)
        assertFalse(connection.useCaches); assertTrue(connection.closed)
    }

    @Test fun `cryptographic failures stale ownership clock expiry and profile loss never produce a page`() = runBlocking {
        val corrupt = frame().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
        for (raw in listOf(corrupt, frame(wrongSigner = true), frame(request = snapshot.copy(authorityEpoch = 2)),
            frame(request = snapshot.copy(deviceId = "different-pc-0001")), frame(request = snapshot.copy(createdUnixMillis = now + 1)))) {
            inbox { Connection(it, json(listOf(raw), 1)) }.use { assertRefused(it) }
        }
        for (time in listOf(now - 1, now + 60000, now + 86400000)) {
            clock.time = now
            inbox { url -> Connection(url, json(listOf(frame()), 1)).apply { onRead = { clock.time = time } } }.use { assertRefused(it) }
        }
        clock.time = now
        var checks = 0
        inbox({ if (++checks == 3) error("ownership changed") }) { Connection(it, json(listOf(frame()), 1)) }.use { assertRefused(it) }
        assertEquals(3, checks)
        clock.time = now + 86400000
        var calls = 0
        inbox { calls++; Connection(it, json(emptyList(), 0)) }.use { assertRefused(it) }
        assertEquals(0, calls)
    }

    @Test fun `HTTP refuses redirects wrong headers huge and truncated streams and cancellation disconnects`() = runBlocking {
        for ((status, content, body) in listOf(Triple(302, "application/json", json(emptyList(), 0)),
            Triple(401, "application/json", json(emptyList(), 0)), Triple(200, "text/html", json(emptyList(), 0)),
            Triple(200, "application/json", ByteArray(NativeInboxPageCodec.MAX_BYTES + 1)), Triple(200, "application/json", "{".toByteArray()))) {
            inbox { Connection(it, body, status, content) }.use { assertRefused(it) }
        }
        inbox { Connection(it, json(emptyList(), 0)).apply { encoding = "gzip" } }.use { assertRefused(it) }
        val entered = CountDownLatch(1); val disconnected = CountDownLatch(1)
        lateinit var blocked: Connection
        inbox { url -> Connection(url, json(listOf(frame()), 1)).also { blocked = it; it.entered = entered; it.disconnected = disconnected } }.use { session ->
            val pending = async(Dispatchers.Default) { session.read() }
            assertTrue(entered.await(2, TimeUnit.SECONDS)); pending.cancelAndJoin()
            assertTrue(disconnected.await(2, TimeUnit.SECONDS)); assertTrue(blocked.closed)
        }
    }

    @Test fun `display makes bidi and hidden controls visible without modifying signed values`() {
        val input = "report\u202Eexe.txt\u2066\u200F\n"
        assertEquals("report\\u{202E}exe.txt\\u{2066}\\u{200F}\\u{A}", requestDisplayText(input))
        assertEquals("Файл 📄", requestDisplayText("Файл 📄"))
        assertTrue(input.contains('\u202E'))
    }

    @Test fun `cancellation while checking local keys cannot dispatch a late HTTP request`() = runBlocking {
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val drained = CountDownLatch(1)
        var checks = 0
        lateinit var connection: Connection
        inbox({ if (++checks == 2) { entered.countDown(); check(release.await(3, TimeUnit.SECONDS)) } }) {
            Connection(it, json(emptyList(), 0)).also { connection = it; it.drained = drained }
        }.use { session ->
            val pending = async(Dispatchers.Default) { session.read() }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            pending.cancelAndJoin(); release.countDown()
            assertTrue(drained.await(2, TimeUnit.SECONDS)); assertEquals(0, connection.responseReads.get())
        }
    }

    @Test fun `real twenty second deadline cancels the blocked connection without returning its late data`() = runTest {
        val entered = CountDownLatch(1); val disconnected = CountDownLatch(1)
        lateinit var connection: Connection
        inbox { url -> Connection(url, json(listOf(frame()), 1)).also {
            connection = it; it.entered = entered; it.disconnected = disconnected
        } }.use { session ->
            val pending = async { session.read() }
            runCurrent(); assertTrue(entered.await(2, TimeUnit.SECONDS))
            advanceTimeBy(20001); runCurrent()
            try { pending.await(); fail("late inbox returned") } catch (_: TimeoutCancellationException) { }
            assertTrue(disconnected.await(2, TimeUnit.SECONDS)); assertTrue(connection.closed)
        }
    }

    private suspend fun assertRefused(session: NativeRequestInbox) {
        try { session.read(); fail("unverified page accepted") }
        catch (error: IOException) { assertEquals("verified inbox unavailable", error.message) }
    }
    private class TestClock(var time: Long) : Clock() {
        override fun millis() = time
        override fun instant() = Instant.ofEpochMilli(time)
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = this
    }
    private class Connection(url: URL, private val body: ByteArray, private val status: Int = 200,
        private val content: String = "application/json; charset=utf-8") : HttpsURLConnection(url) {
        @Volatile var closed = false
        var entered: CountDownLatch? = null; var disconnected: CountDownLatch? = null
        var drained: CountDownLatch? = null
        val responseReads = AtomicInteger(); private val closes = AtomicInteger()
        var onRead: (() -> Unit)? = null; var encoding: String? = null
        override fun connect() = Unit
        override fun disconnect() { closed = true; disconnected?.countDown(); if (closes.incrementAndGet() >= 2) drained?.countDown() }
        override fun usingProxy() = false
        override fun getResponseCode(): Int { responseReads.incrementAndGet(); return status }
        override fun getContentType() = content
        override fun getContentLengthLong() = -1L
        override fun getHeaderField(name: String?) = if (name == "Content-Encoding") encoding else null
        override fun getInputStream(): InputStream {
            entered?.countDown(); disconnected?.await(3, TimeUnit.SECONDS); onRead?.invoke()
            return ByteArrayInputStream(body)
        }
        override fun getCipherSuite() = "TLS_TEST"
        override fun getLocalCertificates(): Array<java.security.cert.Certificate>? = null
        override fun getServerCertificates(): Array<java.security.cert.Certificate> = emptyArray()
    }
}
