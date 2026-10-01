package app.guard.parent

import app.guard.parent.protocol.*
import app.guard.parent.enrollment.NativeRelayProfileStore
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.Properties

/** Public .NET export -> actual JCA/HPKE -> no-backup-style temporary storage, no physical phone claims. */
class NativeRelayProfileTest {
    @TempDir lateinit var directory: File
    private fun properties(name: String) = Properties().apply { requireNotNull(NativeRelayProfileTest::class.java.getResourceAsStream("/$name")).use { load(it) } }
    private val ceremony = properties("enrollment-exchange-v1.properties")
    private val vector = properties("native-profile-v1.properties")
    private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val offer = EnrollmentWire.decodeOffer(hex(ceremony.getProperty("offer")))
    private val claim = EnrollmentWire.decodeClaimForSignature(hex(ceremony.getProperty("claim")))
    private val now = ceremony.getProperty("now").toLong()
    private val expiry = now + 3 * 86_400_000L
    private val raw = hex(vector.getProperty("envelope"))
    private val digest = vector.getProperty("sha256")
    private val info = "Guard.v2.native-relay.install.hpke.v1".toByteArray(Charsets.US_ASCII)
    private fun key(private: String, public: ByteArray) = object : RelayEncryptionKey {
        override fun publicKeySec1() = public.copyOf()
        override fun privateKey(): java.security.PrivateKey {
            val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
            return KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, hex(private)), parameters))
        }
    }
    private val phone = key(ceremony.getProperty("phone.private"), claim.encryptionKey())
    private fun digest(bytes: ByteArray) = GuardWire.sha256(bytes).joinToString("") { "%02x".format(it) }
    private fun open(bytes: ByteArray = raw, expected: String = digest, time: Long = now, chosenClaim: EnrollmentKeyClaim = claim,
        chosenKey: RelayEncryptionKey = phone) = NativeRelayProfile.open(bytes, offer, chosenClaim, chosenKey, expected, time)
    private fun plain() = HpkeP256.decrypt(phone, raw.copyOfRange(68, 133), raw.copyOfRange(133, raw.size), raw.copyOfRange(0, 68), info + raw.copyOfRange(0, 68))
    private fun seal(plain: ByteArray): ByteArray {
        val header = raw.copyOfRange(0, 68)
        val (enc, cipher) = HpkeP256.encrypt(phone.publicKeySec1(), plain, header, info + header)
        return header + enc + cipher
    }

    @Test fun `real dotnet export contains only the expected transport credential and lifetime`() {
        assertEquals(NativeRelayProfile.FILE_BYTES, raw.size)
        val profile = open()
        assertEquals("A".repeat(64), profile.accessToken())
        assertEquals(now, profile.preparedUnixMillis); assertEquals(expiry, profile.expiryUnixMillis)
        assertFalse(raw.toString(Charsets.US_ASCII).contains(profile.accessToken()))
        profile.close()
        assertThrows(IllegalStateException::class.java) { profile.accessToken() }
        assertThrows(IllegalStateException::class.java) { profile.requireCurrent(now) }
    }

    @Test fun `all tamper truncations incorrect digest recipient binding and deadlines reject`() {
        for (index in raw.indices) {
            assertThrows(Exception::class.java) { open(raw.copyOf(index)) }
            val changed = raw.copyOf().apply { this[index] = (this[index].toInt() xor 1).toByte() }
            assertThrows(Exception::class.java) { open(changed) }
            assertThrows(Exception::class.java) { open(changed, digest(changed)) } // HPKE/binding, not just outer checksum.
        }
        assertThrows(Exception::class.java) { open(raw + byteArrayOf(0)) }
        for (wrong in listOf("", "0".repeat(64), digest + " ", "g".repeat(64)))
            assertThrows(Exception::class.java) { open(expected = wrong) }
        for (time in listOf(now - 1, expiry, Long.MAX_VALUE)) assertThrows(Exception::class.java) { open(time = time) }
        val otherClaim = EnrollmentKeyClaim(claim.offerHash(), claim.approvalKeyId, claim.approvalKey(), "other-recipient-0001", claim.encryptionKey())
        assertThrows(Exception::class.java) { open(chosenClaim = otherClaim) }
        assertThrows(Exception::class.java) { open(chosenKey = key(ceremony.getProperty("device.private"), offer.encryptionKey())) }
        // Valid HPKE is not sender authentication: independently trusted digest must reject another credential.
        val otherCredential = seal(plain().apply { fill('B'.code.toByte(), 20, 84) })
        assertThrows(Exception::class.java) { open(otherCredential) }
    }

    @Test fun `even authenticated malformed inner profiles reject without fallback`() {
        val samples = listOf(plain().apply { this[0] = 0 }, plain() + byteArrayOf(0),
            plain().apply { this[20] = 'g'.code.toByte() },
            plain().apply { ByteBuffer.wrap(this, 4, 8).putLong(offer.createdUnixMillis - 1) },
            plain().apply { ByteBuffer.wrap(this, 12, 8).putLong(now) },
            plain().apply { ByteBuffer.wrap(this, 12, 8).putLong(Long.MAX_VALUE) })
        samples.forEach { val bytes = seal(it); assertThrows(Exception::class.java) { open(bytes, digest(bytes)) }; it.fill(0) }
    }

    @Test fun `storage reopens exact import retains ciphertext and refuses replacement corruption or expiry`() {
        val clock = TestClock(now + 1000); val store = NativeRelayProfileStore(directory, clock)
        store.install(offer, claim, phone, raw, digest)
        val file = directory.listFiles()!!.single(); val saved = file.readBytes()
        assertFalse(saved.toString(Charsets.US_ASCII).contains("A".repeat(64)))
        NativeRelayProfileStore(directory, clock).open(offer, claim, phone)!!.use { assertEquals("A".repeat(64), it.accessToken()) }
        store.install(offer, claim, phone, raw, digest)
        val samePlaintext = seal(plain())
        store.install(offer, claim, phone, samePlaintext, digest(samePlaintext))
        assertArrayEquals(saved, file.readBytes())
        val other = seal(plain().apply { this[20] = 'B'.code.toByte() })
        assertThrows(Exception::class.java) { store.install(offer, claim, phone, other, digest(other)) }
        assertArrayEquals(saved, file.readBytes())
        clock.now = now + 999
        assertThrows(Exception::class.java) { store.open(offer, claim, phone) }
        clock.now = expiry
        assertThrows(Exception::class.java) { store.open(offer, claim, phone) }
        assertThrows(Exception::class.java) { store.install(offer, claim, phone, raw, digest) }
        clock.now = now + 1000
        file.writeBytes(saved.copyOf(saved.size - 1))
        assertThrows(Exception::class.java) { store.open(offer, claim, phone) }
        assertThrows(Exception::class.java) { store.install(offer, claim, phone, raw, digest) }
        assertEquals(saved.size - 1L, file.length())
        file.writeBytes(saved.copyOf().apply { this[20] = (this[20].toInt() xor 1).toByte() })
        assertThrows(Exception::class.java) { store.open(offer, claim, phone) }
    }

    @Test fun `expiry at publication leaves no installed profile`() {
        val clock = object : Clock() {
            var calls = 0
            override fun getZone() = ZoneOffset.UTC
            override fun withZone(zone: ZoneId): Clock = this
            override fun instant(): Instant = Instant.ofEpochMilli(millis())
            override fun millis() = if (++calls == 1) now else expiry
        }
        val store = NativeRelayProfileStore(directory, clock)
        assertThrows(Exception::class.java) { store.install(offer, claim, phone, raw, digest) }
        assertTrue(directory.listFiles()!!.isEmpty())
    }
    @Test fun `cancel before publication removes only temporary file and exact retry preserves saved profile`() {
        val store = NativeRelayProfileStore(directory, TestClock(now + 1000))
        var checks = 0
        assertThrows(java.util.concurrent.CancellationException::class.java) {
            store.install(offer, claim, phone, raw, digest) { if (++checks == 2) throw java.util.concurrent.CancellationException() }
        }
        assertEquals(2, checks)
        assertTrue(directory.listFiles()!!.isEmpty())
        store.install(offer, claim, phone, raw, digest)
        val path = directory.listFiles()!!.single(); val saved = path.readBytes()
        checks = 0
        assertThrows(java.util.concurrent.CancellationException::class.java) {
            store.install(offer, claim, phone, raw, digest) { if (++checks == 2) throw java.util.concurrent.CancellationException() }
        }
        assertEquals(2, checks); assertArrayEquals(saved, path.readBytes())
    }
    private class TestClock(var now: Long) : Clock() {
        override fun getZone() = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = this
        override fun instant(): Instant = Instant.ofEpochMilli(now)
        override fun millis() = now
    }
}
