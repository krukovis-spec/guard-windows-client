package app.guard.parent

import app.guard.parent.enrollment.*
import app.guard.parent.protocol.*
import app.guard.parent.security.EcdsaP1363
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.File
import java.security.Signature
import java.util.Base64

/** Public test keys only, same input and reviewed digest constants as the .NET harness. */
class EnrollmentTest {
    private val now = 1790769600000L
    private val secret = ByteArray(32) { (it + 1).toByte() }
    private val challenge = GuardWire.sha256("independent public enrollment challenge".toByteArray(Charsets.UTF_8))
    private val generator = hex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    private val phone = hex("04c06b4f6bebc7bb495cb797ab753f911aff80aefb86fd8b6fcc35525f3ab5f03e0b21bd31a86c6048af3cb2d98e0d3bf01da5cc4c39ff5370d331a4f1f7d5a4e0")
    private val binding = EnrollmentRelayBinding("https://relay.example.test")
    private fun offer(label: String = "Тестовый ПК", endpoint: String = binding.canonicalRelayEndpoint, epoch: Long = 2,
        expiry: Long = now + 300000, signing: ByteArray = ExchangeVector.bytes("device.public"), encryption: ByteArray = generator, nonce: ByteArray = challenge) =
        EnrollmentOffer(endpoint, "enrollment-alpha1", "device-alpha-0001", label, epoch, 4, "mailbox-alpha-0001",
            "device-signing-0001", signing, "device-encrypt-001", encryption, now, expiry, nonce)
    private fun claim(offer: EnrollmentOffer): EnrollmentKeyClaim {
        val spki = hex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + ExchangeVector.bytes("recipient.public")
        return EnrollmentKeyClaim(EnrollmentWire.offerHash(offer), "p256:" + b64(GuardWire.sha256(spki)), spki, "parent-encrypt-01", phone)
    }
    private fun qr(offer: EnrollmentOffer = offer(), rawSecret: ByteArray = secret) =
        "guard-enroll://v2?offer=" + b64(EnrollmentWire.encodeOffer(offer)) + "&secret=" + b64(rawSecret)

    @Test fun `exact enrollment transcript QR MAC and signature interoperate with dotnet`() {
        val offer = offer(); val claim = claim(offer)
        val raw = EnrollmentWire.encodeOffer(offer); val input = EnrollmentWire.encodeClaimForSignature(claim)
        assertArrayEquals(hex("BFA3C18A436D94834FDEC226BA822D60382DC046A9B23B4A50E28F7890DB5D68"), EnrollmentWire.offerHash(offer))
        assertArrayEquals(hex("9DD4DA43ED053E771CEC24624CBB52A74CE9072496A554C46A6D08D407ACB62A"), EnrollmentWire.claimHash(claim))
        val text = qr(offer)
        val proof = EnrollmentQrParser.parse(text, binding, now).use { it.proofFor(claim) }
        assertArrayEquals(hex("9AE65292543C6BA6E16E4D38FD35E30EF4C212788C921C914B769D2C780362DC"), proof)
        assertArrayEquals(raw, EnrollmentWire.encodeOffer(EnrollmentWire.decodeOffer(raw)))
        assertArrayEquals(input, EnrollmentWire.encodeClaimForSignature(EnrollmentWire.decodeClaimForSignature(input)))
        val signature = Signature.getInstance("SHA256withECDSA").apply { initSign(ExchangeVector.key.privateKey()); update(input) }
        val output = File("build/test-interop/android-enrollment.txt")
        requireNotNull(output.parentFile).mkdirs()
        output.writeText(listOf(raw.hex(), input.hex(), proof.hex(), EcdsaP1363.fromDer(signature.sign()).hex(), text).joinToString("\n"))
    }

    @Test fun `QR rejects ambiguous parsing foreign relay expiry and use after close`() {
        val good = qr()
        for (bad in listOf(good + "#fragment", good + "&extra=1", good + "&secret=" + b64(secret), good + "=", good + "\n",
            good.replace("//v2?", "//v1?"), good.replace("//v2?", "//v2:443?"), good.replace("//v2?", "//user@v2?"),
            good.replace("//v2?", "//v2/path?"), good.replace("?offer=", "?offer=%"), good.replace("offer=", "OFFER="),
            qr(rawSecret = secret.copyOf(31)), qr(offer(nonce = secret)), qr(offer(nonce = GuardWire.sha256(secret))), "a".repeat(2201))) {
            assertThrows(IllegalArgumentException::class.java) { EnrollmentQrParser.parse(bad, binding, now) }
        }
        // Same decoded bytes with nonzero unused base64 bits must not create an alternate representation.
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val nonCanonical = good.dropLast(1) + alphabet[alphabet.indexOf(good.last()) + 1]
        assertThrows(IllegalArgumentException::class.java) { EnrollmentQrParser.parse(nonCanonical, binding, now) }
        assertThrows(IllegalArgumentException::class.java) { EnrollmentQrParser.parse(good, EnrollmentRelayBinding("https://other.example.test"), now) }
        for (time in listOf(now - 1, now + 300000, Long.MIN_VALUE, Long.MAX_VALUE))
            assertThrows(IllegalArgumentException::class.java) { EnrollmentQrParser.parse(good, binding, time) }
        val opened = EnrollmentQrParser.parse(good, binding, now)
        assertThrows(IllegalArgumentException::class.java) { opened.proofFor(claim(offer(epoch = 3))) }
        opened.close()
        assertThrows(IllegalStateException::class.java) { opened.proofFor(claim(offer())) }
    }

    @Test fun `canonical enrollment fields reject invalid profiles and preserve immutable buffers`() {
        for (bad in listOf(offer(label = "x\u0085"), offer(label = "e\u0301"), offer(label = "\ud800"), offer(label = "x".repeat(97)),
            offer(endpoint = "https://relay.example.test/../x"), offer(endpoint = "https://relay.example.test:443"), offer(endpoint = "https://RELAY.example.test"),
            offer(endpoint = "http://relay.example.test"), offer(endpoint = "https://relay.example.test\n"), offer(epoch = 0), offer(epoch = -1),
            offer(expiry = now), offer(expiry = now + 600001), offer(signing = ByteArray(65)), offer(encryption = ExchangeVector.bytes("device.public"))))
            assertThrows(IllegalArgumentException::class.java) { EnrollmentWire.encodeOffer(bad) }
        EnrollmentWire.encodeOffer(offer(label = "ПК 💻"))
        val signing = ExchangeVector.bytes("device.public"); val encryption = generator.copyOf(); val value = offer(signing = signing, encryption = encryption)
        val raw = EnrollmentWire.encodeOffer(value); signing.fill(0); encryption.fill(0)
        value.signingKey().fill(0); value.encryptionKey().fill(0); value.challenge().fill(0)
        assertArrayEquals(raw, EnrollmentWire.encodeOffer(value))
        val claim = claim(value); val hash = claim.offerHash(); val approval = claim.approvalKey(); val enc = claim.encryptionKey()
        val copied = EnrollmentKeyClaim(hash, claim.approvalKeyId, approval, claim.encryptionKeyId, enc)
        hash.fill(0); approval.fill(0); enc.fill(0); copied.offerHash().fill(0); copied.approvalKey().fill(0); copied.encryptionKey().fill(0)
        assertArrayEquals(EnrollmentWire.encodeClaimForSignature(claim), EnrollmentWire.encodeClaimForSignature(copied))
        assertThrows(IllegalArgumentException::class.java) { EnrollmentWire.claimProof(ByteArray(31), claim) }
    }

    @Test fun `all offer and claim bytes are either rejected or hashed no truncation is accepted`() {
        fun check(raw: ByteArray, decode: (ByteArray) -> ByteArray) {
            val hash = GuardWire.sha256(raw)
            for (length in 0 until raw.size) assertThrows(IllegalArgumentException::class.java) { decode(raw.copyOf(length)) }
            assertThrows(IllegalArgumentException::class.java) { decode(raw + byteArrayOf(0)) }
            for (index in raw.indices) {
                val changed = raw.copyOf().apply { this[index] = (this[index].toInt() xor 1).toByte() }
                try { assertFalse(hash.contentEquals(decode(changed))) } catch (_: IllegalArgumentException) { }
            }
        }
        check(EnrollmentWire.encodeOffer(offer())) { EnrollmentWire.offerHash(EnrollmentWire.decodeOffer(it)) }
        check(EnrollmentWire.encodeClaimForSignature(claim(offer()))) { EnrollmentWire.claimHash(EnrollmentWire.decodeClaimForSignature(it)) }
    }
    private fun b64(bytes: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
}
