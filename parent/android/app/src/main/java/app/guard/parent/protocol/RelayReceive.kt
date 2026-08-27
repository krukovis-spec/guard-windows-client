package app.guard.parent.protocol

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Full, fail-closed GRF1 receive boundary. Locator/networking deliberately stays outside it. */
data class RelayFrame(val aad: RelayFrameAad, val encapsulatedKey: ByteArray, val ciphertext: ByteArray)
data class DeviceSignedRequest(val snapshot: RequestSnapshot, val deviceKeyId: String, val signature: ByteArray, val signatureInput: ByteArray)
data class RelayRecipient(val mailboxId: String, val keyId: String, val authorityEpoch: Long, val privateKey: RelayEncryptionKey)
data class RelayDeviceTrust(val deviceId: String, val deviceEpoch: Long, val authorityEpoch: Long, val deviceKeyId: String, val devicePublicKeySec1: ByteArray)

/** Non-biometric decryption key. Approval signing must remain a separate biometric-only key. */
interface RelayEncryptionKey { fun privateKey(): java.security.PrivateKey; fun publicKeySec1(): ByteArray }
interface DeviceRequestSignatureVerifier { fun verify(publicKeySec1: ByteArray, hash: ByteArray, signatureP1363: ByteArray): Boolean }

object RelayReceive {
    private const val MAX_FRAME = 64 * 1024
    private const val MAX_CIPHER = 60 * 1024
    private const val DAY = 86_400_000L
    private val infoLabel = "guard-relay-request-hpke-v1".toByteArray(Charsets.US_ASCII)

    fun decodeFrame(raw: ByteArray): RelayFrame {
        val r = StrictReader(raw, "GRF1")
        val aad = RelayFrameAad(r.enum(1, 4), r.id(), r.id(), r.id(), r.nonNegative(), r.nonNegative(), r.i64(), r.i64())
        require(aad.ack <= aad.cursor) { "ack" }; lifetime(aad.createdUnixMillis, aad.expiryUnixMillis, 7 * DAY)
        val enc = r.bytes(65, false); require(enc.size == 65 && enc[0].toInt() == 4) { "enc" }
        val ciphertext = r.bytes(MAX_CIPHER, false); require(ciphertext.size >= 16) { "ciphertext" }
        r.done(); return RelayFrame(aad, enc, ciphertext)
    }

    fun receiveRequest(rawFrame: ByteArray, recipient: RelayRecipient, trust: RelayDeviceTrust, nowUnixMillis: Long, verifier: DeviceRequestSignatureVerifier = P256DeviceSignatureVerifier): DeviceSignedRequest {
        val frame = decodeFrame(rawFrame)
        require(frame.aad.kind == 1 && frame.aad.mailboxId == recipient.mailboxId && frame.aad.recipientKeyId == recipient.keyId) { "recipient" }
        require(recipient.authorityEpoch == trust.authorityEpoch) { "authority epoch" }
        require(nowUnixMillis in frame.aad.createdUnixMillis..frame.aad.expiryUnixMillis) { "frame expiry" }
        val aad = GuardWire.encodeRelayFrameAssociatedData(frame.aad)
        val plaintext = HpkeP256.decrypt(recipient.privateKey, frame.encapsulatedKey, frame.ciphertext, aad, infoLabel + aad)
        val signed = decodeDeviceSignedRequest(plaintext)
        val snapshot = signed.snapshot
        require(snapshot.deviceId == trust.deviceId && snapshot.deviceEpoch == trust.deviceEpoch && snapshot.authorityEpoch == trust.authorityEpoch) { "snapshot binding" }
        require(nowUnixMillis in snapshot.createdUnixMillis until snapshot.pendingExpiryUnixMillis) { "snapshot expiry" }
        val hash = GuardWire.sha256(signed.signatureInput)
        require(verifier.verify(trust.devicePublicKeySec1, hash, signed.signature)) { "device signature" }
        return signed
    }

    fun decodeDeviceSignedRequest(raw: ByteArray): DeviceSignedRequest {
        val r = StrictReader(raw, "GRDE")
        val snapshotBytes = r.bytes(MAX_FRAME, false)
        val keyId = r.id()
        val signature = r.bytes(64, false); require(signature.size == 64) { "signature" }
        r.done()
        val input = raw.copyOfRange(0, raw.size - 4 - signature.size)
        return DeviceSignedRequest(GuardWire.decodeRequestSnapshot(snapshotBytes), keyId, signature, input)
    }

    object P256DeviceSignatureVerifier : DeviceRequestSignatureVerifier {
        override fun verify(publicKeySec1: ByteArray, hash: ByteArray, signatureP1363: ByteArray): Boolean = try {
            require(hash.size == 32 && signatureP1363.size == 64)
            val signature = Signature.getInstance("NONEwithECDSA")
            signature.initVerify(P256.publicKey(publicKeySec1)); signature.update(hash)
            signature.verify(P256.p1363ToDer(signatureP1363))
        } catch (_: Exception) { false }
    }

    private class StrictReader(private val raw: ByteArray, magic: String) {
        private var position = 0
        init { require(raw.size <= MAX_FRAME); require(String(take(4), Charsets.US_ASCII) == magic); require(i32() == 1) { "version" } }
        fun i32(): Int = ByteBuffer.wrap(take(4)).int
        fun i64(): Long = ByteBuffer.wrap(take(8)).long
        fun enum(min: Int, max: Int): Int = i32().also { require(it in min..max) { "enum" } }
        fun nonNegative(): Long = i64().also { require(it >= 0) { "nonnegative" } }
        fun id(): String = text(128, false).also { require(canonicalId(it)) { "id" } }
        fun bytes(max: Int, empty: Boolean): ByteArray { val n = i32(); require(n in (if (empty) 0 else 1)..max) { "length" }; return take(n) }
        fun done() { require(position == raw.size) { "trailing" } }
        private fun text(max: Int, empty: Boolean): String { val b = bytes(max, empty); return strictUtf8(b).also { require(it.toByteArray(Charsets.UTF_8).contentEquals(b)) { "utf8" } } }
        private fun take(n: Int): ByteArray { require(n >= 0 && n <= raw.size - position) { "truncated" }; return raw.copyOfRange(position, position + n).also { position += n } }
    }
    private fun canonicalId(value: String) = value.length in 16..128 && value.all { it.isLetterOrDigit() && it.code < 128 || it == '-' || it == '_' || it == '.' || it == ':' }
    private fun lifetime(start: Long, end: Long, maximum: Long) { require(end > start && end - start <= maximum) { "lifetime" } }
}

/** RFC 9180 base mode: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM. */
private object HpkeP256 {
    private val kemSuite = byteArrayOf(0x4b,0x45,0x4d,0x00,0x10)
    private val suite = byteArrayOf(0x48,0x50,0x4b,0x45,0x00,0x10,0x00,0x01,0x00,0x02)
    private val version = "HPKE-v1".toByteArray(Charsets.US_ASCII)
    fun decrypt(key: RelayEncryptionKey, enc: ByteArray, ciphertext: ByteArray, aad: ByteArray, info: ByteArray): ByteArray {
        val recipient = P256.publicKey(key.publicKeySec1()); val ephemeral = P256.publicKey(enc)
        val ka = KeyAgreement.getInstance("ECDH"); ka.init(key.privateKey()); ka.doPhase(ephemeral, true); val dh = ka.generateSecret()
        try {
            val shared = extractExpand(dh, enc + key.publicKeySec1())
            try {
                val pskIdHash = labeledExtract(suite, ByteArray(0), "psk_id_hash", ByteArray(0)); val infoHash = labeledExtract(suite, ByteArray(0), "info_hash", info)
                val context = byteArrayOf(0) + pskIdHash + infoHash; val secret = labeledExtract(suite, shared, "secret", ByteArray(0))
                val aesKey = labeledExpand(suite, secret, "key", context, 32); val nonce = labeledExpand(suite, secret, "base_nonce", context, 12)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(aesKey, "AES"), GCMParameterSpec(128, nonce)); cipher.updateAAD(aad); return cipher.doFinal(ciphertext)
            } finally { shared.fill(0) }
        } finally { dh.fill(0) }
    }
    private fun extractExpand(dh: ByteArray, context: ByteArray): ByteArray { val prk = labeledExtract(kemSuite, ByteArray(0), "eae_prk", dh); return labeledExpand(kemSuite, prk, "shared_secret", context, 32) }
    private fun labeledExtract(suiteId: ByteArray, salt: ByteArray, label: String, ikm: ByteArray): ByteArray = hkdfExtract(salt, version + suiteId + label.toByteArray(Charsets.US_ASCII) + ikm)
    private fun labeledExpand(suiteId: ByteArray, prk: ByteArray, label: String, info: ByteArray, length: Int): ByteArray = hkdfExpand(prk, byteArrayOf((length shr 8).toByte(), length.toByte()) + version + suiteId + label.toByteArray(Charsets.US_ASCII) + info, length)
    private fun hkdfExtract(salt: ByteArray, input: ByteArray): ByteArray { val mac = Mac.getInstance("HmacSHA256"); mac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256")); return mac.doFinal(input) }
    private fun hkdfExpand(prk: ByteArray, info: ByteArray, len: Int): ByteArray { val out = ByteArrayOutputStream(); var previous = ByteArray(0); var n = 1; while (out.size() < len) { val mac = Mac.getInstance("HmacSHA256"); mac.init(SecretKeySpec(prk,"HmacSHA256")); previous = mac.doFinal(previous + info + byteArrayOf(n++.toByte())); out.write(previous) }; return out.toByteArray().copyOf(len) }
}

private object P256 {
    fun publicKey(sec1: ByteArray): PublicKey { require(sec1.size == 65 && sec1[0].toInt() == 4) { "P-256 point" }; val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(java.security.spec.ECParameterSpec::class.java); val field = params.curve.field as java.security.spec.ECFieldFp; val p = field.p; val x = BigInteger(1, sec1.copyOfRange(1,33)); val y = BigInteger(1, sec1.copyOfRange(33,65)); require(x < p && y < p) { "point range" }; require(y.multiply(y).mod(p) == x.multiply(x).multiply(x).add(params.curve.a.multiply(x)).add(params.curve.b).mod(p)) { "off curve" }; return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x,y),params)) }
    fun p1363ToDer(raw: ByteArray): ByteArray { fun integer(part: ByteArray): ByteArray { val stripped = part.dropWhile { it == 0.toByte() }.toByteArray().ifEmpty { byteArrayOf(0) }; val normalized = if (stripped[0].toInt() and 0x80 != 0) byteArrayOf(0) + stripped else stripped; return byteArrayOf(2, normalized.size.toByte()) + normalized }; val body = integer(raw.copyOfRange(0,32)) + integer(raw.copyOfRange(32,64)); return byteArrayOf(0x30, body.size.toByte()) + body }
}

private fun strictUtf8(bytes: ByteArray): String = try { Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString() } catch (_: CharacterCodingException) { throw WireException("utf8") }
