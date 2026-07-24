package app.guard.parent.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import app.guard.parent.protocol.ApprovalDecision
import app.guard.parent.protocol.GuardWire
import app.guard.parent.protocol.RequestSnapshot
import app.guard.parent.protocol.SignedApproval
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.security.SecureRandom
import java.time.Clock
import java.util.Base64

const val APPROVAL_KEY_ALIAS = "guard.parent.approval.v1"

fun interface SnapshotDecryptor { fun decrypt(locator: String): ByteArray }
fun interface DeviceSnapshotVerifier { fun verify(snapshotEnvelope: ByteArray): VerifiedSnapshot }
data class VerifiedSnapshot(val snapshot: RequestSnapshot, val deviceKeyId: String)

/** UI must call this before showing evidence. A decryptor alone is never sufficient. */
class VerifiedSnapshotLoader(private val decryptor: SnapshotDecryptor, private val verifier: DeviceSnapshotVerifier) {
    fun load(locator: String): VerifiedSnapshot = verifier.verify(decryptor.decrypt(locator))
}

object LocatorOnlyDeepLink {
    private val locator = Regex("^[A-Za-z0-9._~-]{16,256}$")
    fun parse(uri: android.net.Uri): String = parse(uri.toString())
    fun parse(raw: String): String {
        val uri = java.net.URI(raw)
        require(uri.scheme == "guard-parent" && uri.host == "request" && (uri.path.isNullOrEmpty() || uri.path == "/")) { "untrusted link" }
        val pairs = parseQuery(uri.rawQuery)
        require(pairs.keys == setOf("locator") && pairs["locator"]?.size == 1) { "locator only" }
        return pairs["locator"]!!.single().takeIf { locator.matches(it) } ?: throw IllegalArgumentException("locator")
    }
}

internal fun parseQuery(raw: String?): Map<String, List<String>> {
    require(!raw.isNullOrBlank())
    return raw.split('&').map { part -> part.split('=', limit = 2).let { java.net.URLDecoder.decode(it[0], "UTF-8") to java.net.URLDecoder.decode(it.getOrElse(1) { "" }, "UTF-8") } }
        .groupBy({ it.first }, { it.second })
}

data class EnrollmentMaterial(val publicKeySpki: ByteArray, val certificateChain: List<ByteArray>)

class AndroidApprovalKeyStore(private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }) {
    fun enroll(attestationChallenge: ByteArray): EnrollmentMaterial {
        require(attestationChallenge.size in 16..128)
        keyStore.deleteEntry(APPROVAL_KEY_ALIAS)
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val builder = KeyGenParameterSpec.Builder(APPROVAL_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .setAttestationChallenge(attestationChallenge)
        // StrongBox is an optimization only; hardware evidence below is the actual gate.
        if (android.os.Build.VERSION.SDK_INT >= 28) builder.setIsStrongBoxBacked(true)
        try { generator.initialize(builder.build()); generator.generateKeyPair() }
        catch (_: Exception) {
            // A device may not provide StrongBox. Recreate with TEE allowed, then prove hardware backing.
            val tee = KeyGenParameterSpec.Builder(APPROVAL_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")).setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true).setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true).setAttestationChallenge(attestationChallenge).build()
            generator.initialize(tee); generator.generateKeyPair()
        }
        val privateKey = keyStore.getKey(APPROVAL_KEY_ALIAS, null) as PrivateKey
        val keyInfo = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore").getKeySpec(privateKey, KeyInfo::class.java)
        val hardwareBacked = if (android.os.Build.VERSION.SDK_INT >= 31) {
            keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        } else {
            @Suppress("DEPRECATION")
            keyInfo.isInsideSecureHardware
        }
        check(hardwareBacked) { "software-backed key rejected" }
        val chain = keyStore.getCertificateChain(APPROVAL_KEY_ALIAS).map { it.encoded }
        check(chain.isNotEmpty()) { "attestation chain missing" }
        return EnrollmentMaterial(chain.first().let { (keyStore.getCertificate(APPROVAL_KEY_ALIAS) as X509Certificate).publicKey.encoded }, chain)
    }

    fun biometricSignature(): Signature {
        val key = keyStore.getKey(APPROVAL_KEY_ALIAS, null) as? PrivateKey ?: throw KeyPermanentlyInvalidatedException()
        return try { Signature.getInstance("SHA256withECDSA").apply { initSign(key) } }
        catch (error: android.security.keystore.KeyPermanentlyInvalidatedException) { throw KeyPermanentlyInvalidatedException(error) }
    }
}
class KeyPermanentlyInvalidatedException(cause: Throwable? = null) : IllegalStateException("re-enrollment required", cause)

/** DER signatures are variable-sized. The wire representation is strict fixed 64-byte P-1363. */
object EcdsaP1363 {
    fun fromDer(der: ByteArray): ByteArray {
        var p = 0
        fun next(): Int = der.getOrNull(p++)?.toInt()?.and(0xff) ?: throw IllegalArgumentException("der truncated")
        fun len(): Int { val first = next(); if (first < 0x80) return first; val n = first and 0x7f; require(n in 1..2); var v = 0; repeat(n) { v = (v shl 8) or next() }; require(v >= 0x80); return v }
        require(next() == 0x30); val sequenceLength = len(); require(sequenceLength == der.size - p)
        fun integer(): ByteArray { require(next() == 0x02); val n = len(); require(n in 1..33); val raw = der.copyOfRange(p, p + n); p += n
            require(raw.isNotEmpty() && ((raw[0].toInt() and 0x80) == 0)) { "negative" }
            require(raw.size == 1 || raw[0].toInt() != 0 || ((raw[1].toInt() and 0x80) != 0)) { "noncanonical" }
            val unsigned = if (raw.size == 33) raw.copyOfRange(1, 33) else raw
            require(unsigned.size <= 32); return unsigned
        }
        val r = integer(); val s = integer(); require(p == der.size)
        fun pad(value: ByteArray): ByteArray = ByteArray(32 - value.size) + value
        return pad(r) + pad(s)
    }
}

data class PendingSignedEnvelope(val keyId: String, val sequence: Long, val exactBytes: ByteArray)
interface ApprovalOutbox { fun load(keyId: String): PendingSignedEnvelope?; fun save(envelope: PendingSignedEnvelope); fun remove(keyId: String, sequence: Long) }
class StopAndWaitApprovals(private val outbox: ApprovalOutbox) {
    fun getPending(keyId: String): PendingSignedEnvelope? = outbox.load(keyId)
    fun persistBeforeSend(value: PendingSignedEnvelope) {
        val existing = outbox.load(value.keyId)
        require(existing == null || existing.sequence == value.sequence && existing.exactBytes.contentEquals(value.exactBytes)) { "receipt required before next approval" }
        if (existing == null) outbox.save(value)
    }
    fun acceptReceipt(keyId: String, sequence: Long) { outbox.remove(keyId, sequence) }
}

data class RecoveryKit(val bytes: ByteArray, val printable: String)
object RecoveryKitGenerator {
    private val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    fun generate(random: SecureRandom = SecureRandom()): RecoveryKit {
        val secret = ByteArray(32).also(random::nextBytes); val checksum = GuardWire.sha256(secret).copyOfRange(0, 5)
        return RecoveryKit(secret, base32(secret + checksum).chunked(5).joinToString("-"))
    }
    fun verify(printable: String): Boolean = try { val all = fromBase32(printable.replace("-", "")); all.size == 37 && GuardWire.sha256(all.copyOf(32)).copyOfRange(0, 5).contentEquals(all.copyOfRange(32, 37)) } catch (_: Exception) { false }
    private fun base32(bytes: ByteArray): String { var bits = 0; var value = 0; val out = StringBuilder(); bytes.forEach { value = (value shl 8) or (it.toInt() and 255); bits += 8; while (bits >= 5) { out.append(alphabet[(value shr (bits - 5)) and 31]); bits -= 5 } }; if (bits > 0) out.append(alphabet[(value shl (5 - bits)) and 31]); return out.toString() }
    private fun fromBase32(text: String): ByteArray { var bits = 0; var value = 0; val out = ArrayList<Byte>(); text.forEach { c -> val n = alphabet.indexOf(c); require(n >= 0); value = (value shl 5) or n; bits += 5; if (bits >= 8) { out += ((value shr (bits - 8)) and 255).toByte(); bits -= 8 } }; return out.toByteArray() }
}

/** Recovery material is display-only and deliberately has no persistence API. */
data class RecoveryKitConfirmation(val firstTyped: String, val secondTyped: String) { fun confirms(): Boolean = firstTyped == secondTyped && RecoveryKitGenerator.verify(firstTyped) }

object BiometricPolicy {
    fun allowedAuthenticators(): Int = BiometricManager.Authenticators.BIOMETRIC_STRONG
}
