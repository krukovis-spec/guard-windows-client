package app.guard.parent.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.biometric.BiometricManager
import app.guard.parent.protocol.ApprovalDecision
import app.guard.parent.protocol.GuardWire
import app.guard.parent.protocol.RequestSnapshot
import app.guard.parent.protocol.SignedApproval
import app.guard.parent.protocol.CommandReceipt
import app.guard.parent.protocol.RelayDeviceTrust
import app.guard.parent.protocol.RelayRecipient
import app.guard.parent.protocol.RelayReceive
import app.guard.parent.protocol.ReceiptStatus
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

class AndroidApprovalKeyStore(private val alias: String,
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }) {
    private companion object { val generationLock = Any() }
    init { require(alias.matches(Regex("guard\\.parent\\.approval\\.[a-z0-9.]{1,96}"))) { "approval alias" } }

    /** Only a persisted PREPARED ceremony may call this. Existing keys are read, never replaced. */
    fun loadOrEnroll(attestationChallenge: ByteArray): EnrollmentMaterial = synchronized(generationLock) {
        require(attestationChallenge.size == 32)
        if (keyStore.containsAlias(alias)) return@synchronized material()
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .setAttestationChallenge(attestationChallenge)
        // StrongBox is an optimization only; hardware evidence below is the actual gate.
        builder.setIsStrongBoxBacked(true)
        try { generator.initialize(builder.build()); generator.generateKeyPair() }
        catch (_: StrongBoxUnavailableException) {
            // Do not overwrite a key left behind by a provider failure, or hide unrelated failures.
            check(!keyStore.containsAlias(alias)) { "partial key generation requires inspection" }
            generator.initialize(builder.setIsStrongBoxBacked(false).build()); generator.generateKeyPair()
        }
        material()
    }

    fun material(): EnrollmentMaterial {
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey ?: throw KeyPermanentlyInvalidatedException()
        val keyInfo = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore").getKeySpec(privateKey, KeyInfo::class.java)
        val hardwareBacked = keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
            keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        check(hardwareBacked) { "software-backed key rejected" }
        // KeyInfo reports per-operation authorization as -1 (builder input is 0).
        check(keyInfo.keySize == 256 && keyInfo.origin == KeyProperties.ORIGIN_GENERATED &&
            keyInfo.purposes == KeyProperties.PURPOSE_SIGN && keyInfo.digests.toSet() == setOf(KeyProperties.DIGEST_SHA256) &&
            keyInfo.isUserAuthenticationRequired && keyInfo.userAuthenticationValidityDurationSeconds == -1 &&
            keyInfo.userAuthenticationType == KeyProperties.AUTH_BIOMETRIC_STRONG &&
            keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware && keyInfo.isInvalidatedByBiometricEnrollment &&
            !keyInfo.isUserAuthenticationValidWhileOnBody) { "approval key policy" }
        val chain = keyStore.getCertificateChain(alias)?.map { it.encoded } ?: error("attestation chain missing")
        check(chain.size in 2..8 && chain.all { it.size in 1..16384 } && chain.sumOf { it.size } <= 65536) { "attestation chain size" }
        return EnrollmentMaterial((keyStore.getCertificate(alias) as X509Certificate).publicKey.encoded, chain)
    }

    fun biometricSignature(): Signature {
        material()
        val key = keyStore.getKey(alias, null) as? PrivateKey ?: throw KeyPermanentlyInvalidatedException()
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
        fun integer(): ByteArray { require(next() == 0x02); val n = len(); require(n in 1..33 && n <= der.size - p); val raw = der.copyOfRange(p, p + n); p += n
            require(raw.isNotEmpty() && ((raw[0].toInt() and 0x80) == 0)) { "negative" }
            require(raw.size == 1 || raw[0].toInt() != 0 || ((raw[1].toInt() and 0x80) != 0)) { "noncanonical" }
            require(raw.size != 33 || raw[0] == 0.toByte()) { "P-256 integer overflow" }
            val unsigned = if (raw.size == 33) raw.copyOfRange(1, 33) else raw
            require(unsigned.size <= 32); return unsigned
        }
        val r = integer(); val s = integer(); require(p == der.size)
        fun pad(value: ByteArray): ByteArray = ByteArray(32 - value.size) + value
        return pad(r) + pad(s)
    }
}

data class PendingSignedEnvelope(val keyId: String, val sequence: Long, val exactBytes: ByteArray)
interface ApprovalOutbox {
    fun load(keyId: String): PendingSignedEnvelope?
    fun nextSequence(keyId: String): Long
    fun save(envelope: PendingSignedEnvelope)
    fun complete(envelope: PendingSignedEnvelope)
}
class StopAndWaitApprovals(private val outbox: ApprovalOutbox) {
    fun getPending(keyId: String): PendingSignedEnvelope? = outbox.load(keyId)
    fun nextSequence(keyId: String): Long = outbox.nextSequence(keyId)
    fun persistBeforeSend(value: PendingSignedEnvelope) {
        val approval = GuardWire.decodeSignedApproval(value.exactBytes)
        require(value.keyId == approval.keyId && value.sequence == approval.sequence && value.sequence == outbox.nextSequence(value.keyId)) { "approval sequence" }
        val existing = outbox.load(value.keyId)
        require(existing == null || existing.sequence == value.sequence && existing.exactBytes.contentEquals(value.exactBytes)) { "receipt required before next approval" }
        if (existing == null) outbox.save(value)
    }
    fun acceptReceipt(rawFrame: ByteArray, recipient: RelayRecipient, trust: RelayDeviceTrust, now: Long): CommandReceipt {
        val receipt = RelayReceive.receiveReceipt(rawFrame, recipient, trust, now).receipt
        val pending = requireNotNull(outbox.load(receipt.keyId)) { "no pending approval" }
        val approval = GuardWire.decodeSignedApproval(pending.exactBytes)
        require(receipt.sequence == pending.sequence && receipt.commandId == approval.commandId && receipt.requestId == approval.requestId &&
            receipt.requestRevision == approval.requestRevision && receipt.deviceId == approval.deviceId && receipt.deviceEpoch == approval.deviceEpoch &&
            receipt.authorityEpoch == approval.authorityEpoch && receipt.processedUnixMillis >= approval.issuedUnixMillis &&
            java.security.MessageDigest.isEqual(receipt.approvalHash, GuardWire.sha256(GuardWire.encodeApprovalSignatureInput(approval)))) { "receipt does not bind pending approval" }
        if (receipt.status != ReceiptStatus.ACCEPTED_PENDING_RECONCILIATION) outbox.complete(pending)
        return receipt
    }
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
