package app.guard.parent.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyInfo
import app.guard.parent.protocol.RelayEncryptionKey
import java.security.KeyPairGenerator
import java.security.KeyFactory
import java.security.KeyStore
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Relay decryption key only. It has no user-authentication requirement because
 * request viewing must not authorize a child action; ApprovalSecurity owns the
 * separate biometric-only signing key.
 */
class AndroidRelayEncryptionKey private constructor(private val alias: String) : RelayEncryptionKey {
    override fun privateKey() = entry().privateKey

    override fun publicKeySec1(): ByteArray {
        val point = entry().certificate.publicKey as ECPublicKey
        fun coordinate(value: java.math.BigInteger): ByteArray {
            val raw = value.toByteArray()
            val unsigned = if (raw.size == 33 && raw[0].toInt() == 0) raw.copyOfRange(1, 33) else raw
            require(unsigned.size <= 32) { "P-256 coordinate" }
            return ByteArray(32 - unsigned.size) + unsigned
        }
        return byteArrayOf(4) + coordinate(point.w.affineX) + coordinate(point.w.affineY)
    }

    private fun entry(): KeyStore.PrivateKeyEntry {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = store.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("Missing relay encryption key")
        val info = KeyFactory.getInstance("EC", "AndroidKeyStore").getKeySpec(entry.privateKey, KeyInfo::class.java)
        check(info.keySize == 256 && info.origin == KeyProperties.ORIGIN_GENERATED &&
            info.purposes == KeyProperties.PURPOSE_AGREE_KEY && !info.isUserAuthenticationRequired &&
            info.securityLevel in setOf(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT, KeyProperties.SECURITY_LEVEL_STRONGBOX)) { "relay key policy" }
        val public = entry.certificate.publicKey as ECPublicKey
        val curve = java.security.AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(java.security.spec.ECParameterSpec::class.java)
        check(public.params.curve == curve.curve && public.params.generator == curve.generator &&
            public.params.order == curve.order && public.params.cofactor == curve.cofactor) { "relay key curve" }
        return entry
    }

    companion object {
        private val generationLock = Any()
        fun openExisting(alias: String): AndroidRelayEncryptionKey {
            require(alias.matches(Regex("[A-Za-z0-9._:-]{16,128}"))) { "alias" }
            return AndroidRelayEncryptionKey(alias).also { it.entry() }
        }
        fun createIfAbsent(alias: String): AndroidRelayEncryptionKey = synchronized(generationLock) {
            require(alias.matches(Regex("[A-Za-z0-9._:-]{16,128}"))) { "alias" }
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (!store.containsAlias(alias)) {
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                    initialize(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setUserAuthenticationRequired(false)
                        .build())
                    generateKeyPair()
                }
            }
            openExisting(alias)
        }
    }
}
