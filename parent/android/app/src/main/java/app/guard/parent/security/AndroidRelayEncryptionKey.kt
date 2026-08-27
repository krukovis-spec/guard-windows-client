package app.guard.parent.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import app.guard.parent.protocol.RelayEncryptionKey
import java.security.KeyPairGenerator
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
        return store.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("Missing relay encryption key")
    }

    companion object {
        fun createIfAbsent(alias: String): AndroidRelayEncryptionKey {
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
            return AndroidRelayEncryptionKey(alias)
        }
    }
}
