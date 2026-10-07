package app.guard.parent

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.biometric.BiometricManager
import app.guard.parent.security.AndroidApprovalKeyStore
import app.guard.parent.security.AndroidRelayEncryptionKey
import app.guard.parent.protocol.GuardWire
import org.junit.Assert.*
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith

/** Manual gates: use a physical device with a strong biometric enrolled. Never run in CI as a substitute. */
@RunWith(AndroidJUnit4::class)
class RealDeviceSecurityTest {
    @Ignore("manual real-device gate: inspect BiometricPrompt allows only BIOMETRIC_STRONG and no PIN fallback")
    @Test fun biometricStrongOnly() = Unit
    @Ignore("manual real-device gate: add/remove fingerprint and verify old key raises permanent invalidation")
    @Test fun biometricEnrollmentInvalidatesKey() = Unit
    /** Run explicitly on the parent's physical phone. Creates/deletes only two fresh test aliases. */
    @Test fun hardwareProfilesAndRestartKeepSameKeys() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals(BiometricManager.BIOMETRIC_SUCCESS,
            BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG))
        val suffix = java.util.UUID.randomUUID().toString().replace("-", "")
        val approvalAlias = "guard.parent.approval.test.$suffix"
        val encryptionAlias = "guard.parent.encryption.test.$suffix"
        val keystore = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(keystore.containsAlias(approvalAlias)); assertFalse(keystore.containsAlias(encryptionAlias))
        try {
            val challenge = GuardWire.sha256(suffix.toByteArray(Charsets.US_ASCII))
            val approval = AndroidApprovalKeyStore(approvalAlias)
            val first = try { approval.loadOrEnroll(challenge) } catch (failure: IllegalStateException) {
                // Only non-secret policy facts from our fresh test alias; never key/certificate bytes.
                val key = keystore.getKey(approvalAlias, null) as? java.security.PrivateKey ?: throw failure
                val info = java.security.KeyFactory.getInstance("EC", "AndroidKeyStore")
                    .getKeySpec(key, android.security.keystore.KeyInfo::class.java)
                throw AssertionError("Approval policy facts: securityLevel=${info.securityLevel}, size=${info.keySize}, " +
                    "origin=${info.origin}, purposes=${info.purposes}, digests=${info.digests.joinToString()}, " +
                    "authRequired=${info.isUserAuthenticationRequired}, duration=${info.userAuthenticationValidityDurationSeconds}, " +
                    "authType=${info.userAuthenticationType}, hardwareAuth=${info.isUserAuthenticationRequirementEnforcedBySecureHardware}, " +
                    "invalidateOnEnrollment=${info.isInvalidatedByBiometricEnrollment}, onBody=${info.isUserAuthenticationValidWhileOnBody}", failure)
            }
            val second = AndroidApprovalKeyStore(approvalAlias).loadOrEnroll(challenge)
            assertArrayEquals(first.publicKeySpki, second.publicKeySpki)
            assertTrue(first.certificateChain.size in 2..8)
            first.certificateChain.indices.forEach { assertArrayEquals(first.certificateChain[it], second.certificateChain[it]) }
            val encryption = AndroidRelayEncryptionKey.createIfAbsent(encryptionAlias).publicKeySec1()
            assertArrayEquals(encryption, AndroidRelayEncryptionKey.openExisting(encryptionAlias).publicKeySec1())
            assertFalse(encryption.contentEquals(first.publicKeySpki.copyOfRange(26, 91)))
            try {
                val signature = approval.biometricSignature()
                signature.update(byteArrayOf(1, 2, 3)); signature.sign()
                fail("Signature succeeded without a fresh biometric CryptoObject ceremony")
            } catch (_: android.security.keystore.UserNotAuthenticatedException) {
                // Expected at initSign on some providers.
            } catch (_: java.security.SignatureException) {
                // Expected when an unauthenticated per-operation signature reaches sign().
            }
        } finally {
            keystore.deleteEntry(approvalAlias); keystore.deleteEntry(encryptionAlias)
        }
        assertThrows(IllegalStateException::class.java) { AndroidRelayEncryptionKey.openExisting(encryptionAlias) }
        assertThrows(IllegalStateException::class.java) { AndroidApprovalKeyStore(approvalAlias).material() }
        // This does not replace off-phone Google-chain verification or the two interactive gates above.
    }
}
