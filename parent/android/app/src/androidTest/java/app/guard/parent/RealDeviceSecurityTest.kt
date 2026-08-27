package app.guard.parent

import androidx.test.ext.junit.runners.AndroidJUnit4
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
    @Ignore("manual real-device gate: validate Android Keystore KeyInfo and attestation chain server-side")
    @Test fun hardwareAndAttestationEvidence() = Unit
}
