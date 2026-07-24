# Guard Parent for Android

Native approval client foundation. It accepts only locator-only deep links, verifies an encrypted/device-signed request snapshot before displaying it, and creates a P-256 approval only through `BIOMETRIC_STRONG`.

No APK is installed by this repository. Real-device verification is mandatory before any pilot: Strong biometric only, no device credential fallback, enrollment invalidation, hardware/attestation verification, and receipt stop-and-wait recovery.
