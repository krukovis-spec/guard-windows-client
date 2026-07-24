package app.guard.parent

import app.guard.parent.approval.ApprovalChoice
import app.guard.parent.protocol.*
import app.guard.parent.security.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.File
import java.security.SecureRandom

class GuardFoundationTest {
    private val challenge = ByteArray(32) { (it + 1).toByte() }
    private val snapshot = RequestSnapshot("device-alpha-0001", 2, "event-alpha-000001", "request-alpha-001", 3,
        TargetKind.WEBSITE, "https://example.test/path", listOf(Evidence("host", "example.test")), "homework",
        0x19f93ff29e8L, 0x19f93ff2dd0L, challenge, 9)

    @Test fun `golden request vector is byte exact`() {
        val expected = hex("4752525100000001000000116465766963652d616c7068612d303030310000000000000002000000126576656e742d616c7068612d30303030303100000011726571756573742d616c7068612d3030310000000000000003000000010000001968747470733a2f2f6578616d706c652e746573742f706174680000000100000004686f73740000000c6578616d706c652e7465737400000008686f6d65776f726b0000019f93ff29e80000019f93ff2dd00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200000000000000009")
        assertArrayEquals(expected, GuardWire.encodeRequestSnapshot(snapshot))
        assertEquals("f2f0d7eda1b70bfb9374c2fe82e2cab1ccca25a8e312fcd8275c3843222729f0", GuardWire.sha256(expected).hex())
        assertArrayEquals(expected, GuardWire.encodeRequestSnapshot(GuardWire.decodeRequestSnapshot(expected)))
    }

    @Test fun `golden approval signing input is byte exact`() {
        val approval = SignedApproval(4, "parent-key-alpha1", 7, "command-alpha-001", "nonce-alpha-00001", 0x19f93ff31b8L, 0x19f93ff35a0L,
            snapshot.deviceId, 2, snapshot.requestId, 3, GuardWire.sha256(GuardWire.encodeRequestSnapshot(snapshot)), challenge,
            TargetKind.WEBSITE, snapshot.targetIdentity, 9, ApprovalDecision.ALLOW_TEMPORARY, 60, ByteArray(64) { (it + 9).toByte() })
        val expected = hex("4752415000000001000000000000000400000011706172656e742d6b65792d616c70686131000000000000000700000011636f6d6d616e642d616c7068612d303031000000116e6f6e63652d616c7068612d30303030310000019f93ff31b80000019f93ff35a0000000116465766963652d616c7068612d30303031000000000000000200000011726571756573742d616c7068612d3030310000000000000003f2f0d7eda1b70bfb9374c2fe82e2cab1ccca25a8e312fcd8275c3843222729f00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000010000001968747470733a2f2f6578616d706c652e746573742f706174680000000000000009000000020000003c")
        assertArrayEquals(expected, GuardWire.encodeApprovalSignatureInput(approval))
        assertEquals("60f5d9b5c411a12e913c1e7c1504bdf869bb899d78b05046650add82c4283b0d", GuardWire.sha256(expected).hex())
        val signed = hex("4752415000000001000000000000000400000011706172656e742d6b65792d616c70686131000000000000000700000011636f6d6d616e642d616c7068612d303031000000116e6f6e63652d616c7068612d30303030310000019f93ff31b80000019f93ff35a0000000116465766963652d616c7068612d30303031000000000000000200000011726571756573742d616c7068612d3030310000000000000003f2f0d7eda1b70bfb9374c2fe82e2cab1ccca25a8e312fcd8275c3843222729f00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000010000001968747470733a2f2f6578616d706c652e746573742f706174680000000000000009000000020000003c00000040090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748")
        assertArrayEquals(signed, GuardWire.encodeSignedApproval(approval))
        assertArrayEquals(signed, GuardWire.encodeSignedApproval(GuardWire.decodeSignedApproval(signed)))
    }

    @Test fun `der conversion is strict and P1363 fixed`() {
        val der = hex("3006020101020102")
        assertArrayEquals(ByteArray(31) + byteArrayOf(1) + ByteArray(31) + byteArrayOf(2), EcdsaP1363.fromDer(der))
        assertThrows(IllegalArgumentException::class.java) { EcdsaP1363.fromDer(hex("300702020001020102")) }
    }

    @Test fun `locator is locator only`() {
        assertEquals("Abcd_1234-xyz.5678", LocatorOnlyDeepLink.parse("guard-parent://request?locator=Abcd_1234-xyz.5678"))
        assertThrows(IllegalArgumentException::class.java) { LocatorOnlyDeepLink.parse("guard-parent://request?locator=Abcd_1234-xyz.5678&decision=allow") }
    }

    @Test fun `decision duration is bounded`() {
        assertDoesNotThrow { ApprovalChoice(ApprovalDecision.ALLOW_TEMPORARY, 1) }
        assertDoesNotThrow { ApprovalChoice(ApprovalDecision.ALLOW_DAILY_QUOTA, 1440) }
        assertThrows(IllegalArgumentException::class.java) { ApprovalChoice(ApprovalDecision.ALLOW_TEMPORARY, 0) }
        assertThrows(IllegalArgumentException::class.java) { ApprovalChoice(ApprovalDecision.DENY, 1) }
    }

    @Test fun `stop and wait keeps exact bytes until receipt`() {
        val store = MemoryOutbox(); val queue = StopAndWaitApprovals(store); val one = PendingSignedEnvelope("key", 4, byteArrayOf(1))
        queue.persistBeforeSend(one); queue.persistBeforeSend(one)
        assertThrows(IllegalArgumentException::class.java) { queue.persistBeforeSend(PendingSignedEnvelope("key", 5, byteArrayOf(2))) }
        queue.acceptReceipt("key", 4); queue.persistBeforeSend(PendingSignedEnvelope("key", 5, byteArrayOf(2)))
    }

    @Test fun `recovery kit has checksum and needs two copies`() {
        val kit = RecoveryKitGenerator.generate(SecureRandom(byteArrayOf(1,2,3,4)))
        assertTrue(RecoveryKitGenerator.verify(kit.printable)); assertTrue(RecoveryKitConfirmation(kit.printable, kit.printable).confirms())
        val altered = (if (kit.printable.first() == 'A') "B" else "A") + kit.printable.drop(1)
        assertFalse(RecoveryKitGenerator.verify(altered)); assertFalse(RecoveryKitConfirmation(kit.printable, "wrong").confirms())
    }

    @Test fun `unverified snapshot never reaches display model`() {
        val loader = VerifiedSnapshotLoader(SnapshotDecryptor { byteArrayOf(1) }, DeviceSnapshotVerifier { throw SecurityException("bad signature") })
        assertThrows(SecurityException::class.java) { loader.load("Abcd_1234-xyz.5678") }
    }

    @Test fun `biometric source excludes device credential`() {
        assertEquals(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG, BiometricPolicy.allowedAuthenticators())
        val file = generateSequence(File(System.getProperty("user.dir"))) { it.parentFile }.map { File(it, "app/src/main/java/app/guard/parent/security/ApprovalSecurity.kt") }.firstOrNull { it.exists() }
        assertNotNull(file); val text = file!!.readText(); assertTrue(text.contains("AUTH_BIOMETRIC_STRONG")); assertFalse(text.contains("AUTH_DEVICE_CREDENTIAL"))
    }

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
    private class MemoryOutbox : ApprovalOutbox { private val data = mutableMapOf<String, PendingSignedEnvelope>(); override fun load(keyId: String) = data[keyId]; override fun save(envelope: PendingSignedEnvelope) { data[envelope.keyId] = envelope }; override fun remove(keyId: String, sequence: Long) { if (data[keyId]?.sequence == sequence) data.remove(keyId) } }
}
