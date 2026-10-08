package app.guard.parent

import androidx.test.ext.junit.runners.AndroidJUnit4
import app.guard.parent.approval.NativeInboxPageCodec
import app.guard.parent.protocol.*
import app.guard.parent.security.EcdsaP1363
import app.guard.parent.security.PendingSignedEnvelope
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.PrivateKey
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/** Exercise Android's ICU grammar, not the desktop JVM. No network, storage or real keys. */
@RunWith(AndroidJUnit4::class)
class NativeInboxAndroidTest {
    @Test fun reservationResponseUsesAndroidGrammarWithoutChangingSignedApproval() {
        fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val signing = pair(); val encryption = pair(); val approval = pair(); val phone = pair()
        val now = 1_800_000_000_000L
        val offer = EnrollmentOffer("https://relay.example.test", "enrollment-test1", "device-test-0001", "Test PC",
            1, 1, "mailbox-test-0001", "device-signing-001", signing.public.encoded.takeLast(65).toByteArray(),
            "device-encrypt-001", encryption.public.encoded.takeLast(65).toByteArray(), now - 1000, now + 300000, ByteArray(32) { 1 })
        val claim = EnrollmentKeyClaim(EnrollmentWire.offerHash(offer), "phone-approval-001", approval.public.encoded,
            "phone-encrypt-001", phone.public.encoded.takeLast(65).toByteArray())
        val unsigned = SignedApproval(1, claim.approvalKeyId, 1, "command-test-0001", "nonce-test-00001", now, now + 60000,
            offer.deviceId, 1, "request-test-0001", 1, ByteArray(32) { 2 }, ByteArray(32) { 3 },
            TargetKind.WEBSITE, "https://example.test", 0, ApprovalDecision.DENY, 0, ByteArray(64))
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(approval.private); update(GuardWire.encodeApprovalSignatureInput(unsigned))
        }.sign()
        val pending = PendingSignedEnvelope(claim.approvalKeyId, 1,
            GuardWire.encodeSignedApproval(unsigned.copy(signatureP1363 = EcdsaP1363.fromDer(signature))))
        val attempt = NativeApprovalAttempt.prepare(pending, offer, claim, now, now + 86400000)
        val response = "{\"frameId\":\"${attempt.frameId}\",\"recipientKeyId\":\"${offer.encryptionKeyId}\",\"cursor\":7," +
            "\"createdAt\":${attempt.created},\"expiresAt\":${attempt.expiry},\"leaseExpiresAt\":${now + 60000}," +
            "\"status\":\"reserved\",\"nonAuthoritative\":true}"
        val sealed = attempt.seal(pending, offer, claim, response.toByteArray(), 201, now)
        assertEquals(7L, sealed.cursor); assertFalse(sealed.published)
        val frame = RelayReceive.decodeFrame(sealed.frameBytes())
        val deviceKey = object : RelayEncryptionKey {
            override fun privateKey(): PrivateKey = encryption.private
            override fun publicKeySec1() = offer.encryptionKey()
        }
        val aad = GuardWire.encodeRelayFrameAssociatedData(frame.aad)
        assertArrayEquals(pending.exactBytes, HpkeP256.decrypt(deviceKey, frame.encapsulatedKey, frame.ciphertext, aad,
            "guard-relay-approval-hpke-v1".toByteArray() + aad))
        for (bad in listOf(response + "}", response.replace("true}", "false}"), response.replace("\"cursor\":7", "\"cursor\":0"))) {
            assertThrows(IllegalArgumentException::class.java) { attempt.seal(pending, offer, claim, bad.toByteArray(), 201, now) }
        }
    }

    @Test fun emptyInboxAcceptsBothFieldOrdersAndRejectsMalformedPages() {
        val unusedKey = object : RelayEncryptionKey {
            override fun privateKey(): PrivateKey = error("Empty page must not decrypt")
            override fun publicKeySec1(): ByteArray = error("Empty page must not use a key")
        }
        val recipient = RelayRecipient("mailbox-test-0001", "phone-test-00001", 1, unusedKey)
        for (cursor in listOf(0L, NativeInboxPageCodec.MAX_CURSOR)) {
            for (json in listOf("{\"frames\":[],\"nextCursor\":$cursor}",
                " \n{ \"nextCursor\" : $cursor, \"frames\" : [ \t\r\n ] }\t")) {
                val (frames, next) = NativeInboxPageCodec.decode(json.toByteArray(), recipient, cursor)
                assertTrue(frames.isEmpty()); assertEquals(cursor, next)
            }
        }
        for (json in listOf("{}", "{\"frames\":[],\"nextCursor\":0,\"nextCursor\":0}",
            "{\"frames\":[],\"nextCursor\":00}", "{\"frames\":[],\"nextCursor\":9007199254740992}",
            "{\"frames\":[],\"nextCursor\":1}", "{\"frames\":[[]],\"nextCursor\":0}",
            "{\"frames\":[],\"nextCursor\":0}}", "{\"frames\":[],\"nextCursor\":0}\u000b")) {
            assertThrows(IllegalArgumentException::class.java) {
                NativeInboxPageCodec.decode(json.toByteArray(), recipient, 0)
            }
        }
    }
}
