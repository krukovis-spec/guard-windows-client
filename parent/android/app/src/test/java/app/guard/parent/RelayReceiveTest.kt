package app.guard.parent

import app.guard.parent.protocol.RelayReceive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class RelayReceiveTest {
    // Canonical GRF1 fixture emitted by the .NET RelayCanonicalEncoding test suite.
    private val golden = hex("475246310000000100000002000000126d61696c626f782d616c7068612d3030303100000012726563697069656e742d6b65792d30303031000000116672616d652d616c7068612d3030303031000000000000000b000000000000000a0000019f93ff31b80000019f93ff35a0000000410102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40410000002065666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384")

    @Test fun `decodes exact canonical GRF1 fixture`() {
        val frame = RelayReceive.decodeFrame(golden)
        assertEquals(2, frame.aad.kind)
        assertEquals("mailbox-alpha-0001", frame.aad.mailboxId)
        assertEquals("recipient-key-0001", frame.aad.recipientKeyId)
        assertEquals(65, frame.encapsulatedKey.size)
        assertEquals(32, frame.ciphertext.size)
    }

    @Test fun `rejects trailing malformed and off-curve frames`() {
        assertThrows(IllegalArgumentException::class.java) { RelayReceive.decodeFrame(golden + byteArrayOf(0)) }
        assertThrows(IllegalArgumentException::class.java) { RelayReceive.decodeFrame(golden.copyOf(golden.size - 1)) }
        val bad = golden.copyOf(); bad[0] = 0 // corrupts the canonical GRF1 magic
        assertThrows(IllegalArgumentException::class.java) { RelayReceive.decodeFrame(bad) }
    }

    private fun hex(value: String): ByteArray = ByteArray(value.length / 2) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
}
