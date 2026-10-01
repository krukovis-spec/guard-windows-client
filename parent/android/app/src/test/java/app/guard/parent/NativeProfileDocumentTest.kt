package app.guard.parent

import app.guard.parent.enrollment.readNativeProfileBytes
import app.guard.parent.protocol.NativeRelayProfile
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.util.concurrent.CancellationException

class NativeProfileDocumentTest {
    private val bytes = ByteArray(NativeRelayProfile.FILE_BYTES) { it.toByte() }

    @Test fun `reads exact file in partial chunks and refuses every truncation and trailing bytes`() {
        val input = object : ByteArrayInputStream(bytes) {
            override fun read(destination: ByteArray, offset: Int, length: Int): Int = super.read(destination, offset, minOf(3, length))
        }
        assertArrayEquals(bytes, readNativeProfileBytes(input) {})
        for (size in bytes.indices) assertThrows(IllegalArgumentException::class.java) {
            readNativeProfileBytes(ByteArrayInputStream(bytes.copyOf(size))) {}
        }
        val oversized = ByteArrayInputStream(bytes + ByteArray(1000))
        assertThrows(IllegalArgumentException::class.java) { readNativeProfileBytes(oversized) {} }
        assertEquals(999, oversized.available()) // No unbounded draining of untrusted content.
    }

    @Test fun `zero progress errors and cancellation never return a profile`() {
        val stalled = object : InputStream() {
            override fun read(): Int = error("no single-byte reads")
            override fun read(destination: ByteArray, offset: Int, length: Int) = 0
        }
        assertThrows(IllegalArgumentException::class.java) { readNativeProfileBytes(stalled) {} }
        val input = ByteArrayInputStream(bytes)
        assertThrows(CancellationException::class.java) {
            readNativeProfileBytes(input) { throw CancellationException() }
        }
        assertEquals(bytes.size, input.available())
        var checks = 0
        assertThrows(CancellationException::class.java) {
            readNativeProfileBytes(ByteArrayInputStream(bytes)) { if (++checks == 3) throw CancellationException() }
        }
        assertEquals(3, checks) // Including the last check after EOF, before publication to the caller.
    }
}
