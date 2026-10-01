package app.guard.parent.enrollment

import android.content.ContentResolver
import android.net.Uri
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import app.guard.parent.protocol.NativeRelayProfile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Only an explicitly selected local, whole regular file. No URI retention, streaming providers or metadata trust. */
internal object NativeProfileDocument {
    // ponytail: one outstanding provider call per process; an uncooperative provider must drain before retry.
    private val reading = AtomicBoolean(false)

    suspend fun read(resolver: ContentResolver, uri: Uri): ByteArray = withTimeout(20_000) {
        require(uri.scheme == ContentResolver.SCHEME_CONTENT) { "content document required" }
        check(reading.compareAndSet(false, true)) { "document provider still busy" }
        suspendCancellableCoroutine { continuation ->
            val signal = CancellationSignal()
            val active = AtomicReference<InputStream?>()
            continuation.invokeOnCancellation {
                // Provider cancellation may involve Binder. Do not wait for it on the UI thread.
                Dispatchers.IO.dispatch(continuation.context, Runnable {
                    runCatching { active.getAndSet(null)?.close() }
                    runCatching { signal.cancel() }
                })
            }
            Dispatchers.IO.dispatch(continuation.context, Runnable {
                try {
                    fun checkActive() { check(continuation.isActive && !signal.isCanceled) { "document read cancelled" } }
                    checkActive()
                    val bytes = requireNotNull(resolver.openFileDescriptor(uri, "r", signal)).use { descriptor ->
                        checkActive()
                        val stat = Os.fstat(descriptor.fileDescriptor)
                        require(OsConstants.S_ISREG(stat.st_mode) && stat.st_size == NativeRelayProfile.FILE_BYTES.toLong()) {
                            "download the complete local profile first"
                        }
                        ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { input ->
                            active.set(input)
                            try { readNativeProfileBytes(input, ::checkActive) }
                            finally { active.compareAndSet(input, null) }
                        }
                    }
                    continuation.resume(bytes)
                } catch (_: Exception) {
                    // Provider errors can contain private paths/URIs. Never propagate or display them.
                    continuation.resumeWithException(IOException("native profile file unavailable"))
                } finally { reading.set(false) }
            })
        }
    }
}

/** One extra byte detects growth/trailing data; no unbounded read or zero-progress loop. */
internal fun readNativeProfileBytes(input: InputStream, checkActive: () -> Unit): ByteArray {
    val buffer = ByteArray(NativeRelayProfile.FILE_BYTES + 1)
    var count = 0
    while (count < buffer.size) {
        checkActive()
        val size = input.read(buffer, count, buffer.size - count)
        if (size < 0) break
        require(size in 1..(buffer.size - count)) { "document read made no progress" }
        count += size
    }
    checkActive()
    require(count == NativeRelayProfile.FILE_BYTES) { "native profile file size" }
    return buffer.copyOf(count)
}
