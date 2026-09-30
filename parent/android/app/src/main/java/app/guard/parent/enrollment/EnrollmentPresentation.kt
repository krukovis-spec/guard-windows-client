package app.guard.parent.enrollment

import app.guard.parent.protocol.EnrollmentExchange
import app.guard.parent.protocol.EnrollmentResult
import app.guard.parent.protocol.EnrollmentWire
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive

/** Presentation only: callers must obtain result from ceremony.inspect, never relay JSON/HTTP flags. */
internal enum class EnrollmentStage {
    RESCAN, BIOMETRIC, WAITING, COMPARE, QUERY_ONLY, CONFIRMED, EXPIRED, STOPPED, RECOVERY;
    val canSynchronize get() = this == WAITING || this == COMPARE || this == QUERY_ONLY
}

internal fun enrollmentStage(state: PendingEnrollment, verifiedResult: EnrollmentResult?, now: Long): EnrollmentStage {
    if (now < state.observedUnixMillis) return EnrollmentStage.RECOVERY
    if (verifiedResult?.outcome == EnrollmentExchange.CONFIRMED) return EnrollmentStage.CONFIRMED
    val active = !state.abandoned && now < state.offer.expiryUnixMillis
    if (state.isSigned) {
        if (now - state.offer.expiryUnixMillis >= 86_400_000) return EnrollmentStage.RECOVERY
        if (state.capability().size != 32) return if (active) EnrollmentStage.RESCAN else EnrollmentStage.RECOVERY
        if (!active) return EnrollmentStage.QUERY_ONLY
        return if (verifiedResult?.outcome == EnrollmentExchange.NEEDS_LOCAL_CONFIRMATION) EnrollmentStage.COMPARE else EnrollmentStage.WAITING
    }
    if (state.abandoned) return EnrollmentStage.STOPPED
    if (!active) return EnrollmentStage.EXPIRED
    return if (state.claim == null) EnrollmentStage.RESCAN else EnrollmentStage.BIOMETRIC
}

/** All 256 bits, grouped for visual comparison; no shortened-code or clipboard shortcut. */
internal fun enrollmentComparison(state: PendingEnrollment): String =
    EnrollmentWire.claimHash(requireNotNull(state.claim)).joinToString("") { "%02x".format(it) }
        .chunked(8).joinToString("\n")

/** Owned by one foreground screen. Inspect re-verifies stored evidence; exchange never signs or confirms locally. */
internal suspend fun awaitEnrollment(
    inspect: suspend () -> Pair<PendingEnrollment, EnrollmentResult?>,
    exchange: suspend () -> Unit,
    display: (PendingEnrollment, EnrollmentResult?, Boolean) -> Unit,
    now: () -> Long = System::currentTimeMillis
) {
    var failures = 0
    while (true) {
        currentCoroutineContext().ensureActive()
        val (before, priorResult) = inspect()
        currentCoroutineContext().ensureActive()
        display(before, priorResult, failures != 0)
        if (!enrollmentStage(before, priorResult, now()).canSynchronize) return
        try {
            exchange()
            failures = 0
        } catch (timeout: TimeoutCancellationException) {
            currentCoroutineContext().ensureActive() // A transport deadline is retryable, screen cancellation is not.
            failures = minOf(failures + 1, 5)
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: EnrollmentExchangeUnavailable) { failures = minOf(failures + 1, 5) }
        // Storage/key/cryptographic failures deliberately escape instead of becoming endless network retries.
        val (after, verified) = inspect()
        currentCoroutineContext().ensureActive()
        display(after, verified, failures != 0)
        if (!enrollmentStage(after, verified, now()).canSynchronize) return
        // One outstanding exchange; 2s normal polling, 2/4/8/16/30s after consecutive network failures.
        delay(if (failures == 0) 2000 else minOf(2000L shl (failures - 1), 30000))
    }
}
