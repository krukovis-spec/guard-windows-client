package app.guard.parent.enrollment

import app.guard.parent.protocol.EnrollmentExchange
import app.guard.parent.protocol.EnrollmentResult
import app.guard.parent.protocol.EnrollmentWire

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
