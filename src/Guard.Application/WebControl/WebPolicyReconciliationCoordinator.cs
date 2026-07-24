using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Domain;
using Guard.Domain.Web;

namespace Guard.Application.WebControl
{
    public enum DesiredWebPolicyCommitStatus
    {
        Committed = 1,
        AlreadyCommitted = 2,
        StaleOrConflicting = 3
    }

    public sealed class WebPolicyReconcileIntent
    {
        public WebPolicyReconcileIntent(
            string deviceId,
            string childSid,
            long desiredRevision,
            DateTimeOffset reconcileAt)
        {
            if (!GuardIdentifier.IsCanonicalToken(deviceId))
            {
                throw new ArgumentException(
                    "A canonical reconcile-intent device identifier is required.",
                    nameof(deviceId));
            }

            if (desiredRevision < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(desiredRevision));
            }

            DeviceId = deviceId;
            ChildSid = new WindowsAccountSid(childSid).Value;
            DesiredRevision = desiredRevision;
            ReconcileAt = reconcileAt;
        }

        public string DeviceId { get; }

        public string ChildSid { get; }

        public long DesiredRevision { get; }

        public DateTimeOffset ReconcileAt { get; }
    }

    public sealed class DesiredWebPolicyCommitResult
    {
        public DesiredWebPolicyCommitResult(
            DesiredWebPolicyCommitStatus status,
            WebPolicyReconcileIntent? durableReconcileIntent)
        {
            if (!Enum.IsDefined(typeof(DesiredWebPolicyCommitStatus), status))
            {
                throw new ArgumentOutOfRangeException(nameof(status));
            }

            var committed =
                status == DesiredWebPolicyCommitStatus.Committed ||
                status == DesiredWebPolicyCommitStatus.AlreadyCommitted;
            if (committed != (durableReconcileIntent != null))
            {
                throw new ArgumentException(
                    "Committed desired state requires its atomic durable reconcile intent; stale state cannot return one.",
                    nameof(durableReconcileIntent));
            }

            Status = status;
            DurableReconcileIntent = durableReconcileIntent;
        }

        public DesiredWebPolicyCommitStatus Status { get; }

        public WebPolicyReconcileIntent? DurableReconcileIntent { get; }
    }

    public interface IDesiredWebPolicyStore
    {
        /// <summary>
        /// Atomically commits one desired revision and a pending reconcile
        /// intent in the same durable transaction. Already-committed revisions
        /// must atomically restore the exact intent if it is missing. Caller
        /// cancellation is checked before this irreversible boundary.
        /// </summary>
        Task<DesiredWebPolicyCommitResult> CommitWithReconcileIntentAsync(
            DesiredWebPolicy desired,
            DateTimeOffset reconcileAt,
            CancellationToken cancellationToken);
    }

    public interface IVerifiedWebCatalogSource
    {
        Task<VerifiedWebCatalogSet?> GetCurrentAsync(
            WebCatalogReference requiredPublicSuffixCatalog,
            WebCatalogReference requiredServiceCatalog,
            CancellationToken cancellationToken);
    }

    public interface IWebPolicySink
    {
        Task ApplyAsync(
            WebPolicyApplyPlan plan,
            CancellationToken cancellationToken);
    }

    public interface IWebPolicyReconcileScheduler
    {
        /// <summary>
        /// Atomically materializes/replaces the timer for the exact desired
        /// revision and acknowledges its durable store intent. If this throws,
        /// the previously committed intent must remain pending for startup or
        /// background draining.
        /// </summary>
        Task ReplaceAsync(
            string deviceId,
            string childSid,
            long desiredRevision,
            DateTimeOffset? nextReconcileAt,
            CancellationToken cancellationToken);
    }

    public interface IWebPolicyAudit
    {
        Task RecordAsync(
            WebPolicyAuditEvent auditEvent,
            CancellationToken cancellationToken);
    }

    public sealed class WebPolicyAuditEvent
    {
        public WebPolicyAuditEvent(
            string eventCode,
            string deviceId,
            string childSid,
            long desiredRevision,
            DateTimeOffset occurredAt)
        {
            if (string.IsNullOrWhiteSpace(eventCode) ||
                eventCode.Length > 128 ||
                !string.Equals(eventCode, eventCode.Trim(), StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "A bounded web-policy event code is required.",
                    nameof(eventCode));
            }

            if (!GuardIdentifier.IsCanonicalToken(deviceId))
            {
                throw new ArgumentException(
                    "A canonical device identifier is required.",
                    nameof(deviceId));
            }

            EventCode = eventCode;
            DeviceId = deviceId;
            ChildSid = new WindowsAccountSid(childSid).Value;
            if (desiredRevision < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(desiredRevision));
            }

            DesiredRevision = desiredRevision;
            OccurredAt = occurredAt;
        }

        public string EventCode { get; }

        public string DeviceId { get; }

        public string ChildSid { get; }

        public long DesiredRevision { get; }

        public DateTimeOffset OccurredAt { get; }
    }

    public enum WebPolicyReconciliationStatus
    {
        DesiredStateCommittedPendingVerifiedCatalogs = 1,
        RejectedStateConflict = 2,
        Applied = 3,
        DesiredStateCommittedPendingReconcile = 4,
        DesiredStatePersistenceFailedClosed = 5
    }

    public sealed class WebPolicyReconciliationResult
    {
        private readonly string[] _diagnostics;

        internal WebPolicyReconciliationResult(
            WebPolicyReconciliationStatus status,
            IEnumerable<string> diagnostics,
            bool auditRecorded,
            DateTimeOffset? nextReconcileAt)
        {
            Status = status;
            _diagnostics = new List<string>(diagnostics).ToArray();
            AuditRecorded = auditRecorded;
            NextReconcileAt = nextReconcileAt;
        }

        public WebPolicyReconciliationStatus Status { get; }

        public IReadOnlyList<string> Diagnostics =>
            Array.AsReadOnly((string[])_diagnostics.Clone());

        public bool AuditRecorded { get; }

        public DateTimeOffset? NextReconcileAt { get; }
    }

    public sealed class WebPolicyReconciliationCoordinator : IDisposable
    {
        private readonly IDesiredWebPolicyStore _store;
        private readonly IVerifiedWebCatalogSource _catalogSource;
        private readonly IWebPolicySink _sink;
        private readonly IWebPolicyReconcileScheduler _scheduler;
        private readonly IWebPolicyAudit _audit;
        private readonly SemaphoreSlim _singleWriter = new SemaphoreSlim(1, 1);
        private int _disposed;

        public WebPolicyReconciliationCoordinator(
            IDesiredWebPolicyStore store,
            IVerifiedWebCatalogSource catalogSource,
            IWebPolicySink sink,
            IWebPolicyReconcileScheduler scheduler,
            IWebPolicyAudit audit)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _catalogSource = catalogSource ??
                             throw new ArgumentNullException(nameof(catalogSource));
            _sink = sink ?? throw new ArgumentNullException(nameof(sink));
            _scheduler = scheduler ?? throw new ArgumentNullException(nameof(scheduler));
            _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        }

        public async Task<WebPolicyReconciliationResult> ReconcileAsync(
            DesiredWebPolicy desired,
            IEnumerable<TrustedDailyWebUsage>? usage,
            DateTimeOffset now,
            CancellationToken cancellationToken)
        {
            if (desired == null)
            {
                throw new ArgumentNullException(nameof(desired));
            }

            ThrowIfDisposed();
            await _singleWriter.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                DefaultDenyWebPolicyPlan? enforcement = null;
                try
                {
                    enforcement = DefaultDenyWebPolicyCompiler.Compile(
                        desired.Grants,
                        usage,
                        now);
                }
                catch (Exception exception) when (IsNonFatal(exception))
                {
                    // Invalid/transient usage evidence still commits desired
                    // state with a bounded retry, but can never reach a sink.
                }

                var atomicRecoveryAt = Earlier(
                    now.AddMinutes(1),
                    enforcement?.NextReconcileAt);

                // Caller cancellation cannot cross the atomic desired-state
                // plus reconcile-intent commit boundary.
                cancellationToken.ThrowIfCancellationRequested();

                DesiredWebPolicyCommitResult? commitResult;
                try
                {
                    commitResult = await _store
                        .CommitWithReconcileIntentAsync(
                            desired,
                            atomicRecoveryAt,
                            CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch (Exception exception) when (IsNonFatal(exception))
                {
                    return await ResultWithAuditAsync(
                        desired,
                        now,
                        WebPolicyReconciliationStatus
                            .DesiredStatePersistenceFailedClosed,
                        "web-policy.persistence-failed-closed",
                        new[]
                        {
                            "Desired web-policy state was not committed; no policy was applied."
                        },
                        null).ConfigureAwait(false);
                }

                if (commitResult == null)
                {
                    return await ResultWithAuditAsync(
                        desired,
                        now,
                        WebPolicyReconciliationStatus
                            .DesiredStatePersistenceFailedClosed,
                        "web-policy.persistence-failed-closed",
                        new[]
                        {
                            "The desired-state store returned no atomic commit result; no policy was applied."
                        },
                        null).ConfigureAwait(false);
                }

                if (commitResult.Status ==
                    DesiredWebPolicyCommitStatus.StaleOrConflicting)
                {
                    return await ResultWithAuditAsync(
                        desired,
                        now,
                        WebPolicyReconciliationStatus.RejectedStateConflict,
                        "web-policy.rejected-state-conflict",
                        new[]
                        {
                            "The desired web-policy revision is stale or conflicts with committed state."
                        },
                        null).ConfigureAwait(false);
                }

                if (!IsExactDurableIntent(
                        desired,
                        atomicRecoveryAt,
                        commitResult))
                {
                    return await ResultWithAuditAsync(
                        desired,
                        now,
                        WebPolicyReconciliationStatus
                            .DesiredStatePersistenceFailedClosed,
                        "web-policy.persistence-failed-closed",
                        new[]
                        {
                            "The desired-state store did not prove an exact atomic reconcile intent; no policy was applied."
                        },
                        null).ConfigureAwait(false);
                }

                if (enforcement == null)
                {
                    return await PendingReconcileAsync(
                        desired,
                        now,
                        atomicRecoveryAt,
                        atomicRecoveryAt,
                        "Committed web policy could not be compiled and must be reconciled again.")
                        .ConfigureAwait(false);
                }

                VerifiedWebCatalogSet? catalogs;
                try
                {
                    catalogs = await _catalogSource.GetCurrentAsync(
                            desired.RequiredPublicSuffixCatalog,
                            desired.RequiredServiceCatalog,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (Exception exception) when (IsNonFatal(exception))
                {
                    catalogs = null;
                }

                if (catalogs == null ||
                    !catalogs.IsValidFor(
                        desired.RequiredPublicSuffixCatalog,
                        desired.RequiredServiceCatalog,
                        now))
                {
                    var retryAt = Earlier(
                        now.AddMinutes(1),
                        enforcement.NextReconcileAt);
                    var durable = await TryReplaceScheduleAsync(
                            desired,
                            retryAt)
                        .ConfigureAwait(false);
                    var diagnostics = new List<string>
                    {
                        "The exact public-suffix and service-bundle catalogs are not currently verified."
                    };
                    if (!durable)
                    {
                        diagnostics.Add(
                            "The exact catalog retry update failed; the atomic recovery intent remains pending.");
                    }

                    return await ResultWithAuditAsync(
                        desired,
                        now,
                        WebPolicyReconciliationStatus
                            .DesiredStateCommittedPendingVerifiedCatalogs,
                        "web-policy.committed-pending-verified-catalogs",
                        diagnostics,
                        durable ? retryAt : atomicRecoveryAt)
                        .ConfigureAwait(false);
                }

                var applyPlan = new WebPolicyApplyPlan(
                    desired,
                    catalogs,
                    enforcement);
                var preApplyRetryAt = Earlier(
                    now.AddMinutes(1),
                    applyPlan.NextReconcileAt);
                if (!await TryReplaceScheduleAsync(desired, preApplyRetryAt)
                        .ConfigureAwait(false))
                {
                    return await ResultWithAuditAsync(
                        desired,
                        now,
                        WebPolicyReconciliationStatus
                            .DesiredStateCommittedPendingReconcile,
                        "web-policy.committed-pending-reconcile",
                        new[]
                        {
                            "The pre-apply deadline update failed, so the web policy was not applied; the atomic recovery intent remains pending."
                        },
                        atomicRecoveryAt).ConfigureAwait(false);
                }

                try
                {
                    await _sink.ApplyAsync(applyPlan, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (Exception exception) when (IsNonFatal(exception))
                {
                    return await ResultWithAuditAsync(
                        desired,
                        now,
                        WebPolicyReconciliationStatus
                            .DesiredStateCommittedPendingReconcile,
                        "web-policy.committed-pending-reconcile",
                        new[]
                        {
                            "Desired web state is durable, but the policy sink must be reconciled again."
                        },
                        preApplyRetryAt).ConfigureAwait(false);
                }

                if (applyPlan.NextReconcileAt != preApplyRetryAt &&
                    !await TryReplaceScheduleAsync(
                            desired,
                            applyPlan.NextReconcileAt)
                        .ConfigureAwait(false))
                {
                    return await ResultWithAuditAsync(
                        desired,
                        now,
                        WebPolicyReconciliationStatus.Applied,
                        "web-policy.applied-retaining-recovery-deadline",
                        new[]
                        {
                            "The applied policy retains its bounded recovery deadline because schedule cleanup failed."
                        },
                        preApplyRetryAt).ConfigureAwait(false);
                }

                return await ResultWithAuditAsync(
                    desired,
                    now,
                    WebPolicyReconciliationStatus.Applied,
                    "web-policy.applied",
                    Array.Empty<string>(),
                    applyPlan.NextReconcileAt).ConfigureAwait(false);
            }
            finally
            {
                _singleWriter.Release();
            }
        }

        public void Dispose()
        {
            Interlocked.Exchange(ref _disposed, 1);
        }

        private async Task<WebPolicyReconciliationResult> PendingReconcileAsync(
            DesiredWebPolicy desired,
            DateTimeOffset now,
            DateTimeOffset retryAt,
            DateTimeOffset atomicRecoveryAt,
            string diagnostic)
        {
            var durable = await TryReplaceScheduleAsync(desired, retryAt)
                .ConfigureAwait(false);
            return await ResultWithAuditAsync(
                desired,
                now,
                WebPolicyReconciliationStatus.DesiredStateCommittedPendingReconcile,
                "web-policy.committed-pending-reconcile",
                durable
                    ? new[] { diagnostic }
                    : new[]
                    {
                        diagnostic,
                        "The retry update failed; the atomic recovery intent remains pending."
                    },
                durable ? retryAt : atomicRecoveryAt).ConfigureAwait(false);
        }

        private async Task<WebPolicyReconciliationResult> ResultWithAuditAsync(
            DesiredWebPolicy desired,
            DateTimeOffset now,
            WebPolicyReconciliationStatus status,
            string eventCode,
            IEnumerable<string> diagnostics,
            DateTimeOffset? nextReconcileAt)
        {
            var audited = await TryAuditAsync(
                    new WebPolicyAuditEvent(
                        eventCode,
                        desired.DeviceId,
                        desired.ChildSid,
                        desired.Revision,
                        now))
                .ConfigureAwait(false);
            return new WebPolicyReconciliationResult(
                status,
                diagnostics,
                audited,
                nextReconcileAt);
        }

        private async Task<bool> TryAuditAsync(WebPolicyAuditEvent auditEvent)
        {
            try
            {
                await _audit.RecordAsync(auditEvent, CancellationToken.None)
                    .ConfigureAwait(false);
                return true;
            }
            catch (Exception exception) when (IsNonFatal(exception))
            {
                return false;
            }
        }

        private async Task<bool> TryReplaceScheduleAsync(
            DesiredWebPolicy desired,
            DateTimeOffset? nextReconcileAt)
        {
            try
            {
                await _scheduler.ReplaceAsync(
                        desired.DeviceId,
                        desired.ChildSid,
                        desired.Revision,
                        nextReconcileAt,
                        CancellationToken.None)
                    .ConfigureAwait(false);
                return true;
            }
            catch (Exception exception) when (IsNonFatal(exception))
            {
                return false;
            }
        }

        private static bool IsExactDurableIntent(
            DesiredWebPolicy desired,
            DateTimeOffset expectedReconcileAt,
            DesiredWebPolicyCommitResult result)
        {
            var intent = result.DurableReconcileIntent;
            return (result.Status == DesiredWebPolicyCommitStatus.Committed ||
                    result.Status ==
                        DesiredWebPolicyCommitStatus.AlreadyCommitted) &&
                   intent != null &&
                   string.Equals(
                       intent.DeviceId,
                       desired.DeviceId,
                       StringComparison.Ordinal) &&
                   string.Equals(
                       intent.ChildSid,
                       desired.ChildSid,
                       StringComparison.Ordinal) &&
                   intent.DesiredRevision == desired.Revision &&
                   intent.ReconcileAt == expectedReconcileAt;
        }

        private static DateTimeOffset Earlier(
            DateTimeOffset recoveryAt,
            DateTimeOffset? naturalAt)
        {
            return naturalAt.HasValue && naturalAt.Value < recoveryAt
                ? naturalAt.Value
                : recoveryAt;
        }

        private static bool IsNonFatal(Exception exception)
        {
            return !(exception is OutOfMemoryException) &&
                   !(exception is StackOverflowException) &&
                   !(exception is AccessViolationException);
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                throw new ObjectDisposedException(
                    nameof(WebPolicyReconciliationCoordinator));
            }
        }
    }
}
