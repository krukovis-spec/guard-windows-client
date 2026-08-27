using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Guard.Domain.Policy;

namespace Guard.Application.ApplicationControl
{
    public enum DesiredApplicationPolicyCommitStatus
    {
        Committed = 1,
        AlreadyCommitted = 2,
        StaleOrConflicting = 3
    }

    public interface IDesiredApplicationPolicyStore
    {
        Task<DesiredApplicationPolicyCommitStatus> CommitAsync(
            DesiredApplicationPolicy desired,
            CancellationToken cancellationToken);
    }

    public interface IVerifiedRuleCatalogSource
    {
        Task<DisposableVmRuleCatalogAttestation?> GetCurrentAsync(
            RuleCatalogReference requiredCatalog,
            CancellationToken cancellationToken);
    }

    public interface IApplicationPolicySink
    {
        Task ApplyAsync(
            DefaultDenyApplicationPolicyPlan plan,
            CancellationToken cancellationToken);
    }

    public interface IApplicationPolicyReconcileScheduler
    {
        Task ReplaceAsync(
            string deviceId,
            long desiredRevision,
            DateTimeOffset? nextReconcileAt,
            CancellationToken cancellationToken);
    }

    public interface IApplicationPolicyAudit
    {
        Task RecordAsync(ApplicationPolicyAuditEvent auditEvent, CancellationToken cancellationToken);
    }

    public sealed class ApplicationPolicyAuditEvent
    {
        public ApplicationPolicyAuditEvent(
            string eventCode,
            string deviceId,
            long desiredRevision,
            DateTimeOffset occurredAt)
        {
            if (string.IsNullOrWhiteSpace(eventCode) || eventCode.Trim().Length > 128)
            {
                throw new ArgumentException("A bounded application-policy event code is required.", nameof(eventCode));
            }

            if (string.IsNullOrWhiteSpace(deviceId) || deviceId.Trim().Length > 128)
            {
                throw new ArgumentException("A bounded device id is required.", nameof(deviceId));
            }

            if (desiredRevision < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(desiredRevision));
            }

            EventCode = eventCode.Trim();
            DeviceId = deviceId.Trim();
            DesiredRevision = desiredRevision;
            OccurredAt = occurredAt;
        }

        public string EventCode { get; }

        public string DeviceId { get; }

        public long DesiredRevision { get; }

        public DateTimeOffset OccurredAt { get; }
    }

    public enum ApplicationPolicyReconciliationStatus
    {
        DesiredStateCommittedPendingVerifiedRuleCatalog = 1,
        RejectedStateConflict = 2,
        Applied = 3,
        DesiredStateCommittedPendingReconcile = 4,
        DesiredStatePersistenceFailedClosed = 5
    }

    public sealed class ApplicationPolicyReconciliationResult
    {
        private readonly string[] _diagnostics;

        internal ApplicationPolicyReconciliationResult(
            ApplicationPolicyReconciliationStatus status,
            IEnumerable<string> diagnostics,
            bool auditRecorded,
            DateTimeOffset? nextReconcileAt)
        {
            Status = status;
            _diagnostics = new List<string>(diagnostics).ToArray();
            AuditRecorded = auditRecorded;
            NextReconcileAt = nextReconcileAt;
        }

        public ApplicationPolicyReconciliationStatus Status { get; }

        public IReadOnlyList<string> Diagnostics =>
            Array.AsReadOnly((string[])_diagnostics.Clone());

        public bool AuditRecorded { get; }

        public DateTimeOffset? NextReconcileAt { get; }
    }

    public sealed class ApplicationPolicyReconciliationCoordinator : IDisposable
    {
        private readonly IDesiredApplicationPolicyStore _store;
        private readonly IVerifiedRuleCatalogSource _catalogSource;
        private readonly IApplicationPolicySink _sink;
        private readonly IApplicationPolicyReconcileScheduler _scheduler;
        private readonly IApplicationPolicyAudit _audit;
        private readonly SemaphoreSlim _singleWriter = new SemaphoreSlim(1, 1);
        private bool _disposed;

        public ApplicationPolicyReconciliationCoordinator(
            IDesiredApplicationPolicyStore store,
            IVerifiedRuleCatalogSource catalogSource,
            IApplicationPolicySink sink,
            IApplicationPolicyReconcileScheduler scheduler,
            IApplicationPolicyAudit audit)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _catalogSource = catalogSource ?? throw new ArgumentNullException(nameof(catalogSource));
            _sink = sink ?? throw new ArgumentNullException(nameof(sink));
            _scheduler = scheduler ?? throw new ArgumentNullException(nameof(scheduler));
            _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        }

        public async Task<ApplicationPolicyReconciliationResult> ReconcileAsync(
            DesiredApplicationPolicy desired,
            IEnumerable<ApplicationGrantRuntimeState>? runtimeStates,
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
                DesiredApplicationPolicyCommitStatus commitStatus;
                try
                {
                    commitStatus = await _store.CommitAsync(desired, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception exception) when (IsNonFatal(exception))
                {
                    var audited = await TryAuditAsync(
                        new ApplicationPolicyAuditEvent(
                            "application-policy.persistence-failed-closed",
                            desired.DeviceId,
                            desired.Revision,
                            now)).ConfigureAwait(false);
                    return new ApplicationPolicyReconciliationResult(
                        ApplicationPolicyReconciliationStatus.DesiredStatePersistenceFailedClosed,
                        new[] { "Desired application-policy state was not committed; no policy was applied." },
                        audited,
                        null);
                }

                if (commitStatus == DesiredApplicationPolicyCommitStatus.StaleOrConflicting)
                {
                    var audited = await TryAuditAsync(
                        new ApplicationPolicyAuditEvent(
                            "application-policy.rejected-state-conflict",
                            desired.DeviceId,
                            desired.Revision,
                            now)).ConfigureAwait(false);
                    return new ApplicationPolicyReconciliationResult(
                        ApplicationPolicyReconciliationStatus.RejectedStateConflict,
                        new[] { "The desired application-policy revision is stale or conflicts with committed state." },
                        audited,
                        null);
                }

                if (commitStatus != DesiredApplicationPolicyCommitStatus.Committed &&
                    commitStatus != DesiredApplicationPolicyCommitStatus.AlreadyCommitted)
                {
                    throw new InvalidOperationException("The desired-state store returned an unsupported commit status.");
                }

                DisposableVmRuleCatalogAttestation? attestation;
                try
                {
                    attestation = await _catalogSource
                        .GetCurrentAsync(desired.RequiredRuleCatalog, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    attestation = null;
                }
                catch (Exception exception) when (IsNonFatal(exception))
                {
                    attestation = null;
                }

                var plan = DefaultDenyApplicationPolicyCompiler.Compile(desired, attestation, runtimeStates, now);
                if (!plan.CanApply)
                {
                    var retryAt = now.AddMinutes(1);
                    var diagnostics = new List<string>(plan.Diagnostics);
                    var retryIsDurable = await TryReplaceScheduleAsync(
                        desired.DeviceId,
                        desired.Revision,
                        retryAt).ConfigureAwait(false);
                    if (!retryIsDurable)
                    {
                        diagnostics.Add("The catalog retry deadline could not be made durable.");
                    }

                    var audited = await TryAuditAsync(
                        new ApplicationPolicyAuditEvent(
                            "application-policy.committed-pending-verified-catalog",
                            desired.DeviceId,
                            desired.Revision,
                            now)).ConfigureAwait(false);
                    return new ApplicationPolicyReconciliationResult(
                        ApplicationPolicyReconciliationStatus.DesiredStateCommittedPendingVerifiedRuleCatalog,
                        diagnostics,
                        audited,
                        retryIsDurable ? retryAt : null);
                }

                var boundedRetryAt = now.AddMinutes(1);
                var preApplyRetryAt =
                    plan.NextReconcileAt.HasValue && plan.NextReconcileAt.Value < boundedRetryAt
                        ? plan.NextReconcileAt.Value
                        : boundedRetryAt;
                if (!await TryReplaceScheduleAsync(
                        desired.DeviceId,
                        desired.Revision,
                        preApplyRetryAt).ConfigureAwait(false))
                {
                    var audited = await TryAuditAsync(
                        new ApplicationPolicyAuditEvent(
                            "application-policy.committed-pending-reconcile",
                            desired.DeviceId,
                            desired.Revision,
                            now)).ConfigureAwait(false);
                    return new ApplicationPolicyReconciliationResult(
                        ApplicationPolicyReconciliationStatus.DesiredStateCommittedPendingReconcile,
                        AppendDiagnostic(
                            plan.Diagnostics,
                            "The reconciliation deadline was not durable, so the policy was not applied."),
                        audited,
                        null);
                }

                try
                {
                    await _sink.ApplyAsync(plan, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (IsNonFatal(exception))
                {
                    var audited = await TryAuditAsync(
                        new ApplicationPolicyAuditEvent(
                            "application-policy.committed-pending-reconcile",
                            desired.DeviceId,
                            desired.Revision,
                            now)).ConfigureAwait(false);
                    return new ApplicationPolicyReconciliationResult(
                        ApplicationPolicyReconciliationStatus.DesiredStateCommittedPendingReconcile,
                        new[] { "Desired state is durable, but the policy sink must be reconciled again." },
                        audited,
                        preApplyRetryAt);
                }

                if (plan.NextReconcileAt == preApplyRetryAt)
                {
                    var alreadyScheduledAppliedAudit = await TryAuditAsync(
                        new ApplicationPolicyAuditEvent(
                            "application-policy.applied",
                            desired.DeviceId,
                            desired.Revision,
                            now)).ConfigureAwait(false);
                    return new ApplicationPolicyReconciliationResult(
                        ApplicationPolicyReconciliationStatus.Applied,
                        plan.Diagnostics,
                        alreadyScheduledAppliedAudit,
                        plan.NextReconcileAt);
                }

                if (!await TryReplaceScheduleAsync(
                        desired.DeviceId,
                        desired.Revision,
                        plan.NextReconcileAt).ConfigureAwait(false))
                {
                    var audited = await TryAuditAsync(
                        new ApplicationPolicyAuditEvent(
                            "application-policy.committed-pending-reconcile",
                            desired.DeviceId,
                            desired.Revision,
                            now)).ConfigureAwait(false);
                    return new ApplicationPolicyReconciliationResult(
                        ApplicationPolicyReconciliationStatus.Applied,
                        AppendDiagnostic(
                            plan.Diagnostics,
                            "The applied policy retains its prior durable reconciliation deadline because cleanup could not be persisted."),
                        audited,
                        preApplyRetryAt);
                }

                var appliedAudit = await TryAuditAsync(
                    new ApplicationPolicyAuditEvent(
                        "application-policy.applied",
                        desired.DeviceId,
                        desired.Revision,
                        now)).ConfigureAwait(false);
                return new ApplicationPolicyReconciliationResult(
                    ApplicationPolicyReconciliationStatus.Applied,
                    plan.Diagnostics,
                    appliedAudit,
                    plan.NextReconcileAt);
            }
            finally
            {
                _singleWriter.Release();
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _singleWriter.Dispose();
        }

        private async Task<bool> TryAuditAsync(ApplicationPolicyAuditEvent auditEvent)
        {
            try
            {
                await _audit.RecordAsync(auditEvent, CancellationToken.None).ConfigureAwait(false);
                return true;
            }
            catch (Exception exception) when (!(exception is OutOfMemoryException) &&
                                              !(exception is StackOverflowException) &&
                                              !(exception is AccessViolationException))
            {
                return false;
            }
        }

        private async Task<bool> TryReplaceScheduleAsync(
            string deviceId,
            long desiredRevision,
            DateTimeOffset? nextReconcileAt)
        {
            try
            {
                await _scheduler
                    .ReplaceAsync(deviceId, desiredRevision, nextReconcileAt, CancellationToken.None)
                    .ConfigureAwait(false);
                return true;
            }
            catch (Exception exception) when (IsNonFatal(exception))
            {
                return false;
            }
        }

        private static IReadOnlyList<string> AppendDiagnostic(
            IEnumerable<string> diagnostics,
            string additional)
        {
            var result = new List<string>(diagnostics) { additional };
            return result;
        }

        private static bool IsNonFatal(Exception exception)
        {
            return !(exception is OutOfMemoryException) &&
                   !(exception is StackOverflowException) &&
                   !(exception is AccessViolationException);
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(ApplicationPolicyReconciliationCoordinator));
            }
        }
    }
}
