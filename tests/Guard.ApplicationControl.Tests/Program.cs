using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application.ApplicationControl;
using Guard.Domain.Policy;

namespace Guard.ApplicationControl.Tests
{
    internal static class Program
    {
        private const string HashA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        private const string CatalogHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("commits but never applies an unattested policy", NeverAppliesUnattestedPolicy),
                ("commits desired state before applying policy", CommitsBeforeApply),
                ("persists a deadline before applying temporary access", PersistsDeadlineBeforeTemporaryApply),
                ("does not apply when the deadline is not durable", RejectsUndurableDeadline),
                ("removes a temporary rule on scheduled reconciliation", RemovesExpiredRuleOnScheduledReconcile),
                ("retains a bounded retry when expiry apply fails", RetainsRetryAfterExpiryApplyFailure),
                ("retains a bounded retry when permanent revoke apply fails", RetainsRetryAfterPermanentRevokeApplyFailure),
                ("uses a short recovery retry before a later natural deadline", UsesShortRetryBeforeLaterNaturalDeadline),
                ("retains durable retry intent after post-commit cancellation", RetainsRetryAfterPostCommitCancellation),
                ("does not apply a stale or conflicting revision", RejectsConflict),
                ("keeps committed desired state when apply fails", KeepsDesiredStateOnApplyFailure),
                ("reconciles an already committed revision after crash", ReconcilesAlreadyCommittedState),
                ("serializes authoritative application-policy writes", SerializesWriters)
            };

            var failures = 0;
            foreach (var test in tests)
            {
                try
                {
                    test.Run();
                    Console.WriteLine("PASS " + test.Name);
                }
                catch (Exception exception)
                {
                    failures++;
                    Console.WriteLine("FAIL " + test.Name + ": " + exception.Message);
                }
            }

            Console.WriteLine(failures == 0 ? "All Guard application-control checks passed." : failures + " application-control check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void NeverAppliesUnattestedPolicy()
        {
            var trace = new List<string>();
            var store = new FakeStore(trace, DesiredApplicationPolicyCommitStatus.Committed);
            var sink = new FakeSink(trace);
            var scheduler = new FakeScheduler(trace);
            using (var coordinator = new ApplicationPolicyReconciliationCoordinator(
                store,
                new FakeCatalogSource(null),
                sink,
                scheduler,
                new FakeAudit(trace)))
            {
                var result = coordinator.ReconcileAsync(CreateDesired(), null, Now(), CancellationToken.None)
                    .GetAwaiter().GetResult();
                AssertEqual(
                    ApplicationPolicyReconciliationStatus.DesiredStateCommittedPendingVerifiedRuleCatalog,
                    result.Status,
                    "Unattested policy was not retained for safe recovery.");
                AssertEqual(Now().AddMinutes(1), result.NextReconcileAt, "Unattested policy did not request a retry.");
            }

            AssertEqual(1, store.CallCount, "Unattested desired state was lost instead of being committed.");
            AssertEqual(1, scheduler.CallCount, "Unattested desired state did not schedule a retry.");
            AssertEqual(0, sink.CallCount, "Unattested policy reached the policy sink.");
        }

        private static void CommitsBeforeApply()
        {
            var trace = new List<string>();
            var store = new FakeStore(trace, DesiredApplicationPolicyCommitStatus.Committed);
            var sink = new FakeSink(trace);
            using (var coordinator = CreateCoordinator(store, sink, trace))
            {
                var result = coordinator.ReconcileAsync(CreateDesired(), null, Now(), CancellationToken.None)
                    .GetAwaiter().GetResult();
                AssertEqual(ApplicationPolicyReconciliationStatus.Applied, result.Status, "Verified desired policy was not applied.");
            }

            AssertEqual("commit", trace[0], "Policy apply happened before durable desired-state commit.");
            AssertEqual("schedule", trace[1], "Reconciliation schedule was not persisted after commit.");
            AssertEqual("apply", trace[2], "Policy sink was not called after commit and schedule.");
        }

        private static void PersistsDeadlineBeforeTemporaryApply()
        {
            var trace = new List<string>();
            var store = new FakeStore(trace, DesiredApplicationPolicyCommitStatus.Committed);
            var sink = new FakeSink(trace);
            var scheduler = new FakeScheduler(trace);
            var desired = CreateDesired(
                1,
                new ParentDecision(ParentDecisionKind.TemporaryAllow, Now().AddMinutes(15)));
            using (var coordinator = CreateCoordinator(store, sink, scheduler, trace))
            {
                var result = coordinator.ReconcileAsync(desired, null, Now(), CancellationToken.None)
                    .GetAwaiter().GetResult();
                AssertEqual(ApplicationPolicyReconciliationStatus.Applied, result.Status, "Temporary policy was not applied.");
                AssertEqual(Now().AddMinutes(15), result.NextReconcileAt, "Temporary expiry was not exposed.");
            }

            AssertEqual(Now().AddMinutes(15), scheduler.LastDeadline, "Temporary expiry was not made durable.");
            AssertEqual("schedule", trace[1], "Temporary rule was applied before its expiry schedule.");
            AssertEqual("apply", trace[2], "Temporary rule did not reach the sink after scheduling.");
        }

        private static void RejectsUndurableDeadline()
        {
            var trace = new List<string>();
            var store = new FakeStore(trace, DesiredApplicationPolicyCommitStatus.Committed);
            var sink = new FakeSink(trace);
            var scheduler = new FakeScheduler(trace, shouldThrow: true);
            var desired = CreateDesired(
                1,
                new ParentDecision(ParentDecisionKind.TemporaryAllow, Now().AddMinutes(15)));
            using (var coordinator = CreateCoordinator(store, sink, scheduler, trace))
            {
                var result = coordinator.ReconcileAsync(desired, null, Now(), CancellationToken.None)
                    .GetAwaiter().GetResult();
                AssertEqual(
                    ApplicationPolicyReconciliationStatus.DesiredStateCommittedPendingReconcile,
                    result.Status,
                    "Undurable expiry schedule was reported as applied.");
                AssertEqual<DateTimeOffset?>(null, result.NextReconcileAt, "Undurable expiry schedule was reported as a durable retry.");
            }

            AssertEqual(0, sink.CallCount, "A temporary allow was applied without a durable expiry schedule.");
        }

        private static void RemovesExpiredRuleOnScheduledReconcile()
        {
            var trace = new List<string>();
            var store = new FakeStore(trace, DesiredApplicationPolicyCommitStatus.AlreadyCommitted);
            var sink = new FakeSink(trace);
            var scheduler = new FakeScheduler(trace);
            var expiry = Now().AddMinutes(15);
            var desired = CreateDesired(
                1,
                new ParentDecision(ParentDecisionKind.TemporaryAllow, expiry));
            using (var coordinator = CreateCoordinator(store, sink, scheduler, trace))
            {
                var initial = coordinator.ReconcileAsync(desired, null, Now(), CancellationToken.None)
                    .GetAwaiter().GetResult();
                AssertEqual(expiry, initial.NextReconcileAt, "Temporary rule did not schedule its expiry.");
                AssertEqual(1, CountRules(sink.LastPlan), "Temporary rule was not initially applied.");

                var expired = coordinator.ReconcileAsync(desired, null, expiry, CancellationToken.None)
                    .GetAwaiter().GetResult();
                AssertEqual(ApplicationPolicyReconciliationStatus.Applied, expired.Status, "Scheduled expiry reconciliation failed.");
                AssertEqual(0, CountRules(sink.LastPlan), "Expired temporary rule remained in the applied plan.");
                AssertEqual<DateTimeOffset?>(null, expired.NextReconcileAt, "Expired rule retained a deadline.");
            }

            AssertEqual<DateTimeOffset?>(null, scheduler.LastDeadline, "Expired rule did not clear its durable deadline.");
        }

        private static void RetainsRetryAfterExpiryApplyFailure()
        {
            var trace = new List<string>();
            var store = new FakeStore(trace, DesiredApplicationPolicyCommitStatus.AlreadyCommitted);
            var sink = new FakeSink(trace, throwOnCall: 2);
            var scheduler = new FakeScheduler(trace);
            var expiry = Now().AddMinutes(15);
            var desired = CreateDesired(1, new ParentDecision(ParentDecisionKind.TemporaryAllow, expiry));
            using (var coordinator = CreateCoordinator(store, sink, scheduler, trace))
            {
                coordinator.ReconcileAsync(desired, null, Now(), CancellationToken.None).GetAwaiter().GetResult();
                var expired = coordinator.ReconcileAsync(desired, null, expiry, CancellationToken.None).GetAwaiter().GetResult();
                AssertEqual(ApplicationPolicyReconciliationStatus.DesiredStateCommittedPendingReconcile, expired.Status, "Expired policy apply failure was not retained for retry.");
                AssertEqual(expiry.AddMinutes(1), expired.NextReconcileAt, "Expired policy apply failure did not retain a bounded retry.");
            }

            AssertEqual(expiry.AddMinutes(1), scheduler.LastDeadline, "Expiry reconciliation cleared the retry deadline before a failed apply.");
            AssertEqual(0, CountRules(sink.LastPlan), "Expiry reconciliation did not attempt to revoke the temporary rule.");
        }

        private static void RetainsRetryAfterPermanentRevokeApplyFailure()
        {
            var trace = new List<string>();
            var store = new FakeStore(trace, DesiredApplicationPolicyCommitStatus.Committed);
            var sink = new FakeSink(trace, shouldThrow: true);
            var scheduler = new FakeScheduler(trace);
            var desired = CreateDesired(1, new ParentDecision(ParentDecisionKind.Deny));
            using (var coordinator = CreateCoordinator(store, sink, scheduler, trace))
            {
                var result = coordinator.ReconcileAsync(desired, null, Now(), CancellationToken.None).GetAwaiter().GetResult();
                AssertEqual(ApplicationPolicyReconciliationStatus.DesiredStateCommittedPendingReconcile, result.Status, "Permanent revoke apply failure was not retained for retry.");
                AssertEqual(Now().AddMinutes(1), result.NextReconcileAt, "Permanent revoke apply failure did not retain a bounded retry.");
            }

            AssertEqual(Now().AddMinutes(1), scheduler.LastDeadline, "Permanent revoke cleared or omitted its retry deadline before a failed apply.");
            AssertEqual(0, CountRules(sink.LastPlan), "Permanent revoke did not produce a deny-only plan.");
        }

        private static void UsesShortRetryBeforeLaterNaturalDeadline()
        {
            var trace = new List<string>();
            var store = new FakeStore(trace, DesiredApplicationPolicyCommitStatus.Committed);
            var sink = new FakeSink(trace, shouldThrow: true);
            var scheduler = new FakeScheduler(trace);
            var desired = CreateDesired(
                1,
                new ParentDecision(ParentDecisionKind.TemporaryAllow, Now().AddMinutes(15)));
            using (var coordinator = CreateCoordinator(store, sink, scheduler, trace))
            {
                var result = coordinator.ReconcileAsync(desired, null, Now(), CancellationToken.None)
                    .GetAwaiter().GetResult();
                AssertEqual(
                    ApplicationPolicyReconciliationStatus.DesiredStateCommittedPendingReconcile,
                    result.Status,
                    "Apply failure with a later natural deadline was not retained for retry.");
                AssertEqual(
                    Now().AddMinutes(1),
                    result.NextReconcileAt,
                    "A later natural deadline delayed recovery from the failed policy apply.");
            }

            AssertEqual(
                Now().AddMinutes(1),
                scheduler.LastDeadline,
                "The durable recovery deadline was not bounded independently of the natural grant expiry.");
        }

        private static void RetainsRetryAfterPostCommitCancellation()
        {
            var trace = new List<string>();
            using (var cancellation = new CancellationTokenSource())
            {
                var store = new FakeStore(trace, DesiredApplicationPolicyCommitStatus.Committed);
                var sink = new FakeSink(trace, cancelOnCall: cancellation);
                var scheduler = new FakeScheduler(trace);
                var desired = CreateDesired(1, new ParentDecision(ParentDecisionKind.Deny));
                using (var coordinator = CreateCoordinator(store, sink, scheduler, trace))
                {
                    var result = coordinator.ReconcileAsync(desired, null, Now(), cancellation.Token).GetAwaiter().GetResult();
                    AssertEqual(ApplicationPolicyReconciliationStatus.DesiredStateCommittedPendingReconcile, result.Status, "Post-commit cancellation lost the pending reconciliation state.");
                    AssertEqual(Now().AddMinutes(1), result.NextReconcileAt, "Post-commit cancellation lost the durable retry deadline.");
                }

                AssertEqual(Now().AddMinutes(1), scheduler.LastDeadline, "Post-commit cancellation did not preserve the durable retry deadline.");
            }
        }

        private static void RejectsConflict()
        {
            var trace = new List<string>();
            var store = new FakeStore(trace, DesiredApplicationPolicyCommitStatus.StaleOrConflicting);
            var sink = new FakeSink(trace);
            using (var coordinator = CreateCoordinator(store, sink, trace))
            {
                var result = coordinator.ReconcileAsync(CreateDesired(), null, Now(), CancellationToken.None)
                    .GetAwaiter().GetResult();
                AssertEqual(ApplicationPolicyReconciliationStatus.RejectedStateConflict, result.Status, "Stale desired state was not rejected.");
            }

            AssertEqual(0, sink.CallCount, "Conflicting desired state reached the policy sink.");
        }

        private static void KeepsDesiredStateOnApplyFailure()
        {
            var trace = new List<string>();
            var store = new FakeStore(trace, DesiredApplicationPolicyCommitStatus.Committed);
            var sink = new FakeSink(trace, shouldThrow: true);
            using (var coordinator = CreateCoordinator(store, sink, trace))
            {
                var result = coordinator.ReconcileAsync(CreateDesired(), null, Now(), CancellationToken.None)
                    .GetAwaiter().GetResult();
                AssertEqual(
                    ApplicationPolicyReconciliationStatus.DesiredStateCommittedPendingReconcile,
                    result.Status,
                    "Apply failure did not preserve a recoverable desired-state result.");
            }

            AssertEqual(1, store.CallCount, "Desired state was not committed exactly once.");
            AssertEqual(1, sink.CallCount, "Policy sink was not attempted exactly once.");
        }

        private static void ReconcilesAlreadyCommittedState()
        {
            var trace = new List<string>();
            var store = new FakeStore(trace, DesiredApplicationPolicyCommitStatus.AlreadyCommitted);
            var sink = new FakeSink(trace);
            using (var coordinator = CreateCoordinator(store, sink, trace))
            {
                var result = coordinator.ReconcileAsync(CreateDesired(), null, Now(), CancellationToken.None)
                    .GetAwaiter().GetResult();
                AssertEqual(ApplicationPolicyReconciliationStatus.Applied, result.Status, "Crash-recovery reconciliation was rejected.");
            }

            AssertEqual(1, sink.CallCount, "Already committed desired state was not reconciled.");
        }

        private static void SerializesWriters()
        {
            var trace = new List<string>();
            var store = new BlockingStore(trace);
            var sink = new FakeSink(trace);
            using (var coordinator = CreateCoordinator(store, sink, trace))
            {
                var first = coordinator.ReconcileAsync(CreateDesired(1), null, Now(), CancellationToken.None);
                store.FirstEntered.Task.GetAwaiter().GetResult();
                var second = coordinator.ReconcileAsync(CreateDesired(2), null, Now(), CancellationToken.None);
                AssertEqual(1, store.CallCount, "Second writer entered before the first writer completed.");
                store.ReleaseFirst.SetResult(true);
                Task.WhenAll(first, second).GetAwaiter().GetResult();
            }

            AssertEqual(2, store.CallCount, "Serialized second writer never ran.");
            AssertEqual(1, store.MaximumConcurrentCalls, "Application-policy writers ran concurrently.");
        }

        private static ApplicationPolicyReconciliationCoordinator CreateCoordinator(
            IDesiredApplicationPolicyStore store,
            IApplicationPolicySink sink,
            List<string> trace)
        {
            return CreateCoordinator(store, sink, new FakeScheduler(trace), trace);
        }

        private static ApplicationPolicyReconciliationCoordinator CreateCoordinator(
            IDesiredApplicationPolicyStore store,
            IApplicationPolicySink sink,
            IApplicationPolicyReconcileScheduler scheduler,
            List<string> trace)
        {
            var desired = CreateDesired();
            return new ApplicationPolicyReconciliationCoordinator(
                store,
                new FakeCatalogSource(CreateAttestation(desired.RequiredRuleCatalog)),
                sink,
                scheduler,
                new FakeAudit(trace));
        }

        private static DesiredApplicationPolicy CreateDesired(
            long revision = 1,
            ParentDecision? decision = null)
        {
            var catalog = new RuleCatalogReference("guard-v2-win11pro", "1", CatalogHash, "26100.1000", "2.0.0");
            var grant = new ExactApplicationGrant(
                "grant-1",
                "device-v2-000001",
                "S-1-5-21-1000-1001-1002-1003",
                AppControlCollection.Executable,
                new ApplicationIdentity(null, null, null, HashA),
                decision ?? new ParentDecision(ParentDecisionKind.AlwaysAllow));
            return new DesiredApplicationPolicy(
                "device-v2-000001",
                "S-1-5-21-1000-1001-1002-1003",
                revision,
                catalog,
                new[] { grant });
        }

        private static DisposableVmRuleCatalogAttestation CreateAttestation(RuleCatalogReference catalog)
        {
            return new DisposableVmRuleCatalogAttestation(
                catalog,
                new[]
                {
                    AppControlCollection.Executable,
                    AppControlCollection.WindowsInstaller,
                    AppControlCollection.Script,
                    AppControlCollection.PackagedApp,
                    AppControlCollection.DynamicLibrary
                },
                guardSelfProtectionVerified: true,
                criticalSystemToolsVerified: true,
                arbitraryLaunchMatrixVerified: true,
                Now().AddMinutes(-1));
        }

        private static DateTimeOffset Now() => new DateTimeOffset(2026, 7, 23, 12, 0, 0, TimeSpan.Zero);

        private sealed class FakeStore : IDesiredApplicationPolicyStore
        {
            private readonly List<string> _trace;
            private readonly DesiredApplicationPolicyCommitStatus _status;

            public FakeStore(List<string> trace, DesiredApplicationPolicyCommitStatus status)
            {
                _trace = trace;
                _status = status;
            }

            public int CallCount { get; private set; }

            public Task<DesiredApplicationPolicyCommitStatus> CommitAsync(
                DesiredApplicationPolicy desired,
                CancellationToken cancellationToken)
            {
                CallCount++;
                _trace.Add("commit");
                return Task.FromResult(_status);
            }
        }

        private sealed class BlockingStore : IDesiredApplicationPolicyStore
        {
            private int _concurrentCalls;

            public BlockingStore(List<string> trace)
            {
                Trace = trace;
            }

            public List<string> Trace { get; }

            public TaskCompletionSource<bool> FirstEntered { get; } =
                new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            public TaskCompletionSource<bool> ReleaseFirst { get; } =
                new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            public int CallCount { get; private set; }

            public int MaximumConcurrentCalls { get; private set; }

            public async Task<DesiredApplicationPolicyCommitStatus> CommitAsync(
                DesiredApplicationPolicy desired,
                CancellationToken cancellationToken)
            {
                CallCount++;
                _concurrentCalls++;
                if (_concurrentCalls > MaximumConcurrentCalls)
                {
                    MaximumConcurrentCalls = _concurrentCalls;
                }

                Trace.Add("commit");
                if (CallCount == 1)
                {
                    FirstEntered.SetResult(true);
                    await ReleaseFirst.Task.ConfigureAwait(false);
                }

                _concurrentCalls--;
                return DesiredApplicationPolicyCommitStatus.Committed;
            }
        }

        private sealed class FakeCatalogSource : IVerifiedRuleCatalogSource
        {
            private readonly DisposableVmRuleCatalogAttestation? _attestation;

            public FakeCatalogSource(DisposableVmRuleCatalogAttestation? attestation)
            {
                _attestation = attestation;
            }

            public Task<DisposableVmRuleCatalogAttestation?> GetCurrentAsync(
                RuleCatalogReference requiredCatalog,
                CancellationToken cancellationToken)
            {
                return Task.FromResult(_attestation);
            }
        }

        private sealed class FakeSink : IApplicationPolicySink
        {
            private readonly List<string> _trace;
            private readonly bool _shouldThrow;
            private readonly int? _throwOnCall;
            private readonly CancellationTokenSource? _cancelOnCall;

            public FakeSink(
                List<string> trace,
                bool shouldThrow = false,
                int? throwOnCall = null,
                CancellationTokenSource? cancelOnCall = null)
            {
                _trace = trace;
                _shouldThrow = shouldThrow;
                _throwOnCall = throwOnCall;
                _cancelOnCall = cancelOnCall;
            }

            public int CallCount { get; private set; }

            public DefaultDenyApplicationPolicyPlan? LastPlan { get; private set; }

            public Task ApplyAsync(DefaultDenyApplicationPolicyPlan plan, CancellationToken cancellationToken)
            {
                CallCount++;
                LastPlan = plan;
                _trace.Add("apply");
                if (_cancelOnCall != null)
                {
                    _cancelOnCall.Cancel();
                    throw new OperationCanceledException(cancellationToken);
                }

                if (_shouldThrow || _throwOnCall == CallCount)
                {
                    throw new InvalidOperationException("Synthetic sink failure.");
                }

                return Task.CompletedTask;
            }
        }

        private static int CountRules(DefaultDenyApplicationPolicyPlan? plan)
        {
            if (plan == null)
            {
                return 0;
            }

            var count = 0;
            foreach (var collection in plan.Collections)
            {
                count += collection.AllowRules.Count;
            }

            return count;
        }

        private sealed class FakeScheduler : IApplicationPolicyReconcileScheduler
        {
            private readonly List<string> _trace;
            private readonly bool _shouldThrow;

            public FakeScheduler(List<string> trace, bool shouldThrow = false)
            {
                _trace = trace;
                _shouldThrow = shouldThrow;
            }

            public int CallCount { get; private set; }

            public DateTimeOffset? LastDeadline { get; private set; }

            public Task ReplaceAsync(
                string deviceId,
                long desiredRevision,
                DateTimeOffset? nextReconcileAt,
                CancellationToken cancellationToken)
            {
                CallCount++;
                LastDeadline = nextReconcileAt;
                _trace.Add("schedule");
                if (_shouldThrow)
                {
                    throw new InvalidOperationException("Synthetic scheduler failure.");
                }

                return Task.CompletedTask;
            }
        }

        private sealed class FakeAudit : IApplicationPolicyAudit
        {
            private readonly List<string> _trace;

            public FakeAudit(List<string> trace)
            {
                _trace = trace;
            }

            public Task RecordAsync(ApplicationPolicyAuditEvent auditEvent, CancellationToken cancellationToken)
            {
                _trace.Add("audit:" + auditEvent.EventCode);
                return Task.CompletedTask;
            }
        }

        private static void AssertEqual<T>(T expected, T actual, string message)
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
            {
                throw new InvalidOperationException(message + " Expected=" + expected + ", actual=" + actual + ".");
            }
        }
    }
}
