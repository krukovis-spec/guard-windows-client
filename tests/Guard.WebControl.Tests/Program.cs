using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application.WebControl;
using Guard.Domain.Policy;
using Guard.Domain.Web;

namespace Guard.WebControl.Tests
{
    internal static class Program
    {
        private static readonly DateTimeOffset Now =
            new DateTimeOffset(2026, 7, 24, 1, 0, 0, TimeSpan.Zero);

        private static readonly WebCatalogReference PublicSuffixCatalog =
            new WebCatalogReference("psl-icann-private", 20, new string('A', 64), 18);

        private static readonly WebCatalogReference ServiceCatalog =
            new WebCatalogReference("guard-services", 10, new string('B', 64), 8);

        private static async Task<int> Main()
        {
            var tests = new (string Name, Func<Task> Run)[]
            {
                ("rejects grants outside the exact service catalog", RejectsWrongGrantCatalogAsync),
                ("bounds verified catalog validity", BoundsCatalogValidityAsync),
                ("commits before catalog lookup and apply", CommitsBeforeCatalogAndApplyAsync),
                ("uses the earliest natural deadline while catalogs are missing", UsesEarliestMissingCatalogRetryAsync),
                ("rejects mismatched catalog attestations", RejectsMismatchedCatalogsAsync),
                ("does not apply without a durable pre-apply deadline", RequiresDurablePreApplyDeadlineAsync),
                ("retains a durable retry after sink failure", RetainsRetryAfterSinkFailureAsync),
                ("retains a durable retry after post-commit cancellation", RetainsRetryAfterCancellationAsync),
                ("propagates cancellation before commit", PropagatesPreCommitCancellationAsync),
                ("reconciles an already committed revision after crash", ReconcilesAlreadyCommittedAsync),
                ("rejects stale desired state before dependencies", RejectsStaleStateAsync),
                ("schedules retry when committed state cannot compile", SchedulesCompileFailureAsync),
                ("retains the recovery deadline if final scheduling fails", RetainsRecoveryDeadlineAfterApplyAsync),
                ("fails closed when desired-state persistence fails", FailsClosedOnPersistenceFailureAsync)
            };

            var passed = 0;
            foreach (var test in tests)
            {
                try
                {
                    await test.Run().ConfigureAwait(false);
                    Console.WriteLine("PASS " + test.Name);
                    passed++;
                }
                catch (Exception exception)
                {
                    Console.Error.WriteLine(
                        "FAIL " + test.Name + ": " + exception.Message);
                    return 1;
                }
            }

            Console.WriteLine("TOTAL_PASS=" + passed);
            return 0;
        }

        private static Task RejectsWrongGrantCatalogAsync()
        {
            var otherCatalog =
                new WebCatalogReference("other-services", 10, new string('C', 64), 8);
            var wrongGrant = CreateGrant(
                otherCatalog,
                new ParentDecision(ParentDecisionKind.AlwaysAllow));

            AssertThrows<ArgumentException>(
                () => CreateDesired(new[] { wrongGrant }),
                "A grant from another signed catalog was accepted.");
            return Task.CompletedTask;
        }

        private static Task BoundsCatalogValidityAsync()
        {
            AssertThrows<ArgumentOutOfRangeException>(
                () => new VerifiedWebCatalogSet(
                    PublicSuffixCatalog,
                    ServiceCatalog,
                    true,
                    true,
                    true,
                    Now,
                    Now.Add(VerifiedWebCatalogSet.MaximumValidity)
                        .AddTicks(1)),
                "An effectively unbounded catalog attestation was accepted.");
            return Task.CompletedTask;
        }

        private static async Task CommitsBeforeCatalogAndApplyAsync()
        {
            var trace = new List<string>();
            var desired = CreateDesired();
            var scheduler = new FakeScheduler(trace);
            var sink = new FakeSink(trace);
            var store = new FakeStore(
                trace,
                DesiredWebPolicyCommitStatus.Committed);
            using (var coordinator = CreateCoordinator(
                       store,
                       new FakeCatalogSource(trace, CreateCatalogSet()),
                       sink,
                       scheduler,
                       new FakeAudit(trace)))
            {
                var result = await coordinator.ReconcileAsync(
                    desired,
                    null,
                    Now,
                    CancellationToken.None).ConfigureAwait(false);

                AssertEqual(
                    WebPolicyReconciliationStatus.Applied,
                    result.Status,
                    "The verified policy was not applied.");
                Assert(
                    trace.IndexOf("store") < trace.IndexOf("catalog") &&
                    trace.IndexOf("catalog") < trace.IndexOf("schedule-1") &&
                    trace.IndexOf("schedule-1") < trace.IndexOf("sink"),
                    "Desired state was not committed before catalog lookup and apply.");
                Assert(
                    store.DurableIntentAt == Now.AddMinutes(1),
                    "Desired state was committed without its bounded atomic recovery intent.");
                Assert(
                    scheduler.Calls.Count == 2 &&
                    scheduler.Calls[0] == Now.AddMinutes(1) &&
                    scheduler.Calls[1] == Now.AddHours(2),
                    "Recovery and natural deadlines were not persisted in order.");
                Assert(sink.ApplyCount == 1, "The policy sink was not called exactly once.");
            }
        }

        private static async Task UsesEarliestMissingCatalogRetryAsync()
        {
            var trace = new List<string>();
            var expiresAt = Now.AddSeconds(30);
            var desired = CreateDesired(
                grants: new[]
                {
                    CreateGrant(
                        ServiceCatalog,
                        new ParentDecision(
                            ParentDecisionKind.TemporaryAllow,
                            expiresAt))
                });
            var scheduler = new FakeScheduler(trace);
            var sink = new FakeSink(trace);
            using (var coordinator = CreateCoordinator(
                       new FakeStore(trace, DesiredWebPolicyCommitStatus.Committed),
                       new FakeCatalogSource(trace, null),
                       sink,
                       scheduler,
                       new FakeAudit(trace)))
            {
                var result = await coordinator.ReconcileAsync(
                    desired,
                    null,
                    Now,
                    CancellationToken.None).ConfigureAwait(false);

                AssertEqual(
                    WebPolicyReconciliationStatus
                        .DesiredStateCommittedPendingVerifiedCatalogs,
                    result.Status,
                    "Missing catalogs did not fail closed.");
                Assert(
                    scheduler.Calls.Count == 1 &&
                    scheduler.Calls[0] == expiresAt &&
                    result.NextReconcileAt == expiresAt,
                    "The earliest natural revoke deadline was replaced by a later retry.");
                Assert(sink.ApplyCount == 0, "Policy was applied without verified catalogs.");
            }
        }

        private static async Task RejectsMismatchedCatalogsAsync()
        {
            var trace = new List<string>();
            var mismatchedService =
                new WebCatalogReference("guard-services", 11, new string('C', 64), 8);
            var sink = new FakeSink(trace);
            using (var coordinator = CreateCoordinator(
                       new FakeStore(trace, DesiredWebPolicyCommitStatus.Committed),
                       new FakeCatalogSource(
                           trace,
                           CreateCatalogSet(serviceCatalog: mismatchedService)),
                       sink,
                       new FakeScheduler(trace),
                       new FakeAudit(trace)))
            {
                var result = await coordinator.ReconcileAsync(
                    CreateDesired(),
                    null,
                    Now,
                    CancellationToken.None).ConfigureAwait(false);

                AssertEqual(
                    WebPolicyReconciliationStatus
                        .DesiredStateCommittedPendingVerifiedCatalogs,
                    result.Status,
                    "A mismatched service catalog was accepted.");
                Assert(sink.ApplyCount == 0, "Mismatched catalogs reached the sink.");
            }
        }

        private static async Task RequiresDurablePreApplyDeadlineAsync()
        {
            var trace = new List<string>();
            var sink = new FakeSink(trace);
            using (var coordinator = CreateCoordinator(
                       new FakeStore(trace, DesiredWebPolicyCommitStatus.Committed),
                       new FakeCatalogSource(trace, CreateCatalogSet()),
                       sink,
                       new FakeScheduler(trace, throwOnCall: 1),
                       new FakeAudit(trace)))
            {
                var result = await coordinator.ReconcileAsync(
                    CreateDesired(),
                    null,
                    Now,
                    CancellationToken.None).ConfigureAwait(false);

                AssertEqual(
                    WebPolicyReconciliationStatus
                        .DesiredStateCommittedPendingReconcile,
                    result.Status,
                    "A failed recovery-marker write did not stop policy apply.");
                Assert(sink.ApplyCount == 0, "The sink ran without a durable recovery deadline.");
                Assert(
                    result.NextReconcileAt == Now.AddMinutes(1),
                    "The atomic recovery intent was lost after a scheduler failure.");
            }
        }

        private static async Task RetainsRetryAfterSinkFailureAsync()
        {
            var trace = new List<string>();
            var scheduler = new FakeScheduler(trace);
            using (var coordinator = CreateCoordinator(
                       new FakeStore(trace, DesiredWebPolicyCommitStatus.Committed),
                       new FakeCatalogSource(trace, CreateCatalogSet()),
                       new FakeSink(trace, shouldThrow: true),
                       scheduler,
                       new FakeAudit(trace)))
            {
                var result = await coordinator.ReconcileAsync(
                    CreateDesired(),
                    null,
                    Now,
                    CancellationToken.None).ConfigureAwait(false);

                AssertEqual(
                    WebPolicyReconciliationStatus
                        .DesiredStateCommittedPendingReconcile,
                    result.Status,
                    "A sink failure was reported as applied.");
                Assert(
                    scheduler.Calls.Count == 1 &&
                    scheduler.Calls[0] == Now.AddMinutes(1) &&
                    result.NextReconcileAt == Now.AddMinutes(1),
                    "The durable recovery deadline was lost after sink failure.");
            }
        }

        private static async Task RetainsRetryAfterCancellationAsync()
        {
            var trace = new List<string>();
            using (var cancellation = new CancellationTokenSource())
            {
                var scheduler = new FakeScheduler(trace);
                using (var coordinator = CreateCoordinator(
                           new FakeStore(trace, DesiredWebPolicyCommitStatus.Committed),
                           new FakeCatalogSource(trace, CreateCatalogSet()),
                           new FakeSink(trace, cancellationSource: cancellation),
                           scheduler,
                           new FakeAudit(trace)))
                {
                    var result = await coordinator.ReconcileAsync(
                        CreateDesired(),
                        null,
                        Now,
                        cancellation.Token).ConfigureAwait(false);

                    AssertEqual(
                        WebPolicyReconciliationStatus
                            .DesiredStateCommittedPendingReconcile,
                        result.Status,
                        "Post-commit cancellation escaped without a durable retry result.");
                    Assert(
                        scheduler.Calls.Count == 1 &&
                        result.NextReconcileAt == Now.AddMinutes(1),
                        "Cancellation removed the pre-apply recovery deadline.");
                }
            }

            trace = new List<string>();
            using (var cancellation = new CancellationTokenSource())
            {
                var store = new FakeStore(
                    trace,
                    DesiredWebPolicyCommitStatus.Committed,
                    cancellationSource: cancellation);
                var scheduler = new FakeScheduler(trace);
                using (var coordinator = CreateCoordinator(
                           store,
                           new FakeCatalogSource(
                               trace,
                               CreateCatalogSet(),
                               honorCancellation: true),
                           new FakeSink(trace),
                           scheduler,
                           new FakeAudit(trace)))
                {
                    var result = await coordinator.ReconcileAsync(
                        CreateDesired(),
                        null,
                        Now,
                        cancellation.Token).ConfigureAwait(false);

                    Assert(
                        !store.LastTokenCanBeCanceled,
                        "Caller cancellation crossed the atomic desired-state commit boundary.");
                    AssertEqual(
                        WebPolicyReconciliationStatus
                            .DesiredStateCommittedPendingVerifiedCatalogs,
                        result.Status,
                        "Cancellation during commit escaped after desired state became durable.");
                    Assert(
                        scheduler.Calls.Count == 1 &&
                        result.NextReconcileAt == Now.AddMinutes(1),
                        "Cancellation during commit did not leave a durable retry deadline.");
                }
            }
        }

        private static async Task PropagatesPreCommitCancellationAsync()
        {
            var trace = new List<string>();
            using (var cancellation = new CancellationTokenSource())
            using (var coordinator = CreateCoordinator(
                       new FakeStore(trace, DesiredWebPolicyCommitStatus.Committed),
                       new FakeCatalogSource(trace, CreateCatalogSet()),
                       new FakeSink(trace),
                       new FakeScheduler(trace),
                       new FakeAudit(trace)))
            {
                cancellation.Cancel();
                await AssertThrowsAsync<OperationCanceledException>(
                    () => coordinator.ReconcileAsync(
                        CreateDesired(),
                        null,
                        Now,
                        cancellation.Token),
                    "Cancellation before the single-writer gate was swallowed.")
                    .ConfigureAwait(false);
                Assert(trace.Count == 0, "Dependencies ran after pre-commit cancellation.");
            }
        }

        private static async Task ReconcilesAlreadyCommittedAsync()
        {
            var trace = new List<string>();
            var sink = new FakeSink(trace);
            using (var coordinator = CreateCoordinator(
                       new FakeStore(
                           trace,
                           DesiredWebPolicyCommitStatus.AlreadyCommitted),
                       new FakeCatalogSource(trace, CreateCatalogSet()),
                       sink,
                       new FakeScheduler(trace),
                       new FakeAudit(trace)))
            {
                var result = await coordinator.ReconcileAsync(
                    CreateDesired(),
                    null,
                    Now,
                    CancellationToken.None).ConfigureAwait(false);

                AssertEqual(
                    WebPolicyReconciliationStatus.Applied,
                    result.Status,
                    "An already committed revision was not recovered after a crash.");
                Assert(sink.ApplyCount == 1, "Crash recovery did not reapply policy.");
            }
        }

        private static async Task RejectsStaleStateAsync()
        {
            var trace = new List<string>();
            var sink = new FakeSink(trace);
            var scheduler = new FakeScheduler(trace);
            using (var coordinator = CreateCoordinator(
                       new FakeStore(
                           trace,
                           DesiredWebPolicyCommitStatus.StaleOrConflicting),
                       new FakeCatalogSource(trace, CreateCatalogSet()),
                       sink,
                       scheduler,
                       new FakeAudit(trace)))
            {
                var result = await coordinator.ReconcileAsync(
                    CreateDesired(),
                    null,
                    Now,
                    CancellationToken.None).ConfigureAwait(false);

                AssertEqual(
                    WebPolicyReconciliationStatus.RejectedStateConflict,
                    result.Status,
                    "A stale desired revision was not rejected.");
                Assert(
                    !trace.Contains("catalog") &&
                    sink.ApplyCount == 0 &&
                    scheduler.Calls.Count == 0,
                    "A stale revision reached downstream policy dependencies.");
            }
        }

        private static async Task SchedulesCompileFailureAsync()
        {
            var trace = new List<string>();
            var duplicateUsage = new TrustedDailyWebUsage(
                "grant-1",
                0,
                Now.AddSeconds(-10),
                Now.AddSeconds(30));
            var scheduler = new FakeScheduler(trace);
            var sink = new FakeSink(trace);
            using (var coordinator = CreateCoordinator(
                       new FakeStore(trace, DesiredWebPolicyCommitStatus.Committed),
                       new FakeCatalogSource(trace, CreateCatalogSet()),
                       sink,
                       scheduler,
                       new FakeAudit(trace)))
            {
                var result = await coordinator.ReconcileAsync(
                    CreateDesired(),
                    new[] { duplicateUsage, duplicateUsage },
                    Now,
                    CancellationToken.None).ConfigureAwait(false);

                AssertEqual(
                    WebPolicyReconciliationStatus
                        .DesiredStateCommittedPendingReconcile,
                    result.Status,
                    "A compile failure did not become pending reconciliation.");
                Assert(
                    scheduler.Calls.Count == 1 &&
                    scheduler.Calls[0] == Now.AddMinutes(1),
                    "A compile failure did not create the bounded retry marker.");
                Assert(sink.ApplyCount == 0, "Invalid compiled state reached the sink.");
            }
        }

        private static async Task RetainsRecoveryDeadlineAfterApplyAsync()
        {
            var trace = new List<string>();
            var scheduler = new FakeScheduler(trace, throwOnCall: 2);
            var sink = new FakeSink(trace);
            using (var coordinator = CreateCoordinator(
                       new FakeStore(trace, DesiredWebPolicyCommitStatus.Committed),
                       new FakeCatalogSource(trace, CreateCatalogSet()),
                       sink,
                       scheduler,
                       new FakeAudit(trace)))
            {
                var result = await coordinator.ReconcileAsync(
                    CreateDesired(),
                    null,
                    Now,
                    CancellationToken.None).ConfigureAwait(false);

                AssertEqual(
                    WebPolicyReconciliationStatus.Applied,
                    result.Status,
                    "A successfully applied policy was reported as unapplied.");
                Assert(
                    sink.ApplyCount == 1 &&
                    scheduler.Calls.Count == 2 &&
                    result.NextReconcileAt == Now.AddMinutes(1),
                    "The bounded recovery deadline was cleared after final scheduling failed.");
            }
        }

        private static async Task FailsClosedOnPersistenceFailureAsync()
        {
            var trace = new List<string>();
            var sink = new FakeSink(trace);
            var scheduler = new FakeScheduler(trace);
            using (var coordinator = CreateCoordinator(
                       new FakeStore(
                           trace,
                           DesiredWebPolicyCommitStatus.Committed,
                           shouldThrow: true),
                       new FakeCatalogSource(trace, CreateCatalogSet()),
                       sink,
                       scheduler,
                       new FakeAudit(trace)))
            {
                var result = await coordinator.ReconcileAsync(
                    CreateDesired(),
                    null,
                    Now,
                    CancellationToken.None).ConfigureAwait(false);

                AssertEqual(
                    WebPolicyReconciliationStatus
                        .DesiredStatePersistenceFailedClosed,
                    result.Status,
                    "Persistence failure did not fail closed.");
                Assert(
                    !trace.Contains("catalog") &&
                    sink.ApplyCount == 0 &&
                    scheduler.Calls.Count == 0,
                    "Dependencies ran after desired-state persistence failed.");
            }

            trace = new List<string>();
            sink = new FakeSink(trace);
            scheduler = new FakeScheduler(trace);
            using (var coordinator = CreateCoordinator(
                       new FakeStore(
                           trace,
                           DesiredWebPolicyCommitStatus.Committed,
                           returnMismatchedIntent: true),
                       new FakeCatalogSource(trace, CreateCatalogSet()),
                       sink,
                       scheduler,
                       new FakeAudit(trace)))
            {
                var result = await coordinator.ReconcileAsync(
                    CreateDesired(),
                    null,
                    Now,
                    CancellationToken.None).ConfigureAwait(false);

                AssertEqual(
                    WebPolicyReconciliationStatus
                        .DesiredStatePersistenceFailedClosed,
                    result.Status,
                    "A mismatched atomic reconcile intent was trusted.");
                Assert(
                    !trace.Contains("catalog") &&
                    sink.ApplyCount == 0 &&
                    scheduler.Calls.Count == 0,
                    "A mismatched atomic intent reached downstream dependencies.");
            }
        }

        private static WebPolicyReconciliationCoordinator CreateCoordinator(
            IDesiredWebPolicyStore store,
            IVerifiedWebCatalogSource catalogSource,
            IWebPolicySink sink,
            IWebPolicyReconcileScheduler scheduler,
            IWebPolicyAudit audit)
        {
            return new WebPolicyReconciliationCoordinator(
                store,
                catalogSource,
                sink,
                scheduler,
                audit);
        }

        private static DesiredWebPolicy CreateDesired(
            IEnumerable<WebAccessGrant>? grants = null)
        {
            return new DesiredWebPolicy(
                "device-0000000001",
                "S-1-5-21-1000-1001-1002-1003",
                7,
                PublicSuffixCatalog,
                ServiceCatalog,
                grants ?? new[]
                {
                    CreateGrant(
                        ServiceCatalog,
                        new ParentDecision(ParentDecisionKind.AlwaysAllow))
                });
        }

        private static WebAccessGrant CreateGrant(
            WebCatalogReference catalog,
            ParentDecision decision)
        {
            var bundle = new WebServiceBundle(
                "bundle-1",
                new[] { WebScope.ExactHost("example.test") });
            var signature = new WebBundleSignature(
                catalog.CatalogId,
                catalog.Revision,
                3,
                Now.AddMinutes(-1),
                Now.AddHours(4),
                "2.0.0",
                bundle.CanonicalDigestSha256(),
                "release-key-1",
                new byte[] { 1, 2, 3 });
            var verified = VerifiedWebServiceBundle.Verify(
                bundle,
                signature,
                new AcceptingBundleVerifier(),
                new WebBundleAcceptanceFloor(
                    catalog.CatalogId,
                    bundle.BundleId,
                    catalog.RollbackFloor,
                    signature.BundleVersion,
                    bundle.CanonicalDigestSha256()),
                new Version("2.0.0"),
                Now);
            return new WebAccessGrant("grant-1", verified, decision);
        }

        private static VerifiedWebCatalogSet CreateCatalogSet(
            WebCatalogReference? serviceCatalog = null)
        {
            return new VerifiedWebCatalogSet(
                PublicSuffixCatalog,
                serviceCatalog ?? ServiceCatalog,
                true,
                true,
                true,
                Now.AddMinutes(-1),
                Now.AddHours(2));
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private static void AssertEqual<T>(T expected, T actual, string message)
            where T : notnull
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
            {
                throw new InvalidOperationException(
                    message + " Expected=" + expected + ", actual=" + actual + ".");
            }
        }

        private static void AssertThrows<TException>(
            Action action,
            string message)
            where TException : Exception
        {
            try
            {
                action();
            }
            catch (TException)
            {
                return;
            }

            throw new InvalidOperationException(message);
        }

        private static async Task AssertThrowsAsync<TException>(
            Func<Task> action,
            string message)
            where TException : Exception
        {
            try
            {
                await action().ConfigureAwait(false);
            }
            catch (TException)
            {
                return;
            }

            throw new InvalidOperationException(message);
        }

        private sealed class AcceptingBundleVerifier : IWebBundleSignatureVerifier
        {
            public bool Verify(
                string signingKeyId,
                byte[] canonicalBundleBytes,
                byte[] signature)
            {
                return true;
            }
        }

        private sealed class FakeStore : IDesiredWebPolicyStore
        {
            private readonly List<string> _trace;
            private readonly DesiredWebPolicyCommitStatus _status;
            private readonly bool _shouldThrow;
            private readonly CancellationTokenSource? _cancellationSource;
            private readonly bool _returnMismatchedIntent;

            public FakeStore(
                List<string> trace,
                DesiredWebPolicyCommitStatus status,
                bool shouldThrow = false,
                CancellationTokenSource? cancellationSource = null,
                bool returnMismatchedIntent = false)
            {
                _trace = trace;
                _status = status;
                _shouldThrow = shouldThrow;
                _cancellationSource = cancellationSource;
                _returnMismatchedIntent = returnMismatchedIntent;
            }

            public bool LastTokenCanBeCanceled { get; private set; }

            public DateTimeOffset? DurableIntentAt { get; private set; }

            public Task<DesiredWebPolicyCommitResult>
                CommitWithReconcileIntentAsync(
                DesiredWebPolicy desired,
                DateTimeOffset reconcileAt,
                CancellationToken cancellationToken)
            {
                _trace.Add("store");
                LastTokenCanBeCanceled = cancellationToken.CanBeCanceled;
                if (_cancellationSource != null)
                {
                    _cancellationSource.Cancel();
                    cancellationToken.ThrowIfCancellationRequested();
                }

                if (_shouldThrow)
                {
                    throw new InvalidOperationException("store failed");
                }

                WebPolicyReconcileIntent? intent = null;
                if (_status == DesiredWebPolicyCommitStatus.Committed ||
                    _status ==
                        DesiredWebPolicyCommitStatus.AlreadyCommitted)
                {
                    DurableIntentAt = reconcileAt;
                    intent = new WebPolicyReconcileIntent(
                        desired.DeviceId,
                        desired.ChildSid,
                        desired.Revision,
                        _returnMismatchedIntent
                            ? reconcileAt.AddMinutes(1)
                            : reconcileAt);
                }

                return Task.FromResult(
                    new DesiredWebPolicyCommitResult(_status, intent));
            }
        }

        private sealed class FakeCatalogSource : IVerifiedWebCatalogSource
        {
            private readonly List<string> _trace;
            private readonly VerifiedWebCatalogSet? _catalogs;
            private readonly bool _honorCancellation;

            public FakeCatalogSource(
                List<string> trace,
                VerifiedWebCatalogSet? catalogs,
                bool honorCancellation = false)
            {
                _trace = trace;
                _catalogs = catalogs;
                _honorCancellation = honorCancellation;
            }

            public Task<VerifiedWebCatalogSet?> GetCurrentAsync(
                WebCatalogReference requiredPublicSuffixCatalog,
                WebCatalogReference requiredServiceCatalog,
                CancellationToken cancellationToken)
            {
                _trace.Add("catalog");
                if (_honorCancellation)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                }

                return Task.FromResult(_catalogs);
            }
        }

        private sealed class FakeSink : IWebPolicySink
        {
            private readonly List<string> _trace;
            private readonly bool _shouldThrow;
            private readonly CancellationTokenSource? _cancellationSource;

            public FakeSink(
                List<string> trace,
                bool shouldThrow = false,
                CancellationTokenSource? cancellationSource = null)
            {
                _trace = trace;
                _shouldThrow = shouldThrow;
                _cancellationSource = cancellationSource;
            }

            public int ApplyCount { get; private set; }

            public Task ApplyAsync(
                WebPolicyApplyPlan plan,
                CancellationToken cancellationToken)
            {
                _trace.Add("sink");
                ApplyCount++;
                if (_cancellationSource != null)
                {
                    _cancellationSource.Cancel();
                    throw new OperationCanceledException(
                        _cancellationSource.Token);
                }

                if (_shouldThrow)
                {
                    throw new InvalidOperationException("sink failed");
                }

                return Task.CompletedTask;
            }
        }

        private sealed class FakeScheduler : IWebPolicyReconcileScheduler
        {
            private readonly List<string> _trace;
            private readonly int _throwOnCall;

            public FakeScheduler(
                List<string> trace,
                int throwOnCall = 0)
            {
                _trace = trace;
                _throwOnCall = throwOnCall;
            }

            public List<DateTimeOffset?> Calls { get; } =
                new List<DateTimeOffset?>();

            public Task ReplaceAsync(
                string deviceId,
                string childSid,
                long desiredRevision,
                DateTimeOffset? nextReconcileAt,
                CancellationToken cancellationToken)
            {
                Calls.Add(nextReconcileAt);
                _trace.Add("schedule-" + Calls.Count);
                if (_throwOnCall == Calls.Count)
                {
                    throw new InvalidOperationException("scheduler failed");
                }

                return Task.CompletedTask;
            }
        }

        private sealed class FakeAudit : IWebPolicyAudit
        {
            private readonly List<string> _trace;

            public FakeAudit(List<string> trace)
            {
                _trace = trace;
            }

            public Task RecordAsync(
                WebPolicyAuditEvent auditEvent,
                CancellationToken cancellationToken)
            {
                _trace.Add("audit");
                return Task.CompletedTask;
            }
        }
    }
}
