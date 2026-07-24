using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Contracts;
using Guard.Domain;
using Guard.Domain.Policy;
using Guard.Domain.Web;

namespace Guard.WebsiteRequests.Tests
{
    internal static class Program
    {
        private const string DeviceA = "device-website-000001";
        private const string DeviceB = "device-website-000002";
        private const string ObservationA =
            "observation-website-000001";
        private const string ObservationB =
            "observation-website-000002";
        private const string PrimaryHostA =
            "login.school.example.co.uk";
        private const string PrimaryHostB =
            "www.example.co.uk";
        private const string OtherHost =
            "unrelated.example.net";

        private static readonly WindowsAccountSid ChildA =
            new WindowsAccountSid("S-1-5-21-1000");
        private static readonly WindowsAccountSid ChildB =
            new WindowsAccountSid("S-1-5-21-2000");
        private static readonly DateTimeOffset Now =
            new DateTimeOffset(
                2026,
                7,
                24,
                10,
                0,
                0,
                TimeSpan.Zero);

        private static async Task<int> Main()
        {
            var tests = new List<(string Name, Func<Task> Run)>
            {
                ("creates an exact request from service evidence", CreatesExactRequestAsync),
                ("queues an unknown site without creating a grant", QueuesUnknownSiteWithoutGrantAsync),
                ("deduplicates repeated service requests atomically", DeduplicatesServiceRequestsAsync),
                ("rejects missing forged expired and cross-bound observations", RejectsInvalidObservationsAsync),
                ("requires host evidence and a matching signed bundle", RequiresBoundEvidenceAsync),
                ("takes all website identity only from the resolver", UsesResolverIdentityOnlyAsync),
                ("atomically rate-limits the authenticated child before dependencies", EnforcesRateLimitBeforeDependenciesAsync),
                ("fails closed when the rate limiter fails or mismatches", FailsClosedOnRateLimiterErrorsAsync),
                ("fails closed on dependency and store mismatches", FailsClosedOnDependencyErrorsAsync),
                ("commits request and audit intent across the cancellation boundary", CommitsAcrossCancellationBoundaryAsync),
                ("returns committed request when immediate audit delivery fails", ReportsCommittedRequestWhenImmediateAuditFailsAsync),
                ("preserves caller cancellation semantics", PreservesCancellationAsync),
                ("keeps request and audit models immutable and bound", KeepsModelsImmutableAsync)
            };

            var failures = 0;
            foreach (var test in tests)
            {
                try
                {
                    await test.Run().ConfigureAwait(false);
                    Console.WriteLine("PASS " + test.Name);
                }
                catch (Exception exception)
                {
                    failures++;
                    Console.WriteLine(
                        "FAIL " + test.Name + ": " + exception.Message);
                }
            }

            Console.WriteLine(
                failures == 0
                    ? "All website request checks passed."
                    : failures +
                      " website request check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static async Task CreatesExactRequestAsync()
        {
            var evidence = CreateEvidence(PrimaryHostA);
            var bundle = CreateBundle(evidence, "service:school");
            var observation = CreateObservation(
                ObservationA,
                DeviceA,
                ChildA,
                evidence,
                bundle,
                Now.AddSeconds(-10),
                Now.AddMinutes(2));
            var resolver = new FakeResolver(observation);
            var store = new AtomicFakeStore();
            var audit = new FakeAudit();
            var rateLimiter =
                new AtomicRateLimiter(int.MaxValue);
            var coordinator = new WebsiteAccessRequestCoordinator(
                rateLimiter,
                resolver,
                store,
                audit);

            var result = await coordinator.CreateAsync(
                new AuthenticatedChildContext(DeviceA, ChildA),
                new CreateWebsiteRequestPayload(
                    ObservationA,
                    "Needed for homework"),
                Now,
                CancellationToken.None).ConfigureAwait(false);

            Assert(
                result.Status == WebsiteAccessRequestStatus.Created,
                "A valid request was not created.");
            Assert(
                result.Request != null,
                "A successful request returned no record.");
            var request = result.Request!;
            Assert(
                request.CanonicalHost.Value == PrimaryHostA,
                "The verified canonical host changed.");
            Assert(
                request.RegistrableDomainEvidence
                    .RegistrableDomain.Value == "example.co.uk",
                "The trusted registrable domain changed.");
            Assert(
                request.ServiceBundleCandidate!.Bundle.BundleId ==
                    "service:school",
                "The signed service-bundle candidate changed.");
            Assert(
                request.RequestKey.Equals(
                    AccessRequestKey.ForSite(
                        DeviceA,
                        "example.co.uk")),
                "The service-level dedupe key changed.");
            Assert(
                request.ChildAccountSid.Equals(ChildA),
                "The authenticated child binding changed.");
            Assert(
                request.ObservationId == ObservationA,
                "The source observation was not retained.");
            Assert(
                request.DisplayName == "School portal",
                "The resolver display name was not retained.");
            Assert(
                request.ChildReason == "Needed for homework",
                "The bounded child reason was not retained.");
            Assert(
                store.CreateCount == 1,
                "The store did not create exactly one pending request.");
            Assert(
                resolver.LastObservationId == ObservationA,
                "The opaque observation id was not resolved exactly.");
            Assert(
                rateLimiter.CallCount == 1 &&
                rateLimiter.AllowedCount == 1 &&
                rateLimiter.LastDeviceId == DeviceA &&
                rateLimiter.LastChildAccountSid != null &&
                rateLimiter.LastChildAccountSid.Equals(ChildA),
                "The limiter did not atomically acquire the exact authenticated device and child SID.");
            Assert(
                audit.Events.Count == 1 &&
                audit.Events[0].Kind ==
                    WebsiteRequestAuditKind.Created,
                "Creation was not audited.");
            Assert(
                audit.AcknowledgedIntentIds.Count == 1 &&
                string.Equals(
                    audit.AcknowledgedIntentIds[0],
                    WebsiteRequestAuditIntent.ForAttempt(
                        request.RequestId),
                    StringComparison.Ordinal),
                "The delivered successful outbox intent was not acknowledged by its stable id.");
        }

        private static async Task
            QueuesUnknownSiteWithoutGrantAsync()
        {
            var evidenceA = CreateEvidence(PrimaryHostA);
            var evidenceB = CreateEvidence(PrimaryHostB);
            var observationA = CreateUnknownObservation(
                ObservationA,
                DeviceA,
                ChildA,
                evidenceA,
                Now.AddSeconds(-10),
                Now.AddMinutes(2));
            var observationB = CreateUnknownObservation(
                ObservationB,
                DeviceA,
                ChildA,
                evidenceB,
                Now.AddSeconds(-10),
                Now.AddMinutes(2));
            var store = new AtomicFakeStore();
            var audit = new FakeAudit();
            var coordinator = new WebsiteAccessRequestCoordinator(
                new AtomicRateLimiter(int.MaxValue),
                new FakeResolver(observationA, observationB),
                store,
                audit);
            var context =
                new AuthenticatedChildContext(DeviceA, ChildA);

            var created = await coordinator.CreateAsync(
                context,
                new CreateWebsiteRequestPayload(
                    ObservationA,
                    "Unknown school site"),
                Now,
                CancellationToken.None).ConfigureAwait(false);

            Assert(
                created.Status ==
                    WebsiteAccessRequestStatus.Created &&
                created.Request != null,
                "A trusted unknown-site observation was not queued.");
            Assert(
                created.Request!.CanonicalHost.Value ==
                    PrimaryHostA &&
                created.Request.RegistrableDomainEvidence
                    .RegistrableDomain.Value == "example.co.uk",
                "The unknown-site request lost trusted host or PSL evidence.");
            Assert(
                created.Request.ServiceBundleCandidate == null &&
                created.Request
                    .RequiresCatalogResolutionBeforeGrant,
                "An unknown site acquired an automatic service bundle.");
            Throws<ArgumentNullException>(
                () =>
                    new WebAccessGrant(
                        "grant:unknown-site",
                        created.Request.ServiceBundleCandidate!,
                        new ParentDecision(
                            Guard.Domain.Policy
                                .ParentDecisionKind.AlwaysAllow)),
                "An unknown pending request became a grant without a signed bundle.");

            var deduplicated =
                await coordinator.CreateAsync(
                    context,
                    new CreateWebsiteRequestPayload(
                        ObservationB,
                        null),
                    Now,
                    CancellationToken.None).ConfigureAwait(false);
            Assert(
                deduplicated.Status ==
                    WebsiteAccessRequestStatus
                        .PendingAlreadyExists &&
                deduplicated.Request != null &&
                deduplicated.Request.ServiceBundleCandidate == null,
                "Two unknown hosts in the same trusted registrable target were not safely deduplicated.");
            Assert(
                store.CreateCount == 1,
                "Unknown-site deduplication created multiple requests.");

            var addedBundle =
                await new WebsiteAccessRequestCoordinator(
                    new AtomicRateLimiter(int.MaxValue),
                    new FakeResolver(observationA),
                    new BundleAddingStore(),
                    new FakeAudit()).CreateAsync(
                        context,
                        new CreateWebsiteRequestPayload(
                            ObservationA,
                            null),
                        Now,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            Assert(
                addedBundle.Status ==
                    WebsiteAccessRequestStatus.FailedClosed,
                "A store-added bundle was accepted for an unknown site.");

            var knownObservation = CreateObservation(
                ObservationA,
                DeviceA,
                ChildA,
                evidenceA,
                CreateBundle(evidenceA, "service:school"),
                Now.AddSeconds(-10),
                Now.AddMinutes(2));
            var removedBundle =
                await new WebsiteAccessRequestCoordinator(
                    new AtomicRateLimiter(int.MaxValue),
                    new FakeResolver(knownObservation),
                    new BundleRemovingStore(),
                    new FakeAudit()).CreateAsync(
                        context,
                        new CreateWebsiteRequestPayload(
                            ObservationA,
                            null),
                        Now,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            Assert(
                removedBundle.Status ==
                    WebsiteAccessRequestStatus.FailedClosed,
                "A store-removed signed bundle was accepted.");
        }

        private static async Task DeduplicatesServiceRequestsAsync()
        {
            var evidenceA = CreateEvidence(PrimaryHostA);
            var evidenceB = CreateEvidence(PrimaryHostB);
            var bundle = CreateBundle(
                evidenceA,
                "service:school");
            var resolver = new FakeResolver(
                CreateObservation(
                    ObservationA,
                    DeviceA,
                    ChildA,
                    evidenceA,
                    bundle,
                    Now.AddSeconds(-10),
                    Now.AddMinutes(2)),
                CreateObservation(
                    ObservationB,
                    DeviceA,
                    ChildA,
                    evidenceB,
                    bundle,
                    Now.AddSeconds(-10),
                    Now.AddMinutes(2)));
            var store = new AtomicFakeStore();
            var audit = new FakeAudit();
            var coordinator = new WebsiteAccessRequestCoordinator(
                new AtomicRateLimiter(int.MaxValue),
                resolver,
                store,
                audit);
            var context =
                new AuthenticatedChildContext(DeviceA, ChildA);
            var payload =
                new CreateWebsiteRequestPayload(
                    ObservationA,
                    null);

            var tasks = Enumerable.Range(0, 16)
                .Select(
                    _ => Task.Run(
                        () => coordinator.CreateAsync(
                            context,
                            payload,
                            Now,
                            CancellationToken.None)))
                .ToArray();
            var results =
                await Task.WhenAll(tasks).ConfigureAwait(false);

            Assert(
                store.CreateCount == 1,
                "Concurrent requests created more than one record.");
            Assert(
                results.Count(
                    result =>
                        result.Status ==
                            WebsiteAccessRequestStatus.Created) == 1,
                "Exactly one caller must create the record.");
            Assert(
                results.Count(
                    result =>
                        result.Status ==
                            WebsiteAccessRequestStatus
                                .PendingAlreadyExists) == 15,
                "Remaining callers were not deduplicated.");
            Assert(
                results
                    .Select(result => result.Request!.RequestId)
                    .Distinct(StringComparer.Ordinal)
                    .Count() == 1,
                "Deduplicated callers received different records.");

            var relatedHostResult =
                await coordinator.CreateAsync(
                    context,
                    new CreateWebsiteRequestPayload(
                        ObservationB,
                        null),
                    Now,
                    CancellationToken.None).ConfigureAwait(false);
            Assert(
                relatedHostResult.Status ==
                    WebsiteAccessRequestStatus
                        .PendingAlreadyExists,
                "A second host in the same verified service was not deduplicated.");
            Assert(
                store.CreateCount == 1,
                "Service-level deduplication created a second record.");
        }

        private static async Task RejectsInvalidObservationsAsync()
        {
            await AssertObservationRejectedAsync(
                new FakeResolver(),
                new AuthenticatedChildContext(DeviceA, ChildA),
                new CreateWebsiteRequestPayload(
                    ObservationA,
                    null),
                "A missing observation was accepted.")
                .ConfigureAwait(false);

            await AssertObservationRejectedAsync(
                new FakeResolver(
                    CreateObservation(
                        ObservationB,
                        DeviceA,
                        ChildA,
                        CreateEvidence(PrimaryHostA),
                        null,
                        Now.AddSeconds(-10),
                        Now.AddMinutes(2)),
                    ObservationA),
                new AuthenticatedChildContext(DeviceA, ChildA),
                new CreateWebsiteRequestPayload(
                    ObservationA,
                    null),
                "A forged observation id was accepted.")
                .ConfigureAwait(false);

            await AssertObservationRejectedAsync(
                new FakeResolver(
                    CreateObservation(
                        ObservationA,
                        DeviceA,
                        ChildA,
                        CreateEvidence(PrimaryHostA),
                        null,
                        Now.AddMinutes(-2),
                        Now)),
                new AuthenticatedChildContext(DeviceA, ChildA),
                new CreateWebsiteRequestPayload(
                    ObservationA,
                    null),
                "An expired observation was accepted.")
                .ConfigureAwait(false);

            await AssertObservationRejectedAsync(
                new FakeResolver(
                    CreateObservation(
                        ObservationA,
                        DeviceB,
                        ChildA,
                        CreateEvidence(PrimaryHostA),
                        null,
                        Now.AddSeconds(-10),
                        Now.AddMinutes(2))),
                new AuthenticatedChildContext(DeviceA, ChildA),
                new CreateWebsiteRequestPayload(
                    ObservationA,
                    null),
                "An observation crossed its device binding.")
                .ConfigureAwait(false);

            await AssertObservationRejectedAsync(
                new FakeResolver(
                    CreateObservation(
                        ObservationA,
                        DeviceA,
                        ChildB,
                        CreateEvidence(PrimaryHostA),
                        null,
                        Now.AddSeconds(-10),
                        Now.AddMinutes(2))),
                new AuthenticatedChildContext(DeviceA, ChildA),
                new CreateWebsiteRequestPayload(
                    ObservationA,
                    null),
                "An observation crossed its child binding.")
                .ConfigureAwait(false);

            await AssertObservationRejectedAsync(
                new FakeResolver(
                    CreateObservation(
                        ObservationA,
                        DeviceA,
                        ChildA,
                        CreateEvidence(PrimaryHostA),
                        null,
                        Now.AddSeconds(1),
                        Now.AddMinutes(2))),
                new AuthenticatedChildContext(DeviceA, ChildA),
                new CreateWebsiteRequestPayload(
                    ObservationA,
                    null),
                "A future observation was accepted.")
                .ConfigureAwait(false);
        }

        private static Task RequiresBoundEvidenceAsync()
        {
            var evidenceA = CreateEvidence(PrimaryHostA);
            var evidenceB = CreateEvidence(PrimaryHostB);
            var bundleA = CreateBundle(
                evidenceA,
                "service:school");
            var unrelatedEvidence = CreateEvidence(OtherHost);
            var unrelatedBundle = CreateBundle(
                unrelatedEvidence,
                "service:other");

            Throws<ArgumentException>(
                () =>
                    new VerifiedBlockedWebsiteObservation(
                        ObservationA,
                        DeviceA,
                        ChildA,
                        CanonicalDnsHost.Parse(PrimaryHostA),
                        evidenceB,
                        bundleA,
                        "School portal",
                        Now,
                        Now.AddMinutes(1)),
                "Evidence for a different host was accepted.");
            Throws<ArgumentException>(
                () =>
                    new VerifiedBlockedWebsiteObservation(
                        ObservationA,
                        DeviceA,
                        ChildA,
                        CanonicalDnsHost.Parse(PrimaryHostA),
                        evidenceA,
                        unrelatedBundle,
                        "School portal",
                        Now,
                        Now.AddMinutes(1)),
                "A signed bundle not covering the host was accepted.");
            Throws<ArgumentOutOfRangeException>(
                () =>
                    new VerifiedBlockedWebsiteObservation(
                        ObservationA,
                        DeviceA,
                        ChildA,
                        CanonicalDnsHost.Parse(PrimaryHostA),
                        evidenceA,
                        bundleA,
                        "School portal",
                        Now,
                        Now +
                            VerifiedBlockedWebsiteObservation
                                .MaximumLifetime +
                            TimeSpan.FromTicks(1)),
                "An excessively long observation was accepted.");
            return Task.CompletedTask;
        }

        private static async Task UsesResolverIdentityOnlyAsync()
        {
            var evidence = CreateEvidence(PrimaryHostA);
            var bundle = CreateBundle(
                evidence,
                "service:school");
            var observation = CreateObservation(
                ObservationA,
                DeviceA,
                ChildA,
                evidence,
                bundle,
                Now.AddSeconds(-10),
                Now.AddMinutes(2));
            var coordinator = new WebsiteAccessRequestCoordinator(
                new AtomicRateLimiter(int.MaxValue),
                new FakeResolver(observation),
                new AtomicFakeStore(),
                new FakeAudit());
            var payload = new CreateWebsiteRequestPayload(
                ObservationA,
                "Allow https://evil.example/ bundle:service:evil");

            var result = await coordinator.CreateAsync(
                new AuthenticatedChildContext(DeviceA, ChildA),
                payload,
                Now,
                CancellationToken.None).ConfigureAwait(false);

            Assert(
                result.IsAccepted && result.Request != null,
                "The valid resolver-backed request was rejected.");
            Assert(
                result.Request!.CanonicalHost.Value ==
                    PrimaryHostA,
                "Child text influenced the canonical host.");
            Assert(
                result.Request.ServiceBundleCandidate!.Bundle
                    .BundleId == "service:school",
                "Child text influenced the service bundle.");
            var payloadProperties =
                typeof(CreateWebsiteRequestPayload)
                    .GetProperties()
                    .Select(property => property.Name)
                    .OrderBy(name => name, StringComparer.Ordinal)
                    .ToArray();
            Assert(
                payloadProperties.SequenceEqual(
                    new[] { "ObservationId", "ShortReason" },
                    StringComparer.Ordinal),
                "The child payload exposes a host, domain, URL, or bundle field.");
        }

        private static async Task
            EnforcesRateLimitBeforeDependenciesAsync()
        {
            const int maximumAllowed = 3;
            const int attempts = 24;
            var evidence = CreateEvidence(PrimaryHostA);
            var observation = CreateObservation(
                ObservationA,
                DeviceA,
                ChildA,
                evidence,
                CreateBundle(evidence, "service:school"),
                Now.AddSeconds(-10),
                Now.AddMinutes(2));
            var rateLimiter =
                new AtomicRateLimiter(maximumAllowed);
            var resolver = new FakeResolver(observation);
            var store = new AtomicFakeStore();
            var audit = new FakeAudit();
            var coordinator = new WebsiteAccessRequestCoordinator(
                rateLimiter,
                resolver,
                store,
                audit);
            var context =
                new AuthenticatedChildContext(DeviceA, ChildA);
            var payload =
                new CreateWebsiteRequestPayload(
                    ObservationA,
                    "https://payload-host-is-not-a-key.invalid");

            var results = await Task.WhenAll(
                Enumerable.Range(0, attempts)
                    .Select(
                        _ => Task.Run(
                            () => coordinator.CreateAsync(
                                context,
                                payload,
                                Now,
                                CancellationToken.None))))
                .ConfigureAwait(false);

            Assert(
                results.Count(result => result.IsAccepted) ==
                    maximumAllowed,
                "The limiter allowed the wrong number of concurrent requests.");
            Assert(
                results.Count(
                    result =>
                        result.Status ==
                            WebsiteAccessRequestStatus
                                .RateLimited) ==
                    attempts - maximumAllowed,
                "Exceeded requests were not rejected as rate-limited.");
            Assert(
                rateLimiter.CallCount == attempts &&
                rateLimiter.AllowedCount == maximumAllowed,
                "The atomic limiter counters are inconsistent.");
            Assert(
                resolver.CallCount == maximumAllowed,
                "A rate-limited request reached the observation resolver.");
            Assert(
                store.CreateCount == 1,
                "Allowed concurrent requests did not deduplicate.");
            Assert(
                audit.Events.Count == attempts &&
                audit.Events.Count(
                    item =>
                        item.Kind ==
                            WebsiteRequestAuditKind.RateLimited) ==
                    attempts - maximumAllowed,
                "Rate-limit rejections were not audited exactly once.");
        }

        private static async Task
            FailsClosedOnRateLimiterErrorsAsync()
        {
            var context =
                new AuthenticatedChildContext(DeviceA, ChildA);
            var payload =
                new CreateWebsiteRequestPayload(
                    ObservationA,
                    null);

            var throwingResolver = new FakeResolver();
            var throwingStore = new AtomicFakeStore();
            var throwingAudit = new FakeAudit();
            var throwingResult =
                await new WebsiteAccessRequestCoordinator(
                    new ThrowingRateLimiter(),
                    throwingResolver,
                    throwingStore,
                    throwingAudit).CreateAsync(
                        context,
                        payload,
                        Now,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            Assert(
                throwingResult.Status ==
                    WebsiteAccessRequestStatus.FailedClosed,
                "A limiter failure did not fail closed.");
            Assert(
                throwingResolver.CallCount == 0 &&
                throwingStore.CreateCount == 0,
                "A limiter failure reached resolver or store.");
            Assert(
                throwingAudit.Events.Single().Kind ==
                    WebsiteRequestAuditKind.DependencyFailure,
                "A limiter failure was not audited.");

            var mismatchedResolver = new FakeResolver();
            var mismatchedStore = new AtomicFakeStore();
            var mismatchedAudit = new FakeAudit();
            var mismatchedResult =
                await new WebsiteAccessRequestCoordinator(
                    new MismatchedRateLimiter(),
                    mismatchedResolver,
                    mismatchedStore,
                    mismatchedAudit).CreateAsync(
                        context,
                        payload,
                        Now,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            Assert(
                mismatchedResult.Status ==
                    WebsiteAccessRequestStatus.FailedClosed,
                "A limiter result for another identity was accepted.");
            Assert(
                mismatchedResolver.CallCount == 0 &&
                mismatchedStore.CreateCount == 0,
                "A mismatched limiter result reached resolver or store.");
            Assert(
                mismatchedAudit.Events.Single().Kind ==
                    WebsiteRequestAuditKind.DependencyFailure,
                "A limiter identity mismatch was not audited.");
        }

        private static async Task FailsClosedOnDependencyErrorsAsync()
        {
            var context =
                new AuthenticatedChildContext(DeviceA, ChildA);
            var payload =
                new CreateWebsiteRequestPayload(
                    ObservationA,
                    null);

            var resolverAudit = new FakeAudit();
            var resolverFailure =
                await new WebsiteAccessRequestCoordinator(
                    new AtomicRateLimiter(int.MaxValue),
                    new ThrowingResolver(),
                    new AtomicFakeStore(),
                    resolverAudit).CreateAsync(
                        context,
                        payload,
                        Now,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            Assert(
                resolverFailure.Status ==
                    WebsiteAccessRequestStatus.FailedClosed,
                "A resolver failure did not fail closed.");
            Assert(
                resolverAudit.Events.Single().Kind ==
                    WebsiteRequestAuditKind.DependencyFailure,
                "A resolver failure was not audited.");

            var evidence = CreateEvidence(PrimaryHostA);
            var observation = CreateObservation(
                ObservationA,
                DeviceA,
                ChildA,
                evidence,
                CreateBundle(evidence, "service:school"),
                Now.AddSeconds(-10),
                Now.AddMinutes(2));
            var bundleMismatch =
                await new WebsiteAccessRequestCoordinator(
                    new AtomicRateLimiter(int.MaxValue),
                    new FakeResolver(observation),
                    new BundleSubstitutingStore(),
                    new FakeAudit()).CreateAsync(
                        context,
                        payload,
                        Now,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            Assert(
                bundleMismatch.Status ==
                    WebsiteAccessRequestStatus.FailedClosed,
                "A substituted signed service bundle was accepted.");
            Assert(
                bundleMismatch.Request == null,
                "A bundle mismatch exposed an inconsistent request.");

            var metadataMismatch =
                await new WebsiteAccessRequestCoordinator(
                    new AtomicRateLimiter(int.MaxValue),
                    new FakeResolver(observation),
                    new MetadataSubstitutingStore(),
                    new FakeAudit()).CreateAsync(
                        context,
                        payload,
                        Now,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            Assert(
                metadataMismatch.Status ==
                    WebsiteAccessRequestStatus.FailedClosed,
                "Substituted trusted metadata was accepted.");

            var storeFailure =
                await new WebsiteAccessRequestCoordinator(
                    new AtomicRateLimiter(int.MaxValue),
                    new FakeResolver(observation),
                    new ThrowingStore(),
                    new FakeAudit()).CreateAsync(
                        context,
                        payload,
                        Now,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            Assert(
                storeFailure.Status ==
                    WebsiteAccessRequestStatus.FailedClosed,
                "A store failure did not fail closed.");

            var outboxMismatch =
                await new WebsiteAccessRequestCoordinator(
                    new AtomicRateLimiter(int.MaxValue),
                    new FakeResolver(observation),
                    new OutboxMismatchingStore(),
                    new FakeAudit()).CreateAsync(
                        context,
                        payload,
                        Now,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            Assert(
                outboxMismatch.Status ==
                    WebsiteAccessRequestStatus.FailedClosed &&
                outboxMismatch.Request == null,
                "A store result with a mismatched outbox intent was accepted.");

        }

        private static async Task CommitsAcrossCancellationBoundaryAsync()
        {
            var evidence = CreateEvidence(PrimaryHostA);
            var observation = CreateObservation(
                ObservationA,
                DeviceA,
                ChildA,
                evidence,
                CreateBundle(evidence, "service:school"),
                Now.AddSeconds(-10),
                Now.AddMinutes(2));
            using (var canceled = new CancellationTokenSource())
            {
                var store = new CancelAtCommitBoundaryStore(canceled);
                var result = await new WebsiteAccessRequestCoordinator(
                    new AtomicRateLimiter(int.MaxValue),
                    new FakeResolver(observation),
                    store,
                    new FakeAudit()).CreateAsync(
                        new AuthenticatedChildContext(DeviceA, ChildA),
                        new CreateWebsiteRequestPayload(ObservationA, null),
                        Now,
                        canceled.Token).ConfigureAwait(false);

                Assert(
                    canceled.IsCancellationRequested &&
                    store.ReceivedNonCancelableToken,
                    "Caller cancellation crossed the irreversible commit boundary.");
                Assert(
                    result.Status == WebsiteAccessRequestStatus.Created &&
                    result.Request != null && store.CreateCount == 1,
                    "Cancellation at commit boundary hid a durable request.");
            }
        }

        private static async Task
            ReportsCommittedRequestWhenImmediateAuditFailsAsync()
        {
            var evidence = CreateEvidence(PrimaryHostA);
            var observation = CreateObservation(
                ObservationA,
                DeviceA,
                ChildA,
                evidence,
                CreateBundle(evidence, "service:school"),
                Now.AddSeconds(-10),
                Now.AddMinutes(2));
            var store = new AtomicFakeStore();
            var audit = new FakeAudit { ThrowOnWrite = true };
            var result = await new WebsiteAccessRequestCoordinator(
                new AtomicRateLimiter(int.MaxValue),
                new FakeResolver(observation),
                store,
                audit).CreateAsync(
                    new AuthenticatedChildContext(DeviceA, ChildA),
                    new CreateWebsiteRequestPayload(ObservationA, null),
                    Now,
                    CancellationToken.None).ConfigureAwait(false);

            Assert(
                result.Status == WebsiteAccessRequestStatus.Created &&
                result.Request != null && store.CreateCount == 1,
                "Immediate audit delivery failure falsely hid a committed request.");
            Assert(
                audit.WriteAttemptCount == 1,
                "The committed outbox intent was not offered for immediate delivery.");

            var failureAudit =
                new FakeAudit { ThrowOnWrite = true };
            var failure = await new WebsiteAccessRequestCoordinator(
                new ThrowingRateLimiter(),
                new FakeResolver(),
                new AtomicFakeStore(),
                failureAudit).CreateAsync(
                    new AuthenticatedChildContext(DeviceA, ChildA),
                    new CreateWebsiteRequestPayload(
                        ObservationA,
                        null),
                    Now,
                    CancellationToken.None).ConfigureAwait(false);
            Assert(
                failure.Status ==
                    WebsiteAccessRequestStatus.FailedClosed,
                "A dependency failure with delayed audit delivery did not fail closed.");
            Assert(
                failureAudit.EnqueuedIntents.Count == 1 &&
                failureAudit.EnqueuedIntents[0].AuditEvent.Kind ==
                    WebsiteRequestAuditKind.DependencyFailure &&
                failureAudit.WriteAttemptCount == 1 &&
                failureAudit.AcknowledgedIntentIds.Count == 0,
                "A failed security audit delivery lost or acknowledged its durable intent.");
        }

        private static async Task PreservesCancellationAsync()
        {
            var context =
                new AuthenticatedChildContext(DeviceA, ChildA);
            var payload =
                new CreateWebsiteRequestPayload(
                    ObservationA,
                    null);
            var resolver = new FakeResolver();
            var preCanceledLimiter =
                new AtomicRateLimiter(int.MaxValue);
            using (var canceled = new CancellationTokenSource())
            {
                canceled.Cancel();
                await ThrowsCanceledAsync(
                    () =>
                        new WebsiteAccessRequestCoordinator(
                            preCanceledLimiter,
                            resolver,
                            new AtomicFakeStore(),
                            new FakeAudit()).CreateAsync(
                                context,
                                payload,
                                Now,
                                canceled.Token),
                    "A pre-canceled request did not propagate cancellation.")
                    .ConfigureAwait(false);
            }

            Assert(
                preCanceledLimiter.CallCount == 0 &&
                resolver.CallCount == 0,
                "A pre-canceled request reached a dependency.");

            using (var duringLimit =
                new CancellationTokenSource())
            {
                var limitAudit = new FakeAudit();
                var limitResolver = new FakeResolver();
                await ThrowsCanceledAsync(
                    () =>
                        new WebsiteAccessRequestCoordinator(
                            new CancelingRateLimiter(duringLimit),
                            limitResolver,
                            new AtomicFakeStore(),
                            limitAudit).CreateAsync(
                                context,
                                payload,
                                Now,
                                duringLimit.Token),
                    "Limiter cancellation was converted into a result.")
                    .ConfigureAwait(false);
                Assert(
                    limitResolver.CallCount == 0 &&
                    limitAudit.Events.Count == 0,
                    "Caller cancellation in the limiter reached later dependencies or audit.");
            }

            using (var duringResolve =
                new CancellationTokenSource())
            {
                var audit = new FakeAudit();
                await ThrowsCanceledAsync(
                    () =>
                        new WebsiteAccessRequestCoordinator(
                            new AtomicRateLimiter(int.MaxValue),
                            new CancelingResolver(duringResolve),
                            new AtomicFakeStore(),
                            audit).CreateAsync(
                                context,
                                payload,
                                Now,
                                duringResolve.Token),
                    "Resolver cancellation was converted into a result.")
                    .ConfigureAwait(false);
                Assert(
                    audit.Events.Count == 0,
                    "Caller cancellation was audited as a dependency failure.");
            }

            var unrequestedAudit = new FakeAudit();
            var unrequestedCancellation =
                await new WebsiteAccessRequestCoordinator(
                    new AtomicRateLimiter(int.MaxValue),
                    new UnrequestedCancellationResolver(),
                    new AtomicFakeStore(),
                    unrequestedAudit).CreateAsync(
                        context,
                        payload,
                        Now,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            Assert(
                unrequestedCancellation.Status ==
                    WebsiteAccessRequestStatus.FailedClosed,
                "A dependency cancellation without caller cancellation did not fail closed.");
            Assert(
                unrequestedAudit.Events.Single().Kind ==
                    WebsiteRequestAuditKind.DependencyFailure,
                "Unexpected dependency cancellation was not audited.");
        }

        private static Task KeepsModelsImmutableAsync()
        {
            var requestProperties =
                typeof(WebsiteAccessRequest)
                    .GetProperties(
                        BindingFlags.Instance |
                        BindingFlags.Public);
            Assert(
                requestProperties.All(
                    property => property.SetMethod == null),
                "A website request property is publicly mutable.");

            var observationProperties =
                typeof(VerifiedBlockedWebsiteObservation)
                    .GetProperties(
                        BindingFlags.Instance |
                        BindingFlags.Public);
            Assert(
                observationProperties.All(
                    property => property.SetMethod == null),
                "A verified observation property is publicly mutable.");

            var rateLimitProperties =
                typeof(WebsiteRequestRateLimitResult)
                    .GetProperties(
                        BindingFlags.Instance |
                        BindingFlags.Public);
            Assert(
                rateLimitProperties.All(
                    property => property.SetMethod == null),
                "A rate-limit result property is publicly mutable.");

            Throws<ArgumentException>(
                () =>
                    new WebsiteRequestAuditEvent(
                        WebsiteRequestAuditKind.Created,
                        Now,
                        DeviceA,
                        ChildA,
                        ObservationA,
                        Guid.NewGuid().ToString("D"),
                        AccessRequestKey.ForSite(
                            DeviceB,
                            "example.co.uk")),
                "An audit event accepted a key for another device.");
            Throws<ArgumentException>(
                () =>
                    new WebsiteRequestAuditEvent(
                        WebsiteRequestAuditKind
                            .RejectedObservation,
                        Now,
                        DeviceA,
                        ChildA,
                        ObservationA,
                        Guid.NewGuid().ToString("D"),
                        AccessRequestKey.ForSite(
                            DeviceA,
                            "example.co.uk")),
                "A rejection audit carried successful request identity.");
            return Task.CompletedTask;
        }

        private static async Task AssertObservationRejectedAsync(
            IBlockedWebsiteObservationResolver resolver,
            AuthenticatedChildContext context,
            CreateWebsiteRequestPayload payload,
            string message)
        {
            var store = new AtomicFakeStore();
            var audit = new FakeAudit();
            var result =
                await new WebsiteAccessRequestCoordinator(
                    new AtomicRateLimiter(int.MaxValue),
                    resolver,
                    store,
                    audit).CreateAsync(
                        context,
                        payload,
                        Now,
                        CancellationToken.None)
                    .ConfigureAwait(false);

            Assert(
                result.Status ==
                    WebsiteAccessRequestStatus.RejectedObservation,
                message);
            Assert(
                result.Request == null,
                "A rejected observation exposed a request.");
            Assert(
                store.CreateCount == 0,
                "A rejected observation reached the store.");
            Assert(
                audit.Events.Count == 1 &&
                audit.Events[0].Kind ==
                    WebsiteRequestAuditKind.RejectedObservation,
                "Observation rejection was not audited.");
        }

        private static VerifiedBlockedWebsiteObservation
            CreateObservation(
                string observationId,
                string deviceId,
                WindowsAccountSid child,
                RegistrableDomainEvidence evidence,
                VerifiedWebServiceBundle? bundle,
                DateTimeOffset observedAt,
                DateTimeOffset expiresAt)
        {
            return new VerifiedBlockedWebsiteObservation(
                observationId,
                deviceId,
                child,
                evidence.ObservedHost,
                evidence,
                bundle ??
                    CreateBundle(evidence, "service:school"),
                "School portal",
                observedAt,
                expiresAt);
        }

        private static VerifiedBlockedWebsiteObservation
            CreateUnknownObservation(
                string observationId,
                string deviceId,
                WindowsAccountSid child,
                RegistrableDomainEvidence evidence,
                DateTimeOffset observedAt,
                DateTimeOffset expiresAt)
        {
            return new VerifiedBlockedWebsiteObservation(
                observationId,
                deviceId,
                child,
                evidence.ObservedHost,
                evidence,
                null,
                "Unknown website",
                observedAt,
                expiresAt);
        }

        private static RegistrableDomainEvidence CreateEvidence(
            string observedHost)
        {
            if (observedHost.EndsWith(
                    ".example.co.uk",
                    StringComparison.Ordinal) ||
                string.Equals(
                    observedHost,
                    "example.co.uk",
                    StringComparison.Ordinal))
            {
                return RegistrableDomainEvidence.Resolve(
                    observedHost,
                    new FixedRegistrableDomainResolver(
                        "example.co.uk",
                        "co.uk",
                        "psl:2026-07-24"));
            }

            return RegistrableDomainEvidence.Resolve(
                observedHost,
                new FixedRegistrableDomainResolver(
                    "example.net",
                    "net",
                    "psl:2026-07-24"));
        }

        private static VerifiedWebServiceBundle CreateBundle(
            RegistrableDomainEvidence primaryEvidence,
            string bundleId)
        {
            var bundle = new WebServiceBundle(
                bundleId,
                new[]
                {
                    WebScope.RegistrableDomainSubtree(
                        primaryEvidence),
                    WebScope.ExactHost("assets.school-cdn.net")
                });
            var signature = new WebBundleSignature(
                "catalog:2026-07-24",
                24,
                1,
                Now.AddDays(-1),
                Now.AddDays(1),
                "2.0.0",
                bundle.CanonicalDigestSha256(),
                "signing-key:primary",
                new byte[] { 0x01, 0x02, 0x03 });
            return VerifiedWebServiceBundle.Verify(
                bundle,
                signature,
                new AcceptingBundleSignatureVerifier(),
                new WebBundleAcceptanceFloor(
                    signature.CatalogId,
                    bundle.BundleId,
                    24,
                    1,
                    bundle.CanonicalDigestSha256()),
                new Version("2.0.0"),
                 Now);
        }

        private static WebsiteRequestAuditIntent
            CreateSuccessfulAuditIntent(
                WebsiteAccessRequest request,
                string requestAttemptId,
                bool created,
                string observationId,
                DateTimeOffset occurredAtUtc)
        {
            return new WebsiteRequestAuditIntent(
                WebsiteRequestAuditIntent.ForAttempt(
                    requestAttemptId),
                new WebsiteRequestAuditEvent(
                    created
                        ? WebsiteRequestAuditKind.Created
                        : WebsiteRequestAuditKind.Deduplicated,
                    occurredAtUtc,
                    request.DeviceId,
                    request.ChildAccountSid,
                    observationId,
                    request.RequestId,
                    request.RequestKey));
        }

        private static void Throws<TException>(
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

        private static async Task ThrowsCanceledAsync(
            Func<Task> action,
            string message)
        {
            try
            {
                await action().ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            throw new InvalidOperationException(message);
        }

        private static void Assert(
            bool condition,
            string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private sealed class FixedRegistrableDomainResolver :
            ITrustedRegistrableDomainResolver
        {
            private readonly string _registrableDomain;
            private readonly string _publicSuffix;
            private readonly string _revision;

            public FixedRegistrableDomainResolver(
                string registrableDomain,
                string publicSuffix,
                string revision)
            {
                _registrableDomain = registrableDomain;
                _publicSuffix = publicSuffix;
                _revision = revision;
            }

            public bool TryResolve(
                CanonicalDnsHost observedHost,
                out string registrableDomain,
                out string publicSuffix,
                out string resolverRevision)
            {
                registrableDomain = _registrableDomain;
                publicSuffix = _publicSuffix;
                resolverRevision = _revision;
                return true;
            }
        }

        private sealed class AcceptingBundleSignatureVerifier :
            IWebBundleSignatureVerifier
        {
            public bool Verify(
                string signingKeyId,
                byte[] canonicalBundleBytes,
                byte[] signature)
            {
                return true;
            }
        }

        private sealed class AtomicRateLimiter :
            IWebsiteRequestRateLimiter
        {
            private readonly object _sync = new object();
            private readonly int _maximumPerIdentity;
            private readonly Dictionary<RateLimitKey, int> _counts =
                new Dictionary<RateLimitKey, int>();

            public AtomicRateLimiter(int maximumPerIdentity)
            {
                if (maximumPerIdentity <= 0)
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(maximumPerIdentity));
                }

                _maximumPerIdentity = maximumPerIdentity;
            }

            public int CallCount { get; private set; }

            public int AllowedCount { get; private set; }

            public string? LastDeviceId { get; private set; }

            public WindowsAccountSid? LastChildAccountSid
            {
                get;
                private set;
            }

            public Task<WebsiteRequestRateLimitResult>
                TryAcquireAsync(
                    string authenticatedDeviceId,
                    WindowsAccountSid
                        authenticatedChildAccountSid,
                    DateTimeOffset nowUtc,
                    CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                lock (_sync)
                {
                    CallCount++;
                    LastDeviceId = authenticatedDeviceId;
                    LastChildAccountSid =
                        authenticatedChildAccountSid;
                    var key = new RateLimitKey(
                        authenticatedDeviceId,
                        authenticatedChildAccountSid);
                    int count;
                    _counts.TryGetValue(key, out count);
                    var outcome =
                        count < _maximumPerIdentity
                            ? WebsiteRequestRateLimitOutcome.Allowed
                            : WebsiteRequestRateLimitOutcome.Exceeded;
                    if (outcome ==
                        WebsiteRequestRateLimitOutcome.Allowed)
                    {
                        _counts[key] = count + 1;
                        AllowedCount++;
                    }

                    return Task.FromResult(
                        new WebsiteRequestRateLimitResult(
                            outcome,
                            authenticatedDeviceId,
                            authenticatedChildAccountSid));
                }
            }
        }

        private sealed class RateLimitKey :
            IEquatable<RateLimitKey>
        {
            public RateLimitKey(
                string deviceId,
                WindowsAccountSid childAccountSid)
            {
                DeviceId = deviceId;
                ChildAccountSid = childAccountSid;
            }

            public string DeviceId { get; }

            public WindowsAccountSid ChildAccountSid { get; }

            public bool Equals(RateLimitKey? other)
            {
                return other != null &&
                       string.Equals(
                           DeviceId,
                           other.DeviceId,
                           StringComparison.Ordinal) &&
                       ChildAccountSid.Equals(
                           other.ChildAccountSid);
            }

            public override bool Equals(object? obj)
            {
                return Equals(obj as RateLimitKey);
            }

            public override int GetHashCode()
            {
                return (
                    StringComparer.Ordinal.GetHashCode(DeviceId) *
                    397) ^
                    ChildAccountSid.GetHashCode();
            }
        }

        private sealed class ThrowingRateLimiter :
            IWebsiteRequestRateLimiter
        {
            public Task<WebsiteRequestRateLimitResult>
                TryAcquireAsync(
                    string authenticatedDeviceId,
                    WindowsAccountSid
                        authenticatedChildAccountSid,
                    DateTimeOffset nowUtc,
                    CancellationToken cancellationToken)
            {
                throw new InvalidOperationException(
                    "Simulated rate-limit failure.");
            }
        }

        private sealed class MismatchedRateLimiter :
            IWebsiteRequestRateLimiter
        {
            public Task<WebsiteRequestRateLimitResult>
                TryAcquireAsync(
                    string authenticatedDeviceId,
                    WindowsAccountSid
                        authenticatedChildAccountSid,
                    DateTimeOffset nowUtc,
                    CancellationToken cancellationToken)
            {
                return Task.FromResult(
                    new WebsiteRequestRateLimitResult(
                        WebsiteRequestRateLimitOutcome.Allowed,
                        DeviceB,
                        ChildB));
            }
        }

        private sealed class CancelingRateLimiter :
            IWebsiteRequestRateLimiter
        {
            private readonly CancellationTokenSource _source;

            public CancelingRateLimiter(
                CancellationTokenSource source)
            {
                _source = source;
            }

            public Task<WebsiteRequestRateLimitResult>
                TryAcquireAsync(
                    string authenticatedDeviceId,
                    WindowsAccountSid
                        authenticatedChildAccountSid,
                    DateTimeOffset nowUtc,
                    CancellationToken cancellationToken)
            {
                _source.Cancel();
                throw new OperationCanceledException(
                    cancellationToken);
            }
        }

        private sealed class FakeResolver :
            IBlockedWebsiteObservationResolver
        {
            private readonly Dictionary<
                string,
                VerifiedBlockedWebsiteObservation> _observations =
                    new Dictionary<
                        string,
                        VerifiedBlockedWebsiteObservation>(
                            StringComparer.Ordinal);

            public FakeResolver()
            {
            }

            public FakeResolver(
                VerifiedBlockedWebsiteObservation observation,
                string? lookupId = null)
            {
                _observations.Add(
                    lookupId ?? observation.ObservationId,
                    observation);
            }

            public FakeResolver(
                VerifiedBlockedWebsiteObservation first,
                VerifiedBlockedWebsiteObservation second)
            {
                _observations.Add(first.ObservationId, first);
                _observations.Add(second.ObservationId, second);
            }

            public string? LastObservationId { get; private set; }

            public int CallCount { get; private set; }

            public Task<VerifiedBlockedWebsiteObservation?>
                ResolveAsync(
                    string observationId,
                    CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                CallCount++;
                LastObservationId = observationId;
                VerifiedBlockedWebsiteObservation? observation;
                _observations.TryGetValue(
                    observationId,
                    out observation);
                return Task.FromResult(observation);
            }
        }

        private sealed class ThrowingResolver :
            IBlockedWebsiteObservationResolver
        {
            public Task<VerifiedBlockedWebsiteObservation?>
                ResolveAsync(
                    string observationId,
                    CancellationToken cancellationToken)
            {
                throw new InvalidOperationException(
                    "Simulated resolver failure.");
            }
        }

        private sealed class CancelingResolver :
            IBlockedWebsiteObservationResolver
        {
            private readonly CancellationTokenSource _source;

            public CancelingResolver(
                CancellationTokenSource source)
            {
                _source = source;
            }

            public Task<VerifiedBlockedWebsiteObservation?>
                ResolveAsync(
                    string observationId,
                    CancellationToken cancellationToken)
            {
                _source.Cancel();
                throw new OperationCanceledException(
                    cancellationToken);
            }
        }

        private sealed class UnrequestedCancellationResolver :
            IBlockedWebsiteObservationResolver
        {
            public Task<VerifiedBlockedWebsiteObservation?>
                ResolveAsync(
                    string observationId,
                    CancellationToken cancellationToken)
            {
                throw new OperationCanceledException(
                    "Simulated dependency cancellation.");
            }
        }

        private sealed class AtomicFakeStore :
            IPendingWebsiteAccessRequestStore
        {
            private readonly object _sync = new object();
            private readonly Dictionary<
                AccessRequestKey,
                WebsiteAccessRequest> _requests =
                    new Dictionary<
                        AccessRequestKey,
                        WebsiteAccessRequest>();

            public int CreateCount { get; private set; }

            public Task<PendingWebsiteRequestStoreResult>
                CommitPendingWithAuditIntentAsync(
                    WebsiteAccessRequest candidate,
                    DateTimeOffset auditOccurredAtUtc,
                    CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                lock (_sync)
                {
                    WebsiteAccessRequest? existing;
                    if (_requests.TryGetValue(
                            candidate.RequestKey,
                            out existing))
                    {
                        return Task.FromResult(
                            new PendingWebsiteRequestStoreResult(
                                existing!,
                                false,
                                CreateSuccessfulAuditIntent(
                                    existing!,
                                    candidate.RequestId,
                                    false,
                                    candidate.ObservationId,
                                    auditOccurredAtUtc)));
                    }

                    _requests.Add(
                        candidate.RequestKey,
                        candidate);
                    CreateCount++;
                    return Task.FromResult(
                        new PendingWebsiteRequestStoreResult(
                            candidate,
                            true,
                            CreateSuccessfulAuditIntent(
                                candidate,
                                candidate.RequestId,
                                true,
                                candidate.ObservationId,
                                auditOccurredAtUtc)));
                }
            }
        }

        private sealed class CancelAtCommitBoundaryStore :
            IPendingWebsiteAccessRequestStore
        {
            private readonly CancellationTokenSource _source;

            public CancelAtCommitBoundaryStore(
                CancellationTokenSource source)
            {
                _source = source;
            }

            public int CreateCount { get; private set; }

            public bool ReceivedNonCancelableToken { get; private set; }

            public Task<PendingWebsiteRequestStoreResult>
                CommitPendingWithAuditIntentAsync(
                    WebsiteAccessRequest candidate,
                    DateTimeOffset auditOccurredAtUtc,
                    CancellationToken cancellationToken)
            {
                ReceivedNonCancelableToken = !cancellationToken.CanBeCanceled;
                _source.Cancel();
                CreateCount++;
                return Task.FromResult(
                    new PendingWebsiteRequestStoreResult(
                        candidate,
                        true,
                        CreateSuccessfulAuditIntent(
                            candidate,
                            candidate.RequestId,
                            true,
                            candidate.ObservationId,
                            auditOccurredAtUtc)));
            }
        }

        private sealed class OutboxMismatchingStore :
            IPendingWebsiteAccessRequestStore
        {
            public Task<PendingWebsiteRequestStoreResult>
                CommitPendingWithAuditIntentAsync(
                    WebsiteAccessRequest candidate,
                    DateTimeOffset auditOccurredAtUtc,
                    CancellationToken cancellationToken)
            {
                var mismatchedAudit = new WebsiteRequestAuditIntent(
                    Guid.NewGuid().ToString("D"),
                    new WebsiteRequestAuditEvent(
                        WebsiteRequestAuditKind.Created,
                        auditOccurredAtUtc,
                        candidate.DeviceId,
                        candidate.ChildAccountSid,
                        candidate.ObservationId,
                        Guid.NewGuid().ToString("D"),
                        candidate.RequestKey));
                return Task.FromResult(
                    new PendingWebsiteRequestStoreResult(
                        candidate,
                        true,
                        mismatchedAudit));
            }
        }

        private sealed class BundleSubstitutingStore :
            IPendingWebsiteAccessRequestStore
        {
            public Task<PendingWebsiteRequestStoreResult>
                CommitPendingWithAuditIntentAsync(
                    WebsiteAccessRequest candidate,
                    DateTimeOffset auditOccurredAtUtc,
                    CancellationToken cancellationToken)
            {
                var substituted = new WebsiteAccessRequest(
                    candidate.RequestId,
                    candidate.DeviceId,
                    candidate.ChildAccountSid,
                    candidate.ObservationId,
                    candidate.CanonicalHost,
                    candidate.RegistrableDomainEvidence,
                    CreateBundle(
                        candidate.RegistrableDomainEvidence,
                        "service:school-alternative"),
                    candidate.DisplayName,
                    candidate.ChildReason,
                    candidate.CreatedAtUtc);
                return Task.FromResult(
                    new PendingWebsiteRequestStoreResult(
                        substituted,
                        true,
                        CreateSuccessfulAuditIntent(
                            substituted,
                            candidate.RequestId,
                            true,
                            candidate.ObservationId,
                            auditOccurredAtUtc)));
            }
        }

        private sealed class BundleAddingStore :
            IPendingWebsiteAccessRequestStore
        {
            public Task<PendingWebsiteRequestStoreResult>
                CommitPendingWithAuditIntentAsync(
                    WebsiteAccessRequest candidate,
                    DateTimeOffset auditOccurredAtUtc,
                    CancellationToken cancellationToken)
            {
                var substituted = new WebsiteAccessRequest(
                    candidate.RequestId,
                    candidate.DeviceId,
                    candidate.ChildAccountSid,
                    candidate.ObservationId,
                    candidate.CanonicalHost,
                    candidate.RegistrableDomainEvidence,
                    CreateBundle(
                        candidate.RegistrableDomainEvidence,
                        "service:store-added"),
                    candidate.DisplayName,
                    candidate.ChildReason,
                    candidate.CreatedAtUtc);
                return Task.FromResult(
                    new PendingWebsiteRequestStoreResult(
                        substituted,
                        true,
                        CreateSuccessfulAuditIntent(
                            substituted,
                            candidate.RequestId,
                            true,
                            candidate.ObservationId,
                            auditOccurredAtUtc)));
            }
        }

        private sealed class BundleRemovingStore :
            IPendingWebsiteAccessRequestStore
        {
            public Task<PendingWebsiteRequestStoreResult>
                CommitPendingWithAuditIntentAsync(
                    WebsiteAccessRequest candidate,
                    DateTimeOffset auditOccurredAtUtc,
                    CancellationToken cancellationToken)
            {
                var substituted = new WebsiteAccessRequest(
                    candidate.RequestId,
                    candidate.DeviceId,
                    candidate.ChildAccountSid,
                    candidate.ObservationId,
                    candidate.CanonicalHost,
                    candidate.RegistrableDomainEvidence,
                    null,
                    candidate.DisplayName,
                    candidate.ChildReason,
                    candidate.CreatedAtUtc);
                return Task.FromResult(
                    new PendingWebsiteRequestStoreResult(
                        substituted,
                        true,
                        CreateSuccessfulAuditIntent(
                            substituted,
                            candidate.RequestId,
                            true,
                            candidate.ObservationId,
                            auditOccurredAtUtc)));
            }
        }

        private sealed class MetadataSubstitutingStore :
            IPendingWebsiteAccessRequestStore
        {
            public Task<PendingWebsiteRequestStoreResult>
                CommitPendingWithAuditIntentAsync(
                    WebsiteAccessRequest candidate,
                    DateTimeOffset auditOccurredAtUtc,
                    CancellationToken cancellationToken)
            {
                var substituted = new WebsiteAccessRequest(
                    candidate.RequestId,
                    candidate.DeviceId,
                    candidate.ChildAccountSid,
                    candidate.ObservationId,
                    candidate.CanonicalHost,
                    candidate.RegistrableDomainEvidence,
                    candidate.ServiceBundleCandidate,
                    "Substituted display name",
                    candidate.ChildReason,
                    candidate.CreatedAtUtc);
                return Task.FromResult(
                    new PendingWebsiteRequestStoreResult(
                        substituted,
                        true,
                        CreateSuccessfulAuditIntent(
                            substituted,
                            candidate.RequestId,
                            true,
                            candidate.ObservationId,
                            auditOccurredAtUtc)));
            }
        }

        private sealed class ThrowingStore :
            IPendingWebsiteAccessRequestStore
        {
            public Task<PendingWebsiteRequestStoreResult>
                CommitPendingWithAuditIntentAsync(
                    WebsiteAccessRequest candidate,
                    DateTimeOffset auditOccurredAtUtc,
                    CancellationToken cancellationToken)
            {
                throw new InvalidOperationException(
                    "Simulated store failure.");
            }
        }

        private sealed class FakeAudit : IWebsiteRequestAudit
        {
            private readonly object _sync = new object();
            private readonly List<WebsiteRequestAuditEvent> _events =
                new List<WebsiteRequestAuditEvent>();
            private readonly List<WebsiteRequestAuditIntent> _enqueued =
                new List<WebsiteRequestAuditIntent>();
            private readonly List<string> _acknowledgedIntentIds =
                new List<string>();
            private readonly HashSet<string> _deliveredIntentIds =
                new HashSet<string>(StringComparer.Ordinal);

            public bool ThrowOnWrite { get; set; }

            public int WriteAttemptCount { get; private set; }

            public IReadOnlyList<WebsiteRequestAuditEvent> Events
            {
                get
                {
                    lock (_sync)
                    {
                        return _events.ToArray();
                    }
                }
            }

            public IReadOnlyList<WebsiteRequestAuditIntent> EnqueuedIntents
            {
                get
                {
                    lock (_sync)
                    {
                        return _enqueued.ToArray();
                    }
                }
            }

            public IReadOnlyList<string> AcknowledgedIntentIds
            {
                get
                {
                    lock (_sync)
                    {
                        return _acknowledgedIntentIds.ToArray();
                    }
                }
            }

            public Task EnqueueAsync(
                WebsiteRequestAuditIntent intent,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                lock (_sync)
                {
                    if (!_enqueued.Any(
                            item =>
                                string.Equals(
                                    item.IntentId,
                                    intent.IntentId,
                                    StringComparison.Ordinal)))
                    {
                        _enqueued.Add(intent);
                    }
                }

                return Task.CompletedTask;
            }

            public Task WriteAsync(
                WebsiteRequestAuditIntent intent,
                CancellationToken cancellationToken)
            {
                WriteAttemptCount++;
                cancellationToken.ThrowIfCancellationRequested();
                if (ThrowOnWrite)
                {
                    throw new InvalidOperationException(
                        "Simulated audit failure.");
                }

                lock (_sync)
                {
                    if (_deliveredIntentIds.Add(intent.IntentId))
                    {
                        _events.Add(intent.AuditEvent);
                    }
                }

                return Task.CompletedTask;
            }

            public Task AcknowledgeAsync(
                string intentId,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                lock (_sync)
                {
                    if (!_acknowledgedIntentIds.Contains(intentId))
                    {
                        _acknowledgedIntentIds.Add(intentId);
                    }
                }

                return Task.CompletedTask;
            }
        }
    }
}
