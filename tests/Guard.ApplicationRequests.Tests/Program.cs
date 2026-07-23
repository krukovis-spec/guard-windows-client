using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Contracts;
using Guard.Domain;
using Guard.Domain.Policy;

namespace Guard.ApplicationRequests.Tests
{
    internal static class Program
    {
        private const string DeviceA = "device-0000000001";
        private const string DeviceB = "device-0000000002";
        private const string ObservationA = "observation-00000001";
        private const string ObservationB = "observation-00000002";
        private const string ObservationC = "observation-00000003";
        private const string HashA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        private const string HashB = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        private static readonly WindowsAccountSid ChildA = new WindowsAccountSid("S-1-5-21-1000");
        private static readonly WindowsAccountSid ChildB = new WindowsAccountSid("S-1-5-21-2000");
        private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 7, 23, 18, 0, 0, TimeSpan.Zero);

        private static async Task<int> Main()
        {
            var tests = new List<(string Name, Func<Task> Run)>
            {
                ("creates an exact request from a verified service observation", CreatesExactRequestAsync),
                ("atomically deduplicates repeated and concurrent child clicks", DeduplicatesConcurrentlyAsync),
                ("rejects missing forged expired and cross-bound observations", RejectsInvalidObservationsAsync),
                ("accepts only an optional bounded child reason", ValidatesReasonBoundsAsync),
                ("takes application identity only from the resolver", UsesResolverIdentityOnlyAsync),
                ("fails closed when a dependency or audit response is inconsistent", FailsClosedOnDependencyErrorsAsync)
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
                    Console.WriteLine("FAIL " + test.Name + ": " + exception.Message);
                }
            }

            Console.WriteLine(
                failures == 0
                    ? "All application request checks passed."
                    : failures + " application request check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static async Task CreatesExactRequestAsync()
        {
            var identity = HashIdentity(HashA);
            var observation = CreateObservation(
                ObservationA,
                DeviceA,
                ChildA,
                identity,
                Now.AddMinutes(-1),
                Now.AddMinutes(4),
                @"C:\Program Files\Acme\Reader.exe",
                "Verified publisher: Acme Ltd");
            var resolver = new FakeResolver(observation);
            var store = new AtomicFakeStore();
            var audit = new FakeAudit();
            var coordinator = new ApplicationAccessRequestCoordinator(resolver, store, audit);

            var result = await coordinator.CreateAsync(
                new AuthenticatedChildContext(DeviceA, ChildA),
                new CreateApplicationRequestPayload(ObservationA, "Needed for homework"),
                Now,
                CancellationToken.None).ConfigureAwait(false);

            Assert(result.Status == ApplicationAccessRequestStatus.Created, "A valid request was not created.");
            Assert(result.Request != null, "A successful request returned no record.");
            var request = result.Request!;
            Assert(request.Identity.Equals(identity), "The verified application identity changed.");
            Assert(request.RequestKey.Equals(AccessRequestKey.ForApplication(DeviceA, identity)), "The exact dedupe key was not persisted.");
            Assert(request.ChildAccountSid.Equals(ChildA), "The authenticated child binding changed.");
            Assert(request.ObservationId == ObservationA, "The source observation was not retained.");
            Assert(request.DisplayName == "Acme Reader", "The resolver display name was not retained.");
            Assert(request.ChildReason == "Needed for homework", "The bounded child reason was not retained.");
            Assert(request.ObservedExecutablePath == @"C:\Program Files\Acme\Reader.exe", "Observed path metadata was not retained.");
            Assert(request.VerifiedSignatureSummary == "Verified publisher: Acme Ltd", "Signature metadata was not retained.");
            Assert(store.CreateCount == 1, "The store did not create exactly one pending request.");
            Assert(resolver.LastObservationId == ObservationA, "The opaque observation id was not resolved exactly.");
            Assert(audit.Events.Count == 1 && audit.Events[0].Kind == ApplicationRequestAuditKind.Created, "Creation was not audited.");
        }

        private static async Task DeduplicatesConcurrentlyAsync()
        {
            var observation = CreateObservation(
                ObservationA,
                DeviceA,
                ChildA,
                HashIdentity(HashA),
                Now.AddMinutes(-1),
                Now.AddMinutes(4));
            var store = new AtomicFakeStore();
            var audit = new FakeAudit();
            var coordinator = new ApplicationAccessRequestCoordinator(
                new FakeResolver(observation),
                store,
                audit);
            var context = new AuthenticatedChildContext(DeviceA, ChildA);
            var payload = new CreateApplicationRequestPayload(ObservationA, null);

            var tasks = Enumerable.Range(0, 16)
                .Select(_ => Task.Run(() => coordinator.CreateAsync(context, payload, Now, CancellationToken.None)))
                .ToArray();
            var results = await Task.WhenAll(tasks).ConfigureAwait(false);

            Assert(store.CreateCount == 1, "Concurrent requests created more than one pending record.");
            Assert(results.Count(result => result.Status == ApplicationAccessRequestStatus.Created) == 1, "Exactly one caller must create the record.");
            Assert(results.Count(result => result.Status == ApplicationAccessRequestStatus.PendingAlreadyExists) == 15, "Remaining callers were not deduplicated.");
            Assert(results.All(result => result.Request != null), "A deduplicated success omitted the existing record.");
            Assert(results.Select(result => result.Request!.RequestId).Distinct(StringComparer.Ordinal).Count() == 1, "Deduplicated callers received different records.");
            Assert(audit.Events.Count(eventItem => eventItem.Kind == ApplicationRequestAuditKind.Created) == 1, "Creation audit count was incorrect.");
            Assert(audit.Events.Count(eventItem => eventItem.Kind == ApplicationRequestAuditKind.Deduplicated) == 15, "Deduplication audit count was incorrect.");
        }

        private static async Task RejectsInvalidObservationsAsync()
        {
            await AssertObservationRejectedAsync(
                new FakeResolver(),
                new AuthenticatedChildContext(DeviceA, ChildA),
                new CreateApplicationRequestPayload(ObservationA, null),
                "A missing observation was accepted.").ConfigureAwait(false);

            await AssertObservationRejectedAsync(
                new FakeResolver(CreateObservation(
                    ObservationB,
                    DeviceA,
                    ChildA,
                    HashIdentity(HashA),
                    Now.AddMinutes(-1),
                    Now.AddMinutes(4)),
                    ObservationA),
                new AuthenticatedChildContext(DeviceA, ChildA),
                new CreateApplicationRequestPayload(ObservationA, null),
                "A resolver response with a forged observation id was accepted.").ConfigureAwait(false);

            await AssertObservationRejectedAsync(
                new FakeResolver(CreateObservation(
                    ObservationA,
                    DeviceA,
                    ChildA,
                    HashIdentity(HashA),
                    Now.AddMinutes(-5),
                    Now)),
                new AuthenticatedChildContext(DeviceA, ChildA),
                new CreateApplicationRequestPayload(ObservationA, null),
                "An expired observation was accepted.").ConfigureAwait(false);

            await AssertObservationRejectedAsync(
                new FakeResolver(CreateObservation(
                    ObservationA,
                    DeviceB,
                    ChildA,
                    HashIdentity(HashA),
                    Now.AddMinutes(-1),
                    Now.AddMinutes(4))),
                new AuthenticatedChildContext(DeviceA, ChildA),
                new CreateApplicationRequestPayload(ObservationA, null),
                "An observation crossed its device binding.").ConfigureAwait(false);

            await AssertObservationRejectedAsync(
                new FakeResolver(CreateObservation(
                    ObservationA,
                    DeviceA,
                    ChildB,
                    HashIdentity(HashA),
                    Now.AddMinutes(-1),
                    Now.AddMinutes(4))),
                new AuthenticatedChildContext(DeviceA, ChildA),
                new CreateApplicationRequestPayload(ObservationA, null),
                "An observation crossed its child binding.").ConfigureAwait(false);

            await AssertObservationRejectedAsync(
                new FakeResolver(CreateObservation(
                    ObservationA,
                    DeviceA,
                    ChildA,
                    HashIdentity(HashA),
                    Now.AddMinutes(1),
                    Now.AddMinutes(6))),
                new AuthenticatedChildContext(DeviceA, ChildA),
                new CreateApplicationRequestPayload(ObservationA, null),
                "A future observation was accepted before it became active.").ConfigureAwait(false);
        }

        private static Task ValidatesReasonBoundsAsync()
        {
            var absent = new CreateApplicationRequestPayload(ObservationA, null);
            var maximum = new CreateApplicationRequestPayload(
                ObservationA,
                new string('x', ApplicationRequestPayloadLimits.MaximumShortReasonCharacters));

            Assert(absent.ShortReason == null, "An absent reason was not accepted.");
            Assert(maximum.ShortReason!.Length == ApplicationRequestPayloadLimits.MaximumShortReasonCharacters, "The maximum bounded reason was rejected.");
            Throws<ArgumentException>(
                () => new CreateApplicationRequestPayload(ObservationA, "   "),
                "A whitespace-only reason was accepted.");
            Throws<ArgumentException>(
                () => new CreateApplicationRequestPayload(
                    ObservationA,
                    new string('x', ApplicationRequestPayloadLimits.MaximumShortReasonCharacters + 1)),
                "An oversized reason was accepted.");
            Throws<ArgumentException>(
                () => new CreateApplicationRequestPayload(ObservationA, "line1\nline2"),
                "A control character was accepted in a child reason.");
            Throws<ArgumentException>(
                () => new CreateApplicationRequestPayload("short", null),
                "A malformed observation id was accepted.");
            return Task.CompletedTask;
        }

        private static async Task UsesResolverIdentityOnlyAsync()
        {
            Throws<ArgumentException>(
                () => CreateObservation(
                    ObservationB,
                    DeviceA,
                    ChildA,
                    new ApplicationIdentity("Acme Ltd", "Reader", SecureInstallRoot.ProgramFiles64, null),
                    Now.AddMinutes(-1),
                    Now.AddMinutes(4)),
                "A signed provenance tuple became a child-request enforcement identity.");

            var resolverIdentity = HashIdentity(HashA);
            var observation = CreateObservation(
                ObservationA,
                DeviceA,
                ChildA,
                resolverIdentity,
                Now.AddMinutes(-1),
                Now.AddMinutes(4));
            var store = new AtomicFakeStore();
            var coordinator = new ApplicationAccessRequestCoordinator(
                new FakeResolver(observation),
                store,
                new FakeAudit());
            var payload = new CreateApplicationRequestPayload(
                ObservationA,
                "Ignore this untrusted sha256:" + HashB);

            var result = await coordinator.CreateAsync(
                new AuthenticatedChildContext(DeviceA, ChildA),
                payload,
                Now,
                CancellationToken.None).ConfigureAwait(false);

            Assert(result.IsAccepted && result.Request != null, "The valid resolver-backed request was rejected.");
            Assert(result.Request!.Identity.Equals(resolverIdentity), "Untrusted child text influenced the application identity.");
            Assert(result.Request.RequestKey.Equals(AccessRequestKey.ForApplication(DeviceA, resolverIdentity)), "The resolver identity was not used for the request key.");
            var payloadProperties = typeof(CreateApplicationRequestPayload)
                .GetProperties()
                .Select(property => property.Name)
                .OrderBy(name => name, StringComparer.Ordinal)
                .ToArray();
            Assert(
                payloadProperties.SequenceEqual(new[] { "ObservationId", "ShortReason" }, StringComparer.Ordinal),
                "The child payload exposes an application identity, path, publisher, or package field.");
        }

        private static async Task FailsClosedOnDependencyErrorsAsync()
        {
            var context = new AuthenticatedChildContext(DeviceA, ChildA);
            var payload = new CreateApplicationRequestPayload(ObservationA, null);

            var resolverAudit = new FakeAudit();
            var resolverFailure = await new ApplicationAccessRequestCoordinator(
                new ThrowingResolver(),
                new AtomicFakeStore(),
                resolverAudit).CreateAsync(context, payload, Now, CancellationToken.None).ConfigureAwait(false);
            Assert(resolverFailure.Status == ApplicationAccessRequestStatus.FailedClosed, "A resolver failure did not fail closed.");
            Assert(resolverAudit.Events.Single().Kind == ApplicationRequestAuditKind.DependencyFailure, "A resolver failure was not audited.");

            var observation = CreateObservation(
                ObservationA,
                DeviceA,
                ChildA,
                HashIdentity(HashA),
                Now.AddMinutes(-1),
                Now.AddMinutes(4));
            var inconsistentStoreFailure = await new ApplicationAccessRequestCoordinator(
                new FakeResolver(observation),
                new InconsistentStore(),
                new FakeAudit()).CreateAsync(context, payload, Now, CancellationToken.None).ConfigureAwait(false);
            Assert(inconsistentStoreFailure.Status == ApplicationAccessRequestStatus.FailedClosed, "An inconsistent store response was accepted.");
            Assert(inconsistentStoreFailure.Request == null, "A failed-closed result exposed an inconsistent request.");

            var metadataStoreFailure = await new ApplicationAccessRequestCoordinator(
                new FakeResolver(observation),
                new MetadataSubstitutingStore(),
                new FakeAudit()).CreateAsync(context, payload, Now, CancellationToken.None).ConfigureAwait(false);
            Assert(metadataStoreFailure.Status == ApplicationAccessRequestStatus.FailedClosed, "Substituted resolver metadata was accepted.");

            var failingAudit = new FakeAudit { ThrowOnWrite = true };
            var auditFailure = await new ApplicationAccessRequestCoordinator(
                new FakeResolver(observation),
                new AtomicFakeStore(),
                failingAudit).CreateAsync(context, payload, Now, CancellationToken.None).ConfigureAwait(false);
            Assert(auditFailure.Status == ApplicationAccessRequestStatus.FailedClosed, "An unaudited creation was reported as successful.");
            Assert(auditFailure.Request == null, "An unaudited result exposed a request as successful.");
        }

        private static async Task AssertObservationRejectedAsync(
            IBlockedApplicationObservationResolver resolver,
            AuthenticatedChildContext context,
            CreateApplicationRequestPayload payload,
            string message)
        {
            var store = new AtomicFakeStore();
            var audit = new FakeAudit();
            var result = await new ApplicationAccessRequestCoordinator(
                resolver,
                store,
                audit).CreateAsync(context, payload, Now, CancellationToken.None).ConfigureAwait(false);

            Assert(result.Status == ApplicationAccessRequestStatus.RejectedObservation, message);
            Assert(result.Request == null, "A rejected observation exposed a pending request.");
            Assert(store.CreateCount == 0, "A rejected observation reached the pending store.");
            Assert(audit.Events.Count == 1 && audit.Events[0].Kind == ApplicationRequestAuditKind.RejectedObservation, "Observation rejection was not audited.");
        }

        private static VerifiedBlockedApplicationObservation CreateObservation(
            string observationId,
            string deviceId,
            WindowsAccountSid child,
            ApplicationIdentity identity,
            DateTimeOffset observedAt,
            DateTimeOffset expiresAt,
            string? path = null,
            string? signature = null)
        {
            return new VerifiedBlockedApplicationObservation(
                observationId,
                deviceId,
                child,
                identity,
                "Acme Reader",
                observedAt,
                expiresAt,
                path,
                signature);
        }

        private static ApplicationIdentity HashIdentity(string hash)
        {
            return new ApplicationIdentity(null, null, null, hash);
        }

        private static void Throws<TException>(Action action, string message)
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

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private sealed class FakeResolver : IBlockedApplicationObservationResolver
        {
            private readonly Dictionary<string, VerifiedBlockedApplicationObservation> _observations =
                new Dictionary<string, VerifiedBlockedApplicationObservation>(StringComparer.Ordinal);

            public FakeResolver()
            {
            }

            public FakeResolver(
                VerifiedBlockedApplicationObservation observation,
                string? lookupId = null)
            {
                _observations.Add(lookupId ?? observation.ObservationId, observation);
            }

            public string? LastObservationId { get; private set; }

            public Task<VerifiedBlockedApplicationObservation?> ResolveAsync(
                string observationId,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                LastObservationId = observationId;
                VerifiedBlockedApplicationObservation? observation;
                _observations.TryGetValue(observationId, out observation);
                return Task.FromResult(observation);
            }
        }

        private sealed class ThrowingResolver : IBlockedApplicationObservationResolver
        {
            public Task<VerifiedBlockedApplicationObservation?> ResolveAsync(
                string observationId,
                CancellationToken cancellationToken)
            {
                throw new InvalidOperationException("Simulated resolver failure.");
            }
        }

        private sealed class AtomicFakeStore : IPendingApplicationAccessRequestStore
        {
            private readonly object _sync = new object();
            private readonly Dictionary<AccessRequestKey, ApplicationAccessRequest> _requests =
                new Dictionary<AccessRequestKey, ApplicationAccessRequest>();

            public int CreateCount { get; private set; }

            public Task<PendingApplicationRequestStoreResult> CreateOrGetPendingAsync(
                ApplicationAccessRequest candidate,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                lock (_sync)
                {
                    ApplicationAccessRequest? existing;
                    if (_requests.TryGetValue(candidate.RequestKey, out existing))
                    {
                        return Task.FromResult(new PendingApplicationRequestStoreResult(existing!, false));
                    }

                    _requests.Add(candidate.RequestKey, candidate);
                    CreateCount++;
                    return Task.FromResult(new PendingApplicationRequestStoreResult(candidate, true));
                }
            }
        }

        private sealed class InconsistentStore : IPendingApplicationAccessRequestStore
        {
            public Task<PendingApplicationRequestStoreResult> CreateOrGetPendingAsync(
                ApplicationAccessRequest candidate,
                CancellationToken cancellationToken)
            {
                var substituted = new ApplicationAccessRequest(
                    candidate.RequestId,
                    candidate.DeviceId,
                    candidate.ChildAccountSid,
                    candidate.ObservationId,
                    HashIdentity(HashB),
                    candidate.DisplayName,
                    candidate.ChildReason,
                    candidate.CreatedAtUtc);
                return Task.FromResult(new PendingApplicationRequestStoreResult(substituted, true));
            }
        }

        private sealed class MetadataSubstitutingStore : IPendingApplicationAccessRequestStore
        {
            public Task<PendingApplicationRequestStoreResult> CreateOrGetPendingAsync(
                ApplicationAccessRequest candidate,
                CancellationToken cancellationToken)
            {
                var substituted = new ApplicationAccessRequest(
                    candidate.RequestId,
                    candidate.DeviceId,
                    candidate.ChildAccountSid,
                    candidate.ObservationId,
                    candidate.Identity,
                    "Substituted display name",
                    candidate.ChildReason,
                    candidate.CreatedAtUtc,
                    candidate.ObservedExecutablePath,
                    candidate.VerifiedSignatureSummary);
                return Task.FromResult(new PendingApplicationRequestStoreResult(substituted, true));
            }
        }

        private sealed class FakeAudit : IApplicationRequestAudit
        {
            private readonly object _sync = new object();
            private readonly List<ApplicationRequestAuditEvent> _events =
                new List<ApplicationRequestAuditEvent>();

            public bool ThrowOnWrite { get; set; }

            public IReadOnlyList<ApplicationRequestAuditEvent> Events
            {
                get
                {
                    lock (_sync)
                    {
                        return _events.ToArray();
                    }
                }
            }

            public Task WriteAsync(
                ApplicationRequestAuditEvent auditEvent,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (ThrowOnWrite)
                {
                    throw new InvalidOperationException("Simulated audit failure.");
                }

                lock (_sync)
                {
                    _events.Add(auditEvent);
                }

                return Task.CompletedTask;
            }
        }
    }
}
