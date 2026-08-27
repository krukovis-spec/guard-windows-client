using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Application.Readiness;
using Guard.Contracts;
using Guard.Domain;
using Guard.Domain.Readiness;
using Guard.Protocol;
using Guard.Service;
using Guard.Windows.Accounts;
using Guard.Windows.Readiness;
using Guard.Windows.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Guard.Service.Tests
{
    internal static class BootstrapAndIpcChecks
    {
        public static Task ParsesExplicitBootstrapArgumentAsync()
        {
            string[] hostArgs;
            var options = ServiceStartupOptions.Parse(
                new[]
                {
                    "--environment",
                    "Production",
                    ServiceStartupOptions.InitializeAuthoritativeStateArgument
                },
                out hostArgs);
            Assert(
                options.InitializeAuthoritativeState,
                "The exact bootstrap argument was ignored.");
            Assert(
                hostArgs.Length == 2 &&
                hostArgs[0] == "--environment" &&
                hostArgs[1] == "Production",
                "The security bootstrap argument leaked into host configuration.");

            var nearMatch = ServiceStartupOptions.Parse(
                new[] { "--Initialize-Authoritative-State" },
                out hostArgs);
            Assert(
                !nearMatch.InitializeAuthoritativeState,
                "A case-insensitive near-match enabled bootstrap mode.");
            Assert(
                hostArgs.Length == 1,
                "A non-security host argument was removed.");

            AssertThrows<ArgumentException>(() =>
                ServiceStartupOptions.Parse(
                    new[]
                    {
                        ServiceStartupOptions.InitializeAuthoritativeStateArgument,
                        ServiceStartupOptions.InitializeAuthoritativeStateArgument
                    },
                    out hostArgs));
            return Task.CompletedTask;
        }

        public static async Task RejectsBootstrapOutsideServiceBoundaryAsync()
        {
            var initializer = new RecordingBoundaryInitializer();
            var runtime = new GuardServiceRuntime(
                new ServiceExecutionBoundary(
                    new FixedProcessContext(
                        isWindowsService: false,
                        isLocalSystem: true)),
                initializer);
            await AssertThrowsAsync<SecurityException>(
                () => runtime.InitializeAsync(CancellationToken.None))
                .ConfigureAwait(false);
            Assert(
                initializer.InitializeCalls == 0,
                "Unauthorized execution reached bootstrap initialization.");
        }

        public static async Task BootstrapsInFailClosedOrderAsync()
        {
            string[] ignored;
            var options = ServiceStartupOptions.Parse(
                new[]
                {
                    ServiceStartupOptions.InitializeAuthoritativeStateArgument
                },
                out ignored);
            var events = new List<string>();
            var initializer = new ServiceBoundaryInitializer(
                new OrderedWriterLease(events),
                new OrderedBoundaryGuard(events),
                new OrderedBoundaryBootstrapper(events),
                new OrderedStateStore(events),
                new OrderedStateInitializer(events),
                new OrderedPolicyReconciler(events),
                new NoProxyIdentityProvider(),
                new OrderedPipeSupervisor(events),
                options);
            var runtime = new GuardServiceRuntime(
                new ServiceExecutionBoundary(
                    new FixedProcessContext(
                        isWindowsService: true,
                        isLocalSystem: true)),
                initializer);

            await runtime
                .InitializeAsync(CancellationToken.None)
                .ConfigureAwait(false);
            var expected = new[]
            {
                "prepare-empty-boundary",
                "acl",
                "lease",
                "acl",
                "initialize-state",
                "acl",
                "load",
                "reconcile",
                "pipes"
            };
            AssertSequence(events, expected);
            await runtime
                .ShutdownAsync(CancellationToken.None)
                .ConfigureAwait(false);
        }

        public static Task ComposesExplicitBootstrapAndFunctionalHandlerAsync()
        {
            using (var normalHost = GuardServiceHost.Build(Array.Empty<string>()))
            {
                Assert(
                    !normalHost.Services
                        .GetRequiredService<ServiceStartupOptions>()
                        .InitializeAuthoritativeState,
                    "Normal startup silently enabled state initialization.");
                Assert(
                    normalHost.Services
                        .GetRequiredService<IGuardIpcOperationHandler>()
                        is GuardServiceIpcOperationHandler,
                    "Production IPC remained wired to an unavailable handler.");
            }

            using (var bootstrapHost = GuardServiceHost.Build(
                new[]
                {
                    ServiceStartupOptions.InitializeAuthoritativeStateArgument
                }))
            {
                Assert(
                    bootstrapHost.Services
                        .GetRequiredService<ServiceStartupOptions>()
                        .InitializeAuthoritativeState,
                    "Explicit bootstrap mode was not composed.");
                var boundary = bootstrapHost.Services
                    .GetRequiredService<IServiceWriterLease>()
                    as ServiceAuthoritativeStateBoundary;
                Assert(
                    boundary != null && !boundary.IsAcquired,
                    "Composing bootstrap mode touched ProgramData before the execution boundary.");
            }

            return Task.CompletedTask;
        }

        public static async Task HandlesBoundedSetupStatusAndBindingAsync()
        {
            var now = new DateTimeOffset(
                2026,
                7,
                23,
                12,
                0,
                0,
                TimeSpan.Zero);
            var setupStore = new MutableStateStore(
                new DeviceSecurityState(
                    "device-v2-setup01",
                    version: 0,
                    highestAcceptedSequence: 0,
                    desiredPolicyRevision: 0));
            var childSid = "S-1-5-21-1001-2002-3003-1004";
            var setupHandler = CreateHandler(
                setupStore,
                new ExactChildValidator(childSid),
                now);

            var statusRequest = Request(
                GuardVerb.GetStatus,
                Array.Empty<byte>());
            var statusResponse = await setupHandler
                .HandleAsync(
                    ClientRole.AdminSetup,
                    statusRequest,
                    CancellationToken.None)
                .ConfigureAwait(false);
            Assert(
                statusResponse.Status == GuardIpcResponseStatus.Success,
                "GetStatus was not available.");
            var status = GuardStatusPayloadCodec.Decode(
                statusResponse.GetPayloadCopy());
            Assert(
                status.StateVersion == 0 &&
                !status.IsProvisioned &&
                !status.IsChildAccountBound,
                "GetStatus exposed an incorrect security state.");

            var beginRequest = Request(
                GuardVerb.BeginSetup,
                Array.Empty<byte>());
            var beginResponse = await setupHandler
                .HandleAsync(
                    ClientRole.AdminSetup,
                    beginRequest,
                    CancellationToken.None)
                .ConfigureAwait(false);
            Assert(
                beginResponse.Status == GuardIpcResponseStatus.Success,
                "BeginSetup was not available to the authenticated admin endpoint.");
            var ticket = SetupTicketPayloadCodec.Decode(
                beginResponse.GetPayloadCopy());
            var ticketSecret = ticket.GetSecretCopy();
            try
            {
                Assert(
                    ticket.ChallengeId == DeterministicSecretGenerator.ChallengeId,
                    "BeginSetup returned the wrong challenge id.");
                Assert(
                    ticketSecret.Length == GuardProtocol.SetupSecretBytes &&
                    ticketSecret[0] == 0x5A,
                    "BeginSetup returned the wrong one-time secret.");
                Assert(
                    ticket.ExpiresAtUtc == now.AddMinutes(5),
                    "BeginSetup returned the wrong expiry.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ticketSecret);
            }

            var bindRequest = Request(
                GuardVerb.BindChildAccount,
                BindChildAccountPayloadCodec.Encode(
                    new BindChildAccountRequest(childSid)));
            var forbidden = await setupHandler
                .HandleAsync(
                    ClientRole.Child,
                    bindRequest,
                    CancellationToken.None)
                .ConfigureAwait(false);
            Assert(
                forbidden.Status == GuardIpcResponseStatus.Forbidden,
                "A child role reached the account-binding operation.");

            var bound = await setupHandler
                .HandleAsync(
                    ClientRole.AdminSetup,
                    bindRequest,
                    CancellationToken.None)
                .ConfigureAwait(false);
            Assert(
                bound.Status == GuardIpcResponseStatus.Success,
                "An eligible child account was not bound.");
            var bindingPayload = ChildAccountBindingPayloadCodec.Decode(
                bound.GetPayloadCopy());
            Assert(
                bindingPayload.ServiceRestartRequired,
                "The new exact-SID endpoint was presented as live before restart.");
            Assert(
                setupStore.State.ChildAccountSid != null &&
                setupStore.State.ChildAccountSid.Value == childSid &&
                !setupStore.State.IsProvisioned,
                "Fresh setup did not commit the child SID before relay provisioning.");
        }

        public static async Task ReturnsAdminOnlyReadinessSnapshotAsync()
        {
            var now = new DateTimeOffset(
                2026,
                7,
                23,
                13,
                0,
                0,
                TimeSpan.Zero);
            var store = new MutableStateStore(
                new DeviceSecurityState(
                    "device-v2-ready001",
                    version: 4,
                    highestAcceptedSequence: 0,
                    desiredPolicyRevision: 0));
            var childSid = "S-1-5-21-1001-2002-3003-1004";
            var handler = CreateHandler(
                store,
                new ExactChildValidator(childSid),
                now,
                new FixedReadinessFactsProvider(
                    ReadinessFactState.Satisfied));
            var request = Request(
                GuardVerb.GetReadiness,
                Array.Empty<byte>());

            var childResponse = await handler
                .HandleAsync(
                    ClientRole.Child,
                    request,
                    CancellationToken.None)
                .ConfigureAwait(false);
            Assert(
                childResponse.Status ==
                    GuardIpcResponseStatus.Forbidden &&
                childResponse.PayloadLength == 0,
                "A child role received readiness details.");

            var invalid = await handler
                .HandleAsync(
                    ClientRole.AdminSetup,
                    Request(
                        GuardVerb.GetReadiness,
                        new byte[] { 0x01 }),
                    CancellationToken.None)
                .ConfigureAwait(false);
            Assert(
                invalid.Status ==
                    GuardIpcResponseStatus.InvalidRequest,
                "A non-empty readiness request was accepted.");

            var response = await handler
                .HandleAsync(
                    ClientRole.AdminSetup,
                    request,
                    CancellationToken.None)
                .ConfigureAwait(false);
            Assert(
                response.Status == GuardIpcResponseStatus.Success,
                "The authenticated admin could not inspect readiness.");
            var payload = GuardReadinessPayloadCodec.Decode(
                response.GetPayloadCopy());
            Assert(
                payload.StateVersion == 4 &&
                payload.ObservedAtUtc == now &&
                payload.CanEnableProtection &&
                payload.GetFindingsCopy().Length == 8,
                "The readiness response lost its bounded snapshot.");

            var failingHandler = CreateHandler(
                store,
                new ExactChildValidator(childSid),
                now,
                new ThrowingReadinessFactsProvider());
            var failingResponse = await failingHandler
                .HandleAsync(
                    ClientRole.AdminSetup,
                    request,
                    CancellationToken.None)
                .ConfigureAwait(false);
            var failingPayload = GuardReadinessPayloadCodec.Decode(
                failingResponse.GetPayloadCopy());
            Assert(
                failingResponse.Status ==
                    GuardIpcResponseStatus.Success &&
                !failingPayload.CanEnableProtection &&
                failingPayload.WindowsEdition ==
                    GuardReadinessFactState.Error &&
                failingPayload.ProgramDataAcl ==
                    GuardReadinessFactState.Error,
                "A failed readiness provider produced a ready snapshot.");
        }

        public static Task UsesOnlyObservedProductionReadinessFactsAsync()
        {
            var childSid = new WindowsAccountSid(
                "S-1-5-21-1001-2002-3003-1004");
            var administratorSid = new WindowsAccountSid(
                "S-1-5-21-1001-2002-3003-1005");
            var provider = new ProductionReadinessFactsProvider(
                new FixedLocalAccountFactsProvider(childSid),
                new FixedWindowsEditionFactsSource(
                    new WindowsEditionFacts(
                        buildNumber: 22621,
                        productType: 0x30)),
                new FixedSecureBootStateSource(),
                new FixedSeparateAdministratorSource(
                    new[]
                    {
                        new WindowsSeparateLocalAdministratorSourceCandidate(
                            administratorSid,
                            isNormalLocalUser: true,
                            isEnabled: true,
                            isLocked: false,
                            passwordRequired: true,
                            isGuest: false,
                            isServiceIdentity: false,
                            isEffectiveAdministrator: true)
                    }),
                new PassingReadinessBoundaryGuard(),
                new GuardServiceHealthInspector(
                    new UnknownServiceHealthQuery(),
                    GuardServiceIdentity.ServiceName,
                    GuardServiceIdentity.ExpectedBinaryPath));
            var facts = provider.Probe(
                new DeviceSecurityState(
                    "device-v2-ready002",
                    version: 5,
                    highestAcceptedSequence: 0,
                    desiredPolicyRevision: 0,
                    childAccountSid: childSid),
                CancellationToken.None);

            Assert(
                facts.WindowsEdition.State ==
                    ReadinessFactState.Satisfied &&
                facts.ChildAccount.State ==
                    ReadinessFactState.Satisfied &&
                facts.SeparateLocalAdministrator.State ==
                    ReadinessFactState.Satisfied &&
                facts.SecureBoot.State ==
                    ReadinessFactState.Satisfied &&
                facts.ProgramDataAcl.State ==
                    ReadinessFactState.Satisfied,
                "Observed production readiness facts were not preserved.");
            Assert(
                facts.BitLocker.State ==
                    ReadinessFactState.Unknown &&
                facts.ServiceBoundary.State ==
                    ReadinessFactState.Unknown &&
                facts.SupportedManagedBrowser.State ==
                    ReadinessFactState.Unknown &&
                !ReadinessEvaluator.Evaluate(facts)
                    .CanEnableProtection,
                "An unobserved production fact was presented as ready.");
            return Task.CompletedTask;
        }

        private static GuardServiceIpcOperationHandler CreateHandler(
            MutableStateStore store,
            IManagedChildAccountValidator validator,
            DateTimeOffset now,
            IDeviceReadinessFactsProvider? readinessFactsProvider = null)
        {
            var ceremony = new SetupCeremony(
                new DeterministicSecretGenerator(),
                new Sha256Hasher(),
                new AcceptingTrustAnchorValidator());
            return new GuardServiceIpcOperationHandler(
                store,
                new SetupCoordinator(store, ceremony),
                new ChildAccountBindingCoordinator(store, validator),
                new GuardReadinessCoordinator(
                    store,
                    readinessFactsProvider ??
                        new FixedReadinessFactsProvider(
                            ReadinessFactState.Unknown)),
                new FixedClock(now));
        }

        private static GuardIpcRequest Request(
            GuardVerb verb,
            byte[] payload)
        {
            return new GuardIpcRequest(
                GuardProtocol.CurrentVersion,
                Guid.NewGuid().ToString("D"),
                verb,
                payload);
        }

        private static async Task AssertThrowsAsync<TException>(
            Func<Task> action)
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

            throw new InvalidOperationException(
                "Expected " + typeof(TException).Name + ".");
        }

        private static void AssertThrows<TException>(Action action)
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

            throw new InvalidOperationException(
                "Expected " + typeof(TException).Name + ".");
        }

        private static void AssertSequence(
            IReadOnlyList<string> actual,
            IReadOnlyList<string> expected)
        {
            Assert(
                actual.Count == expected.Count,
                "Bootstrap emitted an unexpected number of boundary steps.");
            for (var index = 0; index < expected.Count; index++)
            {
                Assert(
                    string.Equals(
                        actual[index],
                        expected[index],
                        StringComparison.Ordinal),
                    "Bootstrap order was unsafe at step " + index + ".");
            }
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private sealed class FixedProcessContext : IServiceProcessContext
        {
            public FixedProcessContext(
                bool isWindowsService,
                bool isLocalSystem)
            {
                IsWindowsService = isWindowsService;
                IsLocalSystem = isLocalSystem;
            }

            public bool IsWindowsService { get; }

            public bool IsLocalSystem { get; }
        }

        private sealed class RecordingBoundaryInitializer :
            IServiceBoundaryInitializer
        {
            public int InitializeCalls { get; private set; }

            public Task InitializeAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                InitializeCalls++;
                return Task.CompletedTask;
            }

            public Task ShutdownAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return Task.CompletedTask;
            }
        }

        private sealed class OrderedWriterLease : IServiceWriterLease
        {
            private readonly List<string> _events;

            public OrderedWriterLease(List<string> events)
            {
                _events = events;
            }

            public Task AcquireAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                _events.Add("lease");
                return Task.CompletedTask;
            }

            public ValueTask DisposeAsync()
            {
                return ValueTask.CompletedTask;
            }
        }

        private sealed class OrderedBoundaryGuard :
            IServiceDataBoundaryGuard
        {
            private readonly List<string> _events;

            public OrderedBoundaryGuard(List<string> events)
            {
                _events = events;
            }

            public void DemandReady()
            {
                _events.Add("acl");
            }
        }

        private sealed class OrderedBoundaryBootstrapper :
            IServiceDataBoundaryBootstrapper
        {
            private readonly List<string> _events;

            public OrderedBoundaryBootstrapper(List<string> events)
            {
                _events = events;
            }

            public void PrepareEmptyBoundary()
            {
                _events.Add("prepare-empty-boundary");
            }
        }

        private sealed class OrderedStateInitializer :
            IServiceAuthoritativeStateInitializer
        {
            private readonly List<string> _events;

            public OrderedStateInitializer(List<string> events)
            {
                _events = events;
            }

            public Task InitializeNewAsync(
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                _events.Add("initialize-state");
                return Task.CompletedTask;
            }
        }

        private sealed class OrderedStateStore : IAuthoritativeStateStore
        {
            private readonly List<string> _events;

            public OrderedStateStore(List<string> events)
            {
                _events = events;
            }

            public Task<DeviceSecurityState> LoadAsync(
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                _events.Add("load");
                return Task.FromResult(
                    new DeviceSecurityState(
                        "device-v2-bootstrap",
                        version: 0,
                        highestAcceptedSequence: 0,
                        desiredPolicyRevision: 0));
            }

            public Task<bool> TryCommitAsync(
                long expectedVersion,
                DeviceSecurityState nextState,
                CancellationToken cancellationToken)
            {
                throw new NotSupportedException();
            }
        }

        private sealed class OrderedPolicyReconciler :
            IPolicyReconciler
        {
            private readonly List<string> _events;

            public OrderedPolicyReconciler(List<string> events)
            {
                _events = events;
            }

            public Task ReconcileAsync(
                DeviceSecurityState desiredState,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                _events.Add("reconcile");
                return Task.CompletedTask;
            }
        }

        private sealed class NoProxyIdentityProvider :
            IServiceProxyIdentityProvider
        {
            public WindowsAccountSid? GetProxyAccountSid()
            {
                return null;
            }
        }

        private sealed class OrderedPipeSupervisor :
            IServicePipeSupervisor
        {
            private readonly List<string> _events;

            public OrderedPipeSupervisor(List<string> events)
            {
                _events = events;
            }

            public Task StartAsync(
                IReadOnlyList<ServicePipeEndpoint> endpoints,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                _events.Add("pipes");
                return Task.CompletedTask;
            }

            public Task StopAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return Task.CompletedTask;
            }
        }

        private sealed class MutableStateStore : IAuthoritativeStateStore
        {
            private readonly object _sync = new object();

            public MutableStateStore(DeviceSecurityState state)
            {
                State = state;
            }

            public DeviceSecurityState State { get; private set; }

            public Task<DeviceSecurityState> LoadAsync(
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                lock (_sync)
                {
                    return Task.FromResult(State);
                }
            }

            public Task<bool> TryCommitAsync(
                long expectedVersion,
                DeviceSecurityState nextState,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                lock (_sync)
                {
                    if (State.Version != expectedVersion)
                    {
                        return Task.FromResult(false);
                    }

                    State = nextState;
                    return Task.FromResult(true);
                }
            }
        }

        private sealed class DeterministicSecretGenerator :
            ISetupSecretGenerator
        {
            public const string ChallengeId =
                "setup:deterministic-challenge";

            public string CreateChallengeId()
            {
                return ChallengeId;
            }

            public byte[] CreateSecret(int byteCount)
            {
                var secret = new byte[byteCount];
                for (var index = 0; index < secret.Length; index++)
                {
                    secret[index] = 0x5A;
                }

                return secret;
            }
        }

        private sealed class Sha256Hasher : ISetupSecretHasher
        {
            public byte[] ComputeHash(byte[] secret)
            {
                return SHA256.HashData(secret);
            }
        }

        private sealed class AcceptingTrustAnchorValidator :
            IParentTrustAnchorValidator
        {
            public bool IsValid(ParentTrustAnchor trustAnchor)
            {
                return true;
            }
        }

        private sealed class ExactChildValidator :
            IManagedChildAccountValidator
        {
            private readonly string _expectedSid;

            public ExactChildValidator(string expectedSid)
            {
                _expectedSid = expectedSid;
            }

            public bool TryValidate(
                string candidateSid,
                out WindowsAccountSid binding)
            {
                if (!string.Equals(
                    candidateSid,
                    _expectedSid,
                    StringComparison.Ordinal))
                {
                    binding = null!;
                    return false;
                }

                binding = new WindowsAccountSid(candidateSid);
                return true;
            }
        }

        private sealed class FixedClock : IServiceUtcClock
        {
            public FixedClock(DateTimeOffset utcNow)
            {
                UtcNow = utcNow;
            }

            public DateTimeOffset UtcNow { get; }
        }

        private sealed class FixedReadinessFactsProvider :
            IDeviceReadinessFactsProvider
        {
            private readonly ReadinessFactState _state;

            public FixedReadinessFactsProvider(
                ReadinessFactState state)
            {
                _state = state;
            }

            public ReadinessProbeFacts Probe(
                DeviceSecurityState authoritativeState,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var fact = new ReadinessProbeFact(_state);
                var browser = _state == ReadinessFactState.Satisfied
                    ? new SupportedManagedBrowserProbeFact(
                        _state,
                        managedBrowserCount: 2)
                    : new SupportedManagedBrowserProbeFact(
                        _state,
                        managedBrowserCount: 0);
                return new ReadinessProbeFacts(
                    fact,
                    fact,
                    fact,
                    fact,
                    fact,
                    fact,
                    fact,
                    browser);
            }
        }

        private sealed class ThrowingReadinessFactsProvider :
            IDeviceReadinessFactsProvider
        {
            public ReadinessProbeFacts Probe(
                DeviceSecurityState authoritativeState,
                CancellationToken cancellationToken)
            {
                throw new InvalidOperationException(
                    "Synthetic readiness probe failure.");
            }
        }

        private sealed class FixedLocalAccountFactsProvider :
            ILocalAccountSecurityFactsProvider
        {
            private readonly WindowsAccountSid _childSid;

            public FixedLocalAccountFactsProvider(
                WindowsAccountSid childSid)
            {
                _childSid = childSid;
            }

            public bool TryGet(
                WindowsAccountSid candidateSid,
                out LocalAccountSecurityFacts facts)
            {
                facts = new LocalAccountSecurityFacts(
                    _childSid,
                    exists: true,
                    isLocalUser: true,
                    isEnabled: true,
                    isGuest: false,
                    isServiceIdentity: false,
                    isAdministrator: false);
                return candidateSid.Equals(_childSid);
            }
        }

        private sealed class FixedWindowsEditionFactsSource :
            IWindowsEditionFactsSource
        {
            private readonly WindowsEditionFacts _facts;

            public FixedWindowsEditionFactsSource(
                WindowsEditionFacts facts)
            {
                _facts = facts;
            }

            public WindowsEditionFacts Get()
            {
                return _facts;
            }
        }

        private sealed class FixedSecureBootStateSource :
            ISecureBootStateSource
        {
            public bool TryReadEnabled(out int enabled)
            {
                enabled = 1;
                return true;
            }
        }

        private sealed class FixedSeparateAdministratorSource :
            IWindowsSeparateLocalAdministratorSource
        {
            private readonly IReadOnlyCollection<
                WindowsSeparateLocalAdministratorSourceCandidate>
                _candidates;

            public FixedSeparateAdministratorSource(
                IReadOnlyCollection<
                    WindowsSeparateLocalAdministratorSourceCandidate>
                    candidates)
            {
                _candidates = candidates;
            }

            public IReadOnlyCollection<
                WindowsSeparateLocalAdministratorSourceCandidate>
                Enumerate(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return _candidates;
            }
        }

        private sealed class PassingReadinessBoundaryGuard :
            IServiceDataBoundaryGuard
        {
            public void DemandReady()
            {
            }
        }

        private sealed class UnknownServiceHealthQuery :
            IServiceHealthQuery
        {
            public ServiceHealthProbeResult Query(string serviceName)
            {
                return new ServiceHealthProbeResult(
                    ServiceHealthProbeState.Unknown,
                    facts: null);
            }
        }
    }
}
