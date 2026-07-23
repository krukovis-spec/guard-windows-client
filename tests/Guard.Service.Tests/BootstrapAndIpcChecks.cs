using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Contracts;
using Guard.Domain;
using Guard.Protocol;
using Guard.Service;
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

        private static GuardServiceIpcOperationHandler CreateHandler(
            MutableStateStore store,
            IManagedChildAccountValidator validator,
            DateTimeOffset now)
        {
            var ceremony = new SetupCeremony(
                new DeterministicSecretGenerator(),
                new Sha256Hasher(),
                new AcceptingTrustAnchorValidator());
            return new GuardServiceIpcOperationHandler(
                store,
                new SetupCoordinator(store, ceremony),
                new ChildAccountBindingCoordinator(store, validator),
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
    }
}
