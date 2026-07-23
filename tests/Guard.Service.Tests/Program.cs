using System;
using System.Collections.Generic;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using Guard.Service;
using Guard.Application;
using Guard.Contracts;
using Guard.Domain;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Guard.Service.Tests
{
    internal static class Program
    {
        private static async Task<int> Main()
        {
            var tests = new List<(string Name, Func<Task> Run)>
            {
                ("rejects an interactive process before initialization", RejectsInteractiveProcessAsync),
                ("rejects a non-LocalSystem service before initialization", RejectsNonSystemServiceAsync),
                ("initializes only inside the LocalSystem service boundary", InitializesAuthorizedServiceAsync),
                ("does not report started before boundary initialization completes", WaitsForBoundaryInitializationAsync),
                ("propagates boundary initialization failure from host start", PropagatesBoundaryFailureAsync),
                ("shuts down boundary resources and records fatal exit", ShutsDownAndRecordsFatalExitAsync),
                ("does not publish pipes when authoritative state fails", DoesNotPublishPipesOnStateFailureAsync),
                ("checks ACL before and after acquiring the writer lease", EnforcesBoundaryStartupOrderAsync),
                ("rolls back acquired boundary resources on pipe failure", RollsBackBoundaryResourcesAsync),
                ("rolls back earlier listeners when a later endpoint fails", RollsBackEarlierPipeHostsAsync),
                ("marks unexpected pipe completion as a fatal service exit", MarksPipeRuntimeFailureAsync),
                ("exposes only role-fixed pipe endpoints with exact SIDs", BuildsRestrictedPipeCatalogAsync),
                ("registers the Windows service worker", RegistersWindowsServiceWorkerAsync),
                ("composes one lazy authoritative production boundary", ComposesLazyProductionBoundaryAsync),
                ("refuses policy-bearing state before enforcement exists", RejectsPolicyStateWithoutEnforcementAsync),
                ("parses only the explicit one-time bootstrap argument", BootstrapAndIpcChecks.ParsesExplicitBootstrapArgumentAsync),
                ("rejects bootstrap outside the service execution boundary", BootstrapAndIpcChecks.RejectsBootstrapOutsideServiceBoundaryAsync),
                ("bootstraps state in fail-closed boundary order", BootstrapAndIpcChecks.BootstrapsInFailClosedOrderAsync),
                ("composes explicit bootstrap and a functional production handler", BootstrapAndIpcChecks.ComposesExplicitBootstrapAndFunctionalHandlerAsync),
                ("handles bounded status setup and child binding operations", BootstrapAndIpcChecks.HandlesBoundedSetupStatusAndBindingAsync),
                ("returns an admin-only fail-closed readiness snapshot", BootstrapAndIpcChecks.ReturnsAdminOnlyReadinessSnapshotAsync),
                ("keeps unobserved production readiness facts blocking", BootstrapAndIpcChecks.UsesOnlyObservedProductionReadinessFactsAsync)
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

            Console.WriteLine(failures == 0
                ? "All Guard service boundary checks passed."
                : failures + " Guard service boundary check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static async Task RejectsInteractiveProcessAsync()
        {
            var initializer = new RecordingInitializer();
            var runtime = CreateRuntime(isWindowsService: false, isLocalSystem: true, initializer);
            await AssertThrowsAsync<SecurityException>(() => runtime.InitializeAsync(CancellationToken.None)).ConfigureAwait(false);
            Assert(initializer.CallCount == 0, "Interactive execution reached service initialization.");
        }

        private static async Task RejectsNonSystemServiceAsync()
        {
            var initializer = new RecordingInitializer();
            var runtime = CreateRuntime(isWindowsService: true, isLocalSystem: false, initializer);
            await AssertThrowsAsync<SecurityException>(() => runtime.InitializeAsync(CancellationToken.None)).ConfigureAwait(false);
            Assert(initializer.CallCount == 0, "A non-LocalSystem service reached initialization.");
        }

        private static async Task InitializesAuthorizedServiceAsync()
        {
            var initializer = new RecordingInitializer();
            var runtime = CreateRuntime(isWindowsService: true, isLocalSystem: true, initializer);
            await runtime.InitializeAsync(CancellationToken.None).ConfigureAwait(false);
            Assert(initializer.CallCount == 1, "Authorized service initialization was not called exactly once.");
        }

        private static async Task WaitsForBoundaryInitializationAsync()
        {
            var initializer = new BlockingInitializer();
            using (var host = GuardServiceHost.BuildForTesting(
                new FakeProcessContext(isWindowsService: true, isLocalSystem: true),
                initializer))
            {
                var startTask = host.StartAsync();
                await initializer.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
                Assert(!startTask.IsCompleted, "Host start completed before boundary initialization.");
                initializer.Release.TrySetResult(true);
                await startTask.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
                await host.StopAsync().ConfigureAwait(false);
            }
        }

        private static async Task PropagatesBoundaryFailureAsync()
        {
            using (var host = GuardServiceHost.BuildForTesting(
                new FakeProcessContext(isWindowsService: true, isLocalSystem: true),
                new FailingInitializer()))
            {
                await AssertThrowsAsync<InvalidOperationException>(() => host.StartAsync()).ConfigureAwait(false);
            }
        }

        private static async Task ShutsDownAndRecordsFatalExitAsync()
        {
            var initializer = new RecordingInitializer();
            var runtime = CreateRuntime(isWindowsService: true, isLocalSystem: true, initializer);
            await runtime.InitializeAsync(CancellationToken.None).ConfigureAwait(false);
            await runtime.ShutdownAsync(CancellationToken.None).ConfigureAwait(false);
            Assert(initializer.ShutdownCallCount == 1, "Service boundary resources were not shut down.");

            var status = new ServiceExitStatus();
            Assert(status.ExitCode == ServiceExitStatus.Success, "Fresh service status was not successful.");
            status.MarkFatalRuntimeFailure();
            Assert(status.ExitCode == ServiceExitStatus.FatalRuntimeFailure, "Fatal runtime failure kept a success exit code.");
        }

        private static async Task DoesNotPublishPipesOnStateFailureAsync()
        {
            var lease = new FakeWriterLease();
            var pipes = new FakePipeSupervisor();
            var initializer = new ServiceBoundaryInitializer(
                lease,
                new PassingDataBoundaryGuard(),
                new NoOpDataBoundaryBootstrapper(),
                new FailingStateStore(),
                new RejectingStateInitializer(),
                new NoOpPolicyReconciler(),
                new NoProxyIdentityProvider(),
                pipes,
                ServiceStartupOptions.Normal);
            await AssertThrowsAsync<InvalidOperationException>(
                () => initializer.InitializeAsync(CancellationToken.None)).ConfigureAwait(false);
            Assert(pipes.StartCount == 0, "Pipes were published before authoritative state loaded.");
            Assert(lease.DisposeCount == 1, "Writer lease was not released after state failure.");
        }

        private static async Task EnforcesBoundaryStartupOrderAsync()
        {
            var events = new List<string>();
            var initializer = new ServiceBoundaryInitializer(
                new OrderedWriterLease(events),
                new OrderedDataBoundaryGuard(events),
                new NoOpDataBoundaryBootstrapper(),
                new OrderedStateStore(events),
                new RejectingStateInitializer(),
                new OrderedPolicyReconciler(events),
                new NoProxyIdentityProvider(),
                new OrderedPipeSupervisor(events),
                ServiceStartupOptions.Normal);
            await initializer.InitializeAsync(CancellationToken.None).ConfigureAwait(false);
            var expected = new[]
            {
                "acl",
                "lease",
                "acl",
                "load",
                "reconcile",
                "pipes"
            };
            Assert(events.Count == expected.Length, "Boundary startup emitted an unexpected number of steps.");
            for (var index = 0; index < expected.Length; index++)
            {
                Assert(
                    string.Equals(events[index], expected[index], StringComparison.Ordinal),
                    "Boundary startup order was unsafe at step " + index + ".");
            }

            await initializer.ShutdownAsync(CancellationToken.None).ConfigureAwait(false);
        }

        private static async Task RollsBackBoundaryResourcesAsync()
        {
            var lease = new FakeWriterLease();
            var pipes = new FakePipeSupervisor { FailStart = true };
            var initializer = new ServiceBoundaryInitializer(
                lease,
                new PassingDataBoundaryGuard(),
                new NoOpDataBoundaryBootstrapper(),
                new FixedStateStore(new DeviceSecurityState("device-v2-000001", 0, 0, 0)),
                new RejectingStateInitializer(),
                new NoOpPolicyReconciler(),
                new NoProxyIdentityProvider(),
                pipes,
                ServiceStartupOptions.Normal);
            await AssertThrowsAsync<InvalidOperationException>(
                () => initializer.InitializeAsync(CancellationToken.None)).ConfigureAwait(false);
            Assert(pipes.StartCount == 1, "Pipe startup was not attempted.");
            Assert(pipes.StopCount == 1, "Partially started pipes were not rolled back.");
            Assert(lease.DisposeCount == 1, "Writer lease was not released after pipe failure.");
        }

        private static async Task RollsBackEarlierPipeHostsAsync()
        {
            var first = new FakeEndpointHost();
            var second = new FakeEndpointHost { FailStart = true };
            var lifetime = new FakeApplicationLifetime();
            var supervisor = new ServicePipeSupervisor(
                new FakeEndpointHostFactory(first, second),
                new ServiceExitStatus(),
                lifetime);
            var endpoints = new[]
            {
                ServicePipeCatalog.Create(
                    new DeviceSecurityState("device-v2-000001", 0, 0, 0),
                    proxyAccountSid: null)[0],
                new ServicePipeEndpoint(
                    ServicePipeNames.Child,
                    ClientRole.Child,
                    PipeClientAuthorizationKind.ExactAccountSid,
                    new WindowsAccountSid("S-1-5-21-1001-2002-3003-1004"))
            };
            await AssertThrowsAsync<InvalidOperationException>(
                () => supervisor.StartAsync(endpoints, CancellationToken.None)).ConfigureAwait(false);
            Assert(first.StopCount == 1, "Earlier pipe listener survived a later startup failure.");
        }

        private static async Task MarksPipeRuntimeFailureAsync()
        {
            var host = new FakeEndpointHost();
            var lifetime = new FakeApplicationLifetime();
            var status = new ServiceExitStatus();
            var supervisor = new ServicePipeSupervisor(
                new FakeEndpointHostFactory(host),
                status,
                lifetime);
            var endpoints = ServicePipeCatalog.Create(
                new DeviceSecurityState("device-v2-000001", 0, 0, 0),
                proxyAccountSid: null);
            await supervisor.StartAsync(endpoints, CancellationToken.None).ConfigureAwait(false);
            host.CompleteUnexpectedly();
            await lifetime.Stopped.Task.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            Assert(status.ExitCode == ServiceExitStatus.FatalRuntimeFailure, "Pipe runtime failure kept a success exit code.");
            await supervisor.StopAsync(CancellationToken.None).ConfigureAwait(false);
        }

        private static Task RegistersWindowsServiceWorkerAsync()
        {
            using (var host = GuardServiceHost.Build(Array.Empty<string>()))
            {
                var workers = host.Services.GetServices<IHostedService>();
                var found = false;
                foreach (var worker in workers)
                {
                    if (worker is GuardServiceWorker)
                    {
                        found = true;
                    }
                }

                Assert(found, "Guard service worker was not registered.");
            }

            return Task.CompletedTask;
        }

        private static Task ComposesLazyProductionBoundaryAsync()
        {
            using (var host = GuardServiceHost.Build(Array.Empty<string>()))
            {
                var writerLease = host.Services.GetRequiredService<IServiceWriterLease>();
                var stateStore = host.Services.GetRequiredService<IAuthoritativeStateStore>();
                Assert(
                    ReferenceEquals(writerLease, stateStore),
                    "Production composition registered more than one authoritative writer.");
                var boundary = writerLease as ServiceAuthoritativeStateBoundary;
                Assert(boundary != null, "Production authoritative boundary was not composed.");
                Assert(
                    !boundary!.IsAcquired,
                    "Resolving production services opened ProgramData before execution-boundary authorization.");
                Assert(
                    host.Services.GetRequiredService<IServiceBoundaryInitializer>()
                        is ServiceBoundaryInitializer,
                    "Production service retained an unconfigured initializer.");
            }

            return Task.CompletedTask;
        }

        private static async Task RejectsPolicyStateWithoutEnforcementAsync()
        {
            var reconciler = new BoundaryOnlyPolicyReconciler();
            await reconciler.ReconcileAsync(
                new DeviceSecurityState("device-v2-000001", 0, 0, 0),
                CancellationToken.None).ConfigureAwait(false);
            await AssertThrowsAsync<InvalidOperationException>(
                () => reconciler.ReconcileAsync(
                    new DeviceSecurityState("device-v2-000001", 1, 1, 1),
                    CancellationToken.None)).ConfigureAwait(false);
        }

        private static Task BuildsRestrictedPipeCatalogAsync()
        {
            var unbound = new DeviceSecurityState("device-v2-000001", 0, 0, 0);
            var initial = ServicePipeCatalog.Create(unbound, proxyAccountSid: null);
            Assert(initial.Count == 1, "Unbound state exposed child or proxy IPC.");
            Assert(initial[0].Role == ClientRole.AdminSetup, "Admin setup was not the only bootstrap endpoint.");
            Assert(initial[0].PipeName == ServicePipeNames.AdminSetup, "Admin pipe name changed unexpectedly.");
            Assert(initial[0].AuthorizedSid.Value == "S-1-5-32-544", "Admin pipe did not use BUILTIN Administrators.");

            var childSid = new WindowsAccountSid("S-1-5-21-1001-2002-3003-1004");
            var proxySid = new WindowsAccountSid("S-1-5-80-1001-2002-3003-4004");
            var bound = new DeviceSecurityState(
                "device-v2-000001",
                1,
                0,
                0,
                childAccountSid: childSid);
            var endpoints = ServicePipeCatalog.Create(bound, proxySid);
            Assert(endpoints.Count == 3, "Bound service did not expose exactly three public endpoints.");
            AssertEndpoint(endpoints, ServicePipeNames.Child, ClientRole.Child, childSid);
            AssertEndpoint(endpoints, ServicePipeNames.Proxy, ClientRole.Proxy, proxySid);
            for (var index = 0; index < endpoints.Count; index++)
            {
                Assert(
                    endpoints[index].Role != ClientRole.ParentRelay &&
                    endpoints[index].Role != ClientRole.ServiceInternal,
                    "An internal authority was exposed as a public pipe.");
            }

            return Task.CompletedTask;
        }

        private static void AssertEndpoint(
            IReadOnlyList<ServicePipeEndpoint> endpoints,
            string name,
            ClientRole role,
            WindowsAccountSid sid)
        {
            for (var index = 0; index < endpoints.Count; index++)
            {
                var endpoint = endpoints[index];
                if (string.Equals(endpoint.PipeName, name, StringComparison.Ordinal))
                {
                    Assert(endpoint.Role == role, "Pipe role was derived incorrectly.");
                    Assert(endpoint.AuthorizationKind == PipeClientAuthorizationKind.ExactAccountSid, "Pipe did not require an exact SID.");
                    Assert(endpoint.AuthorizedSid.Equals(sid), "Pipe authorized a different SID.");
                    return;
                }
            }

            throw new InvalidOperationException("Expected pipe endpoint was missing: " + name);
        }

        private static GuardServiceRuntime CreateRuntime(
            bool isWindowsService,
            bool isLocalSystem,
            RecordingInitializer initializer)
        {
            var context = new FakeProcessContext(isWindowsService, isLocalSystem);
            return new GuardServiceRuntime(new ServiceExecutionBoundary(context), initializer);
        }

        private static async Task AssertThrowsAsync<TException>(Func<Task> action)
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

            throw new InvalidOperationException("Expected " + typeof(TException).Name + ".");
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private sealed class FakeProcessContext : IServiceProcessContext
        {
            public FakeProcessContext(bool isWindowsService, bool isLocalSystem)
            {
                IsWindowsService = isWindowsService;
                IsLocalSystem = isLocalSystem;
            }

            public bool IsWindowsService { get; }

            public bool IsLocalSystem { get; }
        }

        private sealed class RecordingInitializer : IServiceBoundaryInitializer
        {
            public int CallCount { get; private set; }

            public int ShutdownCallCount { get; private set; }

            public Task InitializeAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                CallCount++;
                return Task.CompletedTask;
            }

            public Task ShutdownAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                ShutdownCallCount++;
                return Task.CompletedTask;
            }
        }

        private sealed class BlockingInitializer : IServiceBoundaryInitializer
        {
            public TaskCompletionSource<bool> Entered { get; } =
                new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            public TaskCompletionSource<bool> Release { get; } =
                new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            public async Task InitializeAsync(CancellationToken cancellationToken)
            {
                Entered.TrySetResult(true);
                await Release.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            public Task ShutdownAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return Task.CompletedTask;
            }
        }

        private sealed class FailingInitializer : IServiceBoundaryInitializer
        {
            public Task InitializeAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                throw new InvalidOperationException("Expected startup failure.");
            }

            public Task ShutdownAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return Task.CompletedTask;
            }
        }

        private sealed class FakeWriterLease : IServiceWriterLease
        {
            public int DisposeCount { get; private set; }

            public Task AcquireAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return Task.CompletedTask;
            }

            public ValueTask DisposeAsync()
            {
                DisposeCount++;
                return ValueTask.CompletedTask;
            }
        }

        private sealed class PassingDataBoundaryGuard : IServiceDataBoundaryGuard
        {
            public void DemandReady()
            {
            }
        }

        private sealed class NoOpDataBoundaryBootstrapper :
            IServiceDataBoundaryBootstrapper
        {
            public void PrepareEmptyBoundary()
            {
            }
        }

        private sealed class RejectingStateInitializer :
            IServiceAuthoritativeStateInitializer
        {
            public Task InitializeNewAsync(
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                throw new InvalidOperationException(
                    "Unexpected authoritative-state initialization.");
            }
        }

        private sealed class OrderedDataBoundaryGuard : IServiceDataBoundaryGuard
        {
            private readonly List<string> _events;

            public OrderedDataBoundaryGuard(List<string> events)
            {
                _events = events;
            }

            public void DemandReady()
            {
                _events.Add("acl");
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

        private sealed class NoProxyIdentityProvider : IServiceProxyIdentityProvider
        {
            public WindowsAccountSid? GetProxyAccountSid()
            {
                return null;
            }
        }

        private sealed class NoOpPolicyReconciler : IPolicyReconciler
        {
            public Task ReconcileAsync(
                DeviceSecurityState desiredState,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return Task.CompletedTask;
            }
        }

        private sealed class OrderedPolicyReconciler : IPolicyReconciler
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

        private sealed class FakePipeSupervisor : IServicePipeSupervisor
        {
            public bool FailStart { get; set; }

            public int StartCount { get; private set; }

            public int StopCount { get; private set; }

            public Task StartAsync(
                IReadOnlyList<ServicePipeEndpoint> endpoints,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                StartCount++;
                if (FailStart)
                {
                    throw new InvalidOperationException("Synthetic pipe startup failure.");
                }

                return Task.CompletedTask;
            }

            public Task StopAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                StopCount++;
                return Task.CompletedTask;
            }
        }

        private sealed class OrderedPipeSupervisor : IServicePipeSupervisor
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

        private sealed class FailingStateStore : IAuthoritativeStateStore
        {
            public Task<DeviceSecurityState> LoadAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                throw new InvalidOperationException("Synthetic state failure.");
            }

            public Task<bool> TryCommitAsync(
                long expectedVersion,
                DeviceSecurityState nextState,
                CancellationToken cancellationToken)
            {
                throw new NotSupportedException();
            }
        }

        private sealed class FixedStateStore : IAuthoritativeStateStore
        {
            private readonly DeviceSecurityState _state;

            public FixedStateStore(DeviceSecurityState state)
            {
                _state = state;
            }

            public Task<DeviceSecurityState> LoadAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return Task.FromResult(_state);
            }

            public Task<bool> TryCommitAsync(
                long expectedVersion,
                DeviceSecurityState nextState,
                CancellationToken cancellationToken)
            {
                throw new NotSupportedException();
            }
        }

        private sealed class OrderedStateStore : IAuthoritativeStateStore
        {
            private readonly List<string> _events;

            public OrderedStateStore(List<string> events)
            {
                _events = events;
            }

            public Task<DeviceSecurityState> LoadAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                _events.Add("load");
                return Task.FromResult(
                    new DeviceSecurityState("device-v2-000001", 0, 0, 0));
            }

            public Task<bool> TryCommitAsync(
                long expectedVersion,
                DeviceSecurityState nextState,
                CancellationToken cancellationToken)
            {
                throw new NotSupportedException();
            }
        }

        private sealed class FakeEndpointHostFactory : IServicePipeEndpointHostFactory
        {
            private readonly Queue<FakeEndpointHost> _hosts;

            public FakeEndpointHostFactory(params FakeEndpointHost[] hosts)
            {
                _hosts = new Queue<FakeEndpointHost>(hosts);
            }

            public IServicePipeEndpointHost Create(ServicePipeEndpoint endpoint)
            {
                return _hosts.Dequeue();
            }
        }

        private sealed class FakeEndpointHost : IServicePipeEndpointHost
        {
            private readonly TaskCompletionSource<bool> _completion =
                new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            public bool FailStart { get; set; }

            public int StopCount { get; private set; }

            public Task Completion => _completion.Task;

            public Task StartAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (FailStart)
                {
                    throw new InvalidOperationException("Synthetic endpoint startup failure.");
                }

                return Task.CompletedTask;
            }

            public Task StopAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                StopCount++;
                _completion.TrySetCanceled(cancellationToken);
                return Task.CompletedTask;
            }

            public void CompleteUnexpectedly()
            {
                _completion.TrySetResult(true);
            }
        }

        private sealed class FakeApplicationLifetime : IHostApplicationLifetime
        {
            private readonly CancellationTokenSource _started = new CancellationTokenSource();
            private readonly CancellationTokenSource _stopping = new CancellationTokenSource();
            private readonly CancellationTokenSource _stopped = new CancellationTokenSource();

            public TaskCompletionSource<bool> Stopped { get; } =
                new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            public CancellationToken ApplicationStarted => _started.Token;

            public CancellationToken ApplicationStopping => _stopping.Token;

            public CancellationToken ApplicationStopped => _stopped.Token;

            public void StopApplication()
            {
                _stopping.Cancel();
                Stopped.TrySetResult(true);
            }
        }
    }
}
