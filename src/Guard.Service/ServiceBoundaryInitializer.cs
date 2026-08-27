using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Domain;

namespace Guard.Service
{
    internal interface IServiceWriterLease : IAsyncDisposable
    {
        Task AcquireAsync(CancellationToken cancellationToken);
    }

    internal interface IServiceDataBoundaryGuard
    {
        void DemandReady();
    }

    internal interface IServiceDataBoundaryBootstrapper
    {
        void PrepareEmptyBoundary();
    }

    internal interface IServiceAuthoritativeStateInitializer
    {
        Task InitializeNewAsync(CancellationToken cancellationToken);
    }

    internal interface IServiceProxyIdentityProvider
    {
        WindowsAccountSid? GetProxyAccountSid();
    }

    internal interface IServicePipeSupervisor
    {
        Task StartAsync(
            IReadOnlyList<ServicePipeEndpoint> endpoints,
            CancellationToken cancellationToken);

        Task StopAsync(CancellationToken cancellationToken);
    }

    internal sealed class ServiceBoundaryInitializer : IServiceBoundaryInitializer
    {
        private readonly IServiceWriterLease _writerLease;
        private readonly IServiceDataBoundaryGuard _dataBoundaryGuard;
        private readonly IServiceDataBoundaryBootstrapper _dataBoundaryBootstrapper;
        private readonly IAuthoritativeStateStore _stateStore;
        private readonly IServiceAuthoritativeStateInitializer _stateInitializer;
        private readonly IPolicyReconciler _policyReconciler;
        private readonly IServiceProxyIdentityProvider _proxyIdentityProvider;
        private readonly IServicePipeSupervisor _pipeSupervisor;
        private readonly ServiceStartupOptions _startupOptions;
        private int _started;

        public ServiceBoundaryInitializer(
            IServiceWriterLease writerLease,
            IServiceDataBoundaryGuard dataBoundaryGuard,
            IServiceDataBoundaryBootstrapper dataBoundaryBootstrapper,
            IAuthoritativeStateStore stateStore,
            IServiceAuthoritativeStateInitializer stateInitializer,
            IPolicyReconciler policyReconciler,
            IServiceProxyIdentityProvider proxyIdentityProvider,
            IServicePipeSupervisor pipeSupervisor,
            ServiceStartupOptions startupOptions)
        {
            _writerLease = writerLease ?? throw new ArgumentNullException(nameof(writerLease));
            _dataBoundaryGuard = dataBoundaryGuard ?? throw new ArgumentNullException(nameof(dataBoundaryGuard));
            _dataBoundaryBootstrapper = dataBoundaryBootstrapper ??
                throw new ArgumentNullException(nameof(dataBoundaryBootstrapper));
            _stateStore = stateStore ?? throw new ArgumentNullException(nameof(stateStore));
            _stateInitializer = stateInitializer ??
                throw new ArgumentNullException(nameof(stateInitializer));
            _policyReconciler = policyReconciler ?? throw new ArgumentNullException(nameof(policyReconciler));
            _proxyIdentityProvider = proxyIdentityProvider ?? throw new ArgumentNullException(nameof(proxyIdentityProvider));
            _pipeSupervisor = pipeSupervisor ?? throw new ArgumentNullException(nameof(pipeSupervisor));
            _startupOptions = startupOptions ??
                throw new ArgumentNullException(nameof(startupOptions));
        }

        public async Task InitializeAsync(CancellationToken cancellationToken)
        {
            if (Interlocked.CompareExchange(ref _started, 1, 0) != 0)
            {
                throw new InvalidOperationException("The service boundary is already initialized.");
            }

            var leaseAcquired = false;
            try
            {
                if (_startupOptions.InitializeAuthoritativeState)
                {
                    _dataBoundaryBootstrapper.PrepareEmptyBoundary();
                }

                // Refuse attacker-controlled, inherited, or reparse-backed
                // storage before opening any lease file. Re-check after the
                // lease is held to close the boundary-change window.
                _dataBoundaryGuard.DemandReady();
                await _writerLease.AcquireAsync(cancellationToken).ConfigureAwait(false);
                leaseAcquired = true;
                _dataBoundaryGuard.DemandReady();
                if (_startupOptions.InitializeAuthoritativeState)
                {
                    await _stateInitializer
                        .InitializeNewAsync(cancellationToken)
                        .ConfigureAwait(false);
                    _dataBoundaryGuard.DemandReady();
                }

                var state = await _stateStore.LoadAsync(cancellationToken).ConfigureAwait(false);
                await _policyReconciler.ReconcileAsync(state, cancellationToken).ConfigureAwait(false);
                var endpoints = ServicePipeCatalog.Create(
                    state,
                    _proxyIdentityProvider.GetProxyAccountSid());
                await _pipeSupervisor.StartAsync(endpoints, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                Interlocked.Exchange(ref _started, 0);
                await TryStopPipesAsync().ConfigureAwait(false);
                if (leaseAcquired)
                {
                    await _writerLease.DisposeAsync().ConfigureAwait(false);
                }

                throw;
            }
        }

        public async Task ShutdownAsync(CancellationToken cancellationToken)
        {
            if (Interlocked.Exchange(ref _started, 0) == 0)
            {
                return;
            }

            Exception? stopFailure = null;
            try
            {
                await _pipeSupervisor.StopAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                stopFailure = exception;
            }

            await _writerLease.DisposeAsync().ConfigureAwait(false);
            if (stopFailure != null)
            {
                throw stopFailure;
            }
        }

        private async Task TryStopPipesAsync()
        {
            try
            {
                await _pipeSupervisor.StopAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
            }
        }
    }
}
