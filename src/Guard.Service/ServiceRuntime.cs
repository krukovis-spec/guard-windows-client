using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;

namespace Guard.Service
{
    internal interface IServiceBoundaryInitializer
    {
        Task InitializeAsync(CancellationToken cancellationToken);

        Task ShutdownAsync(CancellationToken cancellationToken);
    }

    internal sealed class GuardServiceRuntime
    {
        private readonly ServiceExecutionBoundary _executionBoundary;
        private readonly IServiceBoundaryInitializer _initializer;

        public GuardServiceRuntime(
            ServiceExecutionBoundary executionBoundary,
            IServiceBoundaryInitializer initializer)
        {
            _executionBoundary = executionBoundary ?? throw new ArgumentNullException(nameof(executionBoundary));
            _initializer = initializer ?? throw new ArgumentNullException(nameof(initializer));
        }

        public async Task InitializeAsync(CancellationToken cancellationToken)
        {
            _executionBoundary.DemandAuthorizedServiceProcess();
            await _initializer.InitializeAsync(cancellationToken).ConfigureAwait(false);
        }

        public Task ShutdownAsync(CancellationToken cancellationToken)
        {
            return _initializer.ShutdownAsync(cancellationToken);
        }
    }

    internal sealed class GuardServiceWorker : IHostedService
    {
        private readonly GuardServiceRuntime _runtime;

        public GuardServiceWorker(GuardServiceRuntime runtime)
        {
            _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            return _runtime.InitializeAsync(cancellationToken);
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            return _runtime.ShutdownAsync(cancellationToken);
        }
    }

}
