using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;

namespace Guard.Service
{
    internal interface IServicePipeEndpointHost
    {
        Task Completion { get; }

        Task StartAsync(CancellationToken cancellationToken);

        Task StopAsync(CancellationToken cancellationToken);
    }

    internal interface IServicePipeEndpointHostFactory
    {
        IServicePipeEndpointHost Create(ServicePipeEndpoint endpoint);
    }

    internal sealed class ServicePipeSupervisor : IServicePipeSupervisor
    {
        private readonly IServicePipeEndpointHostFactory _hostFactory;
        private readonly ServiceExitStatus _exitStatus;
        private readonly IHostApplicationLifetime _applicationLifetime;
        private readonly List<IServicePipeEndpointHost> _hosts =
            new List<IServicePipeEndpointHost>();
        private CancellationTokenSource? _monitorStop;
        private Task? _monitorTask;
        private int _stopping;

        public ServicePipeSupervisor(
            IServicePipeEndpointHostFactory hostFactory,
            ServiceExitStatus exitStatus,
            IHostApplicationLifetime applicationLifetime)
        {
            _hostFactory = hostFactory ?? throw new ArgumentNullException(nameof(hostFactory));
            _exitStatus = exitStatus ?? throw new ArgumentNullException(nameof(exitStatus));
            _applicationLifetime = applicationLifetime ?? throw new ArgumentNullException(nameof(applicationLifetime));
        }

        public async Task StartAsync(
            IReadOnlyList<ServicePipeEndpoint> endpoints,
            CancellationToken cancellationToken)
        {
            if (endpoints == null || endpoints.Count == 0)
            {
                throw new ArgumentException("At least one restricted pipe endpoint is required.", nameof(endpoints));
            }

            if (_hosts.Count != 0)
            {
                throw new InvalidOperationException("The pipe supervisor is already started.");
            }

            Interlocked.Exchange(ref _stopping, 0);
            try
            {
                for (var index = 0; index < endpoints.Count; index++)
                {
                    var host = _hostFactory.Create(endpoints[index]);
                    await host.StartAsync(cancellationToken).ConfigureAwait(false);
                    _hosts.Add(host);
                }
            }
            catch
            {
                await StopHostsReverseAsync(CancellationToken.None).ConfigureAwait(false);
                throw;
            }

            _monitorStop = new CancellationTokenSource();
            _monitorTask = MonitorAsync(_monitorStop.Token);
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            Interlocked.Exchange(ref _stopping, 1);
            _monitorStop?.Cancel();
            await StopHostsReverseAsync(cancellationToken).ConfigureAwait(false);
            if (_monitorTask != null)
            {
                try
                {
                    await _monitorTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
            }

            _monitorStop?.Dispose();
            _monitorStop = null;
            _monitorTask = null;
        }

        private async Task MonitorAsync(CancellationToken cancellationToken)
        {
            var completions = new Task[_hosts.Count];
            for (var index = 0; index < _hosts.Count; index++)
            {
                completions[index] = _hosts[index].Completion;
            }

            var cancellationTask = Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            var all = new Task[completions.Length + 1];
            Array.Copy(completions, all, completions.Length);
            all[all.Length - 1] = cancellationTask;
            var completed = await Task.WhenAny(all).ConfigureAwait(false);
            if (ReferenceEquals(completed, cancellationTask) ||
                Volatile.Read(ref _stopping) != 0)
            {
                if (ReferenceEquals(completed, cancellationTask))
                {
                    await cancellationTask.ConfigureAwait(false);
                }

                return;
            }

            try
            {
                await completed.ConfigureAwait(false);
            }
            catch
            {
            }

            _exitStatus.MarkFatalRuntimeFailure();
            _applicationLifetime.StopApplication();
        }

        private async Task StopHostsReverseAsync(CancellationToken cancellationToken)
        {
            Exception? firstFailure = null;
            for (var index = _hosts.Count - 1; index >= 0; index--)
            {
                try
                {
                    await _hosts[index].StopAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    firstFailure ??= exception;
                }
            }

            _hosts.Clear();
            if (firstFailure != null)
            {
                throw firstFailure;
            }
        }
    }
}
