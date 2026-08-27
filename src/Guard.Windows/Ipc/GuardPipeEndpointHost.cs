using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;

namespace Guard.Windows.Ipc
{
    public sealed class GuardPipeEndpointHost : IAsyncDisposable
    {
        private readonly object _sync = new object();
        private readonly GuardPipeSecurityProfile _profile;
        private readonly WindowsNamedPipeFactory _pipeFactory;
        private readonly GuardPipeConnectionProcessor _connectionProcessor;
        private CancellationTokenSource? _stopSource;
        private NamedPipeServerStream? _currentListener;
        private NamedPipeServerStream? _standbyListener;
        private Task? _runTask;

        public GuardPipeEndpointHost(
            GuardPipeSecurityProfile profile,
            WindowsNamedPipeFactory pipeFactory,
            GuardPipeConnectionProcessor connectionProcessor)
        {
            _profile = profile ?? throw new ArgumentNullException(nameof(profile));
            _pipeFactory = pipeFactory ?? throw new ArgumentNullException(nameof(pipeFactory));
            _connectionProcessor = connectionProcessor ?? throw new ArgumentNullException(nameof(connectionProcessor));
        }

        public Task Completion
        {
            get
            {
                lock (_sync)
                {
                    return _runTask ?? Task.CompletedTask;
                }
            }
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_sync)
            {
                if (_runTask != null)
                {
                    throw new InvalidOperationException("The pipe endpoint is already started.");
                }

                var listener = _pipeFactory.Create(_profile, firstInstance: true);
                _stopSource = new CancellationTokenSource();
                _currentListener = listener;
                _runTask = RunAsync(listener, _stopSource.Token);
            }

            return Task.CompletedTask;
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            Task? runTask;
            lock (_sync)
            {
                _stopSource?.Cancel();
                _currentListener?.Dispose();
                _standbyListener?.Dispose();
                runTask = _runTask;
            }

            try
            {
                if (runTask != null)
                {
                    try
                    {
                        // Once stop begins, resource ordering is security
                        // critical: do not let the caller's timeout detach an
                        // in-flight dispatcher from the writer lease. Closing
                        // both listeners and cancelling the endpoint token
                        // makes the run task responsible for draining fully.
                        await runTask.ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (
                        _stopSource?.IsCancellationRequested == true)
                    {
                    }
                    catch (ObjectDisposedException)
                    {
                    }
                    catch (IOException) when (_stopSource?.IsCancellationRequested == true)
                    {
                    }
                }
            }
            finally
            {
                lock (_sync)
                {
                    _currentListener = null;
                    _standbyListener = null;
                    _runTask = null;
                    _stopSource?.Dispose();
                    _stopSource = null;
                }
            }
        }

        public async ValueTask DisposeAsync()
        {
            await StopAsync(CancellationToken.None).ConfigureAwait(false);
        }

        private async Task RunAsync(
            NamedPipeServerStream initialListener,
            CancellationToken cancellationToken)
        {
            var listener = initialListener;
            while (!cancellationToken.IsCancellationRequested)
            {
                NamedPipeServerStream? nextListener = null;
                try
                {
                    await listener.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();

                    // Keep the pipe namespace continuously anchored. The next
                    // listener is created while the accepted instance still
                    // exists, so a client never gets an unowned-name window.
                    // Client ACLs deliberately exclude FILE_CREATE_PIPE_INSTANCE.
                    nextListener = _pipeFactory.Create(
                        _profile,
                        firstInstance: false);
                    lock (_sync)
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            nextListener.Dispose();
                            nextListener = null;
                        }
                        else
                        {
                            _standbyListener = nextListener;
                        }
                    }

                    cancellationToken.ThrowIfCancellationRequested();
                    await _connectionProcessor
                        .ProcessOneAsync(_profile, listener, cancellationToken)
                        .ConfigureAwait(false);
                }
                finally
                {
                    try
                    {
                        if (listener.IsConnected)
                        {
                            listener.Disconnect();
                        }
                    }
                    catch (IOException)
                    {
                    }
                    catch (InvalidOperationException)
                    {
                    }

                    listener.Dispose();
                }

                cancellationToken.ThrowIfCancellationRequested();
                lock (_sync)
                {
                    listener = nextListener ?? throw new InvalidOperationException(
                        "The named-pipe standby listener was not created.");
                    _currentListener = listener;
                    _standbyListener = null;
                }
            }
        }
    }
}
