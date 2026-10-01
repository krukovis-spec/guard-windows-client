using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;

namespace Guard.Service;

// Started after the authorized service boundary; stopped/drained before its keys and writer lease.
internal sealed class NativeEnrollmentDeliveryWorker(ServiceExecutionBoundary boundary, ServiceStartupOptions options,
    Func<CancellationToken, Task<bool>> deliver, ServiceExitStatus exitStatus, IHostApplicationLifetime lifetime,
    Func<TimeSpan, CancellationToken, Task>? delay = null) : IHostedService, IDisposable
{
    private readonly CancellationTokenSource _stop = new();
    private readonly Func<TimeSpan, CancellationToken, Task> _delay = delay ?? Task.Delay;
    private Task? _run;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        boundary.DemandAuthorizedServiceProcess();
        if (options.InitializeAuthoritativeState || options.ImportDeviceRelayProfile) return Task.CompletedTask;
        if (_run != null) throw new InvalidOperationException("Enrollment delivery already started.");
        _run = Task.Run(() => RunAsync(_stop.Token));
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _stop.Cancel();
        // Do not release the service writer/key lifetime while a cancelled HTTP pass is still unwinding.
        if (_run != null) await _run.ConfigureAwait(false);
    }

    private async Task RunAsync(CancellationToken token)
    {
        var failures = 0;
        try
        {
            while (!token.IsCancellationRequested)
            {
                TimeSpan wait;
                try
                {
                    var processed = await deliver(token).ConfigureAwait(false);
                    failures = 0;
                    wait = TimeSpan.FromSeconds(processed ? 2 : 10);
                }
                catch (HttpRequestException)
                { wait = Backoff(ref failures); }
                catch (OperationCanceledException) when (!token.IsCancellationRequested)
                { wait = Backoff(ref failures); } // One bounded pass timed out; shutdown is not a retry.
                await _delay(wait, token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch
        {
            // Storage/identity/integrity failures are not an offline success. Never log raw exceptions.
            exitStatus.MarkFatalRuntimeFailure();
            lifetime.StopApplication();
        }
    }

    private static TimeSpan Backoff(ref int failures) =>
        TimeSpan.FromSeconds(Math.Min(30, 1 << (failures = Math.Min(failures + 1, 5))));

    public void Dispose() => _stop.Dispose();
}
