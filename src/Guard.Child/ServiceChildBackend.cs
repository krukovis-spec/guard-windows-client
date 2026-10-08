using Guard.Contracts;
using Guard.Windows.Ipc;

namespace Guard.Child;

internal sealed class ServiceChildBackend : IChildBackend
{
    public Task<GuardIpcResponse> ReadAsync(CancellationToken token) => GuardChildClient.GetBlockedApplicationsAsync(token);
    public Task<GuardIpcResponse> RequestAsync(CreateApplicationRequestPayload request, CancellationToken token)
        => GuardChildClient.CreateApplicationRequestAsync(request, token);
}
