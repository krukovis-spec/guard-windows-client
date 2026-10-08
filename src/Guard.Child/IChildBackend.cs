using Guard.Contracts;

namespace Guard.Child;

internal interface IChildBackend
{
    Task<GuardIpcResponse> ReadAsync(CancellationToken token);
    Task<GuardIpcResponse> RequestAsync(CreateApplicationRequestPayload request, CancellationToken token);
}
