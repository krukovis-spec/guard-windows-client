using System;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Protocol;

namespace Guard.Windows.Ipc;

public static class GuardChildClient
{
    public static Task<GuardIpcResponse> GetBlockedApplicationsAsync(CancellationToken token)
        => SendAsync(GuardVerb.GetBlockedApplications, Array.Empty<byte>(), token);

    public static Task<GuardIpcResponse> CreateApplicationRequestAsync(CreateApplicationRequestPayload request, CancellationToken token)
        => SendAsync(GuardVerb.CreateApplicationRequest, ApplicationRequestPayloadCodec.Encode(request), token);

    private static Task<GuardIpcResponse> SendAsync(GuardVerb verb, byte[] payload, CancellationToken token)
        => GuardSetupQueryClient.SendAuthenticatedAsync("Guard.V2.Child.v1",
            new GuardIpcRequest(GuardProtocol.CurrentVersion, Guid.NewGuid().ToString("D"), verb, payload),
            GuardProtocol.MaximumIpcReadTimeoutMilliseconds, token);
}
