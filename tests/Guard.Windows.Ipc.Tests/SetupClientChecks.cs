using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Guard.Windows.Ipc;
using Guard.Contracts;
using Guard.Protocol;
using Guard.Windows.Services;

namespace Guard.Windows.Ipc.Tests;

internal static class SetupClientChecks
{
    public static void ReadIdentificationToken() => ReadIdentificationTokenAsync().GetAwaiter().GetResult();

    private static async Task ReadIdentificationTokenAsync()
    {
        // A private, current-user-only TEST pipe; never the installed Guard endpoint.
        var name = "GuardTests-" + Guid.NewGuid().ToString("N");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var identity = WindowsIdentity.GetCurrent();
        var security = new PipeSecurity();
        security.SetOwner(identity.User!);
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new PipeAccessRule(identity.User!,
            (PipeAccessRights)NamedPipeSecurityDescriptorFactory.PipeClientReadWriteMaskWithoutCreateInstance,
            AccessControlType.Allow));
        using var server = NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, security);
        using var client = GuardSetupQueryClient.CreatePipe(name);
        var accept = server.WaitForConnectionAsync(deadline.Token);
        await client.ConnectAsync(deadline.Token);
        await accept;
        var facts = new WindowsPipeClientTokenFactsResolver().Resolve(server);
        if (facts.UserSid != identity.User!.Value)
            throw new InvalidOperationException("Pipe token did not identify the connecting user.");
        if (!GuardSetupQueryClient.ReadPipeOwner(client).Equals(identity.User) ||
            GuardSetupQueryClient.ReadServerProcessId(client) != (uint)Environment.ProcessId)
            throw new InvalidOperationException("Native pipe owner/PID lookup disagreed with the test server.");
        server.RunAsClient(() =>
        {
            using var token = WindowsIdentity.GetCurrent();
            if (token.ImpersonationLevel != TokenImpersonationLevel.Identification)
                throw new InvalidOperationException("Setup exposed an impersonation-capable token.");
        });
    }

    public static void RejectWrongServiceBinding()
    {
        const string path = @"C:\Program Files\Guard\Guard.Service.exe";
        const uint pid = 1234;
        var good = new ScmServiceConfiguration(2, false, "LocalSystem", "\"" + path + "\"");
        var running = new ScmServiceProcessStatus(0x10, 4, pid);
        GuardSetupQueryClient.DemandServiceBinding(good, running, pid, true, path, path);
        foreach (var status in new[] {
            running with { ProcessId = pid + 1 }, running with { ProcessId = 0 },
            running with { ServiceType = 0x20 }, running with { ServiceType = 0x110 },
            running with { State = 1 }, running with { State = 2 }, running with { State = 3 },
            running with { State = 7 } })
            Refuses(() => GuardSetupQueryClient.DemandServiceBinding(good, status, pid, true, path, path));
        foreach (var config in new[] {
            new ScmServiceConfiguration(3, false, "LocalSystem", good.BinaryPath),
            new ScmServiceConfiguration(2, true, "LocalSystem", good.BinaryPath),
            new ScmServiceConfiguration(2, false, "LocalService", good.BinaryPath),
            new ScmServiceConfiguration(2, false, null, good.BinaryPath),
            new ScmServiceConfiguration(2, false, "LocalSystem", path),
            new ScmServiceConfiguration(2, false, "LocalSystem", good.BinaryPath + " --initialize-authoritative-state"),
            new ScmServiceConfiguration(2, false, "LocalSystem", "\"C:\\Other\\Guard.Service.exe\""),
            new ScmServiceConfiguration(2, false, "LocalSystem", null) })
            Refuses(() => GuardSetupQueryClient.DemandServiceBinding(config, running, pid, true, path, path));
        Refuses(() => GuardSetupQueryClient.DemandServiceBinding(good, running, pid, false, path, path));
        Refuses(() => GuardSetupQueryClient.DemandServiceBinding(good, running, 0, true, path, path));
        Refuses(() => GuardSetupQueryClient.DemandServiceBinding(good, running, pid, true, path + ".old", path));
        Refuses(() => GuardSetupQueryClient.QueryAsync(GuardVerb.BeginSetup, CancellationToken.None).GetAwaiter().GetResult());
        using var process = Process.GetCurrentProcess();
        using var token = WindowsIdentity.GetCurrent();
        if (token.IsSystem) throw new InvalidOperationException("Run these safe tests as an ordinary user, not SYSTEM.");
        using var spoofedService = new ClaimedService((uint)process.Id);
        // Exercise the actual process handle/image/token PInvokes, with no SCM write
        // or service launch. Fake SCM assertions cannot turn this user process into SYSTEM.
        Refuses(() => GuardSetupQueryClient.DemandServer(spoofedService, process.SafeHandle, (uint)process.Id));
    }

    public static void CheckResponses() => CheckResponsesAsync().GetAwaiter().GetResult();

    private static async Task CheckResponsesAsync()
    {
        for (var variant = 0; variant < 7; variant++)
        {
            var name = "GuardTests-" + Guid.NewGuid().ToString("N");
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            using var client = GuardSetupQueryClient.CreatePipe(name);
            var accept = server.WaitForConnectionAsync(deadline.Token);
            await client.ConnectAsync(deadline.Token);
            await accept;
            var request = new GuardIpcRequest(GuardProtocol.CurrentVersion, Guid.NewGuid().ToString("D"),
                GuardVerb.GetDeviceProvisioning, Array.Empty<byte>());
            using var exchangeCancellation = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            var exchange = GuardSetupQueryClient.ExchangeAsync(client, request, exchangeCancellation.Token);
            var decoded = await IpcFrameCodec.DecodeAsync(server, TimeSpan.FromSeconds(5), deadline.Token);
            if (decoded.Verb != request.Verb || decoded.PayloadLength != 0 || decoded.RequestId != request.RequestId)
                throw new InvalidOperationException("Setup query changed in transit.");
            var frame = IpcResponseFrameCodec.Encode(new GuardIpcResponse(GuardProtocol.CurrentVersion,
                variant == 1 ? Guid.NewGuid().ToString("D") : request.RequestId,
                GuardIpcResponseStatus.Unavailable,
                variant == 6 ? new byte[GuardProtocol.MaximumFrameBytes] : Array.Empty<byte>()));
            if (variant == 2) frame[7] = 99; // unsupported version
            if (variant == 3) frame = frame[..^1]; // truncated header
            if (variant == 4) frame = new byte[GuardProtocol.MaximumFrameBytes + 53];
            if (variant == 5)
            {
                await server.WriteAsync(frame.AsMemory(0, 1), deadline.Token);
                exchangeCancellation.Cancel(); // partial response cannot bypass the caller deadline
            }
            else
            {
                // Fragmentation must not alter the frame decoder's bounds/correlation.
                await server.WriteAsync(frame.AsMemory(0, 1), deadline.Token);
                await server.WriteAsync(frame.AsMemory(1), deadline.Token);
                server.Disconnect(); // same end-of-request sequence as GuardPipeEndpointHost
            }
            try
            {
                var response = await exchange;
                if ((variant != 0 && variant != 6) || response.Status != GuardIpcResponseStatus.Unavailable ||
                    response.PayloadLength != (variant == 6 ? GuardProtocol.MaximumFrameBytes : 0))
                    throw new InvalidOperationException("An invalid response was accepted or an error became success.");
            }
            catch (InvalidDataException) when (variant is >= 1 and <= 4) { }
            catch (OperationCanceledException) when (variant == 5 && !deadline.IsCancellationRequested) { }
        }
    }

    private static void Refuses(Action action)
    {
        try { action(); }
        catch (UnauthorizedAccessException) { return; }
        catch (ArgumentOutOfRangeException) { return; }
        throw new InvalidOperationException("An untrusted setup operation was accepted.");
    }

    private sealed class ClaimedService(uint pid) : IScmQuerySession
    {
        public ScmServiceConfiguration ReadConfiguration() => new(2, false, "LocalSystem",
            "\"" + GuardServiceIdentity.ExpectedBinaryPath + "\"");
        public ScmServiceProcessStatus ReadProcessStatus() => new(0x10, 4, pid);
        public uint ReadCurrentState() => 4;
        public void Dispose() { }
    }
}
