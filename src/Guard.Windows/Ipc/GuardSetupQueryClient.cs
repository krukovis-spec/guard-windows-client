using System;
using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Protocol;
using Guard.Windows.Services;
using Microsoft.Win32.SafeHandles;

namespace Guard.Windows.Ipc;

/// <summary>Authenticated setup IPC. Requires a trusted installation; not an administrator-tamper boundary.</summary>
public static class GuardSetupQueryClient
{
    public static Task<GuardIpcResponse> QueryAsync(GuardVerb verb, CancellationToken cancellationToken)
    {
        if (verb != GuardVerb.GetStatus && verb != GuardVerb.GetReadiness && verb != GuardVerb.GetDeviceProvisioning)
            throw new ArgumentOutOfRangeException(nameof(verb));
        return SendAsync(new GuardIpcRequest(GuardProtocol.CurrentVersion, Guid.NewGuid().ToString("D"), verb, Array.Empty<byte>()),
            GuardProtocol.DefaultIpcReadTimeoutMilliseconds, cancellationToken);
    }

    // Retain the session capability privately; never auto-confirm a returned claim hash.
    public static Task<GuardIpcResponse> NativeSetupAsync(GuardVerb verb, byte[] payload, CancellationToken cancellationToken)
    {
        if (verb != GuardVerb.BeginNativeSetup && verb != GuardVerb.AdvanceNativeSetup &&
            verb != GuardVerb.ConfirmNativeSetup && verb != GuardVerb.CancelNativeSetup && verb != GuardVerb.GetNativeSetupResult)
            throw new ArgumentOutOfRangeException(nameof(verb));
        ArgumentNullException.ThrowIfNull(payload);
        if (payload.Length > 512 || (verb == GuardVerb.BeginNativeSetup ? payload.Length != 0 : payload.Length == 0))
            throw new ArgumentException("Invalid native setup payload size.", nameof(payload));
        return SendAsync(new GuardIpcRequest(GuardProtocol.CurrentVersion, Guid.NewGuid().ToString("D"), verb, payload),
            GuardProtocol.MaximumIpcReadTimeoutMilliseconds, cancellationToken);
    }

    private static async Task<GuardIpcResponse> SendAsync(GuardIpcRequest request, int timeoutMilliseconds, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeoutMilliseconds);
        var token = deadline.Token;
        using var pipe = CreatePipe("Guard.V2.AdminSetup.v1");
        await pipe.ConnectAsync(token).ConfigureAwait(false);

        // A name or PID alone does not authenticate a service. In particular, an
        // unprivileged name squatter must not lend us a recycled server PID.
        if (!ReadPipeOwner(pipe).IsWellKnown(WellKnownSidType.LocalSystemSid))
            throw new UnauthorizedAccessException("The setup pipe is not owned by SYSTEM.");
        var processId = ReadServerProcessId(pipe);
        var opened = new WindowsScmNativeApi().OpenForQuery(GuardServiceIdentity.ServiceName);
        using var service = opened.Session;
        if (opened.State != ScmServiceOpenState.Found || service == null)
            throw new UnauthorizedAccessException("The installed Guard service is unavailable.");
        using var process = OpenProcess(0x00101000, false, processId); // QUERY_LIMITED_INFORMATION | SYNCHRONIZE
        if (process.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        DemandServer(service, process, processId);
        if (ReadServerProcessId(pipe) != processId)
            throw new UnauthorizedAccessException("The pipe server changed during authentication.");
        token.ThrowIfCancellationRequested();

        var response = await ExchangeAsync(pipe, request, token).ConfigureAwait(false);
        // Keep the original process handle until acceptance: exit/PID reuse or
        // a service restart invalidates this response, including a buffered one.
        DemandServer(service, process, processId);
        token.ThrowIfCancellationRequested();
        return response;
    }

    internal static NamedPipeClientStream CreatePipe(string name) => new(".", name,
        (PipeAccessRights)NamedPipeSecurityDescriptorFactory.PipeClientReadWriteMaskWithoutCreateInstance,
        PipeOptions.Asynchronous, TokenImpersonationLevel.Identification, HandleInheritability.None);

    internal static SecurityIdentifier ReadPipeOwner(NamedPipeClientStream pipe)
        => (SecurityIdentifier)(pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier))
            ?? throw new UnauthorizedAccessException("The pipe owner is unavailable."));

    internal static uint ReadServerProcessId(NamedPipeClientStream pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var pid))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if (pid == 0) throw new UnauthorizedAccessException("The pipe server PID is unavailable.");
        return pid;
    }

    internal static void DemandServer(IScmQuerySession service, SafeProcessHandle process, uint processId)
    {
        if (WaitForSingleObject(process, 0) != 258) // WAIT_TIMEOUT means still alive; errors also refuse.
            throw new UnauthorizedAccessException("The authenticated service process has exited.");
        var imagePath = new StringBuilder(32768);
        var length = imagePath.Capacity;
        if (!QueryFullProcessImageName(process, 0, imagePath, ref length))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if (!OpenProcessToken(process, 8, out var accessToken)) // TOKEN_QUERY only
            throw new Win32Exception(Marshal.GetLastWin32Error());
        using (accessToken)
        using (var identity = new WindowsIdentity(accessToken.DangerousGetHandle()))
            DemandServiceBinding(service.ReadConfiguration(), service.ReadProcessStatus(), processId,
                identity.IsSystem, imagePath.ToString(), GuardServiceIdentity.ExpectedBinaryPath);
    }

    internal static void DemandServiceBinding(ScmServiceConfiguration config, ScmServiceProcessStatus status,
        uint pipeProcessId, bool processIsSystem, string imagePath, string expectedPath)
    {
        // Only the normal, argument-free own-process service is a setup authority.
        // Installer one-shot flags must be removed from SCM before querying.
        if (pipeProcessId == 0 || status.ProcessId != pipeProcessId || status.State != 4 || status.ServiceType != 0x10 ||
            config.StartType != 2 || config.DelayedAutoStart || !processIsSystem ||
            !string.Equals(config.AccountName, "LocalSystem", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(config.BinaryPath, "\"" + expectedPath + "\"", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(imagePath, expectedPath, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("The pipe is not bound to the expected running Guard service.");
    }

    internal static async Task<GuardIpcResponse> ExchangeAsync(Stream pipe, GuardIpcRequest request, CancellationToken token)
    {
        var frame = IpcFrameCodec.Encode(request);
        try { await pipe.WriteAsync(frame, token).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(frame); }
        await pipe.FlushAsync(token).ConfigureAwait(false);
        // The service handles exactly one frame, then closes this connection.
        // One extra byte detects overflow, without an unbounded CopyToAsync.
        var bytes = new byte[GuardProtocol.MaximumFrameBytes + 53];
        var count = 0;
        while (count < bytes.Length)
        {
            var read = await pipe.ReadAsync(bytes.AsMemory(count), token).ConfigureAwait(false);
            if (read == 0) break;
            count += read;
        }
        var response = IpcResponseFrameCodec.Decode(bytes.AsSpan(0, count).ToArray());
        if (!string.Equals(response.RequestId, request.RequestId, StringComparison.Ordinal))
            throw new InvalidDataException("The setup response belongs to another request.");
        return response;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder path, ref int size);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
}
