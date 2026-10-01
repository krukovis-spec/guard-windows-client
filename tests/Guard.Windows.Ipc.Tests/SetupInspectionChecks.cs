using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Domain;
using Guard.Protocol;
using Guard.Windows.Cryptography;
using Guard.Windows.Ipc;

namespace Guard.Windows.Ipc.Tests;

internal static class SetupInspectionChecks
{
    internal static void Run() => RunAsync().GetAwaiter().GetResult();
    private static async Task RunAsync()
    {
        var ready = GuardReadinessFactState.Satisfied;
        Task<GuardIpcResponse> Query(GuardVerb verb, CancellationToken token) => Task.FromResult(Reply(verb switch {
            GuardVerb.GetStatus => GuardStatusPayloadCodec.Encode(new GuardStatusPayload(0, false, false)),
            GuardVerb.GetReadiness => GuardReadinessPayloadCodec.Encode(Readiness(0, ready)),
            _ => throw new InvalidOperationException("inspection attempted a mutation or unsolicited export")
        }));
        var result = await SetupInspection.ReadAsync(Query, default);
        Check(result.CanExport && result.Readiness.CanEnableProtection, "initial export eligibility");
        Check(result.Lines.Any(line => line.Contains("Включение защиты этим не подтверждено")) &&
            SetupInspection.ProtectionNotice.Contains("Защита не подтверждена"), "readiness presented as protection");
        foreach (var state in Enum.GetValues<GuardReadinessFactState>())
        {
            var status = new GuardStatusPayload(4, true, true);
            var observed = await SetupInspection.ReadAsync((verb, _) => Task.FromResult(Reply(verb == GuardVerb.GetStatus
                ? GuardStatusPayloadCodec.Encode(status) : GuardReadinessPayloadCodec.Encode(Readiness(4, state)))), default);
            Check(!observed.CanExport && observed.Lines[0] == "Родитель: привязан", "ownership/export separation");
            if (state != ready) Check(!observed.Readiness.CanEnableProtection && observed.Lines.Last().StartsWith("Не все"), "unknown/error shown ready");
        }
        foreach (var responseStatus in Enum.GetValues<GuardIpcResponseStatus>().Where(s => s != GuardIpcResponseStatus.Success))
            await Reject(() => SetupInspection.ReadAsync((_, _) => Task.FromResult(Reply(GuardStatusPayloadCodec.Encode(new(0, false, false)), responseStatus)), default));
        await Reject(() => SetupInspection.ReadAsync((verb, _) => Task.FromResult(Reply(verb == GuardVerb.GetStatus
            ? GuardStatusPayloadCodec.Encode(new(0, false, false)) : GuardReadinessPayloadCodec.Encode(Readiness(1, ready)))), default));
        await Reject(() => SetupInspection.ReadAsync((_, _) => Task.FromResult(Reply(new byte[] { 1, 2, 3 })), default));
        await Reject(() => SetupInspection.ReadAsync((_, _) => Task.FromResult(new GuardIpcResponse(42, Guid.NewGuid().ToString("D"),
            GuardIpcResponseStatus.Success, GuardStatusPayloadCodec.Encode(new(0, false, false)))), default));
        using (var cancelled = new CancellationTokenSource())
        {
            cancelled.Cancel();
            await Reject(() => SetupInspection.ReadAsync((_, _) => throw new Exception("must not call cancelled query"), cancelled.Token));
        }
        using (var cancelled = new CancellationTokenSource())
            await Reject(() => SetupInspection.ReadAsync(async (verb, token) => { var response = await Query(verb, token); cancelled.Cancel(); return response; }, cancelled.Token));
        Check(!SetupInspection.DescribeFailure(new IOException("private-payload-value")).Contains("private-payload-value"), "error leaked payload");

        using var signing = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var encryption = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var signingKey = new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, signing.ExportSubjectPublicKeyInfo());
        var encryptionKey = new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, encryption.ExportSubjectPublicKeyInfo());
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new { version = 1, relayOrigin = "https://relay.example.test",
            deviceId = "device-setup-inspection-001", signingKeyId = signingKey.KeyId,
            signingPublicKeySpki = Convert.ToBase64String(signing.ExportSubjectPublicKeyInfo()), encryptionKeyId = encryptionKey.KeyId,
            encryptionPublicKeySpki = Convert.ToBase64String(encryption.ExportSubjectPublicKeyInfo()), deviceEpoch = 1, authorityEpoch = 1 });
        var descriptor = await SetupInspection.ReadDescriptorAsync((verb, _) => {
            Check(verb == GuardVerb.GetDeviceProvisioning, "wrong export query"); return Task.FromResult(Reply(bytes));
        }, default);
        var digest = Convert.ToHexString(SHA256.HashData(bytes));
        Check(descriptor.Sha256 == digest && descriptor.DeviceId == "device-setup-inspection-001", "export digest/identity");
        descriptor.GetBytesCopy()[0] = 0; descriptor.GetEncryptionKeyCopy()[0] = 0;
        var parsed = DeviceProvisioningDescriptor.Parse(bytes); var originalFirst = bytes[0]; bytes[0] = 0;
        Check(parsed.GetBytesCopy()[0] == originalFirst && descriptor.GetBytesCopy()[0] == originalFirst &&
            descriptor.GetEncryptionKeyCopy().SequenceEqual(encryption.ExportSubjectPublicKeyInfo()), "descriptor retained mutable caller bytes");
        bytes[0] = originalFirst;
        foreach (var field in new[] { "version", "deviceId", "relayOrigin", "signingPublicKeySpki", "encryptionKeyId", "deviceEpoch", "authorityEpoch", "unexpected" })
        {
            var bad = JsonNode.Parse(bytes)!.AsObject();
            if (field is "version" or "deviceEpoch" or "authorityEpoch") bad[field] = 2;
            else bad[field] = "invalid";
            await Reject(() => Task.FromResult(DeviceProvisioningDescriptor.Parse(JsonSerializer.SerializeToUtf8Bytes(bad))));
            var missing = JsonNode.Parse(bytes)!.AsObject();
            if (field != "unexpected") { missing.Remove(field); await Reject(() => Task.FromResult(DeviceProvisioningDescriptor.Parse(JsonSerializer.SerializeToUtf8Bytes(missing)))); }
        }
        foreach (var badBytes in new[] { Array.Empty<byte>(), new byte[2049], Encoding.UTF8.GetBytes("[]"),
            Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(bytes).Replace("\"version\":1", "\"version\":1,\"version\":1")) })
            await Reject(() => Task.FromResult(DeviceProvisioningDescriptor.Parse(badBytes)));
        var overlap = JsonNode.Parse(bytes)!.AsObject();
        overlap["encryptionKeyId"] = signingKey.KeyId; overlap["encryptionPublicKeySpki"] = Convert.ToBase64String(signing.ExportSubjectPublicKeyInfo());
        await Reject(() => Task.FromResult(DeviceProvisioningDescriptor.Parse(JsonSerializer.SerializeToUtf8Bytes(overlap))));
        foreach (var badOrigin in new[] { "http://relay.example.test", "https://relay.example.test/path", "https://relay.example.test/" })
        {
            var bad = JsonNode.Parse(bytes)!.AsObject(); bad["relayOrigin"] = badOrigin;
            await Reject(() => Task.FromResult(DeviceProvisioningDescriptor.Parse(JsonSerializer.SerializeToUtf8Bytes(bad))));
        }
        await Reject(() => SetupInspection.ReadDescriptorAsync((_, _) => Task.FromResult(Reply(bytes, GuardIpcResponseStatus.Unavailable)), default));
        var root = Path.Combine(Path.GetTempPath(), "GuardSetupExportTests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "device.json"); descriptor.SaveNew(path);
            Check(File.ReadAllBytes(path).SequenceEqual(bytes), "export changed exact bytes");
            foreach (var refused in new[] { path, "relative.json", path + ":stream", Path.Combine(root, "trailing. "), @"\\localhost\share\device.json" })
                await Reject(() => { descriptor.SaveNew(refused); return Task.CompletedTask; });
            Check(File.ReadAllBytes(path).SequenceEqual(bytes) && Directory.GetFiles(root).Length == 1, "export overwrote or created refused path");
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static GuardReadinessPayload Readiness(long version, GuardReadinessFactState state)
    {
        var ready = state == GuardReadinessFactState.Satisfied;
        var codes = ready ? new[] { GuardReadinessFindingCodes.WindowsEditionReady, GuardReadinessFindingCodes.ChildAccountReady,
            GuardReadinessFindingCodes.SeparateLocalAdministratorReady, GuardReadinessFindingCodes.SecureBootReady,
            GuardReadinessFindingCodes.BitLockerReady, GuardReadinessFindingCodes.ServiceBoundaryReady,
            GuardReadinessFindingCodes.ProgramDataAclReady, GuardReadinessFindingCodes.SupportedManagedBrowserReady }
            : new[] { GuardReadinessFindingCodes.WindowsEditionBlocking, GuardReadinessFindingCodes.ChildAccountBlocking,
            GuardReadinessFindingCodes.SeparateLocalAdministratorBlocking, GuardReadinessFindingCodes.SecureBootBlocking,
            GuardReadinessFindingCodes.BitLockerBlocking, GuardReadinessFindingCodes.ServiceBoundaryBlocking,
            GuardReadinessFindingCodes.ProgramDataAclBlocking, GuardReadinessFindingCodes.SupportedManagedBrowserBlocking };
        return new GuardReadinessPayload(version, DateTimeOffset.UtcNow, state, state, state, state, state, state, state, state,
            ready ? 2 : 0, ready, codes.Select(code => new GuardReadinessFindingPayload(code,
                ready ? GuardReadinessFindingSeverity.Ready : GuardReadinessFindingSeverity.Blocking)).ToArray());
    }
    private static GuardIpcResponse Reply(byte[] payload, GuardIpcResponseStatus status = GuardIpcResponseStatus.Success) => new(
        GuardProtocol.CurrentVersion, Guid.NewGuid().ToString("D"), status, payload);
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static async Task Reject(Func<Task> action, [System.Runtime.CompilerServices.CallerLineNumber] int line = 0)
    {
        try { await action(); }
        catch (Exception e) when (e is IOException or InvalidDataException or ArgumentException or FormatException or InvalidOperationException or JsonException or OperationCanceledException) { return; }
        throw new Exception("Expected setup refusal at check line " + line);
    }
}
