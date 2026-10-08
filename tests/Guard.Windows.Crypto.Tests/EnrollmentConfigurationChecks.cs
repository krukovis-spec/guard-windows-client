using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Contracts.Relay;
using Guard.Application;
using Guard.Application.Readiness;
using Guard.Domain;
using Guard.Domain.Readiness;
using Guard.Protocol;
using Guard.Protocol.Relay;
using Guard.Service;
using Guard.Storage;
using Guard.Windows.Cryptography;
using Guard.Windows.Ipc;
using Guard.Windows.Storage;

namespace Guard.Windows.Crypto.Tests;

internal static class EnrollmentConfigurationChecks
{
    private const string Origin = "https://relay.example.test";
    private const string Credential = "synthetic-device-credential-not-for-production";
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeMilliseconds(1790812800000);
    internal static void Run() => RunAsync().GetAwaiter().GetResult();
    private static async Task RunAsync()
    {
        var signer = new string('A', 64);
        var trust = new EnrollmentDeploymentTrust(Origin, signer, 1);
        var metadata = new[] { new AssemblyMetadataAttribute("Guard.Enrollment.RelayOrigin", Origin),
            new AssemblyMetadataAttribute("Guard.Enrollment.AndroidSignerSha256", signer),
            new AssemblyMetadataAttribute("Guard.Enrollment.MinimumAndroidVersion", "1") };
        Check(EnrollmentDeploymentTrust.FromMetadata(metadata).Origin == trust.Origin, "release metadata mapping");
        foreach (var bad in new[] { Array.Empty<AssemblyMetadataAttribute>(), metadata[..2], metadata.Concat(metadata[..1]).ToArray(),
            metadata.Concat(new[] { new AssemblyMetadataAttribute("Guard.Enrollment.Unknown", "x") }).ToArray(),
            new[] { metadata[0], metadata[1], new AssemblyMetadataAttribute(metadata[2].Key, "01") } })
            Throws(() => EnrollmentDeploymentTrust.FromMetadata(bad));
        // Default builds intentionally have no release authority; environment/appsettings cannot supply it.
        Throws(() => EnrollmentDeploymentTrust.FromServiceAssembly());
        foreach (var origin in new[] { "http://relay.example.test", Origin + "/", Origin + "/path", Origin + ":443",
            "https://RELAY.example.test", "https://user@relay.example.test", Origin + ".", "https://127.0.0.1", Origin + "?x=1" })
            Throws(() => new EnrollmentDeploymentTrust(origin, signer, 1));
        Throws(() => new EnrollmentDeploymentTrust(Origin, new string('0', 64), 1));
        Throws(() => new EnrollmentDeploymentTrust(Origin, signer, 0));

        var root = Path.Combine(Path.GetTempPath(), "GuardConfigurationTests-" + Guid.NewGuid().ToString("N"));
        var paths = new GuardDataPaths(root);
        Directory.CreateDirectory(paths.RootDirectory);
        try
        {
            await CheckColdImportAsync(root, trust);
            var guard = new TestGuard();
            var identityStore = new DeviceIdentityStore(paths, new LocalSystemDpapiDataProtector(DeviceIdentityStore.Purpose, true), guard);
            using var boundary = new ServiceAuthoritativeStateBoundary(paths,
                new LocalSystemDpapiDataProtector(LocalSystemDpapiDataProtector.DefaultPurpose, true), guard, identityStore,
                () => DeviceIdentityChecks.OpenRelay(paths));
            var protector = new LocalSystemDpapiDataProtector(DeviceRelayConfigurationStore.Purpose, true);
            var store = new DeviceRelayConfigurationStore(paths, protector, guard);
            await boundary.AcquireAsync(default); await boundary.InitializeNewAsync(default);
            var state = await boundary.LoadAsync(default); var identity = boundary.Identity;
            var publicRequest = new GuardIpcRequest(GuardProtocol.CurrentVersion, Guid.NewGuid().ToString("D"),
                GuardVerb.GetDeviceProvisioning, Array.Empty<byte>());
            var publicHandler = Handler(boundary, trust);
            var dispatcher = new SecureIpcRequestDispatcher(publicHandler);
            var beforeExport = File.ReadAllBytes(paths.StateFile);
            using (var frame = new MemoryStream(IpcFrameCodec.Encode(publicRequest)))
            {
                var decoded = await IpcFrameCodec.DecodeAsync(frame, TimeSpan.FromSeconds(5), default);
                var response = await dispatcher.DispatchAsync(ClientRole.AdminSetup, decoded, default);
                Check(response.Status == GuardIpcResponseStatus.Success && response.RequestId == publicRequest.RequestId &&
                    response.PayloadLength <= 2048, "public provisioning IPC response");
                using var document = JsonDocument.Parse(response.GetPayloadCopy());
                var descriptor = document.RootElement;
                var fields = descriptor.EnumerateObject().Select(p => p.Name).OrderBy(p => p).ToArray();
                Check(fields.SequenceEqual(new[] { "version", "relayOrigin", "deviceId", "signingKeyId", "signingPublicKeySpki",
                    "encryptionKeyId", "encryptionPublicKeySpki", "deviceEpoch", "authorityEpoch" }.OrderBy(p => p)),
                    "public provisioning exposed unexpected fields");
                Check(descriptor.GetProperty("version").GetInt32() == 1 && descriptor.GetProperty("relayOrigin").GetString() == Origin &&
                    descriptor.GetProperty("deviceId").GetString() == identity.DeviceId &&
                    descriptor.GetProperty("signingKeyId").GetString() == identity.SigningKeyId &&
                    descriptor.GetProperty("encryptionKeyId").GetString() == identity.EncryptionKeyId &&
                    descriptor.GetProperty("deviceEpoch").GetInt64() == 1 && descriptor.GetProperty("authorityEpoch").GetInt64() == 1,
                    "public provisioning used unbound identifiers");
                Check(Convert.FromBase64String(descriptor.GetProperty("signingPublicKeySpki").GetString()!).SequenceEqual(identity.Signing.ExportSubjectPublicKeyInfo()) &&
                    Convert.FromBase64String(descriptor.GetProperty("encryptionPublicKeySpki").GetString()!).SequenceEqual(identity.Encryption.ExportSubjectPublicKeyInfo()),
                    "public provisioning did not return the distinct persistent PUBLIC keys");
            }
            Check(beforeExport.SequenceEqual(File.ReadAllBytes(paths.StateFile)) && !File.Exists(paths.DeviceRelayConfigurationFile),
                "public export changed state or installed a credential");
            guard.Check = () => throw new InvalidOperationException("unexpected storage access");
            foreach (var role in Enum.GetValues<ClientRole>().Where(r => r != ClientRole.AdminSetup))
            {
                var denied = await publicHandler.HandleAsync(role, publicRequest, default);
                Check(!IpcSecurityPolicy.CanInvoke(role, GuardVerb.GetDeviceProvisioning) &&
                    denied.Status == GuardIpcResponseStatus.Forbidden && denied.PayloadLength == 0, "non-admin public export");
            }
            var badRequest = new GuardIpcRequest(GuardProtocol.CurrentVersion, publicRequest.RequestId, publicRequest.Verb, new byte[] { 1 });
            Check((await publicHandler.HandleAsync(ClientRole.AdminSetup, badRequest, default)).Status == GuardIpcResponseStatus.InvalidRequest,
                "public export accepted caller-supplied identity");
            guard.Check = () => { };
            var noPins = await Handler(boundary, null).HandleAsync(ClientRole.AdminSetup, publicRequest, default);
            Check(noPins.Status == GuardIpcResponseStatus.Unavailable && noPins.PayloadLength == 0, "default build invented release authority");
            await ThrowsAsync(() => ServiceNativeEnrollment.OpenAsync(boundary, store, default));
            Check(!File.Exists(paths.DeviceRelayConfigurationFile), "missing pins caused config creation");
            var profile = Profile(identity);
            var raw = JsonSerializer.SerializeToUtf8Bytes(profile); var original = (byte[])raw.Clone();
            await store.InstallNewAsync(raw, trust, boundary, Now, default);
            Check(raw.SequenceEqual(original), "import mutated caller buffer");
            var ciphertext = File.ReadAllBytes(paths.DeviceRelayConfigurationFile);
            Check(!Encoding.UTF8.GetString(ciphertext).Contains(Credential, StringComparison.Ordinal), "plaintext credential on disk");
            await ThrowsAsync(() => store.InstallNewAsync(raw, trust, boundary, Now, default));
            Check(ciphertext.SequenceEqual(File.ReadAllBytes(paths.DeviceRelayConfigurationFile)), "repeat import overwrote config");
            var config = new DeviceRelayConfigurationStore(paths, protector, guard).Load(trust, identity, state, Now);
            await CheckNativeIpcAsync(boundary, config, trust);
            using var transport = config.CreateTransport(trust, identity, state, Now);
            using var runtime = ServiceNativeEnrollment.Create(boundary.NativeEnrollmentStore, identity, state, config, trust, new Clock());
            var offer = config.CreateOffer(trust, identity, state, "Lab PC", Now.AddTicks(1));
            Check(offer.CreatedAtUtc == Now && offer.ExpiresAtUtc == Now.AddMinutes(5) && offer.SigningKeyId == identity.SigningKeyId &&
                offer.EncryptionKeyId == identity.EncryptionKeyId && offer.MailboxId == "mailbox-configuration-test", "offer did not use trusted device profile");
            var (result, start) = await runtime.Coordinator.BeginAsync(ClientRole.AdminSetup, offer, default);
            using (start) Check(result == Guard.Application.SetupOperationStatus.Succeeded && start != null, "real coordinator did not accept locally constructed offer");
            var pending = await boundary.LoadAsync(default);
            var afterSetup = await dispatcher.DispatchAsync(ClientRole.AdminSetup, publicRequest, default);
            Check(afterSetup.Status == GuardIpcResponseStatus.Conflict && afterSetup.PayloadLength == 0,
                "setup exported a new provisioning request");
            _ = store.Load(trust, identity, pending, Now);
            await ThrowsAsync(() => store.InstallNewAsync(raw, trust, boundary, Now, default));
            Check(ciphertext.SequenceEqual(File.ReadAllBytes(paths.DeviceRelayConfigurationFile)), "setup import changed profile");

            var variants = new (string Field, object Value)[] {
                ("role", "admin"), ("version", 2), ("deviceId", "device-another-test"), ("signingKeyId", identity.EncryptionKeyId),
                ("encryptionKeyId", identity.SigningKeyId), ("mailboxId", "guard:bff:auth:v1"), ("mailboxId", "mailbox-another-test"),
                ("deviceEpoch", 2L), ("authorityEpoch", 2L), ("authorityEpoch", 9007199254740992L),
                ("relayOrigin", "https://other.example.test"), ("relayOrigin", Origin + "/"),
                ("accessToken", "too-short"), ("accessToken", Credential + "\r\nInjected: yes"),
                ("issuedAt", Now.AddSeconds(1).ToUnixTimeMilliseconds()), ("expiresAt", Now.ToUnixTimeMilliseconds()) };
            foreach (var variant in variants)
            {
                var value = Profile(identity); value[variant.Field] = variant.Value;
                var bad = JsonSerializer.SerializeToUtf8Bytes(value);
                File.WriteAllBytes(paths.DeviceRelayConfigurationFile, protector.Protect(bad));
                Throws(() => store.Load(trust, identity, pending, Now));
                CryptographicOperations.ZeroMemory(bad);
            }
            File.WriteAllBytes(paths.DeviceRelayConfigurationFile, ciphertext);
            Throws(() => store.Load(new EnrollmentDeploymentTrust("https://other.example.test", signer, 1), identity, pending, Now));
            Throws(() => store.Load(trust, identity, pending, Now.AddDays(3)));
            Throws(() => config.CreateOffer(trust, identity, state, "Lab", Now.AddDays(2).AddMinutes(-1)));
            var text = Encoding.UTF8.GetString(raw);
            foreach (var bad in new[] { Encoding.UTF8.GetBytes(text[..^1] + ",\"role\":\"device\"}"),
                Encoding.UTF8.GetBytes(text[..^1] + ",\"apkSignerSha256\":\"untrusted\"}"),
                raw[..^1], new byte[4097], new byte[] { 0xEF, 0xBB, 0xBF }.Concat(raw).ToArray() })
            { Throws(() => DeviceRelayConfiguration.Decode(bad)); CryptographicOperations.ZeroMemory(bad); }
            var wrongPurpose = new LocalSystemDpapiDataProtector(DeviceIdentityStore.Purpose, true).Protect(raw);
            File.WriteAllBytes(paths.DeviceRelayConfigurationFile, wrongPurpose);
            Throws(() => store.Load(trust, identity, pending, Now));
            File.Delete(paths.DeviceRelayConfigurationFile);
            Throws(() => store.Load(trust, identity, pending, Now));
            Check(!File.Exists(paths.DeviceRelayConfigurationFile), "load regenerated missing profile");
            await ThrowsAsync(() => store.InstallNewAsync(raw, trust, boundary, Now, default));
            Check(!File.Exists(paths.DeviceRelayConfigurationFile), "import ignored current pending setup");
            var freshPaths = new GuardDataPaths(Path.Combine(root, "fresh"));
            Directory.CreateDirectory(freshPaths.RootDirectory);
            using var freshBoundary = new ServiceAuthoritativeStateBoundary(freshPaths,
                new LocalSystemDpapiDataProtector(LocalSystemDpapiDataProtector.DefaultPurpose, true), guard,
                new DeviceIdentityStore(freshPaths, new LocalSystemDpapiDataProtector(DeviceIdentityStore.Purpose, true), guard),
                () => DeviceIdentityChecks.OpenRelay(freshPaths));
            var freshStore = new DeviceRelayConfigurationStore(freshPaths, protector, guard);
            // No held writer lease must fail before any protected record can be published.
            await ThrowsAsync(() => freshStore.InstallNewAsync(original, trust, freshBoundary, Now, default));
            await ThrowsAsync(() => freshBoundary.ExportDeviceProvisioningAsync(trust, default));
            CryptographicOperations.ZeroMemory(raw); CryptographicOperations.ZeroMemory(original);
            await freshBoundary.AcquireAsync(default); await freshBoundary.InitializeNewAsync(default);
            _ = await freshBoundary.LoadAsync(default);
            var freshRaw = JsonSerializer.SerializeToUtf8Bytes(Profile(freshBoundary.Identity));
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await ThrowsAsync(() => freshStore.InstallNewAsync(freshRaw, trust, freshBoundary, Now, cancelled.Token));
            guard.Check = () => { if (File.Exists(freshPaths.DeviceRelayConfigurationPendingFile)) throw new UnauthorizedAccessException("synthetic ACL change"); };
            await ThrowsAsync(() => freshStore.InstallNewAsync(freshRaw, trust, freshBoundary, Now, default));
            Check(!File.Exists(freshPaths.DeviceRelayConfigurationFile) && !File.Exists(freshPaths.DeviceRelayConfigurationPendingFile), "failed guard published profile");
            guard.Check = () => { };
            var handoffProtector = new DeviceRelayProfileEnvelope(freshBoundary.Identity.Encryption);
            // Actual encrypted installer handoff, never plaintext/token in args, using only owned temporary files.
            async Task Import() => await freshStore.ImportStagedAsync(trust, freshBoundary, Now, default);
            await ThrowsAsync(Import); // no staged file
            File.WriteAllBytes(freshPaths.DeviceRelayInstallFile, protector.Protect(freshRaw));
            await ThrowsAsync(Import); // DPAPI storage records are not transferable installer envelopes.
            Check(File.Exists(freshPaths.DeviceRelayInstallFile) && !File.Exists(freshPaths.DeviceRelayConfigurationFile), "bad handoff was consumed");
            File.WriteAllBytes(freshPaths.DeviceRelayInstallFile, new byte[8193]);
            await ThrowsAsync(Import);
            var staged = handoffProtector.Protect(freshRaw);
            Check(!Encoding.UTF8.GetString(staged).Contains(Credential, StringComparison.Ordinal), "installer handoff contains plaintext credential");
            File.WriteAllBytes(freshPaths.DeviceRelayInstallFile, staged);
            File.WriteAllBytes(freshPaths.DeviceRelayInstallPendingFile, Array.Empty<byte>());
            await ThrowsAsync(Import);
            File.Delete(freshPaths.DeviceRelayInstallPendingFile);
            await ThrowsAsync(() => freshStore.ImportStagedAsync(trust, freshBoundary, Now, cancelled.Token));
            Check(staged.SequenceEqual(File.ReadAllBytes(freshPaths.DeviceRelayInstallFile)), "cancel consumed handoff");
            guard.Check = () => { if (File.Exists(freshPaths.DeviceRelayConfigurationFile)) throw new UnauthorizedAccessException("synthetic interruption after commit"); };
            await ThrowsAsync(Import);
            var installed = File.ReadAllBytes(freshPaths.DeviceRelayConfigurationFile);
            Check(staged.SequenceEqual(File.ReadAllBytes(freshPaths.DeviceRelayInstallFile)), "interruption lost installer handoff");
            guard.Check = () => { };
            var different = Profile(freshBoundary.Identity); different["accessToken"] = Credential + "-different";
            File.WriteAllBytes(freshPaths.DeviceRelayInstallFile, handoffProtector.Protect(JsonSerializer.SerializeToUtf8Bytes(different)));
            await ThrowsAsync(Import);
            Check(installed.SequenceEqual(File.ReadAllBytes(freshPaths.DeviceRelayConfigurationFile)), "retry rotated credential");
            File.WriteAllBytes(freshPaths.DeviceRelayInstallFile, staged);
            await Import(); // exact retry completes consumption only
            Check(!File.Exists(freshPaths.DeviceRelayInstallFile) && installed.SequenceEqual(File.ReadAllBytes(freshPaths.DeviceRelayConfigurationFile)),
                "resume overwrote installed record or left handoff behind");
            await ThrowsAsync(Import); // flag is one-shot; normal startup must not retain it
            var freshState = await freshBoundary.LoadAsync(default);
            var freshConfig = freshStore.Load(trust, freshBoundary.Identity, freshState, Now);
            var activationDescriptor = await freshBoundary.ExportDeviceProvisioningAsync(trust, default);
            using var freshRuntime = ServiceNativeEnrollment.Create(freshBoundary.NativeEnrollmentStore, freshBoundary.Identity,
                freshState, freshConfig, trust, new Clock());
            var begun = await freshRuntime.Coordinator.BeginAsync(ClientRole.AdminSetup,
                freshConfig.CreateOffer(trust, freshBoundary.Identity, freshState, "Lab", Now), default);
            using var freshStart = begun.Start;
            Check(begun.Status == Guard.Application.SetupOperationStatus.Succeeded, "imported profile did not reach actual enrollment");
            File.WriteAllBytes(freshPaths.DeviceRelayInstallFile, staged);
            await ThrowsAsync(Import); // even identical import is forbidden once setup has begun
            Check(File.Exists(freshPaths.DeviceRelayInstallFile) && installed.SequenceEqual(File.ReadAllBytes(freshPaths.DeviceRelayConfigurationFile)),
                "active setup accepted/replaced installer profile");
            await CheckNativeConfirmIpcAsync(freshBoundary, freshConfig, trust, freshStart!, activationDescriptor, freshStore);
            CryptographicOperations.ZeroMemory(freshRaw);
        }
        finally { Directory.Delete(root, recursive: true); }
    }
    private static async Task CheckColdImportAsync(string root, EnrollmentDeploymentTrust trust)
    {
        var paths = new GuardDataPaths(Path.Combine(root, "cold-import"));
        Directory.CreateDirectory(paths.RootDirectory);
        var guard = new TestGuard();
        ServiceAuthoritativeStateBoundary Open() => new(paths,
            new LocalSystemDpapiDataProtector(LocalSystemDpapiDataProtector.DefaultPurpose, true), guard,
            new DeviceIdentityStore(paths, new LocalSystemDpapiDataProtector(DeviceIdentityStore.Purpose, true), guard),
            () => DeviceIdentityChecks.OpenRelay(paths));
        string deviceId;
        using (var initial = Open())
        {
            await initial.AcquireAsync(default); await initial.InitializeNewAsync(default);
            await initial.LoadAsync(default); deviceId = initial.Identity.DeviceId;
            var profile = JsonSerializer.SerializeToUtf8Bytes(Profile(initial.Identity));
            try { File.WriteAllBytes(paths.DeviceRelayInstallFile, new DeviceRelayProfileEnvelope(initial.Identity.Encryption).Protect(profile)); }
            finally { CryptographicOperations.ZeroMemory(profile); }
        }
        using var cold = Open();
        await cold.AcquireAsync(default);
        Throws(() => _ = cold.Identity); // Same startup order as the real SCM import, no prior status query.
        var store = new DeviceRelayConfigurationStore(paths,
            new LocalSystemDpapiDataProtector(DeviceRelayConfigurationStore.Purpose, true), guard);
        await store.ImportStagedAsync(trust, cold, Now, default);
        var state = await cold.LoadAsync(default);
        Check(cold.Identity.DeviceId == deviceId && state.Version == 0 && !state.IsProvisioned &&
            !File.Exists(paths.DeviceRelayInstallFile), "cold import replaced identity/state or retained staging");
        _ = store.Load(trust, cold.Identity, state, Now);
    }

    private static Dictionary<string, object> Profile(DeviceIdentity identity) => new(StringComparer.Ordinal) {
        ["version"] = 1, ["role"] = "device", ["relayOrigin"] = Origin, ["deviceId"] = identity.DeviceId,
        ["signingKeyId"] = identity.SigningKeyId, ["encryptionKeyId"] = identity.EncryptionKeyId,
        ["mailboxId"] = "mailbox-configuration-test", ["deviceEpoch"] = 1L, ["authorityEpoch"] = 1L,
        ["accessToken"] = Credential, ["issuedAt"] = Now.ToUnixTimeMilliseconds(), ["expiresAt"] = Now.AddDays(2).ToUnixTimeMilliseconds() };
    private static async Task CheckNativeIpcAsync(ServiceAuthoritativeStateBoundary boundary, DeviceRelayConfiguration config,
        EnrollmentDeploymentTrust trust)
    {
        var network = new EnrollmentSetupHttp();
        var opens = 0;
        async Task<ServiceNativeEnrollment> Open(CancellationToken token)
        {
            opens++;
            return ServiceNativeEnrollment.Create(boundary.NativeEnrollmentStore, boundary.Identity,
                await boundary.LoadAsync(token), config, trust, new Clock(), network);
        }
        using var handler = Handler(boundary, trust, Open);
        var dispatcher = new SecureIpcRequestDispatcher(handler);
        async Task<GuardIpcResponse> Send(GuardVerb verb, byte[] input, ClientRole role = ClientRole.AdminSetup)
        {
            var request = new GuardIpcRequest(1, Guid.NewGuid().ToString("D"), verb, input);
            using var wire = new MemoryStream(IpcFrameCodec.Encode(request));
            return await dispatcher.DispatchAsync(role, await IpcFrameCodec.DecodeAsync(wire, TimeSpan.FromSeconds(5), default), default);
        }
        foreach (var verb in new[] { GuardVerb.BeginNativeSetup, GuardVerb.AdvanceNativeSetup, GuardVerb.ConfirmNativeSetup,
            GuardVerb.CancelNativeSetup, GuardVerb.GetNativeSetupResult })
            foreach (var role in Enum.GetValues<ClientRole>().Where(r => r != ClientRole.AdminSetup))
                Check((await Send(verb, Array.Empty<byte>(), role)).Status is GuardIpcResponseStatus.Forbidden or GuardIpcResponseStatus.InvalidRequest,
                    "non-admin native setup role");
        Check(opens == 0 && network.Calls == 0, "unauthorized native setup opened dependencies");
        Check((await Send(GuardVerb.BeginNativeSetup, new byte[] { 1 })).Status == GuardIpcResponseStatus.InvalidRequest,
            "native begin accepted payload");
        using (var unconfigured = Handler(boundary, null))
        {
            var denied = await new SecureIpcRequestDispatcher(unconfigured).DispatchAsync(ClientRole.AdminSetup,
                new GuardIpcRequest(1, Guid.NewGuid().ToString("D"), GuardVerb.BeginNativeSetup, Array.Empty<byte>()), default);
            Check(denied.Status == GuardIpcResponseStatus.Unavailable, "unconfigured native setup fallback");
        }
        GuardIpcResponse? lastResponse = null;
        await using var client = await NativeSetupSession.BeginAsync(async (verb, input, token) => {
            token.ThrowIfCancellationRequested();
            return lastResponse = await Send(verb, input);
        }, () => Now, default);
        var begun = lastResponse!;
        Check(begun.Status == GuardIpcResponseStatus.Success && opens == 1 && network.Calls == 0, "native begin failed or used network");
        using var started = JsonDocument.Parse(begun.GetPayloadCopy());
        Check(started.RootElement.EnumerateObject().Count() == 5 && !started.RootElement.TryGetProperty("qr", out _) &&
            started.RootElement.GetProperty("phase").GetString() == "relay-pending", "QR exposed before provisioning");
        var secret = started.RootElement.GetProperty("confirmationSecret").GetString()!;
        var enrollmentId = started.RootElement.GetProperty("enrollmentId").GetString();
        var pending = await boundary.LoadAsync(default);
        Check(!pending.IsProvisioned && pending.Enrollment?.Offer.EnrollmentId == enrollmentId, "native begin claimed owner");
        Check((await Send(GuardVerb.BeginNativeSetup, Array.Empty<byte>())).Status == GuardIpcResponseStatus.Conflict, "begin replaced a session");
        byte[] Poll(string capability) => JsonSerializer.SerializeToUtf8Bytes(new { version = 1, confirmationSecret = capability });
        Check((await Send(GuardVerb.AdvanceNativeSetup, Poll(Convert.ToBase64String(new byte[32])))).Status == GuardIpcResponseStatus.Forbidden &&
            network.Calls == 0, "foreign local session reached relay");
        foreach (var bad in new[] { "{}", "{\"version\":1,\"version\":1,\"confirmationSecret\":\"" + secret + "\"}",
            "{\"version\":1,\"confirmationSecret\":12}", "{\"version\":1,\"confirmationSecret\":\"" + secret + "\",\"extra\":true}" })
            Check((await Send(GuardVerb.AdvanceNativeSetup, Encoding.UTF8.GetBytes(bad))).Status == GuardIpcResponseStatus.InvalidRequest,
                "malformed native setup payload");
        network.Fail = true;
        var failed = await Send(GuardVerb.AdvanceNativeSetup, Poll(secret));
        Check(failed.Status == GuardIpcResponseStatus.Unavailable && failed.PayloadLength == 0 &&
            (await boundary.LoadAsync(default)).Version == pending.Version, "failed HTTP revealed QR or changed ownership");
        network.Fail = false;
        var clientView = await client.RefreshAsync(default);
        var advanced = lastResponse!;
        Check(advanced.Status == GuardIpcResponseStatus.Success, "retry native provisioning");
        using var snapshot = JsonDocument.Parse(advanced.GetPayloadCopy());
        Check(snapshot.RootElement.GetProperty("phase").GetString() == "scan-phone" &&
            snapshot.RootElement.GetProperty("qr").GetString()!.StartsWith("guard-enroll://v2?offer=", StringComparison.Ordinal) &&
            snapshot.RootElement.GetProperty("claimHash").ValueKind == JsonValueKind.Null && opens == 1, "native QR gate or cached runtime");
        var version = snapshot.RootElement.GetProperty("stateVersion").GetInt64();
        Check(clientView.Phase == NativeSetupPhase.ScanPhone && clientView.StateVersion == version &&
            clientView.QrText == snapshot.RootElement.GetProperty("qr").GetString(), "typed setup client changed real service QR");
        var confirm = JsonSerializer.SerializeToUtf8Bytes(new { version = 1, confirmationSecret = secret,
            expectedVersion = version, claimHash = new string('0', 64) });
        Check((await Send(GuardVerb.ConfirmNativeSetup, confirm)).Status == GuardIpcResponseStatus.Rejected &&
            !(await boundary.LoadAsync(default)).IsProvisioned, "local click created an owner without phone proof/attestation");
        var staleCancel = JsonSerializer.SerializeToUtf8Bytes(new { version = 1, confirmationSecret = secret, expectedVersion = version - 1 });
        Check((await Send(GuardVerb.CancelNativeSetup, staleCancel)).Status == GuardIpcResponseStatus.Conflict, "stale cancel committed");

        // New handler has no retained QR. Persisted session and capability still work; no silent re-key.
        var resumedNetwork = new EnrollmentSetupHttp();
        using var resumed = Handler(boundary, trust, async token => ServiceNativeEnrollment.Create(boundary.NativeEnrollmentStore,
            boundary.Identity, await boundary.LoadAsync(token), config, trust, new Clock(), resumedNetwork));
        var response = await new SecureIpcRequestDispatcher(resumed).DispatchAsync(ClientRole.AdminSetup,
            new GuardIpcRequest(1, Guid.NewGuid().ToString("D"), GuardVerb.AdvanceNativeSetup, Poll(secret)), default);
        Check(response.Status == GuardIpcResponseStatus.Success, "restart lost persisted session");
        using var resumedSnapshot = JsonDocument.Parse(response.GetPayloadCopy());
        Check(resumedSnapshot.RootElement.GetProperty("phase").GetString() == "restart-required" &&
            resumedSnapshot.RootElement.GetProperty("qr").ValueKind == JsonValueKind.Null &&
            (await boundary.LoadAsync(default)).Version == version, "restart regenerated QR or state");
        Check((await client.CancelAsync(clientView.StateVersion, default)).Phase == NativeSetupPhase.Cancelled,
            "originating typed client could not cancel");
        Check((await Send(GuardVerb.AdvanceNativeSetup, Poll(secret))).Status == GuardIpcResponseStatus.Forbidden &&
            (await boundary.LoadAsync(default)).Enrollment == null, "cancelled capability remained usable");
    }

    private static async Task CheckNativeConfirmIpcAsync(ServiceAuthoritativeStateBoundary boundary, DeviceRelayConfiguration config,
        EnrollmentDeploymentTrust trust, NativeEnrollmentStart start, byte[] activationDescriptor, DeviceRelayConfigurationStore configurations)
    {
        // Real synthetic CA/phone keys, never a fake "verified" result or production trust override.
        using var phone = new AndroidAttestationChecks.Fixture();
        using var phoneEncryption = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var coordinator = new NativeEnrollmentCoordinator(boundary.NativeEnrollmentStore, phone.Verifier,
            _ => Task.FromResult(AndroidAttestationRevocations.FromTrustedResponse(Encoding.UTF8.GetBytes("{\"entries\":{}}"),
                Now.AddMinutes(-1), Now.AddHours(1))), new Clock());
        var state = await boundary.LoadAsync(default);
        var offer = state.Enrollment!.Offer;
        var encryptionPoint = phoneEncryption.ExportSubjectPublicKeyInfo()[26..];
        var claim = new EnrollmentKeyClaim(RelayCanonicalEncoding.ComputeEnrollmentOfferHash(offer), phone.Anchor.KeyId,
            phone.Anchor.GetSubjectPublicKeyInfoCopy(), "phone-encryption-ipc-test", encryptionPoint);
        var hash = RelayCanonicalEncoding.ComputeEnrollmentClaimHash(claim);
        var encoded = start.QrText.Split("&secret=", StringSplitOptions.None)[1].Replace('-', '+').Replace('_', '/');
        var qrSecret = Convert.FromBase64String(encoded + "=");
        var mac = RelayCanonicalEncoding.ComputeEnrollmentClaimProof(SHA256.HashData(qrSecret), claim);
        CryptographicOperations.ZeroMemory(qrSecret);
        var staged = await coordinator.StageAsync(ClientRole.ParentRelay, claim, mac,
            phone.Chain(AndroidAttestationChecks.Description(challenge: RelayCanonicalEncoding.ComputeEnrollmentOfferHash(offer)), at: Now),
            phone.Sign(hash), default);
        Check(staged == SetupOperationStatus.Succeeded, "synthetic attested stage failed: " + staged);
        Check(!(await boundary.LoadAsync(default)).IsProvisioned, "attested stage became owner");
        var candidate = (await boundary.LoadAsync(default)).Enrollment!;
        var privateKey = phoneEncryption.ExportParameters(true).D!;
        var witness = RelayCryptography.Decrypt(privateKey, encryptionPoint, candidate.GetEncapsulatedKeyCopy(),
            candidate.GetEncryptedChallengeCopy(), hash, NativeEnrollmentCoordinator.KeyConfirmationInfo(hash));
        var proof = NativeEnrollmentCoordinator.ComputePhoneKeyProof(witness, hash);
        CryptographicOperations.ZeroMemory(privateKey); CryptographicOperations.ZeroMemory(witness);
        Check(await coordinator.ConfirmPhoneKeyAsync(ClientRole.ParentRelay, hash, proof, default) == SetupOperationStatus.Succeeded,
            "phone decryption proof failed");
        var network = new EnrollmentSetupHttp();
        var transport = config.CreateTransport(trust, boundary.Identity, await boundary.LoadAsync(default), Now, network);
        var exchange = new NativeEnrollmentExchange(boundary.NativeEnrollmentStore, coordinator, boundary.Identity.Encryption, boundary.Identity.Signing, new Clock());
        var runtime = new ServiceNativeEnrollment(new GoogleAndroidAttestationSource(), transport, coordinator,
            new NativeEnrollmentRelay(boundary.NativeEnrollmentStore, exchange, transport, new Clock()), config, trust, boundary.Identity);
        using var handler = Handler(boundary, trust, _ => Task.FromResult(runtime));
        Check(!await handler.DeliverConfirmedEnrollmentAsync(default) && network.Calls == 0,
            "background delivery polled/provisioned an unconfirmed phone");
        var dispatcher = new SecureIpcRequestDispatcher(handler);
        var activationRequest = new GuardIpcRequest(1, Guid.NewGuid().ToString("D"), GuardVerb.GetNativeActivationConfirmation, Array.Empty<byte>());
        Check((await dispatcher.DispatchAsync(ClientRole.AdminSetup, activationRequest, default)).Status == GuardIpcResponseStatus.Conflict,
            "pending phone proof issued an owner activation confirmation");
        var capability = start.GetConfirmationSecretCopy();
        try
        {
            var secret = Convert.ToBase64String(capability);
            async Task<GuardIpcResponse> Send(GuardVerb verb, object payload) => await dispatcher.DispatchAsync(ClientRole.AdminSetup,
                new GuardIpcRequest(1, Guid.NewGuid().ToString("D"), verb, JsonSerializer.SerializeToUtf8Bytes(payload)), default);
            var advanced = await Send(GuardVerb.AdvanceNativeSetup, new { version = 1, confirmationSecret = secret });
            Check(advanced.Status == GuardIpcResponseStatus.Success, "candidate IPC inspection failed");
            using var snapshot = JsonDocument.Parse(advanced.GetPayloadCopy());
            Check(snapshot.RootElement.GetProperty("phase").GetString() == "compare-phone" &&
                snapshot.RootElement.GetProperty("qr").ValueKind == JsonValueKind.Null &&
                snapshot.RootElement.GetProperty("claimHash").GetString() == Convert.ToHexStringLower(hash), "comparison commitment mismatch");
            var version = snapshot.RootElement.GetProperty("stateVersion").GetInt64();
            var wrong = await Send(GuardVerb.ConfirmNativeSetup, new { version = 1, confirmationSecret = secret,
                expectedVersion = version, claimHash = new string('0', 64) });
            Check(wrong.Status == GuardIpcResponseStatus.Rejected && !(await boundary.LoadAsync(default)).IsProvisioned,
                "wrong phone comparison became owner");
            var correct = new { version = 1, confirmationSecret = secret, expectedVersion = version, claimHash = Convert.ToHexStringLower(hash) };
            Check((await Send(GuardVerb.ConfirmNativeSetup, correct)).Status == GuardIpcResponseStatus.Success &&
                (await boundary.LoadAsync(default)).IsProvisioned, "actual attested owner commit through IPC failed");
            Check((await Send(GuardVerb.ConfirmNativeSetup, correct)).Status == GuardIpcResponseStatus.Forbidden, "spent confirmation capability was reused");
            var callsBeforeExport = network.Calls;
            var activated = await dispatcher.DispatchAsync(ClientRole.AdminSetup, activationRequest, default);
            Check(activated.Status == GuardIpcResponseStatus.Success && activated.RequestId == activationRequest.RequestId && network.Calls == callsBeforeExport,
                "confirmed activation export failed or performed unexpected networking");
            await ActivationConfirmationChecks.RunAsync(activated, activationDescriptor, await boundary.LoadAsync(default), boundary.Identity.Signing, phoneEncryption, Now);
            foreach (var role in Enum.GetValues<ClientRole>().Where(value => value != ClientRole.AdminSetup))
                Check((await handler.HandleAsync(role, activationRequest, default)).Status == GuardIpcResponseStatus.Forbidden,
                    "non-admin read native activation export");
            Check((await Send(GuardVerb.GetNativeActivationConfirmation, new { chosenPhone = "not-allowed" })).Status == GuardIpcResponseStatus.InvalidRequest,
                "activation export accepted a caller-selected identity");
            Check((await Send(GuardVerb.GetNativeSetupResult, new { version = 1, enrollmentId = offer.EnrollmentId,
                claimHash = new string('0', 64) })).Status == GuardIpcResponseStatus.Rejected, "terminal query accepted another transcript");
            var terminal = await Send(GuardVerb.GetNativeSetupResult, new { version = 1, enrollmentId = offer.EnrollmentId,
                claimHash = Convert.ToHexStringLower(hash) });
            using var terminalPayload = JsonDocument.Parse(terminal.GetPayloadCopy());
            Check(terminal.Status == GuardIpcResponseStatus.Success && terminalPayload.RootElement.GetProperty("phase").GetString() == "confirmed",
                "lost confirmation response could not be reconciled");
            network.Fail = true;
            var offline = await Send(GuardVerb.GetNativeSetupResult, new { version = 1, enrollmentId = offer.EnrollmentId,
                claimHash = Convert.ToHexStringLower(hash) });
            using var offlinePayload = JsonDocument.Parse(offline.GetPayloadCopy());
            Check(offline.Status == GuardIpcResponseStatus.Success && !offlinePayload.RootElement.GetProperty("relayPassCompleted").GetBoolean() &&
                offlinePayload.RootElement.GetProperty("phase").GetString() == "confirmed", "relay outage obscured durable owner or became delivery success");
            var owner = await boundary.LoadAsync(default);
            Check((await Send(GuardVerb.CancelNativeSetup, new { version = 1, confirmationSecret = secret,
                expectedVersion = owner.Version })).Status == GuardIpcResponseStatus.Forbidden &&
                (await boundary.LoadAsync(default)).Version == owner.Version, "cancel removed confirmed owner");

            network.Fail = false;
            var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            network.BeforePoll = async token => { entered.TrySetResult(true); await release.Task.WaitAsync(token); };
            var foreground = Send(GuardVerb.GetNativeSetupResult, new { version = 1, enrollmentId = offer.EnrollmentId,
                claimHash = Convert.ToHexStringLower(hash) });
            try
            {
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
                var calls = network.Calls;
                Check(!await handler.DeliverConfirmedEnrollmentAsync(default) && network.Calls == calls,
                    "background delivery queued over the originating setup action");
            }
            finally { release.TrySetResult(true); await foreground; network.BeforePoll = null; }

            // A new handler has no originating window/capability/runtime; reconstruct from durable owner + keys.
            var backgroundNetwork = new EnrollmentSetupHttp();
            var backgroundClock = new Clock();
            using var resumed = Handler(boundary, trust, async token => ServiceNativeEnrollment.Create(boundary.NativeEnrollmentStore,
                boundary.Identity, await boundary.LoadAsync(token), config, trust, backgroundClock, backgroundNetwork), backgroundClock);
            var query = EnrollmentExchange.Seal(EnrollmentExchange.Header(EnrollmentExchange.Query,
                RelayCanonicalEncoding.ComputeEnrollmentOfferHash(offer), hash, RandomNumberGenerator.GetBytes(32)),
                Array.Empty<byte>(), offer.GetEncryptionKeyCopy());
            backgroundNetwork.Pending = query; backgroundNetwork.LoseReply = true;
            try { await resumed.DeliverConfirmedEnrollmentAsync(default); throw new InvalidOperationException("Expected lost reply."); }
            catch (HttpRequestException) { }
            Check(backgroundNetwork.Reply != null && backgroundNetwork.Pending == null, "confirmed reply was not published before lost acknowledgment");
            NativeEnrollmentExchange.RequireReplyBinding(backgroundNetwork.Reply!, query, offer);
            var message = EnrollmentExchange.Decode(backgroundNetwork.Reply!);
            var plaintext = EnrollmentExchange.Open(message, phoneEncryption);
            try
            {
                Check(BinaryPrimitives.ReadInt32BigEndian(plaintext.AsSpan(8, 4)) == EnrollmentExchange.Confirmed &&
                    boundary.Identity.Signing.VerifyData(EnrollmentExchange.SignatureInput(message.Header, plaintext[..^64]),
                        plaintext[^64..], HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
                    "background response did not prove committed owner to the exact phone");
            }
            finally { CryptographicOperations.ZeroMemory(plaintext); }
            var savedReply = backgroundNetwork.Reply;
            Check(!await resumed.DeliverConfirmedEnrollmentAsync(default) && ReferenceEquals(savedReply, backgroundNetwork.Reply),
                "retry blindly republished a confirmed nonce instead of polling");
            foreach (var unavailableAt in new[] { offer.CreatedAtUtc.AddMilliseconds(-1), offer.ExpiresAtUtc.AddDays(1) })
            {
                backgroundClock.NowValue = unavailableAt;
                var calls = backgroundNetwork.Calls;
                Check(!await resumed.DeliverConfirmedEnrollmentAsync(default) && backgroundNetwork.Calls == calls,
                    "clock rollback/retention expiry reached background network");
            }
            backgroundClock.NowValue = offer.ExpiresAtUtc.AddDays(1).AddMilliseconds(-1);
            backgroundNetwork.BeforePoll = _ => { backgroundClock.NowValue = offer.ExpiresAtUtc.AddDays(1); return Task.CompletedTask; };
            Check(!await resumed.DeliverConfirmedEnrollmentAsync(default) && ReferenceEquals(savedReply, backgroundNetwork.Reply),
                "retention crossing during HTTP was fatal or published a late result");
            Check((await boundary.LoadAsync(default)).Version == owner.Version,
                "background delivery mutated owner or policy state");
            await NativeApplicationRequestChecks.RunAsync(owner, boundary.Identity, config, trust, phoneEncryption, Now);
            await NativeRelayCommitChecks.RunAsync(boundary.NativeEnrollmentStore, boundary.Identity, config, trust, phone.Sign, Now);
            await NativeRelayCommitChecks.CheckBoundaryRestartAsync(boundary, config, trust, Now);
            await NativeRelayDeliveryChecks.RunAsync(boundary, config, trust, phone.Sign, Now);
            await ChildApplicationIpcChecks.RunAsync(boundary, configurations, trust, Now.AddMinutes(1));
        }
        finally { CryptographicOperations.ZeroMemory(capability); }
    }

    private sealed class EnrollmentSetupHttp : HttpMessageHandler
    {
        internal bool Fail;
        internal int Calls;
        internal byte[]? Pending;
        internal byte[]? Reply;
        internal bool LoseReply;
        internal Func<CancellationToken, Task>? BeforePoll;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Calls++;
            Check(request.RequestUri!.Host == "relay.example.test" && request.Headers.Authorization?.Parameter == Credential,
                "native setup used unexpected endpoint or credentials");
            if (Fail) return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            if (request.Method == HttpMethod.Get)
            {
                if (BeforePoll != null) await BeforePoll(token);
                if (Pending == null) return new HttpResponseMessage(HttpStatusCode.NoContent);
                var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Pending) };
                response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                return response;
            }
            if (request.RequestUri.AbsolutePath.EndsWith("/replies", StringComparison.Ordinal))
            {
                Check(Pending != null, "blind background publication");
                Reply = await request.Content!.ReadAsByteArrayAsync(token); Pending = null;
                if (LoseReply) { LoseReply = false; throw new HttpRequestException("Synthetic lost reply acknowledgment."); }
                return new HttpResponseMessage(HttpStatusCode.Created) { Content = new StringContent("{\"duplicate\":false}", Encoding.UTF8, "application/json") };
            }
            using var body = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(token));
            var expiry = body.RootElement.GetProperty("expiresAt").GetInt64();
            return new HttpResponseMessage(HttpStatusCode.Created) { Content = new StringContent(
                JsonSerializer.Serialize(new { duplicate = false, retainUntil = expiry + 86400000 }), Encoding.UTF8, "application/json") };
        }
    }

    private sealed class TestGuard : IServiceDataBoundaryGuard { internal Action Check = () => { }; public void DemandReady() => Check(); }
    private static GuardServiceIpcOperationHandler Handler(ServiceAuthoritativeStateBoundary boundary, EnrollmentDeploymentTrust? trust,
        Func<CancellationToken, Task<ServiceNativeEnrollment>>? open = null, IServiceUtcClock? clock = null)
    {
        var unused = new UnusedSetupDependencies();
        return new GuardServiceIpcOperationHandler(boundary,
            new ChildAccountBindingCoordinator(boundary, unused), new GuardReadinessCoordinator(boundary, unused), clock ?? unused, trust,
            openNativeEnrollment: open);
    }
    private sealed class UnusedSetupDependencies : IManagedChildAccountValidator, IDeviceReadinessFactsProvider, IServiceUtcClock
    {
        public DateTimeOffset UtcNow => Now;
        public bool TryValidate(string sid, out WindowsAccountSid binding) => throw new InvalidOperationException("Export must not query accounts.");
        public ReadinessProbeFacts Probe(DeviceSecurityState state, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Export must not probe/change platform readiness.");
    }
    private sealed class Clock : TimeProvider, IServiceUtcClock
    {
        internal DateTimeOffset NowValue = Now;
        public DateTimeOffset UtcNow => NowValue;
        public override DateTimeOffset GetUtcNow() => NowValue;
    }
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static void Throws(Action action)
    { try { action(); } catch (Exception e) when (e is ArgumentException or InvalidDataException or InvalidOperationException or JsonException or CryptographicException or IOException) { return; }
        throw new InvalidOperationException("Expected configuration rejection"); }
    private static async Task ThrowsAsync(Func<Task> action)
    { try { await action(); } catch (Exception e) when (e is InvalidDataException or IOException or InvalidOperationException or OperationCanceledException or UnauthorizedAccessException or CryptographicException) { return; }
        throw new InvalidOperationException("Expected installation rejection"); }
}
