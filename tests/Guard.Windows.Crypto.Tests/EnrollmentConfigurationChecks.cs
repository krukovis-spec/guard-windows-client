using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Application;
using Guard.Application.Readiness;
using Guard.Domain;
using Guard.Domain.Readiness;
using Guard.Protocol;
using Guard.Service;
using Guard.Storage;
using Guard.Windows.Cryptography;
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
            var guard = new TestGuard();
            var identityStore = new DeviceIdentityStore(paths, new LocalSystemDpapiDataProtector(DeviceIdentityStore.Purpose, true), guard);
            using var boundary = new ServiceAuthoritativeStateBoundary(paths,
                new LocalSystemDpapiDataProtector(LocalSystemDpapiDataProtector.DefaultPurpose, true), guard, identityStore);
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
                new DeviceIdentityStore(freshPaths, new LocalSystemDpapiDataProtector(DeviceIdentityStore.Purpose, true), guard));
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
            var handoffProtector = new LocalSystemDpapiDataProtector(DeviceRelayConfigurationStore.InstallPurpose, true);
            // Actual encrypted installer handoff, never plaintext/token in args, using only owned temporary files.
            async Task Import() => await freshStore.ImportStagedAsync(trust, freshBoundary, handoffProtector, Now, default);
            await ThrowsAsync(Import); // no staged file
            File.WriteAllBytes(freshPaths.DeviceRelayInstallFile, protector.Protect(freshRaw));
            await ThrowsAsync(Import); // storage purpose is not the installer purpose
            Check(File.Exists(freshPaths.DeviceRelayInstallFile) && !File.Exists(freshPaths.DeviceRelayConfigurationFile), "bad handoff was consumed");
            File.WriteAllBytes(freshPaths.DeviceRelayInstallFile, new byte[8193]);
            await ThrowsAsync(Import);
            var staged = handoffProtector.Protect(freshRaw);
            Check(!Encoding.UTF8.GetString(staged).Contains(Credential, StringComparison.Ordinal), "installer handoff contains plaintext credential");
            File.WriteAllBytes(freshPaths.DeviceRelayInstallFile, staged);
            File.WriteAllBytes(freshPaths.DeviceRelayInstallPendingFile, Array.Empty<byte>());
            await ThrowsAsync(Import);
            File.Delete(freshPaths.DeviceRelayInstallPendingFile);
            await ThrowsAsync(() => freshStore.ImportStagedAsync(trust, freshBoundary, handoffProtector, Now, cancelled.Token));
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
            using var freshRuntime = ServiceNativeEnrollment.Create(freshBoundary.NativeEnrollmentStore, freshBoundary.Identity,
                freshState, freshConfig, trust, new Clock());
            var begun = await freshRuntime.Coordinator.BeginAsync(ClientRole.AdminSetup,
                freshConfig.CreateOffer(trust, freshBoundary.Identity, freshState, "Lab", Now), default);
            using (begun.Start) Check(begun.Status == Guard.Application.SetupOperationStatus.Succeeded, "imported profile did not reach actual enrollment");
            File.WriteAllBytes(freshPaths.DeviceRelayInstallFile, staged);
            await ThrowsAsync(Import); // even identical import is forbidden once setup has begun
            Check(File.Exists(freshPaths.DeviceRelayInstallFile) && installed.SequenceEqual(File.ReadAllBytes(freshPaths.DeviceRelayConfigurationFile)),
                "active setup accepted/replaced installer profile");
            CryptographicOperations.ZeroMemory(freshRaw);
        }
        finally { Directory.Delete(root, recursive: true); }
    }
    private static Dictionary<string, object> Profile(DeviceIdentity identity) => new(StringComparer.Ordinal) {
        ["version"] = 1, ["role"] = "device", ["relayOrigin"] = Origin, ["deviceId"] = identity.DeviceId,
        ["signingKeyId"] = identity.SigningKeyId, ["encryptionKeyId"] = identity.EncryptionKeyId,
        ["mailboxId"] = "mailbox-configuration-test", ["deviceEpoch"] = 1L, ["authorityEpoch"] = 1L,
        ["accessToken"] = Credential, ["issuedAt"] = Now.ToUnixTimeMilliseconds(), ["expiresAt"] = Now.AddDays(2).ToUnixTimeMilliseconds() };
    private sealed class TestGuard : IServiceDataBoundaryGuard { internal Action Check = () => { }; public void DemandReady() => Check(); }
    private static GuardServiceIpcOperationHandler Handler(ServiceAuthoritativeStateBoundary boundary, EnrollmentDeploymentTrust? trust)
    {
        var unused = new UnusedSetupDependencies();
        return new GuardServiceIpcOperationHandler(boundary,
            new SetupCoordinator(boundary, new SetupCeremony(new CryptographicSetupSecretGenerator(), new Sha256SetupSecretHasher(), new EcdsaP256SignatureVerifier())),
            new ChildAccountBindingCoordinator(boundary, unused), new GuardReadinessCoordinator(boundary, unused), unused, trust);
    }
    private sealed class UnusedSetupDependencies : IManagedChildAccountValidator, IDeviceReadinessFactsProvider, IServiceUtcClock
    {
        public DateTimeOffset UtcNow => Now;
        public bool TryValidate(string sid, out WindowsAccountSid binding) => throw new InvalidOperationException("Export must not query accounts.");
        public ReadinessProbeFacts Probe(DeviceSecurityState state, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Export must not probe/change platform readiness.");
    }
    private sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static void Throws(Action action)
    { try { action(); } catch (Exception e) when (e is ArgumentException or InvalidDataException or InvalidOperationException or JsonException or CryptographicException or IOException) { return; }
        throw new InvalidOperationException("Expected configuration rejection"); }
    private static async Task ThrowsAsync(Func<Task> action)
    { try { await action(); } catch (Exception e) when (e is InvalidDataException or IOException or InvalidOperationException or OperationCanceledException or UnauthorizedAccessException or CryptographicException) { return; }
        throw new InvalidOperationException("Expected installation rejection"); }
}
