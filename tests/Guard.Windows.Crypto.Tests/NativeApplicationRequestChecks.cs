using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Contracts;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Domain.Policy;
using Guard.Domain.Relay;
using Guard.Protocol.Relay;
using Guard.Service;
using Guard.Storage;
using Guard.Storage.Relay;
using Guard.Windows.Cryptography;

namespace Guard.Windows.Crypto.Tests;

internal static class NativeApplicationRequestChecks
{
    internal static async Task RunAsync(DeviceSecurityState enrolled, DeviceIdentity identity,
        DeviceRelayConfiguration config, EnrollmentDeploymentTrust trust, ECDiffieHellman phoneEncryption, DateTimeOffset now)
    {
        var directory = Directory.CreateTempSubdirectory("Guard-observed-request-");
        var child = new WindowsAccountSid("S-1-5-21-11-22-33-1001");
        var other = new WindowsAccountSid("S-1-5-21-11-22-33-1002");
        var caller = new AuthenticatedChildContext(enrolled.DeviceId, child);
        var owner = new DeviceSecurityState(enrolled.DeviceId, 0, 0, 0, trustedParentKeys: enrolled.TrustedParentKeys,
            childAccountSid: child, enrollment: enrolled.Enrollment);
        var clock = new Clock { Value = now.AddTicks(37) }; // Real Windows clocks are not millisecond-aligned.
        var guard = new Boundary();
        var resolver = new Resolver();
        var input = new CreateApplicationRequestPayload("observation-0001", new string('я', 140));
        VerifiedBlockedApplicationObservation Observation(string id = "observation-0001", char hash = 'A',
            WindowsAccountSid? account = null, string? device = null, DateTimeOffset? start = null) => new(id,
                device ?? owner.DeviceId, account ?? child, new ApplicationIdentity(null, null, null, new string(hash, 64)),
                "Тест е\u0301", start ?? now, (start ?? now).AddMinutes(10).AddTicks(57),
                @"\Device\HarddiskVolume1\" + string.Concat(Enumerable.Repeat("😀", 240)) + ".exe");
        var firstObservation = Observation();
        FileRelayTransactionStore OpenRelay() => new(Path.Combine(directory.FullName, "relay.dat"),
            new LocalSystemDpapiDataProtector(FileRelayTransactionStore.StateDataProtectionPurpose, true),
            new ProtectedFileStateVersionJournal(Path.Combine(directory.FullName, "relay.journal"),
                new LocalSystemDpapiDataProtector(FileRelayTransactionStore.JournalDataProtectionPurpose, true)));
        try
        {
            using var owners = new FileAuthoritativeStateStore(Path.Combine(directory.FullName, "owner.dat"),
                new LocalSystemDpapiDataProtector(LocalSystemDpapiDataProtector.DefaultPurpose, true),
                new ProtectedFileStateVersionJournal(Path.Combine(directory.FullName, "owner.journal"),
                    new LocalSystemDpapiDataProtector(LocalSystemDpapiDataProtector.DefaultPurpose, true)));
            await owners.InitializeAsync(owner, default);
            byte[] originalFrame;
            RequestSnapshot original;
            using (var relay = OpenRelay())
            {
                await relay.InitializeAsync(new RelayTransactionState(owner.DeviceId, 0, 1, 1, 0, 0, 0, 0), default);
                var runtime = new NativeRelayTransactions(owners, relay, identity, config, trust, guard, clock);
                async Task<(RequestSnapshot Request, bool Created)?> Create(long version = 0, AuthenticatedChildContext? context = null,
                    CreateApplicationRequestPayload? payload = null, CancellationToken token = default) =>
                    await runtime.CreateApplicationRequestAsync(version, context ?? caller, payload ?? input, resolver, token);

                foreach (var invalid in new VerifiedBlockedApplicationObservation?[] { null, Observation(account: other),
                    Observation(device: "other-device-0001"), Observation("different-observation"),
                    Observation(start: now.AddMinutes(-11)), Observation(start: now.AddSeconds(1)) })
                {
                    resolver.Observation = invalid;
                    await RejectAsync(async () => { await Create(); });
                    Check((await relay.LoadAsync(default)).Version == 0, "invalid evidence wrote state");
                }
                resolver.Observation = firstObservation;
                await RejectAsync(async () => { await Create(context: new AuthenticatedChildContext(owner.DeviceId, other)); });
                await RejectAsync(async () => { await Create(context: new AuthenticatedChildContext("foreign-device-01", child)); });
                Check(await Create(version: 1) == null, "stale owner was accepted");
                var unbound = new DeviceSecurityState(owner.DeviceId, 0, 0, 0,
                    trustedParentKeys: owner.TrustedParentKeys, enrollment: owner.Enrollment);
                await RejectAsync(async () => { _ = NativeApprovalTransaction.PrepareApplicationRequest(unbound,
                    await relay.LoadAsync(default), caller, input, firstObservation, identity.Encryption, identity.Signing, clock.Value); });
                using (var cancellation = new CancellationTokenSource())
                {
                    cancellation.Cancel();
                    await RejectAsync(async () => { await Create(token: cancellation.Token); });
                }
                resolver.BeforeRead = () => throw new IOException("Synthetic event source failure.");
                await RejectAsync(async () => { await Create(); });
                resolver.BeforeRead = () => clock.Value = now.AddTicks(-1);
                await RejectAsync(async () => { await Create(); });
                resolver.BeforeRead = null; clock.Value = now.AddTicks(37);
                foreach (var change in new Action[] { () => clock.Value = firstObservation.ExpiresAtUtc,
                    () => clock.Value = now.AddTicks(-1), () => throw new UnauthorizedAccessException() })
                {
                    guard.Reset(change, 4);
                    try { Check(await Create() == null, "late publication guard allowed a request"); }
                    catch (Exception e) when (e is UnauthorizedAccessException or InvalidDataException) { }
                    Check((await relay.LoadAsync(default)).Version == 0, "late failure changed state");
                    clock.Value = now.AddTicks(37);
                }
                guard.Reset();
                // Both the original and encrypted frame commit together; no duplicate signing/lease extension.
                var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Create()));
                Check(results.All(r => r.HasValue) && results.Count(r => r!.Value.Created) == 1 &&
                    results.Select(r => r!.Value.Request.RequestId).Distinct().Count() == 1, "concurrent deduplication failed");
                original = results[0]!.Value.Request;
                var saved = await relay.LoadAsync(default);
                Check(saved.Version == 1 && saved.Outbox.Count == 1 && saved.TrackedRequests.Count == 1 &&
                    saved.PolicyLedger.Count == 0 && saved.SignedReceipts.Count == 0 && saved.ReconcileIntents.Count == 0 &&
                    saved.CommittedInboundCursor == 0 && saved.PolicyRevision == 0, "request falsely changed protection");
                Check(original.CanonicalTargetIdentity == firstObservation.Identity.AuthorizationKey &&
                    original.PendingExpiresAtUtc <= firstObservation.ExpiresAtUtc && original.ChildReason == input.ShortReason &&
                    original.DisplayEvidence.All(e => Encoding.UTF8.GetByteCount(e.Value) <= RelayProtocol.MaximumEvidenceValueBytes) &&
                    original.DisplayEvidence.Single(e => e.Name == "path-hint").Value.EndsWith("…") &&
                    original.DisplayEvidence.Single(e => e.Name == "application-name").Value.IsNormalized(), "wire display/identity mismatch");
                originalFrame = saved.Outbox.Single().GetEncryptedFrameCopy();
                VerifyPhoneRequest(originalFrame, original, identity, phoneEncryption);
                // A new event/reason for the same exact image returns the original, not an edited request.
                resolver.Observation = Observation("observation-0002", start: now.AddMinutes(1));
                clock.Value = now.AddMinutes(1);
                var duplicate = await Create(payload: new CreateApplicationRequestPayload("observation-0002", "другая причина"));
                Check(duplicate is { Created: false } && Same(original, duplicate.Value.Request) &&
                    (await relay.LoadAsync(default)).Outbox.Single().GetEncryptedFrameCopy().SequenceEqual(originalFrame),
                    "retry changed signed content/deadline/frame");
                guard.Reset(() => clock.Value = original.PendingExpiresAtUtc, 3);
                Check(await Create(payload: new CreateApplicationRequestPayload("observation-0002", null)) == null,
                    "deduplicated reply crossed original expiry");
                guard.Reset(); clock.Value = now.AddMinutes(1);
                Check(await runtime.AcknowledgePublishedAsync(owner.Version, saved.Outbox.Single(), default), "delivery ack failed");
            }
            using (var relay = OpenRelay())
            {
                var runtime = new NativeRelayTransactions(owners, relay, identity, config, trust, guard, clock);
                var retryInput = new CreateApplicationRequestPayload("observation-0002", null);
                var retried = await runtime.CreateApplicationRequestAsync(0, caller, retryInput, resolver, default);
                var restored = await relay.LoadAsync(default);
                Check(retried is { Created: false } && Same(original, retried.Value.Request) && restored.Version == 2 &&
                    restored.Outbox.Count == 0 && restored.HighestOutboundCursor == 1, "restart/ack lost deduplication");
                resolver.Observation = Observation("observation-0002", 'B', start: now.AddMinutes(1));
                var changed = await runtime.CreateApplicationRequestAsync(0, caller, retryInput, resolver, default);
                Check(changed is { Created: true } && changed.Value.Request.RequestId != original.RequestId &&
                    changed.Value.Request.CanonicalTargetIdentity != original.CanonicalTargetIdentity, "replacement inherited request");
                resolver.Observation = firstObservation; clock.Value = firstObservation.ExpiresAtUtc;
                await RejectAsync(async () => { await runtime.CreateApplicationRequestAsync(0, caller, input, resolver, default); });
                resolver.Observation = Observation("observation-fresh", start: now.AddMinutes(10));
                var fresh = await runtime.CreateApplicationRequestAsync(0, caller,
                    new CreateApplicationRequestPayload("observation-fresh", null), resolver, default);
                Check(fresh is { Created: true } && fresh.Value.Request.RequestId != original.RequestId, "expired original reused");
                var before = (await relay.LoadAsync(default)).Version;
                resolver.Observation = Observation("observation-long", 'C', start: now.AddMinutes(10));
                await RejectAsync(async () => { await runtime.CreateApplicationRequestAsync(0, caller,
                    new CreateApplicationRequestPayload("observation-long", new string('я', 160)), resolver, default); });
                Check((await relay.LoadAsync(default)).Version == before, "oversize reason silently truncated/committed");
                // Preserve all existing requests when the bounded queue is full; a retry still succeeds.
                for (var i = 0; i < 6; i++)
                {
                    resolver.Observation = Observation("observation-fill-" + i, "CDEF01"[i], start: now.AddMinutes(10));
                    // The sixth case is a package identity, never a publisher-wide authorization.
                    if (i == 5) resolver.Observation = new VerifiedBlockedApplicationObservation("observation-package", owner.DeviceId,
                        child, ApplicationIdentity.ForPackageFamily("Guard.Sample_123456789abcd"), "Пакет", now.AddMinutes(10), now.AddMinutes(20));
                    Check((await runtime.CreateApplicationRequestAsync(0, caller,
                        new CreateApplicationRequestPayload(resolver.Observation.ObservationId, null), resolver, default)) is { Created: true },
                        "bounded queue fill failed");
                }
                var full = await relay.LoadAsync(default);
                Check(full.Outbox.Count == RelayTransactionState.MaximumOutboxItems, "queue fixture not full");
                var duplicateAtCapacity = await runtime.CreateApplicationRequestAsync(0, caller,
                    new CreateApplicationRequestPayload(resolver.Observation!.ObservationId, null), resolver, default);
                Check(duplicateAtCapacity is { Created: false } &&
                    duplicateAtCapacity.Value.Request.CanonicalTargetIdentity == resolver.Observation.Identity.AuthorizationKey,
                    "exact package retry at capacity failed");
                resolver.Observation = Observation("observation-overflow", '9', start: now.AddMinutes(10));
                await RejectAsync(async () => { await runtime.CreateApplicationRequestAsync(0, caller,
                    new CreateApplicationRequestPayload("observation-overflow", null), resolver, default); });
                before = full.Version;
                Check((await relay.LoadAsync(default)).Version == before, "overflow replaced older pending requests");
                var nextOwner = new DeviceSecurityState(owner.DeviceId, 1, 0, 0, trustedParentKeys: owner.TrustedParentKeys,
                    childAccountSid: child, enrollment: owner.Enrollment);
                Check(await owners.TryCommitAsync(0, nextOwner, default), "owner fixture update failed");
                Check(await runtime.CreateApplicationRequestAsync(0, caller,
                    new CreateApplicationRequestPayload("observation-long", null), resolver, default) == null &&
                    (await relay.LoadAsync(default)).Version == before, "changed owner accepted stale operation");
            }
            Console.WriteLine("PASS: native blocked observation -> atomic encrypted request, deduplication/reopen/refusals.");
        }
        finally { directory.Delete(recursive: true); }
    }

    private static void VerifyPhoneRequest(byte[] bytes, RequestSnapshot expected, DeviceIdentity identity, ECDiffieHellman phone)
    {
        var frame = RelayCanonicalEncoding.DecodeRelayFrame(bytes);
        var aad = RelayCanonicalEncoding.EncodeRelayFrameAssociatedData(frame);
        var key = phone.ExportParameters(true);
        byte[] plain;
        try { plain = RelayCryptography.Decrypt(key.D!, phone.ExportSubjectPublicKeyInfo()[26..], frame.GetEncapsulatedKeyCopy(),
            frame.GetCiphertextCopy(), aad, "guard-relay-request-hpke-v1"u8.ToArray().Concat(aad).ToArray()); }
        finally { CryptographicOperations.ZeroMemory(key.D!); }
        try
        {
            var signed = RelayCanonicalEncoding.DecodeDeviceRequestEnvelope(plain);
            Check(Same(expected, signed.Snapshot) && identity.Signing.VerifyHash(RelayCanonicalEncoding.ComputeDeviceRequestHash(signed),
                signed.GetSignatureP1363Copy(), DSASignatureFormat.IeeeP1363FixedFieldConcatenation), "phone decryption/signature mismatch");
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }
    private static bool Same(RequestSnapshot a, RequestSnapshot b) =>
        RelayCanonicalEncoding.EncodeRequestSnapshot(a).SequenceEqual(RelayCanonicalEncoding.EncodeRequestSnapshot(b));
    private sealed class Clock : TimeProvider { internal DateTimeOffset Value; public override DateTimeOffset GetUtcNow() => Value; }
    private sealed class Resolver : IBlockedApplicationObservationResolver
    {
        internal VerifiedBlockedApplicationObservation? Observation;
        internal Action? BeforeRead;
        public Task<VerifiedBlockedApplicationObservation?> ResolveAsync(string id, CancellationToken token)
        { token.ThrowIfCancellationRequested(); BeforeRead?.Invoke(); return Task.FromResult(Observation); }
    }
    private sealed class Boundary : IServiceDataBoundaryGuard
    {
        private int _calls, _at; private Action? _action;
        internal void Reset(Action? action = null, int at = 0) { _calls = 0; _action = action; _at = at; }
        public void DemandReady() { if (++_calls == _at) _action?.Invoke(); }
    }
    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
    private static async Task RejectAsync(Func<Task> action)
    {
        try { await action(); }
        catch (Exception e) when (e is InvalidDataException or ArgumentException or IOException or OperationCanceledException or InvalidOperationException) { return; }
        throw new Exception("Expected observed request refusal.");
    }
}
