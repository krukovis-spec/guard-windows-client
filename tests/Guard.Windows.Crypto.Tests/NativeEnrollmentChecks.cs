using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Contracts;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Protocol.Relay;
using Guard.Storage;
using Guard.Windows;
using Guard.Windows.Cryptography;

namespace Guard.Windows.Crypto.Tests;

internal static class NativeEnrollmentChecks
{
    private static readonly CancellationToken None = CancellationToken.None;
    internal static void Run() => RunAsync().GetAwaiter().GetResult();
    private static async Task RunAsync()
    {
        using (var lab = new Lab())
        {
            var forbidden = await lab.Coordinator.BeginAsync(ClientRole.Child, lab.Offer, None);
            Check(forbidden.Status == SetupOperationStatus.Forbidden && forbidden.Start == null, "child begin");
            using var start = await lab.Begin();
            var secret = start.GetConfirmationSecretCopy();
            var claim = lab.Claim(lab.PhoneOne);
            var claimHash = RelayCanonicalEncoding.ComputeEnrollmentClaimHash(claim);
            lab.Reopen();
            Check((await lab.State()).Enrollment?.Offer.DeviceLabel == "Lab PC", "offer lost on restart");
            Check(await lab.Stage(lab.PhoneOne, start, claim, badMac: true) == SetupOperationStatus.Rejected, "bad QR MAC");
            Check(await lab.Stage(lab.PhoneOne, start, claim) == SetupOperationStatus.Succeeded, "valid candidate");
            var pending = await lab.State();
            Check(!pending.IsProvisioned && pending.Enrollment!.Candidate != null, "first reply became owner");
            Check(await lab.Stage(lab.PhoneOne, start, claim) == SetupOperationStatus.Succeeded && (await lab.State()).Version == pending.Version, "duplicate stage changed bytes");
            Check(await lab.Stage(lab.PhoneTwo, start, lab.Claim(lab.PhoneTwo)) == SetupOperationStatus.StateConflict, "second genuine phone replaced pending");
            Check(await lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, pending.Version, secret, claimHash, None) == SetupOperationStatus.Rejected, "unconfirmed decryption key");
            var keyProof = lab.DecryptProof(pending.Enrollment!);
            Check(await lab.Coordinator.ConfirmPhoneKeyAsync(ClientRole.AdminSetup, claimHash, keyProof, None) == SetupOperationStatus.Forbidden, "admin asserted phone role");
            Check(await lab.Coordinator.ConfirmPhoneKeyAsync(ClientRole.ParentRelay, claimHash, new byte[32], None) == SetupOperationStatus.Rejected, "guessed phone key");
            Check(await lab.Coordinator.ConfirmPhoneKeyAsync(ClientRole.ParentRelay, claimHash, keyProof, None) == SetupOperationStatus.Succeeded, "phone proof rejected");
            var confirmedPhone = await lab.State();
            Check(!confirmedPhone.IsProvisioned && confirmedPhone.Enrollment!.PhoneKeyConfirmed, "phone proof became owner");
            Check(await lab.Coordinator.ConfirmPhoneKeyAsync(ClientRole.ParentRelay, claimHash, keyProof, None) == SetupOperationStatus.Succeeded &&
                (await lab.State()).Version == confirmedPhone.Version, "phone proof replay changed state");
            lab.Reopen();
            Check(await lab.Coordinator.ConfirmLocalAsync(ClientRole.ParentRelay, confirmedPhone.Version, secret, claimHash, None) == SetupOperationStatus.Forbidden, "remote local confirmation");
            Check(await lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, confirmedPhone.Version, new byte[32], claimHash, None) == SetupOperationStatus.Rejected, "other elevated session");
            Check(await lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, confirmedPhone.Version, secret, new byte[32], None) == SetupOperationStatus.Rejected, "other claim confirmation");
            Check(await lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, pending.Version, secret, claimHash, None) == SetupOperationStatus.StateConflict, "stale local display");
            var results = await Task.WhenAll(
                lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, confirmedPhone.Version, secret, claimHash, None),
                lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, confirmedPhone.Version, secret, claimHash, None));
            Check(results.Count(s => s == SetupOperationStatus.Succeeded) == 1 && results.Count(s => s == SetupOperationStatus.StateConflict) == 1, "local confirmation CAS");
            lab.Reopen(); var owner = await lab.State();
            Check(owner.IsProvisioned && owner.TrustedParentKeys.Single().Equals(lab.PhoneOne.Anchor) && owner.SetupChallenge == null,
                "atomic owner/challenge across reopen");
            Check(owner.Enrollment!.Confirmed && owner.Enrollment.GetConfirmationHashCopy().Length == 0 && owner.Enrollment.GetExpectedKeyProofCopy().Length == 0, "retained setup authenticators");
            Check((await lab.Coordinator.BeginAsync(ClientRole.AdminSetup, lab.Offer, None)).Status == SetupOperationStatus.AlreadyProvisioned, "re-enrollment overwrote owner");
            Check(await lab.Coordinator.CancelAsync(ClientRole.AdminSetup, owner.Version, secret, None) == SetupOperationStatus.Rejected, "setup cancellation removed owner");
            Check(await lab.Stage(lab.PhoneTwo, start, lab.Claim(lab.PhoneTwo)) == SetupOperationStatus.Rejected, "replayed QR changed owner");
            var dropped = new DeviceSecurityState(owner.DeviceId, owner.Version + 1, 0, 0, trustedParentKeys: owner.TrustedParentKeys);
            await Reject<ArgumentException>(() => lab.Store.TryCommitAsync(owner.Version, dropped, None));
            Check(await lab.Store.TryCommitAsync(owner.Version, owner.WithAcceptedCommand("command-test-0001", 1), None), "ordinary command lost enrollment");
            start.Dispose(); RejectSync<ObjectDisposedException>(() => start.GetConfirmationSecretCopy());
        }
        foreach (var failure in new[] { "expired", "status-await", "before-publish", "revoked", "cancelled" })
        {
            using var lab = new Lab(); using var start = await lab.Begin();
            var claim = lab.Claim(lab.PhoneOne); var hash = RelayCanonicalEncoding.ComputeEnrollmentClaimHash(claim);
            await lab.Stage(lab.PhoneOne, start, claim);
            var staged = await lab.State();
            await lab.Coordinator.ConfirmPhoneKeyAsync(ClientRole.ParentRelay, hash, lab.DecryptProof(staged.Enrollment!), None);
            var before = await lab.State();
            if (failure == "expired") lab.Clock.Now = lab.Offer.ExpiresAtUtc;
            if (failure == "status-await") lab.Status = _ => { lab.Clock.Now = lab.Offer.ExpiresAtUtc; return Task.FromResult(lab.PhoneOne.Status); };
            if (failure == "before-publish") lab.Protector.OnProtect = () => lab.Clock.Now = lab.Offer.ExpiresAtUtc;
            if (failure == "revoked") lab.Status = _ => Task.FromResult(AndroidAttestationRevocations.FromTrustedResponse(
                "{\"entries\":{\"1\":{\"status\":\"REVOKED\"}}}"u8.ToArray(), lab.Clock.Now.AddSeconds(-1), lab.Clock.Now.AddMinutes(10)));
            if (failure == "cancelled")
            {
                using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
                await Reject<OperationCanceledException>(() => lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, before.Version, start.GetConfirmationSecretCopy(), hash, cancellation.Token));
            }
            else Check(await lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, before.Version, start.GetConfirmationSecretCopy(), hash, None) != SetupOperationStatus.Succeeded, failure);
            lab.Protector.OnProtect = null; lab.Reopen();
            Check((await lab.State()).Version == before.Version && !(await lab.State()).IsProvisioned, "failed confirmation changed ownership: " + failure);
            Check(!Directory.EnumerateFiles(lab.DirectoryPath, "*.tmp").Any(), "unpublished temporary state leaked");
        }
        using (var lab = new Lab())
        {
            using var start = await lab.Begin(); var state = await lab.State();
            Check(await lab.Store.TryCommitAsync(state.Version, state.WithBoundChildAccount(new WindowsAccountSid("S-1-5-21-1000"), lab.Clock.Now), None), "child binding");
            state = await lab.State();
            Check(state.Enrollment != null, "child binding dropped pending ceremony");
            Check(await lab.Coordinator.CancelAsync(ClientRole.AdminSetup, state.Version, new byte[32], None) == SetupOperationStatus.Rejected, "other session cancelled setup");
            Check(await lab.Coordinator.CancelAsync(ClientRole.AdminSetup, state.Version, start.GetConfirmationSecretCopy(), None) == SetupOperationStatus.Succeeded, "originating session cannot cancel");
            lab.Reopen(); state = await lab.State();
            Check(state.Enrollment == null && state.SetupChallenge == null && state.ChildAccountSid != null && !state.IsProvisioned, "cancel did not preserve child binding");
        }
        LegacyCodec();
        Console.WriteLine("PASS real-file enrollment: restart, two genuine phones, QR replay, key proof, originating session, CAS, deadline-at-publication, revocation, cancellation and legacy codec");
    }

    private static void LegacyCodec()
    {
        // Exercise the on-disk codec directly without fabricating production ciphertext/journal commitments.
        var type = typeof(FileAuthoritativeStateStore).Assembly.GetType("Guard.Storage.CanonicalStateCodec")!;
        var encode = type.GetMethod("Encode", BindingFlags.Public | BindingFlags.Static)!;
        var decode = type.GetMethod("Decode", BindingFlags.Public | BindingFlags.Static)!;
        var original = new DeviceSecurityState("device-test-00001", 7, 0, 0);
        var bytes = (byte[])encode.Invoke(null, new object[] { original })!;
        Check(bytes[11] == 2 && bytes[^1] == 0, "schema 2 expected");
        var legacy = bytes[..^1]; legacy[11] = 1;
        var restored = (DeviceSecurityState)decode.Invoke(null, new object[] { legacy })!;
        Check(restored.Version == 7 && restored.Enrollment == null && !restored.IsProvisioned, "legacy state promoted/reset");
        Check(((byte[])encode.Invoke(null, new object[] { restored })!)[11] == 2, "schema migration");
        legacy[11] = 3;
        RejectSync<TargetInvocationException>(() => decode.Invoke(null, new object[] { legacy }));
        RejectSync<TargetInvocationException>(() => decode.Invoke(null, new object[] { bytes.Concat(new byte[] {0}).ToArray() }));
    }

    private sealed class Lab : IDisposable
    {
        public string DirectoryPath { get; } = Path.Combine(Path.GetTempPath(), "guard-enrollment-tests-" + Guid.NewGuid().ToString("N"));
        public AndroidAttestationChecks.Fixture PhoneOne { get; } = new();
        public AndroidAttestationChecks.Fixture PhoneTwo { get; } = new();
        private readonly ECDsa _deviceSign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _deviceEnc = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDiffieHellman _phoneEncryption = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        public TestProtector Protector { get; } = new();
        public Clock Clock { get; } = new();
        public Func<CancellationToken, Task<AndroidAttestationRevocations>> Status { get; set; }
        public FileAuthoritativeStateStore Store { get; private set; } = null!;
        public NativeEnrollmentCoordinator Coordinator { get; private set; } = null!;
        public EnrollmentOffer Offer { get; }
        public Lab()
        {
            Directory.CreateDirectory(DirectoryPath);
            Offer = new EnrollmentOffer("https://relay.example.test", "enrollment-test-001", "device-test-00001", "Lab PC", 1, 1,
                "mailbox-test-00001", "device-sign-test1", _deviceSign.ExportSubjectPublicKeyInfo()[26..], "device-enc-test01",
                _deviceEnc.ExportSubjectPublicKeyInfo()[26..], Clock.Now.AddMinutes(-1), Clock.Now.AddMinutes(4), RandomNumberGenerator.GetBytes(32));
            Status = _ => Task.FromResult(PhoneOne.Status); Reopen();
            Store.InitializeAsync(new DeviceSecurityState(Offer.DeviceId, 0, 0, 0), None).GetAwaiter().GetResult();
        }
        public void Reopen()
        {
            Store?.Dispose();
            Store = new FileAuthoritativeStateStore(Path.Combine(DirectoryPath, "state.dat"), Protector,
                new ProtectedFileStateVersionJournal(Path.Combine(DirectoryPath, "journal.dat"), Protector));
            Coordinator = new NativeEnrollmentCoordinator(Store, new AndroidApprovalAttestation(new[] { PhoneOne.RootCertificate, PhoneTwo.RootCertificate },
                AndroidAttestationChecks.ApkSigner, 1), token => Status(token), Clock);
        }
        public Task<DeviceSecurityState> State() => Store.LoadAsync(None);
        public async Task<NativeEnrollmentStart> Begin()
        {
            var result = await Coordinator.BeginAsync(ClientRole.AdminSetup, Offer, None);
            Check(result.Status == SetupOperationStatus.Succeeded && result.Start != null, "begin"); return result.Start!;
        }
        public EnrollmentKeyClaim Claim(AndroidAttestationChecks.Fixture phone) => new(RelayCanonicalEncoding.ComputeEnrollmentOfferHash(Offer),
            phone.Anchor.KeyId, phone.Anchor.GetSubjectPublicKeyInfoCopy(), "phone-encrypt-001", Point(_phoneEncryption.ExportParameters(false).Q));
        public Task<SetupOperationStatus> Stage(AndroidAttestationChecks.Fixture phone, NativeEnrollmentStart start, EnrollmentKeyClaim claim, bool badMac = false)
        {
            var encoded = start.QrText.Split("&secret=", StringSplitOptions.None)[1].Replace('-', '+').Replace('_', '/');
            var secret = Convert.FromBase64String(encoded + "=");
            var mac = RelayCanonicalEncoding.ComputeEnrollmentClaimProof(SHA256.HashData(secret), claim); CryptographicOperations.ZeroMemory(secret);
            return Coordinator.StageAsync(ClientRole.ParentRelay, claim, badMac ? new byte[32] : mac,
                phone.Chain(AndroidAttestationChecks.Description(challenge: RelayCanonicalEncoding.ComputeEnrollmentOfferHash(Offer))),
                phone.Sign(RelayCanonicalEncoding.ComputeEnrollmentClaimHash(claim)), None);
        }
        public byte[] DecryptProof(DeviceEnrollmentState session)
        {
            var hash = RelayCanonicalEncoding.ComputeEnrollmentClaimHash(session.Candidate!);
            var parameters = _phoneEncryption.ExportParameters(true);
            var witness = RelayCryptography.Decrypt(parameters.D!, Point(parameters.Q), session.GetEncapsulatedKeyCopy(),
                session.GetEncryptedChallengeCopy(), hash, NativeEnrollmentCoordinator.KeyConfirmationInfo(hash));
            try { return NativeEnrollmentCoordinator.ComputePhoneKeyProof(witness, hash); }
            finally { CryptographicOperations.ZeroMemory(witness); CryptographicOperations.ZeroMemory(parameters.D!); }
        }
        public void Dispose()
        {
            Store.Dispose(); PhoneOne.Dispose(); PhoneTwo.Dispose(); _deviceSign.Dispose(); _deviceEnc.Dispose(); _phoneEncryption.Dispose(); Protector.Dispose();
            var full = Path.GetFullPath(DirectoryPath);
            if (!full.StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase) ||
                !Path.GetFileName(full).StartsWith("guard-enrollment-tests-", StringComparison.Ordinal)) throw new InvalidOperationException("Unsafe test cleanup.");
            Directory.Delete(full, recursive: true);
        }
    }
    private sealed class Clock : TimeProvider { public DateTimeOffset Now = AndroidAttestationChecks.Now; public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class TestProtector : IStateDataProtector, IDisposable
    {
        private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
        public Action? OnProtect;
        public byte[] Protect(byte[] plaintext)
        {
            OnProtect?.Invoke(); var output = new byte[28 + plaintext.Length]; RandomNumberGenerator.Fill(output.AsSpan(0, 12));
            using var aes = new AesGcm(_key, 16); aes.Encrypt(output.AsSpan(0, 12), plaintext, output.AsSpan(28), output.AsSpan(12, 16)); return output;
        }
        public byte[] Unprotect(byte[] encoded)
        {
            var result = new byte[encoded.Length - 28]; using var aes = new AesGcm(_key, 16);
            aes.Decrypt(encoded.AsSpan(0, 12), encoded.AsSpan(28), encoded.AsSpan(12, 16), result); return result;
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(_key);
    }
    private static byte[] Point(ECPoint point) => new byte[] {4}.Concat(point.X!).Concat(point.Y!).ToArray();
    private static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static async Task Reject<T>(Func<Task> action) where T : Exception { try { await action(); } catch (T) { return; } throw new InvalidOperationException("Expected " + typeof(T).Name); }
    private static void RejectSync<T>(Action action) where T : Exception { try { action(); } catch (T) { return; } throw new InvalidOperationException("Expected " + typeof(T).Name); }
}
