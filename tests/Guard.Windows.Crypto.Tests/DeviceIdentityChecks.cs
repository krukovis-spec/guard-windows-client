using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Service;
using Guard.Storage;
using Guard.Windows.Cryptography;
using Guard.Windows.Storage;

namespace Guard.Windows.Crypto.Tests;

internal static class DeviceIdentityChecks
{
    internal static void Run() => RunAsync().GetAwaiter().GetResult();
    private static async Task RunAsync()
    {
        // Actual DPAPI of the test user in an owned temporary folder; no SYSTEM/ProgramData/ACL mutation.
        using var lab = new Lab();
        Check(!File.Exists(lab.Paths.DeviceIdentityFile), "composition generated keys");
        using var boundary = lab.Boundary();
        await ThrowsAsync<InvalidOperationException>(() => boundary.InitializeNewAsync(default));
        await boundary.AcquireAsync(default);
        await ThrowsAsync<Exception>(() => boundary.LoadAsync(default));
        Check(!File.Exists(lab.Paths.DeviceIdentityFile), "ordinary startup generated keys");
        await boundary.InitializeNewAsync(default);
        var state = await boundary.LoadAsync(default);
        var identity = boundary.Identity;
        var sign = identity.SigningPoint; var enc = identity.EncryptionPoint;
        Check(identity.DeviceId == state.DeviceId && !sign.SequenceEqual(enc) &&
            identity.SigningKeyId != identity.EncryptionKeyId, "device/key roles");
        var cipher = File.ReadAllBytes(lab.Paths.DeviceIdentityFile);
        Check(lab.Protector.LastPlaintext != null && lab.Protector.LastPlaintext.All(x => x == 0), "plaintext not cleared");
        Check(!File.Exists(lab.Paths.DeviceIdentityPendingFile), "pending file remains");
        await ThrowsAsync<InvalidOperationException>(() => boundary.InitializeNewAsync(default));
        Check(cipher.SequenceEqual(File.ReadAllBytes(lab.Paths.DeviceIdentityFile)), "double initialization rotated keys");
        using (var contender = lab.Boundary()) await ThrowsAsync<IOException>(() => contender.AcquireAsync(default));

        var hash = SHA256.HashData("identity-test"u8);
        var signature = identity.Signing.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var header = EnrollmentExchange.Header(EnrollmentExchange.Query, new byte[32], new byte[32], RandomNumberGenerator.GetBytes(32));
        var sealedQuery = EnrollmentExchange.Seal(header, Array.Empty<byte>(), enc);
        var now = DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        var offer = new EnrollmentOffer("https://relay.example.test", "enrollment-identity-test", identity.DeviceId, "Lab", 1, 1,
            "mailbox-identity-test", identity.SigningKeyId, sign, identity.EncryptionKeyId, enc, now, now.AddMinutes(5), RandomNumberGenerator.GetBytes(32));
        var pending = state.WithEnrollment(new SetupChallengeState(offer.EnrollmentId, new byte[32], offer.ExpiresAtUtc, false),
            new DeviceEnrollmentState(offer, new byte[32]));
        Check(await boundary.TryCommitAsync(state.Version, pending, default), "could not pin enrollment identity");
        var wrongOffer = new EnrollmentOffer(offer.RelayEndpoint, offer.EnrollmentId, offer.DeviceId, offer.DeviceLabel, 1, 1,
            offer.MailboxId, identity.EncryptionKeyId, enc, identity.SigningKeyId, sign, now, now.AddMinutes(5), offer.GetChallengeCopy());
        var wrong = pending.WithEnrollment(pending.SetupChallenge, new DeviceEnrollmentState(wrongOffer, new byte[32]));
        await ThrowsAsync<InvalidDataException>(() => boundary.TryCommitAsync(pending.Version, wrong, default));
        boundary.Dispose();
        Throws<InvalidOperationException>(() => _ = boundary.Identity);

        using (var reopened = lab.Boundary())
        {
            await reopened.AcquireAsync(default);
            var restored = await reopened.LoadAsync(default);
            Check(restored.Version == pending.Version && restored.DeviceId == state.DeviceId, "state changed on reopen");
            Check(reopened.Identity.SigningPoint.SequenceEqual(sign) && reopened.Identity.EncryptionPoint.SequenceEqual(enc), "keys changed on reopen");
            Check(reopened.Identity.Signing.VerifyHash(hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation), "signature lost on reopen");
            Check(EnrollmentExchange.Open(EnrollmentExchange.Decode(sealedQuery), reopened.Identity.Encryption).Length == 0, "decryption lost on reopen");
        }

        using var other = new Lab();
        using var otherIdentity = await other.Store.InitializeOrResumeNewAsync(default);
        var otherCipher = File.ReadAllBytes(other.Paths.DeviceIdentityFile);
        foreach (var bad in new[] { Array.Empty<byte>(), new byte[DeviceIdentityStore.MaximumFileBytes + 1],
            cipher.Select((v, i) => i == cipher.Length / 2 ? (byte)(v ^ 1) : v).ToArray(), otherCipher,
            new LocalSystemDpapiDataProtector("guard-v2-wrong-purpose-test", true).Protect("not-identity"u8.ToArray()) })
        {
            File.WriteAllBytes(lab.Paths.DeviceIdentityFile, bad);
            using var reopened = lab.Boundary(); await reopened.AcquireAsync(default);
            await ThrowsAsync<Exception>(() => reopened.LoadAsync(default));
            await ThrowsAsync<InvalidOperationException>(() => reopened.InitializeNewAsync(default));
            Check(bad.SequenceEqual(File.ReadAllBytes(lab.Paths.DeviceIdentityFile)), "failed load repaired/replaced keys");
        }
        File.Delete(lab.Paths.DeviceIdentityFile);
        using (var reopened = lab.Boundary())
        {
            await reopened.AcquireAsync(default);
            await ThrowsAsync<FileNotFoundException>(() => reopened.LoadAsync(default));
            await ThrowsAsync<InvalidOperationException>(() => reopened.InitializeNewAsync(default));
            Check(!File.Exists(lab.Paths.DeviceIdentityFile), "missing keys regenerated");
        }
        File.WriteAllBytes(lab.Paths.DeviceIdentityFile, cipher);
        MalformedRecords(lab, cipher);

        // Power cut after durable keys and before first state: explicit bootstrap resumes the same keys.
        using (var recovered = other.Boundary())
        {
            await recovered.AcquireAsync(default);
            await recovered.InitializeNewAsync(default);
            await recovered.LoadAsync(default);
            Check(recovered.Identity.DeviceId == otherIdentity.DeviceId &&
                otherCipher.SequenceEqual(File.ReadAllBytes(other.Paths.DeviceIdentityFile)), "bootstrap replaced committed keys");
        }
        using var interrupted = new Lab();
        File.WriteAllBytes(interrupted.Paths.DeviceIdentityPendingFile, new byte[] { 1 });
        await ThrowsAsync<InvalidDataException>(() => interrupted.Store.InitializeOrResumeNewAsync(default));
        Check(!File.Exists(interrupted.Paths.DeviceIdentityFile) && File.ReadAllBytes(interrupted.Paths.DeviceIdentityPendingFile)[0] == 1,
            "interrupted publication silently reset");

        using var failed = new Lab();
        failed.Guard.Check = () => { if (File.Exists(failed.Paths.DeviceIdentityPendingFile)) throw new UnauthorizedAccessException("synthetic ACL change"); };
        await ThrowsAsync<UnauthorizedAccessException>(() => failed.Store.InitializeOrResumeNewAsync(default));
        Check(!File.Exists(failed.Paths.DeviceIdentityFile) && !File.Exists(failed.Paths.DeviceIdentityPendingFile), "failed guard published keys");
        failed.Guard.Check = () => { };
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await ThrowsAsync<OperationCanceledException>(() => failed.Store.InitializeOrResumeNewAsync(cancel.Token));
        Check(!File.Exists(failed.Paths.DeviceIdentityFile), "cancelled bootstrap wrote keys");
        using var lateCancel = new CancellationTokenSource();
        failed.Guard.Check = () => { if (File.Exists(failed.Paths.DeviceIdentityPendingFile)) lateCancel.Cancel(); };
        await ThrowsAsync<OperationCanceledException>(() => failed.Store.InitializeOrResumeNewAsync(lateCancel.Token));
        Check(!File.Exists(failed.Paths.DeviceIdentityFile) && !File.Exists(failed.Paths.DeviceIdentityPendingFile),
            "cancellation after flush published keys");
    }

    private static void MalformedRecords(Lab lab, byte[] validCipher)
    {
        var raw = lab.Protector.Unprotect(validCipher);
        try
        {
            var idLength = BinaryPrimitives.ReadInt32BigEndian(raw.AsSpan(4));
            var signOffset = 8 + idLength;
            var signLength = BinaryPrimitives.ReadInt32BigEndian(raw.AsSpan(signOffset));
            var encOffset = signOffset + 4 + signLength;
            var duplicate = new byte[signOffset + 8 + signLength * 2];
            raw.AsSpan(0, encOffset).CopyTo(duplicate);
            raw.AsSpan(signOffset, 4 + signLength).CopyTo(duplicate.AsSpan(encOffset));
            var variants = new[] { raw[..^1], raw.Concat(new byte[] { 0 }).ToArray(), duplicate,
                raw.Select((v, i) => i == 0 || i == 8 ? (byte)0xFF : v).ToArray(),
                raw.Select((v, i) => i == 4 ? (byte)0x7F : v).ToArray() };
            try
            {
                foreach (var bad in variants)
                {
                    File.WriteAllBytes(lab.Paths.DeviceIdentityFile, lab.Protector.Protect(bad));
                    Throws<Exception>(() => { using var unexpected = lab.Store.Load(); });
                    Check(lab.Protector.LastPlaintext!.All(x => x == 0), "rejected plaintext retained");
                }
            }
            finally { foreach (var bytes in variants) CryptographicOperations.ZeroMemory(bytes); }
        }
        finally { CryptographicOperations.ZeroMemory(raw); File.WriteAllBytes(lab.Paths.DeviceIdentityFile, validCipher); }
    }

    private sealed class Lab : IDisposable
    {
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "GuardIdentityTests-" + Guid.NewGuid().ToString("N"));
        internal GuardDataPaths Paths { get; }
        internal TrackingProtector Protector { get; } = new();
        internal TestGuard Guard { get; } = new();
        internal DeviceIdentityStore Store { get; }
        internal Lab()
        {
            Paths = new GuardDataPaths(_directory); Directory.CreateDirectory(Paths.RootDirectory);
            Store = new DeviceIdentityStore(Paths, Protector, Guard);
        }
        internal ServiceAuthoritativeStateBoundary Boundary() => new(Paths,
            new LocalSystemDpapiDataProtector(LocalSystemDpapiDataProtector.DefaultPurpose, true), Guard, Store);
        public void Dispose() => Directory.Delete(_directory, recursive: true);
    }
    private sealed class TestGuard : IServiceDataBoundaryGuard
    {
        internal Action Check = () => { };
        public void DemandReady() => Check();
    }
    private sealed class TrackingProtector : IStateDataProtector
    {
        private readonly LocalSystemDpapiDataProtector _inner = new(DeviceIdentityStore.Purpose, true);
        internal byte[]? LastPlaintext;
        public byte[] Protect(byte[] plaintext) { LastPlaintext = plaintext; return _inner.Protect(plaintext); }
        public byte[] Unprotect(byte[] ciphertext) => LastPlaintext = _inner.Unprotect(ciphertext);
    }
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static void Throws<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { return; }
        throw new InvalidOperationException("Expected " + typeof(T).Name);
    }
    private static async Task ThrowsAsync<T>(Func<Task> action) where T : Exception
    {
        try { await action(); } catch (T) { return; }
        throw new InvalidOperationException("Expected " + typeof(T).Name);
    }
}
