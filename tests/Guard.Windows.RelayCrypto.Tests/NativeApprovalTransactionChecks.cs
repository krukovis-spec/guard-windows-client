using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Domain.Relay;
using Guard.Protocol.Relay;
using Guard.Storage;
using Guard.Storage.Relay;
using Decision = Guard.Contracts.Relay.ParentDecisionKind;

namespace Guard.Windows.RelayCrypto.Tests;

// Ephemeral test keys, temporary files and real HPKE/signatures/CAS. No service or Windows policies.
internal static class NativeApprovalTransactionChecks
{
    public static void Run()
    {
        using var f = new Fixture();
        foreach (var decision in new[] { Decision.AllowAlways, Decision.AllowTemporary, Decision.AllowDailyQuota, Decision.Deny })
        {
            var approval = f.Approval(decision);
            var next = f.Prepare(f.Seal(approval));
            var receipt = f.OpenReceipt(next);
            Check(next.Version == f.Current.Version + 1 && next.CommittedInboundCursor == 1 &&
                next.ReplayFloors.Single().HighestAcceptedSequence == 1 && next.SignedReceipts.Count == 1, "atomic markers");
            Check(receipt.KeyId == approval.KeyId && receipt.CommandId == approval.CommandId && receipt.RequestId == approval.RequestId &&
                receipt.RequestRevision == approval.RequestRevision && receipt.GetApprovalHashCopy().SequenceEqual(RelayCanonicalEncoding.ComputeApprovalHash(approval)), "exact receipt");
            if (decision == Decision.Deny)
                Check(next.PolicyRevision == 0 && next.PolicyLedger.Count == 0 && next.ReconcileIntents.Count == 0 &&
                    next.TrackedRequests.Single().Resolution == RelayRequestResolution.Denied && receipt.Status == CommandReceiptStatus.Applied, "deny is nonpermissive");
            else
                Check(next.PolicyRevision == 1 && next.PolicyLedger.Single().Decision == decision &&
                    next.ReconcileIntents.Single().GetPolicyDigestCopy().SequenceEqual(next.PolicyLedger.Single().ComputeDigest()) &&
                    next.TrackedRequests.Single().Resolution == RelayRequestResolution.Allowed &&
                    receipt.Status == CommandReceiptStatus.AcceptedPendingReconciliation && receipt.ReconciliationStatus == ReconciliationStatus.Pending, "allow must await effect");
            Reject(() => f.Prepare(f.Seal(approval), next), "same cursor replay");
            Reject(() => f.Prepare(f.Seal(approval, cursor: 2), next), "same approval at new cursor");
            if (decision != Decision.Deny)
                Reject(() => f.Prepare(f.Seal(f.Approval(Decision.Deny, sequence: 2, command: "next-command-0001"), cursor: 2), next),
                    "next sequence before terminal receipt");
        }

        var expired = f.Prepare(f.Seal(f.Approval(expires: f.Now)), now: f.Now);
        Check(f.OpenReceipt(expired).Status == CommandReceiptStatus.Expired && expired.PolicyLedger.Count == 0 &&
            expired.TrackedRequests.Single().IsPending, "signed expiry advances only receipt/floor");
        var denied = f.Prepare(f.Seal(f.Approval(Decision.Deny)));
        var resolved = f.Prepare(f.Seal(f.Approval(sequence: 2, command: "next-command-0001"), cursor: 2), denied);
        Check(f.OpenReceipt(resolved).Status == CommandReceiptStatus.AlreadyResolved && resolved.PolicyLedger.Count == 0 &&
            resolved.ReplayFloors.Single().HighestAcceptedSequence == 2, "resolved request cannot grant");
        var stalePolicy = new RelayTransactionState(f.Owner.DeviceId, f.Current.Version, 1, 1, 0, 1, 1, 1,
            trackedRequests: f.Current.TrackedRequests, policyLedger: new[] { new RelayPolicyLedgerEntry(1, "another-request-001",
                "another-command-001", RelayTargetKind.Application, "another.exe", Decision.AllowAlways, 0, new byte[32]) },
            recipientOutboundCursors: f.Current.RecipientOutboundCursors);
        var rejected = f.Prepare(f.Seal(f.Approval()), stalePolicy);
        Check(f.OpenReceipt(rejected).Status == CommandReceiptStatus.Rejected && rejected.PolicyLedger.Count == 1 &&
            rejected.PolicyLedger[0].CommandId == "another-command-001" && rejected.PolicyRevision == 1 &&
            rejected.TrackedRequests.Single().IsPending, "stale policy cannot grant");

        foreach (var invalid in new[] {
            f.Approval(sequence: 2), f.Approval(key: "wrong-parent-key"), f.Approval(device: "wrong-device-001"),
            f.Approval(deviceEpoch: 2), f.Approval(authorityEpoch: 2), f.Approval(request: "wrong-request-001"),
            f.Approval(revision: 2), f.Approval(snapshotHash: new byte[32]), f.Approval(challenge: new byte[32]),
            f.Approval(target: "another.exe"), f.Approval(kind: RelayTargetKind.Website), f.Approval(policy: 1),
            f.Approval(issued: f.Now.AddSeconds(1)), f.Approval(issued: f.Now.AddMinutes(-3)),
            f.Approval(signatureKey: f.DeviceSigning) })
            Reject(() => f.Prepare(f.Seal(invalid)), "invalid signed input");
        foreach (var frame in new[] { f.Seal(f.Approval(), cursor: 0), f.Seal(f.Approval(), cursor: 2),
            f.Seal(f.Approval(), ack: 1), f.Seal(f.Approval(), recipient: "wrong-recipient1"),
            f.Seal(f.Approval(), mailbox: "wrong-mailbox-001"), f.Seal(f.Approval(), kind: RelayFrameKind.Receipt),
            f.Seal(f.Approval(), created: f.Now.AddSeconds(1)), f.Seal(f.Approval(), expires: f.Now),
            f.Seal(f.Approval(), domain: "guard-relay-request-hpke-v1") })
            Reject(() => f.Prepare(frame), "invalid encrypted transport");
        var good = f.Seal(f.Approval());
        for (var i = 0; i < good.Length; i++)
        {
            var changed = (byte[])good.Clone(); changed[i] ^= 1;
            Reject(() => f.Prepare(changed), "mutated encrypted input");
        }
        Reject(() => f.Prepare(good[..^1]), "truncation");
        Reject(() => f.Prepare(good.Concat(new byte[1]).ToArray()), "trailing bytes");
        Reject(() => f.Prepare(good, owner: new DeviceSecurityState(f.Owner.DeviceId, 0, 0, 0)), "unprovisioned");
        Reject(() => f.Prepare(good, owner: new DeviceSecurityState(f.Owner.DeviceId, 1, 0, 0,
            trustedParentKeys: f.Owner.TrustedParentKeys)), "legacy owner is not native authority");
        using var wrongDecrypt = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var wrongSign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Reject(() => NativeApprovalTransaction.Prepare(f.Owner, f.Current, f.Snapshot, good, wrongDecrypt, f.DeviceSigning, f.Now), "device decryption key");
        Reject(() => NativeApprovalTransaction.Prepare(f.Owner, f.Current, f.Snapshot, good, f.DeviceEncryption, wrongSign, f.Now), "device signing key");
        var otherSnapshot = new RequestSnapshot(f.Snapshot.DeviceId, 1, 1, f.Snapshot.DeviceEventId, f.Snapshot.RequestId, 1,
            RelayTargetKind.Application, "different.exe", Array.Empty<RelayEvidenceField>(), "test", f.Now.AddMinutes(-2),
            f.Now.AddMinutes(10), f.Snapshot.GetDecisionChallengeCopy(), 0);
        Reject(() => NativeApprovalTransaction.Prepare(f.Owner, f.Current, otherSnapshot, good, f.DeviceEncryption, f.DeviceSigning, f.Now), "durable snapshot mismatch");
        var nextTime = f.Prepare(f.Seal(f.Approval(Decision.Deny)), now: f.Now.AddSeconds(2));
        Reject(() => f.Prepare(f.Seal(f.Approval(sequence: 2, command: "next-command-0001"), cursor: 2), nextTime), "stored receipt time floor");
        // Enrollment QR expiry is NOT expiry of an already confirmed owner.
        var late = f.Now.AddDays(2);
        using var lateFixture = new Fixture(late, late.AddDays(-3));
        Check(lateFixture.OpenReceipt(lateFixture.Prepare(lateFixture.Seal(lateFixture.Approval()))).Status ==
            CommandReceiptStatus.AcceptedPendingReconciliation, "confirmed owner survives QR expiry");
        PersistsAtomic(f);
    }

    private static void PersistsAtomic(Fixture f)
    {
        var directory = Directory.CreateTempSubdirectory("Guard-approval-transaction-");
        using var protector = new TestProtector();
        FileRelayTransactionStore Open() => new(Path.Combine(directory.FullName, "relay.dat"), protector,
            new ProtectedFileStateVersionJournal(Path.Combine(directory.FullName, "relay.journal"), protector));
        try
        {
            byte[] exactReply;
            using (var store = Open())
            {
                store.InitializeAsync(f.Initial, CancellationToken.None).GetAwaiter().GetResult();
                Check(store.TryCommitAsync(0, f.Published, CancellationToken.None).GetAwaiter().GetResult(), "publish commit");
                Check(store.TryCommitAsync(1, f.Current, CancellationToken.None).GetAwaiter().GetResult(), "delivery commit");
                var encoded = f.Seal(f.Approval());
                var next = f.Prepare(encoded);
                using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                Reject(() => store.TryCommitAsync(f.Current.Version, next, cancelled.Token).GetAwaiter().GetResult(), "cancel before commit");
                Check(store.LoadAsync(CancellationToken.None).GetAwaiter().GetResult().CommittedInboundCursor == 0, "cancellation unchanged");
                var other = f.Prepare(encoded);
                Check(store.TryCommitAsync(f.Current.Version, next, CancellationToken.None).GetAwaiter().GetResult(), "approval commit");
                Check(!store.TryCommitAsync(f.Current.Version, other, CancellationToken.None).GetAwaiter().GetResult(), "CAS loser");
                exactReply = next.Outbox.Single().GetEncryptedFrameCopy();
            }
            using var reopened = Open();
            var restored = reopened.LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
            Check(restored.Outbox.Single().GetEncryptedFrameCopy().SequenceEqual(exactReply) && restored.PolicyLedger.Count == 1 &&
                restored.ReplayFloors.Count == 1 && restored.ReconcileIntents.Count == 1 && restored.CommittedInboundCursor == 1 &&
                f.OpenReceipt(restored).Status == CommandReceiptStatus.AcceptedPendingReconciliation, "restart retains one complete transaction");
        }
        finally { directory.Delete(recursive: true); } // Only this newly created disposable test directory.
    }

    private sealed class Fixture : IDisposable
    {
        public readonly ECDsa DeviceSigning = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public readonly ECDsa ParentSigning = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public readonly ECDiffieHellman DeviceEncryption = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDiffieHellman _parentEncryption = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        public readonly DateTimeOffset Now;
        public readonly EnrollmentOffer Offer;
        public readonly EnrollmentKeyClaim Claim;
        public readonly DeviceSecurityState Owner;
        public readonly RequestSnapshot Snapshot;
        public readonly RelayTransactionState Initial, Published, Current;
        public Fixture(DateTimeOffset? now = null, DateTimeOffset? offered = null)
        {
            Now = now ?? new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);
            var created = offered ?? Now.AddMinutes(-3);
            Offer = new EnrollmentOffer("https://guard.example", "enrollment-test-01", "device-test-0001", "Test", 1, 1, "mailbox-test-001",
                Id(DeviceSigning.ExportSubjectPublicKeyInfo()), DeviceSigning.ExportSubjectPublicKeyInfo()[26..],
                Id(DeviceEncryption.ExportSubjectPublicKeyInfo()), DeviceEncryption.ExportSubjectPublicKeyInfo()[26..], created, created.AddMinutes(5), RandomNumberGenerator.GetBytes(32));
            var anchor = new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, ParentSigning.ExportSubjectPublicKeyInfo());
            Claim = new EnrollmentKeyClaim(RelayCanonicalEncoding.ComputeEnrollmentOfferHash(Offer), anchor.KeyId, anchor.GetSubjectPublicKeyInfoCopy(),
                "parent-encryption-01", _parentEncryption.ExportSubjectPublicKeyInfo()[26..]);
            // Synthetic already-trusted state only; tests do not claim Google or physical biometric attestation.
            var enrollment = new DeviceEnrollmentState(Offer, Array.Empty<byte>(), Claim, new[] { new byte[1], new byte[1] },
                new byte[64], new byte[32], new byte[65], new byte[48], Array.Empty<byte>(), true, true);
            Owner = new DeviceSecurityState(Offer.DeviceId, 3, 0, 0, trustedParentKeys: new[] { anchor }, enrollment: enrollment);
            Snapshot = new RequestSnapshot(Offer.DeviceId, 1, 1, "event-test-00001", "request-test-001", 1, RelayTargetKind.Application,
                "sha256:" + new string('a', 64), Array.Empty<RelayEvidenceField>(), "test", Now.AddMinutes(-2), Now.AddMinutes(10), RandomNumberGenerator.GetBytes(32), 0);
            Initial = new RelayTransactionState(Offer.DeviceId, 0, 1, 1, 0, 0, 0, 0);
            Published = Initial.WithPublishedRequest(new RelayTrackedRequest(Snapshot.RequestId, 1,
                RelayCanonicalEncoding.ComputeRequestSnapshotHash(Snapshot), Snapshot.GetDecisionChallengeCopy()),
                new RelayEncryptedOutboxItem("test-request-frame", 1, RelayFrameKind.Request, Claim.EncryptionKeyId, 1, new byte[] { 1 }));
            Current = Published.WithAcknowledgedOutboundCursor(1);
        }
        public SignedApprovalEnvelope Approval(Decision decision = Decision.AllowTemporary, long sequence = 1, string command = "command-test-001",
            string? key = null, string? device = null, long deviceEpoch = 1, long authorityEpoch = 1, string? request = null, long revision = 1,
            byte[]? snapshotHash = null, byte[]? challenge = null, string? target = null, RelayTargetKind kind = RelayTargetKind.Application,
            long policy = 0, DateTimeOffset? issued = null, DateTimeOffset? expires = null, ECDsa? signatureKey = null)
        {
            SignedApprovalEnvelope Make(byte[] signature) => new(authorityEpoch, key ?? Claim.ApprovalKeyId, sequence, command, "nonce-test-00001",
                issued ?? Now.AddSeconds(-1), expires ?? Now.AddMinutes(5), device ?? Owner.DeviceId, deviceEpoch, request ?? Snapshot.RequestId,
                revision, snapshotHash ?? RelayCanonicalEncoding.ComputeRequestSnapshotHash(Snapshot), challenge ?? Snapshot.GetDecisionChallengeCopy(),
                kind, target ?? Snapshot.CanonicalTargetIdentity, policy, decision, decision is Decision.AllowTemporary or Decision.AllowDailyQuota ? 15 : 0, signature);
            return Make((signatureKey ?? ParentSigning).SignHash(RelayCanonicalEncoding.ComputeApprovalHash(Make(new byte[64])), DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        }
        public byte[] Seal(SignedApprovalEnvelope approval, long cursor = 1, long ack = 0, string? recipient = null, string? mailbox = null,
            RelayFrameKind kind = RelayFrameKind.Approval, DateTimeOffset? created = null, DateTimeOffset? expires = null, string domain = "guard-relay-approval-hpke-v1")
        {
            RelayFrame Make(byte[] enc, byte[] cipher) => new(kind, mailbox ?? Offer.MailboxId, recipient ?? Offer.EncryptionKeyId,
                "frame-test-00001", cursor, ack, created ?? Now.AddMinutes(-1), expires ?? Now.AddHours(1), enc, cipher);
            var aad = RelayCanonicalEncoding.EncodeRelayFrameAssociatedData(Make(Array.Empty<byte>(), Array.Empty<byte>()));
            var ciphertext = Cryptography.RelayCryptography.Encrypt(Offer.GetEncryptionKeyCopy(), RelayCanonicalEncoding.EncodeApprovalEnvelope(approval),
                aad, System.Text.Encoding.ASCII.GetBytes(domain).Concat(aad).ToArray(), out var encapsulated);
            return RelayCanonicalEncoding.EncodeRelayFrame(Make(encapsulated, ciphertext));
        }
        public RelayTransactionState Prepare(byte[] frame, RelayTransactionState? state = null, DateTimeOffset? now = null, DeviceSecurityState? owner = null) =>
            NativeApprovalTransaction.Prepare(owner ?? Owner, state ?? Current, Snapshot, frame, DeviceEncryption, DeviceSigning, now ?? Now);
        public CommandReceipt OpenReceipt(RelayTransactionState state)
        {
            var item = state.Outbox.Last(); var frame = RelayCanonicalEncoding.DecodeRelayFrame(item.GetEncryptedFrameCopy());
            Check(frame.Kind == RelayFrameKind.Receipt && frame.RecipientKeyId == Claim.EncryptionKeyId && frame.MailboxId == Offer.MailboxId &&
                frame.Cursor == item.RecipientCursor && frame.AckCursor == 0 && frame.CreatedAtUtc == Now && frame.ExpiresAtUtc == Now.AddDays(1), "receipt transport");
            var aad = RelayCanonicalEncoding.EncodeRelayFrameAssociatedData(frame); var key = _parentEncryption.ExportParameters(true);
            byte[] plain;
            try { plain = Cryptography.RelayCryptography.Decrypt(key.D!, Claim.GetEncryptionKeyCopy(), frame.GetEncapsulatedKeyCopy(), frame.GetCiphertextCopy(),
                aad, "guard-relay-receipt-hpke-v1"u8.ToArray().Concat(aad).ToArray()); }
            finally { CryptographicOperations.ZeroMemory(key.D!); }
            var signed = RelayCanonicalEncoding.DecodeDeviceReceiptEnvelope(plain);
            Check(signed.DeviceKeyId == Offer.SigningKeyId && DeviceSigning.VerifyHash(RelayCanonicalEncoding.ComputeDeviceReceiptHash(signed),
                signed.GetSignatureP1363Copy(), DSASignatureFormat.IeeeP1363FixedFieldConcatenation), "device signature");
            Check(state.SignedReceipts.Last().GetSignedReceiptCopy().SequenceEqual(plain), "same saved encrypted receipt");
            return signed.Receipt;
        }
        public void Dispose() { DeviceSigning.Dispose(); ParentSigning.Dispose(); DeviceEncryption.Dispose(); _parentEncryption.Dispose(); }
        private static string Id(byte[] spki) => new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, spki).KeyId;
    }
    private sealed class TestProtector : IStateDataProtector, IDisposable
    {
        private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
        public byte[] Protect(byte[] plain)
        {
            var output = new byte[28 + plain.Length]; RandomNumberGenerator.Fill(output.AsSpan(0, 12));
            using var aes = new AesGcm(_key, 16); aes.Encrypt(output.AsSpan(0, 12), plain, output.AsSpan(28), output.AsSpan(12, 16)); return output;
        }
        public byte[] Unprotect(byte[] input)
        {
            var plain = new byte[input.Length - 28]; using var aes = new AesGcm(_key, 16);
            aes.Decrypt(input.AsSpan(0, 12), input.AsSpan(28), input.AsSpan(12, 16), plain); return plain;
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(_key);
    }
    private static void Reject(Action action, string what)
    {
        try { action(); }
        catch (Exception error) when (error is ArgumentException or InvalidDataException or InvalidOperationException or CryptographicException or OperationCanceledException ||
            error is PlatformNotSupportedException { InnerException: CryptographicException }) { return; }
        throw new Exception("Accepted " + what);
    }
    private static void Check(bool valid, string what) { if (!valid) throw new Exception(what); }
}
