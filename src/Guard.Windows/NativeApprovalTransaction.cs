using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Domain.Relay;
using Guard.Protocol.Relay;
using Guard.Windows.Cryptography;

namespace Guard.Windows;

/// <summary>
/// Untrusted GRF1 to one complete successor aggregate, without I/O or policy effects.
/// The service must hold its authority boundary, supply its durable request snapshot,
/// and CAS this successor before publishing the outbox or acknowledging the input.
/// Preparing a result is not a commit, application, or fresh attestation check.
/// </summary>
public static class NativeApprovalTransaction
{
    public static RelayTransactionState Prepare(DeviceSecurityState owner, RelayTransactionState current,
        RequestSnapshot snapshot, byte[] encodedFrame, ECDiffieHellman decryptionKey, ECDsa signingKey, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(current);
        var session = RequireOwner(owner, current, decryptionKey, signingKey);
        var offer = session.Offer;
        var claim = session.Candidate!;
        var frame = RelayCanonicalEncoding.DecodeRelayFrame(encodedFrame);
        if (frame.Kind != RelayFrameKind.Approval || frame.MailboxId != offer.MailboxId ||
            frame.RecipientKeyId != offer.EncryptionKeyId || frame.AckCursor != 0 ||
            current.CommittedInboundCursor >= RelayTransactionState.MaximumRecipientCursor ||
            frame.Cursor != current.CommittedInboundCursor + 1 || now < frame.CreatedAtUtc || now >= frame.ExpiresAtUtc ||
            frame.CreatedAtUtc < offer.CreatedAtUtc)
            throw new InvalidDataException("Approval transport binding, ordering or time.");

        var aad = RelayCanonicalEncoding.EncodeRelayFrameAssociatedData(frame);
        ECParameters key;
        lock (decryptionKey) key = decryptionKey.ExportParameters(true);
        byte[] plain;
        try
        {
            plain = RelayCryptography.Decrypt(key.D!, offer.GetEncryptionKeyCopy(), frame.GetEncapsulatedKeyCopy(),
                frame.GetCiphertextCopy(), aad, "guard-relay-approval-hpke-v1"u8.ToArray().Concat(aad).ToArray());
        }
        finally { if (key.D != null) CryptographicOperations.ZeroMemory(key.D); }
        SignedApprovalEnvelope approval;
        try { approval = RelayCanonicalEncoding.DecodeApprovalEnvelope(plain); }
        finally { CryptographicOperations.ZeroMemory(plain); }
        var hash = RelayCanonicalEncoding.ComputeApprovalHash(approval);
        if (approval.KeyId != claim.ApprovalKeyId || approval.DeviceId != current.DeviceId ||
            approval.DeviceEpoch != current.DeviceEpoch || approval.AuthorityEpoch != current.AuthorityEpoch)
            throw new InvalidDataException("Approval authority binding.");
        using var parent = ECDsa.Create();
        var spki = claim.GetApprovalKeyCopy();
        parent.ImportSubjectPublicKeyInfo(spki, out var consumed);
        if (consumed != spki.Length || !parent.VerifyHash(hash, approval.GetSignatureP1363Copy(),
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            throw new InvalidDataException("Approval signature.");

        var snapshotHash = RelayCanonicalEncoding.ComputeRequestSnapshotHash(snapshot);
        var tracked = current.TrackedRequests.SingleOrDefault(r => r.RequestId == snapshot.RequestId &&
            r.RequestRevision == snapshot.RequestRevision && Equal(r.GetSnapshotHashCopy(), snapshotHash));
        if (tracked == null || !Equal(tracked.GetDecisionChallengeCopy(), snapshot.GetDecisionChallengeCopy()) ||
            snapshot.DeviceId != current.DeviceId || snapshot.DeviceEpoch != current.DeviceEpoch ||
            snapshot.AuthorityEpoch != current.AuthorityEpoch || approval.RequestId != snapshot.RequestId ||
            approval.RequestRevision != snapshot.RequestRevision || !Equal(approval.GetRequestSnapshotHashCopy(), snapshotHash) ||
            !Equal(approval.GetDecisionChallengeCopy(), snapshot.GetDecisionChallengeCopy()) ||
            approval.TargetKind != snapshot.TargetKind || approval.CanonicalTargetIdentity != snapshot.CanonicalTargetIdentity ||
            approval.PolicyRevision != snapshot.PolicyRevision || approval.IssuedAtUtc < snapshot.CreatedAtUtc ||
            approval.IssuedAtUtc < offer.CreatedAtUtc || now < approval.IssuedAtUtc ||
            approval.ExpiresAtUtc > snapshot.PendingExpiresAtUtc)
            throw new InvalidDataException("Approval request binding or time.");
        // The stored response time is a local rollback floor, not a hardware-backed trusted clock.
        foreach (var saved in current.SignedReceipts)
            if (now < RelayCanonicalEncoding.DecodeDeviceReceiptEnvelope(saved.GetSignedReceiptCopy()).Receipt.ProcessedAtUtc)
                throw new InvalidDataException("Approval clock rollback.");
        var nextSequence = current.TryGetReplayFloor(current.AuthorityEpoch, approval.KeyId, out var floor)
            ? checked(floor.HighestAcceptedSequence + 1) : 1;
        if (approval.Sequence != nextSequence || current.SignedReceipts.Any(r => r.CommandId == approval.CommandId))
            throw new InvalidDataException("Approval replay or sequence gap.");
        if (floor != null && current.SignedReceipts.LastOrDefault(r => r.ApprovalKeyId == approval.KeyId &&
            r.Sequence == floor.HighestAcceptedSequence)?.Status == CommandReceiptStatus.AcceptedPendingReconciliation)
            throw new InvalidDataException("Previous approval still awaits reconciliation.");

        var disposition = !tracked.IsPending ? RelayApprovalDisposition.AlreadyResolved :
            now >= approval.ExpiresAtUtc || now >= snapshot.PendingExpiresAtUtc ? RelayApprovalDisposition.Expired :
            approval.PolicyRevision != current.PolicyRevision ? RelayApprovalDisposition.Rejected :
            approval.Decision == ParentDecisionKind.Deny ? RelayApprovalDisposition.Denied : RelayApprovalDisposition.Allowed;
        RelayPolicyLedgerEntry? policy = null;
        RelayReconcileIntent? intent = null;
        if (disposition == RelayApprovalDisposition.Allowed)
        {
            policy = new RelayPolicyLedgerEntry(checked(current.PolicyRevision + 1), approval.RequestId, approval.CommandId,
                approval.TargetKind, approval.CanonicalTargetIdentity, approval.Decision, approval.DurationMinutes, hash);
            intent = new RelayReconcileIntent(Guid.NewGuid().ToString("N"), policy.PolicyRevision, approval.CommandId, policy.ComputeDigest());
        }
        var status = disposition switch
        {
            RelayApprovalDisposition.Allowed => CommandReceiptStatus.AcceptedPendingReconciliation,
            RelayApprovalDisposition.Denied => CommandReceiptStatus.Applied,
            RelayApprovalDisposition.AlreadyResolved => CommandReceiptStatus.AlreadyResolved,
            RelayApprovalDisposition.Expired => CommandReceiptStatus.Expired,
            _ => CommandReceiptStatus.Rejected
        };
        var receipt = new CommandReceipt(current.DeviceId, current.DeviceEpoch, current.AuthorityEpoch, approval.KeyId,
            approval.Sequence, approval.CommandId, approval.RequestId, approval.RequestRevision, status, now, hash,
            policy?.PolicyRevision ?? current.PolicyRevision,
            status == CommandReceiptStatus.Applied ? ReconciliationStatus.Reconciled :
                intent == null ? ReconciliationStatus.NotRequired : ReconciliationStatus.Pending,
            disposition switch
            {
                RelayApprovalDisposition.Allowed => "policy-pending-0001",
                RelayApprovalDisposition.Denied => "request-denied-0001",
                RelayApprovalDisposition.AlreadyResolved => "request-resolved-01",
                RelayApprovalDisposition.Expired => "approval-expired-01",
                _ => "policy-changed-0001"
            });
        var signed = new DeviceSignedCommandReceiptEnvelope(receipt, offer.SigningKeyId, new byte[64]);
        byte[] signature;
        lock (signingKey) signature = signingKey.SignHash(RelayCanonicalEncoding.ComputeDeviceReceiptHash(signed),
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        signed = new DeviceSignedCommandReceiptEnvelope(receipt, offer.SigningKeyId, signature);
        var signedBytes = RelayCanonicalEncoding.EncodeDeviceReceiptEnvelope(signed);
        var record = new RelaySignedReceiptRecord(current.DeviceId, current.DeviceEpoch, approval.CommandId, approval.RequestId,
            approval.RequestRevision, current.AuthorityEpoch, approval.KeyId, approval.Sequence, status, hash, signedBytes);
        var outbox = SealReceipt(current, offer, claim, signedBytes, now);
        return current.WithCommittedApproval(new RelayApprovalTransaction(frame.Cursor, snapshot.RequestId, snapshot.RequestRevision,
            snapshotHash, disposition, new RelayReplayFloor(current.AuthorityEpoch, approval.KeyId, approval.Sequence, approval.CommandId, hash),
            policy, intent, record, outbox));
    }

    private static DeviceEnrollmentState RequireOwner(DeviceSecurityState owner, RelayTransactionState state,
        ECDiffieHellman decrypt, ECDsa sign)
    {
        if (!owner.IsProvisioned || owner.Enrollment is not { Confirmed: true, PhoneKeyConfirmed: true, Candidate: not null } session)
            throw new InvalidDataException("Confirmed native owner required.");
        var offer = session.Offer; var claim = session.Candidate;
        _ = RelayCanonicalEncoding.EncodeEnrollmentClaimForSignature(claim);
        if (owner.DeviceId != state.DeviceId || offer.DeviceEpoch != state.DeviceEpoch || offer.AuthorityEpoch != state.AuthorityEpoch ||
            !Equal(claim.GetOfferHashCopy(), RelayCanonicalEncoding.ComputeEnrollmentOfferHash(offer)) ||
            !owner.TryGetParentTrustAnchor(claim.ApprovalKeyId, out var anchor) ||
            !Equal(anchor.GetSubjectPublicKeyInfoCopy(), claim.GetApprovalKeyCopy()))
            throw new InvalidDataException("Native owner and relay state mismatch.");
        byte[] decryptSpki, signSpki;
        lock (decrypt) decryptSpki = decrypt.ExportSubjectPublicKeyInfo();
        lock (sign) signSpki = sign.ExportSubjectPublicKeyInfo();
        if (!Equal(decryptSpki.AsSpan(26), offer.GetEncryptionKeyCopy()) || !Equal(signSpki.AsSpan(26), offer.GetSigningKeyCopy()) ||
            new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, decryptSpki).KeyId != offer.EncryptionKeyId ||
            new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, signSpki).KeyId != offer.SigningKeyId ||
            new[] { offer.SigningKeyId, offer.EncryptionKeyId, claim.ApprovalKeyId, claim.EncryptionKeyId }.Distinct().Count() != 4 ||
            new[] { offer.GetSigningKeyCopy(), offer.GetEncryptionKeyCopy(), claim.GetApprovalKeyCopy()[26..], claim.GetEncryptionKeyCopy() }
                .Select(Convert.ToHexString).Distinct().Count() != 4)
            throw new InvalidDataException("Native device keys mismatch.");
        return session;
    }

    private static RelayEncryptedOutboxItem SealReceipt(RelayTransactionState state, EnrollmentOffer offer, EnrollmentKeyClaim claim,
        byte[] signedReceipt, DateTimeOffset now)
    {
        state.RecipientOutboundCursors.TryGetValue(claim.EncryptionKeyId, out var head);
        var cursor = checked(head + 1); var id = Guid.NewGuid().ToString("N");
        RelayFrame Frame(byte[] enc, byte[] cipher) => new(RelayFrameKind.Receipt, offer.MailboxId, claim.EncryptionKeyId,
            id, cursor, 0, now, now.AddDays(1), enc, cipher); // Inbound ack is a separate post-commit operation, not this recipient's cursor.
        var aad = RelayCanonicalEncoding.EncodeRelayFrameAssociatedData(Frame(Array.Empty<byte>(), Array.Empty<byte>()));
        var encrypted = RelayCryptography.Encrypt(claim.GetEncryptionKeyCopy(), signedReceipt, aad,
            "guard-relay-receipt-hpke-v1"u8.ToArray().Concat(aad).ToArray(), out var encapsulated);
        return new RelayEncryptedOutboxItem(id, checked(state.HighestOutboundCursor + 1), RelayFrameKind.Receipt,
            claim.EncryptionKeyId, cursor, RelayCanonicalEncoding.EncodeRelayFrame(Frame(encapsulated, encrypted)));
    }

    private static bool Equal(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => CryptographicOperations.FixedTimeEquals(left, right);
}
