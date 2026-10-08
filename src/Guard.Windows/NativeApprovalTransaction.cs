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
/// Native request publication and untrusted GRF1 approval to complete successor aggregates, without I/O or policy effects.
/// The service must hold its authority boundary, originate the request snapshot locally,
/// and CAS this successor before publishing the outbox or acknowledging the input.
/// Preparing a result is not a commit, application, or fresh attestation check.
/// </summary>
public static partial class NativeApprovalTransaction
{
    public static RelayTransactionState PrepareRequest(DeviceSecurityState owner, RelayTransactionState current,
        RequestSnapshot snapshot, ECDiffieHellman decryptionKey, ECDsa signingKey, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(current);
        var session = RequireOwner(owner, current, decryptionKey, signingKey);
        // Canonical copy is the single source for both the stored original and signed phone display.
        var bytes = RelayCanonicalEncoding.EncodeRequestSnapshot(snapshot);
        snapshot = RelayCanonicalEncoding.DecodeRequestSnapshot(bytes);
        if (snapshot.DeviceId != current.DeviceId || snapshot.DeviceEpoch != current.DeviceEpoch ||
            snapshot.AuthorityEpoch != current.AuthorityEpoch || snapshot.PolicyRevision != current.PolicyRevision ||
            snapshot.CreatedAtUtc < session.Offer.CreatedAtUtc || now < snapshot.CreatedAtUtc || now >= snapshot.PendingExpiresAtUtc)
            throw new InvalidDataException("Request authority, policy or time binding.");
        RequireClockFloor(current, now);
        var signed = new DeviceSignedRequestEnvelope(snapshot, session.Offer.SigningKeyId, new byte[64]);
        byte[] signature;
        lock (signingKey) signature = signingKey.SignHash(RelayCanonicalEncoding.ComputeDeviceRequestHash(signed),
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        signed = new DeviceSignedRequestEnvelope(snapshot, session.Offer.SigningKeyId, signature);
        var tracked = new RelayTrackedRequest(snapshot.RequestId, snapshot.RequestRevision,
            RelayCanonicalEncoding.ComputeRequestSnapshotHash(snapshot), snapshot.GetDecisionChallengeCopy(), encodedSnapshot: bytes);
        return current.WithPublishedRequest(tracked, Seal(current, session.Offer, session.Candidate!, RelayFrameKind.Request,
            RelayCanonicalEncoding.EncodeDeviceRequestEnvelope(signed), now, snapshot.PendingExpiresAtUtc));
    }

    public static RelayTransactionState Prepare(DeviceSecurityState owner, RelayTransactionState current,
        byte[] encodedFrame, ECDiffieHellman decryptionKey, ECDsa signingKey, DateTimeOffset now)
        => Prepare(owner, current, encodedFrame, decryptionKey, signingKey, now, out _);

    // The caller must recheck this exclusive deadline at the actual durable commit.
    public static RelayTransactionState Prepare(DeviceSecurityState owner, RelayTransactionState current,
        byte[] encodedFrame, ECDiffieHellman decryptionKey, ECDsa signingKey, DateTimeOffset now, out DateTimeOffset validUntilUtc)
    {
        ArgumentNullException.ThrowIfNull(current);
        var session = RequireOwner(owner, current, decryptionKey, signingKey);
        var offer = session.Offer;
        var claim = session.Candidate!;
        var frame = RelayCanonicalEncoding.DecodeRelayFrame(encodedFrame);
        if (frame.Kind != RelayFrameKind.Approval || frame.MailboxId != offer.MailboxId ||
            frame.RecipientKeyId != offer.EncryptionKeyId || frame.AckCursor != 0 ||
            current.CommittedInboundCursor >= RelayTransactionState.MaximumRecipientCursor ||
            frame.Cursor <= current.CommittedInboundCursor || frame.Cursor > RelayTransactionState.MaximumRecipientCursor ||
            now < frame.CreatedAtUtc || now >= frame.ExpiresAtUtc ||
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

        var tracked = current.TrackedRequests.SingleOrDefault(r => r.RequestId == approval.RequestId &&
            r.RequestRevision == approval.RequestRevision && Equal(r.GetSnapshotHashCopy(), approval.GetRequestSnapshotHashCopy()));
        if (tracked == null || tracked.GetEncodedSnapshotCopy().Length == 0)
            throw new InvalidDataException("Original durable request snapshot required; legacy metadata cannot authorize.");
        var snapshot = RelayCanonicalEncoding.DecodeRequestSnapshot(tracked.GetEncodedSnapshotCopy());
        var snapshotHash = RelayCanonicalEncoding.ComputeRequestSnapshotHash(snapshot);
        if (!Equal(tracked.GetSnapshotHashCopy(), snapshotHash) || !Equal(tracked.GetDecisionChallengeCopy(), snapshot.GetDecisionChallengeCopy()) ||
            snapshot.DeviceId != current.DeviceId || snapshot.DeviceEpoch != current.DeviceEpoch ||
            snapshot.AuthorityEpoch != current.AuthorityEpoch || approval.RequestId != snapshot.RequestId ||
            approval.RequestRevision != snapshot.RequestRevision || !Equal(approval.GetRequestSnapshotHashCopy(), snapshotHash) ||
            !Equal(approval.GetDecisionChallengeCopy(), snapshot.GetDecisionChallengeCopy()) ||
            approval.TargetKind != snapshot.TargetKind || approval.CanonicalTargetIdentity != snapshot.CanonicalTargetIdentity ||
            approval.PolicyRevision != snapshot.PolicyRevision || approval.IssuedAtUtc < snapshot.CreatedAtUtc ||
            approval.IssuedAtUtc < offer.CreatedAtUtc || now < approval.IssuedAtUtc ||
            approval.ExpiresAtUtc > snapshot.PendingExpiresAtUtc)
            throw new InvalidDataException("Approval request binding or time.");
        RequireClockFloor(current, now);
        current.TryGetReplayFloor(current.AuthorityEpoch, approval.KeyId, out var floor);
        var saved = current.SignedReceipts.SingleOrDefault(r => r.CommandId == approval.CommandId);
        if (saved != null)
        {
            if (floor == null || floor.HighestAcceptedSequence < approval.Sequence ||
                (floor.HighestAcceptedSequence == approval.Sequence &&
                    (floor.CommandId != approval.CommandId || !Equal(floor.GetApprovalHashCopy(), hash))))
                throw new InvalidDataException("Repeated approval does not match its durable replay floor.");
            RequireSavedReceipt(saved, approval, hash, offer.SigningKeyId, signingKey);
            validUntilUtc = frame.ExpiresAtUtc; // This resends history; expired decisions never acquire a new lifetime.
            return current.WithRedeliveredReceipt(frame.Cursor, Seal(current, offer, claim, RelayFrameKind.Receipt,
                saved.GetSignedReceiptCopy(), now, now.AddDays(1)));
        }
        // Relay TTL can remove transport positions. Only a fully verified command (or exact signed
        // history above) advances the cursor; the authoritative per-key sequence stays gap-free.
        var nextSequence = floor != null ? checked(floor.HighestAcceptedSequence + 1) : 1;
        if (approval.Sequence != nextSequence)
            throw new InvalidDataException("Approval replay or sequence gap.");
        if (floor != null && current.SignedReceipts.LastOrDefault(r => r.ApprovalKeyId == approval.KeyId &&
            r.Sequence == floor.HighestAcceptedSequence)?.Status == CommandReceiptStatus.AcceptedPendingReconciliation)
            throw new InvalidDataException("Previous approval still awaits reconciliation.");

        var disposition = !tracked.IsPending ? RelayApprovalDisposition.AlreadyResolved :
            now >= approval.ExpiresAtUtc || now >= snapshot.PendingExpiresAtUtc ? RelayApprovalDisposition.Expired :
            approval.PolicyRevision != current.PolicyRevision ? RelayApprovalDisposition.Rejected :
            approval.Decision == ParentDecisionKind.Deny ? RelayApprovalDisposition.Denied : RelayApprovalDisposition.Allowed;
        validUntilUtc = frame.ExpiresAtUtc;
        if (disposition is RelayApprovalDisposition.Allowed or RelayApprovalDisposition.Denied)
        {
            if (approval.ExpiresAtUtc < validUntilUtc) validUntilUtc = approval.ExpiresAtUtc;
            if (snapshot.PendingExpiresAtUtc < validUntilUtc) validUntilUtc = snapshot.PendingExpiresAtUtc;
        }
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
            approval.Sequence, approval.CommandId, approval.RequestId, approval.RequestRevision, status, MillisecondTime(now), hash,
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
        var outbox = Seal(current, offer, claim, RelayFrameKind.Receipt, signedBytes, now, now.AddDays(1));
        return current.WithCommittedApproval(new RelayApprovalTransaction(frame.Cursor, snapshot.RequestId, snapshot.RequestRevision,
            snapshotHash, disposition, new RelayReplayFloor(current.AuthorityEpoch, approval.KeyId, approval.Sequence, approval.CommandId, hash),
            policy, intent, record, outbox));
    }

    private static void RequireSavedReceipt(RelaySignedReceiptRecord saved, SignedApprovalEnvelope approval,
        byte[] hash, string signingKeyId, ECDsa signingKey)
    {
        if (saved.DeviceId != approval.DeviceId || saved.DeviceEpoch != approval.DeviceEpoch ||
            saved.AuthorityEpoch != approval.AuthorityEpoch || saved.ApprovalKeyId != approval.KeyId ||
            saved.Sequence != approval.Sequence || saved.RequestId != approval.RequestId ||
            saved.RequestRevision != approval.RequestRevision || !Equal(saved.GetApprovalHashCopy(), hash))
            throw new InvalidDataException("Conflicting repeated approval.");
        var envelope = RelayCanonicalEncoding.DecodeDeviceReceiptEnvelope(saved.GetSignedReceiptCopy());
        var receipt = envelope.Receipt;
        if (envelope.DeviceKeyId != signingKeyId || receipt.DeviceId != saved.DeviceId || receipt.DeviceEpoch != saved.DeviceEpoch ||
            receipt.AuthorityEpoch != saved.AuthorityEpoch || receipt.KeyId != saved.ApprovalKeyId || receipt.Sequence != saved.Sequence ||
            receipt.CommandId != saved.CommandId || receipt.RequestId != saved.RequestId || receipt.RequestRevision != saved.RequestRevision ||
            receipt.Status != saved.Status || !Equal(receipt.GetApprovalHashCopy(), hash) || receipt.ProcessedAtUtc < approval.IssuedAtUtc)
            throw new InvalidDataException("Stored receipt binding.");
        lock (signingKey)
            if (!signingKey.VerifyHash(RelayCanonicalEncoding.ComputeDeviceReceiptHash(envelope), envelope.GetSignatureP1363Copy(),
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                throw new InvalidDataException("Stored receipt signature.");
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

    private static RelayEncryptedOutboxItem Seal(RelayTransactionState state, EnrollmentOffer offer, EnrollmentKeyClaim claim,
        RelayFrameKind kind, byte[] signedPayload, DateTimeOffset now, DateTimeOffset expires)
    {
        state.RecipientOutboundCursors.TryGetValue(claim.EncryptionKeyId, out var head);
        var cursor = checked(head + 1); var id = Guid.NewGuid().ToString("N");
        RelayFrame Frame(byte[] enc, byte[] cipher) => new(kind, offer.MailboxId, claim.EncryptionKeyId,
            id, cursor, 0, MillisecondTime(now), MillisecondTime(expires), enc, cipher); // Inbound ack is a separate post-commit operation, not this recipient's cursor.
        var aad = RelayCanonicalEncoding.EncodeRelayFrameAssociatedData(Frame(Array.Empty<byte>(), Array.Empty<byte>()));
        var domain = kind == RelayFrameKind.Request ? "guard-relay-request-hpke-v1"u8.ToArray() : "guard-relay-receipt-hpke-v1"u8.ToArray();
        var encrypted = RelayCryptography.Encrypt(claim.GetEncryptionKeyCopy(), signedPayload, aad,
            domain.Concat(aad).ToArray(), out var encapsulated);
        return new RelayEncryptedOutboxItem(id, checked(state.HighestOutboundCursor + 1), kind,
            claim.EncryptionKeyId, cursor, RelayCanonicalEncoding.EncodeRelayFrame(Frame(encapsulated, encrypted)));
    }

    private static void RequireClockFloor(RelayTransactionState current, DateTimeOffset now)
    {
        // Stored response time is a local rollback floor, not a hardware-backed trusted clock.
        foreach (var saved in current.SignedReceipts)
            if (now < RelayCanonicalEncoding.DecodeDeviceReceiptEnvelope(saved.GetSignedReceiptCopy()).Receipt.ProcessedAtUtc)
                throw new InvalidDataException("Relay clock rollback.");
    }

    private static bool Equal(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => CryptographicOperations.FixedTimeEquals(left, right);

    // Wire timestamps are milliseconds; truncate only encoded fields, never the clock
    // used for deadline/rollback checks. Rounding up would extend authorization.
    private static DateTimeOffset MillisecondTime(DateTimeOffset value) =>
        DateTimeOffset.FromUnixTimeMilliseconds(value.ToUnixTimeMilliseconds());
}
