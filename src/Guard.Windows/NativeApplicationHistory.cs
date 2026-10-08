using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Guard.Application;
using Guard.Contracts;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Domain.Relay;
using Guard.Protocol.Relay;

namespace Guard.Windows;

public static partial class NativeApprovalTransaction
{
    // Read-only projection from one owner-bound local aggregate. No delivery, acknowledgement or grant.
    public static ApplicationRequestHistoryPayload ReadApplicationHistory(DeviceSecurityState owner, RelayTransactionState current,
        AuthenticatedChildContext caller, ECDiffieHellman decryptionKey, ECDsa signingKey, DateTimeOffset now)
    {
        var session = RequireOwner(owner, current, decryptionKey, signingKey);
        if (owner.DeviceId != caller.DeviceId || owner.ChildAccountSid == null || !owner.ChildAccountSid.Equals(caller.ChildAccountSid))
            throw new InvalidDataException("History requires the bound authenticated account.");
        RequireClockFloor(current, now);
        var result = new List<ApplicationRequestHistoryItem>();
        foreach (var tracked in current.TrackedRequests)
        {
            var bytes = tracked.GetEncodedSnapshotCopy();
            if (bytes.Length == 0) continue; // Legacy metadata cannot identify an account or display a request.
            var original = RelayCanonicalEncoding.DecodeRequestSnapshot(bytes);
            if (original.RequestId != tracked.RequestId || original.RequestRevision != tracked.RequestRevision ||
                !Equal(tracked.GetSnapshotHashCopy(), RelayCanonicalEncoding.ComputeRequestSnapshotHash(original)) ||
                !Equal(tracked.GetDecisionChallengeCopy(), original.GetDecisionChallengeCopy()))
                throw new InvalidDataException("History original mismatch.");
            if (original.DeviceId != current.DeviceId || original.DeviceEpoch != current.DeviceEpoch ||
                original.AuthorityEpoch != current.AuthorityEpoch || original.TargetKind != RelayTargetKind.Application ||
                original.DisplayEvidence.SingleOrDefault(e => e.Name == "child-account")?.Value != caller.ChildAccountSid.Value)
                continue;
            if (original.CreatedAtUtc < session.Offer.CreatedAtUtc || now < original.CreatedAtUtc)
                throw new InvalidDataException("History clock or enrollment mismatch.");
            var name = original.DisplayEvidence.SingleOrDefault(e => e.Name == "application-name")?.Value
                ?? throw new InvalidDataException("History name missing.");
            var status = now >= original.PendingExpiresAtUtc ? ApplicationRequestHistoryStatus.Expired : ApplicationRequestHistoryStatus.AwaitingResponse;
            var recorded = original.CreatedAtUtc;
            var saved = tracked.IsPending
                ? current.SignedReceipts.LastOrDefault(r => r.RequestId == tracked.RequestId && r.RequestRevision == tracked.RequestRevision)
                : current.SignedReceipts.SingleOrDefault(r => r.CommandId == tracked.ResolvedCommandId);
            if (saved == null && !tracked.IsPending) throw new InvalidDataException("Resolved history receipt missing.");
            if (saved != null)
            {
                var envelope = RelayCanonicalEncoding.DecodeDeviceReceiptEnvelope(saved.GetSignedReceiptCopy());
                var receipt = envelope.Receipt;
                if (envelope.DeviceKeyId != session.Offer.SigningKeyId || saved.DeviceId != current.DeviceId ||
                    saved.DeviceEpoch != current.DeviceEpoch || saved.AuthorityEpoch != current.AuthorityEpoch ||
                    saved.RequestId != tracked.RequestId || saved.RequestRevision != tracked.RequestRevision ||
                    saved.ApprovalKeyId != session.Candidate!.ApprovalKeyId || receipt.DeviceId != saved.DeviceId ||
                    receipt.DeviceEpoch != saved.DeviceEpoch || receipt.AuthorityEpoch != saved.AuthorityEpoch ||
                    receipt.KeyId != saved.ApprovalKeyId || receipt.Sequence != saved.Sequence || receipt.CommandId != saved.CommandId ||
                    receipt.RequestId != saved.RequestId || receipt.RequestRevision != saved.RequestRevision || receipt.Status != saved.Status ||
                    !Equal(receipt.GetApprovalHashCopy(), saved.GetApprovalHashCopy()) ||
                    (!tracked.IsPending && !Equal(tracked.GetApprovalHashCopy(), saved.GetApprovalHashCopy())) ||
                    receipt.ProcessedAtUtc < original.CreatedAtUtc || receipt.ProcessedAtUtc > now ||
                    receipt.CommittedPolicyRevision > current.PolicyRevision)
                    throw new InvalidDataException("History receipt mismatch.");
                lock (signingKey)
                    if (!signingKey.VerifyHash(RelayCanonicalEncoding.ComputeDeviceReceiptHash(envelope), envelope.GetSignatureP1363Copy(),
                        DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw new InvalidDataException("History receipt signature.");
                recorded = receipt.ProcessedAtUtc;
                status = tracked.Resolution switch
                {
                    RelayRequestResolution.Denied when receipt.Status == CommandReceiptStatus.Applied &&
                        receipt.ReconciliationStatus == ReconciliationStatus.Reconciled => ApplicationRequestHistoryStatus.Denied,
                    RelayRequestResolution.Allowed when receipt.Status == CommandReceiptStatus.AcceptedPendingReconciliation &&
                        receipt.ReconciliationStatus == ReconciliationStatus.Pending => ApplicationRequestHistoryStatus.AwaitingApplication,
                    RelayRequestResolution.Allowed when receipt.Status == CommandReceiptStatus.Applied &&
                        receipt.ReconciliationStatus == ReconciliationStatus.Reconciled => ApplicationRequestHistoryStatus.AppliedPreviously,
                    _ when receipt.Status is CommandReceiptStatus.Rejected or CommandReceiptStatus.Expired =>
                        now >= original.PendingExpiresAtUtc ? ApplicationRequestHistoryStatus.Expired : ApplicationRequestHistoryStatus.NotApplied,
                    _ => throw new InvalidDataException("History resolution mismatch.")
                };
            }
            result.Add(new ApplicationRequestHistoryItem(original.RequestId, name, original.CreatedAtUtc, recorded, status));
        }
        return new ApplicationRequestHistoryPayload(now, result.OrderByDescending(r => r.CreatedAtUtc)
            .ThenBy(r => r.RequestId, StringComparer.Ordinal).Take(ApplicationRequestHistoryPayload.MaximumItems).ToArray());
    }
}
