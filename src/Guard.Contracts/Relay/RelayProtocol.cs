using System;
using System.Collections.Generic;

namespace Guard.Contracts.Relay
{
    public static class RelayProtocol
    {
        public const int Version = 1;
        public const int MaximumFrameBytes = 64 * 1024;
        public const int MaximumEvidenceFields = 8;
        public const int MaximumEvidenceNameBytes = 48;
        public const int MaximumEvidenceValueBytes = 512;
        public const int MaximumReasonBytes = 280;
        public const int MaximumIdentityBytes = 2048;
        public const int ChallengeBytes = 32;
        public const int Sha256Bytes = 32;
        public const int MaximumCiphertextBytes = 60 * 1024;
        public const int MaximumSignatureBytes = 64;
        public const int HpkeEncapsulatedKeyBytes = 65;
        public const int MinimumCiphertextBytes = 16;
        public const int MaximumSnapshotLifetimeDays = 7;
        public const int MaximumApprovalLifetimeMinutes = 15;
        public const int MaximumFrameLifetimeDays = 7;
    }

    public enum RelayTargetKind
    {
        Unknown = 0,
        Website = 1,
        Application = 2
    }

    public enum ParentDecisionKind
    {
        Unknown = 0,
        AllowAlways = 1,
        AllowTemporary = 2,
        AllowDailyQuota = 3,
        Deny = 4
    }

    public enum RelayFrameKind
    {
        Unknown = 0,
        Request = 1,
        Approval = 2,
        Receipt = 3,
        SigningIntent = 4
    }

    public sealed class RelayEvidenceField
    {
        public RelayEvidenceField(string name, string value)
        {
            Name = name;
            Value = value;
        }

        public string Name { get; private set; }

        public string Value { get; private set; }
    }

    public sealed class RequestSnapshot
    {
        private readonly byte[] _decisionChallenge;
        private readonly IReadOnlyList<RelayEvidenceField> _displayEvidence;
        public RequestSnapshot(
            string deviceId,
            long deviceEpoch,
            long authorityEpoch,
            string deviceEventId,
            string requestId,
            long requestRevision,
            RelayTargetKind targetKind,
            string canonicalTargetIdentity,
            IReadOnlyList<RelayEvidenceField> displayEvidence,
            string childReason,
            DateTimeOffset createdAtUtc,
            DateTimeOffset pendingExpiresAtUtc,
            byte[] decisionChallenge,
            long policyRevision)
        {
            DeviceId = deviceId;
            DeviceEpoch = deviceEpoch;
            AuthorityEpoch = authorityEpoch;
            DeviceEventId = deviceEventId;
            RequestId = requestId;
            RequestRevision = requestRevision;
            TargetKind = targetKind;
            CanonicalTargetIdentity = canonicalTargetIdentity;
            _displayEvidence = new List<RelayEvidenceField>(displayEvidence ?? throw new ArgumentNullException(nameof(displayEvidence))).AsReadOnly();
            ChildReason = childReason;
            CreatedAtUtc = createdAtUtc;
            PendingExpiresAtUtc = pendingExpiresAtUtc;
            _decisionChallenge = Copy(decisionChallenge);
            PolicyRevision = policyRevision;
        }
        public string DeviceId { get; private set; }

        public string DeviceEventId { get; private set; }

        public long DeviceEpoch { get; private set; }

        public long AuthorityEpoch { get; private set; }

        public string RequestId { get; private set; }
        public long RequestRevision { get; private set; }
        public RelayTargetKind TargetKind { get; private set; }
        public string CanonicalTargetIdentity { get; private set; }
        public IReadOnlyList<RelayEvidenceField> DisplayEvidence
        {
            get { return _displayEvidence; }
        }

        public string ChildReason { get; private set; }
        public DateTimeOffset CreatedAtUtc { get; private set; }
        public DateTimeOffset PendingExpiresAtUtc { get; private set; }
        public long PolicyRevision { get; private set; }
        public byte[] GetDecisionChallengeCopy()
        {
            return Copy(_decisionChallenge);
        }

        private static byte[] Copy(byte[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            var copy = new byte[value.Length];
            Buffer.BlockCopy(value, 0, copy, 0, value.Length);
            return copy;
        }
    }

    public sealed class SignedApprovalEnvelope
    {
        private readonly byte[] _requestSnapshotHash;
        private readonly byte[] _signature;
        private readonly byte[] _decisionChallenge;

        public SignedApprovalEnvelope(
            long authorityEpoch,
            string keyId,
            long sequence,
            string commandId,
            string nonce,
            DateTimeOffset issuedAtUtc,
            DateTimeOffset expiresAtUtc,
            string deviceId,
            long deviceEpoch,
            string requestId,
            long requestRevision,
            byte[] requestSnapshotHash,
            byte[] decisionChallenge,
            RelayTargetKind targetKind,
            string canonicalTargetIdentity,
            long policyRevision,
            ParentDecisionKind decision,
            int durationMinutes,
            byte[] signatureP1363)
        {
            AuthorityEpoch = authorityEpoch;
            KeyId = keyId;
            Sequence = sequence;
            CommandId = commandId;
            Nonce = nonce;
            IssuedAtUtc = issuedAtUtc;
            ExpiresAtUtc = expiresAtUtc;
            DeviceId = deviceId;
            DeviceEpoch = deviceEpoch;
            RequestId = requestId;
            RequestRevision = requestRevision;
            _requestSnapshotHash = Copy(requestSnapshotHash);
            _decisionChallenge = Copy(decisionChallenge);
            TargetKind = targetKind;
            CanonicalTargetIdentity = canonicalTargetIdentity;
            PolicyRevision = policyRevision;
            Decision = decision;
            DurationMinutes = durationMinutes;
            _signature = Copy(signatureP1363);
        }
        public long AuthorityEpoch { get; private set; }
        public string KeyId { get; private set; }
        public long Sequence { get; private set; }
        public string CommandId { get; private set; }
        public string Nonce { get; private set; }
        public DateTimeOffset IssuedAtUtc { get; private set; }
        public DateTimeOffset ExpiresAtUtc { get; private set; }
        public string DeviceId { get; private set; }
        public long DeviceEpoch { get; private set; }
        public string RequestId { get; private set; }
        public long RequestRevision { get; private set; }
        public RelayTargetKind TargetKind { get; private set; }
        public string CanonicalTargetIdentity { get; private set; }
        public long PolicyRevision { get; private set; }
        public ParentDecisionKind Decision { get; private set; }
        public int DurationMinutes { get; private set; }
        public byte[] GetRequestSnapshotHashCopy()
        {
            return Copy(_requestSnapshotHash);
        }

        public byte[] GetDecisionChallengeCopy()
        {
            return Copy(_decisionChallenge);
        }

        public byte[] GetSignatureP1363Copy()
        {
            return Copy(_signature);
        }

        private static byte[] Copy(byte[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            var copy = new byte[value.Length];
            Buffer.BlockCopy(value, 0, copy, 0, value.Length);
            return copy;
        }
    }

    public sealed class DeviceSignedRequestEnvelope
    {
        private readonly byte[] _signature;

        public DeviceSignedRequestEnvelope(RequestSnapshot snapshot, string deviceKeyId, byte[] signatureP1363)
        {
            Snapshot = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
            DeviceKeyId = deviceKeyId;
            _signature = Copy(signatureP1363);
        }
        public RequestSnapshot Snapshot { get; private set; }
        public string DeviceKeyId { get; private set; }
        public byte[] GetSignatureP1363Copy()
        {
            return Copy(_signature);
        }

        private static byte[] Copy(byte[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            var copy = new byte[value.Length];
            Buffer.BlockCopy(value, 0, copy, 0, value.Length);
            return copy;
        }
    }

    public enum CommandReceiptStatus
    {
        Unknown = 0,
        Applied = 1,
        AlreadyResolved = 2,
        Rejected = 3,
        Expired = 4,
        AcceptedPendingReconciliation = 5
    }

    public enum ReconciliationStatus
    {
        Unknown = 0,
        NotRequired = 1,
        Pending = 2,
        Reconciled = 3,
        Failed = 4
    }

    public sealed class CommandReceipt
    {
        private readonly byte[] _approvalHash;

        public CommandReceipt(
            string deviceId,
            long deviceEpoch,
            long authorityEpoch,
            string keyId,
            long sequence,
            string commandId,
            string requestId,
            long requestRevision,
            CommandReceiptStatus status,
            DateTimeOffset processedAtUtc,
            byte[] approvalHash,
            long committedPolicyRevision,
            ReconciliationStatus reconciliationStatus,
            string detailCode)
        {
            DeviceId = deviceId;
            DeviceEpoch = deviceEpoch;
            AuthorityEpoch = authorityEpoch;
            KeyId = keyId;
            Sequence = sequence;
            CommandId = commandId;
            RequestId = requestId;
            RequestRevision = requestRevision;
            Status = status;
            ProcessedAtUtc = processedAtUtc;
            _approvalHash = Copy(approvalHash);
            CommittedPolicyRevision = committedPolicyRevision;
            ReconciliationStatus = reconciliationStatus;
            DetailCode = detailCode;
        }
        public string DeviceId { get; private set; }

        public long DeviceEpoch { get; private set; }

        public long AuthorityEpoch { get; private set; }

        public string KeyId { get; private set; }
        public long Sequence { get; private set; }
        public string CommandId { get; private set; }
        public string RequestId { get; private set; }
        public long RequestRevision { get; private set; }
        public CommandReceiptStatus Status { get; private set; }
        public DateTimeOffset ProcessedAtUtc { get; private set; }
        public long CommittedPolicyRevision { get; private set; }
        public ReconciliationStatus ReconciliationStatus { get; private set; }
        public string DetailCode { get; private set; }
        public byte[] GetApprovalHashCopy()
        {
            return Copy(_approvalHash);
        }

        private static byte[] Copy(byte[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            var copy = new byte[value.Length];
            Buffer.BlockCopy(value, 0, copy, 0, value.Length);
            return copy;
        }
    }

    public sealed class DeviceSignedCommandReceiptEnvelope
    {
        private readonly byte[] _signature;

        public DeviceSignedCommandReceiptEnvelope(CommandReceipt receipt, string deviceKeyId, byte[] signatureP1363)
        {
            Receipt = receipt ?? throw new ArgumentNullException(nameof(receipt));
            DeviceKeyId = deviceKeyId;
            _signature = Copy(signatureP1363);
        }
        public CommandReceipt Receipt { get; private set; }
        public string DeviceKeyId { get; private set; }
        public byte[] GetSignatureP1363Copy()
        {
            return Copy(_signature);
        }

        private static byte[] Copy(byte[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            var copy = new byte[value.Length];
            Buffer.BlockCopy(value, 0, copy, 0, value.Length);
            return copy;
        }
    }

    public sealed class RelayFrame
    {
        private readonly byte[] _encapsulatedKey;
        private readonly byte[] _ciphertext;

        public RelayFrame(
            RelayFrameKind kind,
            string mailboxId,
            string recipientKeyId,
            string frameId,
            long cursor,
            long ackCursor,
            DateTimeOffset createdAtUtc,
            DateTimeOffset expiresAtUtc,
            byte[] encapsulatedKey,
            byte[] ciphertext)
        {
            Kind = kind;
            MailboxId = mailboxId;
            RecipientKeyId = recipientKeyId;
            FrameId = frameId;
            Cursor = cursor;
            AckCursor = ackCursor;
            CreatedAtUtc = createdAtUtc;
            ExpiresAtUtc = expiresAtUtc;
            _encapsulatedKey = Copy(encapsulatedKey);
            _ciphertext = Copy(ciphertext);
        }
        public RelayFrameKind Kind { get; private set; }
        public string MailboxId { get; private set; }
        public string RecipientKeyId { get; private set; }
        public string FrameId { get; private set; }
        public long Cursor { get; private set; }
        public long AckCursor { get; private set; }
        public DateTimeOffset CreatedAtUtc { get; private set; }
        public DateTimeOffset ExpiresAtUtc { get; private set; }
        public byte[] GetEncapsulatedKeyCopy()
        {
            return Copy(_encapsulatedKey);
        }

        public byte[] GetCiphertextCopy()
        {
            return Copy(_ciphertext);
        }

        private static byte[] Copy(byte[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            var copy = new byte[value.Length];
            Buffer.BlockCopy(value, 0, copy, 0, value.Length);
            return copy;
        }
    }
}
