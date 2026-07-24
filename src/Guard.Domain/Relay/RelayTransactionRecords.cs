using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Guard.Contracts;
using Guard.Contracts.Relay;
using RelayParentDecisionKind = Guard.Contracts.Relay.ParentDecisionKind;

namespace Guard.Domain.Relay
{
    public enum RelayRequestResolution
    {
        Pending = 0,
        Allowed = 1,
        Denied = 2
    }

    public enum RelayApprovalDisposition
    {
        Allowed = 1,
        Denied = 2,
        AlreadyResolved = 3,
        Rejected = 4,
        Expired = 5
    }

    public sealed class RelayTrackedRequest
    {
        private readonly byte[] _snapshotHash;
        private readonly byte[] _decisionChallenge;
        private readonly byte[] _approvalHash;

        public RelayTrackedRequest(
            string requestId,
            long requestRevision,
            byte[] snapshotHash,
            byte[] decisionChallenge,
            RelayRequestResolution resolution = RelayRequestResolution.Pending,
            string? resolvedCommandId = null,
            byte[]? approvalHash = null)
        {
            RequireToken(requestId, nameof(requestId));
            if (requestRevision <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(requestRevision));
            }

            RequireSha256(snapshotHash, nameof(snapshotHash));
            RequireChallenge(decisionChallenge, nameof(decisionChallenge));
            if (!Enum.IsDefined(typeof(RelayRequestResolution), resolution))
            {
                throw new ArgumentOutOfRangeException(nameof(resolution));
            }

            if (resolution == RelayRequestResolution.Pending)
            {
                if (resolvedCommandId != null || approvalHash != null)
                {
                    throw new ArgumentException(
                        "A pending relay request cannot contain resolution evidence.");
                }
            }
            else
            {
                RequireToken(resolvedCommandId, nameof(resolvedCommandId));
                RequireSha256(approvalHash, nameof(approvalHash));
            }

            RequestId = requestId;
            RequestRevision = requestRevision;
            Resolution = resolution;
            ResolvedCommandId = resolvedCommandId;
            _snapshotHash = Copy(snapshotHash);
            _decisionChallenge = Copy(decisionChallenge);
            _approvalHash = approvalHash == null ? Array.Empty<byte>() : Copy(approvalHash);
        }

        public string RequestId { get; }

        public long RequestRevision { get; }

        public RelayRequestResolution Resolution { get; }

        public string? ResolvedCommandId { get; }

        public bool IsPending => Resolution == RelayRequestResolution.Pending;

        public byte[] GetSnapshotHashCopy()
        {
            return Copy(_snapshotHash);
        }

        public byte[] GetDecisionChallengeCopy()
        {
            return Copy(_decisionChallenge);
        }

        public byte[] GetApprovalHashCopy()
        {
            return Copy(_approvalHash);
        }

        public RelayTrackedRequest Resolve(
            RelayRequestResolution resolution,
            string commandId,
            byte[] approvalHash)
        {
            if (!IsPending)
            {
                throw new InvalidOperationException("The relay request is already resolved.");
            }

            if (resolution == RelayRequestResolution.Pending)
            {
                throw new ArgumentOutOfRangeException(nameof(resolution));
            }

            return new RelayTrackedRequest(
                RequestId,
                RequestRevision,
                _snapshotHash,
                _decisionChallenge,
                resolution,
                commandId,
                approvalHash);
        }

        private static void RequireChallenge(byte[]? value, string parameterName)
        {
            if (value == null || value.Length != RelayProtocol.ChallengeBytes)
            {
                throw new ArgumentException(
                    "A complete relay decision challenge is required.",
                    parameterName);
            }
        }

        internal static void RequireSha256(byte[]? value, string parameterName)
        {
            if (value == null || value.Length != RelayProtocol.Sha256Bytes)
            {
                throw new ArgumentException(
                    "A complete SHA-256 value is required.",
                    parameterName);
            }
        }

        internal static void RequireToken(string? value, string parameterName)
        {
            if (value == null || !GuardIdentifier.IsCanonicalToken(value))
            {
                throw new ArgumentException(
                    "A canonical relay identifier is required.",
                    parameterName);
            }
        }

        internal static byte[] Copy(byte[] value)
        {
            var copy = new byte[value.Length];
            Buffer.BlockCopy(value, 0, copy, 0, value.Length);
            return copy;
        }
    }

    public sealed class RelayReplayFloor
    {
        private readonly byte[] _approvalHash;

        public RelayReplayFloor(
            long authorityEpoch,
            string approvalKeyId,
            long highestAcceptedSequence,
            string commandId,
            byte[] approvalHash)
        {
            if (authorityEpoch <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
            }

            RelayTrackedRequest.RequireToken(approvalKeyId, nameof(approvalKeyId));
            if (highestAcceptedSequence <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(highestAcceptedSequence));
            }

            RelayTrackedRequest.RequireToken(commandId, nameof(commandId));
            RelayTrackedRequest.RequireSha256(approvalHash, nameof(approvalHash));
            AuthorityEpoch = authorityEpoch;
            ApprovalKeyId = approvalKeyId;
            HighestAcceptedSequence = highestAcceptedSequence;
            CommandId = commandId;
            _approvalHash = RelayTrackedRequest.Copy(approvalHash);
        }

        public long AuthorityEpoch { get; }

        public string ApprovalKeyId { get; }

        public long HighestAcceptedSequence { get; }

        public string CommandId { get; }

        public byte[] GetApprovalHashCopy()
        {
            return RelayTrackedRequest.Copy(_approvalHash);
        }

    }

    public sealed class RelayPolicyLedgerEntry
    {
        public const int MaximumDecisionDurationMinutes = 24 * 60;

        private readonly byte[] _approvalHash;

        public RelayPolicyLedgerEntry(
            long policyRevision,
            string requestId,
            string commandId,
            RelayTargetKind targetKind,
            string canonicalTargetIdentity,
            RelayParentDecisionKind decision,
            int durationMinutes,
            byte[] approvalHash)
        {
            if (policyRevision <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(policyRevision));
            }

            RelayTrackedRequest.RequireToken(requestId, nameof(requestId));
            RelayTrackedRequest.RequireToken(commandId, nameof(commandId));
            if (targetKind != RelayTargetKind.Website &&
                targetKind != RelayTargetKind.Application)
            {
                throw new ArgumentOutOfRangeException(nameof(targetKind));
            }

            RequireBoundedIdentity(canonicalTargetIdentity);
            if (decision != RelayParentDecisionKind.AllowAlways &&
                decision != RelayParentDecisionKind.AllowTemporary &&
                decision != RelayParentDecisionKind.AllowDailyQuota)
            {
                throw new ArgumentOutOfRangeException(nameof(decision));
            }

            if (decision == RelayParentDecisionKind.AllowTemporary ||
                decision == RelayParentDecisionKind.AllowDailyQuota)
            {
                if (durationMinutes <= 0 ||
                    durationMinutes > MaximumDecisionDurationMinutes)
                {
                    throw new ArgumentOutOfRangeException(nameof(durationMinutes));
                }
            }
            else if (durationMinutes != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(durationMinutes));
            }

            RelayTrackedRequest.RequireSha256(approvalHash, nameof(approvalHash));
            PolicyRevision = policyRevision;
            RequestId = requestId;
            CommandId = commandId;
            TargetKind = targetKind;
            CanonicalTargetIdentity = canonicalTargetIdentity;
            Decision = decision;
            DurationMinutes = durationMinutes;
            _approvalHash = RelayTrackedRequest.Copy(approvalHash);
        }

        public long PolicyRevision { get; }

        public string RequestId { get; }

        public string CommandId { get; }

        public RelayTargetKind TargetKind { get; }

        public string CanonicalTargetIdentity { get; }

        public RelayParentDecisionKind Decision { get; }

        public int DurationMinutes { get; }

        public byte[] GetApprovalHashCopy()
        {
            return RelayTrackedRequest.Copy(_approvalHash);
        }

        public byte[] ComputeDigest()
        {
            using (var stream = new MemoryStream())
            {
                WriteInt64(stream, PolicyRevision);
                WriteString(stream, RequestId);
                WriteString(stream, CommandId);
                WriteInt32(stream, (int)TargetKind);
                WriteString(stream, CanonicalTargetIdentity);
                WriteInt32(stream, (int)Decision);
                WriteInt32(stream, DurationMinutes);
                stream.Write(_approvalHash, 0, _approvalHash.Length);
                using (var sha256 = SHA256.Create())
                {
                    return sha256.ComputeHash(stream.ToArray());
                }
            }
        }

        private static void RequireBoundedIdentity(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException(
                    "A canonical target identity is required.",
                    nameof(value));
            }

            byte[] encoded;
            try
            {
                encoded = new UTF8Encoding(false, true).GetBytes(value);
            }
            catch (EncoderFallbackException exception)
            {
                throw new ArgumentException(
                    "The canonical target identity must be valid UTF-8.",
                    nameof(value),
                    exception);
            }

            if (encoded.Length == 0 ||
                encoded.Length > RelayProtocol.MaximumIdentityBytes)
            {
                throw new ArgumentException(
                    "The canonical target identity is oversized.",
                    nameof(value));
            }
        }

        private static void WriteString(Stream stream, string value)
        {
            var encoded = new UTF8Encoding(false, true).GetBytes(value);
            WriteInt32(stream, encoded.Length);
            stream.Write(encoded, 0, encoded.Length);
        }

        private static void WriteInt32(Stream stream, int value)
        {
            stream.WriteByte((byte)((value >> 24) & 0xFF));
            stream.WriteByte((byte)((value >> 16) & 0xFF));
            stream.WriteByte((byte)((value >> 8) & 0xFF));
            stream.WriteByte((byte)(value & 0xFF));
        }

        private static void WriteInt64(Stream stream, long value)
        {
            stream.WriteByte((byte)((value >> 56) & 0xFF));
            stream.WriteByte((byte)((value >> 48) & 0xFF));
            stream.WriteByte((byte)((value >> 40) & 0xFF));
            stream.WriteByte((byte)((value >> 32) & 0xFF));
            stream.WriteByte((byte)((value >> 24) & 0xFF));
            stream.WriteByte((byte)((value >> 16) & 0xFF));
            stream.WriteByte((byte)((value >> 8) & 0xFF));
            stream.WriteByte((byte)(value & 0xFF));
        }
    }

    public sealed class RelayReconcileIntent
    {
        private readonly byte[] _policyDigest;

        public RelayReconcileIntent(
            string intentId,
            long policyRevision,
            string commandId,
            byte[] policyDigest)
        {
            RelayTrackedRequest.RequireToken(intentId, nameof(intentId));
            if (policyRevision <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(policyRevision));
            }

            RelayTrackedRequest.RequireToken(commandId, nameof(commandId));
            RelayTrackedRequest.RequireSha256(policyDigest, nameof(policyDigest));
            IntentId = intentId;
            PolicyRevision = policyRevision;
            CommandId = commandId;
            _policyDigest = RelayTrackedRequest.Copy(policyDigest);
        }

        public string IntentId { get; }

        public long PolicyRevision { get; }

        public string CommandId { get; }

        public byte[] GetPolicyDigestCopy()
        {
            return RelayTrackedRequest.Copy(_policyDigest);
        }
    }

    public sealed class RelaySignedReceiptRecord
    {
        public const int MaximumSignedReceiptBytes = 16 * 1024;

        private readonly byte[] _approvalHash;
        private readonly byte[] _signedReceipt;

        public RelaySignedReceiptRecord(
            string deviceId,
            long deviceEpoch,
            string commandId,
            string requestId,
            long requestRevision,
            long authorityEpoch,
            string approvalKeyId,
            long sequence,
            CommandReceiptStatus status,
            byte[] approvalHash,
            byte[] signedReceipt)
        {
            RelayTrackedRequest.RequireToken(deviceId, nameof(deviceId));
            if (deviceEpoch <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(deviceEpoch));
            }

            RelayTrackedRequest.RequireToken(commandId, nameof(commandId));
            RelayTrackedRequest.RequireToken(requestId, nameof(requestId));
            if (requestRevision <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(requestRevision));
            }

            if (authorityEpoch <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
            }

            RelayTrackedRequest.RequireToken(approvalKeyId, nameof(approvalKeyId));
            if (sequence <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(sequence));
            }

            if (!Enum.IsDefined(typeof(CommandReceiptStatus), status) ||
                status == CommandReceiptStatus.Unknown)
            {
                throw new ArgumentOutOfRangeException(nameof(status));
            }

            RelayTrackedRequest.RequireSha256(approvalHash, nameof(approvalHash));
            if (signedReceipt == null ||
                signedReceipt.Length == 0 ||
                signedReceipt.Length > MaximumSignedReceiptBytes)
            {
                throw new ArgumentException(
                    "A bounded device-signed receipt is required.",
                    nameof(signedReceipt));
            }

            DeviceId = deviceId;
            DeviceEpoch = deviceEpoch;
            CommandId = commandId;
            RequestId = requestId;
            RequestRevision = requestRevision;
            AuthorityEpoch = authorityEpoch;
            ApprovalKeyId = approvalKeyId;
            Sequence = sequence;
            Status = status;
            _approvalHash = RelayTrackedRequest.Copy(approvalHash);
            _signedReceipt = RelayTrackedRequest.Copy(signedReceipt);
        }

        public string DeviceId { get; }

        public long DeviceEpoch { get; }

        public string CommandId { get; }

        public string RequestId { get; }

        public long RequestRevision { get; }

        public long AuthorityEpoch { get; }

        public string ApprovalKeyId { get; }

        public long Sequence { get; }

        public CommandReceiptStatus Status { get; }

        public byte[] GetApprovalHashCopy()
        {
            return RelayTrackedRequest.Copy(_approvalHash);
        }

        public byte[] GetSignedReceiptCopy()
        {
            return RelayTrackedRequest.Copy(_signedReceipt);
        }
    }

    public sealed class RelayEncryptedOutboxItem
    {
        private readonly byte[] _encryptedFrame;

        public RelayEncryptedOutboxItem(
            string frameId,
            long outboundCursor,
            RelayFrameKind kind,
            byte[] encryptedFrame)
        {
            RelayTrackedRequest.RequireToken(frameId, nameof(frameId));
            if (outboundCursor <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(outboundCursor));
            }

            if (!Enum.IsDefined(typeof(RelayFrameKind), kind) ||
                kind == RelayFrameKind.Unknown)
            {
                throw new ArgumentOutOfRangeException(nameof(kind));
            }

            if (encryptedFrame == null ||
                encryptedFrame.Length == 0 ||
                encryptedFrame.Length > RelayProtocol.MaximumFrameBytes)
            {
                throw new ArgumentException(
                    "A bounded encrypted relay frame is required.",
                    nameof(encryptedFrame));
            }

            FrameId = frameId;
            OutboundCursor = outboundCursor;
            Kind = kind;
            _encryptedFrame = RelayTrackedRequest.Copy(encryptedFrame);
        }

        public string FrameId { get; }

        public long OutboundCursor { get; }

        public RelayFrameKind Kind { get; }

        public byte[] GetEncryptedFrameCopy()
        {
            return RelayTrackedRequest.Copy(_encryptedFrame);
        }
    }

    public sealed class RelayApprovalTransaction
    {
        private readonly byte[] _snapshotHash;

        public RelayApprovalTransaction(
            long inboundCursor,
            string requestId,
            long requestRevision,
            byte[] snapshotHash,
            RelayApprovalDisposition disposition,
            RelayReplayFloor replayFloor,
            RelayPolicyLedgerEntry? policyLedgerEntry,
            RelayReconcileIntent? reconcileIntent,
            RelaySignedReceiptRecord signedReceipt,
            RelayEncryptedOutboxItem encryptedReceiptOutboxItem)
        {
            if (inboundCursor <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(inboundCursor));
            }

            RelayTrackedRequest.RequireToken(requestId, nameof(requestId));
            if (requestRevision <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(requestRevision));
            }

            RelayTrackedRequest.RequireSha256(snapshotHash, nameof(snapshotHash));
            if (!Enum.IsDefined(typeof(RelayApprovalDisposition), disposition))
            {
                throw new ArgumentOutOfRangeException(nameof(disposition));
            }

            InboundCursor = inboundCursor;
            RequestId = requestId;
            RequestRevision = requestRevision;
            Disposition = disposition;
            ReplayFloor = replayFloor ?? throw new ArgumentNullException(nameof(replayFloor));
            PolicyLedgerEntry = policyLedgerEntry;
            ReconcileIntent = reconcileIntent;
            SignedReceipt = signedReceipt ?? throw new ArgumentNullException(nameof(signedReceipt));
            EncryptedReceiptOutboxItem = encryptedReceiptOutboxItem ??
                throw new ArgumentNullException(nameof(encryptedReceiptOutboxItem));
            _snapshotHash = RelayTrackedRequest.Copy(snapshotHash);
        }

        public long InboundCursor { get; }

        public string RequestId { get; }

        public long RequestRevision { get; }

        public RelayApprovalDisposition Disposition { get; }

        public RelayReplayFloor ReplayFloor { get; }

        public RelayPolicyLedgerEntry? PolicyLedgerEntry { get; }

        public RelayReconcileIntent? ReconcileIntent { get; }

        public RelaySignedReceiptRecord SignedReceipt { get; }

        public RelayEncryptedOutboxItem EncryptedReceiptOutboxItem { get; }

        public byte[] GetSnapshotHashCopy()
        {
            return RelayTrackedRequest.Copy(_snapshotHash);
        }
    }
}
