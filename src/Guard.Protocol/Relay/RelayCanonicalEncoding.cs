using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Guard.Contracts.Relay;

namespace Guard.Protocol.Relay
{
    public static class RelayCanonicalEncoding
    {
        private static readonly UTF8Encoding Utf8 =
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        private static readonly byte[] RequestMagic =
            { 0x47, 0x52, 0x52, 0x51 };

        private static readonly byte[] DeviceMagic =
            { 0x47, 0x52, 0x44, 0x45 };

        private static readonly byte[] ApprovalMagic =
            { 0x47, 0x52, 0x41, 0x50 };

        private static readonly byte[] ReceiptMagic =
            { 0x47, 0x52, 0x52, 0x43 };

        private static readonly byte[] DeviceReceiptMagic =
            { 0x47, 0x52, 0x44, 0x43 };

        private static readonly byte[] FrameMagic =
            { 0x47, 0x52, 0x46, 0x31 };

        public static byte[] EncodeRequestSnapshot(RequestSnapshot snapshot)
        {
            if (snapshot == null)
            {
                throw new ArgumentNullException(nameof(snapshot));
            }

            return Encode(
                RequestMagic,
                stream =>
                {
                    WriteVersion(stream);
                    WriteIdentifier(stream, snapshot.DeviceId);
                    WritePositiveInt64(stream, snapshot.DeviceEpoch);
                    WritePositiveInt64(stream, snapshot.AuthorityEpoch);
                    WriteIdentifier(stream, snapshot.DeviceEventId);
                    WriteIdentifier(stream, snapshot.RequestId);
                    WritePositiveInt64(stream, snapshot.RequestRevision);
                    WriteEnum(stream, (int)snapshot.TargetKind, 1, 2);
                    WriteText(
                        stream,
                        snapshot.CanonicalTargetIdentity,
                        RelayProtocol.MaximumIdentityBytes,
                        allowEmpty: false);
                    WriteEvidence(stream, snapshot.DisplayEvidence);
                    WriteText(
                        stream,
                        snapshot.ChildReason,
                        RelayProtocol.MaximumReasonBytes,
                        allowEmpty: true);
                    WriteTime(stream, snapshot.CreatedAtUtc);
                    WriteTime(stream, snapshot.PendingExpiresAtUtc);
                    RequireLifetime(
                        snapshot.CreatedAtUtc,
                        snapshot.PendingExpiresAtUtc,
                        TimeSpan.FromDays(RelayProtocol.MaximumSnapshotLifetimeDays),
                        "snapshot");
                    WriteFixedBytes(
                        stream,
                        snapshot.GetDecisionChallengeCopy(),
                        RelayProtocol.ChallengeBytes);
                    WriteNonNegativeInt64(stream, snapshot.PolicyRevision);
                });
        }

        public static RequestSnapshot DecodeRequestSnapshot(byte[] encoded)
        {
            var reader = new Reader(encoded, RequestMagic);
            RequireVersion(reader);
            var deviceId = reader.ReadIdentifier();
            var deviceEpoch = reader.ReadPositiveInt64();
            var authorityEpoch = reader.ReadPositiveInt64();
            var deviceEventId = reader.ReadIdentifier();
            var requestId = reader.ReadIdentifier();
            var requestRevision = reader.ReadPositiveInt64();
            var targetKind = (RelayTargetKind)reader.ReadEnum(1, 2);
            var targetIdentity = reader.ReadText(
                RelayProtocol.MaximumIdentityBytes,
                allowEmpty: false);
            var evidenceCount = reader.ReadInt32();
            if (evidenceCount < 0 ||
                evidenceCount > RelayProtocol.MaximumEvidenceFields)
            {
                throw new ArgumentException("Invalid evidence count.");
            }

            var evidence = new List<RelayEvidenceField>(evidenceCount);
            for (var index = 0; index < evidenceCount; index++)
            {
                evidence.Add(
                    new RelayEvidenceField(
                        reader.ReadText(
                            RelayProtocol.MaximumEvidenceNameBytes,
                            allowEmpty: false),
                        reader.ReadText(
                            RelayProtocol.MaximumEvidenceValueBytes,
                            allowEmpty: true)));
            }

            var childReason = reader.ReadText(
                RelayProtocol.MaximumReasonBytes,
                allowEmpty: true);
            var createdAtUtc = reader.ReadTime();
            var pendingExpiresAtUtc = reader.ReadTime();
            RequireLifetime(
                createdAtUtc,
                pendingExpiresAtUtc,
                TimeSpan.FromDays(RelayProtocol.MaximumSnapshotLifetimeDays),
                "snapshot");
            var decisionChallenge =
                reader.ReadFixedBytes(RelayProtocol.ChallengeBytes);
            var policyRevision = reader.ReadNonNegativeInt64();
            reader.RequireEnd();

            return new RequestSnapshot(
                deviceId,
                deviceEpoch,
                authorityEpoch,
                deviceEventId,
                requestId,
                requestRevision,
                targetKind,
                targetIdentity,
                evidence,
                childReason,
                createdAtUtc,
                pendingExpiresAtUtc,
                decisionChallenge,
                policyRevision);
        }

        public static byte[] ComputeRequestSnapshotHash(RequestSnapshot snapshot)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(EncodeRequestSnapshot(snapshot));
            }
        }

        public static byte[] EncodeDeviceRequestForSignature(
            DeviceSignedRequestEnvelope envelope)
        {
            if (envelope == null)
            {
                throw new ArgumentNullException(nameof(envelope));
            }

            return Encode(
                DeviceMagic,
                stream =>
                {
                    WriteVersion(stream);
                    WriteBytes(
                        stream,
                        EncodeRequestSnapshot(envelope.Snapshot),
                        RelayProtocol.MaximumFrameBytes,
                        allowEmpty: false);
                    WriteIdentifier(stream, envelope.DeviceKeyId);
                });
        }

        public static byte[] EncodeDeviceRequestEnvelope(
            DeviceSignedRequestEnvelope envelope)
        {
            return AppendSignature(
                EncodeDeviceRequestForSignature(envelope),
                envelope.GetSignatureP1363Copy());
        }

        public static byte[] ComputeDeviceRequestHash(
            DeviceSignedRequestEnvelope envelope)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(
                    EncodeDeviceRequestForSignature(envelope));
            }
        }

        public static DeviceSignedRequestEnvelope DecodeDeviceRequestEnvelope(
            byte[] encoded)
        {
            var reader = new Reader(encoded, DeviceMagic);
            RequireVersion(reader);
            var snapshot = DecodeRequestSnapshot(
                reader.ReadBytes(
                    RelayProtocol.MaximumFrameBytes,
                    allowEmpty: false));
            var deviceKeyId = reader.ReadIdentifier();
            var signature = reader.ReadBytes(
                RelayProtocol.MaximumSignatureBytes,
                allowEmpty: false);
            RequireSignature(signature);
            reader.RequireEnd();
            return new DeviceSignedRequestEnvelope(
                snapshot,
                deviceKeyId,
                signature);
        }

        public static byte[] EncodeApprovalForSignature(
            SignedApprovalEnvelope envelope)
        {
            if (envelope == null)
            {
                throw new ArgumentNullException(nameof(envelope));
            }

            return Encode(
                ApprovalMagic,
                stream =>
                {
                    WriteVersion(stream);
                    WritePositiveInt64(stream, envelope.AuthorityEpoch);
                    WriteIdentifier(stream, envelope.KeyId);
                    WritePositiveInt64(stream, envelope.Sequence);
                    WriteIdentifier(stream, envelope.CommandId);
                    WriteIdentifier(stream, envelope.Nonce);
                    WriteTime(stream, envelope.IssuedAtUtc);
                    WriteTime(stream, envelope.ExpiresAtUtc);
                    RequireLifetime(
                        envelope.IssuedAtUtc,
                        envelope.ExpiresAtUtc,
                        TimeSpan.FromMinutes(
                            RelayProtocol.MaximumApprovalLifetimeMinutes),
                        "approval");
                    WriteIdentifier(stream, envelope.DeviceId);
                    WritePositiveInt64(stream, envelope.DeviceEpoch);
                    WriteIdentifier(stream, envelope.RequestId);
                    WritePositiveInt64(stream, envelope.RequestRevision);
                    WriteFixedBytes(
                        stream,
                        envelope.GetRequestSnapshotHashCopy(),
                        RelayProtocol.Sha256Bytes);
                    WriteFixedBytes(
                        stream,
                        envelope.GetDecisionChallengeCopy(),
                        RelayProtocol.ChallengeBytes);
                    WriteEnum(stream, (int)envelope.TargetKind, 1, 2);
                    WriteText(
                        stream,
                        envelope.CanonicalTargetIdentity,
                        RelayProtocol.MaximumIdentityBytes,
                        allowEmpty: false);
                    WriteNonNegativeInt64(stream, envelope.PolicyRevision);
                    WriteEnum(stream, (int)envelope.Decision, 1, 4);
                    RequireDuration(
                        envelope.Decision,
                        envelope.DurationMinutes);
                    WriteInt32(stream, envelope.DurationMinutes);
                });
        }

        public static byte[] EncodeApprovalEnvelope(
            SignedApprovalEnvelope envelope)
        {
            return AppendSignature(
                EncodeApprovalForSignature(envelope),
                envelope.GetSignatureP1363Copy());
        }

        public static SignedApprovalEnvelope DecodeApprovalEnvelope(
            byte[] encoded)
        {
            var reader = new Reader(encoded, ApprovalMagic);
            RequireVersion(reader);
            var authorityEpoch = reader.ReadPositiveInt64();
            var keyId = reader.ReadIdentifier();
            var sequence = reader.ReadPositiveInt64();
            var commandId = reader.ReadIdentifier();
            var nonce = reader.ReadIdentifier();
            var issuedAtUtc = reader.ReadTime();
            var expiresAtUtc = reader.ReadTime();
            RequireLifetime(
                issuedAtUtc,
                expiresAtUtc,
                TimeSpan.FromMinutes(
                    RelayProtocol.MaximumApprovalLifetimeMinutes),
                "approval");
            var deviceId = reader.ReadIdentifier();
            var deviceEpoch = reader.ReadPositiveInt64();
            var requestId = reader.ReadIdentifier();
            var requestRevision = reader.ReadPositiveInt64();
            var requestSnapshotHash =
                reader.ReadFixedBytes(RelayProtocol.Sha256Bytes);
            var decisionChallenge =
                reader.ReadFixedBytes(RelayProtocol.ChallengeBytes);
            var targetKind =
                (RelayTargetKind)reader.ReadEnum(1, 2);
            var targetIdentity = reader.ReadText(
                RelayProtocol.MaximumIdentityBytes,
                allowEmpty: false);
            var policyRevision = reader.ReadNonNegativeInt64();
            var decision =
                (ParentDecisionKind)reader.ReadEnum(1, 4);
            var durationMinutes = reader.ReadInt32();
            RequireDuration(decision, durationMinutes);
            var signature = reader.ReadBytes(
                RelayProtocol.MaximumSignatureBytes,
                allowEmpty: false);
            RequireSignature(signature);
            reader.RequireEnd();

            return new SignedApprovalEnvelope(
                authorityEpoch,
                keyId,
                sequence,
                commandId,
                nonce,
                issuedAtUtc,
                expiresAtUtc,
                deviceId,
                deviceEpoch,
                requestId,
                requestRevision,
                requestSnapshotHash,
                decisionChallenge,
                targetKind,
                targetIdentity,
                policyRevision,
                decision,
                durationMinutes,
                signature);
        }

        public static byte[] ComputeApprovalHash(
            SignedApprovalEnvelope envelope)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(
                    EncodeApprovalForSignature(envelope));
            }
        }

        public static byte[] EncodeCommandReceipt(CommandReceipt receipt)
        {
            if (receipt == null)
            {
                throw new ArgumentNullException(nameof(receipt));
            }

            return Encode(
                ReceiptMagic,
                stream =>
                {
                    WriteVersion(stream);
                    WriteIdentifier(stream, receipt.DeviceId);
                    WritePositiveInt64(stream, receipt.DeviceEpoch);
                    WritePositiveInt64(stream, receipt.AuthorityEpoch);
                    WriteIdentifier(stream, receipt.KeyId);
                    WritePositiveInt64(stream, receipt.Sequence);
                    WriteIdentifier(stream, receipt.CommandId);
                    WriteIdentifier(stream, receipt.RequestId);
                    WritePositiveInt64(stream, receipt.RequestRevision);
                    WriteEnum(stream, (int)receipt.Status, 1, 5);
                    WriteTime(stream, receipt.ProcessedAtUtc);
                    WriteFixedBytes(
                        stream,
                        receipt.GetApprovalHashCopy(),
                        RelayProtocol.Sha256Bytes);
                    WriteNonNegativeInt64(
                        stream,
                        receipt.CommittedPolicyRevision);
                    WriteEnum(
                        stream,
                        (int)receipt.ReconciliationStatus,
                        1,
                        4);
                    RequireReceiptState(
                        receipt.Status,
                        receipt.ReconciliationStatus);
                    WriteIdentifier(stream, receipt.DetailCode);
                });
        }

        public static CommandReceipt DecodeCommandReceipt(byte[] encoded)
        {
            var reader = new Reader(encoded, ReceiptMagic);
            RequireVersion(reader);
            var deviceId = reader.ReadIdentifier();
            var deviceEpoch = reader.ReadPositiveInt64();
            var authorityEpoch = reader.ReadPositiveInt64();
            var keyId = reader.ReadIdentifier();
            var sequence = reader.ReadPositiveInt64();
            var commandId = reader.ReadIdentifier();
            var requestId = reader.ReadIdentifier();
            var requestRevision = reader.ReadPositiveInt64();
            var status =
                (CommandReceiptStatus)reader.ReadEnum(1, 5);
            var processedAtUtc = reader.ReadTime();
            var approvalHash =
                reader.ReadFixedBytes(RelayProtocol.Sha256Bytes);
            var committedPolicyRevision =
                reader.ReadNonNegativeInt64();
            var reconciliationStatus =
                (ReconciliationStatus)reader.ReadEnum(1, 4);
            RequireReceiptState(status, reconciliationStatus);
            var detailCode = reader.ReadIdentifier();
            reader.RequireEnd();

            return new CommandReceipt(
                deviceId,
                deviceEpoch,
                authorityEpoch,
                keyId,
                sequence,
                commandId,
                requestId,
                requestRevision,
                status,
                processedAtUtc,
                approvalHash,
                committedPolicyRevision,
                reconciliationStatus,
                detailCode);
        }

        public static byte[] EncodeDeviceReceiptForSignature(
            DeviceSignedCommandReceiptEnvelope envelope)
        {
            if (envelope == null)
            {
                throw new ArgumentNullException(nameof(envelope));
            }

            return Encode(
                DeviceReceiptMagic,
                stream =>
                {
                    WriteVersion(stream);
                    WriteBytes(
                        stream,
                        EncodeCommandReceipt(envelope.Receipt),
                        RelayProtocol.MaximumFrameBytes,
                        allowEmpty: false);
                    WriteIdentifier(stream, envelope.DeviceKeyId);
                });
        }

        public static byte[] EncodeDeviceReceiptEnvelope(
            DeviceSignedCommandReceiptEnvelope envelope)
        {
            return AppendSignature(
                EncodeDeviceReceiptForSignature(envelope),
                envelope.GetSignatureP1363Copy());
        }

        public static byte[] ComputeDeviceReceiptHash(
            DeviceSignedCommandReceiptEnvelope envelope)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(
                    EncodeDeviceReceiptForSignature(envelope));
            }
        }

        public static DeviceSignedCommandReceiptEnvelope
            DecodeDeviceReceiptEnvelope(byte[] encoded)
        {
            var reader = new Reader(encoded, DeviceReceiptMagic);
            RequireVersion(reader);
            var receipt = DecodeCommandReceipt(
                reader.ReadBytes(
                    RelayProtocol.MaximumFrameBytes,
                    allowEmpty: false));
            var deviceKeyId = reader.ReadIdentifier();
            var signature = reader.ReadBytes(
                RelayProtocol.MaximumSignatureBytes,
                allowEmpty: false);
            RequireSignature(signature);
            reader.RequireEnd();
            return new DeviceSignedCommandReceiptEnvelope(
                receipt,
                deviceKeyId,
                signature);
        }

        public static byte[] EncodeRelayFrameAssociatedData(
            RelayFrame frame)
        {
            if (frame == null)
            {
                throw new ArgumentNullException(nameof(frame));
            }

            return Encode(
                FrameMagic,
                stream =>
                {
                    WriteVersion(stream);
                    WriteEnum(stream, (int)frame.Kind, 1, 4);
                    WriteIdentifier(stream, frame.MailboxId);
                    WriteIdentifier(stream, frame.RecipientKeyId);
                    WriteIdentifier(stream, frame.FrameId);
                    if (frame.Cursor < 0 ||
                        frame.AckCursor < 0 ||
                        frame.AckCursor > frame.Cursor)
                    {
                        throw new ArgumentOutOfRangeException(
                            nameof(frame));
                    }

                    WriteInt64(stream, frame.Cursor);
                    WriteInt64(stream, frame.AckCursor);
                    WriteTime(stream, frame.CreatedAtUtc);
                    WriteTime(stream, frame.ExpiresAtUtc);
                    RequireLifetime(
                        frame.CreatedAtUtc,
                        frame.ExpiresAtUtc,
                        TimeSpan.FromDays(
                            RelayProtocol.MaximumFrameLifetimeDays),
                        "frame");
                });
        }

        public static byte[] EncodeRelayFrame(RelayFrame frame)
        {
            var associatedData =
                EncodeRelayFrameAssociatedData(frame);
            var encapsulatedKey = frame.GetEncapsulatedKeyCopy();
            var ciphertext = frame.GetCiphertextCopy();
            if (encapsulatedKey.Length !=
                RelayProtocol.HpkeEncapsulatedKeyBytes)
            {
                throw new ArgumentException(
                    "Invalid HPKE encapsulated key length.");
            }

            if (ciphertext.Length < RelayProtocol.MinimumCiphertextBytes)
            {
                throw new ArgumentException(
                    "Ciphertext lacks GCM tag.");
            }

            using (var stream = new MemoryStream())
            {
                stream.Write(
                    associatedData,
                    0,
                    associatedData.Length);
                WriteBytes(
                    stream,
                    encapsulatedKey,
                    RelayProtocol.HpkeEncapsulatedKeyBytes,
                    allowEmpty: false);
                WriteBytes(
                    stream,
                    ciphertext,
                    RelayProtocol.MaximumCiphertextBytes,
                    allowEmpty: false);
                return Finish(stream);
            }
        }

        public static RelayFrame DecodeRelayFrame(byte[] encoded)
        {
            var reader = new Reader(encoded, FrameMagic);
            RequireVersion(reader);
            var kind = (RelayFrameKind)reader.ReadEnum(1, 4);
            var mailboxId = reader.ReadIdentifier();
            var recipientKeyId = reader.ReadIdentifier();
            var frameId = reader.ReadIdentifier();
            var cursor = reader.ReadNonNegativeInt64();
            var ackCursor = reader.ReadNonNegativeInt64();
            if (ackCursor > cursor)
            {
                throw new ArgumentException(
                    "Ack cursor exceeds cursor.");
            }

            var createdAtUtc = reader.ReadTime();
            var expiresAtUtc = reader.ReadTime();
            RequireLifetime(
                createdAtUtc,
                expiresAtUtc,
                TimeSpan.FromDays(
                    RelayProtocol.MaximumFrameLifetimeDays),
                "frame");
            var encapsulatedKey = reader.ReadBytes(
                RelayProtocol.HpkeEncapsulatedKeyBytes,
                allowEmpty: false);
            if (encapsulatedKey.Length !=
                RelayProtocol.HpkeEncapsulatedKeyBytes)
            {
                throw new ArgumentException(
                    "Invalid HPKE encapsulated key length.");
            }

            var ciphertext = reader.ReadBytes(
                RelayProtocol.MaximumCiphertextBytes,
                allowEmpty: false);
            if (ciphertext.Length < RelayProtocol.MinimumCiphertextBytes)
            {
                throw new ArgumentException(
                    "Ciphertext lacks GCM tag.");
            }

            reader.RequireEnd();
            return new RelayFrame(
                kind,
                mailboxId,
                recipientKeyId,
                frameId,
                cursor,
                ackCursor,
                createdAtUtc,
                expiresAtUtc,
                encapsulatedKey,
                ciphertext);
        }

        private static byte[] AppendSignature(
            byte[] signedBytes,
            byte[] signature)
        {
            RequireSignature(signature);
            using (var stream = new MemoryStream())
            {
                stream.Write(signedBytes, 0, signedBytes.Length);
                WriteBytes(
                    stream,
                    signature,
                    RelayProtocol.MaximumSignatureBytes,
                    allowEmpty: false);
                return Finish(stream);
            }
        }

        private static byte[] Encode(
            byte[] magic,
            Action<MemoryStream> writeBody)
        {
            using (var stream = new MemoryStream())
            {
                stream.Write(magic, 0, magic.Length);
                writeBody(stream);
                return Finish(stream);
            }
        }

        private static byte[] Finish(MemoryStream stream)
        {
            if (stream.Length > RelayProtocol.MaximumFrameBytes)
            {
                throw new ArgumentException(
                    "Oversized relay message.");
            }

            return stream.ToArray();
        }

        private static void WriteVersion(Stream stream)
        {
            WriteInt32(stream, RelayProtocol.Version);
        }

        private static void RequireVersion(Reader reader)
        {
            if (reader.ReadInt32() != RelayProtocol.Version)
            {
                throw new ArgumentException(
                    "Unsupported relay version.");
            }
        }

        private static void WriteEvidence(
            Stream stream,
            IReadOnlyList<RelayEvidenceField> evidence)
        {
            if (evidence == null ||
                evidence.Count > RelayProtocol.MaximumEvidenceFields)
            {
                throw new ArgumentException(
                    "Invalid evidence count.");
            }

            WriteInt32(stream, evidence.Count);
            foreach (var field in evidence)
            {
                if (field == null)
                {
                    throw new ArgumentException("Null evidence.");
                }

                WriteText(
                    stream,
                    field.Name,
                    RelayProtocol.MaximumEvidenceNameBytes,
                    allowEmpty: false);
                WriteText(
                    stream,
                    field.Value,
                    RelayProtocol.MaximumEvidenceValueBytes,
                    allowEmpty: true);
            }
        }

        private static void WriteIdentifier(
            Stream stream,
            string value)
        {
            if (!Guard.Contracts.GuardIdentifier
                .IsCanonicalToken(value))
            {
                throw new ArgumentException(
                    "Canonical identifier required.");
            }

            WriteText(
                stream,
                value,
                Guard.Contracts.GuardIdentifier.MaximumCharacters,
                allowEmpty: false);
        }

        private static void WriteText(
            Stream stream,
            string value,
            int maximumByteCount,
            bool allowEmpty)
        {
            RequireValidText(value, allowEmpty);
            var encoded = Utf8.GetBytes(value);
            if (encoded.Length > maximumByteCount)
            {
                throw new ArgumentException(
                    "Invalid UTF-8 text.");
            }

            WriteBytes(
                stream,
                encoded,
                maximumByteCount,
                allowEmpty);
        }

        private static void RequireValidText(
            string value,
            bool allowEmpty)
        {
            if (value == null ||
                (!allowEmpty && value.Length == 0) ||
                !string.Equals(
                    value,
                    value.Normalize(NormalizationForm.FormC),
                    StringComparison.Ordinal))
            {
                throw new ArgumentException("Text must be NFC.");
            }

            for (var index = 0; index < value.Length; index++)
            {
                if (char.IsControl(value[index]))
                {
                    throw new ArgumentException(
                        "Control characters are forbidden.");
                }
            }
        }

        private static void WriteBytes(
            Stream stream,
            byte[] value,
            int maximumByteCount,
            bool allowEmpty)
        {
            if (value == null ||
                value.Length > maximumByteCount ||
                (!allowEmpty && value.Length == 0))
            {
                throw new ArgumentException(
                    "Invalid byte length.");
            }

            WriteInt32(stream, value.Length);
            stream.Write(value, 0, value.Length);
        }

        private static void WriteFixedBytes(
            Stream stream,
            byte[] value,
            int expectedByteCount)
        {
            if (value == null || value.Length != expectedByteCount)
            {
                throw new ArgumentException(
                    "Invalid fixed byte length.");
            }

            stream.Write(value, 0, value.Length);
        }

        private static void WritePositiveInt64(
            Stream stream,
            long value)
        {
            if (value <= 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(value));
            }

            WriteInt64(stream, value);
        }

        private static void WriteNonNegativeInt64(
            Stream stream,
            long value)
        {
            if (value < 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(value));
            }

            WriteInt64(stream, value);
        }

        private static void WriteEnum(
            Stream stream,
            int value,
            int minimum,
            int maximum)
        {
            if (value < minimum || value > maximum)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(value));
            }

            WriteInt32(stream, value);
        }

        private static void RequireDuration(
            ParentDecisionKind decision,
            int durationMinutes)
        {
            if (decision == ParentDecisionKind.AllowTemporary ||
                decision == ParentDecisionKind.AllowDailyQuota)
            {
                if (durationMinutes < 1 || durationMinutes > 1440)
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(durationMinutes));
                }
            }
            else if (durationMinutes != 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(durationMinutes));
            }
        }

        private static void RequireSignature(byte[] signature)
        {
            if (signature == null ||
                signature.Length != RelayProtocol.MaximumSignatureBytes)
            {
                throw new ArgumentException(
                    "P-256 P1363 signature must be exactly 64 bytes.");
            }
        }

        private static void RequireLifetime(
            DateTimeOffset start,
            DateTimeOffset end,
            TimeSpan maximum,
            string name)
        {
            if (end <= start || end - start > maximum)
            {
                throw new ArgumentException(
                    "Invalid " + name + " lifetime.");
            }
        }

        private static void RequireReceiptState(
            CommandReceiptStatus status,
            ReconciliationStatus reconciliation)
        {
            if (status == CommandReceiptStatus.Applied)
            {
                if (reconciliation != ReconciliationStatus.Reconciled)
                {
                    throw new ArgumentException(
                        "Applied must reconcile.");
                }
            }
            else if (
                status ==
                CommandReceiptStatus.AcceptedPendingReconciliation)
            {
                if (reconciliation != ReconciliationStatus.Pending &&
                    reconciliation != ReconciliationStatus.Failed)
                {
                    throw new ArgumentException(
                        "Pending acceptance requires pending/failed reconciliation.");
                }
            }
            else if (reconciliation != ReconciliationStatus.NotRequired)
            {
                throw new ArgumentException(
                    "Terminal receipt must not reconcile.");
            }
        }

        private static void WriteTime(
            Stream stream,
            DateTimeOffset value)
        {
            if (value.UtcDateTime.Ticks %
                TimeSpan.TicksPerMillisecond != 0)
            {
                throw new ArgumentException(
                    "Millisecond precision required.");
            }

            var unixMilliseconds = value.ToUnixTimeMilliseconds();
            if (unixMilliseconds < 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(value));
            }

            WriteInt64(stream, unixMilliseconds);
        }

        private static void WriteInt32(Stream stream, int value)
        {
            stream.WriteByte((byte)(value >> 24));
            stream.WriteByte((byte)(value >> 16));
            stream.WriteByte((byte)(value >> 8));
            stream.WriteByte((byte)value);
        }

        private static void WriteInt64(Stream stream, long value)
        {
            for (var shift = 56; shift >= 0; shift -= 8)
            {
                stream.WriteByte((byte)(value >> shift));
            }
        }

        private sealed class Reader
        {
            private readonly byte[] _data;
            private int _offset;

            public Reader(byte[] encoded, byte[] expectedMagic)
            {
                if (encoded == null ||
                    encoded.Length > RelayProtocol.MaximumFrameBytes ||
                    encoded.Length < expectedMagic.Length + 4)
                {
                    throw new ArgumentException(
                        "Invalid relay message.");
                }

                _data = encoded;
                for (var index = 0;
                    index < expectedMagic.Length;
                    index++)
                {
                    if (_data[_offset++] != expectedMagic[index])
                    {
                        throw new ArgumentException(
                            "Unexpected magic.");
                    }
                }
            }

            public int ReadInt32()
            {
                RequireAvailable(4);
                var value =
                    (_data[_offset] << 24) |
                    (_data[_offset + 1] << 16) |
                    (_data[_offset + 2] << 8) |
                    _data[_offset + 3];
                _offset += 4;
                return value;
            }

            public long ReadInt64()
            {
                RequireAvailable(8);
                long value = 0;
                for (var index = 0; index < 8; index++)
                {
                    value = (value << 8) | _data[_offset++];
                }

                return value;
            }

            public long ReadPositiveInt64()
            {
                var value = ReadInt64();
                if (value <= 0)
                {
                    throw new ArgumentException(
                        "Positive integer required.");
                }

                return value;
            }

            public long ReadNonNegativeInt64()
            {
                var value = ReadInt64();
                if (value < 0)
                {
                    throw new ArgumentException(
                        "Nonnegative integer required.");
                }

                return value;
            }

            public int ReadEnum(int minimum, int maximum)
            {
                var value = ReadInt32();
                if (value < minimum || value > maximum)
                {
                    throw new ArgumentException("Unknown enum.");
                }

                return value;
            }

            public byte[] ReadBytes(
                int maximumByteCount,
                bool allowEmpty)
            {
                var byteCount = ReadInt32();
                if (byteCount < 0 ||
                    byteCount > maximumByteCount ||
                    (!allowEmpty && byteCount == 0))
                {
                    throw new ArgumentException(
                        "Invalid byte length.");
                }

                RequireAvailable(byteCount);
                var result = new byte[byteCount];
                Buffer.BlockCopy(
                    _data,
                    _offset,
                    result,
                    0,
                    byteCount);
                _offset += byteCount;
                return result;
            }

            public byte[] ReadFixedBytes(int byteCount)
            {
                RequireAvailable(byteCount);
                var result = new byte[byteCount];
                Buffer.BlockCopy(
                    _data,
                    _offset,
                    result,
                    0,
                    byteCount);
                _offset += byteCount;
                return result;
            }

            public string ReadText(
                int maximumByteCount,
                bool allowEmpty)
            {
                try
                {
                    var value = Utf8.GetString(
                        ReadBytes(
                            maximumByteCount,
                            allowEmpty));
                    RequireValidText(value, allowEmpty);
                    return value;
                }
                catch (DecoderFallbackException exception)
                {
                    throw new ArgumentException(
                        "Invalid UTF-8.",
                        exception);
                }
            }

            public string ReadIdentifier()
            {
                var value = ReadText(
                    Guard.Contracts.GuardIdentifier
                        .MaximumCharacters,
                    allowEmpty: false);
                if (!Guard.Contracts.GuardIdentifier
                    .IsCanonicalToken(value))
                {
                    throw new ArgumentException(
                        "Invalid identifier.");
                }

                return value;
            }

            public DateTimeOffset ReadTime()
            {
                var unixMilliseconds = ReadInt64();
                if (unixMilliseconds < 0)
                {
                    throw new ArgumentException(
                        "Invalid timestamp.");
                }

                try
                {
                    return DateTimeOffset.FromUnixTimeMilliseconds(
                        unixMilliseconds);
                }
                catch (ArgumentOutOfRangeException exception)
                {
                    throw new ArgumentException(
                        "Invalid timestamp.",
                        exception);
                }
            }

            public void RequireEnd()
            {
                if (_offset != _data.Length)
                {
                    throw new ArgumentException(
                        "Trailing bytes forbidden.");
                }
            }

            private void RequireAvailable(int byteCount)
            {
                if (byteCount < 0 ||
                    _offset > _data.Length - byteCount)
                {
                    throw new ArgumentException(
                        "Truncated relay message.");
                }
            }
        }
    }
}
