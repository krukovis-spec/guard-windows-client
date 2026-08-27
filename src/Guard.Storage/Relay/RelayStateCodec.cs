using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Guard.Contracts.Relay;
using Guard.Domain.Relay;

namespace Guard.Storage.Relay
{
    internal static class RelayStateCodec
    {
        private static readonly byte[] Magic =
        {
            0x47, 0x52, 0x44, 0x52, 0x4C, 0x59, 0x53, 0x54
        };

        private static readonly UTF8Encoding StrictUtf8 =
            new UTF8Encoding(false, true);

        private const int SchemaVersion = 1;
        private const int MaximumIdentifierBytes = 128;
        public const int MaximumPayloadBytes = 768 * 1024;

        public static byte[] Encode(RelayTransactionState state)
        {
            if (state == null)
            {
                throw new ArgumentNullException(nameof(state));
            }

            using (var stream = new MemoryStream())
            {
                stream.Write(Magic, 0, Magic.Length);
                WriteInt32(stream, SchemaVersion);
                WriteIdentifier(stream, state.DeviceId);
                WriteInt64(stream, state.Version);
                WriteInt64(stream, state.DeviceEpoch);
                WriteInt64(stream, state.AuthorityEpoch);
                WriteInt64(stream, state.CommittedInboundCursor);
                WriteInt64(stream, state.HighestOutboundCursor);
                WriteInt64(stream, state.AcknowledgedOutboundCursor);
                WriteInt64(stream, state.PolicyRevision);

                WriteInt32(stream, state.ReplayFloors.Count);
                for (var index = 0; index < state.ReplayFloors.Count; index++)
                {
                    var floor = state.ReplayFloors[index];
                    WriteInt64(stream, floor.AuthorityEpoch);
                    WriteIdentifier(stream, floor.ApprovalKeyId);
                    WriteInt64(stream, floor.HighestAcceptedSequence);
                    WriteIdentifier(stream, floor.CommandId);
                    WriteFixedBytes(stream, floor.GetApprovalHashCopy());
                }

                WriteInt32(stream, state.TrackedRequests.Count);
                for (var index = 0; index < state.TrackedRequests.Count; index++)
                {
                    var request = state.TrackedRequests[index];
                    WriteIdentifier(stream, request.RequestId);
                    WriteInt64(stream, request.RequestRevision);
                    WriteFixedBytes(stream, request.GetSnapshotHashCopy());
                    WriteFixedBytes(stream, request.GetDecisionChallengeCopy());
                    WriteInt32(stream, (int)request.Resolution);
                    if (request.IsPending)
                    {
                        stream.WriteByte(0);
                    }
                    else
                    {
                        stream.WriteByte(1);
                        WriteIdentifier(stream, request.ResolvedCommandId!);
                        WriteFixedBytes(stream, request.GetApprovalHashCopy());
                    }
                }

                WriteInt32(stream, state.PolicyLedger.Count);
                for (var index = 0; index < state.PolicyLedger.Count; index++)
                {
                    var entry = state.PolicyLedger[index];
                    WriteInt64(stream, entry.PolicyRevision);
                    WriteIdentifier(stream, entry.RequestId);
                    WriteIdentifier(stream, entry.CommandId);
                    WriteInt32(stream, (int)entry.TargetKind);
                    WriteString(
                        stream,
                        entry.CanonicalTargetIdentity,
                        RelayProtocol.MaximumIdentityBytes);
                    WriteInt32(stream, (int)entry.Decision);
                    WriteInt32(stream, entry.DurationMinutes);
                    WriteFixedBytes(stream, entry.GetApprovalHashCopy());
                }

                WriteInt32(stream, state.ReconcileIntents.Count);
                for (var index = 0; index < state.ReconcileIntents.Count; index++)
                {
                    var intent = state.ReconcileIntents[index];
                    WriteIdentifier(stream, intent.IntentId);
                    WriteInt64(stream, intent.PolicyRevision);
                    WriteIdentifier(stream, intent.CommandId);
                    WriteFixedBytes(stream, intent.GetPolicyDigestCopy());
                }

                WriteInt32(stream, state.SignedReceipts.Count);
                for (var index = 0; index < state.SignedReceipts.Count; index++)
                {
                    var receipt = state.SignedReceipts[index];
                    WriteIdentifier(stream, receipt.DeviceId);
                    WriteInt64(stream, receipt.DeviceEpoch);
                    WriteIdentifier(stream, receipt.CommandId);
                    WriteIdentifier(stream, receipt.RequestId);
                    WriteInt64(stream, receipt.RequestRevision);
                    WriteInt64(stream, receipt.AuthorityEpoch);
                    WriteIdentifier(stream, receipt.ApprovalKeyId);
                    WriteInt64(stream, receipt.Sequence);
                    WriteInt32(stream, (int)receipt.Status);
                    WriteFixedBytes(stream, receipt.GetApprovalHashCopy());
                    WriteVariableBytes(
                        stream,
                        receipt.GetSignedReceiptCopy(),
                        RelaySignedReceiptRecord.MaximumSignedReceiptBytes);
                }

                WriteInt32(stream, state.Outbox.Count);
                for (var index = 0; index < state.Outbox.Count; index++)
                {
                    var item = state.Outbox[index];
                    WriteIdentifier(stream, item.FrameId);
                    WriteInt64(stream, item.OutboundCursor);
                    WriteInt32(stream, (int)item.Kind);
                    WriteVariableBytes(
                        stream,
                        item.GetEncryptedFrameCopy(),
                        RelayProtocol.MaximumFrameBytes);
                }

                if (stream.Length > MaximumPayloadBytes)
                {
                    throw new ArgumentException(
                        "The relay transaction state payload is oversized.",
                        nameof(state));
                }

                return stream.ToArray();
            }
        }

        public static RelayTransactionState Decode(byte[] payload)
        {
            if (payload == null ||
                payload.Length == 0 ||
                payload.Length > MaximumPayloadBytes)
            {
                throw new StateStoreCorruptionException(
                    "The relay transaction state payload is empty or oversized.");
            }

            try
            {
                using (var stream = new MemoryStream(payload, writable: false))
                {
                    RequireBytes(stream, Magic, "relay state magic");
                    if (ReadInt32(stream) != SchemaVersion)
                    {
                        throw new StateStoreCorruptionException(
                            "The relay state schema version is unsupported.");
                    }

                    var deviceId = ReadIdentifier(stream);
                    var version = ReadNonNegativeInt64(stream, "state version");
                    var deviceEpoch = ReadNonNegativeInt64(stream, "device epoch");
                    var authorityEpoch = ReadNonNegativeInt64(stream, "authority epoch");
                    var committedInboundCursor =
                        ReadNonNegativeInt64(stream, "inbound cursor");
                    var highestOutboundCursor =
                        ReadNonNegativeInt64(stream, "outbound cursor");
                    var acknowledgedOutboundCursor =
                        ReadNonNegativeInt64(stream, "outbound ack cursor");
                    var policyRevision =
                        ReadNonNegativeInt64(stream, "policy revision");

                    var replayFloorCount = ReadBoundedCount(
                        stream,
                        RelayTransactionState.MaximumReplayFloors,
                        "replay floor");
                    var replayFloors =
                        new List<RelayReplayFloor>(replayFloorCount);
                    while (replayFloors.Count < replayFloorCount)
                    {
                        replayFloors.Add(new RelayReplayFloor(
                            ReadNonNegativeInt64(stream, "replay authority epoch"),
                            ReadIdentifier(stream),
                            ReadPositiveInt64(stream, "replay sequence"),
                            ReadIdentifier(stream),
                            ReadExact(stream, RelayProtocol.Sha256Bytes)));
                    }

                    var trackedRequestCount = ReadBoundedCount(
                        stream,
                        RelayTransactionState.MaximumTrackedRequests,
                        "tracked request");
                    var trackedRequests =
                        new List<RelayTrackedRequest>(trackedRequestCount);
                    while (trackedRequests.Count < trackedRequestCount)
                    {
                        var requestId = ReadIdentifier(stream);
                        var requestRevision =
                            ReadNonNegativeInt64(stream, "request revision");
                        var snapshotHash =
                            ReadExact(stream, RelayProtocol.Sha256Bytes);
                        var challenge =
                            ReadExact(stream, RelayProtocol.ChallengeBytes);
                        var resolutionValue = ReadInt32(stream);
                        if (!Enum.IsDefined(
                            typeof(RelayRequestResolution),
                            resolutionValue))
                        {
                            throw new StateStoreCorruptionException(
                                "A tracked request resolution is invalid.");
                        }

                        var resolution = (RelayRequestResolution)resolutionValue;
                        var hasResolution = ReadBoolean(
                            stream,
                            "tracked request resolution evidence");
                        if (resolution == RelayRequestResolution.Pending)
                        {
                            if (hasResolution)
                            {
                                throw new StateStoreCorruptionException(
                                    "A pending request contains resolution evidence.");
                            }

                            trackedRequests.Add(new RelayTrackedRequest(
                                requestId,
                                requestRevision,
                                snapshotHash,
                                challenge));
                        }
                        else
                        {
                            if (!hasResolution)
                            {
                                throw new StateStoreCorruptionException(
                                    "A resolved request is missing resolution evidence.");
                            }

                            trackedRequests.Add(new RelayTrackedRequest(
                                requestId,
                                requestRevision,
                                snapshotHash,
                                challenge,
                                resolution,
                                ReadIdentifier(stream),
                                ReadExact(stream, RelayProtocol.Sha256Bytes)));
                        }
                    }

                    var policyLedgerCount = ReadBoundedCount(
                        stream,
                        RelayTransactionState.MaximumPolicyLedgerEntries,
                        "policy ledger");
                    var policyLedger =
                        new List<RelayPolicyLedgerEntry>(policyLedgerCount);
                    while (policyLedger.Count < policyLedgerCount)
                    {
                        policyLedger.Add(new RelayPolicyLedgerEntry(
                            ReadPositiveInt64(stream, "ledger policy revision"),
                            ReadIdentifier(stream),
                            ReadIdentifier(stream),
                            ReadEnum<RelayTargetKind>(stream, "relay target kind"),
                            ReadString(
                                stream,
                                RelayProtocol.MaximumIdentityBytes),
                            ReadEnum<ParentDecisionKind>(
                                stream,
                                "parent decision"),
                            ReadInt32(stream),
                            ReadExact(stream, RelayProtocol.Sha256Bytes)));
                    }

                    var reconcileIntentCount = ReadBoundedCount(
                        stream,
                        RelayTransactionState.MaximumReconcileIntents,
                        "reconciliation intent");
                    var reconcileIntents =
                        new List<RelayReconcileIntent>(reconcileIntentCount);
                    while (reconcileIntents.Count < reconcileIntentCount)
                    {
                        reconcileIntents.Add(new RelayReconcileIntent(
                            ReadIdentifier(stream),
                            ReadPositiveInt64(stream, "intent policy revision"),
                            ReadIdentifier(stream),
                            ReadExact(stream, RelayProtocol.Sha256Bytes)));
                    }

                    var signedReceiptCount = ReadBoundedCount(
                        stream,
                        RelayTransactionState.MaximumSignedReceipts,
                        "signed receipt");
                    var signedReceipts =
                        new List<RelaySignedReceiptRecord>(signedReceiptCount);
                    while (signedReceipts.Count < signedReceiptCount)
                    {
                        signedReceipts.Add(new RelaySignedReceiptRecord(
                            ReadIdentifier(stream),
                            ReadPositiveInt64(stream, "receipt device epoch"),
                            ReadIdentifier(stream),
                            ReadIdentifier(stream),
                            ReadPositiveInt64(
                                stream,
                                "receipt request revision"),
                            ReadPositiveInt64(
                                stream,
                                "receipt authority epoch"),
                            ReadIdentifier(stream),
                            ReadPositiveInt64(stream, "receipt sequence"),
                            ReadEnum<CommandReceiptStatus>(
                                stream,
                                "receipt status"),
                            ReadExact(stream, RelayProtocol.Sha256Bytes),
                            ReadVariableBytes(
                                stream,
                                RelaySignedReceiptRecord.MaximumSignedReceiptBytes)));
                    }

                    var outboxCount = ReadBoundedCount(
                        stream,
                        RelayTransactionState.MaximumOutboxItems,
                        "outbox item");
                    var outbox =
                        new List<RelayEncryptedOutboxItem>(outboxCount);
                    while (outbox.Count < outboxCount)
                    {
                        outbox.Add(new RelayEncryptedOutboxItem(
                            ReadIdentifier(stream),
                            ReadPositiveInt64(stream, "outbox cursor"),
                            ReadEnum<RelayFrameKind>(
                                stream,
                                "relay frame kind"),
                            ReadVariableBytes(
                                stream,
                                RelayProtocol.MaximumFrameBytes)));
                    }

                    if (stream.Position != stream.Length)
                    {
                        throw new StateStoreCorruptionException(
                            "Trailing bytes are not allowed in relay transaction state.");
                    }

                    return new RelayTransactionState(
                        deviceId,
                        version,
                        deviceEpoch,
                        authorityEpoch,
                        committedInboundCursor,
                        highestOutboundCursor,
                        acknowledgedOutboundCursor,
                        policyRevision,
                        replayFloors,
                        trackedRequests,
                        policyLedger,
                        reconcileIntents,
                        signedReceipts,
                        outbox);
                }
            }
            catch (StateStoreCorruptionException)
            {
                throw;
            }
            catch (Exception exception) when (
                exception is ArgumentException ||
                exception is DecoderFallbackException ||
                exception is EndOfStreamException ||
                exception is OverflowException)
            {
                throw new StateStoreCorruptionException(
                    "The relay transaction state payload is malformed.",
                    exception);
            }
        }

        private static TEnum ReadEnum<TEnum>(Stream stream, string fieldName)
            where TEnum : struct
        {
            var value = ReadInt32(stream);
            if (!Enum.IsDefined(typeof(TEnum), value) || value == 0)
            {
                throw new StateStoreCorruptionException(
                    "The " + fieldName + " is invalid.");
            }

            return (TEnum)Enum.ToObject(typeof(TEnum), value);
        }

        private static int ReadBoundedCount(
            Stream stream,
            int maximum,
            string fieldName)
        {
            var count = ReadInt32(stream);
            if (count < 0 || count > maximum)
            {
                throw new StateStoreCorruptionException(
                    "The " + fieldName + " count is invalid.");
            }

            return count;
        }

        private static long ReadNonNegativeInt64(
            Stream stream,
            string fieldName)
        {
            var value = ReadInt64(stream);
            if (value < 0)
            {
                throw new StateStoreCorruptionException(
                    "The " + fieldName + " is invalid.");
            }

            return value;
        }

        private static long ReadPositiveInt64(Stream stream, string fieldName)
        {
            var value = ReadInt64(stream);
            if (value <= 0)
            {
                throw new StateStoreCorruptionException(
                    "The " + fieldName + " is invalid.");
            }

            return value;
        }

        private static bool ReadBoolean(Stream stream, string fieldName)
        {
            var value = stream.ReadByte();
            if (value == 0)
            {
                return false;
            }

            if (value == 1)
            {
                return true;
            }

            if (value < 0)
            {
                throw new EndOfStreamException();
            }

            throw new StateStoreCorruptionException(
                "The " + fieldName + " flag is invalid.");
        }

        private static string ReadIdentifier(Stream stream)
        {
            return ReadString(stream, MaximumIdentifierBytes);
        }

        private static string ReadString(Stream stream, int maximumBytes)
        {
            var length = ReadInt32(stream);
            if (length <= 0 || length > maximumBytes)
            {
                throw new StateStoreCorruptionException(
                    "An encoded relay string length is invalid.");
            }

            return StrictUtf8.GetString(ReadExact(stream, length));
        }

        private static byte[] ReadVariableBytes(Stream stream, int maximum)
        {
            var length = ReadInt32(stream);
            if (length <= 0 || length > maximum)
            {
                throw new StateStoreCorruptionException(
                    "An encoded relay byte-string length is invalid.");
            }

            return ReadExact(stream, length);
        }

        private static byte[] ReadExact(Stream stream, int count)
        {
            if (count < 0 || count > stream.Length - stream.Position)
            {
                throw new EndOfStreamException();
            }

            var result = new byte[count];
            var offset = 0;
            while (offset < count)
            {
                var read = stream.Read(result, offset, count - offset);
                if (read <= 0)
                {
                    throw new EndOfStreamException();
                }

                offset += read;
            }

            return result;
        }

        private static void RequireBytes(
            Stream stream,
            byte[] expected,
            string fieldName)
        {
            var actual = ReadExact(stream, expected.Length);
            var difference = 0;
            for (var index = 0; index < expected.Length; index++)
            {
                difference |= actual[index] ^ expected[index];
            }

            if (difference != 0)
            {
                throw new StateStoreCorruptionException(
                    "The " + fieldName + " is invalid.");
            }
        }

        private static int ReadInt32(Stream stream)
        {
            var bytes = ReadExact(stream, 4);
            return (bytes[0] << 24) |
                   (bytes[1] << 16) |
                   (bytes[2] << 8) |
                   bytes[3];
        }

        private static long ReadInt64(Stream stream)
        {
            var bytes = ReadExact(stream, 8);
            ulong value = ((ulong)bytes[0] << 56) |
                          ((ulong)bytes[1] << 48) |
                          ((ulong)bytes[2] << 40) |
                          ((ulong)bytes[3] << 32) |
                          ((ulong)bytes[4] << 24) |
                          ((ulong)bytes[5] << 16) |
                          ((ulong)bytes[6] << 8) |
                          bytes[7];
            return unchecked((long)value);
        }

        private static void WriteIdentifier(Stream stream, string value)
        {
            WriteString(stream, value, MaximumIdentifierBytes);
        }

        private static void WriteString(
            Stream stream,
            string value,
            int maximumBytes)
        {
            var encoded = StrictUtf8.GetBytes(value);
            if (encoded.Length == 0 || encoded.Length > maximumBytes)
            {
                throw new ArgumentException(
                    "An encoded relay string is empty or oversized.",
                    nameof(value));
            }

            WriteInt32(stream, encoded.Length);
            stream.Write(encoded, 0, encoded.Length);
        }

        private static void WriteFixedBytes(Stream stream, byte[] value)
        {
            stream.Write(value, 0, value.Length);
        }

        private static void WriteVariableBytes(
            Stream stream,
            byte[] value,
            int maximum)
        {
            if (value.Length == 0 || value.Length > maximum)
            {
                throw new ArgumentException(
                    "An encoded relay byte-string is empty or oversized.",
                    nameof(value));
            }

            WriteInt32(stream, value.Length);
            stream.Write(value, 0, value.Length);
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
}
