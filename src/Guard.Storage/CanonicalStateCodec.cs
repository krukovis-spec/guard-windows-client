using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Guard.Contracts;
using Guard.Domain;

namespace Guard.Storage
{
    internal static class CanonicalStateCodec
    {
        private static readonly byte[] Magic = { 0x47, 0x52, 0x44, 0x53, 0x54, 0x41, 0x54, 0x45 };
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        private const int SchemaVersion = 1;
        private const int MaximumEncodedStringBytes = 1024;
        public const int MaximumPayloadBytes = 128 * 1024;

        public static byte[] Encode(DeviceSecurityState state)
        {
            if (state == null)
            {
                throw new ArgumentNullException(nameof(state));
            }

            if (state.TrustedParentKeys.Count > DeviceSecurityState.MaximumTrustedParentKeys)
            {
                throw new ArgumentException("The authoritative state has too many trusted parent keys.", nameof(state));
            }

            using (var stream = new MemoryStream())
            {
                stream.Write(Magic, 0, Magic.Length);
                WriteInt32(stream, SchemaVersion);
                WriteString(stream, state.DeviceId);
                WriteInt64(stream, state.Version);
                WriteInt64(stream, state.HighestAcceptedSequence);
                WriteInt64(stream, state.DesiredPolicyRevision);

                WriteInt32(stream, state.RecentCommandIds.Count);
                for (var index = 0; index < state.RecentCommandIds.Count; index++)
                {
                    WriteString(stream, state.RecentCommandIds[index]);
                }

                var challenge = state.SetupChallenge;
                stream.WriteByte(challenge == null ? (byte)0 : (byte)1);
                if (challenge != null)
                {
                    WriteString(stream, challenge.ChallengeId);
                    var secretHash = challenge.GetSecretHashCopy();
                    stream.Write(secretHash, 0, secretHash.Length);
                    WriteInt64(stream, challenge.ExpiresAtUtc.UtcDateTime.Ticks);
                    stream.WriteByte(challenge.Consumed ? (byte)1 : (byte)0);
                }

                stream.WriteByte(state.ChildAccountSid == null ? (byte)0 : (byte)1);
                if (state.ChildAccountSid != null)
                {
                    WriteString(stream, state.ChildAccountSid.Value);
                }

                WriteInt32(stream, state.TrustedParentKeys.Count);
                for (var index = 0; index < state.TrustedParentKeys.Count; index++)
                {
                    var trustAnchor = state.TrustedParentKeys[index];
                    WriteInt32(stream, (int)trustAnchor.Algorithm);
                    var publicKey = trustAnchor.GetSubjectPublicKeyInfoCopy();
                    WriteInt32(stream, publicKey.Length);
                    stream.Write(publicKey, 0, publicKey.Length);
                }

                if (stream.Length > MaximumPayloadBytes)
                {
                    throw new ArgumentException("The authoritative state payload is oversized.", nameof(state));
                }

                return stream.ToArray();
            }
        }

        public static DeviceSecurityState Decode(byte[] payload)
        {
            if (payload == null || payload.Length == 0 || payload.Length > MaximumPayloadBytes)
            {
                throw new StateStoreCorruptionException("The authoritative state payload is empty or oversized.");
            }

            try
            {
                using (var stream = new MemoryStream(payload, writable: false))
                {
                    RequireMagic(stream);
                    if (ReadInt32(stream) != SchemaVersion)
                    {
                        throw new StateStoreCorruptionException("The authoritative state schema version is unsupported.");
                    }

                    var deviceId = ReadString(stream);
                    var version = ReadNonNegativeInt64(stream, "state version");
                    var highestAcceptedSequence = ReadNonNegativeInt64(stream, "accepted sequence");
                    var desiredPolicyRevision = ReadNonNegativeInt64(stream, "policy revision");

                    var recentCount = ReadBoundedCount(
                        stream,
                        DeviceSecurityState.MaximumRecentCommandIds,
                        "recent command id");
                    var recentCommandIds = new List<string>(recentCount);
                    for (var index = 0; index < recentCount; index++)
                    {
                        recentCommandIds.Add(ReadString(stream));
                    }

                    SetupChallengeState? setupChallenge = null;
                    var hasChallenge = ReadBoolean(stream, "setup-challenge presence");
                    if (hasChallenge)
                    {
                        var challengeId = ReadString(stream);
                        var secretHash = ReadExact(stream, SetupChallengeState.SecretHashBytes);
                        var expiryTicks = ReadInt64(stream);
                        if (expiryTicks < DateTimeOffset.MinValue.UtcDateTime.Ticks ||
                            expiryTicks > DateTimeOffset.MaxValue.UtcDateTime.Ticks)
                        {
                            throw new StateStoreCorruptionException("The setup challenge expiry is invalid.");
                        }

                        var expiry = new DateTimeOffset(new DateTime(expiryTicks, DateTimeKind.Utc));
                        var consumed = ReadBoolean(stream, "setup-challenge consumed flag");
                        setupChallenge = new SetupChallengeState(challengeId, secretHash, expiry, consumed);
                    }

                    WindowsAccountSid? childAccountSid = null;
                    if (ReadBoolean(stream, "child-account SID presence"))
                    {
                        childAccountSid = new WindowsAccountSid(ReadString(stream));
                    }

                    var parentKeyCount = ReadBoundedCount(
                        stream,
                        DeviceSecurityState.MaximumTrustedParentKeys,
                        "trusted parent key");
                    var trustedParentKeys = new List<ParentTrustAnchor>(parentKeyCount);
                    for (var index = 0; index < parentKeyCount; index++)
                    {
                        var algorithmValue = ReadInt32(stream);
                        if (!Enum.IsDefined(typeof(ParentKeyAlgorithm), algorithmValue))
                        {
                            throw new StateStoreCorruptionException("A trusted parent key algorithm is unsupported.");
                        }

                        var keyLength = ReadInt32(stream);
                        if (keyLength <= 0 || keyLength > GuardProtocol.MaximumParentPublicKeyBytes)
                        {
                            throw new StateStoreCorruptionException("A trusted parent public key length is invalid.");
                        }

                        trustedParentKeys.Add(new ParentTrustAnchor(
                            (ParentKeyAlgorithm)algorithmValue,
                            ReadExact(stream, keyLength)));
                    }

                    if (stream.Position != stream.Length)
                    {
                        throw new StateStoreCorruptionException("Trailing bytes are not allowed in authoritative state.");
                    }

                    return new DeviceSecurityState(
                        deviceId,
                        version,
                        highestAcceptedSequence,
                        desiredPolicyRevision,
                        recentCommandIds,
                        setupChallenge,
                        trustedParentKeys,
                        childAccountSid);
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
                    "The authoritative state payload is malformed.",
                    exception);
            }
        }

        private static void RequireMagic(Stream stream)
        {
            var actual = ReadExact(stream, Magic.Length);
            for (var index = 0; index < Magic.Length; index++)
            {
                if (actual[index] != Magic[index])
                {
                    throw new StateStoreCorruptionException("The authoritative state payload magic is invalid.");
                }
            }
        }

        private static int ReadBoundedCount(Stream stream, int maximum, string fieldName)
        {
            var value = ReadInt32(stream);
            if (value < 0 || value > maximum)
            {
                throw new StateStoreCorruptionException("The " + fieldName + " count is invalid.");
            }

            return value;
        }

        private static long ReadNonNegativeInt64(Stream stream, string fieldName)
        {
            var value = ReadInt64(stream);
            if (value < 0)
            {
                throw new StateStoreCorruptionException("The " + fieldName + " is invalid.");
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

            throw new StateStoreCorruptionException("The " + fieldName + " is invalid.");
        }

        private static string ReadString(Stream stream)
        {
            var byteCount = ReadInt32(stream);
            if (byteCount <= 0 || byteCount > MaximumEncodedStringBytes)
            {
                throw new StateStoreCorruptionException("An encoded state string length is invalid.");
            }

            return StrictUtf8.GetString(ReadExact(stream, byteCount));
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

        private static void WriteString(Stream stream, string value)
        {
            var bytes = StrictUtf8.GetBytes(value);
            if (bytes.Length == 0 || bytes.Length > MaximumEncodedStringBytes)
            {
                throw new ArgumentException("An encoded state string is empty or oversized.", nameof(value));
            }

            WriteInt32(stream, bytes.Length);
            stream.Write(bytes, 0, bytes.Length);
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
