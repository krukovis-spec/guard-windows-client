using System;
using System.IO;
using System.Text;
using Guard.Contracts;

namespace Guard.Protocol
{
    public static class GuardStatusPayloadCodec
    {
        private static readonly byte[] Magic = { 0x47, 0x53, 0x54, 0x32 };
        private const int EncodedBytes = 4 + 4 + 8 + 1;

        public static byte[] Encode(GuardStatusPayload payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }

            using (var stream = new MemoryStream(EncodedBytes))
            {
                stream.Write(Magic, 0, Magic.Length);
                ServicePayloadCodecPrimitives.WriteInt32(
                    stream,
                    GuardProtocol.CurrentVersion);
                ServicePayloadCodecPrimitives.WriteInt64(
                    stream,
                    payload.StateVersion);
                var flags = 0;
                if (payload.IsProvisioned)
                {
                    flags |= 0x01;
                }

                if (payload.IsChildAccountBound)
                {
                    flags |= 0x02;
                }

                stream.WriteByte((byte)flags);
                return stream.ToArray();
            }
        }

        public static GuardStatusPayload Decode(byte[] payload)
        {
            if (payload == null || payload.Length != EncodedBytes)
            {
                throw new InvalidDataException(
                    "The Guard status payload length is invalid.");
            }

            using (var stream = new MemoryStream(payload, writable: false))
            {
                ServicePayloadCodecPrimitives.RequireMagic(
                    stream,
                    Magic,
                    "Guard status");
                ServicePayloadCodecPrimitives.RequireCurrentVersion(
                    stream,
                    "Guard status");
                var stateVersion =
                    ServicePayloadCodecPrimitives.ReadInt64(stream);
                var flags = stream.ReadByte();
                if (stateVersion < 0 || flags < 0 || (flags & ~0x03) != 0)
                {
                    throw new InvalidDataException(
                        "The Guard status payload is invalid.");
                }

                return new GuardStatusPayload(
                    stateVersion,
                    isProvisioned: (flags & 0x01) != 0,
                    isChildAccountBound: (flags & 0x02) != 0);
            }
        }
    }

    public static class SetupTicketPayloadCodec
    {
        private static readonly byte[] Magic = { 0x47, 0x53, 0x51, 0x32 };
        private static readonly Encoding Ascii = Encoding.ASCII;
        private const int FixedBytes = 4 + 4 + 4 + 4 + 8;

        public static byte[] Encode(SetupTicketPayload payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }

            var challengeBytes = Ascii.GetBytes(payload.ChallengeId);
            var secret = payload.GetSecretCopy();
            try
            {
                using (var stream = new MemoryStream(
                    FixedBytes + challengeBytes.Length + secret.Length))
                {
                    stream.Write(Magic, 0, Magic.Length);
                    ServicePayloadCodecPrimitives.WriteInt32(
                        stream,
                        GuardProtocol.CurrentVersion);
                    ServicePayloadCodecPrimitives.WriteInt32(
                        stream,
                        challengeBytes.Length);
                    stream.Write(
                        challengeBytes,
                        0,
                        challengeBytes.Length);
                    ServicePayloadCodecPrimitives.WriteInt32(
                        stream,
                        secret.Length);
                    stream.Write(secret, 0, secret.Length);
                    ServicePayloadCodecPrimitives.WriteInt64(
                        stream,
                        payload.ExpiresAtUtc.ToUnixTimeMilliseconds());
                    return stream.ToArray();
                }
            }
            finally
            {
                Array.Clear(secret, 0, secret.Length);
            }
        }

        public static SetupTicketPayload Decode(byte[] payload)
        {
            if (payload == null ||
                payload.Length <= FixedBytes ||
                payload.Length > GuardProtocol.MaximumFrameBytes)
            {
                throw new InvalidDataException(
                    "The setup ticket payload is empty or oversized.");
            }

            try
            {
                using (var stream = new MemoryStream(payload, writable: false))
                {
                    ServicePayloadCodecPrimitives.RequireMagic(
                        stream,
                        Magic,
                        "setup ticket");
                    ServicePayloadCodecPrimitives.RequireCurrentVersion(
                        stream,
                        "setup ticket");
                    var challengeLength =
                        ServicePayloadCodecPrimitives.ReadInt32(stream);
                    if (challengeLength < GuardIdentifier.MinimumCharacters ||
                        challengeLength > GuardIdentifier.MaximumCharacters)
                    {
                        throw new InvalidDataException(
                            "The setup challenge id length is invalid.");
                    }

                    var challengeBytes =
                        ServicePayloadCodecPrimitives.ReadExact(
                            stream,
                            challengeLength);
                    for (var index = 0;
                         index < challengeBytes.Length;
                         index++)
                    {
                        if (challengeBytes[index] > 0x7F)
                        {
                            throw new InvalidDataException(
                                "The setup challenge id is not ASCII.");
                        }
                    }

                    var secretLength =
                        ServicePayloadCodecPrimitives.ReadInt32(stream);
                    if (secretLength != GuardProtocol.SetupSecretBytes)
                    {
                        throw new InvalidDataException(
                            "The setup secret length is invalid.");
                    }

                    var secret = ServicePayloadCodecPrimitives.ReadExact(
                        stream,
                        secretLength);
                    var expiresUnixMilliseconds =
                        ServicePayloadCodecPrimitives.ReadInt64(stream);
                    if (stream.Position != stream.Length)
                    {
                        throw new InvalidDataException(
                            "The setup ticket payload contains trailing data.");
                    }

                    try
                    {
                        return new SetupTicketPayload(
                            Ascii.GetString(challengeBytes),
                            secret,
                            DateTimeOffset.FromUnixTimeMilliseconds(
                                expiresUnixMilliseconds));
                    }
                    catch (ArgumentException exception)
                    {
                        throw new InvalidDataException(
                            "The setup ticket payload is invalid.",
                            exception);
                    }
                    finally
                    {
                        Array.Clear(secret, 0, secret.Length);
                    }
                }
            }
            catch (EndOfStreamException exception)
            {
                throw new InvalidDataException(
                    "The setup ticket payload ended unexpectedly.",
                    exception);
            }
            catch (ArgumentOutOfRangeException exception)
            {
                throw new InvalidDataException(
                    "The setup ticket expiry is invalid.",
                    exception);
            }
        }
    }

    public static class ChildAccountBindingPayloadCodec
    {
        private static readonly byte[] Magic = { 0x47, 0x43, 0x52, 0x32 };
        private const int EncodedBytes = 4 + 4 + 1;

        public static byte[] Encode(ChildAccountBindingPayload payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }

            using (var stream = new MemoryStream(EncodedBytes))
            {
                stream.Write(Magic, 0, Magic.Length);
                ServicePayloadCodecPrimitives.WriteInt32(
                    stream,
                    GuardProtocol.CurrentVersion);
                stream.WriteByte(
                    payload.ServiceRestartRequired
                        ? (byte)0x01
                        : (byte)0x00);
                return stream.ToArray();
            }
        }

        public static ChildAccountBindingPayload Decode(byte[] payload)
        {
            if (payload == null || payload.Length != EncodedBytes)
            {
                throw new InvalidDataException(
                    "The child-account binding result length is invalid.");
            }

            using (var stream = new MemoryStream(payload, writable: false))
            {
                ServicePayloadCodecPrimitives.RequireMagic(
                    stream,
                    Magic,
                    "child-account binding result");
                ServicePayloadCodecPrimitives.RequireCurrentVersion(
                    stream,
                    "child-account binding result");
                var flags = stream.ReadByte();
                if (flags < 0 || (flags & ~0x01) != 0)
                {
                    throw new InvalidDataException(
                        "The child-account binding result is invalid.");
                }

                return new ChildAccountBindingPayload(
                    serviceRestartRequired: (flags & 0x01) != 0);
            }
        }
    }

    internal static class ServicePayloadCodecPrimitives
    {
        public static byte[] ReadExact(Stream stream, int count)
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

        public static void RequireMagic(
            Stream stream,
            byte[] expected,
            string payloadName)
        {
            var actual = ReadExact(stream, expected.Length);
            for (var index = 0; index < expected.Length; index++)
            {
                if (actual[index] != expected[index])
                {
                    throw new InvalidDataException(
                        "The " + payloadName + " payload magic is invalid.");
                }
            }
        }

        public static void RequireCurrentVersion(
            Stream stream,
            string payloadName)
        {
            if (ReadInt32(stream) != GuardProtocol.CurrentVersion)
            {
                throw new InvalidDataException(
                    "The " + payloadName +
                    " payload version is unsupported.");
            }
        }

        public static int ReadInt32(Stream stream)
        {
            var bytes = ReadExact(stream, 4);
            return (bytes[0] << 24) |
                   (bytes[1] << 16) |
                   (bytes[2] << 8) |
                   bytes[3];
        }

        public static long ReadInt64(Stream stream)
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

        public static void WriteInt32(Stream stream, int value)
        {
            stream.WriteByte((byte)((value >> 24) & 0xFF));
            stream.WriteByte((byte)((value >> 16) & 0xFF));
            stream.WriteByte((byte)((value >> 8) & 0xFF));
            stream.WriteByte((byte)(value & 0xFF));
        }

        public static void WriteInt64(Stream stream, long value)
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
