using System;
using System.IO;
using System.Text;
using Guard.Contracts;

namespace Guard.Protocol
{
    public static class ParentDecisionPayloadCodec
    {
        private static readonly byte[] Magic = { 0x47, 0x50, 0x44, 0x32 };
        private static readonly Encoding Ascii = Encoding.ASCII;
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        public static byte[] Encode(ParentDecisionCommand command)
        {
            if (command == null)
            {
                throw new ArgumentNullException(nameof(command));
            }

            var targetBytes = StrictUtf8.GetBytes(command.TargetIdentity);
            if (targetBytes.Length == 0 || targetBytes.Length > GuardProtocol.MaximumFrameBytes)
            {
                throw new ArgumentException("The encoded target identity is empty or oversized.", nameof(command));
            }

            using (var stream = new MemoryStream())
            {
                stream.Write(Magic, 0, Magic.Length);
                WriteInt32(stream, GuardProtocol.CurrentVersion);
                var requestIdBytes = Ascii.GetBytes(command.RequestId);
                stream.Write(requestIdBytes, 0, requestIdBytes.Length);
                WriteInt32(stream, (int)command.TargetKind);
                WriteInt32(stream, (int)command.Decision);
                WriteInt32(stream, command.TemporaryMinutes ?? 0);
                WriteInt32(stream, command.DailyQuotaMinutes ?? 0);
                WriteInt32(stream, targetBytes.Length);
                stream.Write(targetBytes, 0, targetBytes.Length);
                if (stream.Length > GuardProtocol.MaximumFrameBytes)
                {
                    throw new ArgumentException("The parent decision payload is oversized.", nameof(command));
                }

                return stream.ToArray();
            }
        }

        public static ParentDecisionCommand Decode(byte[] payload)
        {
            if (payload == null || payload.Length == 0 || payload.Length > GuardProtocol.MaximumFrameBytes)
            {
                throw new InvalidDataException("The parent decision payload is empty or oversized.");
            }

            using (var stream = new MemoryStream(payload, writable: false))
            {
                var magic = ReadExact(stream, Magic.Length);
                for (var index = 0; index < Magic.Length; index++)
                {
                    if (magic[index] != Magic[index])
                    {
                        throw new InvalidDataException("The parent decision payload magic is invalid.");
                    }
                }

                if (ReadInt32(stream) != GuardProtocol.CurrentVersion)
                {
                    throw new InvalidDataException("The parent decision payload version is unsupported.");
                }

                var requestId = Ascii.GetString(ReadExact(stream, 36));
                var targetKind = (GuardTargetKind)ReadInt32(stream);
                var decision = (ParentDecisionKind)ReadInt32(stream);
                var temporaryMinutes = ReadInt32(stream);
                var dailyQuotaMinutes = ReadInt32(stream);
                var targetLength = ReadInt32(stream);
                if (targetLength <= 0 || targetLength > GuardProtocol.MaximumFrameBytes || targetLength > stream.Length - stream.Position)
                {
                    throw new InvalidDataException("The target identity length is invalid.");
                }

                string targetIdentity;
                try
                {
                    targetIdentity = StrictUtf8.GetString(ReadExact(stream, targetLength));
                }
                catch (DecoderFallbackException exception)
                {
                    throw new InvalidDataException("The target identity is not valid UTF-8.", exception);
                }

                if (stream.Position != stream.Length)
                {
                    throw new InvalidDataException("Trailing bytes are not allowed in a parent decision payload.");
                }

                try
                {
                    return new ParentDecisionCommand(
                        requestId,
                        targetKind,
                        targetIdentity,
                        decision,
                        temporaryMinutes == 0 ? (int?)null : temporaryMinutes,
                        dailyQuotaMinutes == 0 ? (int?)null : dailyQuotaMinutes);
                }
                catch (ArgumentException exception)
                {
                    throw new InvalidDataException("The parent decision payload fields are invalid.", exception);
                }
            }
        }

        private static byte[] ReadExact(Stream stream, int count)
        {
            var result = new byte[count];
            var offset = 0;
            while (offset < count)
            {
                var read = stream.Read(result, offset, count - offset);
                if (read <= 0)
                {
                    throw new EndOfStreamException("The parent decision payload ended unexpectedly.");
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

        private static void WriteInt32(Stream stream, int value)
        {
            stream.WriteByte((byte)((value >> 24) & 0xFF));
            stream.WriteByte((byte)((value >> 16) & 0xFF));
            stream.WriteByte((byte)((value >> 8) & 0xFF));
            stream.WriteByte((byte)(value & 0xFF));
        }
    }
}
