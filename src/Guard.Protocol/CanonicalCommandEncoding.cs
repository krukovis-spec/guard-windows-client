using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Guard.Contracts;

namespace Guard.Protocol
{
    public static class CanonicalCommandEncoding
    {
        private static readonly byte[] Magic = { 0x47, 0x52, 0x44, 0x32 };
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        public static byte[] EncodeForSignature(SignedCommandEnvelope envelope)
        {
            if (envelope == null)
            {
                throw new ArgumentNullException(nameof(envelope));
            }

            ValidateIdentifier(envelope.CommandId, nameof(envelope.CommandId));
            ValidateIdentifier(envelope.DeviceId, nameof(envelope.DeviceId));
            ValidateIdentifier(envelope.Nonce, nameof(envelope.Nonce));
            ValidateIdentifier(envelope.KeyId, nameof(envelope.KeyId));

            if (envelope.Sequence <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(envelope.Sequence));
            }

            if (envelope.ExpiresAtUtc <= envelope.IssuedAtUtc)
            {
                throw new ArgumentException("The command expiry must follow issuance.", nameof(envelope));
            }

            var payload = envelope.GetCanonicalPayloadCopy();
            if (payload.Length <= 0 || payload.Length > GuardProtocol.MaximumFrameBytes)
            {
                throw new ArgumentException("The canonical payload is empty or oversized.", nameof(envelope));
            }

            using (var stream = new MemoryStream())
            {
                stream.Write(Magic, 0, Magic.Length);
                WriteInt32(stream, GuardProtocol.CurrentVersion);
                WriteString(stream, envelope.CommandId);
                WriteString(stream, envelope.DeviceId);
                WriteInt64(stream, envelope.Sequence);
                WriteInt64(stream, GetCanonicalUnixTimeMilliseconds(envelope.IssuedAtUtc, nameof(envelope.IssuedAtUtc)));
                WriteInt64(stream, GetCanonicalUnixTimeMilliseconds(envelope.ExpiresAtUtc, nameof(envelope.ExpiresAtUtc)));
                WriteString(stream, envelope.Nonce);
                WriteString(stream, envelope.KeyId);
                WriteInt32(stream, payload.Length);
                stream.Write(payload, 0, payload.Length);
                return stream.ToArray();
            }
        }

        public static byte[] ComputeSignatureHash(SignedCommandEnvelope envelope)
        {
            var encoded = EncodeForSignature(envelope);
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(encoded);
            }
        }

        private static void ValidateIdentifier(string value, string parameterName)
        {
            if (!GuardIdentifier.IsCanonicalToken(value))
            {
                throw new ArgumentException("A canonical identifier is required.", parameterName);
            }
        }

        private static long GetCanonicalUnixTimeMilliseconds(DateTimeOffset value, string parameterName)
        {
            if (value.UtcDateTime.Ticks % TimeSpan.TicksPerMillisecond != 0)
            {
                throw new ArgumentException("Command timestamps must have exact millisecond precision.", parameterName);
            }

            return value.ToUnixTimeMilliseconds();
        }

        private static void WriteString(Stream stream, string value)
        {
            var bytes = StrictUtf8.GetBytes(value);
            if (bytes.Length > 1024)
            {
                throw new ArgumentException("An encoded identifier is oversized.", nameof(value));
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
