using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;

namespace Guard.Protocol
{
    public static class IpcFrameCodec
    {
        private static readonly byte[] Magic = { 0x47, 0x49, 0x50, 0x43 };
        private static readonly Encoding Ascii = Encoding.ASCII;

        public static byte[] Encode(GuardIpcRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            ValidateHeader(request.ProtocolVersion, request.RequestId, request.Verb, request.PayloadLength);
            var payload = request.GetPayloadCopy();

            using (var stream = new MemoryStream())
            {
                stream.Write(Magic, 0, Magic.Length);
                WriteInt32(stream, request.ProtocolVersion);
                var requestIdBytes = Ascii.GetBytes(request.RequestId);
                stream.Write(requestIdBytes, 0, requestIdBytes.Length);
                WriteInt32(stream, (int)request.Verb);
                WriteInt32(stream, payload.Length);
                stream.Write(payload, 0, payload.Length);
                return stream.ToArray();
            }
        }

        public static async Task<GuardIpcRequest> DecodeAsync(
            Stream stream,
            TimeSpan readTimeout,
            CancellationToken cancellationToken)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (readTimeout <= TimeSpan.Zero ||
                readTimeout > TimeSpan.FromMilliseconds(GuardProtocol.MaximumIpcReadTimeoutMilliseconds))
            {
                throw new ArgumentOutOfRangeException(nameof(readTimeout));
            }

            using (var readBudget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                readBudget.CancelAfter(readTimeout);
                var readToken = readBudget.Token;
                var magic = await ReadExactAsync(stream, Magic.Length, readToken).ConfigureAwait(false);
                for (var index = 0; index < Magic.Length; index++)
                {
                    if (magic[index] != Magic[index])
                    {
                        throw new InvalidDataException("The IPC frame magic is invalid.");
                    }
                }

                var protocolVersion = await ReadInt32Async(stream, readToken).ConfigureAwait(false);
                var requestId = Ascii.GetString(await ReadExactAsync(stream, 36, readToken).ConfigureAwait(false));
                var verbValue = await ReadInt32Async(stream, readToken).ConfigureAwait(false);
                var payloadLength = await ReadInt32Async(stream, readToken).ConfigureAwait(false);

                GuardVerb verb;
                if (!Enum.IsDefined(typeof(GuardVerb), verbValue))
                {
                    throw new InvalidDataException("The IPC verb is unknown.");
                }

                verb = (GuardVerb)verbValue;
                ValidateHeader(protocolVersion, requestId, verb, payloadLength);
                var payload = await ReadExactAsync(stream, payloadLength, readToken).ConfigureAwait(false);
                return new GuardIpcRequest(protocolVersion, requestId, verb, payload);
            }
        }

        private static void ValidateHeader(int protocolVersion, string requestId, GuardVerb verb, int payloadLength)
        {
            if (protocolVersion != GuardProtocol.CurrentVersion)
            {
                throw new InvalidDataException("The IPC protocol version is unsupported.");
            }

            Guid parsed;
            if (!Guid.TryParseExact(requestId, "D", out parsed))
            {
                throw new InvalidDataException("The IPC request id is invalid.");
            }

            if (!Enum.IsDefined(typeof(GuardVerb), verb) || verb == GuardVerb.Unknown)
            {
                throw new InvalidDataException("The IPC verb is unknown.");
            }

            if (payloadLength < 0 || payloadLength > GuardProtocol.MaximumFrameBytes)
            {
                throw new InvalidDataException("The IPC payload length is invalid.");
            }
        }

        private static async Task<byte[]> ReadExactAsync(Stream stream, int count, CancellationToken cancellationToken)
        {
            var result = new byte[count];
            var offset = 0;
            while (offset < count)
            {
                var read = await stream.ReadAsync(result, offset, count - offset, cancellationToken).ConfigureAwait(false);
                if (read <= 0)
                {
                    throw new EndOfStreamException("The IPC frame ended unexpectedly.");
                }

                offset += read;
            }

            return result;
        }

        private static async Task<int> ReadInt32Async(Stream stream, CancellationToken cancellationToken)
        {
            var bytes = await ReadExactAsync(stream, 4, cancellationToken).ConfigureAwait(false);
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
