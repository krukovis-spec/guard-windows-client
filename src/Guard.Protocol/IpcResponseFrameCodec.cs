using System;
using System.IO;
using System.Text;
using Guard.Contracts;

namespace Guard.Protocol
{
    public static class IpcResponseFrameCodec
    {
        private static readonly byte[] Magic = { 0x47, 0x52, 0x53, 0x50 };
        private static readonly Encoding Ascii = Encoding.ASCII;

        public static byte[] Encode(GuardIpcResponse response)
        {
            if (response == null)
            {
                throw new ArgumentNullException(nameof(response));
            }

            ValidateHeader(
                response.ProtocolVersion,
                response.RequestId,
                response.Status,
                response.PayloadLength);
            var payload = response.GetPayloadCopy();
            using (var stream = new MemoryStream())
            {
                stream.Write(Magic, 0, Magic.Length);
                WriteInt32(stream, response.ProtocolVersion);
                var requestIdBytes = Ascii.GetBytes(response.RequestId);
                stream.Write(requestIdBytes, 0, requestIdBytes.Length);
                WriteInt32(stream, (int)response.Status);
                WriteInt32(stream, payload.Length);
                stream.Write(payload, 0, payload.Length);
                return stream.ToArray();
            }
        }

        public static GuardIpcResponse Decode(byte[] frame)
        {
            if (frame == null || frame.Length == 0 ||
                frame.Length > GuardProtocol.MaximumFrameBytes + 52)
            {
                throw new InvalidDataException("The IPC response frame is empty or oversized.");
            }

            try
            {
                using (var stream = new MemoryStream(frame, writable: false))
                {
                    var magic = ReadExact(stream, Magic.Length);
                    for (var index = 0; index < Magic.Length; index++)
                    {
                        if (magic[index] != Magic[index])
                        {
                            throw new InvalidDataException("The IPC response frame magic is invalid.");
                        }
                    }

                    var protocolVersion = ReadInt32(stream);
                    var requestId = Ascii.GetString(ReadExact(stream, 36));
                    var status = (GuardIpcResponseStatus)ReadInt32(stream);
                    var payloadLength = ReadInt32(stream);
                    ValidateHeader(protocolVersion, requestId, status, payloadLength);
                    if (payloadLength != stream.Length - stream.Position)
                    {
                        throw new InvalidDataException("The IPC response payload length is invalid.");
                    }

                    return new GuardIpcResponse(
                        protocolVersion,
                        requestId,
                        status,
                        ReadExact(stream, payloadLength));
                }
            }
            catch (EndOfStreamException exception)
            {
                throw new InvalidDataException("The IPC response frame ended unexpectedly.", exception);
            }
        }

        private static void ValidateHeader(
            int protocolVersion,
            string requestId,
            GuardIpcResponseStatus status,
            int payloadLength)
        {
            if (protocolVersion != GuardProtocol.CurrentVersion)
            {
                throw new InvalidDataException("The IPC response protocol version is unsupported.");
            }

            Guid parsed;
            if (!Guid.TryParseExact(requestId, "D", out parsed))
            {
                throw new InvalidDataException("The IPC response request id is invalid.");
            }

            if (!Enum.IsDefined(typeof(GuardIpcResponseStatus), status))
            {
                throw new InvalidDataException("The IPC response status is unknown.");
            }

            if (payloadLength < 0 || payloadLength > GuardProtocol.MaximumFrameBytes)
            {
                throw new InvalidDataException("The IPC response payload length is invalid.");
            }
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

        private static void WriteInt32(Stream stream, int value)
        {
            stream.WriteByte((byte)((value >> 24) & 0xFF));
            stream.WriteByte((byte)((value >> 16) & 0xFF));
            stream.WriteByte((byte)((value >> 8) & 0xFF));
            stream.WriteByte((byte)(value & 0xFF));
        }
    }
}
