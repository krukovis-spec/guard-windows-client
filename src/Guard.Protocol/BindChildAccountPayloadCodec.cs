using System;
using System.IO;
using System.Text;
using Guard.Contracts;

namespace Guard.Protocol
{
    public static class BindChildAccountPayloadCodec
    {
        private static readonly byte[] Magic = { 0x47, 0x43, 0x42, 0x32 };
        private static readonly Encoding Ascii = Encoding.ASCII;

        public static byte[] Encode(BindChildAccountRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var sidBytes = Ascii.GetBytes(request.CandidateSid);
            using (var stream = new MemoryStream())
            {
                stream.Write(Magic, 0, Magic.Length);
                WriteInt32(stream, GuardProtocol.CurrentVersion);
                WriteInt32(stream, sidBytes.Length);
                stream.Write(sidBytes, 0, sidBytes.Length);
                return stream.ToArray();
            }
        }

        public static BindChildAccountRequest Decode(byte[] payload)
        {
            if (payload == null || payload.Length == 0 || payload.Length > GuardProtocol.MaximumFrameBytes)
            {
                throw new InvalidDataException("The child-account binding payload is empty or oversized.");
            }

            try
            {
                using (var stream = new MemoryStream(payload, writable: false))
                {
                    var magic = ReadExact(stream, Magic.Length);
                    for (var index = 0; index < Magic.Length; index++)
                    {
                        if (magic[index] != Magic[index])
                        {
                            throw new InvalidDataException("The child-account binding payload magic is invalid.");
                        }
                    }

                    if (ReadInt32(stream) != GuardProtocol.CurrentVersion)
                    {
                        throw new InvalidDataException("The child-account binding payload version is unsupported.");
                    }

                    var sidLength = ReadInt32(stream);
                    if (sidLength <= 0 ||
                        sidLength > GuardProtocol.MaximumWindowsSidCharacters ||
                        sidLength != stream.Length - stream.Position)
                    {
                        throw new InvalidDataException("The child-account SID length is invalid.");
                    }

                    var sidBytes = ReadExact(stream, sidLength);
                    for (var index = 0; index < sidBytes.Length; index++)
                    {
                        if (sidBytes[index] > 0x7F)
                        {
                            throw new InvalidDataException("The child-account SID is not ASCII.");
                        }
                    }

                    var sid = Ascii.GetString(sidBytes);
                    try
                    {
                        return new BindChildAccountRequest(sid);
                    }
                    catch (ArgumentException exception)
                    {
                        throw new InvalidDataException("The child-account SID is invalid.", exception);
                    }
                }
            }
            catch (EndOfStreamException exception)
            {
                throw new InvalidDataException("The child-account binding payload ended unexpectedly.", exception);
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
