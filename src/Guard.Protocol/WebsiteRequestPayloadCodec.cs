using System;
using System.IO;
using System.Text;
using Guard.Contracts;

namespace Guard.Protocol
{
    public static class WebsiteRequestPayloadCodec
    {
        private static readonly byte[] Magic =
            { 0x47, 0x57, 0x52, 0x32 };
        private static readonly UTF8Encoding StrictUtf8 =
            new UTF8Encoding(false, true);

        public static byte[] Encode(
            CreateWebsiteRequestPayload request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var observationBytes =
                StrictUtf8.GetBytes(request.ObservationId);
            var reasonBytes = request.ShortReason == null
                ? null
                : StrictUtf8.GetBytes(request.ShortReason);
            if (observationBytes.Length == 0 ||
                observationBytes.Length >
                    GuardIdentifier.MaximumCharacters ||
                (reasonBytes != null &&
                 (reasonBytes.Length == 0 ||
                  reasonBytes.Length >
                      WebsiteRequestPayloadLimits
                          .MaximumShortReasonUtf8Bytes)))
            {
                throw new ArgumentException(
                    "The encoded website request fields are invalid.",
                    nameof(request));
            }

            using (var stream = new MemoryStream())
            {
                stream.Write(Magic, 0, Magic.Length);
                WriteInt32(stream, GuardProtocol.CurrentVersion);
                WriteInt32(stream, observationBytes.Length);
                WriteInt32(
                    stream,
                    reasonBytes == null ? -1 : reasonBytes.Length);
                stream.Write(
                    observationBytes,
                    0,
                    observationBytes.Length);
                if (reasonBytes != null)
                {
                    stream.Write(reasonBytes, 0, reasonBytes.Length);
                }

                if (stream.Length >
                    WebsiteRequestPayloadLimits.MaximumPayloadBytes)
                {
                    throw new ArgumentException(
                        "The website request payload is oversized.",
                        nameof(request));
                }

                return stream.ToArray();
            }
        }

        public static CreateWebsiteRequestPayload Decode(
            byte[] payload)
        {
            if (payload == null ||
                payload.Length == 0 ||
                payload.Length >
                    WebsiteRequestPayloadLimits.MaximumPayloadBytes)
            {
                throw new InvalidDataException(
                    "The website request payload is empty or oversized.");
            }

            var payloadSnapshot = (byte[])payload.Clone();
            try
            {
                using (var stream =
                    new MemoryStream(payloadSnapshot, writable: false))
                {
                    RequireMagic(stream);
                    if (ReadInt32(stream) !=
                        GuardProtocol.CurrentVersion)
                    {
                        throw new InvalidDataException(
                            "The website request payload version is unsupported.");
                    }

                    var observationLength = ReadInt32(stream);
                    var reasonLength = ReadInt32(stream);
                    if (observationLength <= 0 ||
                        observationLength >
                            GuardIdentifier.MaximumCharacters)
                    {
                        throw new InvalidDataException(
                            "The observation identifier length is invalid.");
                    }

                    if (reasonLength != -1 &&
                        (reasonLength <= 0 ||
                         reasonLength >
                             WebsiteRequestPayloadLimits
                                 .MaximumShortReasonUtf8Bytes))
                    {
                        throw new InvalidDataException(
                            "The optional short reason length is invalid.");
                    }

                    var expectedRemaining =
                        (long)observationLength +
                        (reasonLength < 0 ? 0L : reasonLength);
                    if (expectedRemaining !=
                        stream.Length - stream.Position)
                    {
                        throw new InvalidDataException(
                            "The website request field lengths are inconsistent.");
                    }

                    var observationId =
                        DecodeUtf8(
                            ReadExact(stream, observationLength),
                            "observation identifier");
                    var shortReason = reasonLength < 0
                        ? null
                        : DecodeUtf8(
                            ReadExact(stream, reasonLength),
                            "optional short reason");

                    if (stream.Position != stream.Length)
                    {
                        throw new InvalidDataException(
                            "Trailing website request bytes are not allowed.");
                    }

                    try
                    {
                        return new CreateWebsiteRequestPayload(
                            observationId,
                            shortReason);
                    }
                    catch (ArgumentException exception)
                    {
                        throw new InvalidDataException(
                            "The website request fields are invalid.",
                            exception);
                    }
                }
            }
            catch (EndOfStreamException exception)
            {
                throw new InvalidDataException(
                    "The website request payload ended unexpectedly.",
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
                    throw new InvalidDataException(
                        "The website request payload magic is invalid.");
                }
            }
        }

        private static string DecodeUtf8(
            byte[] bytes,
            string fieldName)
        {
            try
            {
                return StrictUtf8.GetString(bytes);
            }
            catch (DecoderFallbackException exception)
            {
                throw new InvalidDataException(
                    "The " + fieldName + " is not valid UTF-8.",
                    exception);
            }
        }

        private static byte[] ReadExact(Stream stream, int count)
        {
            if (count < 0 ||
                count > stream.Length - stream.Position)
            {
                throw new EndOfStreamException();
            }

            var result = new byte[count];
            var offset = 0;
            while (offset < count)
            {
                var read =
                    stream.Read(result, offset, count - offset);
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
