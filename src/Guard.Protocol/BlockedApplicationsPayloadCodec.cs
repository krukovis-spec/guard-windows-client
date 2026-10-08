using System;
using System.IO;
using System.Text;
using Guard.Contracts;
using static Guard.Protocol.ServicePayloadCodecPrimitives;

namespace Guard.Protocol
{
    public static class BlockedApplicationsPayloadCodec
    {
        private static readonly byte[] ListMagic = { 0x47, 0x42, 0x4c, 0x31 }; // GBL1
        private static readonly byte[] QueuedMagic = { 0x47, 0x43, 0x41, 0x31 }; // GCA1
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        private const int MaximumBytes = 24 * 1024;

        public static byte[] Encode(BlockedApplicationsPayload payload)
        {
            if (payload == null) throw new ArgumentNullException(nameof(payload));
            using (var stream = Start(ListMagic))
            {
                WriteTime(stream, payload.CheckedAtUtc);
                WriteInt32(stream, payload.Items.Count);
                foreach (var item in payload.Items)
                {
                    WriteText(stream, item.ObservationId); WriteText(stream, item.DisplayName);
                    WriteTime(stream, item.ObservedAtUtc); WriteTime(stream, item.ExpiresAtUtc);
                }
                return stream.ToArray();
            }
        }

        public static BlockedApplicationsPayload Decode(byte[] payload) => Read(payload, ListMagic, stream =>
        {
            var now = ReadTime(stream);
            var count = ReadInt32(stream);
            if (count < 0 || count > BlockedApplicationsPayload.MaximumItems) throw new InvalidDataException("Invalid observation count.");
            var items = new BlockedApplicationItem[count];
            for (var i = 0; i < count; i++)
                items[i] = new BlockedApplicationItem(ReadText(stream, 128), ReadText(stream, 1024), ReadTime(stream), ReadTime(stream));
            return new BlockedApplicationsPayload(now, items);
        });

        public static byte[] EncodeQueued(ApplicationRequestQueuedPayload payload)
        {
            if (payload == null) throw new ArgumentNullException(nameof(payload));
            using (var stream = Start(QueuedMagic))
            {
                WriteText(stream, payload.RequestId);
                stream.WriteByte(payload.Created ? (byte)1 : (byte)0);
                WriteTime(stream, payload.ExpiresAtUtc);
                return stream.ToArray();
            }
        }

        public static ApplicationRequestQueuedPayload DecodeQueued(byte[] payload) => Read(payload, QueuedMagic, stream =>
        {
            var id = ReadText(stream, 128);
            var flag = stream.ReadByte();
            if (flag != 0 && flag != 1) throw new InvalidDataException("Invalid queue flag.");
            return new ApplicationRequestQueuedPayload(id, flag == 1, ReadTime(stream));
        });

        private static MemoryStream Start(byte[] magic)
        {
            var stream = new MemoryStream();
            stream.Write(magic, 0, magic.Length); WriteInt32(stream, GuardProtocol.CurrentVersion);
            return stream;
        }

        private static T Read<T>(byte[] payload, byte[] magic, Func<MemoryStream, T> decode)
        {
            if (payload == null || payload.Length < 8 || payload.Length > MaximumBytes) throw new InvalidDataException("Invalid child response size.");
            try
            {
                using (var stream = new MemoryStream((byte[])payload.Clone(), false))
                {
                    RequireMagic(stream, magic, "child response"); RequireCurrentVersion(stream, "child response");
                    var result = decode(stream);
                    if (stream.Position != stream.Length) throw new InvalidDataException("Trailing child response bytes.");
                    return result;
                }
            }
            catch (Exception error) when (error is ArgumentException || error is EndOfStreamException || error is OverflowException)
            { throw new InvalidDataException("Invalid child response fields.", error); }
        }

        // Preserve the source's exact UTC precision; never extend a historical event deadline.
        private static void WriteTime(Stream stream, DateTimeOffset value) => WriteInt64(stream, value.UtcDateTime.Ticks);
        private static DateTimeOffset ReadTime(Stream stream) => new DateTimeOffset(ReadInt64(stream), TimeSpan.Zero);
        private static void WriteText(Stream stream, string text)
        {
            var bytes = Utf8.GetBytes(text); WriteInt32(stream, bytes.Length); stream.Write(bytes, 0, bytes.Length);
        }
        private static string ReadText(Stream stream, int maximum)
        {
            var count = ReadInt32(stream);
            if (count <= 0 || count > maximum) throw new InvalidDataException("Invalid child text size.");
            return Utf8.GetString(ReadExact(stream, count));
        }
    }
}
