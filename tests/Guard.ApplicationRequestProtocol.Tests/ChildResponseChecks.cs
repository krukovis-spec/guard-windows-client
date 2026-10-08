using System;
using System.IO;
using System.Linq;
using Guard.Contracts;
using Guard.Protocol;

namespace Guard.ApplicationRequestProtocol.Tests;

internal static class ChildResponseChecks
{
    internal static void Run()
    {
        var now = new DateTimeOffset(2026, 10, 8, 12, 0, 0, TimeSpan.Zero).AddTicks(37);
        var item = new BlockedApplicationItem("blocked-event-0001", "Программа 😀", now, now.AddMinutes(10));
        var list = new BlockedApplicationsPayload(now, new[] { item });
        var encoded = BlockedApplicationsPayloadCodec.Encode(list);
        var decoded = BlockedApplicationsPayloadCodec.Decode(encoded);
        Check(decoded.CheckedAtUtc == now && decoded.Items.Single().DisplayName == item.DisplayName &&
            decoded.Items[0].ExpiresAtUtc == item.ExpiresAtUtc, "list precision/Unicode");
        var queued = BlockedApplicationsPayloadCodec.EncodeQueued(new ApplicationRequestQueuedPayload("request-00000001", false, now.AddMinutes(5)));
        Check(!BlockedApplicationsPayloadCodec.DecodeQueued(queued).Created, "duplicate flag");
        foreach (var (bytes, decode) in new (byte[], Action<byte[]>)[] {
            (encoded, b => BlockedApplicationsPayloadCodec.Decode(b)), (queued, b => BlockedApplicationsPayloadCodec.DecodeQueued(b)) })
        {
            for (var count = 0; count < bytes.Length; count++) Reject(() => decode(bytes.Take(count).ToArray()));
            Reject(() => decode(bytes.Concat(new byte[] { 0 }).ToArray()));
            var bad = (byte[])bytes.Clone(); bad[0] = 0; Reject(() => decode(bad));
            bad = (byte[])bytes.Clone(); bad[7] = 2; Reject(() => decode(bad));
        }
        var many = (byte[])encoded.Clone(); many[19] = 17; Reject(() => BlockedApplicationsPayloadCodec.Decode(many));
        var invalidFlag = (byte[])queued.Clone(); invalidFlag[invalidFlag.Length - 9] = 2;
        Reject(() => BlockedApplicationsPayloadCodec.DecodeQueued(invalidFlag));
        Reject(() => new BlockedApplicationsPayload(now, new[] { item, item }));
        Reject(() => new BlockedApplicationsPayload(item.ExpiresAtUtc, new[] { item }));
        Reject(() => new BlockedApplicationsPayload(now.AddTicks(-1), new[] { item }));
        foreach (var text in new[] { " ", "bad\u202ename", "bad\0name", "bad\ud800", new string('a', 257) })
            Reject(() => new BlockedApplicationItem(item.ObservationId, text, now, now.AddMinutes(1)));
        var empty = BlockedApplicationsPayloadCodec.Decode(BlockedApplicationsPayloadCodec.Encode(new BlockedApplicationsPayload(now, Array.Empty<BlockedApplicationItem>())));
        Check(empty.Items.Count == 0, "empty historical list");
    }
    private static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static void Reject(Action action)
    {
        try { action(); } catch (Exception error) when (error is InvalidDataException or ArgumentException) { return; }
        throw new InvalidOperationException("Malformed child response accepted.");
    }
}
