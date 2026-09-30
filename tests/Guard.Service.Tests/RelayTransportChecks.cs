using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application.Relay;
using Guard.Contracts.Relay;
using Guard.Domain.Relay;
using Guard.Protocol.Relay;

namespace Guard.Service.Tests
{
    internal static class RelayTransportChecks
    {
        private const string Mailbox = "mailbox-test-00001";
        private const string Recipient = "recipient-test-0001";
        private const string Credential = "synthetic-test-credential-00000001";
        private static readonly Uri Origin = new Uri("https://relay.example.test/");

        public static async Task PreservesDurableOutboxAsync()
        {
            var raw = Frame(RelayFrameKind.Request, 1);
            var item = new RelayEncryptedOutboxItem("frame-test-000001", 1, RelayFrameKind.Request, Recipient, 1, raw);
            var state = EmptyState().WithPublishedRequest(
                new RelayTrackedRequest("request-test-0001", 1, new byte[32], new byte[32]), item);
            var store = new RecordingStore(state);
            var calls = 0;
            using var transport = Transport(async (request, cancellationToken) =>
            {
                Assert(request.RequestUri == new Uri(Origin, "v1/mailboxes/" + Mailbox + "/frames"), "Wrong publication URL.");
                Assert(request.Headers.Authorization?.Scheme == "Bearer" && request.Headers.Authorization.Parameter == Credential,
                    "Missing scoped credential.");
                Assert(request.Content!.Headers.ContentType?.MediaType == "application/octet-stream", "Wrong frame content type.");
                var submitted = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
                Assert(submitted.AsSpan().SequenceEqual(raw), "Retry changed the exact durable frame bytes.");
                return ++calls == 1 ? Json("{}", HttpStatusCode.ServiceUnavailable) :
                    Json("{\"frameId\":\"frame-test-000001\",\"duplicate\":true}");
            });
            await ThrowsAsync(() => transport.DeliverOutboxAsync(store, CancellationToken.None)).ConfigureAwait(false);
            Assert(store.State.Version == state.Version && store.CommitCount == 0, "HTTP failure committed delivery.");
            store.FailCommit = true;
            Assert(!await transport.DeliverOutboxAsync(store, CancellationToken.None).ConfigureAwait(false), "CAS loss reported success.");
            Assert(store.State.Outbox.Count == 1 && store.State.AcknowledgedOutboundCursor == 0, "CAS loss removed retry bytes.");
            store.FailCommit = false;
            Assert(await transport.DeliverOutboxAsync(store, CancellationToken.None).ConfigureAwait(false), "Retry did not drain outbox.");
            Assert(calls == 3 && store.State.Outbox.Count == 0 && store.State.AcknowledgedOutboundCursor == 1,
                "Duplicate delivery did not produce exactly one local effect.");
            Assert(store.State.CommittedInboundCursor == 0 && store.State.PolicyRevision == 0 && store.State.ReplayFloors.Count == 0,
                "Relay delivery changed approval authority.");

            var mismatchCalls = 0;
            using var mismatchTransport = Transport((_, _) =>
            {
                mismatchCalls++;
                return Task.FromResult(Json("{\"frameId\":\"frame-other-00001\",\"duplicate\":false}", HttpStatusCode.Created));
            });
            await ThrowsAsync(() => mismatchTransport.PublishAsync(
                new RelayEncryptedOutboxItem("frame-other-00001", 1, RelayFrameKind.Request, Recipient, 1, raw), CancellationToken.None)).ConfigureAwait(false);
            await ThrowsAsync(() => mismatchTransport.PublishAsync(
                new RelayEncryptedOutboxItem("frame-test-000001", 1, RelayFrameKind.Request, "recipient-other-01", 1, raw), CancellationToken.None)).ConfigureAwait(false);
            await ThrowsAsync(() => mismatchTransport.PublishAsync(
                new RelayEncryptedOutboxItem("frame-test-000001", 1, RelayFrameKind.Request, Recipient, 2, raw), CancellationToken.None)).ConfigureAwait(false);
            Assert(mismatchCalls == 0, "Mismatched durable metadata reached the relay.");

            var full = EmptyState();
            for (var cursor = 1; cursor <= RelayTransactionState.MaximumOutboxItems; cursor++)
            {
                var frameId = "frame-bounded-000" + cursor;
                full = full.WithPublishedRequest(
                    new RelayTrackedRequest("request-bounded-" + cursor, 1, new byte[32], new byte[32]),
                    new RelayEncryptedOutboxItem(frameId, cursor, RelayFrameKind.Request, Recipient, cursor,
                        Frame(RelayFrameKind.Request, cursor, frameId: frameId)));
            }
            var fullStore = new RecordingStore(full);
            var delivered = 0;
            using var boundedTransport = Transport(async (request, cancellationToken) =>
            {
                delivered++;
                var frame = RelayCanonicalEncoding.DecodeRelayFrame(
                    await request.Content!.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false));
                return Json(JsonSerializer.Serialize(new { frameId = frame.FrameId, duplicate = false }), HttpStatusCode.Created);
            });
            Assert(await boundedTransport.DeliverOutboxAsync(fullStore, CancellationToken.None).ConfigureAwait(false) &&
                delivered == RelayTransactionState.MaximumOutboxItems && fullStore.State.Outbox.Count == 0,
                "A full bounded outbox did not report successful drain.");

            const string viewRecipient = "recipient-view-0001";
            var phone1 = Frame(RelayFrameKind.Request, 1, frameId: "frame-phone-00001");
            var view1 = Frame(RelayFrameKind.Request, 1, recipient: viewRecipient, frameId: "frame-view-000001");
            var fanout = EmptyState().WithPublishedRequest(new RelayTrackedRequest("request-fanout-01", 1, new byte[32], new byte[32]),
                new RelayEncryptedOutboxItem("frame-phone-00001", 1, RelayFrameKind.Request, Recipient, 1, phone1),
                new RelayEncryptedOutboxItem("frame-view-000001", 2, RelayFrameKind.Request, viewRecipient, 1, view1));
            fanout = fanout.WithPublishedRequest(new RelayTrackedRequest("request-fanout-02", 1, new byte[32], new byte[32]),
                new RelayEncryptedOutboxItem("frame-phone-00002", 3, RelayFrameKind.Request, Recipient, 2,
                    Frame(RelayFrameKind.Request, 2, frameId: "frame-phone-00002")));
            var fanoutStore = new RecordingStore(fanout);
            var accepted = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            var heads = new Dictionary<string, long>(StringComparer.Ordinal);
            var loseViewResponse = true;
            using var fanoutTransport = Transport(async (request, cancellationToken) =>
            {
                var bytes = await request.Content!.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
                var frame = RelayCanonicalEncoding.DecodeRelayFrame(bytes);
                var duplicate = accepted.TryGetValue(frame.FrameId, out var prior);
                if (duplicate)
                    Assert(prior!.AsSpan().SequenceEqual(bytes), "A lost-response retry changed ciphertext or recipient cursor.");
                else
                {
                    heads.TryGetValue(frame.RecipientKeyId, out var head);
                    Assert(frame.Cursor == head + 1, "Global queue sequence leaked into a recipient's wire cursor.");
                    heads[frame.RecipientKeyId] = frame.Cursor;
                    accepted.Add(frame.FrameId, bytes);
                }
                if (frame.FrameId == "frame-view-000001" && loseViewResponse)
                {
                    loseViewResponse = false;
                    throw new HttpRequestException("Synthetic lost response after relay publication.");
                }
                return Json(JsonSerializer.Serialize(new { frameId = frame.FrameId, duplicate }),
                    duplicate ? HttpStatusCode.OK : HttpStatusCode.Created);
            });
            await ThrowsAsync(() => fanoutTransport.DeliverOutboxAsync(fanoutStore, CancellationToken.None)).ConfigureAwait(false);
            Assert(fanoutStore.State.AcknowledgedOutboundCursor == 1 && fanoutStore.State.Outbox.Count == 2 &&
                fanoutStore.State.Outbox[0].GetEncryptedFrameCopy().AsSpan().SequenceEqual(view1),
                "Partial recipient delivery dropped the lost-response frame.");
            Assert(await fanoutTransport.DeliverOutboxAsync(fanoutStore, CancellationToken.None).ConfigureAwait(false),
                "Independent recipient retry did not drain.");
            Assert(heads[Recipient] == 2 && heads[viewRecipient] == 1 && accepted.Count == 3 &&
                fanoutStore.State.AcknowledgedOutboundCursor == 3 && fanoutStore.State.RecipientOutboundCursors[Recipient] == 2 &&
                fanoutStore.State.RecipientOutboundCursors[viewRecipient] == 1 && fanoutStore.State.PolicyRevision == 0,
                "Delivery conflated queue heads, recipient heads, or policy authority.");
        }

        public static async Task ValidatesBoundedInboxAsync()
        {
            var first = Frame(RelayFrameKind.Approval, 1);
            var second = Frame(RelayFrameKind.Approval, 2, frameId: "frame-test-000002");
            var response = Inbox(2, first, second);
            var calls = 0;
            using var transport = Transport((request, _) =>
            {
                calls++;
                Assert(request.RequestUri!.Query == "?recipient=" + Recipient + "&after=0&limit=16", "Wrong polling bounds.");
                return Task.FromResult(Json(response));
            });
            var page = await transport.PollAsync(0, CancellationToken.None).ConfigureAwait(false);
            Assert(page.Count == 2 && page[0].AsSpan().SequenceEqual(first) && page[1].AsSpan().SequenceEqual(second),
                "Polling changed or reordered ciphertext.");
            var invalid = new List<string>
            {
                Inbox(1, first, first), Inbox(1, second, first), Inbox(3, first, second), Inbox(1),
                Inbox(1, Frame(RelayFrameKind.Request, 1)),
                Inbox(1, Frame(RelayFrameKind.Approval, 1, mailbox: "mailbox-other-0001")),
                Inbox(1, Frame(RelayFrameKind.Approval, 1, recipient: "recipient-other-01")),
                "{\"frames\":[],\"nextCursor\":0,\"nextCursor\":0}",
                "{\"frames\":[],\"nextCursor\":0,\"grant\":true}",
                "{\"frames\":[],\"nextCursor\":9007199254740992}",
                "{\"frames\":[\" " + Convert.ToBase64String(first) + "\"],\"nextCursor\":1}",
                Inbox(1, Frame(RelayFrameKind.Approval, 1, frameId: "frame:test:000001"))
            };
            var oversizedPage = new byte[HttpRelayTransport.PageSize + 1][];
            Array.Fill(oversizedPage, first);
            invalid.Add(Inbox(1, oversizedPage));
            foreach (var body in invalid)
            {
                response = body;
                await ThrowsAsync(() => transport.PollAsync(0, CancellationToken.None)).ConfigureAwait(false);
            }
            var before = calls;
            await ThrowsAsync(() => transport.PollAsync(HttpRelayTransport.MaximumCursor + 1, CancellationToken.None)).ConfigureAwait(false);
            Assert(calls == before, "Unsafe JS cursor reached HTTP.");
            response = Inbox(0);
            Assert((await transport.PollAsync(0, CancellationToken.None).ConfigureAwait(false)).Count == 0, "Empty inbox failed.");
        }

        public static async Task AcknowledgesOnlyCommittedCursorAsync()
        {
            var committed = new RelayTransactionState("device-test-00001", 3, 1, 1, 7, 0, 0, 0);
            var store = new RecordingStore(committed);
            var calls = 0;
            using var transport = Transport(async (request, cancellationToken) =>
            {
                calls++;
                using var json = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false));
                Assert(request.RequestUri!.AbsolutePath.EndsWith("/ack", StringComparison.Ordinal) &&
                    json.RootElement.GetProperty("recipientKeyId").GetString() == Recipient &&
                    json.RootElement.GetProperty("cursor").GetInt64() == 7, "Ack exceeded locally committed state.");
                return Json("{\"cursor\":999,\"duplicate\":true}");
            });
            await transport.AcknowledgeCommittedInboxAsync(store, CancellationToken.None).ConfigureAwait(false);
            Assert(ReferenceEquals(store.State, committed) && store.CommitCount == 0, "Untrusted ack hint advanced local state.");
            store.FailLoad = true;
            await ThrowsAsync(() => transport.AcknowledgeCommittedInboxAsync(store, CancellationToken.None)).ConfigureAwait(false);
            Assert(calls == 1, "State read failure sent an ack.");
            await transport.AcknowledgeCommittedInboxAsync(new RecordingStore(EmptyState()), CancellationToken.None).ConfigureAwait(false);
            Assert(calls == 1, "Empty state sent an ack.");
        }

        public static async Task RejectsUnsafeHttpAndCancelsBodyAsync()
        {
            foreach (var uri in new[] { "http://relay.example.test/", "https://user:pass@relay.example.test/",
                "https://relay.example.test/path", "https://relay.example.test/?token=hidden", "https://relay.example.test/#fragment",
                "https://localhost/", "https://127.0.0.1/", "https://relay.example.test:8443/" })
                Throws(() => { using var unused = new HttpRelayTransport(new Uri(uri), Mailbox, Recipient, Credential); });
            Throws(() => { using var unused = new HttpRelayTransport(Origin, "mailbox:test:0001", Recipient, Credential); });
            Throws(() => { using var unused = new HttpRelayTransport(Origin, Mailbox, Recipient, Credential + "\r\n"); });

            var item = new RelayEncryptedOutboxItem("frame-test-000001", 1, RelayFrameKind.Request, Recipient, 1, Frame(RelayFrameKind.Request, 1));
            foreach (var status in new[] { HttpStatusCode.TemporaryRedirect, HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden,
                HttpStatusCode.Conflict, HttpStatusCode.TooManyRequests, HttpStatusCode.ServiceUnavailable })
            {
                var calls = 0;
                using var transport = Transport((_, _) =>
                {
                    calls++;
                    var response = Json("{\"grant\":true}", status);
                    response.Headers.Location = new Uri("https://attacker.example.test/");
                    return Task.FromResult(response);
                });
                await ThrowsAsync(() => transport.PublishAsync(item, CancellationToken.None)).ConfigureAwait(false);
                Assert(calls == 1, "HTTP error or redirect was retried inside the transport.");
            }
            foreach (var body in new[] { "{\"frameId\":\"frame-other-00001\",\"duplicate\":false}",
                "{\"frameId\":\"frame-test-000001\",\"duplicate\":true}", new string(' ', 513) })
            {
                using var transport = Transport((_, _) => Task.FromResult(Json(body, HttpStatusCode.Created, streaming: true)));
                await ThrowsAsync(() => transport.PublishAsync(item, CancellationToken.None)).ConfigureAwait(false);
            }
            using (var transport = Transport((_, _) =>
            {
                var response = Json(Inbox(0));
                response.Content.Headers.ContentEncoding.Add("gzip");
                return Task.FromResult(response);
            }))
                await ThrowsAsync(() => transport.PollAsync(0, CancellationToken.None)).ConfigureAwait(false);

            using (var timeoutTransport = Transport((_, _) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamOnlyContent(new SlowStream()) }),
                TimeSpan.FromMilliseconds(50)))
                await ThrowsCancellationAsync(() => timeoutTransport.PollAsync(0, CancellationToken.None)).ConfigureAwait(false);
            using var canceled = new CancellationTokenSource();
            canceled.Cancel();
            using var canceledTransport = Transport(async (_, cancellationToken) =>
            {
                await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
                return Json(Inbox(0));
            });
            await ThrowsCancellationAsync(() => canceledTransport.PollAsync(0, canceled.Token)).ConfigureAwait(false);
        }

        private static RelayTransactionState EmptyState() => new RelayTransactionState("device-test-00001", 0, 1, 1, 0, 0, 0, 0);
        private static byte[] Frame(RelayFrameKind kind, long cursor, string mailbox = Mailbox,
            string recipient = Recipient, string frameId = "frame-test-000001") => RelayCanonicalEncoding.EncodeRelayFrame(
                new RelayFrame(kind, mailbox, recipient, frameId, cursor, 0, DateTimeOffset.FromUnixTimeMilliseconds(1700000000000),
                    DateTimeOffset.FromUnixTimeMilliseconds(1700000300000), new byte[65], new byte[16]));
        private static string Inbox(long next, params byte[][] frames) => JsonSerializer.Serialize(
            new { frames = Array.ConvertAll(frames, Convert.ToBase64String), nextCursor = next });
        private static HttpRelayTransport Transport(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send,
            TimeSpan? timeout = null) => new HttpRelayTransport(Origin, Mailbox, Recipient, Credential,
                new Handler(send), timeout ?? TimeSpan.FromSeconds(2));
        private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK, bool streaming = false) =>
            new HttpResponseMessage(status) { Content = streaming ? new StreamOnlyContent(new MemoryStream(Encoding.UTF8.GetBytes(body))) :
                new StringContent(body, Encoding.UTF8, "application/json") };
        private static void Assert(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
        private static void Throws(Action action)
        {
            try { action(); } catch (ArgumentException) { return; }
            throw new InvalidOperationException("Expected argument rejection.");
        }
        private static async Task ThrowsAsync(Func<Task> action)
        {
            try { await action().ConfigureAwait(false); }
            catch (Exception exception) when (exception is HttpRequestException || exception is InvalidDataException ||
                exception is ArgumentException || exception is JsonException || exception is InvalidOperationException || exception is FormatException)
            { return; }
            throw new InvalidOperationException("Expected fail-closed relay rejection.");
        }
        private static async Task ThrowsCancellationAsync(Func<Task> action)
        {
            try { await action().WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
            throw new InvalidOperationException("Expected bounded cancellation.");
        }
        private sealed class Handler : HttpMessageHandler
        {
            private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _send;
            public Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) { _send = send; }
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
                _send(request, cancellationToken);
        }
        private sealed class RecordingStore : IRelayTransactionStore
        {
            public RecordingStore(RelayTransactionState state) { State = state; }
            public RelayTransactionState State { get; private set; }
            public bool FailCommit { get; set; }
            public bool FailLoad { get; set; }
            public int CommitCount { get; private set; }
            public Task<RelayTransactionState> LoadAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (FailLoad) throw new InvalidDataException("Synthetic state read failure.");
                return Task.FromResult(State);
            }
            public Task<bool> TryCommitAsync(long version, RelayTransactionState next, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                CommitCount++;
                if (FailCommit || version != State.Version) return Task.FromResult(false);
                State = next;
                return Task.FromResult(true);
            }
        }
        private sealed class StreamOnlyContent : HttpContent
        {
            private readonly Stream _stream;
            public StreamOnlyContent(Stream stream) { _stream = stream; Headers.ContentType = new MediaTypeHeaderValue("application/json"); }
            protected override bool TryComputeLength(out long length) { length = 0; return false; }
            protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => _stream.CopyToAsync(stream);
            protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult(_stream);
            protected override void Dispose(bool disposing) { if (disposing) _stream.Dispose(); base.Dispose(disposing); }
        }
        private sealed class SlowStream : Stream
        {
            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            { await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false); return 0; }
            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override void Flush() => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }
    }
}
