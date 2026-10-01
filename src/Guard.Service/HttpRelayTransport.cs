using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application.Relay;
using Guard.Contracts;
using Guard.Contracts.Relay;
using Guard.Domain.Relay;
using Guard.Protocol.Relay;
using Guard.Windows;

namespace Guard.Service
{
    /// <summary>
    /// Ciphertext-only transport. Delivery is not approval or policy application.
    /// Enrollment must pin the origin and credentials before constructing this adapter.
    /// No network activity occurs in the constructor.
    /// </summary>
    internal sealed class HttpRelayTransport : IDisposable
    {
        internal const long MaximumCursor = RelayTransactionState.MaximumRecipientCursor;
        internal const int PageSize = 16;
        private const int MaximumEncodedFrameCharacters = ((RelayProtocol.MaximumFrameBytes + 2) / 3) * 4;
        private const int MaximumPollResponseBytes = PageSize * (MaximumEncodedFrameCharacters + 4) + 128;
        private readonly HttpClient _client;
        private readonly Uri _mailboxUri;
        private readonly string _mailboxId;
        private readonly string _recipientKeyId;
        private readonly string _accessToken;
        private readonly TimeSpan _requestTimeout;

        public HttpRelayTransport(Uri origin, string mailboxId, string recipientKeyId, string accessToken)
            : this(origin, mailboxId, recipientKeyId, accessToken, null, TimeSpan.FromSeconds(20))
        {
        }

        internal HttpRelayTransport(Uri origin, string mailboxId, string recipientKeyId, string accessToken,
            HttpMessageHandler? handler, TimeSpan requestTimeout)
        {
            RequireOrigin(origin);
            RequireIdentifier(mailboxId);
            RequireIdentifier(recipientKeyId);
            RequireCredential(accessToken);
            if (requestTimeout <= TimeSpan.Zero || requestTimeout > TimeSpan.FromSeconds(30))
                throw new ArgumentOutOfRangeException(nameof(requestTimeout));

            _mailboxId = mailboxId;
            _recipientKeyId = recipientKeyId;
            _accessToken = accessToken;
            _mailboxUri = new Uri(origin, "v1/mailboxes/" + mailboxId + "/");
            _requestTimeout = requestTimeout;
            _client = new HttpClient(handler ?? new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                UseProxy = false,
                AutomaticDecompression = DecompressionMethods.None,
                ConnectTimeout = TimeSpan.FromSeconds(5),
                MaxResponseHeadersLength = 8,
                MaxConnectionsPerServer = 2,
                PooledConnectionLifetime = TimeSpan.FromMinutes(5)
            }, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
        }

        internal static void RequireOrigin(Uri origin)
        {
            if (origin == null || !origin.IsAbsoluteUri || origin.Scheme != Uri.UriSchemeHttps ||
                !origin.IsDefaultPort || origin.HostNameType != UriHostNameType.Dns || origin.IsLoopback ||
                origin.UserInfo.Length != 0 || origin.AbsolutePath != "/" || origin.Query.Length != 0 || origin.Fragment.Length != 0)
                throw new ArgumentException("An enrollment-pinned HTTPS origin is required.", nameof(origin));
        }

        internal static void RequireCredential(string accessToken)
        {
            if (accessToken == null || accessToken.Length < 32 || accessToken.Length > 512)
                throw new ArgumentException("A bounded relay credential is required.", nameof(accessToken));
            foreach (var character in accessToken)
                if (character < '!' || character > '~')
                    throw new ArgumentException("Invalid relay credential encoding.", nameof(accessToken));
        }

        // One bounded pass. Failure/CAS conflict retains the exact durable bytes for retry.
        public async Task<bool> DeliverOutboxAsync(IRelayTransactionStore store, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(store);
            for (var index = 0; index < RelayTransactionState.MaximumOutboxItems; index++)
            {
                var state = await store.LoadAsync(cancellationToken).ConfigureAwait(false);
                if (state.Outbox.Count == 0) return true;
                var item = state.Outbox[0];
                await PublishAsync(item, cancellationToken).ConfigureAwait(false);
                if (!await store.TryCommitAsync(state.Version,
                    state.WithAcknowledgedOutboundCursor(item.OutboundCursor), cancellationToken).ConfigureAwait(false))
                    return false;
            }
            return (await store.LoadAsync(cancellationToken).ConfigureAwait(false)).Outbox.Count == 0;
        }

        public async Task PublishAsync(RelayEncryptedOutboxItem item, CancellationToken cancellationToken)
        {
            var (_, bytes) = RequireDeviceOutboxFrame(item);
            using var content = new ByteArrayContent(bytes);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            using var result = await SendAsync(HttpMethod.Post, "frames", content, 512,
                cancellationToken, HttpStatusCode.OK, HttpStatusCode.Created).ConfigureAwait(false);
            ReadRemoteResponse(() =>
            {
                RequireObject(result.Document.RootElement, "frameId", "duplicate");
                if (result.Document.RootElement.GetProperty("frameId").GetString() != item.FrameId ||
                    result.Document.RootElement.GetProperty("duplicate").GetBoolean() != (result.Status == HttpStatusCode.OK))
                    throw new InvalidDataException("Relay publication response does not match the submitted frame.");
                return true;
            });
        }

        public async Task RetireExpiredAsync(RelayEncryptedOutboxItem item, DateTimeOffset now, CancellationToken cancellationToken)
        {
            var (frame, bytes) = RequireDeviceOutboxFrame(item);
            if (now < frame.ExpiresAtUtc) throw new InvalidDataException("Only a locally expired frame can be retired.");
            using var content = new ByteArrayContent(bytes);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            using var result = await SendAsync(HttpMethod.Post, "frames/retire", content, 512, cancellationToken, HttpStatusCode.OK).ConfigureAwait(false);
            ReadRemoteResponse(() =>
            {
                RequireObject(result.Document.RootElement, "frameId", "cursor", "retired");
                if (result.Document.RootElement.GetProperty("frameId").GetString() != item.FrameId ||
                    result.Document.RootElement.GetProperty("cursor").GetInt64() != item.RecipientCursor ||
                    !result.Document.RootElement.GetProperty("retired").GetBoolean())
                    throw new InvalidDataException("Relay retirement response does not match the expired frame.");
                return true;
            });
        }

        private (RelayFrame Frame, byte[] Bytes) RequireDeviceOutboxFrame(RelayEncryptedOutboxItem item)
        {
            ArgumentNullException.ThrowIfNull(item);
            var bytes = item.GetEncryptedFrameCopy();
            var frame = RelayCanonicalEncoding.DecodeRelayFrame(bytes);
            RequireFrameBinding(frame);
            if (frame.FrameId != item.FrameId || frame.Cursor != item.RecipientCursor ||
                frame.RecipientKeyId != item.RecipientKeyId || frame.Kind != item.Kind ||
                (frame.Kind != RelayFrameKind.Request && frame.Kind != RelayFrameKind.Receipt) || frame.Cursor == 0)
                throw new InvalidDataException("Durable outbox metadata does not match its device frame.");
            return (frame, bytes);
        }

        /// <summary>
        /// Returns untrusted, bounded, ordered ciphertext. The caller must decrypt, verify,
        /// and atomically persist each semantic outcome before acknowledging its cursor.
        /// </summary>
        public async Task<IReadOnlyList<byte[]>> PollAsync(long after, CancellationToken cancellationToken)
        {
            RequireCursor(after);
            var path = "poll?recipient=" + _recipientKeyId + "&after=" + after.ToString(CultureInfo.InvariantCulture) +
                "&limit=" + PageSize.ToString(CultureInfo.InvariantCulture);
            using var result = await SendAsync(HttpMethod.Get, path, null, MaximumPollResponseBytes,
                cancellationToken, HttpStatusCode.OK).ConfigureAwait(false);
            return ReadRemoteResponse(() => ReadInboxPage(result.Document.RootElement, after));
        }

        private IReadOnlyList<byte[]> ReadInboxPage(JsonElement root, long after)
        {
            RequireObject(root, "frames", "nextCursor");
            var encodedFrames = root.GetProperty("frames");
            if (encodedFrames.ValueKind != JsonValueKind.Array || encodedFrames.GetArrayLength() > PageSize)
                throw new InvalidDataException("Relay inbox exceeds the bounded page size.");
            var frames = new List<byte[]>();
            var cursor = after;
            foreach (var encoded in encodedFrames.EnumerateArray())
            {
                var text = encoded.GetString();
                if (string.IsNullOrEmpty(text) || text.Length > MaximumEncodedFrameCharacters)
                    throw new InvalidDataException("Invalid relay frame size.");
                var bytes = Convert.FromBase64String(text);
                if (Convert.ToBase64String(bytes) != text)
                    throw new InvalidDataException("Noncanonical relay base64.");
                var frame = RelayCanonicalEncoding.DecodeRelayFrame(bytes);
                RequireFrameBinding(frame);
                if (frame.RecipientKeyId != _recipientKeyId || frame.Kind != RelayFrameKind.Approval || frame.Cursor <= cursor)
                    throw new InvalidDataException("Relay inbox binding or ordering mismatch.");
                cursor = frame.Cursor;
                frames.Add(bytes);
            }
            var next = root.GetProperty("nextCursor").GetInt64();
            RequireCursor(next);
            if (next != cursor) throw new InvalidDataException("Relay cursor hint does not match this page.");
            return frames.AsReadOnly(); // No replay floor or desired policy is advanced here.
        }

        public async Task AcknowledgeCommittedInboxAsync(IRelayTransactionStore store, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(store);
            var state = await store.LoadAsync(cancellationToken).ConfigureAwait(false);
            var committedCursor = state.CommittedInboundCursor;
            RequireCursor(committedCursor);
            if (committedCursor == 0) return;
            using var content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(
                new { recipientKeyId = _recipientKeyId, cursor = committedCursor }));
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            using var result = await SendAsync(HttpMethod.Post, "ack", content, 512,
                cancellationToken, HttpStatusCode.OK).ConfigureAwait(false);
            ReadRemoteResponse(() =>
            {
                RequireObject(result.Document.RootElement, "cursor", "duplicate");
                var hint = result.Document.RootElement.GetProperty("cursor").GetInt64();
                RequireCursor(hint);
                if (hint < committedCursor) throw new InvalidDataException("Relay did not acknowledge the committed cursor.");
                return result.Document.RootElement.GetProperty("duplicate").GetBoolean();
            });
            // Even a higher relay hint must never be written into authoritative local state.
        }

        public async Task ProvisionEnrollmentAsync(EnrollmentOffer offer, byte[] capability, CancellationToken cancellationToken)
        {
            var path = EnrollmentPath(offer);
            if (capability == null || capability.Length != 32) throw new ArgumentException("Enrollment capability required.");
            var body = JsonSerializer.SerializeToUtf8Bytes(new {
                phoneToken = Convert.ToHexString(capability).ToLowerInvariant(), expiresAt = offer.ExpiresAtUtc.ToUnixTimeMilliseconds()
            });
            try
            {
                using var content = new ByteArrayContent(body);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                using var result = await SendAsync(HttpMethod.Post, path, content, 512, cancellationToken,
                    HttpStatusCode.OK, HttpStatusCode.Created).ConfigureAwait(false);
                RequireObject(result.Document.RootElement, "duplicate", "retainUntil");
                if (result.Document.RootElement.GetProperty("duplicate").GetBoolean() != (result.Status == HttpStatusCode.OK) ||
                    result.Document.RootElement.GetProperty("retainUntil").GetInt64() != offer.ExpiresAtUtc.AddDays(1).ToUnixTimeMilliseconds())
                    throw new InvalidDataException("Enrollment provisioning response mismatch.");
            }
            finally { CryptographicOperations.ZeroMemory(body); }
        }

        public async Task<byte[]?> PollEnrollmentAsync(EnrollmentOffer offer, CancellationToken cancellationToken)
        {
            var result = await SendRawAsync(HttpMethod.Get, EnrollmentPath(offer) + "/requests", null, NativeEnrollmentExchange.MaximumRequestBytes,
                "application/octet-stream", cancellationToken, HttpStatusCode.OK, HttpStatusCode.NoContent).ConfigureAwait(false);
            if (result.Status == HttpStatusCode.NoContent) return null;
            _ = NativeEnrollmentExchange.RequestNonce(result.Bytes, offer);
            return result.Bytes;
        }

        public async Task PublishEnrollmentReplyAsync(EnrollmentOffer offer, byte[] request, byte[] reply, CancellationToken cancellationToken)
        {
            var path = EnrollmentPath(offer);
            // Snapshot before the first await; mutable caller buffers must not change the checked routing.
            if (reply == null || reply.Length > NativeEnrollmentExchange.MaximumReplyBytes) throw new ArgumentException("Enrollment reply size.");
            var copy = (byte[])reply.Clone();
            NativeEnrollmentExchange.RequireReplyBinding(copy, request, offer);
            using var content = new ByteArrayContent(copy);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            using var result = await SendAsync(HttpMethod.Post, path + "/replies", content, 512, cancellationToken,
                HttpStatusCode.OK, HttpStatusCode.Created).ConfigureAwait(false);
            RequireObject(result.Document.RootElement, "duplicate");
            if (result.Document.RootElement.GetProperty("duplicate").GetBoolean() != (result.Status == HttpStatusCode.OK))
                throw new InvalidDataException("Enrollment reply acknowledgment mismatch.");
        }

        public async Task RejectEnrollmentRequestAsync(EnrollmentOffer offer, byte[] request, CancellationToken cancellationToken)
        {
            var nonce = NativeEnrollmentExchange.RequestNonce(request, offer);
            _ = await SendRawAsync(HttpMethod.Delete, EnrollmentPath(offer) + "/requests/" + Convert.ToHexString(nonce).ToLowerInvariant(),
                null, 0, "application/octet-stream", cancellationToken, HttpStatusCode.NoContent).ConfigureAwait(false);
        }

        public async Task RevokeEnrollmentChannelAsync(EnrollmentOffer offer, CancellationToken cancellationToken)
        {
            _ = await SendRawAsync(HttpMethod.Delete, EnrollmentPath(offer), null, 0, "application/octet-stream",
                cancellationToken, HttpStatusCode.NoContent).ConfigureAwait(false);
        }

        private string EnrollmentPath(EnrollmentOffer offer)
        {
            _ = RelayCanonicalEncoding.EncodeEnrollmentOffer(offer);
            if (offer.RelayEndpoint != _mailboxUri.GetLeftPart(UriPartial.Authority) || offer.MailboxId != _mailboxId ||
                offer.EncryptionKeyId != _recipientKeyId)
                throw new InvalidDataException("Enrollment does not match the pinned device transport.");
            return "enrollments/" + Convert.ToHexString(RelayCanonicalEncoding.ComputeEnrollmentOfferHash(offer)).ToLowerInvariant();
        }

        private async Task<ResponseDocument> SendAsync(HttpMethod method, string path, HttpContent? content,
            int maximumBytes, CancellationToken cancellationToken, params HttpStatusCode[] expectedStatuses)
        {
            var result = await SendRawAsync(method, path, content, maximumBytes, "application/json", cancellationToken, expectedStatuses).ConfigureAwait(false);
            return new ResponseDocument(result.Status,
                ReadRemoteResponse(() => JsonDocument.Parse(result.Bytes, new JsonDocumentOptions { MaxDepth = 4 })));
        }

        // Only untrusted response parsing belongs here; never wrap store reads, profile checks or durable commits.
        private static T ReadRemoteResponse<T>(Func<T> read)
        {
            try { return read(); }
            catch (Exception e) when (e is InvalidDataException or JsonException or ArgumentException or FormatException or
                OverflowException || e is InvalidOperationException and not ObjectDisposedException)
            { throw new HttpRequestException("Relay returned an invalid response."); }
        }

        private async Task<(HttpStatusCode Status, byte[] Bytes)> SendRawAsync(HttpMethod method, string path, HttpContent? content,
            int maximumBytes, string mediaType, CancellationToken cancellationToken, params HttpStatusCode[] expectedStatuses)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(_requestTimeout);
            using var request = new HttpRequestMessage(method, new Uri(_mailboxUri, path)) { Content = content };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(mediaType));
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                deadline.Token).ConfigureAwait(false);
            if (Array.IndexOf(expectedStatuses, response.StatusCode) < 0)
                throw new HttpRequestException("Relay request failed.", null, response.StatusCode);
            if (response.StatusCode == HttpStatusCode.NoContent)
            {
                if (response.Content.Headers.ContentLength > 0 || response.Content.Headers.ContentEncoding.Count != 0)
                    throw new HttpRequestException("Unexpected relay response body.");
                return (response.StatusCode, Array.Empty<byte>());
            }
            if (response.Content.Headers.ContentType?.MediaType != mediaType ||
                response.Content.Headers.ContentEncoding.Count != 0 || response.Content.Headers.ContentLength > maximumBytes)
                throw new HttpRequestException("Invalid relay response headers or size.");
            try
            {
                await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
                using var buffer = new MemoryStream();
                var chunk = new byte[4096];
                while (true)
                {
                    var count = await stream.ReadAsync(chunk.AsMemory(0,
                        (int)Math.Min(chunk.Length, maximumBytes + 1 - buffer.Length)), deadline.Token).ConfigureAwait(false);
                    if (count == 0) break;
                    buffer.Write(chunk, 0, count);
                    if (buffer.Length > maximumBytes) throw new InvalidDataException("Relay response exceeds its limit.");
                }
                return (response.StatusCode, buffer.ToArray());
            }
            catch (IOException)
            { throw new HttpRequestException("Relay response body could not be read."); }
        }

        private void RequireFrameBinding(RelayFrame frame)
        {
            RequireIdentifier(frame.MailboxId);
            RequireIdentifier(frame.RecipientKeyId);
            RequireIdentifier(frame.FrameId);
            RequireCursor(frame.Cursor);
            RequireCursor(frame.AckCursor);
            if (frame.MailboxId != _mailboxId) throw new InvalidDataException("Relay mailbox mismatch.");
        }

        private static void RequireIdentifier(string value)
        {
            if (!GuardIdentifier.IsCanonicalToken(value))
                throw new ArgumentException("Invalid relay identifier.");
        }

        private static void RequireCursor(long cursor)
        {
            if (cursor < 0 || cursor > MaximumCursor) throw new ArgumentOutOfRangeException(nameof(cursor));
        }

        internal static void RequireObject(JsonElement value, params string[] expectedNames)
        {
            if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Relay JSON object required.");
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
                if (Array.IndexOf(expectedNames, property.Name) < 0 || !seen.Add(property.Name))
                    throw new InvalidDataException("Unexpected or duplicate relay JSON field.");
            if (seen.Count != expectedNames.Length) throw new InvalidDataException("Incomplete relay JSON response.");
        }

        public void Dispose() => _client.Dispose();

        private sealed class ResponseDocument : IDisposable
        {
            public ResponseDocument(HttpStatusCode status, JsonDocument document) { Status = status; Document = document; }
            public HttpStatusCode Status { get; }
            public JsonDocument Document { get; }
            public void Dispose() => Document.Dispose();
        }
    }
}
