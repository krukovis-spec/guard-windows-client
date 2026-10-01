using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Protocol.Relay;
using Guard.Service;
using Guard.Storage;
using Guard.Windows.Cryptography;

namespace Guard.Windows.Crypto.Tests;

// Actual attested-owner fixture, service boundary and temporary DPAPI; HTTP is controlled, never external.
internal static class NativeRelayDeliveryChecks
{
    internal static async Task RunAsync(ServiceAuthoritativeStateBoundary service, DeviceRelayConfiguration config,
        EnrollmentDeploymentTrust trust, Func<byte[], byte[]> sign, DateTimeOffset now)
    {
        var owner = await service.LoadAsync(default);
        var initial = await service.RelayTransactions.LoadAsync(default);
        var snapshot = RelayCanonicalEncoding.DecodeRequestSnapshot(initial.TrackedRequests.Single().GetEncodedSnapshotCopy());
        var expectedRequest = initial.Outbox.Single().GetEncryptedFrameCopy();
        SignedApprovalEnvelope Approval(byte[] signature) => new(1, owner.Enrollment!.Candidate!.ApprovalKeyId, 1,
            "command-delivery-01", "nonce-delivery-0001", now, now.AddMinutes(2), owner.DeviceId, 1, snapshot.RequestId, 1,
            RelayCanonicalEncoding.ComputeRequestSnapshotHash(snapshot), snapshot.GetDecisionChallengeCopy(), snapshot.TargetKind,
            snapshot.CanonicalTargetIdentity, 0, ParentDecisionKind.AllowTemporary, 10, signature);
        var signed = Approval(sign(RelayCanonicalEncoding.ComputeApprovalHash(Approval(new byte[64]))));
        RelayFrame Frame(byte[] enc, byte[] cipher) => new(RelayFrameKind.Approval, config.MailboxId, service.Identity.EncryptionKeyId,
            "frame-delivery-001", 1, 0, now, now.AddHours(1), enc, cipher);
        var aad = RelayCanonicalEncoding.EncodeRelayFrameAssociatedData(Frame(Array.Empty<byte>(), Array.Empty<byte>()));
        var ciphertext = RelayCryptography.Encrypt(service.Identity.EncryptionPoint, RelayCanonicalEncoding.EncodeApprovalEnvelope(signed),
            aad, "guard-relay-approval-hpke-v1"u8.ToArray().Concat(aad).ToArray(), out var encapsulated);
        var frame = RelayCanonicalEncoding.EncodeRelayFrame(Frame(encapsulated, ciphertext));
        var published = new Dictionary<string, byte[]>();
        var clock = new Clock { Now = now }; var guard = new Boundary();
        var calls = 0; var polls = 0; var acks = 0;
        var loseRequest = true; var changeOwner = false; var corrupt = false;
        var expireDuringPoll = false; var loseReceipt = false; var loseAck = false; var replay = false;
        string? badResponse = null;

        async Task<HttpResponseMessage> Send(HttpRequestMessage request, CancellationToken token)
        {
            calls++;
            if (badResponse == "json") return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{", Encoding.UTF8, "application/json") };
            if (badResponse == "headers") return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}", Encoding.UTF8, "text/plain") };
            Check(request.RequestUri!.GetLeftPart(UriPartial.Authority) == trust.Origin.GetLeftPart(UriPartial.Authority) &&
                request.Headers.Authorization?.Scheme == "Bearer", "transport target/credential binding");
            var state = await service.RelayTransactions.LoadAsync(token);
            if (request.RequestUri.AbsolutePath.EndsWith("/frames", StringComparison.Ordinal))
            {
                var bytes = await request.Content!.ReadAsByteArrayAsync(token);
                var item = RelayCanonicalEncoding.DecodeRelayFrame(bytes);
                Check(state.Outbox[0].GetEncryptedFrameCopy().SequenceEqual(bytes), "sent uncommitted bytes");
                if (item.Kind == RelayFrameKind.Request) Check(expectedRequest.SequenceEqual(bytes), "request retry changed bytes");
                else Check(item.Kind == RelayFrameKind.Receipt && state.CommittedInboundCursor == 1 && state.PolicyRevision == 1 &&
                    state.SignedReceipts.Single().Status == CommandReceiptStatus.AcceptedPendingReconciliation, "receipt before durable transaction");
                var duplicate = published.TryGetValue(item.FrameId, out var previous);
                if (duplicate) Check(previous!.SequenceEqual(bytes), "lost response changed ciphertext");
                else published.Add(item.FrameId, bytes);
                if (changeOwner)
                {
                    changeOwner = false;
                    var current = await service.NativeEnrollmentStore.LoadAsync(token);
                    Check(await service.NativeEnrollmentStore.TryCommitAsync(current.Version, new DeviceSecurityState(current.DeviceId,
                        current.Version + 1, current.HighestAcceptedSequence, current.DesiredPolicyRevision, current.RecentCommandIds,
                        current.SetupChallenge, current.TrustedParentKeys, current.ChildAccountSid, current.Enrollment), token), "owner race setup");
                }
                if (item.Kind == RelayFrameKind.Request && loseRequest) { loseRequest = false; throw new HttpRequestException("Synthetic lost request response."); }
                if (item.Kind == RelayFrameKind.Receipt && loseReceipt) { loseReceipt = false; throw new HttpRequestException("Synthetic lost receipt response."); }
                if (badResponse == "publication") return Reply(new { frameId = "wrong-frame-0001", duplicate = true });
                return Reply(new { frameId = item.FrameId, duplicate }, duplicate ? HttpStatusCode.OK : HttpStatusCode.Created);
            }
            if (request.RequestUri.AbsolutePath.EndsWith("/poll", StringComparison.Ordinal))
            {
                polls++;
                Check(request.RequestUri.Query.Contains("&after=" + state.CommittedInboundCursor + "&", StringComparison.Ordinal), "poll did not resume committed cursor");
                var bytes = (byte[])frame.Clone(); if (corrupt) bytes[^1] ^= 1;
                if (expireDuringPoll) clock.Now = config.ExpiresAt;
                return Reply(new { frames = state.CommittedInboundCursor == 0 || replay ? new[] { Convert.ToBase64String(bytes) } : Array.Empty<string>(), nextCursor = 1 });
            }
            Check(request.RequestUri.AbsolutePath.EndsWith("/ack", StringComparison.Ordinal), "unexpected HTTP route");
            using var ack = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(token));
            Check(ack.RootElement.GetProperty("cursor").GetInt64() == 1 && state.CommittedInboundCursor == 1 &&
                state.ReplayFloors.Single().HighestAcceptedSequence == 1, "ack preceded durable acceptance");
            acks++;
            if (loseAck) { loseAck = false; throw new HttpRequestException("Synthetic lost ack response."); }
            return Reply(new { cursor = badResponse == "ack" ? 0 : 99, duplicate = acks > 1 }); // Untrusted hints never enter local state.
        }
        async Task<bool> Pass(CancellationToken token = default)
        {
            using var transport = config.CreateTransport(trust, service.Identity, await service.LoadAsync(token), clock.Now, new Handler(Send));
            return await new NativeRelayDelivery(service, config, trust, guard, clock, transport).RunAsync(token);
        }
        async Task Reopen() { service.Dispose(); await service.AcquireAsync(default); await service.LoadAsync(default); }

        await Reject(() => Pass());
        Check((await service.RelayTransactions.LoadAsync(default)).Version == initial.Version && polls == 0 && acks == 0, "lost publication removed retry or polled");
        badResponse = "publication"; await Reject(() => Pass(), typeof(HttpRequestException)); badResponse = null;
        Check((await service.RelayTransactions.LoadAsync(default)).Version == initial.Version, "invalid publication response removed retry bytes");
        await Reopen(); changeOwner = true;
        Check(!await Pass() && polls == 0 && (await service.RelayTransactions.LoadAsync(default)).Outbox.Count == 1, "owner changed during HTTP but item was acknowledged");
        corrupt = true; await Reject(() => Pass(), typeof(HttpRequestException)); corrupt = false;
        Check((await service.RelayTransactions.LoadAsync(default)).CommittedInboundCursor == 0 && acks == 0, "invalid approval was acknowledged");
        expireDuringPoll = true; await Reject(() => Pass(), typeof(InvalidDataException)); expireDuringPoll = false; clock.Now = now;
        Check((await service.RelayTransactions.LoadAsync(default)).PolicyRevision == 0 && acks == 0, "profile expiry during HTTP authorized");
        loseReceipt = true; await Reject(() => Pass());
        var committed = await service.RelayTransactions.LoadAsync(default);
        Check(committed.PolicyRevision == 1 && committed.CommittedInboundCursor == 1 && committed.Outbox.Count == 1 && acks == 0,
            "lost receipt delivery lost or prematurely acknowledged approval");
        await Reopen(); loseAck = true; await Reject(() => Pass());
        Check((await service.RelayTransactions.LoadAsync(default)).Outbox.Count == 0 && acks == 1, "receipt retry/ack order");
        await Reopen(); Check(!await Pass(), "empty page reported a new decision");
        var restored = await service.RelayTransactions.LoadAsync(default);
        Check(restored.PolicyRevision == 1 && restored.CommittedInboundCursor == 1 && restored.PolicyLedger.Count == 1 &&
            restored.SignedReceipts.Count == 1 && restored.AcknowledgedOutboundCursor == 2 && published.Count == 2,
            "restart/remote hint duplicated grant or lost state");
        replay = true; await Reject(() => Pass(), typeof(HttpRequestException)); replay = false;
        Check((await service.RelayTransactions.LoadAsync(default)).Version == restored.Version, "old frame replay mutated history");
        foreach (var bad in new[] { "json", "headers", "ack" })
        {
            badResponse = bad; await Reject(() => Pass(), typeof(HttpRequestException)); badResponse = null;
            Check((await service.RelayTransactions.LoadAsync(default)).Version == restored.Version, "bad response mutated history");
        }
        var priorCalls = calls;
        guard.Fail = true; await Reject(() => Pass(), typeof(UnauthorizedAccessException)); guard.Fail = false;
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel(); await Reject(() => Pass(cancelled.Token));
        clock.Now = config.ExpiresAt; await Reject(() => Pass()); clock.Now = now;
        Check(calls == priorCalls, "lost boundary/profile/cancellation reached network");
        var path = service.RelayTransactions.StateFilePath; var durable = File.ReadAllBytes(path);
        try
        {
            File.WriteAllBytes(path, new byte[] { 1 });
            await Reject(() => Pass(), typeof(StateStoreCorruptionException));
            Check(calls == priorCalls, "local corruption reached network or became retryable peer input");
        }
        finally { File.WriteAllBytes(path, durable); }
        Console.WriteLine("PASS native relay delivery: actual owner/DPAPI/HPKE commit, lost responses/restart/owner race, durable-only ack, hostile frame/profile and hint rejection; controlled HTTP only");
    }

    private sealed class Clock : TimeProvider { internal DateTimeOffset Now; public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class Boundary : IServiceDataBoundaryGuard
    { internal bool Fail; public void DemandReady() { if (Fail) throw new UnauthorizedAccessException("Synthetic lost boundary."); } }
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token); }
    private static HttpResponseMessage Reply(object body, HttpStatusCode code = HttpStatusCode.OK) =>
        new(code) { Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json") };
    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
    private static async Task Reject(Func<Task> action, Type? expected = null)
    {
        try { await action(); }
        catch (Exception e) when (e is ArgumentException or InvalidDataException or InvalidOperationException or
            OperationCanceledException or UnauthorizedAccessException or CryptographicException or HttpRequestException or IOException)
        { if (expected != null) Check(e.GetType() == expected, "Wrong local/remote failure classification: " + e.GetType().Name); return; }
        throw new Exception("Expected relay delivery rejection.");
    }
}
