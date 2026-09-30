using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Contracts.Relay;
using Guard.Protocol.Relay;
using Guard.Windows.Ipc;

namespace Guard.Windows.Ipc.Tests;

internal static class NativeSetupSessionChecks
{
    public static void Run()
    {
        try { RunAsync().GetAwaiter().GetResult(); }
        catch (Exception e) { Console.Error.WriteLine(e.StackTrace); throw; }
    }

    private static async Task RunAsync()
    {
        var peer = new Peer();
        await using (var session = await peer.Begin())
        {
            Check(session.Snapshot.Phase == NativeSetupPhase.RelayPending && session.Snapshot.QrText == null, "begin exposed QR");
            peer.Fail = GuardVerb.AdvanceNativeSetup;
            await Refuses(() => session.RefreshAsync(default));
            Check(session.Snapshot.Phase == NativeSetupPhase.RelayPending, "failed provisioning advanced UI");
            peer.Fail = null;
            var scanned = await session.RefreshAsync(default);
            Check(scanned.Phase == NativeSetupPhase.ScanPhone && scanned.QrText == peer.Qr, "canonical QR not displayed");
            Check(!scanned.ToString()!.Contains(peer.Qr, StringComparison.Ordinal), "snapshot ToString leaked QR");
            await Refuses(() => session.ConfirmComparedAsync(scanned.StateVersion, Peer.Hash, default));
            peer.Phase = "phone-proof"; peer.Version++;
            Check((await session.RefreshAsync(default)).QrText == null, "staged candidate kept QR");
            peer.Phase = "compare-phone"; peer.Version++;
            var compared = await session.RefreshAsync(default);
            await Refuses(() => session.ConfirmComparedAsync(compared.StateVersion - 1, Peer.Hash, default));
            await Refuses(() => session.ConfirmComparedAsync(compared.StateVersion, Peer.Hash[..8], default));
            await Refuses(() => session.ConfirmComparedAsync(compared.StateVersion, new string('f', 64), default));
            Check(peer.ConfirmCalls == 0, "poll or stale comparison auto-confirmed");
            await session.ConfirmComparedAsync(compared.StateVersion, compared.ClaimHash!, default);
            Check(session.Snapshot.Phase == NativeSetupPhase.Confirmed && !session.Snapshot.RelayPassCompleted,
                "owner commit was not distinct from relay delivery");
            await Refuses(() => session.CancelAsync(compared.StateVersion, default));
            peer.Now = peer.Now.AddHours(1);
            Check((await session.RefreshAsync(default)).Phase == NativeSetupPhase.Confirmed, "post-expiry owner query failed");
            Check(peer.ConfirmCalls == 1 && peer.ResultCalls == 1, "duplicate confirmation instead of result query");
        }
        Check(peer.CancelCalls == 0 && peer.Payloads.All(p => p.All(b => b == 0)), "close sent cancel or retained request bytes");

        // Reply loss both before and after commit: only a negative exact result + live
        // original capability can offer another explicit comparison. Never auto-retry confirm.
        foreach (var committed in new[] { false, true })
        {
            peer = new Peer { Phase = "compare-phone", LoseConfirm = true, CommitOnConfirm = committed };
            await using var session = await peer.Begin();
            var compared = await session.RefreshAsync(default);
            await Refuses(() => session.ConfirmComparedAsync(compared.StateVersion, Peer.Hash, default));
            Check(session.Snapshot.Phase == NativeSetupPhase.ConfirmationUnknown, "lost reply claimed success/failure");
            await Refuses(() => session.CancelAsync(compared.StateVersion, default));
            peer.Fail = GuardVerb.GetNativeSetupResult;
            await Refuses(() => session.RefreshAsync(default));
            Check(session.Snapshot.Phase == NativeSetupPhase.ConfirmationUnknown, "offline query lost uncertainty");
            peer.Fail = null;
            var restored = await session.RefreshAsync(default);
            Check(restored.Phase == (committed ? NativeSetupPhase.Confirmed : NativeSetupPhase.ComparePhone) &&
                peer.ConfirmCalls == 1, "lost confirmation was not safely reconciled");
        }

        peer = new Peer { Phase = "compare-phone", LoseConfirm = true, CommitOnConfirm = false };
        await using (var session = await peer.Begin())
        {
            var compared = await session.RefreshAsync(default);
            await Refuses(() => session.ConfirmComparedAsync(compared.StateVersion, Peer.Hash, default));
            peer.Now = peer.Expiry;
            Check((await session.RefreshAsync(default)).Phase == NativeSetupPhase.RecoveryRequired,
                "expired ambiguous commit was treated as a fresh setup");
            Check(peer.AdvanceCalls == 1, "expired capability used for advance");
        }

        foreach (var lost in new[] { false, true })
        {
            peer = new Peer { LoseCancel = lost };
            await using var session = await peer.Begin();
            var snapshot = await session.RefreshAsync(default);
            if (lost) await Refuses(() => session.CancelAsync(snapshot.StateVersion, default));
            else await session.CancelAsync(snapshot.StateVersion, default);
            var phase = lost ? NativeSetupPhase.CancellationUnknown : NativeSetupPhase.Cancelled;
            Check((await session.RefreshAsync(default)).Phase == phase, "cancellation invented a definitive outcome");
            await Refuses(() => session.CancelAsync(snapshot.StateVersion, default));
            Check(peer.CancelCalls == 1, "cancel was blindly retried");
        }

        foreach (var backwards in new[] { false, true })
        {
            peer = new Peer { Phase = "compare-phone" };
            await using var session = await peer.Begin();
            var snapshot = await session.RefreshAsync(default);
            peer.Now = backwards ? peer.Now.AddSeconds(-1) : peer.Expiry;
            await Refuses(() => session.ConfirmComparedAsync(snapshot.StateVersion, Peer.Hash, default));
            Check(peer.ConfirmCalls == 0 && session.Snapshot.Phase ==
                (backwards ? NativeSetupPhase.RecoveryRequired : NativeSetupPhase.Expired), "clock/expiry allowed confirmation");
        }

        await MalformedAsync();
        await ExpiryDuringReplyAsync();
        await SerializedCloseAsync();
    }

    private static async Task ExpiryDuringReplyAsync()
    {
        var peer = new Peer();
        await using var session = await NativeSetupSession.BeginAsync(async (verb, bytes, token) => {
            var response = await peer.Send(verb, bytes, token);
            if (verb == GuardVerb.AdvanceNativeSetup) peer.Now = peer.Expiry;
            return response;
        }, () => peer.Now, default);
        Check((await session.RefreshAsync(default)).Phase == NativeSetupPhase.Expired && session.Snapshot.QrText == null,
            "reply arriving at expiry exposed QR");
    }

    private static async Task MalformedAsync()
    {
        var peer = new Peer();
        var validBegin = Encoding.UTF8.GetString(peer.BeginResponse().GetPayloadCopy());
        foreach (var bad in new[] { "[]", "{}", validBegin + "{}", validBegin.Replace("\"version\":1", "\"version\":1,\"version\":1"),
            validBegin.Replace("\"version\":1", "\"version\":2"), validBegin.Replace("\"version\":1", "\"extra\":1,\"version\":1"),
            validBegin.Replace("relay-pending", "confirmed"), validBegin.Replace(Peer.Id, "short"),
            validBegin.Replace(JsonSerializer.Serialize(Convert.ToBase64String(peer.Secret)), "\"invalid\""),
            validBegin.Replace(peer.Expiry.ToUnixTimeMilliseconds().ToString(), "0"),
            validBegin.Replace(peer.Expiry.ToUnixTimeMilliseconds().ToString(), "9223372036854775807"), new string(' ', 4097) })
        {
            Check(bad != validBegin, "malformed-input test did not change the serialized response");
            await Refuses(() => NativeSetupSession.BeginAsync((_, _, _) => Task.FromResult(Raw(bad)), () => peer.Now, default));
        }

        var edits = new Func<Dictionary<string, object?>, Dictionary<string, object?>>[] {
            d => { d["enrollmentId"] = "another-enrollment-0001"; return d; },
            d => { d["expiresAt"] = peer.Expiry.AddMinutes(1).ToUnixTimeMilliseconds(); return d; },
            d => { d["stateVersion"] = -1; return d; }, d => { d["stateVersion"] = "1"; return d; },
            d => { d["phase"] = "confirmed"; return d; }, d => { d["qr"] = "https://relay.example.test/"; return d; },
            d => { d["qr"] = peer.Qr[..(peer.Qr.IndexOf("&secret=", StringComparison.Ordinal) + 8)] +
                Convert.ToBase64String(peer.Secret).TrimEnd('=').Replace('+', '-').Replace('/', '_'); return d; },
            d => { d["qr"] = peer.Qr + "&extra=1"; return d; }, d => { d["claimHash"] = Peer.Hash; return d; },
            d => { d["phase"] = "compare-phone"; d["qr"] = null; d["claimHash"] = Peer.Hash.ToUpperInvariant(); return d; },
            d => { d["unknown"] = false; return d; }
        };
        foreach (var edit in edits)
        {
            peer.EditAdvance = edit;
            await using var session = await peer.Begin();
            await Refuses(() => session.RefreshAsync(default));
            Check(session.Snapshot.Phase == NativeSetupPhase.RecoveryRequired && session.Snapshot.QrText == null,
                "malformed response left active display");
        }
        peer.EditAdvance = null;
        await using (var session = await peer.Begin())
        {
            await session.RefreshAsync(default);
            peer.Qr = peer.Qr[..^1] + (peer.Qr[^1] == 'A' ? 'E' : 'A');
            await Refuses(() => session.RefreshAsync(default));
        }

        peer = new Peer { Phase = "compare-phone" };
        await using (var session = await peer.Begin())
        {
            var snapshot = await session.RefreshAsync(default);
            await session.ConfirmComparedAsync(snapshot.StateVersion, Peer.Hash, default);
            peer.WrongResult = true;
            await Refuses(() => session.RefreshAsync(default));
            Check(session.Snapshot.Phase == NativeSetupPhase.RecoveryRequired, "different owner transcript accepted");
        }
    }

    private static async Task SerializedCloseAsync()
    {
        var peer = new Peer();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var session = await NativeSetupSession.BeginAsync(async (verb, bytes, token) => {
            if (verb != GuardVerb.BeginNativeSetup)
            { entered.SetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, token); }
            return await peer.Send(verb, bytes, token);
        }, () => peer.Now, default);
        var waiting = session.RefreshAsync(default);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var queued = session.RefreshAsync(default);
        await session.DisposeAsync();
        await Refuses(() => waiting); await Refuses(() => queued);
        await Refuses(() => session.RefreshAsync(default));
        Check(peer.AdvanceCalls == 0 && peer.CancelCalls == 0 && session.Snapshot.QrText == null,
            "close left work active or cancelled remote ownership");
    }

    private sealed class Peer
    {
        internal const string Id = "enrollment-client-test-0001";
        internal const string Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        internal DateTimeOffset Now = DateTimeOffset.FromUnixTimeMilliseconds(1790812800000);
        internal DateTimeOffset Expiry;
        internal readonly byte[] Secret = RandomNumberGenerator.GetBytes(32);
        internal string Qr;
        internal string Phase = "scan-phone";
        internal long Version = 1;
        internal int AdvanceCalls, ConfirmCalls, CancelCalls, ResultCalls;
        internal bool LoseConfirm, LoseCancel, Committed, WrongResult;
        internal bool CommitOnConfirm = true;
        internal GuardVerb? Fail;
        internal readonly List<byte[]> Payloads = new();
        internal Func<Dictionary<string, object?>, Dictionary<string, object?>>? EditAdvance;

        internal Peer()
        {
            Expiry = Now.AddMinutes(5);
            using var key1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var key2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var offer = new EnrollmentOffer("https://relay.example.test", Id, "device-client-test-0001", "Guard test",
                1, 1, "mailbox-client-test-0001", "signing-client-test-0001", key1.ExportSubjectPublicKeyInfo()[26..],
                "encryption-client-test-0001", key2.ExportSubjectPublicKeyInfo()[26..], Now, Expiry, RandomNumberGenerator.GetBytes(32));
            Qr = RelayCanonicalEncoding.EncodeEnrollmentQr(offer, RandomNumberGenerator.GetBytes(32));
        }
        internal Task<NativeSetupSession> Begin() => NativeSetupSession.BeginAsync(Send, () => Now, default);
        internal GuardIpcResponse BeginResponse() => Json(new { version = 1, enrollmentId = Id,
            expiresAt = Expiry.ToUnixTimeMilliseconds(), confirmationSecret = Convert.ToBase64String(Secret), phase = "relay-pending" });
        internal Task<GuardIpcResponse> Send(GuardVerb verb, byte[] bytes, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (verb == GuardVerb.BeginNativeSetup) { Check(bytes.Length == 0, "begin payload not empty"); return Task.FromResult(BeginResponse()); }
            Payloads.Add(bytes); // Observe clearing later; do not copy/log capabilities.
            using var doc = JsonDocument.Parse(bytes);
            var input = doc.RootElement;
            if (verb == Fail) throw new IOException("Synthetic offline service.");
            if (verb == GuardVerb.GetNativeSetupResult)
            {
                ResultCalls++;
                Check(input.EnumerateObject().Count() == 3 && input.GetProperty("enrollmentId").GetString() == Id &&
                    input.GetProperty("claimHash").GetString() == Hash, "result query leaked capability or changed identity");
                return Task.FromResult(Committed ? Json(new { version = 1, stateVersion = Version + 1, enrollmentId = Id,
                    claimHash = WrongResult ? new string('0', 64) : Hash, phase = "confirmed", relayPassCompleted = false,
                    recoveryRequired = false }) : new GuardIpcResponse(1, "test", GuardIpcResponseStatus.Rejected, Array.Empty<byte>()));
            }
            Check(input.GetProperty("confirmationSecret").GetString() == Convert.ToBase64String(Secret), "original capability changed");
            if (verb == GuardVerb.AdvanceNativeSetup)
            {
                AdvanceCalls++;
                var value = new Dictionary<string, object?> { ["version"] = 1, ["stateVersion"] = Version, ["enrollmentId"] = Id,
                    ["expiresAt"] = Expiry.ToUnixTimeMilliseconds(), ["phase"] = Phase, ["qr"] = Phase == "scan-phone" ? Qr : null,
                    ["claimHash"] = Phase == "compare-phone" ? Hash : null };
                return Task.FromResult(Json(EditAdvance?.Invoke(value) ?? value));
            }
            Check(input.GetProperty("expectedVersion").GetInt64() == Version, "comparison state version changed");
            if (verb == GuardVerb.ConfirmNativeSetup)
            {
                ConfirmCalls++; Committed = CommitOnConfirm;
                Check(input.GetProperty("claimHash").GetString() == Hash, "truncated/changed comparison sent");
                if (LoseConfirm) throw new IOException("Synthetic lost response.");
            }
            else { Check(verb == GuardVerb.CancelNativeSetup, "unexpected verb"); CancelCalls++;
                if (LoseCancel) throw new IOException("Synthetic lost response."); }
            return Task.FromResult(new GuardIpcResponse(1, "test", GuardIpcResponseStatus.Success, Array.Empty<byte>()));
        }
    }
    private static GuardIpcResponse Json(object value) => new(1, "test", GuardIpcResponseStatus.Success, JsonSerializer.SerializeToUtf8Bytes(value));
    private static GuardIpcResponse Raw(string value) => new(1, "test", GuardIpcResponseStatus.Success, Encoding.UTF8.GetBytes(value));
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static async Task Refuses(Func<Task> action)
    {
        try { await action(); }
        catch (Exception e) when (e is IOException or InvalidDataException or InvalidOperationException or OperationCanceledException) { return; }
        throw new InvalidOperationException("Expected setup rejection.");
    }
}
