using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using System.Text.Json;
using Guard.Application;
using Guard.Contracts;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Protocol.Relay;
using Guard.Storage;
using Guard.Service;
using Guard.Windows;
using Guard.Windows.Cryptography;

namespace Guard.Windows.Crypto.Tests;

internal static class NativeEnrollmentChecks
{
    private static readonly CancellationToken None = CancellationToken.None;
    internal static void Run() => RunAsync().GetAwaiter().GetResult();
    internal static string ExportExchange() => ExportExchangeAsync().GetAwaiter().GetResult();
    private static async Task<string> ExportExchangeAsync()
    {
        using var lab = new Lab(); using var start = await lab.Begin();
        var claim = lab.Claim(lab.PhoneOne); var hash = RelayCanonicalEncoding.ComputeEnrollmentClaimHash(claim);
        await lab.Stage(lab.PhoneOne, start, claim);
        var state = await lab.State(); var pending = state.Enrollment!;
        var nonce = RandomNumberGenerator.GetBytes(32);
        var query = EnrollmentExchange.Seal(EnrollmentExchange.Header(EnrollmentExchange.Query,
            RelayCanonicalEncoding.ComputeEnrollmentOfferHash(lab.Offer), hash, nonce), Array.Empty<byte>(), lab.Offer.GetEncryptionKeyCopy());
        var replyPending = await lab.Exchange.HandleAsync(query, None);
        await lab.Coordinator.ConfirmPhoneKeyAsync(ClientRole.ParentRelay, hash, lab.DecryptProof(pending), None);
        state = await lab.State();
        Check(await lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, state.Version, start.GetConfirmationSecretCopy(), hash, None) == SetupOperationStatus.Succeeded, "fixture commit");
        var replyConfirmed = await lab.Exchange.HandleAsync(query, None);
        return "# PUBLIC TEST-ONLY KEYS and synthetic attestation ceremony. Never use for real enrollment.\n" +
            string.Join("\n", new[] {
                "now=" + lab.Clock.Now.ToUnixTimeMilliseconds(),
                "offer=" + Convert.ToHexString(RelayCanonicalEncoding.EncodeEnrollmentOffer(lab.Offer)),
                "claim=" + Convert.ToHexString(RelayCanonicalEncoding.EncodeEnrollmentClaimForSignature(claim)),
                "mac=" + Convert.ToHexString(pending.GetMacCopy()), "signature=" + Convert.ToHexString(pending.GetSignatureCopy()),
                "nonce=" + Convert.ToHexString(nonce), "phone.private=" + Convert.ToHexString(lab.PhonePrivate),
                "device.private=" + Convert.ToHexString(lab.DevicePrivate),
                "reply.pending=" + Convert.ToHexString(replyPending), "reply.confirmed=" + Convert.ToHexString(replyConfirmed) }) + "\n";
    }
    internal static void VerifyAndroidExchange(string path)
    {
        var properties = File.ReadAllLines("protocol/test-vectors/enrollment-exchange-v1.properties")
            .Where(line => line.Length > 0 && !line.StartsWith('#')).Select(line => line.Split('=', 2)).ToDictionary(pair => pair[0], pair => pair[1]);
        byte[] Value(string key) => Convert.FromHexString(properties[key]);
        var offer = RelayCanonicalEncoding.DecodeEnrollmentOffer(Value("offer"));
        using var key = ECDiffieHellman.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, D = Value("device.private"),
            Q = new ECPoint { X = offer.GetEncryptionKeyCopy()[1..33], Y = offer.GetEncryptionKeyCopy()[33..65] } });
        var rows = File.ReadAllLines(path); Check(rows.Length == 3, "Android exchange count");
        for (var i = 0; i < rows.Length; i++)
        {
            var message = EnrollmentExchange.Decode(Convert.FromHexString(rows[i]));
            Check(message.Kind == i + 1 && message.Nonce.AsSpan().SequenceEqual(Value("nonce")) &&
                message.OfferHash.AsSpan().SequenceEqual(RelayCanonicalEncoding.ComputeEnrollmentOfferHash(offer)), "Android header");
            var plain = EnrollmentExchange.Open(message, key);
            if (i == 0)
            {
                var submission = EnrollmentExchange.DecodeSubmission(plain);
                Check(RelayCanonicalEncoding.EncodeEnrollmentClaimForSignature(submission.Claim).AsSpan().SequenceEqual(Value("claim")) &&
                    submission.Mac.AsSpan().SequenceEqual(Value("mac")) && submission.Signature.AsSpan().SequenceEqual(Value("signature")) &&
                    submission.Chain.Length == 2 && submission.Chain.All(cert => cert.AsSpan().SequenceEqual(new byte[] {1, 2, 3})), "Android payload");
                Check(message.ClaimHash.AsSpan().SequenceEqual(RelayCanonicalEncoding.ComputeEnrollmentClaimHash(submission.Claim)), "Android claim hash");
            }
            else Check(plain.AsSpan().SequenceEqual(i == 1 ? Enumerable.Repeat((byte)7, 32).ToArray() : Array.Empty<byte>()), "Android proof/query");
        }
        Console.WriteLine("PASS actual Kotlin HPKE claim/proof/query decrypted and bound by .NET; test-only certificate bytes, not hardware evidence.");
    }
    private static async Task RunAsync()
    {
        await EncryptedExchange();
        await HttpExchange();
        using (var lab = new Lab())
        {
            var forbidden = await lab.Coordinator.BeginAsync(ClientRole.Child, lab.Offer, None);
            Check(forbidden.Status == SetupOperationStatus.Forbidden && forbidden.Start == null, "child begin");
            using var start = await lab.Begin();
            var secret = start.GetConfirmationSecretCopy();
            var claim = lab.Claim(lab.PhoneOne);
            var claimHash = RelayCanonicalEncoding.ComputeEnrollmentClaimHash(claim);
            lab.Reopen();
            Check((await lab.State()).Enrollment?.Offer.DeviceLabel == "Lab PC", "offer lost on restart");
            Check(await lab.Stage(lab.PhoneOne, start, claim, badMac: true) == SetupOperationStatus.Rejected, "bad QR MAC");
            Check(await lab.Stage(lab.PhoneOne, start, claim) == SetupOperationStatus.Succeeded, "valid candidate");
            var pending = await lab.State();
            Check(!pending.IsProvisioned && pending.Enrollment!.Candidate != null, "first reply became owner");
            Check(await lab.Stage(lab.PhoneOne, start, claim) == SetupOperationStatus.Succeeded && (await lab.State()).Version == pending.Version, "duplicate stage changed bytes");
            Check(await lab.Stage(lab.PhoneTwo, start, lab.Claim(lab.PhoneTwo)) == SetupOperationStatus.StateConflict, "second genuine phone replaced pending");
            Check(await lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, pending.Version, secret, claimHash, None) == SetupOperationStatus.Rejected, "unconfirmed decryption key");
            var keyProof = lab.DecryptProof(pending.Enrollment!);
            Check(await lab.Coordinator.ConfirmPhoneKeyAsync(ClientRole.AdminSetup, claimHash, keyProof, None) == SetupOperationStatus.Forbidden, "admin asserted phone role");
            Check(await lab.Coordinator.ConfirmPhoneKeyAsync(ClientRole.ParentRelay, claimHash, new byte[32], None) == SetupOperationStatus.Rejected, "guessed phone key");
            Check(await lab.Coordinator.ConfirmPhoneKeyAsync(ClientRole.ParentRelay, claimHash, keyProof, None) == SetupOperationStatus.Succeeded, "phone proof rejected");
            var confirmedPhone = await lab.State();
            Check(!confirmedPhone.IsProvisioned && confirmedPhone.Enrollment!.PhoneKeyConfirmed, "phone proof became owner");
            Check(await lab.Coordinator.ConfirmPhoneKeyAsync(ClientRole.ParentRelay, claimHash, keyProof, None) == SetupOperationStatus.Succeeded &&
                (await lab.State()).Version == confirmedPhone.Version, "phone proof replay changed state");
            lab.Reopen();
            Check(await lab.Coordinator.ConfirmLocalAsync(ClientRole.ParentRelay, confirmedPhone.Version, secret, claimHash, None) == SetupOperationStatus.Forbidden, "remote local confirmation");
            Check(await lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, confirmedPhone.Version, new byte[32], claimHash, None) == SetupOperationStatus.Rejected, "other elevated session");
            Check(await lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, confirmedPhone.Version, secret, new byte[32], None) == SetupOperationStatus.Rejected, "other claim confirmation");
            Check(await lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, pending.Version, secret, claimHash, None) == SetupOperationStatus.StateConflict, "stale local display");
            var results = await Task.WhenAll(
                lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, confirmedPhone.Version, secret, claimHash, None),
                lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, confirmedPhone.Version, secret, claimHash, None));
            Check(results.Count(s => s == SetupOperationStatus.Succeeded) == 1 && results.Count(s => s == SetupOperationStatus.StateConflict) == 1, "local confirmation CAS");
            lab.Reopen(); var owner = await lab.State();
            Check(owner.IsProvisioned && owner.TrustedParentKeys.Single().Equals(lab.PhoneOne.Anchor) && owner.SetupChallenge == null,
                "atomic owner/challenge across reopen");
            Check(owner.Enrollment!.Confirmed && owner.Enrollment.GetConfirmationHashCopy().Length == 0 && owner.Enrollment.GetExpectedKeyProofCopy().Length == 0, "retained setup authenticators");
            Check((await lab.Coordinator.BeginAsync(ClientRole.AdminSetup, lab.Offer, None)).Status == SetupOperationStatus.AlreadyProvisioned, "re-enrollment overwrote owner");
            Check(await lab.Coordinator.CancelAsync(ClientRole.AdminSetup, owner.Version, secret, None) == SetupOperationStatus.Rejected, "setup cancellation removed owner");
            Check(await lab.Stage(lab.PhoneTwo, start, lab.Claim(lab.PhoneTwo)) == SetupOperationStatus.Rejected, "replayed QR changed owner");
            var dropped = new DeviceSecurityState(owner.DeviceId, owner.Version + 1, 0, 0, trustedParentKeys: owner.TrustedParentKeys);
            await Reject<ArgumentException>(() => lab.Store.TryCommitAsync(owner.Version, dropped, None));
            Check(await lab.Store.TryCommitAsync(owner.Version, owner.WithAcceptedCommand("command-test-0001", 1), None), "ordinary command lost enrollment");
            start.Dispose(); RejectSync<ObjectDisposedException>(() => start.GetConfirmationSecretCopy());
        }
        foreach (var failure in new[] { "expired", "status-await", "during-crypto", "status-during-crypto", "before-publish", "revoked", "cancelled" })
        {
            using var lab = new Lab(); using var start = await lab.Begin();
            var claim = lab.Claim(lab.PhoneOne); var hash = RelayCanonicalEncoding.ComputeEnrollmentClaimHash(claim);
            await lab.Stage(lab.PhoneOne, start, claim);
            var staged = await lab.State();
            await lab.Coordinator.ConfirmPhoneKeyAsync(ClientRole.ParentRelay, hash, lab.DecryptProof(staged.Enrollment!), None);
            var before = await lab.State();
            if (failure == "expired") lab.Clock.Now = lab.Offer.ExpiresAtUtc;
            if (failure == "status-await") lab.Status = _ => { lab.Clock.Now = lab.Offer.ExpiresAtUtc; return Task.FromResult(lab.PhoneOne.Status); };
            if (failure is "during-crypto" or "status-during-crypto") lab.Status = _ =>
            {
                var deadline = failure == "during-crypto" ? lab.Offer.ExpiresAtUtc : lab.Clock.Now.AddSeconds(1);
                var status = AndroidAttestationRevocations.FromTrustedResponse("{\"entries\":{}}"u8.ToArray(), lab.Clock.Now.AddSeconds(-1), deadline);
                var reads = 0;
                lab.Clock.OnRead = () => { if (++reads == 4) lab.Clock.Now = deadline; };
                return Task.FromResult(status);
            };
            if (failure == "before-publish") lab.Protector.OnProtect = () => lab.Clock.Now = lab.Offer.ExpiresAtUtc;
            if (failure == "revoked") lab.Status = _ => Task.FromResult(AndroidAttestationRevocations.FromTrustedResponse(
                "{\"entries\":{\"1\":{\"status\":\"REVOKED\"}}}"u8.ToArray(), lab.Clock.Now.AddSeconds(-1), lab.Clock.Now.AddMinutes(10)));
            if (failure == "cancelled")
            {
                using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
                await Reject<OperationCanceledException>(() => lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, before.Version, start.GetConfirmationSecretCopy(), hash, cancellation.Token));
            }
            else Check(await lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, before.Version, start.GetConfirmationSecretCopy(), hash, None) != SetupOperationStatus.Succeeded, failure);
            lab.Protector.OnProtect = null; lab.Reopen();
            Check((await lab.State()).Version == before.Version && !(await lab.State()).IsProvisioned, "failed confirmation changed ownership: " + failure);
            Check(!Directory.EnumerateFiles(lab.DirectoryPath, "*.tmp").Any(), "unpublished temporary state leaked");
        }
        using (var lab = new Lab())
        {
            using var start = await lab.Begin(); var state = await lab.State();
            Check(await lab.Store.TryCommitAsync(state.Version, state.WithBoundChildAccount(new WindowsAccountSid("S-1-5-21-1000"), lab.Clock.Now), None), "child binding");
            state = await lab.State();
            Check(state.Enrollment != null, "child binding dropped pending ceremony");
            Check(await lab.Coordinator.CancelAsync(ClientRole.AdminSetup, state.Version, new byte[32], None) == SetupOperationStatus.Rejected, "other session cancelled setup");
            Check(await lab.Coordinator.CancelAsync(ClientRole.AdminSetup, state.Version, start.GetConfirmationSecretCopy(), None) == SetupOperationStatus.Succeeded, "originating session cannot cancel");
            lab.Reopen(); state = await lab.State();
            Check(state.Enrollment == null && state.SetupChallenge == null && state.ChildAccountSid != null && !state.IsProvisioned, "cancel did not preserve child binding");
        }
        LegacyCodec();
        Console.WriteLine("PASS real-file enrollment: restart, two genuine phones, QR replay, key proof, originating session, CAS, deadline-at-publication, revocation, cancellation and legacy codec");
    }

    private static void LegacyCodec()
    {
        // Exercise the on-disk codec directly without fabricating production ciphertext/journal commitments.
        var type = typeof(FileAuthoritativeStateStore).Assembly.GetType("Guard.Storage.CanonicalStateCodec")!;
        var encode = type.GetMethod("Encode", BindingFlags.Public | BindingFlags.Static)!;
        var decode = type.GetMethod("Decode", BindingFlags.Public | BindingFlags.Static)!;
        var original = new DeviceSecurityState("device-test-00001", 7, 0, 0);
        var bytes = (byte[])encode.Invoke(null, new object[] { original })!;
        Check(bytes[11] == 2 && bytes[^1] == 0, "schema 2 expected");
        var legacy = bytes[..^1]; legacy[11] = 1;
        var restored = (DeviceSecurityState)decode.Invoke(null, new object[] { legacy })!;
        Check(restored.Version == 7 && restored.Enrollment == null && !restored.IsProvisioned, "legacy state promoted/reset");
        Check(((byte[])encode.Invoke(null, new object[] { restored })!)[11] == 2, "schema migration");
        legacy[11] = 3;
        RejectSync<TargetInvocationException>(() => decode.Invoke(null, new object[] { legacy }));
        RejectSync<TargetInvocationException>(() => decode.Invoke(null, new object[] { bytes.Concat(new byte[] {0}).ToArray() }));
    }

    private static async Task EncryptedExchange()
    {
        using var lab = new Lab(); using var start = await lab.Begin();
        var claim = lab.Claim(lab.PhoneOne); var hash = RelayCanonicalEncoding.ComputeEnrollmentClaimHash(claim);
        var secretText = start.QrText.Split("&secret=", StringSplitOptions.None)[1].Replace('-', '+').Replace('_', '/');
        var proofKey = SHA256.HashData(Convert.FromBase64String(secretText + "="));
        var submission = EnrollmentExchange.EncodeSubmission(claim,
            lab.PhoneOne.Chain(AndroidAttestationChecks.Description(challenge: RelayCanonicalEncoding.ComputeEnrollmentOfferHash(lab.Offer))),
            RelayCanonicalEncoding.ComputeEnrollmentClaimProof(proofKey, claim), lab.PhoneOne.Sign(hash));
        byte[] Request(int kind, byte[] body, byte[] nonce, byte[]? claimHash = null) => EnrollmentExchange.Seal(
            EnrollmentExchange.Header(kind, RelayCanonicalEncoding.ComputeEnrollmentOfferHash(lab.Offer), claimHash ?? hash, nonce), body, lab.Offer.GetEncryptionKeyCopy());
        int Outcome(byte[] raw, byte[] nonce)
        {
            var message = EnrollmentExchange.Decode(raw);
            Check(message.Kind == EnrollmentExchange.Reply && message.Nonce.AsSpan().SequenceEqual(nonce) && message.ClaimHash.AsSpan().SequenceEqual(hash), "reply correlation");
            var plain = lab.OpenReply(message); var result = plain[..^64];
            using var verifier = ECDsa.Create(); verifier.ImportSubjectPublicKeyInfo(lab.DeviceSigningSpki, out _);
            Check(verifier.VerifyData(EnrollmentExchange.SignatureInput(message.Header, result), plain[^64..], HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation), "reply is not device signed");
            return BinaryPrimitives.ReadInt32BigEndian(result.AsSpan(8, 4));
        }
        var nonce = RandomNumberGenerator.GetBytes(32);
        var request = Request(EnrollmentExchange.Claim, submission, nonce);
        var damaged = (byte[])request.Clone(); damaged[^1] ^= 1;
        await Reject<EnrollmentRequestRejectedException>(() => lab.Exchange.HandleAsync(damaged, None));
        await Reject<EnrollmentRequestRejectedException>(() => lab.Exchange.HandleAsync(Request(EnrollmentExchange.Claim, submission, nonce, new byte[32]), None));
        Check((await lab.State()).Enrollment!.Candidate == null, "rejected encrypted claim staged owner");
        var reply = await lab.Exchange.HandleAsync(request, None);
        Check(Outcome(reply, nonce) == EnrollmentExchange.NeedsPhoneProof && !(await lab.State()).IsProvisioned, "encrypted claim became owner");
        var stageVersion = (await lab.State()).Version;
        lab.Reopen();
        Check(Outcome(await lab.Exchange.HandleAsync(request, None), nonce) == EnrollmentExchange.NeedsPhoneProof && (await lab.State()).Version == stageVersion,
            "lost stage response changed pending evidence");
        var phoneProof = lab.DecryptProof((await lab.State()).Enrollment!);
        nonce = RandomNumberGenerator.GetBytes(32);
        Check(Outcome(await lab.Exchange.HandleAsync(Request(EnrollmentExchange.KeyProof, phoneProof, nonce), None), nonce) == EnrollmentExchange.NeedsLocalConfirmation &&
            !(await lab.State()).IsProvisioned, "phone proof bypassed originating confirmation");
        var query = Request(EnrollmentExchange.Query, Array.Empty<byte>(), nonce);
        Check(Outcome(await lab.Exchange.HandleAsync(query, None), nonce) == EnrollmentExchange.NeedsLocalConfirmation, "query promoted pending");
        var local = await lab.State();
        Check(await lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, local.Version, start.GetConfirmationSecretCopy(), hash, None) == SetupOperationStatus.Succeeded, "local confirmation");
        lab.Reopen(); lab.Clock.Now = lab.Offer.ExpiresAtUtc.AddDays(1);
        // Recover a lost final response after QR expiry; no fresh enrollment or replacement keys.
        nonce = RandomNumberGenerator.GetBytes(32);
        Check(Outcome(await lab.Exchange.HandleAsync(Request(EnrollmentExchange.Query, Array.Empty<byte>(), nonce), None), nonce) == EnrollmentExchange.Confirmed, "lost completion unrecoverable");
        Check(Outcome(await lab.Exchange.HandleAsync(Request(EnrollmentExchange.Claim, submission, nonce), None), nonce) == EnrollmentExchange.Confirmed, "exact committed retry rejected");
        var changed = (byte[])submission.Clone(); changed[^1] ^= 1;
        await Reject<EnrollmentRequestRejectedException>(() => lab.Exchange.HandleAsync(Request(EnrollmentExchange.Claim, changed, nonce), None));
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Reject<OperationCanceledException>(() => lab.Exchange.HandleAsync(query, canceled.Token));
        var reads = 0;
        lab.Clock.OnRead = () => { if (++reads == 2) lab.Clock.Now = lab.Clock.Now.AddMinutes(1); };
        await Reject<InvalidDataException>(() => lab.Exchange.HandleAsync(query, None));
        lab.Clock.OnRead = null; lab.Clock.Now = lab.Offer.CreatedAtUtc.AddMilliseconds(-1);
        await Reject<InvalidDataException>(() => lab.Exchange.HandleAsync(query, None));

        // Dedicated chain ceiling: over ordinary GRF1 but still bounded; never truncates certificates.
        var large = EnrollmentExchange.EncodeSubmission(claim, Enumerable.Range(0, 4).Select(_ => new byte[16384]).ToArray(), new byte[32], new byte[64]);
        Check(large.Length > 65536 && EnrollmentExchange.DecodeSubmission(large).Chain.Sum(c => c.Length) == 65536, "chain truncated to ordinary frame");
        RejectSync<ArgumentException>(() => EnrollmentExchange.EncodeSubmission(claim, Enumerable.Range(0, 5).Select(_ => new byte[16384]).ToArray(), new byte[32], new byte[64]));
        for (var i = 0; i < request.Length; i++) RejectSync<ArgumentException>(() => EnrollmentExchange.Decode(request[..i]));
        RejectSync<ArgumentException>(() => EnrollmentExchange.Decode(request.Concat(new byte[] {0}).ToArray()));
        RejectSync<ArgumentException>(() => EnrollmentExchange.Decode(new byte[EnrollmentExchange.MaximumBytes + 1]));
        Console.WriteLine("PASS encrypted enrollment: real attestation/CAS, signed correlated reply, replay/restart/late completion, tamper, expiry and chain limits");
    }

    private static async Task HttpExchange()
    {
        using var lab = new Lab(); using var start = await lab.Begin();
        var before = await lab.State();
        var cap = RelayCanonicalEncoding.ComputeEnrollmentRelayCapability(before.SetupChallenge!.GetSecretHashCopy(), lab.Offer);
        var hash = RelayCanonicalEncoding.ComputeEnrollmentOfferHash(lab.Offer);
        var path = "/v1/mailboxes/" + lab.Offer.MailboxId + "/enrollments/" + Convert.ToHexString(hash).ToLowerInvariant();
        var claim = lab.Claim(lab.PhoneOne); var claimHash = RelayCanonicalEncoding.ComputeEnrollmentClaimHash(claim);
        var submission = EnrollmentExchange.EncodeSubmission(claim,
            lab.PhoneOne.Chain(AndroidAttestationChecks.Description(challenge: hash)),
            RelayCanonicalEncoding.ComputeEnrollmentClaimProof(before.SetupChallenge.GetSecretHashCopy(), claim), lab.PhoneOne.Sign(claimHash));
        byte[] Request(int kind, byte[] body) => EnrollmentExchange.Seal(EnrollmentExchange.Header(kind, hash, claimHash,
            RandomNumberGenerator.GetBytes(32)), body, lab.Offer.GetEncryptionKeyCopy());
        byte[]? pending = null; byte[]? savedReply = null;
        var provisioned = false; var lostProvision = true; var lostReply = false; var lostBeforeReply = false;
        var rejectCount = 0; var polls = 0; var publishes = 0;
        using var transport = new HttpRelayTransport(new Uri(lab.Offer.RelayEndpoint), lab.Offer.MailboxId, lab.Offer.EncryptionKeyId,
            "synthetic-device-credential-00001", new HttpHandler(async (request, ct) =>
            {
                Check(request.Headers.Authorization?.Parameter == "synthetic-device-credential-00001" &&
                    request.RequestUri!.GetLeftPart(UriPartial.Authority) == lab.Offer.RelayEndpoint, "credential/origin binding");
                var actualPath = request.RequestUri!.AbsolutePath;
                if (request.Method == HttpMethod.Post && actualPath == path)
                {
                    using var json = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(ct));
                    Check(json.RootElement.GetProperty("phoneToken").GetString() == Convert.ToHexString(cap).ToLowerInvariant() &&
                        json.RootElement.GetProperty("expiresAt").GetInt64() == lab.Offer.ExpiresAtUtc.ToUnixTimeMilliseconds(), "derived provisioning capability/deadline");
                    var duplicate = provisioned; provisioned = true;
                    if (lostProvision) { lostProvision = false; throw new HttpRequestException("synthetic lost provision acknowledgment"); }
                    return Json(new { duplicate, retainUntil = lab.Offer.ExpiresAtUtc.AddDays(1).ToUnixTimeMilliseconds() }, duplicate ? HttpStatusCode.OK : HttpStatusCode.Created);
                }
                if (request.Method == HttpMethod.Get && actualPath == path + "/requests")
                {
                    polls++; return pending == null ? new HttpResponseMessage(HttpStatusCode.NoContent) : Binary(pending);
                }
                if (request.Method == HttpMethod.Delete)
                {
                    Check(pending != null && actualPath == path + "/requests/" +
                        Convert.ToHexString(EnrollmentExchange.Decode(pending).Nonce).ToLowerInvariant(), "reject targeted wrong request");
                    rejectCount++; pending = null; return new HttpResponseMessage(HttpStatusCode.NoContent);
                }
                Check(request.Method == HttpMethod.Post && actualPath == path + "/replies", "unexpected transport operation");
                publishes++;
                if (lostBeforeReply) { lostBeforeReply = false; throw new HttpRequestException("synthetic loss before publication"); }
                var reply = await request.Content!.ReadAsByteArrayAsync(ct);
                Check(pending != null, "blind duplicate reply publication");
                NativeEnrollmentExchange.RequireReplyBinding(reply, pending!, lab.Offer);
                savedReply = reply; pending = null; // Worker stops polling this nonce once its reply commits.
                if (lostReply) { lostReply = false; throw new HttpRequestException("synthetic loss after publication"); }
                return Json(new { duplicate = false }, HttpStatusCode.Created);
            }), TimeSpan.FromSeconds(2));
        using (var relay = new NativeEnrollmentRelay(lab.Store, lab.Exchange, transport, lab.Clock))
        {
            await Reject<HttpRequestException>(() => relay.ProvisionPendingAsync(None));
            Check((await lab.State()).Version == before.Version && !(await lab.State()).IsProvisioned, "HTTP failure reset/confirmed setup");
            await relay.ProvisionPendingAsync(None); // Same secret/hash/deadline; no new ceremony on lost acknowledgment.
            pending = Request(EnrollmentExchange.Claim, submission); pending[^1] ^= 1;
            Check(await relay.ProcessNextAsync(None) && rejectCount == 1 && (await lab.State()).Enrollment!.Candidate == null, "bad tag poisoned queue or created owner");
            pending = Request(EnrollmentExchange.Claim, submission); Array.Clear(pending, 109, 64);
            Check(await relay.ProcessNextAsync(None) && rejectCount == 2, "invalid remote curve point poisoned queue");
            pending = Request(EnrollmentExchange.Claim, submission);
            lab.Status = _ => throw new HttpRequestException("synthetic attestation source outage");
            await Reject<HttpRequestException>(() => relay.ProcessNextAsync(None));
            Check(pending != null && rejectCount == 2 && (await lab.State()).Version == before.Version, "transient source failure deleted request or changed state");
            lab.Status = _ => Task.FromResult(lab.PhoneOne.Status);
            pending = Request(EnrollmentExchange.Claim, submission); lostBeforeReply = true;
            await Reject<HttpRequestException>(() => relay.ProcessNextAsync(None));
            Check((await lab.State()).Enrollment!.Candidate != null && !(await lab.State()).IsProvisioned && pending != null, "lost response lost committed candidate");
        }
        lab.Reopen();
        using var resumed = new NativeEnrollmentRelay(lab.Store, lab.Exchange, transport, lab.Clock);
        Check(await resumed.ProcessNextAsync(None) && savedReply != null, "restart failed to answer retained message");
        int Outcome() => BinaryPrimitives.ReadInt32BigEndian(lab.OpenReply(EnrollmentExchange.Decode(savedReply!)).AsSpan(8, 4));
        Check(Outcome() == EnrollmentExchange.NeedsPhoneProof, "claim transport bypassed phone proof");
        pending = Request(EnrollmentExchange.Query, Array.Empty<byte>()); pending[44] ^= 1;
        Check(await resumed.ProcessNextAsync(None) && rejectCount == 3, "other candidate header blocked the intended phone queue");
        pending = Request(EnrollmentExchange.KeyProof, lab.DecryptProof((await lab.State()).Enrollment!)); lostReply = true;
        await Reject<HttpRequestException>(() => resumed.ProcessNextAsync(None));
        Check(Outcome() == EnrollmentExchange.NeedsLocalConfirmation && !(await lab.State()).IsProvisioned, "key proof transport bypassed local confirmation");
        var oldPublishes = publishes;
        Check(!await resumed.ProcessNextAsync(None) && publishes == oldPublishes, "lost HTTP acknowledgment blindly republished different ciphertext");
        var local = await lab.State();
        Check(await lab.Coordinator.ConfirmLocalAsync(ClientRole.AdminSetup, local.Version, start.GetConfirmationSecretCopy(), claimHash, None) == SetupOperationStatus.Succeeded,
            "originating confirmation after HTTP exchange");
        lab.Clock.Now = lab.Offer.ExpiresAtUtc.AddMinutes(1);
        pending = Request(EnrollmentExchange.Query, Array.Empty<byte>());
        Check(await resumed.ProcessNextAsync(None) && Outcome() == EnrollmentExchange.Confirmed, "late query lost final owner confirmation");
        pending = Request(EnrollmentExchange.Query, Array.Empty<byte>());
        var concurrent = await Task.WhenAll(resumed.ProcessNextAsync(None), resumed.ProcessNextAsync(None));
        Check(concurrent.Count(processed => processed) == 1, "concurrent polling double-published a nonce");
        Check((await lab.State()).TrustedParentKeys.Single().Equals(lab.PhoneOne.Anchor), "transport replaced attested parent");
        var callsBeforeExpiry = polls;
        lab.Clock.Now = lab.Offer.ExpiresAtUtc.AddDays(1);
        await Reject<InvalidDataException>(() => resumed.ProcessNextAsync(None));
        Check(polls == callsBeforeExpiry, "expired retained session reached HTTP");

        using var changed = new Lab(); using var changedStart = await changed.Begin();
        var stateBefore = await changed.State();
        using var changedTransport = new HttpRelayTransport(new Uri(changed.Offer.RelayEndpoint), changed.Offer.MailboxId, changed.Offer.EncryptionKeyId,
            "synthetic-device-credential-00001", new HttpHandler(async (_, _) =>
            {
                Check(await changed.Coordinator.CancelAsync(ClientRole.AdminSetup, stateBefore.Version, changedStart.GetConfirmationSecretCopy(), None) == SetupOperationStatus.Succeeded,
                    "synthetic cancellation");
                using var replacement = await changed.Begin(); // Same offer, DIFFERENT secrets; must not accept the old HTTP completion.
                return Json(new { duplicate = false, retainUntil = changed.Offer.ExpiresAtUtc.AddDays(1).ToUnixTimeMilliseconds() }, HttpStatusCode.Created);
            }), TimeSpan.FromSeconds(2));
        using var changedRelay = new NativeEnrollmentRelay(changed.Store, changed.Exchange, changedTransport, changed.Clock);
        await Reject<InvalidDataException>(() => changedRelay.ProvisionPendingAsync(None));
        Console.WriteLine("PASS enrollment HTTP: real file/attestation/CAS, derived capability, poison rejection, lost acknowledgments/restart, mandatory local confirmation, late query and changed-session guard");
    }

    private sealed class HttpHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
    }
    private static HttpResponseMessage Json(object body, HttpStatusCode status) => new(status) { Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json") };
    private static HttpResponseMessage Binary(byte[] body)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream"); return response;
    }

    private sealed class Lab : IDisposable
    {
        public string DirectoryPath { get; } = Path.Combine(Path.GetTempPath(), "guard-enrollment-tests-" + Guid.NewGuid().ToString("N"));
        public AndroidAttestationChecks.Fixture PhoneOne { get; } = new();
        public AndroidAttestationChecks.Fixture PhoneTwo { get; } = new();
        private readonly ECDsa _deviceSign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDiffieHellman _deviceEnc = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDiffieHellman _phoneEncryption = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        public TestProtector Protector { get; } = new();
        public Clock Clock { get; } = new();
        public Func<CancellationToken, Task<AndroidAttestationRevocations>> Status { get; set; }
        public FileAuthoritativeStateStore Store { get; private set; } = null!;
        public NativeEnrollmentCoordinator Coordinator { get; private set; } = null!;
        public EnrollmentOffer Offer { get; }
        public NativeEnrollmentExchange Exchange => new(Store, Coordinator, _deviceEnc, _deviceSign, Clock);
        public byte[] DeviceSigningSpki => _deviceSign.ExportSubjectPublicKeyInfo();
        public byte[] PhonePrivate => _phoneEncryption.ExportParameters(true).D!;
        public byte[] DevicePrivate => _deviceEnc.ExportParameters(true).D!;
        public byte[] OpenReply(EnrollmentExchange.Message message) => EnrollmentExchange.Open(message, _phoneEncryption);
        public Lab()
        {
            Directory.CreateDirectory(DirectoryPath);
            Offer = new EnrollmentOffer("https://relay.example.test", "enrollment-test-001", "device-test-00001", "Lab PC", 1, 1,
                "mailbox-test-00001", "device-sign-test1", _deviceSign.ExportSubjectPublicKeyInfo()[26..], "device-enc-test01",
                _deviceEnc.ExportSubjectPublicKeyInfo()[26..], Clock.Now.AddMinutes(-1), Clock.Now.AddMinutes(4), RandomNumberGenerator.GetBytes(32));
            Status = _ => Task.FromResult(PhoneOne.Status); Reopen();
            Store.InitializeAsync(new DeviceSecurityState(Offer.DeviceId, 0, 0, 0), None).GetAwaiter().GetResult();
        }
        public void Reopen()
        {
            Store?.Dispose();
            Store = new FileAuthoritativeStateStore(Path.Combine(DirectoryPath, "state.dat"), Protector,
                new ProtectedFileStateVersionJournal(Path.Combine(DirectoryPath, "journal.dat"), Protector));
            Coordinator = new NativeEnrollmentCoordinator(Store, new AndroidApprovalAttestation(new[] { PhoneOne.RootCertificate, PhoneTwo.RootCertificate },
                AndroidAttestationChecks.ApkSigner, 1), token => Status(token), Clock);
        }
        public Task<DeviceSecurityState> State() => Store.LoadAsync(None);
        public async Task<NativeEnrollmentStart> Begin()
        {
            var result = await Coordinator.BeginAsync(ClientRole.AdminSetup, Offer, None);
            Check(result.Status == SetupOperationStatus.Succeeded && result.Start != null, "begin"); return result.Start!;
        }
        public EnrollmentKeyClaim Claim(AndroidAttestationChecks.Fixture phone) => new(RelayCanonicalEncoding.ComputeEnrollmentOfferHash(Offer),
            phone.Anchor.KeyId, phone.Anchor.GetSubjectPublicKeyInfoCopy(), "phone-encrypt-001", Point(_phoneEncryption.ExportParameters(false).Q));
        public Task<SetupOperationStatus> Stage(AndroidAttestationChecks.Fixture phone, NativeEnrollmentStart start, EnrollmentKeyClaim claim, bool badMac = false)
        {
            var encoded = start.QrText.Split("&secret=", StringSplitOptions.None)[1].Replace('-', '+').Replace('_', '/');
            var secret = Convert.FromBase64String(encoded + "=");
            var mac = RelayCanonicalEncoding.ComputeEnrollmentClaimProof(SHA256.HashData(secret), claim); CryptographicOperations.ZeroMemory(secret);
            return Coordinator.StageAsync(ClientRole.ParentRelay, claim, badMac ? new byte[32] : mac,
                phone.Chain(AndroidAttestationChecks.Description(challenge: RelayCanonicalEncoding.ComputeEnrollmentOfferHash(Offer))),
                phone.Sign(RelayCanonicalEncoding.ComputeEnrollmentClaimHash(claim)), None);
        }
        public byte[] DecryptProof(DeviceEnrollmentState session)
        {
            var hash = RelayCanonicalEncoding.ComputeEnrollmentClaimHash(session.Candidate!);
            var parameters = _phoneEncryption.ExportParameters(true);
            var witness = RelayCryptography.Decrypt(parameters.D!, Point(parameters.Q), session.GetEncapsulatedKeyCopy(),
                session.GetEncryptedChallengeCopy(), hash, NativeEnrollmentCoordinator.KeyConfirmationInfo(hash));
            try { return NativeEnrollmentCoordinator.ComputePhoneKeyProof(witness, hash); }
            finally { CryptographicOperations.ZeroMemory(witness); CryptographicOperations.ZeroMemory(parameters.D!); }
        }
        public void Dispose()
        {
            Store.Dispose(); PhoneOne.Dispose(); PhoneTwo.Dispose(); _deviceSign.Dispose(); _deviceEnc.Dispose(); _phoneEncryption.Dispose(); Protector.Dispose();
            var full = Path.GetFullPath(DirectoryPath);
            if (!full.StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase) ||
                !Path.GetFileName(full).StartsWith("guard-enrollment-tests-", StringComparison.Ordinal)) throw new InvalidOperationException("Unsafe test cleanup.");
            Directory.Delete(full, recursive: true);
        }
    }
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = AndroidAttestationChecks.Now;
        public Action? OnRead;
        public override DateTimeOffset GetUtcNow() { OnRead?.Invoke(); return Now; }
    }
    private sealed class TestProtector : IStateDataProtector, IDisposable
    {
        private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
        public Action? OnProtect;
        public byte[] Protect(byte[] plaintext)
        {
            OnProtect?.Invoke(); var output = new byte[28 + plaintext.Length]; RandomNumberGenerator.Fill(output.AsSpan(0, 12));
            using var aes = new AesGcm(_key, 16); aes.Encrypt(output.AsSpan(0, 12), plaintext, output.AsSpan(28), output.AsSpan(12, 16)); return output;
        }
        public byte[] Unprotect(byte[] encoded)
        {
            var result = new byte[encoded.Length - 28]; using var aes = new AesGcm(_key, 16);
            aes.Decrypt(encoded.AsSpan(0, 12), encoded.AsSpan(28), encoded.AsSpan(12, 16), result); return result;
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(_key);
    }
    private static byte[] Point(ECPoint point) => new byte[] {4}.Concat(point.X!).Concat(point.Y!).ToArray();
    private static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static async Task Reject<T>(Func<Task> action) where T : Exception { try { await action(); } catch (T) { return; } throw new InvalidOperationException("Expected " + typeof(T).Name); }
    private static void RejectSync<T>(Action action) where T : Exception { try { action(); } catch (T) { return; } throw new InvalidOperationException("Expected " + typeof(T).Name); }
}
