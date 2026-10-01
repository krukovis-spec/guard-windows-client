using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Provisioning;
using Guard.Protocol.Relay;
using Guard.Windows.Cryptography;

namespace Guard.Windows.Crypto.Tests;

// Uses the real committed-owner fixture, DPAPI and files; only HTTP and the clock are controlled.
internal static class NativeActivationJobChecks
{
    internal static async Task RunAsync(string root, string descriptorPath, string deviceJob, string proofPath,
        DeviceSecurityState owner, ECDsa signing, ECDiffieHellman phoneEncryption, DateTimeOffset now)
    {
        var origin = owner.Enrollment!.Offer.RelayEndpoint; var mailbox = owner.Enrollment.Offer.MailboxId;
        var clock = new Clock(now); var job = Path.Combine(root, "activation.job"); var mailboxJob = Path.Combine(root, "mailbox.job");
        const string admin = "synthetic-native-mailbox-admin-not-a-real-secret";
        MailboxProvisioningJob.Prepare(origin, mailbox, admin, mailboxJob, now);
        ProvisioningJob.PrepareNativeActivation(origin, deviceJob, proofPath, job, clock);
        var saved = File.ReadAllBytes(job); var originalDevice = File.ReadAllBytes(deviceJob); var originalMailbox = File.ReadAllBytes(mailboxJob);
        var protector = LocalSystemDpapiDataProtector.ForOperatorNativeActivation();
        Reject(() => ProvisioningJob.PrepareNativeActivation(origin, deviceJob, proofPath, job, clock));
        Reject(() => LocalSystemDpapiDataProtector.ForOperatorMailbox().Unprotect(saved));
        Reject(() => LocalSystemDpapiDataProtector.ForOperatorProvisioning().Unprotect(saved));
        Reject(() => protector.Unprotect(originalDevice));
        var plaintext = protector.Unprotect(saved);
        byte[] expected;
        try
        {
            using var document = JsonDocument.Parse(plaintext);
            expected = Convert.FromBase64String(document.RootElement.GetProperty("body").GetString()!);
            using var payload = JsonDocument.Parse(expected); var fields = payload.RootElement;
            var deviceToken = fields.GetProperty("deviceAccessToken").GetString()!;
            var approvalToken = fields.GetProperty("approvalAccessToken").GetString()!;
            Check(fields.EnumerateObject().Count() == 7 && fields.GetProperty("authorityEpoch").GetInt32() == 1 &&
                fields.GetProperty("expiresAt").GetInt64() == now.AddDays(3).ToUnixTimeMilliseconds() &&
                fields.GetProperty("deviceRecipientKeyId").GetString() == owner.Enrollment.Offer.EncryptionKeyId &&
                fields.GetProperty("approvalRecipientKeyId").GetString() == owner.Enrollment.Candidate!.EncryptionKeyId &&
                fields.GetProperty("approvalKeyId").GetString() == owner.Enrollment.Candidate.ApprovalKeyId &&
                approvalToken.Length == 64 && approvalToken != deviceToken && approvalToken != admin, "native scope/credential binding");
            Check(!Encoding.UTF8.GetString(saved).Contains(approvalToken) && !Encoding.UTF8.GetString(saved).Contains(deviceToken) &&
                !Encoding.UTF8.GetString(plaintext).Contains(admin), "native job leaked clear credentials or saved mailbox admin");
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
        var bodies = new List<byte[]>(); var calls = 0;
        async Task<HttpResponseMessage> Send(HttpRequestMessage request, CancellationToken token)
        {
            calls++;
            Check(request.Method == HttpMethod.Post && request.RequestUri!.AbsoluteUri == origin + "/v1/mailboxes/" + mailbox + "/tokens/activate-native" &&
                request.Headers.Authorization?.ToString() == "Bearer " + admin, "native activation route/admin binding");
            bodies.Add((await request.Content!.ReadAsByteArrayAsync(token)).ToArray());
            Check(bodies[^1].SequenceEqual(expected), "native activation regenerated the saved intent");
            if (calls == 1) throw new HttpRequestException("synthetic loss after server commit");
            return Reply(now.AddDays(3));
        }
        Task Activate(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send,
            string? targetJob = null, string? currentProof = null, string? device = null, string? mailboxFile = null,
            string? targetOrigin = null, TimeProvider? time = null, CancellationToken cancellation = default) =>
            MailboxProvisioningJob.ActivateNativeAsync(targetOrigin ?? origin, device ?? deviceJob, targetJob ?? job,
                currentProof ?? proofPath, mailboxFile ?? mailboxJob, cancellation, time ?? clock, new Http(send));
        await RejectAsync(() => Activate(Send));
        Check(saved.SequenceEqual(File.ReadAllBytes(job)), "uncertain activation rewrote intent");
        await Activate(Send); // Reloads all three actual private files, with a new HTTP client.
        Check(calls == 2 && bodies[0].SequenceEqual(bodies[1]), "lost-response retry changed body");
        var noSend = new Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>((_, _) => {
            calls++; throw new InvalidOperationException("Rejected input reached HTTP.");
        });
        await RejectAsync(() => Activate(noSend, targetOrigin: "https://other.example.test"));
        await RejectAsync(() => Activate(noSend, targetJob: deviceJob));
        var wrongMailbox = Path.Combine(root, "wrong-mailbox-admin.job");
        MailboxProvisioningJob.Prepare(origin, "different-mailbox-0001", admin, wrongMailbox, now);
        await RejectAsync(() => Activate(noSend, mailboxFile: wrongMailbox));
        // Same descriptor/mailbox but a newly generated device token is NOT the original issuance intent.
        var otherDevice = Path.Combine(root, "other-device.job"); var descriptor = DeviceProvisioningDescriptor.Parse(File.ReadAllBytes(descriptorPath));
        ProvisioningJob.Prepare(origin, descriptorPath, descriptor.Sha256, mailbox, now.AddDays(3), otherDevice, now);
        await RejectAsync(() => Activate(noSend, device: otherDevice));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await RejectAsync(() => Activate(noSend, cancellation: cancelled.Token));
        clock.Now = now.AddMinutes(10);
        await RejectAsync(() => Activate(noSend));
        Reject(() => ProvisioningJob.PrepareNativeActivation(origin, deviceJob, proofPath, Path.Combine(root, "expired-activation.job"), clock));
        clock.Now = now.AddMilliseconds(-1);
        await RejectAsync(() => Activate(noSend));
        clock.Now = now;
        var original = owner.Enrollment; var offer = original.Offer; var claim = original.Candidate!;
        DeviceSecurityState Owner(EnrollmentOffer chosenOffer, EnrollmentKeyClaim chosenClaim, long version) => new(owner.DeviceId,
            version, owner.HighestAcceptedSequence, owner.DesiredPolicyRevision, owner.RecentCommandIds, trustedParentKeys: owner.TrustedParentKeys,
            childAccountSid: owner.ChildAccountSid, enrollment: new DeviceEnrollmentState(chosenOffer, Array.Empty<byte>(), chosenClaim,
                original.GetCertificatesCopy(), original.GetSignatureCopy(), original.GetMacCopy(), original.GetEncapsulatedKeyCopy(),
                original.GetEncryptedChallengeCopy(), Array.Empty<byte>(), phoneKeyConfirmed: true, confirmed: true));
        var changedOffer = new EnrollmentOffer(offer.RelayEndpoint, offer.EnrollmentId, offer.DeviceId, "Changed device label",
            offer.DeviceEpoch, offer.AuthorityEpoch, offer.MailboxId, offer.SigningKeyId, offer.GetSigningKeyCopy(), offer.EncryptionKeyId,
            offer.GetEncryptionKeyCopy(), offer.CreatedAtUtc, offer.ExpiresAtUtc, offer.GetChallengeCopy());
        var changedOfferClaim = new EnrollmentKeyClaim(RelayCanonicalEncoding.ComputeEnrollmentOfferHash(changedOffer), claim.ApprovalKeyId,
            claim.GetApprovalKeyCopy(), claim.EncryptionKeyId, claim.GetEncryptionKeyCopy());
        using var otherEncryption = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var changedClaim = new EnrollmentKeyClaim(claim.GetOfferHashCopy(), claim.ApprovalKeyId, claim.GetApprovalKeyCopy(),
            "other-native-encryption-0001", otherEncryption.ExportSubjectPublicKeyInfo()[26..]);
        // Deliberately sign altered persisted transcripts with the real fixture device key.
        // Valid signatures alone must not switch a saved intent to another offer/phone or earlier state.
        foreach (var altered in new[] { Owner(offer, claim, owner.Version - 1), Owner(changedOffer, changedOfferClaim, owner.Version), Owner(offer, changedClaim, owner.Version) })
        {
            var alteredProof = Path.Combine(root, Guid.NewGuid().ToString("N") + ".guard-proof");
            NativeActivationConfirmation.Create(altered, signing, now).SaveNew(alteredProof, now);
            await RejectAsync(() => Activate(noSend, currentProof: alteredProof));
        }
        // Advance time after the last file/intent validation, at the actual HTTP dispatch boundary.
        await RejectAsync(() => Activate(noSend, time: new DispatchClock(now)));

        var fileInfo = new FileInfo(job); var originalAcl = fileInfo.GetAccessControl();
        var aclBytes = originalAcl.GetSecurityDescriptorBinaryForm();
        try
        {
            var altered = fileInfo.GetAccessControl();
            altered.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.Read, AccessControlType.Allow));
            fileInfo.SetAccessControl(altered);
            await RejectAsync(() => Activate(noSend));
        }
        finally { originalAcl.SetSecurityDescriptorBinaryForm(aclBytes, AccessControlSections.Access); fileInfo.SetAccessControl(originalAcl); }
        Check(ProvisioningJob.ReadBounded(job, 32768, true).SequenceEqual(saved), "test did not restore native job ACL");
        File.WriteAllBytes(job, saved[..^1]);
        await RejectAsync(() => Activate(noSend)); File.WriteAllBytes(job, saved);

        // Validate hostile encrypted schema/scope, rather than merely DPAPI corruption.
        void Change(Action<JsonObject> alter)
        {
            var raw = protector.Unprotect(saved);
            try
            {
                var document = JsonNode.Parse(raw)!.AsObject(); alter(document);
                var changed = JsonSerializer.SerializeToUtf8Bytes(document);
                try { File.WriteAllBytes(job, protector.Protect(changed)); }
                finally { CryptographicOperations.ZeroMemory(changed); }
            }
            finally { CryptographicOperations.ZeroMemory(raw); }
        }
        try
        {
            foreach (var field in new[] { "deviceAccessToken", "deviceRecipientKeyId", "approvalRecipientKeyId", "approvalKeyId", "authorityEpoch", "expiresAt", "extra" })
            {
                Change(document => {
                    var body = JsonNode.Parse(expected)!.AsObject();
                    body[field] = field switch { "authorityEpoch" => JsonValue.Create(2), "expiresAt" => JsonValue.Create(now.AddDays(4).ToUnixTimeMilliseconds()), _ => JsonValue.Create("changed-field-value") };
                    document["body"] = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(body));
                });
                await RejectAsync(() => Activate(noSend));
            }
            foreach (Action<JsonObject> alter in new Action<JsonObject>[] {
                document => document["preparedAt"] = now.AddSeconds(1).ToUnixTimeMilliseconds(),
                document => document["relayOrigin"] = "https://different.example.test",
                document => document["version"] = 2,
                document => document["proof"] = "invalid",
                document => document["body"] = " " + Convert.ToBase64String(expected),
                document => document["extra"] = true,
                document => document.Remove("proof") })
            {
                Change(alter); await RejectAsync(() => Activate(noSend));
            }
            foreach (var invalidToken in new[] { "short", new string('g', 64), JsonNode.Parse(expected)!["deviceAccessToken"]!.GetValue<string>() })
            {
                Change(document => {
                    var body = JsonNode.Parse(expected)!.AsObject(); body["approvalAccessToken"] = invalidToken;
                    document["body"] = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(body));
                });
                await RejectAsync(() => Activate(noSend));
            }
        }
        finally { File.WriteAllBytes(job, saved); }
        Check(calls == 2, "rejected activation reached network");

        // A fresh signed proof for the SAME owner renews evidence, never the credential/intent/expiry.
        clock.Now = now.AddMinutes(11);
        var freshProof = Path.Combine(root, "fresh.guard-proof");
        NativeActivationConfirmation.Create(Owner(offer, claim, owner.Version + 1), signing, clock.Now).SaveNew(freshProof, clock.Now);
        await Activate(Send, currentProof: freshProof);
        Check(calls == 3 && bodies[^1].SequenceEqual(expected), "fresh proof changed the durable activation intent");
        var output = Path.Combine(root, "phone.guard-native");
        var digest = await MailboxProvisioningJob.ActivateNativeAsync(origin, deviceJob, job, freshProof, mailboxJob, default, clock, new Http(Send), output);
        var envelope = File.ReadAllBytes(output);
        Check(envelope.Length == NativeRelayProfileEnvelope.FileBytes && digest == Convert.ToHexString(SHA256.HashData(envelope)), "native export commitment/size");
        var key = phoneEncryption.ExportParameters(true);
        byte[] Open(byte[] input) => RelayCryptography.Decrypt(key.D!, claim.GetEncryptionKeyCopy(), input[68..133], input[133..], input[..68],
            Encoding.ASCII.GetBytes("Guard.v2.native-relay.install.hpke.v1").Concat(input[..68]).ToArray());
        var profile = Open(envelope);
        try
        {
            using var intent = JsonDocument.Parse(expected); var approval = intent.RootElement.GetProperty("approvalAccessToken").GetString()!;
            Check(profile.Length == 84 && profile.AsSpan(0, 4).SequenceEqual("GNP1"u8) &&
                BinaryPrimitives.ReadInt64BigEndian(profile.AsSpan(4, 8)) == now.ToUnixTimeMilliseconds() &&
                BinaryPrimitives.ReadInt64BigEndian(profile.AsSpan(12, 8)) == now.AddDays(3).ToUnixTimeMilliseconds() &&
                Encoding.ASCII.GetString(profile[20..]) == approval && !Encoding.ASCII.GetString(envelope).Contains(approval) &&
                !Encoding.ASCII.GetString(profile).Contains(admin) && !Encoding.ASCII.GetString(profile).Contains(intent.RootElement.GetProperty("deviceAccessToken").GetString()!),
                "native profile contained wrong scope/secret/lifetime");
            foreach (var at in new[] { 0, 35, 67, 80, 180, envelope.Length - 1 })
            { var changed = (byte[])envelope.Clone(); changed[at] ^= 1; Reject(() => Open(changed)); }
        }
        finally { CryptographicOperations.ZeroMemory(profile); CryptographicOperations.ZeroMemory(key.D!); }
        await RejectAsync(() => MailboxProvisioningJob.ActivateNativeAsync(origin, deviceJob, job, freshProof, mailboxJob, default, clock, new Http(noSend), output));
        await RejectAsync(() => MailboxProvisioningJob.ActivateNativeAsync(origin, deviceJob, job, freshProof, mailboxJob, default, clock,
            new Http((_, _) => throw new HttpRequestException("lost export response")), output + ".failed"));
        Check(calls == 4 && File.ReadAllBytes(output).SequenceEqual(envelope) && !File.Exists(output + ".failed"), "failed native export wrote or replaced output");
        foreach (var status in new[] { HttpStatusCode.Redirect, HttpStatusCode.NotFound, HttpStatusCode.Conflict, HttpStatusCode.Unauthorized })
            await RejectAsync(() => Activate((_, _) => Task.FromResult(new HttpResponseMessage(status)), currentProof: freshProof));
        foreach (var expiry in new[] { now.AddDays(4), now.AddDays(3).AddMilliseconds(-1) })
            await RejectAsync(() => Activate((_, _) => Task.FromResult(Reply(expiry)), currentProof: freshProof));
        await RejectAsync(() => Activate((_, _) => {
            clock.Now = now.AddMinutes(21); return Task.FromResult(Reply(now.AddDays(3)));
        }, currentProof: freshProof));
        Check(saved.SequenceEqual(File.ReadAllBytes(job)) && originalDevice.SequenceEqual(File.ReadAllBytes(deviceJob)) &&
            originalMailbox.SequenceEqual(File.ReadAllBytes(mailboxJob)) && !File.Exists(Path.Combine(root, "expired-activation.job")),
            "native activation modified existing jobs or created rejected output");
        CryptographicOperations.ZeroMemory(expected);
        foreach (var body in bodies) CryptographicOperations.ZeroMemory(body);
        Console.WriteLine("PASS native activation operator: durable DPAPI intent, exact HTTP retry, renewed signed proof, scope/lineage/clock/ACL/response rejection; no live relay");
    }

    private static HttpResponseMessage Reply(DateTimeOffset expiry) => new(HttpStatusCode.Created) {
        Content = new StringContent("{\"role\":\"approval\",\"expiresAt\":" + expiry.ToUnixTimeMilliseconds() + "}", Encoding.UTF8, "application/json")
    };
    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        internal DateTimeOffset Now = now;
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private sealed class DispatchClock(DateTimeOffset now) : TimeProvider
    {
        private int _reads;
        public override DateTimeOffset GetUtcNow() => ++_reads >= 5 ? now.AddMinutes(10) : now;
    }
    private sealed class Http(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token); }
    private static async Task RejectAsync(Func<Task> action)
    {
        try { await action(); }
        catch (Exception error) when (Expected(error)) { return; }
        throw new InvalidOperationException("Invalid native activation accepted.");
    }
    private static void Reject(Action action) => RejectAsync(() => { action(); return Task.CompletedTask; }).GetAwaiter().GetResult();
    private static bool Expected(Exception error) => error is ArgumentException or FormatException or InvalidDataException or JsonException
        or CryptographicException or IOException or UnauthorizedAccessException or HttpRequestException or OperationCanceledException
        or PlatformNotSupportedException { InnerException: CryptographicException };
    private static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
}
