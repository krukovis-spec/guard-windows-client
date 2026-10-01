using System;
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
using Guard.Provisioning;
using Guard.Service;
using Guard.Storage;
using Guard.Windows.Cryptography;
using Guard.Windows.Storage;

namespace Guard.Windows.Crypto.Tests;

internal static class ProvisioningChecks
{
    private const string Origin = "https://relay.example.test", Mailbox = "mailbox-operator-test-001";
    private const string Admin = "synthetic-operator-admin-not-a-real-secret";
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeMilliseconds(1790812800000);
    internal static void Run() => RunAsync().GetAwaiter().GetResult();

    private static async Task RunAsync()
    {
        var root = Path.Combine(Path.GetTempPath(), "GuardOperatorTests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var guard = new TestGuard(); var paths = new GuardDataPaths(Path.Combine(root, "guest"));
            Directory.CreateDirectory(paths.RootDirectory);
            using var service = new ServiceAuthoritativeStateBoundary(paths,
                new LocalSystemDpapiDataProtector(LocalSystemDpapiDataProtector.DefaultPurpose, true), guard,
                new DeviceIdentityStore(paths, new LocalSystemDpapiDataProtector(DeviceIdentityStore.Purpose, true), guard));
            await service.AcquireAsync(default); await service.InitializeNewAsync(default);
            var trust = new EnrollmentDeploymentTrust(Origin, new string('A', 64), 1);
            var descriptor = await service.ExportDeviceProvisioningAsync(trust, default);
            var descriptorPath = Path.Combine(root, "descriptor.json"); File.WriteAllBytes(descriptorPath, descriptor);
            var jobPath = Path.Combine(root, "operator.job"); var output = Path.Combine(root, "device.profile");
            var digest = Convert.ToHexString(SHA256.HashData(descriptor)); var expires = Now.AddDays(2);
            ProvisioningJob.Prepare(Origin, descriptorPath, digest, Mailbox, expires, jobPath, Now);
            var saved = File.ReadAllBytes(jobPath);
            Reject(() => ProvisioningJob.Prepare(Origin, descriptorPath, digest, Mailbox, expires, jobPath, Now));
            Check(saved.SequenceEqual(File.ReadAllBytes(jobPath)), "prepare overwrote existing intent");
            var opProtector = LocalSystemDpapiDataProtector.ForOperatorProvisioning();
            var serviceProtector = new LocalSystemDpapiDataProtector(DeviceRelayConfigurationStore.Purpose, true);
            Reject(() => serviceProtector.Unprotect(saved));
            Reject(() => opProtector.Unprotect(serviceProtector.Protect(new byte[] { 1, 2, 3 })));
            var mailboxJob = Path.Combine(root, "mailbox.job");
            await MailboxChecks(mailboxJob, jobPath);
            var bodies = new List<byte[]>();
            var calls = 0;
            async Task<HttpResponseMessage> Send(HttpRequestMessage request, CancellationToken token)
            {
                calls++;
                Check(request.RequestUri!.AbsoluteUri == Origin + "/v1/mailboxes/" + Mailbox + "/tokens/initial" && request.Method == HttpMethod.Post,
                    "wrong route or unsafe fallback");
                Check(request.Headers.Authorization?.ToString() == "Bearer " + Admin, "admin header binding");
                bodies.Add((await request.Content!.ReadAsByteArrayAsync(token)).ToArray());
                using var doc = JsonDocument.Parse(bodies[^1]); var body = doc.RootElement;
                Check(body.EnumerateObject().Count() == 5 && body.GetProperty("role").GetString() == "device" &&
                    body.GetProperty("recipientKeyId").GetString() == service.Identity.EncryptionKeyId &&
                    body.GetProperty("publishRecipientKeyIds").GetArrayLength() == 0 &&
                    body.GetProperty("expiresAt").GetInt64() == expires.ToUnixTimeMilliseconds(), "initial scope binding");
                if (calls == 1) throw new HttpRequestException("synthetic lost response after acceptance");
                return Reply("{\"role\":\"device\",\"expiresAt\":" + expires.ToUnixTimeMilliseconds() + "}");
            }
            Task Publish(string target, Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send,
                string origin = Origin, DateTimeOffset? now = null, CancellationToken token = default) =>
                ProvisioningJob.PublishAsync(origin, jobPath, target, Admin, now ?? Now, token, new Http(send));
            await RejectAsync(() => Publish(output, Send));
            Check(!File.Exists(output) && saved.SequenceEqual(File.ReadAllBytes(jobPath)), "ambiguous reply lost durable intent or exported");
            await MailboxProvisioningJob.PublishDeviceAsync(Origin, jobPath, mailboxJob, output, Now, default, new Http(Send));
            Check(calls == 2 && bodies[0].SequenceEqual(bodies[1]), "retry changed credential, scope or expiry");
            var envelope = File.ReadAllBytes(output);
            var open = new DeviceRelayProfileEnvelope(service.Identity.Encryption);
            var profile = open.Unprotect(envelope);
            try
            {
                using var wire = JsonDocument.Parse(bodies[1]); var credential = wire.RootElement.GetProperty("accessToken").GetString()!;
                Check(credential.Length == 64 && credential != Admin && !Encoding.UTF8.GetString(profile).Contains(Admin) &&
                    !Encoding.UTF8.GetString(saved).Contains(credential) && !Encoding.UTF8.GetString(envelope).Contains(credential), "secret boundary");
                var state = await service.LoadAsync(default);
                DeviceRelayConfiguration.Decode(profile).RequireMatches(trust, service.Identity, state, Now);
                // Actual operator envelope -> service staging -> immutable DPAPI configuration -> enrollment offer.
                File.WriteAllBytes(paths.DeviceRelayInstallFile, envelope);
                var store = new DeviceRelayConfigurationStore(paths, serviceProtector, guard);
                await store.ImportStagedAsync(trust, service, Now, default);
                Check(!File.Exists(paths.DeviceRelayInstallFile), "service did not consume committed envelope");
                var configuration = store.Load(trust, service.Identity, state, Now);
                Check(configuration.CreateOffer(trust, service.Identity, state, "Lab", Now).MailboxId == Mailbox,
                    "operator profile did not reach actual offer creation");
            }
            finally { CryptographicOperations.ZeroMemory(profile); }
            using var wrongKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            Reject(() => new DeviceRelayProfileEnvelope(wrongKey).Unprotect(envelope));
            foreach (var at in new[] { 0, 5, 40, 102, envelope.Length - 1 })
            { var bad = (byte[])envelope.Clone(); bad[at] ^= 1; Reject(() => open.Unprotect(bad)); }
            foreach (var bad in new[] { envelope[..^1], envelope[..100], new byte[DeviceRelayProfileEnvelope.MaximumFileBytes + 1], saved })
                Reject(() => open.Unprotect(bad));
            Reject(() => DeviceRelayProfileEnvelope.Seal(service.Identity.Encryption.ExportSubjectPublicKeyInfo(), new byte[4097]));
            var noSend = new Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>((_, _) => {
                calls++; throw new InvalidOperationException("must not reach network"); });
            await RejectAsync(() => Publish(output, noSend)); // Cannot overwrite even an existing encrypted output.
            await RejectAsync(() => Publish(output + "-other", noSend, "https://other.example.test"));
            await RejectAsync(() => Publish(output + "-past", noSend, now: Now.AddMilliseconds(-1)));
            await RejectAsync(() => Publish(output + "-expired", noSend, now: expires));
            var otherMailbox = Path.Combine(root, "other-mailbox.job");
            MailboxProvisioningJob.Prepare(Origin, "mailbox-other-test-0001", Admin, otherMailbox, Now);
            await RejectAsync(() => MailboxProvisioningJob.PublishDeviceAsync(Origin, jobPath, otherMailbox,
                output + "-wrong-mailbox", Now, default, new Http(noSend)));
            Check(calls == 2, "validation sent administrative credentials");
            var fileInfo = new FileInfo(jobPath); var originalAcl = fileInfo.GetAccessControl(); var broadAcl = fileInfo.GetAccessControl();
            broadAcl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Read, AccessControlType.Allow));
            fileInfo.SetAccessControl(broadAcl);
            await RejectAsync(() => Publish(output + "-acl", noSend));
            originalAcl.SetSecurityDescriptorBinaryForm(originalAcl.GetSecurityDescriptorBinaryForm(), AccessControlSections.Access);
            fileInfo.SetAccessControl(originalAcl);
            Check(ProvisioningJob.ReadBounded(jobPath, 16384, true).SequenceEqual(saved), "test did not restore private job ACL");
            File.WriteAllBytes(jobPath, saved[..^1]);
            await RejectAsync(() => Publish(output + "-corrupt", noSend));
            File.WriteAllBytes(jobPath, saved);
            Check(calls == 2, "bad storage caused network activity");
            // No export for redirect/old-server/conflict, malformed/extra/duplicate reply, wrong expiry, oversized or failed body.
            var index = 0;
            foreach (var reply in new[] { "{}", "{\"role\":\"admin\",\"expiresAt\":1}",
                "{\"role\":\"device\",\"expiresAt\":1}", "{\"role\":\"device\",\"role\":\"device\",\"expiresAt\":" + expires.ToUnixTimeMilliseconds() + "}",
                "{\"role\":\"device\",\"expiresAt\":" + expires.ToUnixTimeMilliseconds() + ",\"extra\":true}",
                ("{\"role\":\"device\",\"expiresAt\":" + expires.ToUnixTimeMilliseconds() + "}").PadRight(513) })
            {
                var target = output + "-bad-" + index++;
                await RejectAsync(() => Publish(target, (_, _) => Task.FromResult(Reply(reply))));
                Check(!File.Exists(target), "invalid response exported profile");
            }
            foreach (var status in new[] { HttpStatusCode.Redirect, HttpStatusCode.NotFound, HttpStatusCode.Conflict, HttpStatusCode.Unauthorized })
            {
                var target = output + "-status-" + (int)status;
                await RejectAsync(() => Publish(target, (_, _) => Task.FromResult(new HttpResponseMessage(status))));
                Check(!File.Exists(target), "failed issuance exported profile");
            }
            using var cancellation = new CancellationTokenSource();
            await RejectAsync(() => Publish(output + "-cancel", async (_, token) => {
                cancellation.Cancel(); await Task.Delay(Timeout.Infinite, token); return Reply("{}");
            }, token: cancellation.Token));
            Check(!File.Exists(output + "-cancel") && saved.SequenceEqual(File.ReadAllBytes(jobPath)), "cancellation lost intent");
            using var bodyCancellation = new CancellationTokenSource();
            await RejectAsync(() => Publish(output + "-body-cancel", (_, _) => {
                var content = new StreamContent(new CancelOnRead(bodyCancellation.Cancel));
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Created) { Content = content });
            }, token: bodyCancellation.Token));
            await RejectAsync(() => Publish(output + "-chunked", (_, _) => {
                var otherwiseValid = ("{\"role\":\"device\",\"expiresAt\":" + expires.ToUnixTimeMilliseconds() + "}").PadRight(513);
                var content = new StreamContent(new Unseekable(Encoding.UTF8.GetBytes(otherwiseValid)));
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Created) { Content = content });
            }));
            Check(!File.Exists(output + "-body-cancel") && !File.Exists(output + "-chunked"), "unbounded/cancelled body exported profile");
            foreach (var field in new[] { "relayOrigin", "signingKeyId", "encryptionKeyId", "deviceEpoch", "unknown" })
            {
                var node = JsonNode.Parse(descriptor)!.AsObject();
                if (field == "deviceEpoch") node[field] = 2;
                else node[field] = "incorrect-but-nonempty-value";
                var bad = JsonSerializer.SerializeToUtf8Bytes(node); File.WriteAllBytes(descriptorPath, bad);
                Reject(() => ProvisioningJob.Prepare(Origin, descriptorPath, Convert.ToHexString(SHA256.HashData(bad)), Mailbox, expires,
                    jobPath + "-invalid-" + field, Now));
                Check(!File.Exists(jobPath + "-invalid-" + field), "invalid descriptor saved");
            }
            File.WriteAllBytes(descriptorPath, descriptor);
            Reject(() => ProvisioningJob.Prepare(Origin, descriptorPath, new string('0', 64), Mailbox, expires, jobPath + "-wronghash", Now));
            Reject(() => ProvisioningJob.Prepare(Origin + "/path", descriptorPath, digest, Mailbox, expires, jobPath + "-path", Now));
            Reject(() => ProvisioningJob.Prepare(Origin, descriptorPath, digest, "guard:bff:auth:v1", expires, jobPath + "-reserved", Now));
            Reject(() => ProvisioningJob.Prepare(Origin, descriptorPath, digest, Mailbox, expires, jobPath + "-ambiguous. ", Now));
            Check(!File.Exists(jobPath + "-ambiguous"), "operator path silently trimmed trailing punctuation");
            Directory.CreateDirectory(Path.Combine(root, "repo", ".git"));
            var gitJob = Path.Combine(root, "repo", "operator.job");
            Reject(() => ProvisioningJob.Prepare(Origin, descriptorPath, digest, Mailbox, expires, gitJob, Now));
            Check(!File.Exists(gitJob), "operator secret saved inside Git");
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static async Task MailboxChecks(string path, string deviceJob)
    {
        const string bootstrap = "synthetic-bootstrap-not-cloudflare-api-token";
        MailboxProvisioningJob.Prepare(Origin, Mailbox, Admin, path, Now);
        var saved = File.ReadAllBytes(path);
        Reject(() => MailboxProvisioningJob.Prepare(Origin, Mailbox, Admin, path, Now));
        Check(saved.SequenceEqual(File.ReadAllBytes(path)), "mailbox prepare overwrote durable credential");
        Reject(() => LocalSystemDpapiDataProtector.ForOperatorProvisioning().Unprotect(saved));
        Reject(() => LocalSystemDpapiDataProtector.ForOperatorMailbox().Unprotect(File.ReadAllBytes(deviceJob)));
        var plaintext = LocalSystemDpapiDataProtector.ForOperatorMailbox().Unprotect(saved);
        try
        {
            Check(Encoding.UTF8.GetString(plaintext).Contains(Admin) && !Encoding.UTF8.GetString(plaintext).Contains(bootstrap) &&
                !Encoding.UTF8.GetString(saved).Contains(Admin), "mailbox secret boundary");
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
        var bodies = new List<byte[]>(); var calls = 0; var expires = Now.AddDays(365);
        async Task<HttpResponseMessage> Send(HttpRequestMessage request, CancellationToken token)
        {
            calls++;
            Check(request.Method == HttpMethod.Post && request.RequestUri!.AbsoluteUri == Origin + "/v1/admin/bootstrap" &&
                request.Headers.Authorization?.Parameter == bootstrap, "mailbox endpoint/credential binding");
            bodies.Add((await request.Content!.ReadAsByteArrayAsync(token)).ToArray());
            using var doc = JsonDocument.Parse(bodies[^1]);
            Check(doc.RootElement.EnumerateObject().Count() == 2 && doc.RootElement.GetProperty("mailboxId").GetString() == Mailbox &&
                doc.RootElement.GetProperty("accessToken").GetString() == Admin, "mailbox exact saved intent");
            if (calls == 1) throw new HttpRequestException("synthetic lost bootstrap reply");
            return Reply("{\"role\":\"admin\",\"expiresAt\":" + expires.ToUnixTimeMilliseconds() + "}");
        }
        await RejectAsync(() => MailboxProvisioningJob.PublishAsync(Origin, path, bootstrap, Now, default, new Http(Send)));
        Check(await MailboxProvisioningJob.PublishAsync(Origin, path, bootstrap, Now, default, new Http(Send)) == expires,
            "mailbox confirmation expiry");
        Check(calls == 2 && bodies[0].SequenceEqual(bodies[1]) && saved.SequenceEqual(File.ReadAllBytes(path)),
            "bootstrap retry changed key or lost intent");
        var noSend = new Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>((_, _) => {
            calls++; throw new InvalidOperationException("must not send bootstrap credential"); });
        await RejectAsync(() => MailboxProvisioningJob.PublishAsync("https://other.example.test", path, bootstrap, Now, default, new Http(noSend)));
        await RejectAsync(() => MailboxProvisioningJob.PublishAsync(Origin, path, bootstrap, Now.AddMilliseconds(-1), default, new Http(noSend)));
        await RejectAsync(() => MailboxProvisioningJob.PublishAsync(Origin, path, Admin, Now, default, new Http(noSend)));
        await RejectAsync(() => MailboxProvisioningJob.PublishAsync(Origin, deviceJob, bootstrap, Now, default, new Http(noSend)));
        var fileInfo = new FileInfo(path); var original = fileInfo.GetAccessControl(); var broad = fileInfo.GetAccessControl();
        broad.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Read, AccessControlType.Allow));
        fileInfo.SetAccessControl(broad);
        try { await RejectAsync(() => MailboxProvisioningJob.PublishAsync(Origin, path, bootstrap, Now, default, new Http(noSend))); }
        finally
        {
            original.SetSecurityDescriptorBinaryForm(original.GetSecurityDescriptorBinaryForm(), AccessControlSections.Access);
            fileInfo.SetAccessControl(original);
        }
        Check(ProvisioningJob.ReadBounded(path, 8192, true).SequenceEqual(saved), "test did not restore mailbox ACL");
        File.WriteAllBytes(path, saved[..^1]);
        await RejectAsync(() => MailboxProvisioningJob.PublishAsync(Origin, path, bootstrap, Now, default, new Http(noSend)));
        File.WriteAllBytes(path, saved);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await RejectAsync(() => MailboxProvisioningJob.PublishAsync(Origin, path, bootstrap, Now, cancelled.Token, new Http(noSend)));
        Check(calls == 2, "invalid mailbox intent leaked credential to network");
        foreach (var json in new[] { "{\"role\":\"admin\"}", "{\"role\":\"device\",\"expiresAt\":1}",
            "{\"role\":\"admin\",\"expiresAt\":" + Now.ToUnixTimeMilliseconds() + "}",
            "{\"role\":\"admin\",\"expiresAt\":" + Now.AddDays(366).ToUnixTimeMilliseconds() + "}",
            "{\"role\":\"admin\",\"expiresAt\":1,\"extra\":true}" })
            await RejectAsync(() => MailboxProvisioningJob.PublishAsync(Origin, path, bootstrap, Now, default,
                new Http((_, _) => Task.FromResult(Reply(json)))));
        foreach (var status in new[] { HttpStatusCode.Redirect, HttpStatusCode.Conflict, HttpStatusCode.Unauthorized })
            await RejectAsync(() => MailboxProvisioningJob.PublishAsync(Origin, path, bootstrap, Now, default,
                new Http((_, _) => Task.FromResult(new HttpResponseMessage(status)))));
        Check(saved.SequenceEqual(File.ReadAllBytes(path)), "failed bootstrap discarded durable intent");
        Reject(() => MailboxProvisioningJob.Prepare(Origin, "guard:bff:auth:v1", Admin, path + "-reserved", Now));
        Reject(() => MailboxProvisioningJob.Prepare(Origin, Mailbox, "123456", path + "-weak", Now));
    }
    private static HttpResponseMessage Reply(string value) => new(HttpStatusCode.Created) { Content = new StringContent(value, Encoding.UTF8, "application/json") };
    private sealed class Http(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken); }
    private sealed class CancelOnRead(Action cancel) : MemoryStream
    {
        public override bool CanSeek => false;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        { cancel(); return ValueTask.FromCanceled<int>(cancellationToken); }
    }
    private sealed class Unseekable(byte[] bytes) : MemoryStream(bytes) { public override bool CanSeek => false; }
    private sealed class TestGuard : IServiceDataBoundaryGuard { public void DemandReady() { } }
    private static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static void Reject(Action action) { try { action(); } catch (Exception) { return; } throw new InvalidOperationException("Expected refusal."); }
    private static async Task RejectAsync(Func<Task> action) { try { await action(); } catch (Exception) { return; } throw new InvalidOperationException("Expected refusal."); }
}
