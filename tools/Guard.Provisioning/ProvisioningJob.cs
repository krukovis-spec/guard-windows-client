using System.Net;
using System.Net.Http.Headers;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Guard.Contracts;
using Guard.Protocol.Relay;
using Guard.Windows.Cryptography;

namespace Guard.Provisioning;

// OFF-PC operator only. No admin credential is saved, exported, or passed to the service.
internal sealed class ProvisioningJob
{
    private readonly string _origin, _deviceId, _signingId, _encryptionId, _mailbox, _token;
    private readonly byte[] _encryptionSpki;
    private readonly DeviceProvisioningDescriptor _descriptor;
    private readonly long _issued, _expires;

    private ProvisioningJob(byte[] descriptor, string digest, string origin, string mailbox, string token,
        long issued, long expires, DateTimeOffset now)
    {
        RequireOrigin(origin);
        if (descriptor.Length is < 1 or > 2048 || digest.Length != 64 || !digest.All(Uri.IsHexDigit) ||
            !CryptographicOperations.FixedTimeEquals(Convert.FromHexString(digest), SHA256.HashData(descriptor)))
            throw new InvalidDataException("Device descriptor commitment.");
        var device = _descriptor = DeviceProvisioningDescriptor.Parse(descriptor);
        if (device.RelayOrigin != origin) throw new InvalidDataException("Device deployment.");
        _origin = origin; _mailbox = Id(mailbox); _deviceId = device.DeviceId;
        if (mailbox == "guard:bff:auth:v1") throw new InvalidDataException("Reserved mailbox.");
        _signingId = device.SigningKeyId; _encryptionId = device.EncryptionKeyId;
        _encryptionSpki = device.GetEncryptionKeyCopy();
        if (token.Length != 64 || token.Any(c => !(c is >= '0' and <= '9' or >= 'A' and <= 'F')))
            throw new InvalidDataException("Generated device credential.");
        if (issued < 0 || issued > now.ToUnixTimeMilliseconds() || expires <= now.AddDays(1).AddMinutes(5).ToUnixTimeMilliseconds())
            throw new InvalidDataException("Device credential lifetime/clock.");
        _ = DateTimeOffset.FromUnixTimeMilliseconds(expires);
        _issued = issued; _expires = expires; _token = token;
    }

    internal static void Prepare(string origin, string descriptorPath, string independentlyVerifiedSha256,
        string mailbox, DateTimeOffset expires, string jobPath, DateTimeOffset now)
    {
        var descriptor = ReadBounded(descriptorPath, 2048, requirePrivate: false);
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var issued = now.ToUnixTimeMilliseconds();
        _ = new ProvisioningJob(descriptor, independentlyVerifiedSha256, origin, mailbox, token, issued, expires.ToUnixTimeMilliseconds(), now);
        var raw = JsonSerializer.SerializeToUtf8Bytes(new { version = 1, relayOrigin = origin,
            descriptor = Convert.ToBase64String(descriptor), descriptorSha256 = independentlyVerifiedSha256,
            mailboxId = mailbox, accessToken = token, issuedAt = issued, expiresAt = expires.ToUnixTimeMilliseconds() });
        try { SaveNewPrivate(jobPath, LocalSystemDpapiDataProtector.ForOperatorProvisioning().Protect(raw)); }
        finally { CryptographicOperations.ZeroMemory(raw); }
    }

    internal static async Task PublishAsync(string independentlyTrustedOrigin, string jobPath, string outputPath,
        string adminCredential, DateTimeOffset now, CancellationToken cancellationToken, HttpMessageHandler? handler = null,
        string? expectedMailbox = null)
    {
        // Pin origin independently on EVERY invocation, before using an administrative credential.
        cancellationToken.ThrowIfCancellationRequested();
        RequireOrigin(independentlyTrustedOrigin); RequireCredential(adminCredential);
        RequireOutputPath(outputPath);
        if (File.Exists(outputPath)) throw new IOException("Output already exists.");
        var job = Load(independentlyTrustedOrigin, jobPath, now);
        if (expectedMailbox != null && job._mailbox != expectedMailbox) throw new InvalidDataException("Mailbox credential binding.");
        var body = JsonSerializer.SerializeToUtf8Bytes(new { accessToken = job._token, role = "device", expiresAt = job._expires,
            recipientKeyId = job._encryptionId, publishRecipientKeyIds = Array.Empty<string>() });
        await PostIssuanceAsync(job._origin + "/v1/mailboxes/" + job._mailbox + "/tokens/initial", adminCredential,
            body, "device", job._expires, cancellationToken, handler);
        cancellationToken.ThrowIfCancellationRequested();
        var profile = JsonSerializer.SerializeToUtf8Bytes(new { version = 1, role = "device", relayOrigin = job._origin,
            deviceId = job._deviceId, signingKeyId = job._signingId, encryptionKeyId = job._encryptionId, mailboxId = job._mailbox,
            deviceEpoch = 1, authorityEpoch = 1, accessToken = job._token, issuedAt = job._issued, expiresAt = job._expires });
        try { SaveNewPrivate(outputPath, DeviceRelayProfileEnvelope.Seal(job._encryptionSpki, profile)); }
        finally { CryptographicOperations.ZeroMemory(profile); }
    }

    internal static NativeActivationConfirmation VerifyNativeConfirmation(string origin, string jobPath, string proofPath, DateTimeOffset now)
    {
        var job = Load(origin, jobPath, now);
        return NativeActivationConfirmation.Verify(ReadBounded(proofPath, NativeActivationConfirmation.MaximumBytes, requirePrivate: false),
            job._descriptor, job._mailbox, now);
    }

    private static ProvisioningJob Load(string independentlyTrustedOrigin, string jobPath, DateTimeOffset now)
    {
        RequireOrigin(independentlyTrustedOrigin);
        var raw = LocalSystemDpapiDataProtector.ForOperatorProvisioning().Unprotect(ReadBounded(jobPath, 16384, requirePrivate: true));
        try
        {
            if (raw.Length > 8192) throw new InvalidDataException("Operator job size.");
            using var doc = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 3 });
            var value = doc.RootElement;
            RequireObject(value, "version", "relayOrigin", "descriptor", "descriptorSha256", "mailboxId", "accessToken", "issuedAt", "expiresAt");
            if (value.GetProperty("version").GetInt32() != 1 || String(value, "relayOrigin") != independentlyTrustedOrigin)
                throw new InvalidDataException("Operator deployment mismatch.");
            return new ProvisioningJob(Convert.FromBase64String(String(value, "descriptor")), String(value, "descriptorSha256"),
                independentlyTrustedOrigin, String(value, "mailboxId"), String(value, "accessToken"),
                value.GetProperty("issuedAt").GetInt64(), value.GetProperty("expiresAt").GetInt64(), now);
        }
        finally { CryptographicOperations.ZeroMemory(raw); }
    }

    // The two initial-issuance callers use the same bounded, non-redirecting HTTP path.
    internal static async Task<long> PostIssuanceAsync(string endpoint, string credential, byte[] body,
        string role, long? expiresAt, CancellationToken cancellationToken, HttpMessageHandler? handler)
    {
        using var client = new HttpClient(handler ?? new HttpClientHandler {
            AllowAutoRedirect = false, UseProxy = false, UseCookies = false, AutomaticDecompression = DecompressionMethods.None
        }) { Timeout = Timeout.InfiniteTimeSpan };
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(20));
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential);
        request.Content = new ByteArrayContent(body);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        var reply = new byte[513];
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            // No redirects, fallbacks, body logs, auto retries, or credential echo in exceptions.
            if (response.StatusCode != HttpStatusCode.Created) throw new InvalidDataException("Initial issuance was not confirmed; preserve the saved job.");
            if (response.Content.Headers.ContentLength is > 512 || response.Content.Headers.ContentEncoding.Count != 0 ||
                response.Content.Headers.ContentType?.MediaType != "application/json" ||
                response.Content.Headers.ContentType.CharSet is { } charset && !charset.Equals("utf-8", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Initial issuance response headers.");
            await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
            var length = 0;
            while (length < reply.Length)
            {
                var count = await stream.ReadAsync(reply.AsMemory(length), deadline.Token);
                if (count == 0) break;
                length += count;
            }
            if (length > 512) throw new InvalidDataException("Initial issuance response size.");
            using var result = JsonDocument.Parse(reply.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 2 });
            RequireObject(result.RootElement, "role", "expiresAt");
            var confirmedExpiry = result.RootElement.GetProperty("expiresAt").GetInt64();
            if (String(result.RootElement, "role") != role || confirmedExpiry <= 0 || expiresAt.HasValue && confirmedExpiry != expiresAt.Value)
                throw new InvalidDataException("Initial issuance response binding.");
            deadline.Token.ThrowIfCancellationRequested();
            return confirmedExpiry;
        }
        finally { request.Headers.Authorization = null; CryptographicOperations.ZeroMemory(body); CryptographicOperations.ZeroMemory(reply); }
    }

    internal static void RequireOrigin(string origin)
    {
        RelayCanonicalEncoding.RequireEnrollmentRelay(origin);
        var uri = new Uri(origin, UriKind.Absolute);
        if (origin != uri.GetLeftPart(UriPartial.Authority)) throw new InvalidDataException("Pinned origin must not include a path.");
    }
    internal static string Id(string value) => GuardIdentifier.IsCanonicalToken(value) ? value : throw new InvalidDataException("Identifier.");
    internal static string String(JsonElement value, string name) => value.GetProperty(name).GetString() ?? throw new InvalidDataException("Missing string.");
    internal static void RequireObject(JsonElement value, params string[] names)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException("JSON object required.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var field in value.EnumerateObject())
            if (!names.Contains(field.Name, StringComparer.Ordinal) || !seen.Add(field.Name)) throw new InvalidDataException("Unexpected JSON field.");
        if (seen.Count != names.Length) throw new InvalidDataException("Missing JSON field.");
    }
    internal static void RequireCredential(string value)
    {
        if (value.Length is < 32 or > 512 || value.Any(c => c < '!' || c > '~')) throw new InvalidDataException("Credential format.");
    }
    private static void RequireOutputPath(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new IOException("Absolute local path required.");
        foreach (var segment in path.Split('\\', '/'))
            if (segment.EndsWith('.') || segment.EndsWith(' ')) throw new IOException("Ambiguous operator path.");
        var full = Path.GetFullPath(path);
        if (full.Length < 4 || full[1] != ':' || full[2] != '\\' || full[2..].Contains(':')) throw new IOException("Local file path required.");
        for (var item = new FileInfo(full) as FileSystemInfo; item != null;
             item = item is FileInfo file ? file.Directory : ((DirectoryInfo)item).Parent)
        {
            if (item.Name.EndsWith('.') || item.Name.EndsWith(' ') || (item.Exists && (item.Attributes & FileAttributes.ReparsePoint) != 0))
                throw new IOException("Ambiguous or redirected operator path.");
            if (item is DirectoryInfo directory && (File.Exists(Path.Combine(directory.FullName, ".git")) || Directory.Exists(Path.Combine(directory.FullName, ".git"))))
                throw new IOException("Operator files must remain outside Git.");
        }
    }
    internal static void SaveNewPrivate(string path, byte[] bytes)
    {
        RequireOutputPath(path);
        using var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User ?? throw new UnauthorizedAccessException("Windows user required.");
        var security = new FileSecurity(); security.SetOwner(sid); security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        using var file = new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.WriteThrough, security);
        file.Write(bytes); file.Flush(flushToDisk: true);
        // A partial file after failure is retained and rejected on read, never silently regenerated/overwritten.
    }
    internal static byte[] ReadBounded(string path, int maximum, bool requirePrivate)
    {
        if (requirePrivate) RequireOutputPath(path);
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (requirePrivate)
        {
            using var identity = WindowsIdentity.GetCurrent();
            var security = file.GetAccessControl();
            var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
            if (!security.AreAccessRulesProtected || !Equals(security.GetOwner(typeof(SecurityIdentifier)), identity.User) ||
                rules.Length != 1 || !Equals(rules[0].IdentityReference, identity.User) || rules[0].IsInherited ||
                rules[0].AccessControlType != AccessControlType.Allow || rules[0].FileSystemRights != FileSystemRights.FullControl)
                throw new UnauthorizedAccessException("Operator job must be private to this Windows user.");
        }
        if (file.Length < 1 || file.Length > maximum) throw new InvalidDataException("File size.");
        var raw = new byte[(int)file.Length]; file.ReadExactly(raw);
        if (file.ReadByte() != -1) throw new InvalidDataException("File changed while reading.");
        return raw;
    }
}
