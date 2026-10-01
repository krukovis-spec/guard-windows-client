using System.Security.Cryptography;
using System.Text.Json;
using Guard.Windows.Cryptography;
using static Guard.Provisioning.ProvisioningJob;

namespace Guard.Provisioning;

// OFF-PC only. The caller must first save the administrator credential in their password manager.
internal sealed class MailboxProvisioningJob
{
    private readonly string _origin, _mailbox, _credential;

    private MailboxProvisioningJob(string origin, string mailbox, string credential, long issued, DateTimeOffset now)
    {
        RequireOrigin(origin); Id(mailbox); RequireCredential(credential);
        if (mailbox == "guard:bff:auth:v1" || issued < 0 || issued > now.ToUnixTimeMilliseconds())
            throw new InvalidDataException("Mailbox identity/clock.");
        _origin = origin; _mailbox = mailbox; _credential = credential;
    }

    internal static void Prepare(string origin, string mailbox, string credentialFromPasswordManager, string path, DateTimeOffset now)
    {
        var issued = now.ToUnixTimeMilliseconds();
        _ = new MailboxProvisioningJob(origin, mailbox, credentialFromPasswordManager, issued, now);
        var raw = JsonSerializer.SerializeToUtf8Bytes(new { version = 1, relayOrigin = origin, mailboxId = mailbox,
            accessToken = credentialFromPasswordManager, issuedAt = issued });
        try { SaveNewPrivate(path, LocalSystemDpapiDataProtector.ForOperatorMailbox().Protect(raw)); }
        finally { CryptographicOperations.ZeroMemory(raw); }
    }

    private static MailboxProvisioningJob Load(string origin, string path, DateTimeOffset now)
    {
        RequireOrigin(origin);
        var raw = LocalSystemDpapiDataProtector.ForOperatorMailbox().Unprotect(ReadBounded(path, 8192, requirePrivate: true));
        try
        {
            if (raw.Length > 4096) throw new InvalidDataException("Mailbox job size.");
            using var doc = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 2 }); var value = doc.RootElement;
            RequireObject(value, "version", "relayOrigin", "mailboxId", "accessToken", "issuedAt");
            if (value.GetProperty("version").GetInt32() != 1 || String(value, "relayOrigin") != origin)
                throw new InvalidDataException("Mailbox deployment mismatch.");
            return new MailboxProvisioningJob(origin, String(value, "mailboxId"), String(value, "accessToken"),
                value.GetProperty("issuedAt").GetInt64(), now);
        }
        finally { CryptographicOperations.ZeroMemory(raw); }
    }

    internal static async Task<DateTimeOffset> PublishAsync(string origin, string path, string bootstrapCredential,
        DateTimeOffset now, CancellationToken cancellationToken, HttpMessageHandler? handler = null)
    {
        cancellationToken.ThrowIfCancellationRequested(); RequireCredential(bootstrapCredential);
        var job = Load(origin, path, now);
        if (bootstrapCredential == job._credential) throw new InvalidDataException("Separate bootstrap credential required.");
        var body = JsonSerializer.SerializeToUtf8Bytes(new { mailboxId = job._mailbox, accessToken = job._credential });
        var expiry = await PostIssuanceAsync(job._origin + "/v1/admin/bootstrap", bootstrapCredential, body,
            "admin", null, cancellationToken, handler);
        if (expiry <= now.ToUnixTimeMilliseconds() || expiry > now.AddDays(365).AddMinutes(5).ToUnixTimeMilliseconds())
            throw new InvalidDataException("Mailbox administrator lifetime.");
        return DateTimeOffset.FromUnixTimeMilliseconds(expiry);
    }

    internal static Task PublishDeviceAsync(string origin, string deviceJobPath, string mailboxJobPath, string outputPath,
        DateTimeOffset now, CancellationToken cancellationToken, HttpMessageHandler? handler = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var job = Load(origin, mailboxJobPath, now);
        return ProvisioningJob.PublishAsync(origin, deviceJobPath, outputPath, job._credential, now, cancellationToken, handler, job._mailbox);
    }

    internal static Task<string?> ActivateNativeAsync(string origin, string deviceJobPath, string activationJobPath, string currentProofPath,
        string mailboxJobPath, CancellationToken cancellationToken, TimeProvider? clock = null, HttpMessageHandler? handler = null, string? outputPath = null)
    {
        clock ??= TimeProvider.System;
        cancellationToken.ThrowIfCancellationRequested();
        var job = Load(origin, mailboxJobPath, clock.GetUtcNow());
        return ProvisioningJob.ActivateNativeAsync(origin, deviceJobPath, activationJobPath, currentProofPath, job._credential,
            cancellationToken, clock, handler, job._mailbox, outputPath);
    }
}
