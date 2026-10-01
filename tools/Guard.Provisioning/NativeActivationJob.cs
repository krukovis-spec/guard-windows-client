using System.Security.Cryptography;
using System.Text.Json;
using Guard.Protocol.Relay;
using Guard.Windows.Cryptography;

namespace Guard.Provisioning;

// Same off-PC operator/trust/files as initial issuance. No credential goes to Windows or Android here.
internal sealed partial class ProvisioningJob
{
    internal static void PrepareNativeActivation(string origin, string deviceJobPath, string proofPath,
        string activationJobPath, TimeProvider? clock = null)
    {
        clock ??= TimeProvider.System;
        var device = Load(origin, deviceJobPath, clock.GetUtcNow());
        var bytes = ReadBounded(proofPath, NativeActivationConfirmation.MaximumBytes, requirePrivate: false);
        var prepared = clock.GetUtcNow();
        var proof = NativeActivationConfirmation.Verify(bytes, device._descriptor, device._mailbox, prepared);
        var approvalCredential = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        if (approvalCredential == device._token) throw new CryptographicException("Separate native credential required.");
        var body = JsonSerializer.SerializeToUtf8Bytes(new { deviceAccessToken = device._token,
            deviceRecipientKeyId = device._encryptionId, approvalAccessToken = approvalCredential,
            approvalRecipientKeyId = proof.Claim.EncryptionKeyId, approvalKeyId = proof.Claim.ApprovalKeyId,
            authorityEpoch = 1, expiresAt = device._expires });
        var raw = JsonSerializer.SerializeToUtf8Bytes(new { version = 1, relayOrigin = origin,
            proof = Convert.ToBase64String(bytes), preparedAt = prepared.ToUnixTimeMilliseconds(), body = Convert.ToBase64String(body) });
        try
        {
            proof.RequireCurrent(clock.GetUtcNow());
            SaveNewPrivate(activationJobPath, LocalSystemDpapiDataProtector.ForOperatorNativeActivation().Protect(raw));
        }
        finally { CryptographicOperations.ZeroMemory(raw); CryptographicOperations.ZeroMemory(body); }
    }

    internal static async Task<string?> ActivateNativeAsync(string origin, string deviceJobPath, string activationJobPath,
        string currentProofPath, string adminCredential, CancellationToken cancellationToken,
        TimeProvider? clock = null, HttpMessageHandler? handler = null, string? expectedMailbox = null, string? outputPath = null)
    {
        clock ??= TimeProvider.System;
        cancellationToken.ThrowIfCancellationRequested(); RequireCredential(adminCredential);
        if (outputPath != null)
        {
            RequireOutputPath(outputPath);
            if (File.Exists(outputPath)) throw new IOException("Native output already exists.");
        }
        var device = Load(origin, deviceJobPath, clock.GetUtcNow());
        if (expectedMailbox != null && expectedMailbox != device._mailbox) throw new InvalidDataException("Mailbox credential binding.");
        var bytes = ReadBounded(currentProofPath, NativeActivationConfirmation.MaximumBytes, requirePrivate: false);
        var proof = NativeActivationConfirmation.Verify(bytes, device._descriptor, device._mailbox, clock.GetUtcNow());
        var (body, prepared) = device.ReadNativeActivationBody(activationJobPath, proof, clock.GetUtcNow());
        void CheckCurrent()
        {
            cancellationToken.ThrowIfCancellationRequested();
            var now = clock.GetUtcNow();
            proof.RequireCurrent(now);
            if (now < prepared || now.ToUnixTimeMilliseconds() >= device._expires)
                throw new InvalidDataException("Native activation clock/lifetime.");
        }
        try
        {
            using var payload = JsonDocument.Parse(body);
            var approval = String(payload.RootElement, "approvalAccessToken");
            // Recheck AFTER all file/decryption/validation work, immediately before the only network call.
            await PostIssuanceAsync(origin + "/v1/mailboxes/" + device._mailbox + "/tokens/activate-native", adminCredential,
                body, "approval", device._expires, cancellationToken, handler, CheckCurrent);
            CheckCurrent(); // A late/ambiguous response is not success. Preserve the original job for exact retry.
            if (outputPath == null) return null;
            var envelope = NativeRelayProfileEnvelope.Seal(proof.Offer, proof.Claim, approval, prepared, DateTimeOffset.FromUnixTimeMilliseconds(device._expires));
            CheckCurrent();
            SaveNewPrivate(outputPath, envelope);
            return Convert.ToHexString(SHA256.HashData(envelope)); // Independent parent-channel commitment, no credential.
        }
        finally { CryptographicOperations.ZeroMemory(body); }
    }

    private (byte[] Body, DateTimeOffset Prepared) ReadNativeActivationBody(string path, NativeActivationConfirmation current, DateTimeOffset now)
    {
        var raw = LocalSystemDpapiDataProtector.ForOperatorNativeActivation().Unprotect(ReadBounded(path, 32768, requirePrivate: true));
        byte[]? body = null;
        try
        {
            if (raw.Length > 24576) throw new InvalidDataException("Native activation job size.");
            using var doc = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 2 }); var value = doc.RootElement;
            RequireObject(value, "version", "relayOrigin", "proof", "preparedAt", "body");
            var prepared = DateTimeOffset.FromUnixTimeMilliseconds(value.GetProperty("preparedAt").GetInt64());
            if (value.GetProperty("version").GetInt32() != 1 || String(value, "relayOrigin") != _origin || prepared > now)
                throw new InvalidDataException("Native activation deployment/clock.");
            // Historical proof authenticates the SAVED intent only. A separate live proof is mandatory on every send.
            var saved = NativeActivationConfirmation.Verify(CanonicalBytes(value, "proof"), _descriptor, _mailbox, prepared);
            current.RequireCurrent(now);
            if (current.StateVersion < saved.StateVersion ||
                !RelayCanonicalEncoding.EncodeEnrollmentOffer(current.Offer).AsSpan().SequenceEqual(RelayCanonicalEncoding.EncodeEnrollmentOffer(saved.Offer)) ||
                !RelayCanonicalEncoding.EncodeEnrollmentClaimForSignature(current.Claim).AsSpan().SequenceEqual(RelayCanonicalEncoding.EncodeEnrollmentClaimForSignature(saved.Claim)))
                throw new InvalidDataException("Native activation transcript changed.");
            body = CanonicalBytes(value, "body");
            if (body.Length is < 1 or > 4096) throw new InvalidDataException("Native activation body size.");
            using var payload = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 2 }); var intent = payload.RootElement;
            RequireObject(intent, "deviceAccessToken", "deviceRecipientKeyId", "approvalAccessToken", "approvalRecipientKeyId", "approvalKeyId", "authorityEpoch", "expiresAt");
            var approval = String(intent, "approvalAccessToken");
            if (String(intent, "deviceAccessToken") != _token || String(intent, "deviceRecipientKeyId") != _encryptionId ||
                String(intent, "approvalRecipientKeyId") != saved.Claim.EncryptionKeyId || String(intent, "approvalKeyId") != saved.Claim.ApprovalKeyId ||
                intent.GetProperty("authorityEpoch").GetInt32() != 1 || intent.GetProperty("expiresAt").GetInt64() != _expires ||
                approval == _token || approval.Length != 64 || approval.Any(c => !(c is >= '0' and <= '9' or >= 'A' and <= 'F')))
                throw new InvalidDataException("Native activation intent binding.");
            var result = body; body = null;
            return (result, prepared); // Exact saved bytes, never regenerate credentials or serialize new scope on retry.
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
            if (body != null) CryptographicOperations.ZeroMemory(body);
        }
    }

    private static byte[] CanonicalBytes(JsonElement value, string name)
    {
        var text = String(value, name); var bytes = Convert.FromBase64String(text);
        if (Convert.ToBase64String(bytes) == text) return bytes;
        CryptographicOperations.ZeroMemory(bytes);
        throw new InvalidDataException("Noncanonical native activation encoding.");
    }
}
