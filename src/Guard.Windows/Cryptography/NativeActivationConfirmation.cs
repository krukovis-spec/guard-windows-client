using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Guard.Contracts;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Protocol.Relay;

namespace Guard.Windows.Cryptography;

// Public, signed evidence of a committed INITIAL binding. Not a transport credential,
// application permission, readiness result or attestation supplied by the relay.
public sealed class NativeActivationConfirmation
{
    public const int MaximumBytes = 8192;
    private static readonly byte[] Domain = Encoding.ASCII.GetBytes("Guard.v2.native-activation.v1");
    private readonly byte[] _bytes;
    public EnrollmentOffer Offer { get; }
    public EnrollmentKeyClaim Claim { get; }
    public long StateVersion { get; }
    public DateTimeOffset IssuedAtUtc { get; }
    public DateTimeOffset ExpiresAtUtc { get; }
    public string Sha256 => Convert.ToHexString(SHA256.HashData(_bytes));

    private NativeActivationConfirmation(byte[] raw, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(raw);
        if (raw.Length < 73 || raw.Length > MaximumBytes || !raw.AsSpan(0, 4).SequenceEqual("GNA1"u8) ||
            BinaryPrimitives.ReadInt32BigEndian(raw.AsSpan(4, 4)) != raw.Length - 72)
            throw new InvalidDataException("Native activation envelope.");
        _bytes = (byte[])raw.Clone();
        using var document = JsonDocument.Parse(_bytes.AsMemory(8, _bytes.Length - 72), new JsonDocumentOptions { MaxDepth = 2 });
        var value = document.RootElement;
        var fields = new HashSet<string>(new[] { "version", "offer", "claim", "stateVersion", "issuedAt", "expiresAt" }, StringComparer.Ordinal);
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Native activation object.");
        foreach (var field in value.EnumerateObject())
            if (!fields.Remove(field.Name)) throw new InvalidDataException("Unexpected native activation field.");
        if (fields.Count != 0) throw new InvalidDataException("Missing native activation field.");
        if (value.GetProperty("version").GetInt32() != 1) throw new InvalidDataException("Native activation version.");
        Offer = RelayCanonicalEncoding.DecodeEnrollmentOffer(Bytes(value, "offer"));
        Claim = RelayCanonicalEncoding.DecodeEnrollmentClaimForSignature(Bytes(value, "claim"));
        StateVersion = value.GetProperty("stateVersion").GetInt64();
        IssuedAtUtc = DateTimeOffset.FromUnixTimeMilliseconds(value.GetProperty("issuedAt").GetInt64());
        ExpiresAtUtc = DateTimeOffset.FromUnixTimeMilliseconds(value.GetProperty("expiresAt").GetInt64());
        RequireCurrent(now);
        if (StateVersion < 1 || Offer.DeviceEpoch != 1 || Offer.AuthorityEpoch != 1 ||
            !CryptographicOperations.FixedTimeEquals(Claim.GetOfferHashCopy(), RelayCanonicalEncoding.ComputeEnrollmentOfferHash(Offer)))
            throw new InvalidDataException("Native activation binding.");
        using var signing = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = Point(Offer.GetSigningKeyCopy()) });
        using var deviceEncryption = ECDiffieHellman.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = Point(Offer.GetEncryptionKeyCopy()) });
        using var phoneEncryption = ECDiffieHellman.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = Point(Claim.GetEncryptionKeyCopy()) });
        var approval = new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, Claim.GetApprovalKeyCopy());
        if (new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, signing.ExportSubjectPublicKeyInfo()).KeyId != Offer.SigningKeyId ||
            new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, deviceEncryption.ExportSubjectPublicKeyInfo()).KeyId != Offer.EncryptionKeyId ||
            approval.KeyId != Claim.ApprovalKeyId || !new EcdsaP256SignatureVerifier().IsValid(approval) ||
            new[] { Offer.SigningKeyId, Offer.EncryptionKeyId, Claim.ApprovalKeyId, Claim.EncryptionKeyId }.Distinct(StringComparer.Ordinal).Count() != 4 ||
            new[] { Offer.GetSigningKeyCopy(), Offer.GetEncryptionKeyCopy(), Claim.GetApprovalKeyCopy()[26..], Claim.GetEncryptionKeyCopy() }
                .Select(Convert.ToHexString).Distinct(StringComparer.Ordinal).Count() != 4 ||
            !signing.VerifyData(Input(_bytes.AsSpan(0, _bytes.Length - 64).ToArray()), _bytes.AsSpan(_bytes.Length - 64),
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            throw new InvalidDataException("Native activation signature or keys.");
    }

    public static NativeActivationConfirmation Create(DeviceSecurityState state, ECDsa signingKey, DateTimeOffset now)
    {
        if (!state.IsProvisioned || state.Enrollment is not { Confirmed: true, Candidate: not null } session)
            throw new InvalidOperationException("Committed native enrollment required.");
        var expires = now.AddMinutes(10);
        if (expires > session.Offer.ExpiresAtUtc.AddDays(1)) expires = session.Offer.ExpiresAtUtc.AddDays(1);
        var payload = JsonSerializer.SerializeToUtf8Bytes(new { version = 1,
            offer = Convert.ToBase64String(RelayCanonicalEncoding.EncodeEnrollmentOffer(session.Offer)),
            claim = Convert.ToBase64String(RelayCanonicalEncoding.EncodeEnrollmentClaimForSignature(session.Candidate)),
            stateVersion = state.Version, issuedAt = now.ToUnixTimeMilliseconds(), expiresAt = expires.ToUnixTimeMilliseconds() });
        if (payload.Length > MaximumBytes - 72) throw new InvalidDataException("Native activation size.");
        var raw = new byte[payload.Length + 72]; "GNA1"u8.CopyTo(raw);
        BinaryPrimitives.WriteInt32BigEndian(raw.AsSpan(4), payload.Length); payload.CopyTo(raw, 8);
        lock (signingKey) signingKey.SignData(Input(raw.AsSpan(0, raw.Length - 64).ToArray()), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation).CopyTo(raw, raw.Length - 64);
        return new NativeActivationConfirmation(raw, now); // Validate the actual signed bytes, including device key/time binding.
    }

    // The caller must already trust the descriptor independently (e.g. its saved off-PC provisioning job).
    // Never construct that trust from the offer embedded in this file.
    public static NativeActivationConfirmation Verify(byte[] raw, DeviceProvisioningDescriptor trustedDevice,
        string expectedMailbox, DateTimeOffset now)
    {
        var result = new NativeActivationConfirmation(raw, now);
        var offer = result.Offer;
        if (offer.RelayEndpoint != trustedDevice.RelayOrigin || offer.DeviceId != trustedDevice.DeviceId || offer.MailboxId != expectedMailbox ||
            offer.SigningKeyId != trustedDevice.SigningKeyId || offer.EncryptionKeyId != trustedDevice.EncryptionKeyId ||
            !offer.GetSigningKeyCopy().AsSpan().SequenceEqual(trustedDevice.GetSigningKeyCopy().AsSpan(26)) ||
            !offer.GetEncryptionKeyCopy().AsSpan().SequenceEqual(trustedDevice.GetEncryptionKeyCopy().AsSpan(26)))
            throw new InvalidDataException("Independently trusted device mismatch.");
        return result;
    }

    // Only the authenticated SCM/SYSTEM query client is an authority for this UI path.
    internal static NativeActivationConfirmation FromAuthenticatedService(byte[] raw, DateTimeOffset now) => new(raw, now);
    public void RequireCurrent(DateTimeOffset now)
    {
        if (IssuedAtUtc < Offer.CreatedAtUtc || ExpiresAtUtc <= IssuedAtUtc || ExpiresAtUtc - IssuedAtUtc > TimeSpan.FromMinutes(10) ||
            ExpiresAtUtc > Offer.ExpiresAtUtc.AddDays(1) || now < IssuedAtUtc || now >= ExpiresAtUtc)
            throw new InvalidDataException("Native activation expired or clock invalid.");
    }
    public byte[] GetBytesCopy() => (byte[])_bytes.Clone();
    public void SaveNew(string path, DateTimeOffset now) { RequireCurrent(now); DeviceProvisioningDescriptor.SaveNewPublicFile(path, _bytes); }
    private static byte[] Input(byte[] signed) => Domain.Concat(signed).ToArray();
    private static ECPoint Point(byte[] raw) => new() { X = raw[1..33], Y = raw[33..65] };
    private static byte[] Bytes(JsonElement value, string field)
    {
        var text = value.GetProperty(field).GetString() ?? throw new InvalidDataException("Native activation field.");
        var bytes = Convert.FromBase64String(text);
        if (Convert.ToBase64String(bytes) != text) throw new InvalidDataException("Noncanonical activation field.");
        return bytes;
    }
}
