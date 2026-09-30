using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Domain;
using Guard.Storage;
using Guard.Windows.Cryptography;
using Guard.Windows.Storage;

namespace Guard.Service;

// Service-owned keys, never part of an IPC response or the public authoritative-state model.
internal sealed class DeviceIdentity : IDisposable
{
    internal DeviceIdentity(string deviceId, ECDsa signing, ECDiffieHellman encryption)
    {
        if (!GuardIdentifier.IsCanonicalToken(deviceId)) throw new InvalidDataException("Invalid device identity.");
        var sign = new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, signing.ExportSubjectPublicKeyInfo());
        var enc = new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, encryption.ExportSubjectPublicKeyInfo());
        var verifier = new EcdsaP256SignatureVerifier();
        if (!verifier.IsValid(sign) || !verifier.IsValid(enc) || sign.KeyId == enc.KeyId)
            throw new InvalidDataException("Device keys must be distinct P-256 keys.");
        DeviceId = deviceId; Signing = signing; Encryption = encryption;
        SigningKeyId = sign.KeyId; EncryptionKeyId = enc.KeyId;
    }

    internal string DeviceId { get; }
    internal string SigningKeyId { get; }
    internal string EncryptionKeyId { get; }
    internal ECDsa Signing { get; }
    internal ECDiffieHellman Encryption { get; }
    internal byte[] SigningPoint => Signing.ExportSubjectPublicKeyInfo()[26..];
    internal byte[] EncryptionPoint => Encryption.ExportSubjectPublicKeyInfo()[26..];

    internal void RequireMatches(DeviceSecurityState state)
    {
        var offer = state.Enrollment?.Offer;
        if (state.DeviceId != DeviceId || (offer != null &&
            (offer.SigningKeyId != SigningKeyId || offer.EncryptionKeyId != EncryptionKeyId ||
             !offer.GetSigningKeyCopy().AsSpan().SequenceEqual(SigningPoint) ||
             !offer.GetEncryptionKeyCopy().AsSpan().SequenceEqual(EncryptionPoint))))
            throw new InvalidDataException("Stored device keys do not match authoritative state.");
    }

    public void Dispose() { Signing.Dispose(); Encryption.Dispose(); }
}

/// <summary>Immutable, purpose-separated DPAPI record. Caller holds the authoritative writer lease.</summary>
internal sealed class DeviceIdentityStore(GuardDataPaths paths, IStateDataProtector protector, IServiceDataBoundaryGuard boundary)
{
    internal const string Purpose = "guard-v2-device-identity-v1";
    internal const int MaximumPlaintextBytes = 1200, MaximumFileBytes = 4096;
    private readonly ProtectedServiceRecord _record = new(paths.DeviceIdentityFile, paths.DeviceIdentityPendingFile,
        protector, boundary, MaximumPlaintextBytes, MaximumFileBytes);

    internal DeviceIdentity Load()
    {
        var plaintext = _record.Read();
        DeviceIdentity? identity = null;
        try
        {
            identity = Decode(plaintext);
            boundary.DemandReady();
            return identity;
        }
        catch { identity?.Dispose(); throw; }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    internal async Task<DeviceIdentity> InitializeOrResumeNewAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        boundary.DemandReady();
        // Never initialize missing keys for an existing device, even one without a parent yet.
        if (File.Exists(paths.StateFile) || File.Exists(paths.StateBackupFile) || File.Exists(paths.JournalFile))
            throw new InvalidOperationException("Device identity initialization requires absent authoritative state.");
        if (File.Exists(paths.DeviceIdentityPendingFile))
            throw new InvalidDataException("Interrupted device identity publication requires recovery.");
        // A complete key record may precede state after a power cut. Reuse it; never rotate it.
        if (File.Exists(paths.DeviceIdentityFile)) return Load();

        using var signing = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var encryption = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var deviceId = "device-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var plaintext = Encode(deviceId, signing, encryption);
        try { await _record.PublishNewAsync(plaintext, cancellationToken).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
        return Load();
    }

    // ponytail: one immutable record, no second journal/rotation protocol; replacement requires explicit recovery.
    private static byte[] Encode(string deviceId, ECDsa signing, ECDiffieHellman encryption)
    {
        var sign = signing.ExportPkcs8PrivateKey();
        byte[]? enc = null;
        try
        {
            enc = encryption.ExportPkcs8PrivateKey();
            var id = Encoding.ASCII.GetBytes(deviceId);
            var raw = new byte[16 + id.Length + sign.Length + enc.Length];
            "GDK1"u8.CopyTo(raw);
            var at = 4;
            Put(id); Put(sign); Put(enc);
            return raw;
            void Put(byte[] value)
            {
                BinaryPrimitives.WriteInt32BigEndian(raw.AsSpan(at, 4), value.Length); at += 4;
                value.CopyTo(raw, at); at += value.Length;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sign);
            if (enc != null) CryptographicOperations.ZeroMemory(enc);
        }
    }

    private static DeviceIdentity Decode(byte[] raw)
    {
        if (raw.Length < 16 || raw.Length > MaximumPlaintextBytes || !raw.AsSpan(0, 4).SequenceEqual("GDK1"u8))
            throw new InvalidDataException("Device identity format.");
        var at = 4;
        var idBytes = Field(GuardIdentifier.MaximumCharacters);
        foreach (var value in idBytes) if (value > 127) throw new InvalidDataException("Device identity encoding.");
        var id = Encoding.ASCII.GetString(idBytes);
        var signBytes = Field(512); var encBytes = Field(512);
        if (at != raw.Length) throw new InvalidDataException("Trailing device identity data.");
        var signing = ECDsa.Create();
        ECDiffieHellman? encryption = null;
        try
        {
            signing.ImportPkcs8PrivateKey(signBytes, out var signRead);
            encryption = ECDiffieHellman.Create();
            encryption.ImportPkcs8PrivateKey(encBytes, out var encRead);
            if (signRead != signBytes.Length || encRead != encBytes.Length)
                throw new InvalidDataException("Trailing private key data.");
            return new DeviceIdentity(id, signing, encryption);
        }
        catch { signing.Dispose(); encryption?.Dispose(); throw; }
        ReadOnlySpan<byte> Field(int maximum)
        {
            if (raw.Length - at < 4) throw new InvalidDataException("Truncated device identity.");
            var n = BinaryPrimitives.ReadInt32BigEndian(raw.AsSpan(at, 4)); at += 4;
            if (n < 1 || n > maximum || n > raw.Length - at) throw new InvalidDataException("Device identity field size.");
            var value = raw.AsSpan(at, n); at += n; return value;
        }
    }
}
