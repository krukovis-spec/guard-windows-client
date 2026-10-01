using System;
using System.IO;
using System.Security.Cryptography;
using Guard.Domain;
using Guard.Storage;

namespace Guard.Windows.Cryptography;

// Confidential installer handoff, NOT proof of the sender/ownership. Only the trusted installer may stage it.
// The service still validates the complete inner profile against its compiled pins and pristine identity.
public sealed class DeviceRelayProfileEnvelope(ECDiffieHellman recipient) : IStateDataProtector
{
    public const int MaximumPlaintextBytes = 4096;
    public const int MaximumFileBytes = 4 + 32 + 65 + MaximumPlaintextBytes + 16;
    private static ReadOnlySpan<byte> Info => "Guard.v2.device-relay.install.hpke.v1"u8;

    public static byte[] Seal(byte[] recipientSpki, byte[] plaintext)
    {
        if (plaintext.Length < 1 || plaintext.Length > MaximumPlaintextBytes)
            throw new InvalidDataException("Device profile size.");
        var anchor = new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, recipientSpki);
        if (!new EcdsaP256SignatureVerifier().IsValid(anchor)) throw new InvalidDataException("Device encryption key.");
        var header = new byte[36]; "GDI1"u8.CopyTo(header); SHA256.HashData(recipientSpki).CopyTo(header, 4);
        var cipher = RelayCryptography.Encrypt(recipientSpki[26..], plaintext, header, Info.ToArray(), out var enc);
        var result = new byte[header.Length + enc.Length + cipher.Length];
        header.CopyTo(result, 0); enc.CopyTo(result, header.Length); cipher.CopyTo(result, header.Length + enc.Length);
        return result;
    }

    public byte[] Protect(byte[] plaintext) => Seal(recipient.ExportSubjectPublicKeyInfo(), plaintext);

    public byte[] Unprotect(byte[] ciphertext)
    {
        if (ciphertext.Length < 118 || ciphertext.Length > MaximumFileBytes || !ciphertext.AsSpan(0, 4).SequenceEqual("GDI1"u8))
            throw new InvalidDataException("Device profile envelope.");
        var spki = recipient.ExportSubjectPublicKeyInfo();
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(spki), ciphertext.AsSpan(4, 32)))
            throw new InvalidDataException("Device profile recipient.");
        var key = recipient.ExportParameters(true);
        try { return RelayCryptography.Decrypt(key.D!, spki[26..], ciphertext[36..101], ciphertext[101..],
            ciphertext[..36], Info.ToArray()); }
        finally { if (key.D != null) CryptographicOperations.ZeroMemory(key.D); }
    }
}
