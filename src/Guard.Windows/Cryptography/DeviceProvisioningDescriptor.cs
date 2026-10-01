using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using Guard.Contracts;
using Guard.Domain;
using Guard.Protocol.Relay;

namespace Guard.Windows.Cryptography;

// Public data, not an ownership proof. Parse only after authenticating the service
// (setup UI), or checking its exact digest AND an independently pinned origin (operator).
public sealed class DeviceProvisioningDescriptor
{
    private readonly byte[] _bytes, _signingSpki, _encryptionSpki;
    public string RelayOrigin { get; }
    public string DeviceId { get; }
    public string SigningKeyId { get; }
    public string EncryptionKeyId { get; }
    public string Sha256 { get; }

    private DeviceProvisioningDescriptor(byte[] bytes)
    {
        _bytes = bytes;
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 3 });
        var value = document.RootElement;
        var names = new HashSet<string>(new[] { "version", "relayOrigin", "deviceId", "signingKeyId", "signingPublicKeySpki",
            "encryptionKeyId", "encryptionPublicKeySpki", "deviceEpoch", "authorityEpoch" }, StringComparer.Ordinal);
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Device descriptor object required.");
        foreach (var field in value.EnumerateObject())
            if (!names.Remove(field.Name)) throw new InvalidDataException("Unexpected device descriptor field.");
        if (names.Count != 0 || value.GetProperty("version").GetInt32() != 1 ||
            value.GetProperty("deviceEpoch").GetInt64() != 1 || value.GetProperty("authorityEpoch").GetInt64() != 1)
            throw new InvalidDataException("Device descriptor version/epoch.");
        RelayOrigin = Text(value, "relayOrigin");
        RelayCanonicalEncoding.RequireEnrollmentRelay(RelayOrigin);
        if (RelayOrigin != new Uri(RelayOrigin, UriKind.Absolute).GetLeftPart(UriPartial.Authority))
            throw new InvalidDataException("Device descriptor origin.");
        DeviceId = Id(Text(value, "deviceId"));
        SigningKeyId = Id(Text(value, "signingKeyId")); EncryptionKeyId = Id(Text(value, "encryptionKeyId"));
        _signingSpki = PublicKey(Text(value, "signingPublicKeySpki"), SigningKeyId);
        _encryptionSpki = PublicKey(Text(value, "encryptionPublicKeySpki"), EncryptionKeyId);
        if (SigningKeyId == EncryptionKeyId) throw new InvalidDataException("Device key roles overlap.");
        Sha256 = Convert.ToHexString(SHA256.HashData(bytes));
    }

    public static DeviceProvisioningDescriptor Parse(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length is < 1 or > 2048) throw new InvalidDataException("Device descriptor size.");
        return new DeviceProvisioningDescriptor((byte[])bytes.Clone());
    }

    public byte[] GetEncryptionKeyCopy() => (byte[])_encryptionSpki.Clone();
    public byte[] GetSigningKeyCopy() => (byte[])_signingSpki.Clone();
    public byte[] GetBytesCopy() => (byte[])_bytes.Clone();

    // Never replace an existing file, including after a failed/partial write.
    // No shell, redirected folders, network paths, or alternate data streams.
    public void SaveNew(string path) => SaveNewPublicFile(path, _bytes);
    internal static void SaveNewPublicFile(string path, byte[] bytes)
    {
        if (!Path.IsPathFullyQualified(path)) throw new IOException("Absolute local file required.");
        // GetFullPath silently trims trailing dots/spaces on Windows; validate before normalization.
        foreach (var segment in path.Split('\\', '/'))
            if (segment.EndsWith('.') || segment.EndsWith(' ')) throw new IOException("Ambiguous export path.");
        var full = Path.GetFullPath(path);
        if (full.Length < 4 || full[1] != ':' || full[2] != '\\' || full[2..].Contains(':'))
            throw new IOException("Local file required.");
        for (FileSystemInfo? item = new FileInfo(full); item != null;
             item = item is FileInfo file ? file.Directory : ((DirectoryInfo)item).Parent)
            if (item.Name.EndsWith('.') || item.Name.EndsWith(' ') ||
                item.Exists && (item.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Redirected or ambiguous export path.");
        using var output = new FileStream(full, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        output.Write(bytes); output.Flush(flushToDisk: true);
    }

    private static string Text(JsonElement value, string name) => value.GetProperty(name).GetString() ?? throw new InvalidDataException("Missing string.");
    private static string Id(string value) => GuardIdentifier.IsCanonicalToken(value) ? value : throw new InvalidDataException("Identifier.");
    private static byte[] PublicKey(string encoded, string id)
    {
        var spki = Convert.FromBase64String(encoded);
        var anchor = new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, spki);
        if (Convert.ToBase64String(spki) != encoded || anchor.KeyId != id || !new EcdsaP256SignatureVerifier().IsValid(anchor))
            throw new InvalidDataException("Public device key binding.");
        return spki;
    }
}
