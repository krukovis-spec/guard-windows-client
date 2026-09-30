using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Guard.Domain;

namespace Guard.Windows.Cryptography;

/// <summary>
/// Off-phone verification of a biometric-per-operation approval key. Roots, APK signer
/// digest and revocation response must come from trusted provisioning, never the claim.
/// This does not consume a setup challenge or authorize enrollment by itself.
/// </summary>
public sealed class AndroidApprovalAttestation
{
    public const string ExtensionOid = "1.3.6.1.4.1.11129.2.1.17";
    private const string ProvisioningOid = "1.3.6.1.4.1.11129.2.1.30";
    private const string PackageName = "app.guard.parent";
    private readonly byte[][] _roots;
    private readonly byte[] _apkSigner;
    private readonly long _minimumAppVersion;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public AndroidApprovalAttestation(IReadOnlyList<byte[]> trustedRoots, byte[] apkSignerSha256, long minimumAppVersion)
    {
        Require(trustedRoots != null && trustedRoots.Count is >= 1 and <= 8);
        Require(apkSignerSha256 != null && apkSignerSha256.Length == 32 && minimumAppVersion > 0);
        _roots = trustedRoots.Select(CopyCertificate).ToArray();
        _apkSigner = (byte[])apkSignerSha256.Clone();
        _minimumAppVersion = minimumAppVersion;
    }

    /// <param name="expectedChallenge">Trusted setup transcript digest, exactly 32 bytes.</param>
    /// <param name="claimHash">Domain-separated canonical claim hash binding all enrollment keys and the setup transcript.</param>
    /// <param name="proofP1363">Proof of possession signed by the attested key after fresh biometrics.</param>
    public bool Verify(ParentTrustAnchor key, IReadOnlyList<byte[]> leafFirst, byte[] expectedChallenge,
        byte[] claimHash, byte[] proofP1363, AndroidAttestationRevocations revocations, DateTimeOffset now)
    {
        var certificates = new List<X509Certificate2>();
        var roots = new List<X509Certificate2>();
        try
        {
            Require(key != null && leafFirst != null && leafFirst.Count is >= 2 and <= 8);
            Require(expectedChallenge != null && expectedChallenge.Length == 32 && claimHash != null && claimHash.Length == 32);
            Require(revocations != null && revocations.IsCurrent(now));
            // Snapshot all caller-owned buffers. No network, certificate-store writes, or AIA lookup.
            var challenge = (byte[])expectedChallenge.Clone();
            Require(proofP1363 != null && proofP1363.Length == 64);
            Require(new EcdsaP256SignatureVerifier().Verify(key, (byte[])claimHash.Clone(), (byte[])proofP1363.Clone()));
            var encoded = leafFirst.Select(CopyCertificate).ToArray();
            Require(encoded.Sum(value => value.Length) <= 64 * 1024);
            foreach (var der in encoded) certificates.Add(LoadExact(der));
            foreach (var der in _roots) roots.Add(LoadExact(der));
            var leaf = certificates[0];
            Require(leaf.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(key.GetSubjectPublicKeyInfoCopy()));
            Require(leaf.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault()?.CertificateAuthority != true);
            Require(leaf.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault()?.KeyUsages == X509KeyUsageFlags.DigitalSignature);

            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(roots.ToArray());
            chain.ChainPolicy.ExtraStore.AddRange(certificates.Skip(1).ToArray());
            chain.ChainPolicy.DisableCertificateDownloads = true;
            // Android publishes a separate JSON status list, checked below for EVERY certificate.
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.VerificationTime = now.UtcDateTime;
            Require(chain.Build(leaf) && chain.ChainElements.Count == certificates.Count);
            for (var i = 0; i < certificates.Count; i++)
            {
                var cert = certificates[i];
                Require(chain.ChainElements[i].Certificate.RawData.AsSpan().SequenceEqual(cert.RawData));
                Require(!revocations.Contains(cert.SerialNumber));
                Require(cert.Extensions.Cast<X509Extension>().Select(extension => extension.Oid?.Value).Distinct().Count() == cert.Extensions.Count);
                Require(cert.SignatureAlgorithm.Value is "1.2.840.113549.1.1.11" or "1.2.840.113549.1.1.12" or "1.2.840.113549.1.1.13"
                    or "1.2.840.10045.4.3.2" or "1.2.840.10045.4.3.3" or "1.2.840.10045.4.3.4");
                // The first attestation from the root must attest THIS approval key, not an
                // ancestor whose holder could append a fake attestation for another key.
                if (i > 0) Require(cert.Extensions[ExtensionOid] == null);
                if (cert.Extensions[ProvisioningOid] != null) Require(i == 1);
            }
            Require(roots.Any(root => root.RawData.AsSpan().SequenceEqual(certificates[^1].RawData)));
            var extension = leaf.Extensions[ExtensionOid];
            Require(extension != null && extension.RawData.Length <= 8192);
            ValidateDescription(extension.RawData, challenge);
            return true;
        }
        catch (Exception error) when (error is ArgumentException or CryptographicException or AsnContentException
            or InvalidOperationException or OverflowException)
        {
            return false;
        }
        finally
        {
            foreach (var certificate in certificates) certificate.Dispose();
            foreach (var root in roots) root.Dispose();
        }
    }

    private void ValidateDescription(byte[] bytes, byte[] challenge)
    {
        var reader = new AsnReader(bytes, AsnEncodingRules.DER);
        var description = reader.ReadSequence(); reader.ThrowIfNotEmpty();
        var version = Integer(description);
        var attestationLevel = description.ReadEnumeratedValue<SecurityLevel>();
        var keyVersion = Integer(description);
        var keyLevel = description.ReadEnumeratedValue<SecurityLevel>();
        Require((version, keyVersion) is (3, 4) or (4, 41) or (100, 100) or (200, 200) or (300, 300) or (400, 400));
        Require(attestationLevel is SecurityLevel.TrustedEnvironment or SecurityLevel.StrongBox
            && keyLevel is SecurityLevel.TrustedEnvironment or SecurityLevel.StrongBox);
        Require(CryptographicOperations.FixedTimeEquals(description.ReadOctetString(), challenge));
        Require(description.ReadOctetString().Length == 0); // We do not request device-unique identification.
        var software = Authorizations(description.ReadSequence());
        var hardware = Authorizations(description.ReadSequence());
        description.ThrowIfNotEmpty();

        foreach (var tag in new[] { 1, 2, 3, 5, 10, 504, 702, 704 }) Require(!software.ContainsKey(tag));
        foreach (var tag in new[] { 503, 505, 506, 600, 601 }) Require(!software.ContainsKey(tag) && !hardware.ContainsKey(tag));
        Require(!hardware.ContainsKey(709));
        Require(SingleIntegerSet(hardware, 1) == 2); // SIGN only; no ATTEST_KEY/AGREE_KEY/etc.
        Require(ReadInteger(hardware, 2) == 3 && ReadInteger(hardware, 3) == 256 && ReadInteger(hardware, 10) == 1);
        Require(SingleIntegerSet(hardware, 5) == 4); // SHA-256 only.
        Require(ReadInteger(hardware, 504) == 2); // Biometric only, no PASSWORD bit or ANY.
        // AUTH_TIMEOUT must be absent, even zero is a timeout-key rather than per-operation.
        Require(ReadInteger(hardware, 702) == 0); // GENERATED, not imported.
        Require(ReadInteger(hardware, 705) >= 120000); // Android 12 is this client's minimum.
        ValidateBoot(Field(hardware, 704));
        var app = Field(software, 709);
        var appBytes = app.ReadOctetString(); app.ThrowIfNotEmpty();
        ValidateApp(appBytes);
    }

    private void ValidateApp(byte[] bytes)
    {
        var reader = new AsnReader(bytes, AsnEncodingRules.DER);
        var app = reader.ReadSequence(); reader.ThrowIfNotEmpty();
        var packages = app.ReadSetOf(); var package = packages.ReadSequence(); packages.ThrowIfNotEmpty();
        Require(Utf8.GetString(package.ReadOctetString()) == PackageName);
        Require(Integer(package) >= _minimumAppVersion); package.ThrowIfNotEmpty();
        var digests = app.ReadSetOf();
        Require(CryptographicOperations.FixedTimeEquals(digests.ReadOctetString(), _apkSigner));
        digests.ThrowIfNotEmpty(); app.ThrowIfNotEmpty();
    }

    private static void ValidateBoot(AsnReader field)
    {
        var boot = field.ReadSequence(); field.ThrowIfNotEmpty();
        var bootKey = boot.ReadOctetString(); Require(bootKey.Length is 32 or 64 && bootKey.Any(value => value != 0));
        Require(boot.ReadBoolean() && boot.ReadEnumeratedValue<BootState>() == BootState.Verified);
        var hash = boot.ReadOctetString(); Require(hash.Length is 32 or 64 && hash.Any(value => value != 0));
        boot.ThrowIfNotEmpty();
    }

    private static Dictionary<int, ReadOnlyMemory<byte>> Authorizations(AsnReader list)
    {
        var result = new Dictionary<int, ReadOnlyMemory<byte>>(); var previous = -1;
        while (list.HasData)
        {
            var tag = list.PeekTag();
            Require(tag.TagClass == TagClass.ContextSpecific && tag.IsConstructed && tag.TagValue > previous && result.Count < 64);
            previous = tag.TagValue;
            // Known KeyMint authorization schema. Unknown semantics require an explicit update.
            Require(tag.TagValue is 1 or 2 or 3 or 4 or 5 or 6 or 7 or 8 or 10 or 200 or 203 or 303 or 305
                or 400 or 401 or 402 or 405 or 502 or 503 or 504 or 505 or 506 or 507 or 508 or 509 or 600 or 601
                or 701 or 702 or 703 or 704 or 705 or 706 or 709 or 710 or 711 or 712 or 713 or 714 or 715 or 716
                or 717 or 718 or 719 or 720 or 723 or 724);
            var explicitValue = list.ReadSequence(tag);
            result.Add(tag.TagValue, explicitValue.ReadEncodedValue()); explicitValue.ThrowIfNotEmpty();
        }
        return result;
    }

    private static AsnReader Field(Dictionary<int, ReadOnlyMemory<byte>> fields, int tag)
    {
        Require(fields.TryGetValue(tag, out var value)); return new AsnReader(value, AsnEncodingRules.DER);
    }
    private static long ReadInteger(Dictionary<int, ReadOnlyMemory<byte>> fields, int tag)
    {
        var reader = Field(fields, tag); var value = Integer(reader); reader.ThrowIfNotEmpty(); return value;
    }
    private static long SingleIntegerSet(Dictionary<int, ReadOnlyMemory<byte>> fields, int tag)
    {
        var reader = Field(fields, tag); var set = reader.ReadSetOf(); reader.ThrowIfNotEmpty();
        var value = Integer(set); set.ThrowIfNotEmpty(); return value;
    }
    private static long Integer(AsnReader reader)
    {
        var value = reader.ReadInteger(); Require(value >= 0 && value <= long.MaxValue); return (long)value;
    }
    private static byte[] CopyCertificate(byte[] bytes)
    {
        Require(bytes != null && bytes.Length is > 0 and <= 16384); return (byte[])bytes.Clone();
    }
    private static X509Certificate2 LoadExact(byte[] bytes)
    {
        var reader = new AsnReader(bytes, AsnEncodingRules.DER);
        reader.ReadSequence(); reader.ThrowIfNotEmpty();
        var certificate = X509CertificateLoader.LoadCertificate(bytes);
        if (!certificate.RawData.AsSpan().SequenceEqual(bytes)) { certificate.Dispose(); throw new ArgumentException("certificate encoding"); }
        return certificate;
    }
    private static void Require([DoesNotReturnIf(false)] bool condition) { if (!condition) throw new ArgumentException("Android approval attestation rejected."); }
    private enum SecurityLevel { Software = 0, TrustedEnvironment = 1, StrongBox = 2 }
    private enum BootState { Verified = 0, SelfSigned = 1, Unverified = 2, Failed = 3 }
}

/// <summary>Bounded Google status response from trusted HTTPS; parsing does not authenticate its source.</summary>
public sealed class AndroidAttestationRevocations
{
    private readonly HashSet<string> _serials;
    private readonly DateTimeOffset _fetchedAt;
    private readonly DateTimeOffset _validUntil;

    private AndroidAttestationRevocations(HashSet<string> serials, DateTimeOffset fetchedAt, DateTimeOffset validUntil)
    { _serials = serials; _fetchedAt = fetchedAt; _validUntil = validUntil; }

    /// <summary>Caller must honor HTTP Cache-Control and authenticate android.googleapis.com; never use claim-supplied data/times.</summary>
    public static AndroidAttestationRevocations FromTrustedResponse(byte[] json, DateTimeOffset fetchedAt, DateTimeOffset validUntil)
    {
        if (json == null || json.Length is 0 or > 1024 * 1024 || validUntil <= fetchedAt || validUntil - fetchedAt > TimeSpan.FromHours(24))
            throw new ArgumentException("Invalid attestation status response.");
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 5 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 1 || !root.TryGetProperty("entries", out var entries)
            || entries.ValueKind != JsonValueKind.Object) throw new ArgumentException("Invalid attestation status entries.");
        var serials = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries.EnumerateObject())
        {
            if (serials.Count >= 10000 || entry.Name.Length is 0 or > 64 || entry.Name[0] == '0'
                || entry.Name.Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f')) || !serials.Add(entry.Name)
                || entry.Value.ValueKind != JsonValueKind.Object) throw new ArgumentException("Invalid attestation status serial.");
            var properties = new HashSet<string>(StringComparer.Ordinal); var statusFound = false;
            foreach (var property in entry.Value.EnumerateObject())
            {
                if (!properties.Add(property.Name) || property.Value.ValueKind != JsonValueKind.String
                    || property.Name is not ("status" or "expires" or "reason" or "comment")) throw new ArgumentException("Invalid attestation status field.");
                if (property.Name == "status")
                {
                    if (property.Value.GetString() is not ("REVOKED" or "SUSPENDED")) throw new ArgumentException("Unknown attestation status.");
                    statusFound = true;
                }
            }
            if (!statusFound) throw new ArgumentException("Missing attestation status.");
        }
        return new AndroidAttestationRevocations(serials, fetchedAt, validUntil);
    }
    internal bool IsCurrent(DateTimeOffset now) => now >= _fetchedAt && now < _validUntil;
    internal bool Contains(string serial) => _serials.Contains(serial.TrimStart('0'));
}
