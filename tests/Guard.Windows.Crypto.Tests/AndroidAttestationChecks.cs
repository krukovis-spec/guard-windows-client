using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Guard.Domain;
using Guard.Windows.Cryptography;

namespace Guard.Windows.Crypto.Tests;

internal static class AndroidAttestationChecks
{
    private static readonly DateTimeOffset Now = new(2026, 9, 30, 12, 0, 0, TimeSpan.Zero);
    private static readonly byte[] Challenge = SHA256.HashData("test setup transcript"u8);
    private static readonly byte[] ClaimHash = SHA256.HashData("test domain-separated enrollment claim"u8);
    private static readonly byte[] ApkSigner = SHA256.HashData("public synthetic APK signer"u8);

    internal static void Run()
    {
        using var fixture = new Fixture();
        Check(fixture.Verify(Description()), "valid TEE approval attestation rejected");
        Check(fixture.Verify(Description(level: 2)), "valid StrongBox approval attestation rejected");
        Check(fixture.Verify(Description(keyLevel: 2)), "hardware-backed attestation with StrongBox key rejected");
        Check(fixture.Verify(Description(version: 4, keyVersion: 41)), "supported Keymaster 4.1 rejected");

        var bad = new Dictionary<string, byte[]>
        {
            ["software key"] = Description(level: 0),
            ["software key with hardware attestation"] = Description(keyLevel: 0),
            ["unknown version"] = Description(version: 999),
            ["wrong key version"] = Description(keyVersion: 4),
            ["challenge"] = Description(challenge: new byte[32]),
            ["password fallback"] = Description(authType: 3),
            ["password only"] = Description(authType: 1),
            ["ANY authentication"] = Description(authType: uint.MaxValue),
            ["cached auth"] = Description(extraHardware: (505, Number(60))),
            ["zero timeout"] = Description(extraHardware: (505, Number(0))),
            ["no auth"] = Description(extraHardware: (503, Null())),
            ["on body auth"] = Description(extraHardware: (506, Null())),
            ["software enforced auth"] = Description(softwareAuth: true),
            ["software bypass"] = Description(extraSoftware: (503, Null())),
            ["shared applications"] = Description(extraSoftware: (600, Null())),
            ["imported key"] = Description(origin: 2),
            ["wrong purpose"] = Description(purpose: 7),
            ["multiple purposes"] = Description(extraHardware: (1, Set(Number(2), Number(7))), replaceHardware: true),
            ["wrong digest"] = Description(extraHardware: (5, Set(Number(2))), replaceHardware: true),
            ["unlocked bootloader"] = Description(locked: false),
            ["unverified boot"] = Description(bootState: 2),
            ["another package"] = Description(packageName: "app.other.parent"),
            ["another APK signer"] = Description(signer: new byte[32]),
            ["old app version"] = Description(appVersion: 0),
            ["extra shared UID package"] = Description(sharedUid: true),
            ["old Android"] = Description(osVersion: 110000),
            ["unknown authorization"] = Description(extraHardware: (999, Number(1))),
            ["duplicate authorization"] = Description(extraHardware: (504, Number(2))),
            ["trailing DER"] = Description().Concat(new byte[] { 0 }).ToArray(),
            ["empty DER"] = Array.Empty<byte>(),
            ["truncated DER"] = Description()[..^1]
        };
        foreach (var item in bad) Check(!fixture.Verify(item.Value), "accepted " + item.Key);

        var good = fixture.Chain(Description());
        Check(!fixture.Verifier.Verify(fixture.Anchor, good, new byte[32], ClaimHash, fixture.Proof, fixture.Status, Now), "different expected challenge");
        Check(!fixture.Verifier.Verify(fixture.Anchor, good, Challenge, new byte[32], fixture.Proof, fixture.Status, Now), "different claim");
        Check(!fixture.Verifier.Verify(fixture.Anchor, good, Challenge, ClaimHash, new byte[64], fixture.Status, Now), "missing possession proof");
        using var stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var other = new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, stranger.ExportSubjectPublicKeyInfo());
        Check(!fixture.Verifier.Verify(other, good, Challenge, ClaimHash, stranger.SignHash(ClaimHash), fixture.Status, Now), "different attested key");
        foreach (var index in Enumerable.Range(0, good.Length))
        {
            var altered = good.Select(bytes => (byte[])bytes.Clone()).ToArray(); altered[index][^1] ^= 1;
            Check(!fixture.Check(altered), "broken chain signature " + index);
            using var cert = X509CertificateLoader.LoadCertificate(good[index]);
            var serial = cert.SerialNumber.TrimStart('0').ToLowerInvariant();
            var status = Status("{\"entries\":{\"" + serial + "\":{\"status\":\"SUSPENDED\"}}}");
            Check(!fixture.Check(good, status), "revoked chain certificate " + index);
        }
        Check(!fixture.Check(good.Reverse().ToArray()), "reordered chain");
        Check(!fixture.Check(good.Concat(new[] { good[^1] }).ToArray()), "extra certificate");
        Check(!fixture.Check(new[] { good[0] }), "incomplete chain");
        Check(!fixture.Check(new[] { new byte[16385], good[1], good[2] }), "oversize certificate");
        Check(!fixture.Check(new[] { good[0].Concat(new byte[] { 0 }).ToArray(), good[1], good[2] }), "trailing certificate bytes");
        Check(!fixture.Check(fixture.Chain(Description(), intermediateAttestation: true)), "attestation hidden in ancestor");
        Check(!fixture.Check(fixture.Chain(Description(), expired: true)), "expired certificate");
        using var untrusted = new Fixture();
        Check(!fixture.Verifier.Verify(untrusted.Anchor, untrusted.Chain(Description()), Challenge, ClaimHash, untrusted.Proof, fixture.Status, Now), "untrusted root");
        var stale = AndroidAttestationRevocations.FromTrustedResponse("{\"entries\":{}}"u8.ToArray(), Now.AddHours(-2), Now);
        Check(!fixture.Check(good, stale), "expired status cache");
        Check(!fixture.Verifier.Verify(fixture.Anchor, good, Challenge, ClaimHash, fixture.Proof, fixture.Status, Now.AddMinutes(-2)), "clock before status fetch");

        foreach (var json in new[] { "{}", "[]", "{\"entries\":{},\"entries\":{}}", "{\"entries\":[]}",
            "{\"entries\":{\"01\":{\"status\":\"REVOKED\"}}}", "{\"entries\":{\"1\":{}}}",
            "{\"entries\":{\"1\":{\"status\":\"GOOD\"}}}", "{\"entries\":{\"1\":{\"status\":\"REVOKED\",\"status\":\"SUSPENDED\"}}}",
            "{\"entries\":{\"1\":{\"status\":\"REVOKED\"},\"1\":{\"status\":\"REVOKED\"}}}" })
            Throws(() => Status(json));
        Throws(() => AndroidAttestationRevocations.FromTrustedResponse("{\"entries\":{}}"u8.ToArray(), Now, Now.AddDays(2)));
        Throws(() => AndroidAttestationRevocations.FromTrustedResponse(new byte[1024 * 1024 + 1], Now, Now.AddHours(1)));
        Console.WriteLine($"PASS Android attestation: real synthetic certificate chains, {bad.Count} property/DER rejection cases, trust/proof/revocation/expiry/limits");
    }

    private static byte[] Description(int level = 1, int version = 100, int keyVersion = 100, int? keyLevel = null, byte[]? challenge = null,
        long authType = 2, bool softwareAuth = false, int purpose = 2, int origin = 0, int osVersion = 120000,
        bool locked = true, int bootState = 0, string packageName = "app.guard.parent", byte[]? signer = null, int appVersion = 1,
        bool sharedUid = false, (int Tag, byte[] Value)? extraHardware = null, (int Tag, byte[] Value)? extraSoftware = null, bool replaceHardware = false)
    {
        var package = Sequence(Octets(Encoding.UTF8.GetBytes(packageName)), Number(appVersion));
        var packages = sharedUid ? Set(package, Sequence(Octets("another.package"u8.ToArray()), Number(1))) : Set(package);
        var app = Sequence(packages, Set(Octets(signer ?? ApkSigner)));
        var software = new List<(int Tag, byte[] Value)> { (709, Octets(app)) };
        var hardware = new List<(int Tag, byte[] Value)>
        {
            (1, Set(Number(purpose))), (2, Number(3)), (3, Number(256)), (5, Set(Number(4))), (10, Number(1)),
            (702, Number(origin)), (704, Sequence(Octets(SHA256.HashData("verified boot key"u8)), Boolean(locked),
                EnumValue(bootState), Octets(SHA256.HashData("verified boot hash"u8)))), (705, Number(osVersion))
        };
        (softwareAuth ? software : hardware).Add((504, Number(authType)));
        if (extraHardware is { } h) { if (replaceHardware) hardware.RemoveAll(value => value.Tag == h.Tag); hardware.Add(h); }
        if (extraSoftware is { } s) software.Add(s);
        return Sequence(Number(version), EnumValue(level), Number(keyVersion), EnumValue(keyLevel ?? level), Octets(challenge ?? Challenge),
            Octets(Array.Empty<byte>()), Authorizations(software), Authorizations(hardware));
    }

    private static byte[] Authorizations(IEnumerable<(int Tag, byte[] Value)> entries)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER); writer.PushSequence();
        foreach (var entry in entries.OrderBy(value => value.Tag))
        {
            var tag = new Asn1Tag(TagClass.ContextSpecific, entry.Tag, true);
            writer.PushSequence(tag); writer.WriteEncodedValue(entry.Value); writer.PopSequence(tag);
        }
        writer.PopSequence(); return writer.Encode();
    }
    private static byte[] Encoded(Action<AsnWriter> write) { var writer = new AsnWriter(AsnEncodingRules.DER); write(writer); return writer.Encode(); }
    private static byte[] Number(long value) => Encoded(writer => writer.WriteInteger(value));
    private static byte[] Octets(byte[] bytes) => Encoded(writer => writer.WriteOctetString(bytes));
    private static byte[] Boolean(bool value) => Encoded(writer => writer.WriteBoolean(value));
    private static byte[] Null() => Encoded(writer => writer.WriteNull());
    private static byte[] EnumValue(int value) => Encoded(writer => writer.WriteEnumeratedValue((TestEnum)value));
    private static byte[] Sequence(params byte[][] values) => Encoded(writer => { writer.PushSequence(); foreach (var value in values) writer.WriteEncodedValue(value); writer.PopSequence(); });
    private static byte[] Set(params byte[][] values) => Encoded(writer => { writer.PushSetOf(); foreach (var value in values) writer.WriteEncodedValue(value); writer.PopSetOf(); });
    private enum TestEnum { Zero = 0, One = 1, Two = 2 }
    private static AndroidAttestationRevocations Status(string json = "{\"entries\":{}}") =>
        AndroidAttestationRevocations.FromTrustedResponse(Encoding.UTF8.GetBytes(json), Now.AddMinutes(-1), Now.AddHours(1));
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static void Throws(Action action)
    {
        try { action(); } catch (ArgumentException) { return; }
        throw new InvalidOperationException("Invalid revocation response accepted.");
    }

    private sealed class Fixture : IDisposable
    {
        private readonly ECDsa _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly X509Certificate2 _root;
        public AndroidApprovalAttestation Verifier { get; }
        public ParentTrustAnchor Anchor { get; }
        public byte[] Proof { get; }
        public AndroidAttestationRevocations Status { get; } = AndroidAttestationChecks.Status();
        public Fixture()
        {
            var request = Request("CN=Guard Synthetic Attestation Root", _rootKey, ca: true);
            _root = request.CreateSelfSigned(Now.AddDays(-2), Now.AddDays(2));
            var roots = new[] { _root.RawData }; var apk = (byte[])ApkSigner.Clone();
            Verifier = new AndroidApprovalAttestation(roots, apk, 1);
            // Mutating provisioning buffers must not change established trust.
            Array.Clear(roots[0]); Array.Clear(apk);
            Anchor = new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, _leafKey.ExportSubjectPublicKeyInfo());
            Proof = _leafKey.SignHash(ClaimHash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        public byte[][] Chain(byte[] description, bool intermediateAttestation = false, bool expired = false)
        {
            var issuerRequest = Request("CN=Guard Synthetic Attestation Issuer", _issuerKey, ca: true);
            if (intermediateAttestation) issuerRequest.CertificateExtensions.Add(new X509Extension(AndroidApprovalAttestation.ExtensionOid, Description(), false));
            using var issuerPublic = issuerRequest.Create(_root, Now.AddDays(-1), Now.AddDays(1), new byte[] { 2 });
            using var issuer = issuerPublic.CopyWithPrivateKey(_issuerKey);
            var leafRequest = Request("CN=Guard Synthetic Approval Key", _leafKey, ca: false);
            leafRequest.CertificateExtensions.Add(new X509Extension(AndroidApprovalAttestation.ExtensionOid, description, false));
            using var leaf = leafRequest.Create(issuer, Now.AddHours(-2), expired ? Now.AddHours(-1) : Now.AddHours(1), new byte[] { 1 });
            return new[] { leaf.RawData, issuer.RawData, _root.RawData };
        }
        public bool Verify(byte[] description) => Check(Chain(description));
        public bool Check(byte[][] chain, AndroidAttestationRevocations? status = null) =>
            Verifier.Verify(Anchor, chain, Challenge, ClaimHash, Proof, status ?? Status, Now);
        private static CertificateRequest Request(string subject, ECDsa key, bool ca)
        {
            var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, ca, ca ? 1 : 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(ca ? X509KeyUsageFlags.KeyCertSign : X509KeyUsageFlags.DigitalSignature, true));
            return request;
        }
        public void Dispose() { _root.Dispose(); _rootKey.Dispose(); _issuerKey.Dispose(); _leafKey.Dispose(); }
    }
}
