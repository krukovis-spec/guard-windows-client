using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Protocol.Relay;
using Guard.Windows.Cryptography;

namespace Guard.Windows.RelayCrypto.Tests;

internal static class EnrollmentTranscriptChecks
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeMilliseconds(1790769600000);
    private static readonly byte[] Secret = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray(); // PUBLIC TEST MATERIAL
    private static readonly byte[] Challenge = SHA256.HashData("independent public enrollment challenge"u8);
    private static readonly byte[] GeneratorPoint = Convert.FromHexString("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    private static readonly byte[] PhoneEncryptionPoint = Convert.FromHexString("04c06b4f6bebc7bb495cb797ab753f911aff80aefb86fd8b6fcc35525f3ab5f03e0b21bd31a86c6048af3cb2d98e0d3bf01da5cc4c39ff5370d331a4f1f7d5a4e0");

    private static byte[] Vector(string name) => Convert.FromHexString(File.ReadLines(Path.Combine(AppContext.BaseDirectory, "relay-exchange-v1.properties"))
        .Single(line => line.StartsWith(name + "=", StringComparison.Ordinal)).Split('=', 2)[1]);
    private static EnrollmentOffer Offer(string label = "Тестовый ПК", string relay = "https://relay.example.test", long epoch = 2,
        DateTimeOffset? expiry = null, byte[]? signing = null, byte[]? encryption = null, byte[]? nonce = null) => new(relay, "enrollment-alpha1", "device-alpha-0001", label,
            epoch, 4, "mailbox-alpha-0001", "device-signing-0001", signing ?? Vector("device.public"), "device-encrypt-001",
            encryption ?? GeneratorPoint, Now, expiry ?? Now.AddMinutes(5), nonce ?? Challenge);
    private static EnrollmentKeyClaim Claim(EnrollmentOffer offer)
    {
        var point = Vector("recipient.public");
        using var key = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = point[1..33], Y = point[33..65] } });
        var anchor = new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, key.ExportSubjectPublicKeyInfo());
        return new EnrollmentKeyClaim(RelayCanonicalEncoding.ComputeEnrollmentOfferHash(offer), anchor.KeyId,
            anchor.GetSubjectPublicKeyInfoCopy(), "parent-encrypt-01", PhoneEncryptionPoint);
    }

    internal static void Run()
    {
        VerifyKeyConfirmationFixture();
        var offer = Offer(); var claim = Claim(offer);
        var raw = RelayCanonicalEncoding.EncodeEnrollmentOffer(offer);
        var input = RelayCanonicalEncoding.EncodeEnrollmentClaimForSignature(claim);
        Equal(raw, RelayCanonicalEncoding.EncodeEnrollmentOffer(RelayCanonicalEncoding.DecodeEnrollmentOffer(raw)));
        Equal(input, RelayCanonicalEncoding.EncodeEnrollmentClaimForSignature(RelayCanonicalEncoding.DecodeEnrollmentClaimForSignature(input)));
        // Each accepted byte mutation must alter the digest: no ignored fields, lengths, magic or version.
        CheckWire(raw, value => RelayCanonicalEncoding.ComputeEnrollmentOfferHash(RelayCanonicalEncoding.DecodeEnrollmentOffer(value)));
        CheckWire(input, value => RelayCanonicalEncoding.ComputeEnrollmentClaimHash(RelayCanonicalEncoding.DecodeEnrollmentClaimForSignature(value)));
        foreach (var value in new[] { Offer(label: "x\u0085"), Offer(label: "e\u0301"), Offer(label: "\ud800"), Offer(label: new string('x', 97)),
            Offer(relay: "https://relay.example.test/../x"), Offer(relay: "https://relay.example.test:443"), Offer(relay: "https://RELAY.example.test"),
            Offer(relay: "http://relay.example.test"), Offer(relay: "https://relay.example.test\n"), Offer(epoch: 0), Offer(epoch: -1),
            Offer(expiry: Now), Offer(expiry: Now.AddMinutes(10).AddMilliseconds(1)), Offer(expiry: Now.AddTicks(1)),
            Offer(signing: new byte[65]), Offer(encryption: Vector("device.public")) })
            Reject(() => RelayCanonicalEncoding.EncodeEnrollmentOffer(value));
        RelayCanonicalEncoding.EncodeEnrollmentOffer(Offer(label: "ПК 💻"));
        var hash = RelayCanonicalEncoding.ComputeEnrollmentClaimHash(claim);
        var proof = RelayCanonicalEncoding.ComputeEnrollmentClaimProof(SHA256.HashData(Secret), claim);
        Require(!proof.SequenceEqual(RelayCanonicalEncoding.ComputeEnrollmentClaimProof(new byte[32], claim)));
        Require(!hash.SequenceEqual(RelayCanonicalEncoding.ComputeEnrollmentOfferHash(offer)));
        Reject(() => RelayCanonicalEncoding.ComputeEnrollmentClaimProof(new byte[31], claim));
        Reject(() => RelayCanonicalEncoding.EncodeEnrollmentQr(offer, new byte[31]));
        Reject(() => RelayCanonicalEncoding.EncodeEnrollmentQr(Offer(nonce: Secret), Secret));
        Reject(() => RelayCanonicalEncoding.EncodeEnrollmentQr(Offer(nonce: SHA256.HashData(Secret)), Secret));
        // Construction and access must not expose mutable authority buffers.
        var signing = Vector("device.public"); var encryption = (byte[])GeneratorPoint.Clone();
        var copied = Offer(signing: signing, encryption: encryption); Array.Clear(signing); Array.Clear(encryption);
        Array.Clear(copied.GetSigningKeyCopy()); Array.Clear(copied.GetEncryptionKeyCopy()); Array.Clear(copied.GetChallengeCopy());
        Equal(raw, RelayCanonicalEncoding.EncodeEnrollmentOffer(copied));
        var claimedHash = claim.GetOfferHashCopy(); var approval = claim.GetApprovalKeyCopy(); var enc = claim.GetEncryptionKeyCopy();
        var copiedClaim = new EnrollmentKeyClaim(claimedHash, claim.ApprovalKeyId, approval, claim.EncryptionKeyId, enc);
        Array.Clear(claimedHash); Array.Clear(approval); Array.Clear(enc); Array.Clear(copiedClaim.GetOfferHashCopy());
        Array.Clear(copiedClaim.GetApprovalKeyCopy()); Array.Clear(copiedClaim.GetEncryptionKeyCopy());
        Equal(input, RelayCanonicalEncoding.EncodeEnrollmentClaimForSignature(copiedClaim));
        // Fixed, reviewed hashes shared with Kotlin. Exact QR/input/MAC are also checked cross-runtime below.
        Equal(Convert.FromHexString("BFA3C18A436D94834FDEC226BA822D60382DC046A9B23B4A50E28F7890DB5D68"), SHA256.HashData(raw));
        Equal(Convert.FromHexString("9DD4DA43ED053E771CEC24624CBB52A74CE9072496A554C46A6D08D407ACB62A"), hash);
        Equal(Convert.FromHexString("9AE65292543C6BA6E16E4D38FD35E30EF4C212788C921C914B769D2C780362DC"), proof);
    }

    internal static void VerifyAndroid(string path)
    {
        var lines = File.ReadAllLines(path);
        Require(lines.Length == 5);
        var offer = Offer(); var claim = Claim(offer);
        Equal(Convert.FromHexString(lines[0]), RelayCanonicalEncoding.EncodeEnrollmentOffer(offer));
        Equal(Convert.FromHexString(lines[1]), RelayCanonicalEncoding.EncodeEnrollmentClaimForSignature(claim));
        Equal(Convert.FromHexString(lines[2]), RelayCanonicalEncoding.ComputeEnrollmentClaimProof(SHA256.HashData(Secret), claim));
        var point = Vector("recipient.public");
        using var key = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = point[1..33], Y = point[33..65] } });
        Require(key.VerifyHash(RelayCanonicalEncoding.ComputeEnrollmentClaimHash(claim), Convert.FromHexString(lines[3]), DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        Require(lines[4] == RelayCanonicalEncoding.EncodeEnrollmentQr(offer, Secret));
        Console.WriteLine("PASS Android enrollment exact offer/claim/MAC and real signature verified by .NET (public test keys, not hardware evidence).");
    }
    internal static void ExportKeyConfirmation()
    {
        // PUBLIC TEST MATERIAL: recipient private key is already in relay-exchange-v1.properties.
        var spki = Convert.FromHexString("3059301306072a8648ce3d020106082a8648ce3d030107034200").Concat(GeneratorPoint).ToArray();
        var anchor = new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, spki);
        var claim = new EnrollmentKeyClaim(RelayCanonicalEncoding.ComputeEnrollmentOfferHash(Offer()), anchor.KeyId,
            spki, "parent-encrypt-01", Vector("recipient.public"));
        var hash = RelayCanonicalEncoding.ComputeEnrollmentClaimHash(claim);
        var witness = SHA256.HashData("public enrollment key confirmation test witness"u8);
        var cipher = RelayCryptography.Encrypt(claim.GetEncryptionKeyCopy(), witness, hash,
            NativeEnrollmentCoordinator.KeyConfirmationInfo(hash), out var enc);
        Console.WriteLine("claim=" + Convert.ToHexString(RelayCanonicalEncoding.EncodeEnrollmentClaimForSignature(claim)));
        Console.WriteLine("enc=" + Convert.ToHexString(enc));
        Console.WriteLine("cipher=" + Convert.ToHexString(cipher));
        Console.WriteLine("proof=" + Convert.ToHexString(NativeEnrollmentCoordinator.ComputePhoneKeyProof(witness, hash)));
    }
    private static void VerifyKeyConfirmationFixture()
    {
        byte[] Field(string name) => Convert.FromHexString(File.ReadLines(Path.Combine(AppContext.BaseDirectory, "enrollment-key-confirmation-v1.properties"))
            .Single(line => line.StartsWith(name + "=", StringComparison.Ordinal)).Split('=', 2)[1]);
        var claim = RelayCanonicalEncoding.DecodeEnrollmentClaimForSignature(Field("claim"));
        var hash = RelayCanonicalEncoding.ComputeEnrollmentClaimHash(claim);
        var witness = RelayCryptography.Decrypt(Vector("recipient.private"), claim.GetEncryptionKeyCopy(), Field("enc"), Field("cipher"),
            hash, NativeEnrollmentCoordinator.KeyConfirmationInfo(hash));
        Equal(SHA256.HashData("public enrollment key confirmation test witness"u8), witness);
        Equal(Field("proof"), NativeEnrollmentCoordinator.ComputePhoneKeyProof(witness, hash));
    }
    private static void CheckWire(byte[] raw, Func<byte[], byte[]> decodeHash)
    {
        var hash = SHA256.HashData(raw);
        for (var length = 0; length < raw.Length; length++) { var cut = raw[..length]; Reject(() => decodeHash(cut)); }
        Reject(() => decodeHash(raw.Concat(new byte[] {0}).ToArray()));
        for (var i = 0; i < raw.Length; i++)
        {
            var changed = (byte[])raw.Clone(); changed[i] ^= 1;
            try { Require(!hash.SequenceEqual(decodeHash(changed))); } catch (ArgumentException) { }
        }
    }
    private static void Equal(byte[] a, byte[] b) => Require(a.SequenceEqual(b));
    private static void Require(bool value) { if (!value) throw new InvalidOperationException("Enrollment transcript mismatch."); }
    private static void Reject(Action action) { try { action(); } catch (ArgumentException) { return; } throw new InvalidOperationException("Invalid enrollment accepted."); }
}
