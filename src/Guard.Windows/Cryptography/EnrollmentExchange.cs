using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Guard.Contracts.Relay;
using Guard.Protocol.Relay;

namespace Guard.Windows.Cryptography;

// Separate from GRF1: a bounded 64 KiB attestation chain must not widen ordinary relay limits.
internal static class EnrollmentExchange
{
    internal const int MaximumBytes = 70 * 1024;
    internal const int HeaderBytes = 108;
    internal const int Claim = 1, KeyProof = 2, Query = 3, Reply = 4;
    internal const int NeedsPhoneProof = 1, NeedsLocalConfirmation = 2, Confirmed = 3;
    internal sealed record Message(int Kind, byte[] OfferHash, byte[] ClaimHash, byte[] Nonce, byte[] Header, byte[] Enc, byte[] Cipher);
    internal sealed record Submission(EnrollmentKeyClaim Claim, byte[][] Chain, byte[] Mac, byte[] Signature);
    private static readonly byte[] Info = Encoding.ASCII.GetBytes("guard-enrollment-exchange-hpke-v1");
    private static readonly byte[] SignatureDomain = Encoding.ASCII.GetBytes("guard-enrollment-result-v1");

    internal static byte[] Header(int kind, byte[] offerHash, byte[] claimHash, byte[] nonce) => Write("GREX", w =>
    {
        if (kind < Claim || kind > Reply) throw new ArgumentException("Enrollment message kind.");
        I32(w, kind); Fixed(w, offerHash, 32); Fixed(w, claimHash, 32); Fixed(w, nonce, 32);
    });

    internal static Message Decode(byte[] raw)
    {
        var r = new Reader(raw, "GREX");
        var kind = r.I32(); if (kind < Claim || kind > Reply) throw new ArgumentException("Enrollment message kind.");
        var offer = r.Fixed(32); var claim = r.Fixed(32); var nonce = r.Fixed(32);
        var enc = r.Fixed(65); if (enc[0] != 4) throw new ArgumentException("HPKE point.");
        var cipher = r.Bytes(MaximumBytes - HeaderBytes - 69); if (cipher.Length < 16) throw new ArgumentException("HPKE tag.");
        if ((kind == KeyProof && cipher.Length != 48) || (kind == Query && cipher.Length != 16) || (kind == Reply && cipher.Length > 237))
            throw new ArgumentException("Enrollment message payload size.");
        r.End(); return new Message(kind, offer, claim, nonce, Header(kind, offer, claim, nonce), enc, cipher);
    }

    internal static byte[] Seal(byte[] header, byte[] body, byte[] publicKey)
    {
        if (header.Length != HeaderBytes || body.Length > MaximumBytes - HeaderBytes - 85) throw new ArgumentException("Enrollment size.");
        var cipher = RelayCryptography.Encrypt(publicKey, body, header, Info.Concat(header).ToArray(), out var enc);
        using var w = new MemoryStream(); w.Write(header); w.Write(enc); Bytes(w, cipher); return w.ToArray();
    }

    internal static byte[] Open(Message message, ECDiffieHellman key)
    {
        var parameters = key.ExportParameters(true);
        try { return RelayCryptography.Decrypt(parameters.D!, Point(parameters.Q), message.Enc, message.Cipher,
            message.Header, Info.Concat(message.Header).ToArray()); }
        finally { CryptographicOperations.ZeroMemory(parameters.D!); }
    }

    internal static byte[] EncodeSubmission(EnrollmentKeyClaim claim, IReadOnlyList<byte[]> chain, byte[] mac, byte[] signature) => Write("GREK", w =>
    {
        Bytes(w, RelayCanonicalEncoding.EncodeEnrollmentClaimForSignature(claim));
        if (chain.Count < 2 || chain.Count > 8) throw new ArgumentException("Attestation count.");
        I32(w, chain.Count); var total = 0;
        foreach (var certificate in chain)
        {
            if (certificate == null || certificate.Length == 0 || certificate.Length > 16384 || (total += certificate.Length) > 65536)
                throw new ArgumentException("Attestation size.");
            Bytes(w, certificate);
        }
        Fixed(w, mac, 32); Fixed(w, signature, 64);
    });

    internal static Submission DecodeSubmission(byte[] body)
    {
        var r = new Reader(body, "GREK"); var claim = RelayCanonicalEncoding.DecodeEnrollmentClaimForSignature(r.Bytes(460));
        var count = r.I32(); if (count < 2 || count > 8) throw new ArgumentException("Attestation count.");
        var chain = new byte[count][]; var total = 0;
        for (var i = 0; i < count; i++)
        {
            chain[i] = r.Bytes(16384);
            if ((total += chain[i].Length) > 65536) throw new ArgumentException("Attestation size.");
        }
        var mac = r.Fixed(32); var signature = r.Fixed(64); r.End(); return new Submission(claim, chain, mac, signature);
    }

    internal static byte[] Result(int outcome, long version, DateTimeOffset issued, DateTimeOffset expires, byte[] enc, byte[] cipher) => Write("GRES", w =>
    {
        if (outcome < NeedsPhoneProof || outcome > Confirmed || version < 1 || issued.ToUnixTimeMilliseconds() < 0 ||
            expires <= issued || expires - issued > TimeSpan.FromMinutes(1) ||
            enc.Length != (outcome == NeedsPhoneProof ? 65 : 0) || cipher.Length != (outcome == NeedsPhoneProof ? 48 : 0))
            throw new ArgumentException("Enrollment result.");
        I32(w, outcome); I64(w, version); I64(w, issued.ToUnixTimeMilliseconds()); I64(w, expires.ToUnixTimeMilliseconds());
        Bytes(w, enc); Bytes(w, cipher);
    });
    internal static byte[] SignatureInput(byte[] replyHeader, byte[] result) => SignatureDomain.Concat(replyHeader).Concat(result).ToArray();
    internal static byte[] Point(ECPoint point) => new byte[] { 4 }.Concat(point.X!).Concat(point.Y!).ToArray();
    private static byte[] Write(string magic, Action<MemoryStream> write)
    {
        using var w = new MemoryStream(); w.Write(Encoding.ASCII.GetBytes(magic)); I32(w, 1); write(w);
        if (w.Length > MaximumBytes) throw new ArgumentException("Enrollment size."); return w.ToArray();
    }
    private static void I32(Stream w, int value) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteInt32BigEndian(b, value); w.Write(b); }
    private static void I64(Stream w, long value) { Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteInt64BigEndian(b, value); w.Write(b); }
    private static void Bytes(Stream w, byte[] value) { I32(w, value.Length); w.Write(value); }
    private static void Fixed(Stream w, byte[] value, int size) { if (value == null || value.Length != size) throw new ArgumentException("Enrollment field size."); w.Write(value); }
    private sealed class Reader
    {
        private readonly byte[] _raw; private int _at;
        internal Reader(byte[] raw, string magic)
        {
            if (raw == null || raw.Length > MaximumBytes) throw new ArgumentException("Enrollment size.");
            _raw = (byte[])raw.Clone();
            if (Encoding.ASCII.GetString(Fixed(4)) != magic || I32() != 1) throw new ArgumentException("Enrollment version.");
        }
        internal byte[] Fixed(int n)
        {
            if (n < 0 || n > _raw.Length - _at) throw new ArgumentException("Truncated enrollment.");
            var result = _raw.AsSpan(_at, n).ToArray(); _at += n; return result;
        }
        internal int I32() => BinaryPrimitives.ReadInt32BigEndian(Fixed(4));
        internal byte[] Bytes(int maximum) { var n = I32(); if (n < 1 || n > maximum) throw new ArgumentException("Enrollment field size."); return Fixed(n); }
        internal void End() { if (_at != _raw.Length) throw new ArgumentException("Trailing enrollment bytes."); }
    }
}
