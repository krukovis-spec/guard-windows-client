using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Guard.Protocol.Relay;
using Guard.Windows.Cryptography;

namespace Guard.Windows.Crypto.Tests;

internal static class NativeProfileInterop
{
    // Existing PUBLIC synthetic ceremony only. Never opens device identity, OS state or operational credentials.
    internal static void Export()
    {
        var values = File.ReadAllLines("protocol/test-vectors/enrollment-exchange-v1.properties")
            .Where(line => !line.StartsWith('#') && line.Contains('=')).Select(line => line.Split('=', 2)).ToDictionary(row => row[0], row => row[1]);
        var offer = RelayCanonicalEncoding.DecodeEnrollmentOffer(Convert.FromHexString(values["offer"]));
        var claim = RelayCanonicalEncoding.DecodeEnrollmentClaimForSignature(Convert.FromHexString(values["claim"]));
        var now = DateTimeOffset.FromUnixTimeMilliseconds(long.Parse(values["now"], System.Globalization.CultureInfo.InvariantCulture));
        var bytes = NativeRelayProfileEnvelope.Seal(offer, claim, new string('A', 64), now, now.AddDays(3));
        Console.WriteLine("# PUBLIC SYNTHETIC profile only; uses enrollment-exchange-v1.properties phone key; credential is 64 ASCII A characters.");
        Console.WriteLine("envelope=" + Convert.ToHexString(bytes));
        Console.WriteLine("sha256=" + Convert.ToHexString(SHA256.HashData(bytes)));
    }
}
