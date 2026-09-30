using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using Guard.Protocol.Relay;
using Guard.Windows.Cryptography;

namespace Guard.Service;

// PUBLIC pins compiled into the trusted service release. Never load these from a phone, relay or environment.
internal sealed class EnrollmentDeploymentTrust
{
    private readonly byte[] _apkSigner;
    internal Uri Origin { get; }
    internal long MinimumAndroidVersion { get; }
    internal EnrollmentDeploymentTrust(string origin, string apkSignerSha256, long minimumAndroidVersion)
    {
        RelayCanonicalEncoding.RequireEnrollmentRelay(origin);
        if (origin == null || origin.Length > 256 || !Uri.TryCreate(origin, UriKind.Absolute, out var uri) ||
            origin != uri.GetLeftPart(UriPartial.Authority)) throw new InvalidDataException("Noncanonical deployment origin.");
        HttpRelayTransport.RequireOrigin(uri);
        if (apkSignerSha256 == null || apkSignerSha256.Length != 64 || apkSignerSha256.Any(c => !Uri.IsHexDigit(c)))
            throw new InvalidDataException("Missing deployment APK signing pin.");
        _apkSigner = Convert.FromHexString(apkSignerSha256);
        if (_apkSigner.All(b => b == 0) || minimumAndroidVersion < 1 || minimumAndroidVersion > HttpRelayTransport.MaximumCursor)
            throw new InvalidDataException("Invalid deployment APK identity.");
        Origin = uri; MinimumAndroidVersion = minimumAndroidVersion;
    }

    internal AndroidApprovalAttestation CreateVerifier(GoogleAndroidAttestationSource source) =>
        source.CreateVerifier(_apkSigner, MinimumAndroidVersion);

    internal static EnrollmentDeploymentTrust FromServiceAssembly() => FromMetadata(
        typeof(EnrollmentDeploymentTrust).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>());

    internal static EnrollmentDeploymentTrust FromMetadata(IEnumerable<AssemblyMetadataAttribute> metadata)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var item in metadata)
            if (item.Key.StartsWith("Guard.Enrollment.", StringComparison.Ordinal) &&
                (item.Value == null || !values.TryAdd(item.Key, item.Value)))
                throw new InvalidDataException("Duplicate deployment trust metadata.");
        if (values.Count != 3 || !values.TryGetValue("Guard.Enrollment.RelayOrigin", out var origin) ||
            !values.TryGetValue("Guard.Enrollment.AndroidSignerSha256", out var signer) ||
            !values.TryGetValue("Guard.Enrollment.MinimumAndroidVersion", out var version) ||
            !long.TryParse(version, NumberStyles.None, CultureInfo.InvariantCulture, out var minimum) ||
            version != minimum.ToString(CultureInfo.InvariantCulture))
            throw new InvalidDataException("This service build has no complete enrollment trust profile.");
        return new EnrollmentDeploymentTrust(origin, signer, minimum);
    }
}
