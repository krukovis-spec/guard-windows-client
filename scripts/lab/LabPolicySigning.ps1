# Test-only signer. No certificate store, persisted private key or production authority.
function New-LabPolicyCertificate {
    if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Custom-content PKCS#7 signing requires the installed PowerShell 7 runtime' }
    $rsa = New-Object Security.Cryptography.RSACng(3072)
    try {
        $request = New-Object Security.Cryptography.X509Certificates.CertificateRequest(
            'CN=Guard LAB ONLY ephemeral policy signer', $rsa,
            [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $usage = New-Object Security.Cryptography.OidCollection
        $usage.Add((New-Object Security.Cryptography.Oid('1.3.6.1.5.5.7.3.3'))) | Out-Null
        $request.CertificateExtensions.Add((New-Object Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($usage, $true)))
        $request.CertificateExtensions.Add((New-Object Security.Cryptography.X509Certificates.X509KeyUsageExtension([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true)))
        $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddDays(1))
        $key = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
        try {
            if (-not $key.Key.IsEphemeral) { $certificate.Dispose(); throw 'Lab signing key must remain ephemeral' }
        } finally { $key.Dispose() }
        $certificate
    } finally { $rsa.Dispose() }
}

function Write-LabSignedPolicy([string]$InputPath, [string]$OutputPath, [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
    Add-Type -AssemblyName System.Security
    if (-not ('GuardLabPkcs7Compatibility' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Formats.Asn1;
using System.Runtime.InteropServices;
public static class GuardLabPkcs7Compatibility {
    // Windows CI expects PKCS#7 SignedData v1. This integer is not signed content.
    public static byte[] ToVersionOne(byte[] encoded) {
        var root = new AsnReader(encoded, AsnEncodingRules.DER).ReadSequence();
        if (root.ReadObjectIdentifier() != "1.2.840.113549.1.7.2")
            throw new InvalidOperationException("Not a SignedData container");
        var signed = root.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)).ReadSequence();
        ArraySegment<byte> version;
        if (!MemoryMarshal.TryGetArray(signed.ReadEncodedValue(), out version) ||
            version.Count != 3 || version.Array[version.Offset] != 2 ||
            version.Array[version.Offset + 1] != 1 || version.Array[version.Offset + 2] != 3)
            throw new InvalidOperationException("Unexpected generated SignedData version");
        var result = (byte[])encoded.Clone();
        result[version.Offset + 2] = 1;
        return result;
    }
}
'@
    }
    $inputBytes = [IO.File]::ReadAllBytes($InputPath)
    if ($inputBytes.Length -eq 0 -or $inputBytes.Length -gt 16MB) { throw 'Invalid lab policy size' }
    $content = New-Object Security.Cryptography.Pkcs.ContentInfo((New-Object Security.Cryptography.Oid('1.3.6.1.4.1.311.79.1')), $inputBytes)
    $cms = New-Object Security.Cryptography.Pkcs.SignedCms($content, $false)
    $signer = New-Object Security.Cryptography.Pkcs.CmsSigner($Certificate)
    $signer.DigestAlgorithm = New-Object Security.Cryptography.Oid('2.16.840.1.101.3.4.2.1')
    $signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $cms.ComputeSignature($signer, $true)
    if ($cms.Version -ne 3 -or $cms.SignerInfos.Count -ne 1 -or $cms.SignerInfos[0].Version -ne 1) { throw 'Unexpected generated CMS signer/version' }
    $encoded = [GuardLabPkcs7Compatibility]::ToVersionOne($cms.Encode())
    $check = New-Object Security.Cryptography.Pkcs.SignedCms
    $check.Decode($encoded)
    $check.CheckSignature($true)
    if ($check.Version -ne 1 -or $check.ContentInfo.ContentType.Value -ne '1.3.6.1.4.1.311.79.1' -or $check.SignerInfos.Count -ne 1 -or
        $check.SignerInfos[0].Certificate.Thumbprint -ne $Certificate.Thumbprint -or
        [Convert]::ToBase64String($check.ContentInfo.Content) -ne [Convert]::ToBase64String($inputBytes)) { throw 'Lab signature self-check failed' }
    [IO.File]::WriteAllBytes($OutputPath, $encoded)
}
