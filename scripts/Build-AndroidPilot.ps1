#Requires -Version 7.6
# Local artifact/signing only. Never installs an APK, contacts the relay or changes Windows protection.
param(
    [Parameter(Mandatory)][string]$SigningDirectory,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][string]$JdkDirectory,
    [Parameter(Mandatory)][string]$AndroidSdkDirectory,
    [switch]$InitializeSigningKey
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$relay = 'https://guard-relay.voicepaste.workers.dev'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$entropy = [Text.Encoding]::UTF8.GetBytes('Guard.Android.PackageSigning.v1')
$stage = 'paths'

function Assert-Path([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or
        ($Path -split '[\\/]' | Where-Object { $_.EndsWith('.') -or $_.EndsWith(' ') })) { throw 'Absolute local path required.' }
    $full = [IO.Path]::GetFullPath($Path)
    $item = if (Test-Path -LiteralPath $full) { Get-Item -LiteralPath $full -Force } else { [IO.FileInfo]::new($full) }
    while ($null -ne $item) {
        if (($item.Exists -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) -or
            (Test-Path -LiteralPath (Join-Path $item.FullName '.git'))) { throw 'Redirected or Git path refused.' }
        $item = if ($item -is [IO.FileInfo]) { $item.Directory } else { $item.Parent }
    }
}
function Assert-Private([string]$Path) {
    Assert-Path $Path
    $acl = Get-Acl -LiteralPath $Path
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value -or $rules.Count -ne 1 -or
        $rules[0].IdentityReference.Value -ne $sid.Value -or $rules[0].AccessControlType -ne 'Allow' -or
        $rules[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) { throw 'Non-private signing files.' }
}
function New-PrivateDirectory([string]$Path) {
    Assert-Path $Path
    if (Test-Path -LiteralPath $Path) { throw 'Refusing existing output directory.' }
    $acl = [Security.AccessControl.DirectorySecurity]::new(); $acl.SetOwner($sid); $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($Path), $acl)
    Assert-Private $Path
}
function Write-New([string]$Path, [byte[]]$Bytes) {
    $file = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $file.Write($Bytes); $file.Flush($true) } finally { $file.Dispose() }
}
function Run-Tool([string]$Tool, [string[]]$Arguments, [string]$Password = '') {
    $psi = [Diagnostics.ProcessStartInfo]::new($Tool); $psi.UseShellExecute=$false
    $psi.CreateNoWindow=$true; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true
    foreach ($argument in $Arguments) { $psi.ArgumentList.Add($argument) }
    if ($Password) { $psi.Environment['GUARD_ANDROID_STORE_PASSWORD']=$Password }
    $process = [Diagnostics.Process]::new(); $process.StartInfo=$psi
    try {
        if (-not $process.Start()) { throw 'Tool start failed.' }
        $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(60000)) { $process.Kill($true); throw 'Tool timed out.' }
        $out=$stdout.GetAwaiter().GetResult(); $err=$stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw 'Signing/verification tool failed; output suppressed.' }
        return $out
    } finally { $psi.Environment.Remove('GUARD_ANDROID_STORE_PASSWORD') | Out-Null; $process.Dispose() }
}

try {
    Assert-Path $SigningDirectory; Assert-Path $OutputDirectory
    $keytool=Join-Path $JdkDirectory 'bin\keytool.exe'; $java=Join-Path $JdkDirectory 'bin\java.exe'
    $buildTools=Join-Path $AndroidSdkDirectory 'build-tools\36.0.0'
    $apksigner=Join-Path $buildTools 'lib\apksigner.jar'; $aapt=Join-Path $buildTools 'aapt.exe'
    foreach ($tool in @($keytool,$java,$apksigner,$aapt)) { if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw 'Required installed tool missing.' } }
    $keyPath=Join-Path $SigningDirectory 'guard-parent.p12'
    $passwordPath=Join-Path $SigningDirectory 'store-password.dpapi'
    $certificatePath=Join-Path $SigningDirectory 'guard-parent.der'
    if ($InitializeSigningKey) {
        $stage='create-signing-key'
        # No fallback key generation: losing/changing this key changes APK identity.
        New-PrivateDirectory $SigningDirectory
        $random=[Security.Cryptography.RandomNumberGenerator]::GetBytes(48)
        try { $password=[Convert]::ToBase64String($random) } finally { [Array]::Clear($random) }
        $raw=[Text.Encoding]::UTF8.GetBytes($password)
        try { Write-New $passwordPath ([Security.Cryptography.ProtectedData]::Protect($raw,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)) } finally { [Array]::Clear($raw) }
        $null=Run-Tool $keytool @('-genkeypair','-alias','guard-parent','-keystore',$keyPath,'-storetype','PKCS12',
            '-keyalg','RSA','-keysize','3072','-sigalg','SHA256withRSA','-validity','10000','-dname','CN=Guard Parent',
            '-storepass:env','GUARD_ANDROID_STORE_PASSWORD','-keypass:env','GUARD_ANDROID_STORE_PASSWORD') $password
    }
    $stage='load-signing-key'
    foreach ($path in @($SigningDirectory,$keyPath,$passwordPath)) { Assert-Private $path }
    $protected=[IO.File]::ReadAllBytes($passwordPath)
    if ($protected.Length -gt 4096) { throw 'Password file oversized.' }
    $raw=[Security.Cryptography.ProtectedData]::Unprotect($protected,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    try { $password=[Text.UTF8Encoding]::new($false,$true).GetString($raw) } finally { [Array]::Clear($raw) }
    if ($password -cnotmatch '^[A-Za-z0-9+/]{64}$') { throw 'Signing password format.' }
    New-PrivateDirectory $OutputDirectory
    $exported=Join-Path $OutputDirectory 'guard-parent.der'
    $null=Run-Tool $keytool @('-exportcert','-alias','guard-parent','-keystore',$keyPath,'-storetype','PKCS12',
        '-storepass:env','GUARD_ANDROID_STORE_PASSWORD','-file',$exported) $password
    $pin=(Get-FileHash -LiteralPath $exported -Algorithm SHA256).Hash
    if ($InitializeSigningKey) {
        Write-New $certificatePath ([IO.File]::ReadAllBytes($exported))
        # User-only plaintext handoff for owner-managed Bitwarden backup, never read or print it.
        $note = "Guard - Android package signing backup`nAlias: guard-parent`nCertificate SHA256: $pin`n" +
            "Store password:`n$password`nPKCS12 base64:`n" + [Convert]::ToBase64String([IO.File]::ReadAllBytes($keyPath)) +
            "`nKeep this entire note in Bitwarden. It contains the private APK signing key. Never send it to chat or Git.`n"
        Write-New (Join-Path $SigningDirectory 'Bitwarden-backup.txt') ([Text.UTF8Encoding]::new($true).GetBytes($note))
        $note=$null
    } else {
        Assert-Private $certificatePath
        if ((Get-FileHash -LiteralPath $certificatePath -Algorithm SHA256).Hash -cne $pin) { throw 'Signing certificate changed.' }
    }
    $stage='gradle-build'
    $previousJava=$env:JAVA_HOME; $previousSdk=$env:ANDROID_HOME
    $env:JAVA_HOME=$JdkDirectory; $env:ANDROID_HOME=$AndroidSdkDirectory
    Push-Location (Join-Path $root 'parent\android')
    try {
        & .\gradlew.bat :app:testDebugUnitTest :app:assembleRelease :app:assembleDebugAndroidTest :app:lintRelease --offline --no-daemon --console=plain ('-PguardEnrollmentRelay=' + $relay)
        if ($LASTEXITCODE -ne 0) { throw 'Android build/tests failed.' }
    } finally { Pop-Location; $env:JAVA_HOME=$previousJava; $env:ANDROID_HOME=$previousSdk }
    $stage='sign-and-verify'
    $unsigned=Join-Path $root 'parent\android\app\build\outputs\apk\release\app-release-unsigned.apk'
    $apk=Join-Path $OutputDirectory 'Guard-Parent-pilot.apk'
    $null=Run-Tool $java @('-jar',$apksigner,'sign','--ks',$keyPath,'--ks-key-alias','guard-parent',
        '--ks-pass','env:GUARD_ANDROID_STORE_PASSWORD','--key-pass','env:GUARD_ANDROID_STORE_PASSWORD',
        '--v4-signing-enabled','false','--out',$apk,$unsigned) $password
    $password=$null
    $verified=Run-Tool $java @('-jar',$apksigner,'verify','--verbose','--print-certs',$apk)
    $match=[regex]::Matches($verified,'(?m)^Signer #1 certificate SHA-256 digest: ([0-9a-fA-F]{64})\r?$')
    if ($match.Count -ne 1 -or $match[0].Groups[1].Value.ToUpperInvariant() -cne $pin -or $verified -notmatch 'Number of signers: 1') { throw 'APK signer mismatch.' }
    $badging=Run-Tool $aapt @('dump','badging',$apk)
    if ($badging -notmatch "package: name='app.guard.parent' versionCode='1'" -or $badging -match 'application-debuggable' -or $badging -notmatch "sdkVersion:'31'") { throw 'APK identity/debug/minSdk mismatch.' }
    # Confirm the compiled artifact contains the fixed origin; it is not a runtime preference.
    $zip=[IO.Compression.ZipFile]::OpenRead($apk)
    try {
        $found=$false
        foreach ($entry in $zip.Entries | Where-Object FullName -Match '^classes[0-9]*\.dex$') {
            $stream=$entry.Open(); $memory=[IO.MemoryStream]::new()
            try { $stream.CopyTo($memory); if ([Text.Encoding]::Latin1.GetString($memory.ToArray()).Contains($relay)) { $found=$true } }
            finally { $stream.Dispose(); $memory.Dispose() }
        }
        if (-not $found) { throw 'Compiled relay pin absent.' }
    } finally { $zip.Dispose() }
    $manifest=[ordered]@{Version=1;LabOnly=$true;ProtectionReady=$false;SigningBackupConfirmed=$false;RelayOrigin=$relay;
        AndroidPackage='app.guard.parent';MinimumAndroidVersion=1;AndroidSignerSha256=$pin;ApkSha256=(Get-FileHash -LiteralPath $apk -Algorithm SHA256).Hash;Apk='Guard-Parent-pilot.apk'}
    Write-New (Join-Path $OutputDirectory 'pilot-manifest.json') ([Text.Encoding]::UTF8.GetBytes(($manifest | ConvertTo-Json)))
    $manifest | ConvertTo-Json -Compress
    Write-Output ('Pilot output: ' + $OutputDirectory)
    Write-Output 'No phone installed. Owner backup and physical biometric/enrollment acceptance are still required.'
} catch {
    Write-Output ('FAILED at ' + $stage + '; existing key/output retained, no automatic regeneration. Secret-bearing tool output suppressed.')
    exit 1
}
