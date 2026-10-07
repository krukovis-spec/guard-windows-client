# No service execution or elevation here; output is a temporary LAB-ONLY package.
param([string]$AndroidPilotManifest, [string]$AndroidPilotManifestSha256, [switch]$IncludeSetup)
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$relayOrigin = 'https://guard-lab.invalid'
$androidSigner = 'A' * 64
$minimumVersion = 1
if ($IncludeSetup -and -not $AndroidPilotManifest) { throw 'Phone setup requires a verified Android pilot manifest' }
if ($AndroidPilotManifest -or $AndroidPilotManifestSha256) {
    if (-not [IO.Path]::IsPathRooted($AndroidPilotManifest) -or $AndroidPilotManifestSha256 -notmatch '^[A-F0-9]{64}$') { throw 'Complete Android manifest commitment required' }
    $inputFile = Get-Item -LiteralPath $AndroidPilotManifest
    if ($inputFile.Attributes -band [IO.FileAttributes]::ReparsePoint -or $inputFile.Length -gt 4096 -or
        (Get-FileHash -LiteralPath $inputFile.FullName -Algorithm SHA256).Hash -cne $AndroidPilotManifestSha256) { throw 'Android manifest mismatch' }
    $pilot = Get-Content -LiteralPath $inputFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($pilot.Version -ne 1 -or $pilot.LabOnly -ne $true -or $pilot.ProtectionReady -ne $false -or
        $pilot.RelayOrigin -cne 'https://guard-relay.voicepaste.workers.dev' -or $pilot.AndroidPackage -cne 'app.guard.parent' -or
        $pilot.MinimumAndroidVersion -ne 1 -or $pilot.AndroidSignerSha256 -cnotmatch '^[A-F0-9]{64}$' -or
        $pilot.AndroidSignerSha256 -eq ('0' * 64) -or $pilot.Apk -cne 'Guard-Parent-pilot.apk' -or $pilot.ApkSha256 -cnotmatch '^[A-F0-9]{64}$') { throw 'Android pilot identity invalid' }
    $apk = Get-Item -LiteralPath (Join-Path $inputFile.DirectoryName $pilot.Apk)
    $certificate = Get-Item -LiteralPath (Join-Path $inputFile.DirectoryName 'guard-parent.der')
    if (($apk.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($certificate.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        (Get-FileHash -LiteralPath $apk.FullName -Algorithm SHA256).Hash -cne $pilot.ApkSha256 -or
        (Get-FileHash -LiteralPath $certificate.FullName -Algorithm SHA256).Hash -cne $pilot.AndroidSignerSha256) { throw 'Android artifact identity changed' }
    $relayOrigin = $pilot.RelayOrigin; $androidSigner = $pilot.AndroidSignerSha256; $minimumVersion = $pilot.MinimumAndroidVersion
}
$package = Join-Path ([IO.Path]::GetFullPath($env:TEMP)) ('GuardServiceLab-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $package | Out-Null
$projects = @(
    @{Project='src\Guard.Service\Guard.Service.csproj';Folder='service'},
    @{Project='tests\Guard.Windows.Ipc.Tests\Guard.Windows.Ipc.Tests.csproj';Folder='probe'}
)
if ($IncludeSetup) {
    $projects += @{Project='src\Guard.Setup\Guard.Setup.csproj';Folder='setup'}
}
foreach ($item in $projects) {
    & dotnet publish (Join-Path $projectRoot $item.Project) -c Release -r win-x64 --self-contained true --nologo -o (Join-Path $package $item.Folder) `
        ('-p:GuardRelayOrigin=' + $relayOrigin) ('-p:GuardAndroidSignerSha256=' + $androidSigner) ('-p:GuardMinimumAndroidVersion=' + $minimumVersion)
    if ($LASTEXITCODE -ne 0) { throw ('Lab publish failed; incomplete package: ' + $package) }
}
# dotnet publish can preserve Pinned (0x80000) from build outputs. Windows PowerShell
# Direct cannot deserialize that FileAttributes value. Normalize only our new temporary
# payload, never the source tree/NuGet cache; byte hashes below still pin the exact content.
foreach ($file in Get-ChildItem -LiteralPath $package -File -Recurse) {
    if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected lab output' }
    $file.Attributes = [IO.FileAttributes]::Archive
}
$files = @(Get-ChildItem -LiteralPath $package -File -Recurse | Sort-Object FullName | ForEach-Object {
    [pscustomobject]@{Path=$_.FullName.Substring($package.Length + 1);Length=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
})
[pscustomobject]@{Version=1;LabOnly=$true;ExpectedRelayOrigin=$relayOrigin;AndroidSignerSha256=$androidSigner;MinimumAndroidVersion=$minimumVersion;Files=$files} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $package 'manifest.json') -Encoding UTF8
[pscustomobject]@{Package=$package;ManifestSha256=(Get-FileHash -LiteralPath (Join-Path $package 'manifest.json') -Algorithm SHA256).Hash;Files=$files.Count}
