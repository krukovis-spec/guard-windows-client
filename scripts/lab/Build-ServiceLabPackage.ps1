# No service execution or elevation here; output is a temporary LAB-ONLY package.
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$package = Join-Path ([IO.Path]::GetFullPath($env:TEMP)) ('GuardServiceLab-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $package | Out-Null
foreach ($item in @(
    @{Project='src\Guard.Service\Guard.Service.csproj';Folder='service'},
    @{Project='tests\Guard.Windows.Ipc.Tests\Guard.Windows.Ipc.Tests.csproj';Folder='probe'}
)) {
    & dotnet publish (Join-Path $projectRoot $item.Project) -c Release -r win-x64 --self-contained true --nologo -o (Join-Path $package $item.Folder) `
        '-p:GuardRelayOrigin=https://guard-lab.invalid' ('-p:GuardAndroidSignerSha256=' + ('A' * 64)) '-p:GuardMinimumAndroidVersion=1'
    if ($LASTEXITCODE -ne 0) { throw ('Lab publish failed; incomplete package: ' + $package) }
}
$files = @(Get-ChildItem -LiteralPath $package -File -Recurse | Sort-Object FullName | ForEach-Object {
    [pscustomobject]@{Path=$_.FullName.Substring($package.Length + 1);Length=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
})
[pscustomobject]@{Version=1;LabOnly=$true;Files=$files} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $package 'manifest.json') -Encoding UTF8
[pscustomobject]@{Package=$package;ManifestSha256=(Get-FileHash -LiteralPath (Join-Path $package 'manifest.json') -Algorithm SHA256).Hash;Files=$files.Count}
