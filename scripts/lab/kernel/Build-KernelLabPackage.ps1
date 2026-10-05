param([Parameter(Mandatory=$true)][string]$EwdkRoot,[Parameter(Mandatory=$true)][string]$SignToolPath)
$ErrorActionPreference='Stop'
$EwdkRoot=[IO.Path]::GetFullPath($EwdkRoot).TrimEnd('\')
$SignToolPath=[IO.Path]::GetFullPath($SignToolPath)
if ($EwdkRoot -notmatch '^[A-Za-z]:[A-Za-z0-9_ .\\-]*$' -or
    -not (Test-Path -LiteralPath (Join-Path $EwdkRoot 'BuildEnv\SetupBuildEnv.cmd')) -or
    -not $SignToolPath.StartsWith($EwdkRoot+'\',[StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFileName($SignToolPath) -cne 'signtool.exe') { throw 'Expected official mounted EWDK layout' }
$signature=Get-AuthenticodeSignature -LiteralPath $SignToolPath
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'EWDK signing tool is not verified Microsoft code' }
$tempRoot=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')
$build=Join-Path $tempRoot ('GuardKernelBuild-'+[guid]::NewGuid().ToString('N'))
$package=Join-Path $tempRoot ('GuardKernelLab-'+[guid]::NewGuid().ToString('N'))
if ($build -notmatch '^[A-Za-z]:[A-Za-z0-9_ .\\-]+$' -or $PSScriptRoot -notmatch '^[A-Za-z]:[A-Za-z0-9_ .\\-]+$') { throw 'Unsupported shell path characters' }
New-Item -ItemType Directory -Path $build | Out-Null
& (Join-Path $PSScriptRoot 'BuildFromEwdk.cmd') $EwdkRoot $build
if ($LASTEXITCODE -ne 0) { throw ('Kernel build failed; diagnostics preserved: '+$build) }
$driver=Join-Path $build 'bin\GuardKernelLab.sys'
if (-not (Test-Path -LiteralPath $driver)) { throw 'Driver output missing' }
New-Item -ItemType Directory -Path $package | Out-Null
Copy-Item -LiteralPath $driver -Destination $package
Copy-Item -LiteralPath $SignToolPath -Destination $package
$compiler='C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $compiler /nologo /target:exe /optimize+ /warnaserror+ /reference:System.Management.dll ('/out:'+(Join-Path $package 'LabControl.exe')) (Join-Path $PSScriptRoot 'LabControl.cs')
if ($LASTEXITCODE -ne 0) { throw 'Lab controller compilation failed' }
& $compiler /nologo /target:exe /optimize+ /warnaserror+ ('/out:'+(Join-Path $package 'GuardKernelLabAllowed.exe')) (Join-Path $PSScriptRoot '..\Marker.cs')
if ($LASTEXITCODE -ne 0) { throw 'Allowed marker compilation failed' }
& $compiler /nologo /target:exe /optimize+ /warnaserror+ /define:VARIANT_TWO ('/out:'+(Join-Path $package 'GuardKernelLabDenied.exe')) (Join-Path $PSScriptRoot '..\Marker.cs')
if ($LASTEXITCODE -ne 0) { throw 'Denied marker compilation failed' }
$files=@(Get-ChildItem -LiteralPath $package -File | Sort-Object Name | ForEach-Object {
    if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected build output' }
    $_.Attributes=[IO.FileAttributes]::Archive
    [pscustomobject]@{Path=$_.Name;Length=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
})
if ($files.Count -ne 5) { throw 'Unexpected build outputs' }
[pscustomobject]@{Version=1;LabOnly=$true;Files=$files} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $package 'manifest.json') -Encoding UTF8
[pscustomobject]@{Package=$package;BuildRoot=$build;ManifestSha256=(Get-FileHash -LiteralPath (Join-Path $package 'manifest.json') -Algorithm SHA256).Hash}
