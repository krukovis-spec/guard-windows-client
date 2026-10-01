param(
    [Parameter(Mandatory=$true)][guid]$ExpectedUuid,
    [Parameter(Mandatory=$true)][string]$HostComputerName,
    [Parameter(Mandatory=$true)][string]$PackageRoot,
    [Parameter(Mandatory=$true)][string]$ManifestSha256
)
$ErrorActionPreference = 'Stop'
$machine = Get-CimInstance Win32_ComputerSystem
$product = Get-CimInstance Win32_ComputerSystemProduct
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($env:COMPUTERNAME -eq $HostComputerName -or [guid]$product.UUID -ne $ExpectedUuid -or
    $ExpectedUuid -ne [guid]'236ea6ef-9cc6-4295-9934-6f7497f9d262' -or
    $machine.Manufacturer -ne 'Microsoft Corporation' -or $machine.Model -ne 'Virtual Machine' -or
    -not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This probe can run only in the validated disposable Hyper-V guest.'
}
$identity.Dispose()
$install = Join-Path $env:ProgramFiles 'Guard'
$data = Join-Path $env:ProgramData 'Guard'
if ((Get-Service -Name Guard -ErrorAction SilentlyContinue) -or
    @(Get-ChildItem -LiteralPath $env:ProgramFiles -Force | Where-Object Name -eq 'Guard').Count -or
    @(Get-ChildItem -LiteralPath $env:ProgramData -Force | Where-Object Name -eq 'Guard').Count) {
    throw 'Existing Guard installation/data; laboratory installer refuses to overwrite it.'
}
if ($PackageRoot -notmatch '^C:\\GuardLab\\ServiceSmoke-[a-f0-9]{32}$' -or $ManifestSha256 -notmatch '^[A-F0-9]{64}$') { throw 'Invalid lab package binding' }
$manifestPath = Join-Path $PackageRoot 'manifest.json'
if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -cne $ManifestSha256) { throw 'Lab manifest changed' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.Version -ne 1 -or $manifest.LabOnly -ne $true -or $manifest.Files.Count -lt 10 -or $manifest.Files.Count -gt 2000) { throw 'Invalid lab manifest' }
$expected = @{}
foreach ($entry in $manifest.Files) {
    if ($entry.Path -notmatch '^(service|probe)\\[A-Za-z0-9_.-]+$' -or $expected.ContainsKey($entry.Path) -or
        $entry.Sha256 -notmatch '^[A-F0-9]{64}$' -or $entry.Length -le 0) { throw 'Invalid lab file entry' }
    $expected[$entry.Path] = $true
    $file = Get-Item -LiteralPath (Join-Path $PackageRoot $entry.Path)
    if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint -or $file.Length -ne $entry.Length -or
        (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -cne $entry.Sha256) { throw 'Lab payload mismatch' }
}
$actual = @(Get-ChildItem -LiteralPath $PackageRoot -File -Recurse | Where-Object FullName -ne $manifestPath)
if ($actual.Count -ne $expected.Count) { throw 'Extra lab payload' }
foreach ($folder in @($PackageRoot, (Join-Path $PackageRoot 'service'), (Join-Path $PackageRoot 'probe'), 'C:\GuardLab', $env:ProgramFiles, $env:ProgramData)) {
    if ((Get-Item -LiteralPath $folder).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected lab directory' }
}
foreach ($required in @('service\Guard.Service.exe','probe\Guard.Windows.Ipc.Tests.exe')) {
    if (-not $expected.ContainsKey($required)) { throw 'Lab entry point missing' }
}
New-Item -ItemType Directory -Path $install | Out-Null
# No legacy files, policy, browser/account changes or production credentials. Snapshot is the recovery route.
Get-ChildItem -LiteralPath (Join-Path $PackageRoot 'service') -File | Copy-Item -Destination $install
$binary = '"' + (Join-Path $install 'Guard.Service.exe') + '"'
New-Service -Name Guard -DisplayName 'Guard v2 - disposable VM test' -BinaryPathName ($binary + ' --initialize-authoritative-state') -StartupType Automatic | Out-Null
Start-Service -Name Guard
(Get-Service Guard).WaitForStatus('Running', [timespan]::FromSeconds(30))
Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class GuardLabPipeWait { [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] public static extern bool WaitNamedPipe(string name, uint timeout); }'
$deadline = [datetime]::UtcNow.AddSeconds(30)
while (-not [GuardLabPipeWait]::WaitNamedPipe('\\.\pipe\Guard.V2.AdminSetup.v1', 500)) {
    if ([datetime]::UtcNow -gt $deadline -or (Get-Service Guard).Status -ne 'Running') { throw 'Bootstrap pipe did not become ready' }
    Start-Sleep -Milliseconds 200
}
$probe = Join-Path $PackageRoot 'probe\Guard.Windows.Ipc.Tests.exe'
function Invoke-ReadOnlyProbe([string]$Mode) {
    $text = & $probe --installed-service-lab $Mode
    if ($LASTEXITCODE -ne 0) { throw ('Installed-service probe refused: ' + ($text -join ' ')) }
    $value = ($text -join '') | ConvertFrom-Json
    if ($value.status -ne 'PASS') { throw 'Installed-service probe did not pass' }
    $value
}
$bootstrap = Invoke-ReadOnlyProbe 'reject-bootstrap'
Stop-Service Guard
(Get-Service Guard).WaitForStatus('Stopped', [timespan]::FromSeconds(30))
$changed = Invoke-CimMethod -InputObject (Get-CimInstance Win32_Service -Filter "Name='Guard'") -MethodName Change -Arguments @{PathName=$binary}
if ($changed.ReturnValue -ne 0) { throw 'Removing one-shot SCM argument failed' }
Start-Service Guard
$first = Invoke-ReadOnlyProbe 'inspect'
Stop-Service Guard
(Get-Service Guard).WaitForStatus('Stopped', [timespan]::FromSeconds(30))
Start-Service Guard
$second = Invoke-ReadOnlyProbe 'inspect'
if ($first.descriptorSha256 -cne $second.descriptorSha256) { throw 'Device identity changed on normal service restart' }
$service = Get-CimInstance Win32_Service -Filter "Name='Guard'"
if ($service.StartName -ne 'LocalSystem' -or $service.PathName -cne $binary -or $service.State -ne 'Running') { throw 'Final SCM identity mismatch' }
[pscustomobject]@{Status='PASS';BootstrapEndpoint=$bootstrap.bootstrapEndpoint;First=$first;AfterRestart=$second;ServiceAccount=$service.StartName;PolicyWrites=$false;ProtectionAccepted=$false}
