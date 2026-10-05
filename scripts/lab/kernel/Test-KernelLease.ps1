param(
    [Parameter(Mandatory=$true)][guid]$ExpectedUuid,
    [Parameter(Mandatory=$true)][string]$HostComputerName,
    [Parameter(Mandatory=$true)][string]$PackageRoot,
    [Parameter(Mandatory=$true)][string]$ManifestSha256,
    [ValidateSet('Experiment','AfterBoot')][string]$Phase='Experiment'
)
$ErrorActionPreference='Stop'
$script:labPhase='identity-check'
trap {
    if ($script:labPhase -eq 'identity-check') { throw $_ }
    throw ('Kernel lab phase='+$script:labPhase+'; type='+$_.Exception.GetBaseException().GetType().Name+
        '; id='+$_.FullyQualifiedErrorId+'; line='+$_.InvocationInfo.ScriptLineNumber)
}
$machine=Get-CimInstance Win32_ComputerSystem
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if ($env:COMPUTERNAME -eq $HostComputerName -or
    [guid](Get-CimInstance Win32_ComputerSystemProduct).UUID -ne $ExpectedUuid -or
    $ExpectedUuid -ne [guid]'236ea6ef-9cc6-4295-9934-6f7497f9d262' -or
    $machine.Manufacturer -ne 'Microsoft Corporation' -or $machine.Model -ne 'Virtual Machine' -or
    -not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This probe can run only in the validated disposable Hyper-V guest.'
}
$identity.Dispose()
$script:labPhase='package-validation'
if ($PackageRoot -notmatch '^C:\\GuardLab\\KernelLease-[a-f0-9]{32}$' -or $ManifestSha256 -notmatch '^[A-F0-9]{64}$') { throw 'Invalid kernel lab package binding' }
foreach ($folder in @('C:\GuardLab',$PackageRoot)) {
    if ((Get-Item -LiteralPath $folder -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected lab directory' }
}
$manifestPath=Join-Path $PackageRoot 'manifest.json'
if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -cne $ManifestSha256) { throw 'Lab manifest changed' }
$manifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$names=@('GuardKernelLab.sys','LabControl.exe','GuardKernelLabAllowed.exe','GuardKernelLabDenied.exe','signtool.exe')
if ($manifest.Version -ne 1 -or $manifest.LabOnly -ne $true -or $manifest.Files.Count -ne $names.Count) { throw 'Invalid lab manifest' }
$seen=@{}
foreach ($entry in $manifest.Files) {
    if ($entry.Path -cnotin $names -or $seen.ContainsKey($entry.Path) -or $entry.Sha256 -notmatch '^[A-F0-9]{64}$') { throw 'Unexpected lab file' }
    $seen[$entry.Path]=$true
    $file=Get-Item -LiteralPath (Join-Path $PackageRoot $entry.Path)
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -ne $entry.Length -or
        (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -cne $entry.Sha256) { throw 'Lab payload changed' }
}
if ((Confirm-SecureBootUEFI) -or (Get-Service Guard -ErrorAction SilentlyContinue)) { throw 'Lab requires approved test mode and no Guard user-mode service' }
$allowed=Join-Path $PackageRoot 'GuardKernelLabAllowed.exe'
$denied=Join-Path $PackageRoot 'GuardKernelLabDenied.exe'
$control=Join-Path $PackageRoot 'LabControl.exe'
function Assert-Blocked([string]$Path) {
    $p=New-Object Diagnostics.Process
    $p.StartInfo.FileName=$Path; $p.StartInfo.Arguments='--self-test'; $p.StartInfo.UseShellExecute=$false
    try {
        try { [void]$p.Start() }
        catch {
            $failure=$_.Exception.GetBaseException()
            if ($failure -is [ComponentModel.Win32Exception] -and $failure.NativeErrorCode -eq 5) { return }
            throw
        }
        if (-not $p.WaitForExit(5000)) { $p.Kill(); [void]$p.WaitForExit(5000) }
        throw 'Expected kernel access-denied; marker started instead'
    } finally { $p.Dispose() }
}
function Invoke-DriverControl([string]$Action) {
    $output=& "$env:WINDIR\System32\sc.exe" $Action GuardKernelLab 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Lab driver '+$Action+' failed: '+($output -join ' ')) }
}
if ($Phase -eq 'AfterBoot') {
    $driver=Get-CimInstance Win32_SystemDriver -Filter "Name='GuardKernelLab'"
    if ($driver.State -ne 'Running' -or $driver.StartMode -ne 'Auto') { throw 'Lab driver did not restart automatically' }
    Assert-Blocked $allowed; Assert-Blocked $denied
    [pscustomobject]@{Status='PASS';BootGrant='DENIED_WITHOUT_REARM';GuardUserModeService=$false}
    return
}
if (Get-CimInstance Win32_SystemDriver -Filter "Name='GuardKernelLab'") { throw 'Existing lab driver; no overwrite' }
# The only private signing key exists inside this disposable guest and is removed by snapshot recovery.
$script:labPhase='create-test-certificate'
$certificate=New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Guard Kernel LAB ONLY' -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddDays(3)
$certificatePath=Join-Path $PackageRoot 'lab-public.cer'
$script:labPhase='trust-test-certificate'
Export-Certificate -Cert $certificate -FilePath $certificatePath | Out-Null
Import-Certificate -FilePath $certificatePath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath $certificatePath -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
# Preserve the hash-verified unsigned input; subsequent stages revalidate it, not a modified package member.
$driverPath=Join-Path $PackageRoot 'GuardKernelLab-signed.sys'
if (Test-Path -LiteralPath $driverPath) { throw 'Signed output already exists' }
Copy-Item -LiteralPath (Join-Path $PackageRoot 'GuardKernelLab.sys') -Destination $driverPath
$script:labPhase='sign-test-driver'
$signatureOutput=& (Join-Path $PackageRoot 'signtool.exe') sign /sm /s My /sha1 $certificate.Thumbprint /fd SHA256 $driverPath 2>&1
if ($LASTEXITCODE -ne 0) { throw ('Lab signing failed: '+($signatureOutput -join ' ')) }
$signature=Get-AuthenticodeSignature -LiteralPath $driverPath
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint) { throw 'Lab driver signature not verified' }
$script:labPhase='register-driver'
$createOutput=& "$env:WINDIR\System32\sc.exe" create GuardKernelLab type= kernel start= auto binPath= ('"'+$driverPath+'"') 2>&1
if ($LASTEXITCODE -ne 0) { throw ('Lab driver registration failed: '+($createOutput -join ' ')) }
$script:labPhase='start-driver'
Invoke-DriverControl 'start'
$script:labPhase='initial-default-deny'
Assert-Blocked $allowed; Assert-Blocked $denied
$script:labPhase='arm-once'
$clock=[Diagnostics.Stopwatch]::StartNew()
$armOutput=& $control --arm-lab-once
if ($LASTEXITCODE -ne 0 -or $armOutput -cne 'LAB_ARMED_20_SECONDS') { throw ('Lab arm failed: '+$armOutput) }
$repeatOutput=& $control --arm-lab-once
if ($LASTEXITCODE -ne 5 -or $repeatOutput -cne 'ARM_WIN32=5') { throw 'Repeated arm was not refused' }
Assert-Blocked $denied
$running=New-Object Diagnostics.Process
$running.StartInfo.FileName=$allowed; $running.StartInfo.Arguments='--hold-seconds 120'
$running.StartInfo.UseShellExecute=$false; $running.StartInfo.RedirectStandardOutput=$true
$clockBefore=Get-Date
$wallClockChanged=$false
try {
    $script:labPhase='start-allowed-marker'
    [void]$running.Start()
    $started=$running.StandardOutput.ReadLineAsync()
    if (-not $started.Wait(5000) -or $started.Result -cne 'MARKER_STARTED v1') { throw 'Allowed marker did not execute' }
    $script:labPhase='rollback-clock'
    Set-Date -Date $clockBefore.AddMinutes(-30) | Out-Null
    $wallClockChanged=$true
    $rollbackObserved=((Get-Date)-$clockBefore).TotalMinutes -lt -29
    if (-not $rollbackObserved) { throw 'Clock rollback was not observable' }
    $script:labPhase='wait-kernel-expiry'
    if (-not $running.WaitForExit(25000)) { throw 'Kernel did not terminate the active marker at expiry' }
    $expirySeconds=$clock.Elapsed.TotalSeconds
    if ($running.ExitCode -ne -1073741790 -or $expirySeconds -lt 19 -or $expirySeconds -gt 26) { throw 'Unexpected termination status/deadline' }
} finally {
    if ($wallClockChanged) { Set-Date -Date $clockBefore.AddSeconds($clock.Elapsed.TotalSeconds) | Out-Null }
    try { if (-not $running.HasExited) { $running.Kill(); [void]$running.WaitForExit(5000) } } catch { }
    $running.Dispose()
}
Assert-Blocked $allowed; Assert-Blocked $denied
$script:labPhase='admin-unload'
Invoke-DriverControl 'stop'
# Deliberately measure the bypass, rather than calling successful TTL a solved administrator boundary.
$afterUnload=& $denied --self-test
if ($LASTEXITCODE -ne 0 -or $afterUnload -cne 'MARKER_SELF_TEST_PASS v2') { throw 'Admin-unload outcome was not measured' }
Invoke-DriverControl 'start'
Assert-Blocked $allowed
$armOutput=& $control --arm-lab-once
if ($LASTEXITCODE -ne 0) { throw 'Pre-reboot lab arm failed' }
[pscustomobject]@{Status='PASS';InitialDefaultDeny='PASS';OtherMarker='DENIED';RepeatedArm='REJECTED';
    ActiveExpirySeconds=[math]::Round($expirySeconds,3);ActiveExpiryExit='C0000022';WallClockRollback='OBSERVED';
    GuardUserModeService=$false;AfterExpiryLaunch='DENIED';AdministratorUnload='BYPASS_CONFIRMED';
    ReloadDefaultDeny='PASS';BeforeRebootLease='ARMED';M1Accepted=$false;SleepResume='NOT_RUN'}
