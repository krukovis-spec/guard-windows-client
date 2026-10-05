param([switch]$PolicySigning)
$ErrorActionPreference = 'Stop'
if ($PolicySigning -and $PSVersionTable.PSVersion.Major -lt 7) { throw 'Custom-content PKCS#7 self-test requires the installed PowerShell 7 runtime' }
foreach ($file in @('Get-GuestBaseline.ps1', 'Test-LabSafety.ps1', 'Test-AppLockerFeasibility.ps1', 'Test-AppControlFeasibility.ps1', 'Test-SignedAppControlFeasibility.ps1', 'LabPolicySigning.ps1', 'MarkerProcess.ps1', 'Invoke-AppLockerLab.ps1', 'Build-ServiceLabPackage.ps1', 'Test-ServiceBootstrap.ps1', 'Invoke-ServiceBootstrapLab.ps1')) {
    $tokens = $null
    $parseErrors = $null
    [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file), [ref]$tokens, [ref]$parseErrors) | Out-Null
    if ($parseErrors.Count) { throw ('Parse failure: ' + $file) }
}
# Exercise the real preflight function against a stale wrapper and fresh native disk metadata.
# Child scope mocks every Hyper-V/CIM dependency; never invokes the elevated runner or a real VM.
& {
    $vmName='GuardV2-Lab-20260930'; $vmId=[guid]'8f088b63-9193-4ecc-bb20-415ef11fd4c8'
    $biosGuid=[guid]'236ea6ef-9cc6-4295-9934-6f7497f9d262'; $diskRoot='C:\GuardLabFake\'
    $testDisks=@([pscustomobject]@{ResourceSubType='Microsoft:Hyper-V:Virtual Hard Disk';HostResource=@($diskRoot+'fresh.avhdx')})
    $testTpm=$true
    function Get-VM { [pscustomobject]@{Name=$vmName;Generation=2;Id=$vmId} }
    function Get-VMHardDiskDrive { throw 'Stale wrapper disk was used' }
    function Get-CimInstance { [pscustomobject]@{Name=$vmId.ToString()} }
    function Get-CimAssociatedInstance {
        param($InputObject,$Association,$ResultClassName)
        if ($ResultClassName -eq 'Msvm_VirtualSystemSettingData') { [pscustomobject]@{BIOSGUID=$biosGuid} }
        elseif ($ResultClassName -eq 'Msvm_StorageAllocationSettingData' -and $Association -eq 'Msvm_VirtualSystemSettingDataComponent') { $testDisks }
        else { throw 'Unexpected native metadata query' }
    }
    function Get-VMFirmware { [pscustomobject]@{SecureBoot='On'} }
    function Get-VMSecurity { [pscustomobject]@{TpmEnabled=$testTpm} }
    function Get-VHD { param($Path); if ($Path -ne $diskRoot+'fresh.avhdx') { throw 'Unexpected disk lookup' }; [pscustomobject]@{Size=80GB} }
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Invoke-ServiceBootstrapLab.ps1'),[ref]$null,[ref]$null)
    $definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-PinnedVM'},$false)
    if ($null -eq $definition) { throw 'Missing VM preflight' }
    . ([scriptblock]::Create($definition.Extent.Text))
    if ((Get-PinnedVM).Id -ne $vmId) { throw 'Fresh native disk did not validate' }
    $testDisks[0].HostResource=@('C:\OutsideLab\disk.vhdx')
    try { Get-PinnedVM | Out-Null; throw 'Outside disk accepted' } catch { if ($_.Exception.Message -ne 'Unexpected VM disk') { throw } }
    $testDisks=@()
    try { Get-PinnedVM | Out-Null; throw 'Missing disk accepted' } catch { if ($_.Exception.Message -ne 'Unexpected VM disk count') { throw } }
    $testTpm=$false
    try { Get-PinnedVM | Out-Null; throw 'Missing TPM accepted' } catch { if ($_.Exception.Message -ne 'VM identity/security changed') { throw } }
}
try {
    & (Join-Path $PSScriptRoot 'Test-ServiceBootstrap.ps1') -ExpectedUuid ([guid]::Empty) -HostComputerName $env:COMPUTERNAME -PackageRoot 'not-used' -ManifestSha256 'not-used'
    throw 'Service test host guard did not reject execution'
} catch {
    if ($_.Exception.Message -ne 'This probe can run only in the validated disposable Hyper-V guest.') { throw }
}
foreach ($probe in @('Get-GuestBaseline.ps1', 'Test-AppLockerFeasibility.ps1', 'Test-AppControlFeasibility.ps1', 'Test-SignedAppControlFeasibility.ps1')) {
    try {
        & (Join-Path $PSScriptRoot $probe) -ExpectedUuid ([guid]::Empty) -HostComputerName $env:COMPUTERNAME
        throw 'Host guard did not reject execution'
    } catch {
        if ($_.Exception.Message -ne 'This probe can run only in the validated disposable Hyper-V guest.') { throw }
    }
}
$compiler = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw 'Existing Framework compiler unavailable' }
$tempRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
$outputRoot = [IO.Path]::GetFullPath((Join-Path $tempRoot ('guard-lab-marker-' + [guid]::NewGuid().ToString('N'))))
if (-not $outputRoot.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected temporary output root' }
New-Item -ItemType Directory -Path $outputRoot | Out-Null
$markerOne = Join-Path $outputRoot 'marker-v1.exe'
$markerTwo = Join-Path $outputRoot 'marker-v2.exe'
. (Join-Path $PSScriptRoot 'MarkerProcess.ps1')
. (Join-Path $PSScriptRoot 'LabPolicySigning.ps1')
$certificate = $null
try {
    if ($PolicySigning) {
        $certificate = New-LabPolicyCertificate
        $samplePath = Join-Path $outputRoot 'sample.cip'
        $signedPath = Join-Path $outputRoot 'sample.p7'
        [IO.File]::WriteAllBytes($samplePath, [Text.Encoding]::UTF8.GetBytes('LAB ONLY signature self-test'))
        Write-LabSignedPolicy $samplePath $signedPath $certificate
        $badSignature = [IO.File]::ReadAllBytes($signedPath)
        $badSignature[$badSignature.Length - 1] = $badSignature[$badSignature.Length - 1] -bxor 1
        $badCms = New-Object Security.Cryptography.Pkcs.SignedCms
        $rejected = $false
        try { $badCms.Decode($badSignature); $badCms.CheckSignature($true) } catch { $rejected = $true }
        if (-not $rejected) { throw 'Corrupt signature was accepted' }
    }
    & $compiler /nologo /target:exe /optimize+ /warnaserror+ ('/out:' + $markerOne) (Join-Path $PSScriptRoot 'Marker.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Marker v1 compile failed' }
    & $compiler /nologo /target:exe /optimize+ /warnaserror+ /define:VARIANT_TWO ('/out:' + $markerTwo) (Join-Path $PSScriptRoot 'Marker.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Marker v2 compile failed' }
    foreach ($marker in @($markerOne, $markerTwo)) {
        if ((Get-MarkerDecision $marker -SelfTest) -ne 'Allowed') { throw 'Marker self-test blocked' }
    }
    $hashOne = (Get-FileHash -LiteralPath $markerOne -Algorithm SHA256).Hash
    $hashTwo = (Get-FileHash -LiteralPath $markerTwo -Algorithm SHA256).Hash
    if ($hashOne -eq $hashTwo) { throw 'Marker variants must have distinct exact identities' }
} finally {
    if ($certificate) { $certificate.Dispose() }
    $folder = Get-Item -LiteralPath $outputRoot
    if ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Temporary directory became a reparse point; cleanup refused' }
    Remove-Item -LiteralPath $folder.FullName -Recurse
}
[pscustomobject]@{Status='PASS';HostGuard='REJECTED';LabSignature=$(if ($PolicySigning) {'VERIFIED_WITH_TAMPER_REJECTION'} else {'NOT_RUN'});TemporaryFilesRemoved=(-not (Test-Path -LiteralPath $outputRoot));VariantOneSha256=$hashOne;VariantTwoSha256=$hashTwo}
