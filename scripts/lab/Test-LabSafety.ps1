param([switch]$PolicySigning)
$ErrorActionPreference = 'Stop'
if ($PolicySigning -and $PSVersionTable.PSVersion.Major -lt 7) { throw 'Custom-content PKCS#7 self-test requires the installed PowerShell 7 runtime' }
foreach ($file in @('Get-GuestBaseline.ps1', 'Test-LabSafety.ps1', 'Test-AppLockerFeasibility.ps1', 'Test-AppControlFeasibility.ps1', 'Test-SignedAppControlFeasibility.ps1', 'LabPolicySigning.ps1', 'MarkerProcess.ps1', 'Invoke-AppLockerLab.ps1', 'Build-ServiceLabPackage.ps1', 'Test-ServiceBootstrap.ps1', 'Invoke-ServiceBootstrapLab.ps1', 'Continue-PhoneEnrollmentLab.ps1', 'Import-DeviceProfileLab.ps1', 'kernel/Test-KernelLease.ps1', 'kernel/Invoke-KernelLeaseLab.ps1', 'kernel/Build-KernelLabPackage.ps1')) {
    $tokens = $null
    $parseErrors = $null
    [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file), [ref]$tokens, [ref]$parseErrors) | Out-Null
    if ($parseErrors.Count) { throw ('Parse failure: ' + $file) }
}
$serviceAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-ServiceBootstrap.ps1'),[ref]$null,[ref]$null)
$pathValidator=$serviceAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-ServiceLabPath'},$false)
if ($null -eq $pathValidator) { throw 'Missing service manifest path guard' }
. ([scriptblock]::Create($pathValidator.Extent.Text))
foreach ($valid in @('service\Guard.Service.exe','probe\Guard.Windows.Ipc.Tests.exe','setup\Guard.Setup.exe','setup\ru\PresentationCore.resources.dll')) {
    if (-not (Test-ServiceLabPath $valid $true)) { throw 'Valid service manifest path refused' }
}
foreach ($invalid in @('setup\..\guard.exe','setup\ru\..\guard.exe','setup\ru\foreign.exe','setup\xx\file.resources.dll','C:\Guard.Service.exe','service\..','service\nested\Guard.Service.exe')) {
    if (Test-ServiceLabPath $invalid $true) { throw 'Unsafe service manifest path accepted' }
}
if (Test-ServiceLabPath 'setup\Guard.Setup.exe' $false) { throw 'Setup unexpectedly accepted outside phone mode' }
# The non-PnP kernel probe needs only Root for its explicit Authenticode validation;
# do not reintroduce the unnecessary TrustedPublisher import that the guest rejects.
$kernelProbeAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'kernel/Test-KernelLease.ps1'),[ref]$null,[ref]$null)
$certificateImports=@($kernelProbeAst.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Import-Certificate'},$true))
if ($certificateImports.Count -ne 1 -or $certificateImports[0].Extent.Text -notmatch 'Cert:\\LocalMachine\\Root(?:\s|$)') {
    throw 'Unexpected certificate trust scope in kernel probe'
}
$kernelSource=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'kernel/GuardKernelLab.c') -Raw -Encoding UTF8
if ($kernelSource -match 'KeQueryInterruptTimePrecise\s*\(\s*NULL\s*\)') {
    throw 'KeQueryInterruptTimePrecise requires a writable output pointer, never NULL'
}
# Execute the actual pure manifest/phase validator, never the guest script.
$experimentValidator=$kernelProbeAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-KernelLabExperiment'},$false)
if ($null -eq $experimentValidator) { throw 'Missing experiment binding' }
. ([scriptblock]::Create($experimentValidator.Extent.Text))
Assert-KernelLabExperiment ([pscustomobject]@{Version=1}) 'Experiment'
Assert-KernelLabExperiment ([pscustomobject]@{Version=2;Experiment='Lease'}) 'AfterBoot'
Assert-KernelLabExperiment ([pscustomobject]@{Version=2;Experiment='DenyUnload'}) 'Tamper'
Assert-KernelLabExperiment ([pscustomobject]@{Version=2;Experiment='DenyUnload'}) 'AfterTamperBoot'
foreach ($case in @(
    @([pscustomobject]@{Version=1},'Tamper'),
    @([pscustomobject]@{Version=1;Experiment='DenyUnload'},'Tamper'),
    @([pscustomobject]@{Version=2;Experiment='Lease'},'AfterTamperBoot'),
    @([pscustomobject]@{Version=2;Experiment='DenyUnload'},'Experiment'),
    @([pscustomobject]@{Version=2;Experiment='Unknown'},'Tamper'),
    @([pscustomobject]@{Version=3;Experiment='DenyUnload'},'Tamper')
)) {
    $refused=$false
    try { Assert-KernelLabExperiment $case[0] $case[1] } catch { $refused=$true }
    if (-not $refused) { throw 'Wrong experiment/phase was accepted' }
}
# Exercise the real preflight against stale wrappers/fresh native disk metadata.
# Child scope mocks every Hyper-V/CIM dependency; never invokes the elevated runner or a real VM.
foreach ($runner in @('Invoke-ServiceBootstrapLab.ps1','kernel/Invoke-KernelLeaseLab.ps1')) { & {
    param($RunnerPath)
    $vmName='GuardV2-Lab-20260930'; $vmId=[guid]'8f088b63-9193-4ecc-bb20-415ef11fd4c8'
    $biosGuid=[guid]'236ea6ef-9cc6-4295-9934-6f7497f9d262'; $diskRoot='C:\GuardLabFake\'
    $testDisks=@([pscustomobject]@{ResourceSubType='Microsoft:Hyper-V:Virtual Hard Disk';HostResource=@($diskRoot+'fresh.avhdx')})
    $testTpm=$true; $testSecureBoot='On'; $testMode=$false; $changed=$false; $snapshot=$null
    function Get-VM { [pscustomobject]@{Name=$vmName;Generation=2;Id=$vmId} }
    function Get-VMHardDiskDrive { throw 'Stale wrapper disk was used' }
    function Get-CimInstance { [pscustomobject]@{Name=$vmId.ToString()} }
    function Get-CimAssociatedInstance {
        param($InputObject,$Association,$ResultClassName)
        if ($ResultClassName -eq 'Msvm_VirtualSystemSettingData') { [pscustomobject]@{BIOSGUID=$biosGuid} }
        elseif ($ResultClassName -eq 'Msvm_StorageAllocationSettingData' -and $Association -eq 'Msvm_VirtualSystemSettingDataComponent') { $testDisks }
        else { throw 'Unexpected native metadata query' }
    }
    function Get-VMFirmware { [pscustomobject]@{SecureBoot=$testSecureBoot} }
    function Get-VMSecurity { [pscustomobject]@{TpmEnabled=$testTpm} }
    function Get-VHD { param($Path); if ($Path -ne $diskRoot+'fresh.avhdx') { throw 'Unexpected disk lookup' }; [pscustomobject]@{Size=80GB} }
    $ast=[Management.Automation.Language.Parser]::ParseFile($RunnerPath,[ref]$null,[ref]$null)
    if ($RunnerPath.EndsWith('Invoke-KernelLeaseLab.ps1')) {
        $firmwareCalls=$ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Set-VMFirmware'},$true)
        foreach ($call in $firmwareCalls) {
            if (@($call.CommandElements | Where-Object { $_ -is [Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -like 'SecureBootTemplate*' }).Count) {
                throw 'Lab must not reassign a Secure Boot template after vTPM initialization'
            }
        }
    }
    $definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-PinnedVM'},$false)
    if ($null -eq $definition) { throw 'Missing VM preflight' }
    . ([scriptblock]::Create($definition.Extent.Text))
    if ((Get-PinnedVM).Id -ne $vmId) { throw 'Fresh native disk did not validate' }
    $testSecureBoot='Off'
    try { Get-PinnedVM | Out-Null; throw 'Unexpected disabled Secure Boot accepted' } catch { if ($_.Exception.Message -ne 'VM identity/security changed') { throw } }
    if ($RunnerPath.EndsWith('Invoke-KernelLeaseLab.ps1')) {
        try { Get-PinnedVM -Recovery | Out-Null; throw 'Unbound recovery accepted' } catch { if ($_.Exception.Message -ne 'VM identity/security changed') { throw } }
        $testMode=$true
        if ((Get-PinnedVM).Id -ne $vmId) { throw 'Approved lab test mode refused' }
        $testMode=$false; $changed=$true; $snapshot=[pscustomobject]@{VMId=$vmId}
        if ((Get-PinnedVM -Recovery).Id -ne $vmId) { throw 'Bound firmware recovery refused' }
    }
    $testSecureBoot='On'
    $testDisks[0].HostResource=@('C:\OutsideLab\disk.vhdx')
    try { Get-PinnedVM | Out-Null; throw 'Outside disk accepted' } catch { if ($_.Exception.Message -ne 'Unexpected VM disk') { throw } }
    $testDisks=@()
    try { Get-PinnedVM | Out-Null; throw 'Missing disk accepted' } catch { if ($_.Exception.Message -ne 'Unexpected VM disk count') { throw } }
    $testTpm=$false
    try { Get-PinnedVM | Out-Null; throw 'Missing TPM accepted' } catch { if ($_.Exception.Message -ne 'VM identity/security changed') { throw } }
} (Join-Path $PSScriptRoot $runner) }
foreach ($probe in @('Test-ServiceBootstrap.ps1','kernel/Test-KernelLease.ps1')) {
    try {
        & (Join-Path $PSScriptRoot $probe) -ExpectedUuid ([guid]::Empty) -HostComputerName $env:COMPUTERNAME -PackageRoot 'not-used' -ManifestSha256 'not-used'
        throw 'Service/kernel test host guard did not reject execution'
    } catch {
        if ($_.Exception.Message -ne 'This probe can run only in the validated disposable Hyper-V guest.') { throw }
    }
}
foreach ($phoneMode in @($false, $true)) {
    try {
        # Same positional bool binding as PowerShell Direct -FilePath/-ArgumentList.
        & (Join-Path $PSScriptRoot 'Test-ServiceBootstrap.ps1') ([guid]::Empty) $env:COMPUTERNAME 'not-used' 'not-used' $phoneMode
        throw 'Phone preparation did not refuse host'
    } catch {
        if ($_.Exception.Message -ne 'This probe can run only in the validated disposable Hyper-V guest.') { throw }
    }
    try {
        & (Join-Path $PSScriptRoot 'Import-DeviceProfileLab.ps1') -ExpectedUuid ([guid]::Empty) -HostComputerName $env:COMPUTERNAME -PackageRoot 'not-used' -ProfileSha256 'not-used' -SystemStage:$phoneMode
        throw 'Device profile import did not refuse host'
    } catch {
        if ($_.Exception.Message -ne 'This probe can run only in the validated disposable Hyper-V guest.') { throw }
    }
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
    $control=Join-Path $outputRoot 'LabControl.exe'
    & $compiler /nologo /target:exe /optimize+ /warnaserror+ /reference:System.Management.dll ('/out:'+$control) (Join-Path $PSScriptRoot 'kernel/LabControl.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Lab control compile failed' }
    $controlResult=& $control --arm-lab-once
    if ($LASTEXITCODE -ne 3 -or $controlResult -cne 'LAB_VM_REQUIRED') { throw 'Kernel controller did not refuse host' }
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
