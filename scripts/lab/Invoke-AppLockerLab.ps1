#requires -Version 5.1
#requires -RunAsAdministrator
param([switch]$AppControl, [switch]$SignedAppControl, [switch]$SignedGrantsOnly)
$ErrorActionPreference = 'Stop'
if ($AppControl -and $SignedAppControl) { throw 'Select exactly one experiment' }
if ($SignedGrantsOnly -and -not $SignedAppControl) { throw 'SignedGrantsOnly requires SignedAppControl' }
if ($SignedAppControl -and $PSVersionTable.PSVersion.Major -lt 7) { throw 'Signed lab experiment requires installed PowerShell 7' }
$experimentName = if ($SignedAppControl) {'signed-appcontrol'} elseif ($AppControl) {'appcontrol'} else {'applocker'}
$experimentFile = if ($AppControl) {'Test-AppControlFeasibility.ps1'} else {'Test-AppLockerFeasibility.ps1'}
$vmName = 'GuardV2-Lab-20260930'
$vmId = [guid]'8f088b63-9193-4ecc-bb20-415ef11fd4c8'
$biosGuid = [guid]'236ea6ef-9cc6-4295-9934-6f7497f9d262'
$labRoot = Join-Path $env:LOCALAPPDATA 'GuardV2Lab'
$accessRoot = Join-Path $labRoot 'Access'
$diskRoot = [IO.Path]::GetFullPath((Join-Path $labRoot 'VM\Virtual Hard Disks')).TrimEnd('\') + '\'
$session = $null
$probeStarted = $false
$signedDeployed = $false
$certificate = $null
$signingRoot = $null
$phase = 'host-validation'
$report = [ordered]@{Status='FAIL';SnapshotRecovery='NOT_RUN'}
function Stop-LabVM {
    $target = Get-VM -Id $vmId
    if ($target.Name -ne $vmName) { throw 'Recovery target changed' }
    if ($target.State -eq 'Off') { return }
    Stop-VM -VM $target
    $deadline = [datetime]::UtcNow.AddSeconds(60)
    while ((Get-VM -Id $vmId).State -ne 'Off') {
        if ([datetime]::UtcNow -gt $deadline) { throw 'Graceful VM shutdown timed out; no forced power-off performed' }
        Start-Sleep -Milliseconds 500
    }
}
function Connect-LabVM {
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        try { return (New-PSSession -VMId $vmId -Credential $credential) }
        catch {
            if ($_.Exception.Message -match 'credential|\u0443\u0447\u0435\u0442\u043d\u044b\u0435' -or $attempt -eq 2) { throw }
            Start-Sleep -Seconds 3
        }
    }
}
function Restart-LabVM {
    Remove-PSSession -Session $session
    Stop-LabVM
    Start-VM -VM (Get-VM -Id $vmId)
    Connect-LabVM
}
function Invoke-SignedPhase([string]$Stage) {
    Invoke-Command -Session $session -FilePath (Join-Path $PSScriptRoot 'Test-SignedAppControlFeasibility.ps1') -ArgumentList $biosGuid,$env:COMPUTERNAME,$Stage
}
try {
    Import-Module Hyper-V
    $vm = Get-VM -Id $vmId
    $drives = @(Get-VMHardDiskDrive -VM $vm)
    if ($vm.Name -ne $vmName -or $vm.Generation -ne 2 -or $vm.State -ne 'Running' -or $drives.Count -ne 1 -or
        -not [IO.Path]::GetFullPath($drives[0].Path).StartsWith($diskRoot, [StringComparison]::OrdinalIgnoreCase) -or
        (Get-VHD -Path $drives[0].Path).Size -ne 80GB) { throw 'Unexpected VM target' }
    $system = Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem -Filter ("Name='" + $vm.Id.ToString() + "'")
    $settings = @(Get-CimAssociatedInstance -InputObject $system -Association Msvm_SettingsDefineState -ResultClassName Msvm_VirtualSystemSettingData)
    if ($settings.Count -ne 1 -or [guid]$settings[0].BIOSGUID -ne $biosGuid -or (Get-VMFirmware -VM $vm).SecureBoot -ne 'On' -or -not (Get-VMSecurity -VM $vm).TpmEnabled) { throw 'VM identity or security changed' }
    $snapshot = @(Get-VMSnapshot -VM $vm -Name 'clean-windows-20260930')
    if ($snapshot.Count -ne 1) { throw 'Clean recovery snapshot is not unique' }
    $credential = Import-Clixml -LiteralPath (Join-Path $accessRoot 'guest-credential.xml')
    if ($credential.UserName -ne 'DESKTOP-8C2FU3H\GuardLabAdmin') { throw 'Unexpected guest credential identity' }
    if ($SignedAppControl) {
        $unsignedReport = Get-Content -LiteralPath (Join-Path $accessRoot 'appcontrol-result.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($unsignedReport.Status -ne 'PASS' -or $unsignedReport.SnapshotRecovery -ne 'BOOT_VERIFIED') { throw 'Unsigned App Control/recovery gate not passed' }
        if ($SignedGrantsOnly) {
            $previousSigned = Get-Content -LiteralPath (Join-Path $accessRoot 'signed-appcontrol-result.json') -Raw -Encoding UTF8 | ConvertFrom-Json
            $provenBase = $previousSigned.Experiment.SecondBoot
            if ($previousSigned.SnapshotRecovery -ne 'BOOT_VERIFIED' -or $previousSigned.Experiment.AuthorizedRecovery -ne 'PASS' -or
                $provenBase.Marker -ne 'Blocked' -or -not $provenBase.Signed -or -not $provenBase.Authorized -or -not $provenBase.Enforced) { throw 'Signed base/recovery evidence unavailable for focused grant run' }
            $report.ReusedSignedBaseEvidence = $provenBase.PolicyId
        }
    }
    $phase = 'guest-baseline'
    $session = Connect-LabVM
    $baseline = Invoke-Command -Session $session -FilePath (Join-Path $PSScriptRoot 'Get-GuestBaseline.ps1') -ArgumentList $biosGuid,$env:COMPUTERNAME
    $report.Baseline = $baseline
    if ($SignedGrantsOnly -and ($baseline.Build -ne $previousSigned.Baseline.Build -or $baseline.UpdateBuildRevision -ne $previousSigned.Baseline.UpdateBuildRevision)) { throw 'Guest changed since signed base evidence; run full experiment' }
    Invoke-Command -Session $session -ScriptBlock {
        param([guid]$Uuid)
        $ErrorActionPreference = 'Stop'
        if ([guid](Get-CimInstance Win32_ComputerSystemProduct).UUID -ne $Uuid) { throw 'Guest identity changed' }
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
        $root = 'C:\GuardLab'
        $marker = Join-Path $root '.vm-identity'
        if ((Test-Path -LiteralPath $root) -and (-not (Test-Path -LiteralPath $marker) -or (Get-Content -LiteralPath $marker -Raw).Trim() -ne $Uuid.ToString())) { throw 'Unowned lab directory' }
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $Uuid.ToString() | Set-Content -LiteralPath $marker -Encoding ASCII
    } -ArgumentList $biosGuid
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Marker.cs') -Destination 'C:\GuardLab\Marker.cs' -ToSession $session
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'MarkerProcess.ps1') -Destination 'C:\GuardLab\MarkerProcess.ps1' -ToSession $session
    $phase = $experimentName + '-experiment'
    $probeStarted = $true
    if ($SignedAppControl) {
        . (Join-Path $PSScriptRoot 'LabPolicySigning.ps1')
        $certificate = New-LabPolicyCertificate
        $signingRoot = Join-Path $accessRoot ('lab-signing-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $signingRoot | Out-Null
        $certificatePath = Join-Path $signingRoot 'lab-signer.cer'
        [IO.File]::WriteAllBytes($certificatePath, $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        Copy-Item -LiteralPath $certificatePath -Destination 'C:\GuardLab\lab-signer.cer' -ToSession $session
        $report.Experiment = [ordered]@{PolicyIsProductionCandidate=$false;StrictM1Accepted=$false;PrivateKeyLocation='HOST_MEMORY_ONLY';RecoveryPrepositionedInGuest=$false;AuthorizedRecovery='NOT_RUN'}
        $prepared = Invoke-SignedPhase 'Prepare'
        if (-not $prepared.HasUpdateSigner -or $prepared.BeforePolicy -ne 'Allowed') { throw 'Signed policy preparation failed' }
        $policyId = [guid]$prepared.PolicyId
        $report.Experiment.PolicyId = $policyId.ToString()
        $report.Experiment.Preparation = $prepared
        foreach ($stage in @('audit','enforce','grant','revoke','recovery')) {
            $unsignedPath = Join-Path $signingRoot ($stage + '.unsigned.cip')
            $signedPath = Join-Path $signingRoot ('{' + $policyId.ToString() + '}.' + $stage + '.cip')
            Copy-Item -LiteralPath ('C:\GuardLab\unsigned-' + $stage + '.cip') -Destination $unsignedPath -FromSession $session
            # LAB ONLY: binary rules were generated by this disposable guest; not a production signing service.
            Write-LabSignedPolicy $unsignedPath $signedPath $certificate
            if ($stage -eq 'recovery') { $signedRecoveryPath = $signedPath; continue }
            $remoteDirectory = 'C:\GuardLab\signed-' + $stage
            Invoke-Command -Session $session -ScriptBlock {param($Path); New-Item -ItemType Directory -Path $Path -Force | Out-Null} -ArgumentList $remoteDirectory
            Copy-Item -LiteralPath $signedPath -Destination ($remoteDirectory + '\{' + $policyId.ToString() + '}.cip') -ToSession $session
        }
        $phase = 'signed-audit'
        $signedDeployed = $true
        if (-not $SignedGrantsOnly) {
            $report.Experiment.Audit = Invoke-SignedPhase 'Audit'
            $session = Restart-LabVM
            $report.Experiment.FirstBoot = Invoke-SignedPhase 'VerifyAudit'
        }
        $phase = 'signed-enforced'
        $report.Experiment.Enforce = Invoke-SignedPhase 'Enforce'
        $session = Restart-LabVM
        $report.Experiment.SecondBoot = Invoke-SignedPhase 'VerifyEnforce'
        $phase = 'signed-admin-tamper'
        $report.Experiment.Tamper = Invoke-SignedPhase 'Tamper'
        $phase = 'signed-exact-grant'
        $report.Experiment.Grant = Invoke-SignedPhase 'Grant'
        $session = Restart-LabVM
        $report.Experiment.ExpiredGrantAfterBoot = Invoke-SignedPhase 'VerifyGrant'
        $report.Experiment.NativeOnlyTtlGate = $report.Experiment.ExpiredGrantAfterBoot.NativeOnlyTtlGate
        $phase = 'signed-revoke'
        $report.Experiment.Revoke = Invoke-SignedPhase 'Revoke'
        $session = Restart-LabVM
        $report.Experiment.RevokedBoot = Invoke-SignedPhase 'VerifyRevoke'
    } else {
        $report.Experiment = Invoke-Command -Session $session -FilePath (Join-Path $PSScriptRoot $experimentFile) -ArgumentList $biosGuid,$env:COMPUTERNAME
        if ($report.Experiment.Status -ne 'PASS') { throw $report.Experiment.Failure }
    }
    $report.Status = 'PASS'
} catch {
    $report.Status = 'FAIL'
    $report.FailurePhase = $phase
    $report.Description = $_.Exception.Message
    $report.ErrorId = $_.FullyQualifiedErrorId
} finally {
    if ($signedDeployed) {
        try {
            if (-not $session -or $session.State -ne 'Opened') { $session = Connect-LabVM }
            Invoke-Command -Session $session -ScriptBlock {New-Item -ItemType Directory -Path 'C:\GuardLab\signed-recovery' -Force | Out-Null}
            Copy-Item -LiteralPath $signedRecoveryPath -Destination ('C:\GuardLab\signed-recovery\{' + $policyId.ToString() + '}.cip') -ToSession $session
            $report.Experiment.Recovery = Invoke-SignedPhase 'Recovery'
            $session = Restart-LabVM
            $report.Experiment.Removal = Invoke-SignedPhase 'Remove'
            $report.Experiment.AuthorizedRecovery = 'PASS'
        } catch {
            $report.Status = 'FAIL'
            $report.Experiment.AuthorizedRecovery = 'FAIL'
            $report.SignedRecoveryDescription = $_.Exception.Message
        }
    }
    if ($session) { Remove-PSSession -Session $session }
    if ($probeStarted) {
        try {
            Stop-LabVM
            Restore-VMSnapshot -VMSnapshot $snapshot[0] -Confirm:$false
            Start-VM -VM (Get-VM -Id $vmId)
            $report.SnapshotRecovery = 'RESTORED'
            $bootSession = $null
            try {
                $bootSession = Connect-LabVM
                $after = Invoke-Command -Session $bootSession -FilePath (Join-Path $PSScriptRoot 'Get-GuestBaseline.ps1') -ArgumentList $biosGuid,$env:COMPUTERNAME
                if (@($after.AppLockerCollections | Where-Object { $_.Rules -gt 0 }).Count) { throw 'Unexpected policy after snapshot recovery' }
                $beforeCi = @($baseline.AppControlPolicies | Sort-Object PolicyID | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.PolicyID,$_.IsSignedPolicy,$_.IsOnDisk,$_.IsEnforced }) -join ';'
                $afterCi = @($after.AppControlPolicies | Sort-Object PolicyID | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.PolicyID,$_.IsSignedPolicy,$_.IsOnDisk,$_.IsEnforced }) -join ';'
                if ($beforeCi -ne $afterCi) { throw 'Native App Control policy inventory changed after snapshot recovery' }
                $report.AfterRecovery = $after
                $report.SnapshotRecovery = 'BOOT_VERIFIED'
            } finally {
                if ($bootSession) { Remove-PSSession -Session $bootSession }
            }
        } catch {
            $report.Status = 'FAIL'
            $report.SnapshotRecovery = 'FAIL'
            $report.RecoveryDescription = $_.Exception.Message
        }
    }
    if ($certificate) { $certificate.Dispose() }
    if ($signingRoot -and $report.SnapshotRecovery -eq 'BOOT_VERIFIED') {
        $folder = Get-Item -LiteralPath $signingRoot
        if ($folder.Parent.FullName -ne [IO.Path]::GetFullPath($accessRoot) -or $folder.Name -notmatch '^lab-signing-[a-f0-9]{32}$' -or
            ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected signing artifact directory; cleanup refused' }
        Remove-Item -LiteralPath $folder.FullName -Recurse
        $report.SigningArtifactsRemoved = -not (Test-Path -LiteralPath $signingRoot)
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $accessRoot ($experimentName + '-result.json')) -Encoding UTF8
}
if ($report.Status -eq 'PASS') { exit 0 } else { exit 1 }
