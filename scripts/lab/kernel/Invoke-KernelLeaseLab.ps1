#requires -Version 5.1
#requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][string]$PackageRoot,[Parameter(Mandatory=$true)][string]$ManifestSha256)
$ErrorActionPreference='Stop'
$vmName='GuardV2-Lab-20260930'
$vmId=[guid]'8f088b63-9193-4ecc-bb20-415ef11fd4c8'
$biosGuid=[guid]'236ea6ef-9cc6-4295-9934-6f7497f9d262'
$labRoot=Join-Path $env:LOCALAPPDATA 'GuardV2Lab'
$accessRoot=Join-Path $labRoot 'Access'
$diskRoot=[IO.Path]::GetFullPath((Join-Path $labRoot 'VM\Virtual Hard Disks')).TrimEnd('\')+'\'
$runId=[guid]::NewGuid().ToString('N')
$guestPackage='C:\GuardLab\KernelLease-'+$runId
$resultPath=Join-Path $accessRoot ('kernel-lease-'+$runId+'.json')
$session=$null; $snapshot=$null; $changed=$false; $testMode=$false; $phase='host-validation'
$report=[ordered]@{Status='RUNNING';RunId=$runId;VmId=$vmId.ToString();ManifestSha256=$ManifestSha256;SnapshotRecovery='NOT_RUN';M1Accepted=$false}
function Get-PinnedVM([switch]$Recovery) {
    $vm=Get-VM -Id $vmId
    if ($vm.Name -ne $vmName -or $vm.Generation -ne 2) { throw 'Unexpected VM target' }
    $system=Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem -Filter ("Name='"+$vmId.ToString()+"'")
    $settings=@(Get-CimAssociatedInstance -InputObject $system -Association Msvm_SettingsDefineState -ResultClassName Msvm_VirtualSystemSettingData)
    $expectedBoot=if ($testMode) {'Off'} else {'On'}
    $allowBootRecovery=$Recovery -and $changed -and $snapshot -and $snapshot.VMId -eq $vmId
    if ($settings.Count -ne 1 -or [guid]$settings[0].BIOSGUID -ne $biosGuid -or
        (-not $allowBootRecovery -and (Get-VMFirmware -VM $vm).SecureBoot -ne $expectedBoot) -or
        -not (Get-VMSecurity -VM $vm).TpmEnabled) { throw 'VM identity/security changed' }
    $disks=@(Get-CimAssociatedInstance -InputObject $settings[0] -Association Msvm_VirtualSystemSettingDataComponent -ResultClassName Msvm_StorageAllocationSettingData |
        Where-Object ResourceSubType -eq 'Microsoft:Hyper-V:Virtual Hard Disk')
    if ($disks.Count -ne 1 -or @($disks[0].HostResource).Count -ne 1) { throw 'Unexpected VM disk count' }
    $diskPath=[IO.Path]::GetFullPath($disks[0].HostResource[0])
    if (-not $diskPath.StartsWith($diskRoot,[StringComparison]::OrdinalIgnoreCase) -or (Get-VHD -Path $diskPath).Size -ne 80GB) { throw 'Unexpected VM disk' }
    $vm
}
function Connect-Guest {
    $deadline=[datetime]::UtcNow.AddSeconds(120)
    do {
        try { return New-PSSession -VMId $vmId -Credential $credential }
        catch {
            if ([datetime]::UtcNow -gt $deadline -or $_.Exception.Message -match 'credential|authentication|\u0443\u0447[\u0435\u0451]\u0442\u043d|\u043f\u0430\u0440\u043e\u043b') { throw }
            Start-Sleep -Seconds 3
        }
    } while ($true)
}
function Read-GuestState {
    Invoke-Command -Session $session -ScriptBlock {
        param($Uuid,$HostName)
        $ErrorActionPreference='Stop'
        $system=Get-CimInstance Win32_ComputerSystem
        if ($env:COMPUTERNAME -eq $HostName -or [guid](Get-CimInstance Win32_ComputerSystemProduct).UUID -ne [guid]$Uuid -or
            $system.Manufacturer -ne 'Microsoft Corporation' -or $system.Model -ne 'Virtual Machine') { throw 'Guest identity changed' }
        $bcd=& "$env:WINDIR\System32\bcdedit.exe" /enum all
        if ($LASTEXITCODE -ne 0) { throw 'Cannot observe guest boot configuration' }
        $testSigning=[bool]($bcd -match '^\s*testsigning\s+Yes\s*$')
        [pscustomobject]@{ComputerName=$env:COMPUTERNAME;SecureBoot=[bool](Confirm-SecureBootUEFI);TestSigning=$testSigning;
            BitLockerProtection=(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus.ToString();
            HasGuard=[bool](Get-Service Guard -ErrorAction SilentlyContinue);
            HasLabDriver=[bool](Get-CimInstance Win32_SystemDriver -Filter "Name='GuardKernelLab'");
            HasGuardData=[bool](Test-Path -LiteralPath (Join-Path $env:ProgramData 'Guard'))}
    } -ArgumentList $biosGuid,$env:COMPUTERNAME
}
function Stop-PinnedVM([switch]$Recovery) {
    if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue; $script:session=$null }
    $vm=Get-PinnedVM -Recovery:$Recovery
    if ($vm.State -ne 'Off') {
        $stopJob=Stop-VM -VM $vm -AsJob
        $deadline=[datetime]::UtcNow.AddSeconds(60)
        try {
            while ($stopJob.State -in @('NotStarted','Running')) {
                if ([datetime]::UtcNow -gt $deadline) { throw 'Graceful VM shutdown timed out; checkpoint retained' }
                Wait-Job -Job $stopJob -Timeout 10 | Out-Null
            }
            Receive-Job -Job $stopJob -ErrorAction Stop | Out-Null
            if ((Get-VM -Id $vmId).State -ne 'Off') { throw 'VM did not shut down' }
        } finally {
            if ($stopJob.State -in @('NotStarted','Running')) { Stop-Job -Job $stopJob }
            Remove-Job -Job $stopJob
        }
    }
}
function Start-PinnedVM {
    Start-VM -VM (Get-PinnedVM) | Out-Null
    $script:session=Connect-Guest
    $state=Read-GuestState
    if ($state.ComputerName -ne 'DESKTOP-8C2FU3H' -or $state.HasGuard -or $state.HasGuardData) { throw 'Unexpected guest after boot' }
    $state
}
function Invoke-GuestProbe([string]$ProbePhase) {
    $job=Invoke-Command -Session $session -FilePath (Join-Path $PSScriptRoot 'Test-KernelLease.ps1') -AsJob -ArgumentList $biosGuid,$env:COMPUTERNAME,$guestPackage,$ManifestSha256,$ProbePhase
    $deadline=[datetime]::UtcNow.AddSeconds(180)
    try {
        while ($job.State -in @('NotStarted','Running')) {
            if ([datetime]::UtcNow -gt $deadline) { throw 'Guest kernel probe exceeded 180 seconds; restore snapshot' }
            Wait-Job -Job $job -Timeout 10 | Out-Null
        }
        Receive-Job -Job $job -ErrorAction Stop
        if ($job.State -ne 'Completed') { throw 'Guest kernel probe did not complete' }
    } finally {
        if ($job.State -in @('NotStarted','Running')) { Stop-Job -Job $job }
        Remove-Job -Job $job
    }
}
try {
    Import-Module Hyper-V
    $package=Get-Item -LiteralPath $PackageRoot
    if ($package.Parent.FullName -ne [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') -or
        $package.Name -notmatch '^GuardKernelLab-[a-f0-9]{32}$' -or ($package.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $ManifestSha256 -notmatch '^[A-F0-9]{64}$' -or
        (Get-FileHash -LiteralPath (Join-Path $PackageRoot 'manifest.json') -Algorithm SHA256).Hash -cne $ManifestSha256) { throw 'Untrusted lab package' }
    if (@(Get-ChildItem -LiteralPath $PackageRoot -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Redirected lab payload' }
    $manifest=Get-Content -LiteralPath (Join-Path $PackageRoot 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($manifest.Version -eq 1 -and -not $manifest.PSObject.Properties['Experiment']) { $experiment='Lease' }
    elseif ($manifest.Version -eq 2 -and $manifest.Experiment -cin @('Lease','DenyUnload')) { $experiment=$manifest.Experiment }
    else { throw 'Invalid kernel lab experiment manifest' }
    $report.ExperimentKind=$experiment
    $vm=Get-PinnedVM
    if ($vm.State -ne 'Running' -or @(Get-VMSnapshot -VM $vm -Name 'clean-windows-20260930').Count -ne 1) { throw 'Running clean lab/recovery baseline required' }
    $originalFirmware=Get-VMFirmware -VM $vm
    $report.OriginalSecureBoot=$originalFirmware.SecureBoot.ToString()
    $report.OriginalSecureBootTemplate=$originalFirmware.SecureBootTemplate
    $credential=Import-Clixml -LiteralPath (Join-Path $accessRoot 'guest-credential.xml')
    if ($credential.UserName -ne 'DESKTOP-8C2FU3H\GuardLabAdmin') { throw 'Unexpected credential identity' }
    $phase='guest-preflight'; $session=Connect-Guest; $before=Read-GuestState
    if ($before.ComputerName -ne 'DESKTOP-8C2FU3H' -or -not $before.SecureBoot -or $before.TestSigning -or
        $before.BitLockerProtection -ne 'Off' -or $before.HasGuard -or $before.HasLabDriver -or $before.HasGuardData) { throw 'Guest is not the expected clean test target' }
    $report.Before=$before
    $phase='checkpoint'
    $snapshot=Checkpoint-VM -VM $vm -SnapshotName ('before-kernel-lease-'+$runId) -Passthru
    if ($null -eq $snapshot -or $snapshot.VMId -ne $vmId) { throw 'Pre-test checkpoint failed' }
    $report.SnapshotId=$snapshot.Id.ToString()
    # Persist the recovery locator BEFORE changing firmware. No credential or private key enters this journal.
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    $phase='disable-vm-secureboot'; $changed=$true; Stop-PinnedVM
    Set-VMFirmware -VM (Get-PinnedVM) -EnableSecureBoot Off
    $testMode=$true
    $offState=Start-PinnedVM
    if ($offState.SecureBoot -or $offState.TestSigning -or $offState.HasLabDriver) { throw 'Unexpected test-mode preparation state' }
    $phase='enable-guest-testsigning'
    Invoke-Command -Session $session -ScriptBlock {
        param($Uuid)
        if ([guid](Get-CimInstance Win32_ComputerSystemProduct).UUID -ne [guid]$Uuid -or (Confirm-SecureBootUEFI)) { throw 'Guest test mode not authorized for this machine' }
        $output=& "$env:WINDIR\System32\bcdedit.exe" /set '{current}' testsigning on
        if ($LASTEXITCODE -ne 0) { throw ('Guest test-signing refused: '+($output -join ' ')) }
    } -ArgumentList $biosGuid
    Stop-PinnedVM
    $testState=Start-PinnedVM
    if ($testState.SecureBoot -or -not $testState.TestSigning -or $testState.HasLabDriver) { throw 'Guest test-signing not observed' }
    $report.TestBoot=$testState
    $phase='guest-copy'
    Invoke-Command -Session $session -ScriptBlock {
        param($Uuid,$Target)
        if ([guid](Get-CimInstance Win32_ComputerSystemProduct).UUID -ne [guid]$Uuid) { throw 'Guest identity changed' }
        $root='C:\GuardLab'; $marker=Join-Path $root '.vm-identity'
        if ((Test-Path -LiteralPath $root) -and ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint -or
            -not (Test-Path -LiteralPath $marker) -or (Get-Content -LiteralPath $marker -Raw).Trim() -ne $Uuid.ToString())) { throw 'Unowned lab directory' }
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        if (-not (Test-Path -LiteralPath $marker)) { $Uuid.ToString() | Set-Content -LiteralPath $marker -Encoding ASCII }
        if (Test-Path -LiteralPath $Target) { throw 'Guest output exists' }
        New-Item -ItemType Directory -Path $Target | Out-Null
    } -ArgumentList $biosGuid,$guestPackage
    foreach ($file in Get-ChildItem -LiteralPath $PackageRoot -File) { Copy-Item -LiteralPath $file.FullName -Destination $guestPackage -ToSession $session }
    $phase=if ($experiment -ceq 'DenyUnload') {'kernel-unload-tamper'} else {'kernel-expiry'}
    $probePhase=if ($experiment -ceq 'DenyUnload') {'Tamper'} else {'Experiment'}
    $report.Experiment=Invoke-GuestProbe $probePhase
    if ($report.Experiment.Status -ne 'PASS') { throw 'Kernel experiment did not pass' }
    $phase=if ($experiment -ceq 'DenyUnload') {'admin-disabled-reboot'} else {'active-grant-reboot'}
    Stop-PinnedVM; $boot=Start-PinnedVM
    if (-not $boot.HasLabDriver -or -not $boot.TestSigning -or $boot.SecureBoot) { throw 'Unexpected kernel lab reboot state' }
    $probePhase=if ($experiment -ceq 'DenyUnload') {'AfterTamperBoot'} else {'AfterBoot'}
    $report.AfterBoot=Invoke-GuestProbe $probePhase
    if ($report.AfterBoot.Status -ne 'PASS') { throw 'Reboot test did not pass' }
    $report.Status='PASS'
} catch {
    $report.Status='FAIL'; $report.FailurePhase=$phase; $report.ErrorType=$_.Exception.GetType().Name
    $report.Description=$_.Exception.Message
} finally {
    if ($changed -and $snapshot) {
        try {
            Stop-PinnedVM -Recovery
            $saved=@(Get-VMSnapshot -VM (Get-PinnedVM -Recovery) | Where-Object Id -eq $snapshot.Id)
            if ($saved.Count -ne 1 -or $saved[0].Name -ne ('before-kernel-lease-'+$runId)) { throw 'Recovery checkpoint changed' }
            Restore-VMSnapshot -VMSnapshot $saved[0] -Confirm:$false
            # Restore the explicitly observed firmware even if checkpoint application leaves it unchanged.
            $restored=Get-PinnedVM -Recovery
            if ($restored.State -ne 'Off') { throw 'Restored VM is not off; no firmware mutation' }
            # Reassigning even the SAME template is forbidden once Hyper-V vTPM is initialized.
            # This runner never changes the template; verify it and restore only the ON/OFF flag.
            if ((Get-VMFirmware -VM $restored).SecureBootTemplate -ne $originalFirmware.SecureBootTemplate) { throw 'Original Secure Boot template not restored' }
            Set-VMFirmware -VM $restored -EnableSecureBoot On
            $testMode=$false
            $restored=Get-PinnedVM
            $firmware=Get-VMFirmware -VM $restored
            if ($firmware.SecureBootTemplate -ne $originalFirmware.SecureBootTemplate) { throw 'Original Secure Boot template not restored' }
            $after=Start-PinnedVM
            if (-not $after.SecureBoot -or $after.TestSigning -or $after.HasLabDriver -or $after.BitLockerProtection -ne $before.BitLockerProtection) { throw 'Guest recovery/security state not restored' }
            $report.AfterRecovery=$after; $report.SnapshotRecovery='BOOT_VERIFIED'
            Remove-VMSnapshot -VMSnapshot $saved[0] -Confirm:$false
            $report.TestSnapshotRemoved=$true
        } catch { $report.Status='FAIL'; $report.SnapshotRecovery='FAIL'; $report.RecoveryDescription=$_.Exception.Message }
    }
    if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    $report.CompletedAtUtc=[datetime]::UtcNow.ToString('o')
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resultPath -Encoding UTF8
}
if ($report.Status -eq 'PASS' -and $report.SnapshotRecovery -eq 'BOOT_VERIFIED') { exit 0 } else { exit 1 }
