#requires -Version 5.1
#requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$vmName = 'GuardV2-Lab-20260930'
$vmId = [guid]'8f088b63-9193-4ecc-bb20-415ef11fd4c8'
$biosGuid = [guid]'236ea6ef-9cc6-4295-9934-6f7497f9d262'
$labRoot = Join-Path $env:LOCALAPPDATA 'GuardV2Lab'
$accessRoot = Join-Path $labRoot 'Access'
$diskRoot = [IO.Path]::GetFullPath((Join-Path $labRoot 'VM\Virtual Hard Disks')).TrimEnd('\') + '\'
$session = $null
$probeStarted = $false
$phase = 'host-validation'
$report = [ordered]@{Status='FAIL';SnapshotRecovery='NOT_RUN'}
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
    $phase = 'guest-baseline'
    $session = New-PSSession -VMId $vmId -Credential $credential
    $baseline = Invoke-Command -Session $session -FilePath (Join-Path $PSScriptRoot 'Get-GuestBaseline.ps1') -ArgumentList $biosGuid,$env:COMPUTERNAME
    $report.Baseline = $baseline
    Invoke-Command -Session $session -ScriptBlock {
        param([guid]$Uuid)
        $ErrorActionPreference = 'Stop'
        if ([guid](Get-CimInstance Win32_ComputerSystemProduct).UUID -ne $Uuid) { throw 'Guest identity changed' }
        $root = 'C:\GuardLab'
        $marker = Join-Path $root '.vm-identity'
        if ((Test-Path -LiteralPath $root) -and (-not (Test-Path -LiteralPath $marker) -or (Get-Content -LiteralPath $marker -Raw).Trim() -ne $Uuid.ToString())) { throw 'Unowned lab directory' }
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $Uuid.ToString() | Set-Content -LiteralPath $marker -Encoding ASCII
    } -ArgumentList $biosGuid
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Marker.cs') -Destination 'C:\GuardLab\Marker.cs' -ToSession $session
    $phase = 'applocker-experiment'
    $probeStarted = $true
    $report.Experiment = Invoke-Command -Session $session -FilePath (Join-Path $PSScriptRoot 'Test-AppLockerFeasibility.ps1') -ArgumentList $biosGuid,$env:COMPUTERNAME
    if ($report.Experiment.Status -ne 'PASS') { throw $report.Experiment.Failure }
    $report.Status = 'PASS'
} catch {
    $report.Status = 'FAIL'
    $report.FailurePhase = $phase
    $report.Description = $_.Exception.Message
    $report.ErrorId = $_.FullyQualifiedErrorId
} finally {
    if ($session) { Remove-PSSession -Session $session }
    if ($probeStarted) {
        try {
            $vm = Get-VM -Id $vmId
            if ($vm.Name -ne $vmName) { throw 'Recovery target changed' }
            Stop-VM -VM $vm
            $deadline = [datetime]::UtcNow.AddSeconds(60)
            while ((Get-VM -Id $vmId).State -ne 'Off') {
                if ([datetime]::UtcNow -gt $deadline) { throw 'Graceful VM shutdown timed out; no forced power-off performed' }
                Start-Sleep -Milliseconds 500
            }
            Restore-VMSnapshot -VMSnapshot $snapshot[0] -Confirm:$false
            Start-VM -VM $vm
            $report.SnapshotRecovery = 'RESTORED'
            $bootSession = $null
            try {
                for ($attempt = 0; $attempt -lt 3; $attempt++) {
                    try { $bootSession = New-PSSession -VMId $vmId -Credential $credential; break }
                    catch {
                        if ($_.Exception.Message -match 'credential|\u0443\u0447\u0435\u0442\u043d\u044b\u0435' -or $attempt -eq 2) { throw }
                        Start-Sleep -Seconds 3
                    }
                }
                $after = Invoke-Command -Session $bootSession -FilePath (Join-Path $PSScriptRoot 'Get-GuestBaseline.ps1') -ArgumentList $biosGuid,$env:COMPUTERNAME
                if (@($after.AppLockerCollections | Where-Object { $_.Rules -gt 0 }).Count) { throw 'Unexpected policy after snapshot recovery' }
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
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $accessRoot 'applocker-result.json') -Encoding UTF8
}
if ($report.Status -eq 'PASS') { exit 0 } else { exit 1 }
