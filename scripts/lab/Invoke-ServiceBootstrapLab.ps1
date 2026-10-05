#requires -Version 5.1
#requires -RunAsAdministrator
param(
    [Parameter(Mandatory=$true)][string]$PackageRoot,
    [Parameter(Mandatory=$true)][string]$ManifestSha256
)
$ErrorActionPreference = 'Stop'
$vmName = 'GuardV2-Lab-20260930'
$vmId = [guid]'8f088b63-9193-4ecc-bb20-415ef11fd4c8'
$biosGuid = [guid]'236ea6ef-9cc6-4295-9934-6f7497f9d262'
$labRoot = Join-Path $env:LOCALAPPDATA 'GuardV2Lab'
$accessRoot = Join-Path $labRoot 'Access'
$diskRoot = [IO.Path]::GetFullPath((Join-Path $labRoot 'VM\Virtual Hard Disks')).TrimEnd('\') + '\'
$runId = [guid]::NewGuid().ToString('N')
$guestPackage = 'C:\GuardLab\ServiceSmoke-' + $runId
$resultPath = Join-Path $accessRoot ('service-bootstrap-' + $runId + '.json')
$session = $null
$snapshot = $null
$changedGuest = $false
$phase = 'host-validation'
$report = [ordered]@{Status='FAIL';RunId=$runId;VmId=$vmId.ToString();ManifestSha256=$ManifestSha256;SnapshotRecovery='NOT_RUN';ProtectionAccepted=$false}
function Get-PinnedVM {
    $vm = Get-VM -Id $vmId
    if ($vm.Name -ne $vmName -or $vm.Generation -ne 2) { throw 'Unexpected VM target' }
    $system = Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem -Filter ("Name='" + $vmId.ToString() + "'")
    $settings = @(Get-CimAssociatedInstance -InputObject $system -Association Msvm_SettingsDefineState -ResultClassName Msvm_VirtualSystemSettingData)
    if ($settings.Count -ne 1 -or [guid]$settings[0].BIOSGUID -ne $biosGuid -or
        (Get-VMFirmware -VM $vm).SecureBoot -ne 'On' -or -not (Get-VMSecurity -VM $vm).TpmEnabled) { throw 'VM identity/security changed' }
    # A Hyper-V wrapper retained the pre-restore AVHDX path in the real lab run.
    # Read the CURRENT setting's disk allocation directly; never guess a disk from the directory.
    $disks = @(Get-CimAssociatedInstance -InputObject $settings[0] -Association Msvm_VirtualSystemSettingDataComponent -ResultClassName Msvm_StorageAllocationSettingData |
        Where-Object ResourceSubType -eq 'Microsoft:Hyper-V:Virtual Hard Disk')
    if ($disks.Count -ne 1 -or @($disks[0].HostResource).Count -ne 1) { throw 'Unexpected VM disk count' }
    $diskPath = [IO.Path]::GetFullPath($disks[0].HostResource[0])
    if (-not $diskPath.StartsWith($diskRoot, [StringComparison]::OrdinalIgnoreCase) -or
        (Get-VHD -Path $diskPath).Size -ne 80GB) { throw 'Unexpected VM disk' }
    $vm
}
function Connect-Guest([switch]$AfterBoot) {
    $deadline = [datetime]::UtcNow.AddSeconds(90)
    do {
        try { return New-PSSession -VMId $vmId -Credential $credential }
        catch {
            if (-not $AfterBoot -or [datetime]::UtcNow -gt $deadline -or $_.Exception.Message -match 'credential|authentication|\u0443\u0447[\u0435\u0451]\u0442\u043d|\u043f\u0430\u0440\u043e\u043b') { throw }
            Start-Sleep -Seconds 3
        }
    } while ($true)
}
function Read-GuestState {
    Invoke-Command -Session $session -ScriptBlock {
        param($Uuid, $HostName)
        $ErrorActionPreference = 'Stop'
        $system = Get-CimInstance Win32_ComputerSystem
        if ($env:COMPUTERNAME -eq $HostName -or [guid](Get-CimInstance Win32_ComputerSystemProduct).UUID -ne [guid]$Uuid -or
            $system.Manufacturer -ne 'Microsoft Corporation' -or $system.Model -ne 'Virtual Machine') { throw 'Guest identity changed' }
        [pscustomobject]@{ComputerName=$env:COMPUTERNAME;Build=(Get-CimInstance Win32_OperatingSystem).BuildNumber;
            HasService=[bool](Get-Service Guard -ErrorAction SilentlyContinue);
            HasInstallation=(@(Get-ChildItem -LiteralPath $env:ProgramFiles -Force | Where-Object Name -eq 'Guard').Count -ne 0);
            HasData=(@(Get-ChildItem -LiteralPath $env:ProgramData -Force | Where-Object Name -eq 'Guard').Count -ne 0)}
    } -ArgumentList $biosGuid,$env:COMPUTERNAME
}
try {
    Import-Module Hyper-V
    $package = Get-Item -LiteralPath $PackageRoot
    $tempRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')
    if ($package.Parent.FullName -ne $tempRoot -or $package.Name -notmatch '^GuardServiceLab-[a-f0-9]{32}$' -or
        ($package.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $ManifestSha256 -notmatch '^[A-F0-9]{64}$' -or
        (Get-FileHash -LiteralPath (Join-Path $PackageRoot 'manifest.json') -Algorithm SHA256).Hash -cne $ManifestSha256) { throw 'Untrusted lab package path/manifest' }
    if (@(Get-ChildItem -LiteralPath $PackageRoot -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Redirected lab payload' }
    $vm = Get-PinnedVM
    if ($vm.State -ne 'Running') { throw 'VM is not running; no implicit start/restore' }
    if (@(Get-VMSnapshot -VM $vm -Name 'clean-windows-20260930').Count -ne 1) { throw 'Known recovery baseline unavailable' }
    $credential = Import-Clixml -LiteralPath (Join-Path $accessRoot 'guest-credential.xml')
    if ($credential.UserName -ne 'DESKTOP-8C2FU3H\GuardLabAdmin') { throw 'Unexpected guest credential identity' }
    $phase = 'guest-preflight'
    $session = Connect-Guest
    $before = Read-GuestState
    if ($before.ComputerName -ne 'DESKTOP-8C2FU3H' -or $before.HasService -or $before.HasInstallation -or $before.HasData) { throw 'Guest is not a clean Guard test target' }
    $report.Before = $before
    $phase = 'checkpoint'
    $snapshot = Checkpoint-VM -VM $vm -SnapshotName ('before-service-bootstrap-' + $runId) -Passthru
    if ($null -eq $snapshot -or $snapshot.VMId -ne $vmId) { throw 'Pre-test checkpoint failed' }
    $report.SnapshotId = $snapshot.Id.ToString()
    $phase = 'post-checkpoint-reconnect'
    # Checkpointing invalidated the open PowerShell Direct runspace in the real guest.
    # Do not replay a guest write: establish a fresh session and revalidate before the first write.
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue; $session = $null
    $session = Connect-Guest -AfterBoot
    $afterCheckpoint = Read-GuestState
    if ($afterCheckpoint.ComputerName -ne $before.ComputerName -or $afterCheckpoint.HasService -or
        $afterCheckpoint.HasInstallation -or $afterCheckpoint.HasData) { throw 'Guest changed during checkpoint' }
    $phase = 'guest-copy'
    $changedGuest = $true
    Invoke-Command -Session $session -ScriptBlock {
        param($Uuid,$Target)
        if ([guid](Get-CimInstance Win32_ComputerSystemProduct).UUID -ne [guid]$Uuid) { throw 'Guest identity changed' }
        $root = 'C:\GuardLab'
        $marker = Join-Path $root '.vm-identity'
        if ((Test-Path -LiteralPath $root) -and ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint -or
            -not (Test-Path -LiteralPath $marker) -or (Get-Content -LiteralPath $marker -Raw).Trim() -ne $Uuid.ToString())) { throw 'Unowned lab directory' }
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        if (-not (Test-Path -LiteralPath $marker)) { $Uuid.ToString() | Set-Content -LiteralPath $marker -Encoding ASCII }
        if (Test-Path -LiteralPath $Target) { throw 'Guest package already exists' }
        New-Item -ItemType Directory -Path $Target | Out-Null
    } -ArgumentList $biosGuid,$guestPackage
    foreach ($item in Get-ChildItem -LiteralPath $PackageRoot) { Copy-Item -LiteralPath $item.FullName -Destination $guestPackage -Recurse -ToSession $session }
    $phase = 'service-bootstrap-and-restart'
    $report.Experiment = Invoke-Command -Session $session -FilePath (Join-Path $PSScriptRoot 'Test-ServiceBootstrap.ps1') -ArgumentList $biosGuid,$env:COMPUTERNAME,$guestPackage,$ManifestSha256
    if ($report.Experiment.Status -ne 'PASS') { throw 'Guest experiment did not pass' }
    $report.Status = 'PASS'
} catch {
    $report.Status = 'FAIL'; $report.FailurePhase = $phase
    $report.ErrorType = $_.Exception.GetType().Name; $report.ErrorId = $_.FullyQualifiedErrorId
    # Only controlled lab exceptions/JSON can reach this field; no credential/session object is serialized.
    $report.Description = $_.Exception.Message
} finally {
    if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue; $session = $null }
    if ($changedGuest -and $snapshot) {
        try {
            $vm = Get-PinnedVM
            if ($vm.State -ne 'Off') {
                Stop-VM -VM $vm
                $deadline = [datetime]::UtcNow.AddSeconds(45)
                while ((Get-VM -Id $vmId).State -ne 'Off') {
                    if ([datetime]::UtcNow -gt $deadline) { throw 'Graceful VM shutdown timed out; no forced power-off performed' }
                    Start-Sleep -Milliseconds 500
                }
            }
            $saved = Get-VMSnapshot -VM (Get-PinnedVM) | Where-Object Id -eq $snapshot.Id
            if (@($saved).Count -ne 1 -or $saved.Name -ne ('before-service-bootstrap-' + $runId)) { throw 'Recovery checkpoint changed' }
            Restore-VMSnapshot -VMSnapshot $saved -Confirm:$false
            Start-VM -VM (Get-PinnedVM)
            $session = Connect-Guest -AfterBoot
            $after = Read-GuestState
            if ($after.ComputerName -ne $before.ComputerName -or $after.HasService -or $after.HasInstallation -or $after.HasData) { throw 'Guest recovery is not clean' }
            $report.SnapshotRecovery = 'BOOT_VERIFIED'
            Remove-VMSnapshot -VMSnapshot $saved -Confirm:$false
            $report.TestSnapshotRemoved = $true
        } catch {
            $report.Status='FAIL'; $report.SnapshotRecovery='FAIL'; $report.RecoveryDescription=$_.Exception.Message
        } finally { if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue } }
    }
    $report.CompletedAtUtc = [datetime]::UtcNow.ToString('o')
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resultPath -Encoding UTF8
}
if ($report.Status -eq 'PASS' -and $report.SnapshotRecovery -eq 'BOOT_VERIFIED') { exit 0 } else { exit 1 }
