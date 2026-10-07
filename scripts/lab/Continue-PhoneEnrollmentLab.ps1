#requires -Version 5.1
#requires -RunAsAdministrator
param(
    [Parameter(Mandatory=$true)][string]$PreparationReport,
    [Parameter(Mandatory=$true)][string]$ProfilePath,
    [Parameter(Mandatory=$true)][string]$ProfileSha256,
    [switch]$ResumeUnimported,
    [switch]$InspectOnly,
    [switch]$ResumeStaged,
    [string]$ServiceDllPath,
    [string]$ServiceDllSha256,
    [string]$PreviousGuestScriptSha256
)
$ErrorActionPreference='Stop'
if (@($InspectOnly,$ResumeUnimported,$ResumeStaged | Where-Object { $_ }).Count -gt 1) { throw 'Choose one continuation mode' }
$vmName='GuardV2-Lab-20260930'
$vmId=[guid]'8f088b63-9193-4ecc-bb20-415ef11fd4c8'
$biosGuid=[guid]'236ea6ef-9cc6-4295-9934-6f7497f9d262'
$labRoot=Join-Path $env:LOCALAPPDATA 'GuardV2Lab'
$accessRoot=Join-Path $labRoot 'Access'
$diskRoot=[IO.Path]::GetFullPath((Join-Path $labRoot 'VM\Virtual Hard Disks')).TrimEnd('\')+'\'
# Reuse the exact already-tested VM guard, not another slightly different disk/firmware check.
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Invoke-ServiceBootstrapLab.ps1'),[ref]$null,[ref]$null)
$guard=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-PinnedVM'},$false)
if ($null -eq $guard) { throw 'Pinned VM guard unavailable' }
. ([scriptblock]::Create($guard.Extent.Text))
$file=Get-Item -LiteralPath $PreparationReport
if ($file.DirectoryName -cne $accessRoot -or $file.Name -cnotmatch '^service-bootstrap-[a-f0-9]{32}\.json$' -or
    ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 16384) { throw 'Unexpected preparation report' }
$prepared=Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
$runId=$prepared.RunId
if ($runId -cnotmatch '^[a-f0-9]{32}$' -or $file.Name -cne ('service-bootstrap-'+$runId+'.json') -or
    $prepared.VmId -ne $vmId.ToString() -or $prepared.Status -cne 'PHONE_PREPARED' -or
    $prepared.SnapshotRecovery -cne 'RETAINED_FOR_PHONE' -or $prepared.Experiment.Status -cne 'PASS' -or
    $prepared.PhonePreparation.GuestPackage -cne ('C:\GuardLab\ServiceSmoke-'+$runId)) { throw 'No retained phone preparation' }
$guestPackage=$prepared.PhonePreparation.GuestPackage
$operatorRoot=Join-Path $env:LOCALAPPDATA ('GuardOperator\LabEnrollment-'+$runId)
$profile=Get-Item -LiteralPath $ProfilePath
if ($profile.FullName -cne (Join-Path $operatorRoot 'computer.profile') -or $ProfileSha256 -cnotmatch '^[A-F0-9]{64}$' -or
    $profile.Length -lt 100 -or $profile.Length -gt 8192 -or
    (Get-FileHash -LiteralPath $profile.FullName -Algorithm SHA256).Hash -cne $ProfileSha256) { throw 'Unexpected encrypted profile' }
foreach ($path in @($operatorRoot,$profile.FullName,$accessRoot,$labRoot)) {
    if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected phone lab path' }
}
$resultPath=Join-Path $accessRoot ('phone-import-'+$runId+'.json')
if ($InspectOnly) {
    $resultPath=Join-Path $accessRoot ('phone-inspect-'+$runId+'-'+[guid]::NewGuid().ToString('N')+'.json')
} elseif (Test-Path -LiteralPath $resultPath) {
    $prior=Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ((-not $ResumeUnimported -and -not $ResumeStaged) -or $prior.Status -ne 'FAIL' -or $prior.ErrorId -ne 'UnauthorizedAccess') { throw 'Import already attempted; inspect existing report, do not repeat blindly' }
    $resultPath=Join-Path $accessRoot ('phone-import-'+$runId+'-'+[guid]::NewGuid().ToString('N')+'.json')
} elseif ($ResumeUnimported -or $ResumeStaged) { throw 'No failed import to resume' }
if ($ResumeStaged) {
    $patch=Get-Item -LiteralPath $ServiceDllPath
    $tempRoot=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')
    $patchRoot=Split-Path (Split-Path $patch.FullName -Parent) -Parent
    if ($patch.Name -cne 'Guard.Service.dll' -or $patch.Directory.Name -cne 'service' -or
        (Split-Path $patchRoot -Parent) -cne $tempRoot -or (Split-Path $patchRoot -Leaf) -cnotmatch '^GuardServiceLab-[a-f0-9]{32}$' -or
        $ServiceDllSha256 -cnotmatch '^[A-F0-9]{64}$' -or $PreviousGuestScriptSha256 -cnotmatch '^[A-F0-9]{64}$' -or
        (Get-FileHash -LiteralPath $patch.FullName -Algorithm SHA256).Hash -cne $ServiceDllSha256) { throw 'Untrusted lab service correction' }
    foreach ($path in @($patchRoot,$patch.DirectoryName,$patch.FullName)) {
        if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected lab service correction' }
    }
}
$report=[ordered]@{Status='FAIL';RunId=$runId;VmId=$vmId.ToString();SnapshotId=$prepared.SnapshotId;ProtectionAccepted=$false}
$session=$null
try {
    Import-Module Hyper-V
    $vm=Get-PinnedVM
    if ($vm.State -ne 'Running') { throw 'Prepared VM not running' }
    $snapshot=@(Get-VMSnapshot -VM $vm | Where-Object Id -eq ([guid]$prepared.SnapshotId))
    if ($snapshot.Count -ne 1 -or $snapshot[0].Name -cne ('before-service-bootstrap-'+$runId)) { throw 'Recovery checkpoint missing' }
    $credential=Import-Clixml -LiteralPath (Join-Path $accessRoot 'guest-credential.xml')
    if ($credential.UserName -cne 'DESKTOP-8C2FU3H\GuardLabAdmin') { throw 'Unexpected guest credential identity' }
    $session=New-PSSession -VMId $vmId -Credential $credential
    if ($InspectOnly) {
        $report.Experiment=Invoke-Command -Session $session -ScriptBlock {
            param($Uuid,$Package)
            if ([guid](Get-CimInstance Win32_ComputerSystemProduct).UUID -ne $Uuid) { throw 'Guest binding changed' }
            $service=Get-CimInstance Win32_Service -Filter "Name='Guard'"
            $stage=$null
            $stagePath=Join-Path $Package 'profile-stage-result.json'
            if (Test-Path -LiteralPath $stagePath) { $stage=Get-Content -LiteralPath $stagePath -Raw -Encoding UTF8 | ConvertFrom-Json }
            $types=@(Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=(Get-Date).AddMinutes(-20)} -MaxEvents 128 -ErrorAction SilentlyContinue |
                Where-Object { $_.ProviderName -in @('Guard.Service','.NET Runtime','Application Error') -and $_.Message -match 'Guard\.' } |
                ForEach-Object {
                    foreach ($match in [regex]::Matches($_.Message,'\b(?:System|Microsoft|Guard)\.[A-Za-z0-9_.]*(?:Exception)\b|(?m)^\s+at\s+((?:Guard|System\.IO|System\.Security|Microsoft\.Extensions)\.[A-Za-z0-9_.+`]+)')) {
                        if ($match.Groups[1].Success) { $match.Groups[1].Value } else { $match.Value }
                    }
                } | Select-Object -Unique -First 32)
            [pscustomobject]@{ServiceState=$service.State;ServiceExit=$service.ExitCode;NormalScm=($service.PathName -ceq '"C:\Program Files\Guard\Guard.Service.exe"');
                StageStatus=$stage.status;SystemOnly=$stage.systemOnly;FailureMembers=$types;ExecutionPolicy=[string](Get-ExecutionPolicy)}
        } -ArgumentList $biosGuid,$guestPackage
        $report.Status='OBSERVED'
        return
    }
    $scriptPath=Join-Path $PSScriptRoot 'Import-DeviceProfileLab.ps1'
    $scriptHash=(Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash
    $copyNeeded=Invoke-Command -Session $session -ScriptBlock {
        param($Uuid,$Package,$Resume,$ProfileHash,$ScriptHash,$Staged,$OldScriptHash)
        if ($env:COMPUTERNAME -ne 'DESKTOP-8C2FU3H' -or [guid](Get-CimInstance Win32_ComputerSystemProduct).UUID -ne $Uuid -or
            $Package -cnotmatch '^C:\\GuardLab\\ServiceSmoke-[a-f0-9]{32}$') { throw 'Guest binding changed' }
        foreach ($path in @('C:\GuardLab',$Package)) {
            if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected guest package' }
        }
        if ($Staged) {
            $stage=Get-Content -LiteralPath (Join-Path $Package 'profile-stage-result.json') -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($stage.status -ne 'STAGED' -or $stage.systemOnly -ne $true) { throw 'No verified prior staging' }
        } elseif (Test-Path -LiteralPath (Join-Path $Package 'profile-stage-result.json')) { throw 'SYSTEM staging already started; inspect before retry' }
        foreach ($name in @('device.profile','Import-DeviceProfileLab.ps1')) {
            $target=Join-Path $Package $name
            if (Test-Path -LiteralPath $target) {
                $expectedHash=if ($name -eq 'device.profile') { $ProfileHash } elseif ($Staged) { $OldScriptHash } else { $ScriptHash }
                if (-not $Resume -or (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -cne $expectedHash) { throw 'Existing import input differs' }
            } elseif ($Resume) { throw 'Incomplete failed transfer; no blind resume' }
        }
        -not $Resume
    } -ArgumentList $biosGuid,$guestPackage,([bool]($ResumeUnimported -or $ResumeStaged)),$ProfileSha256,$scriptHash,([bool]$ResumeStaged),$PreviousGuestScriptSha256
    if ($copyNeeded) {
        Copy-Item -LiteralPath $profile.FullName -Destination (Join-Path $guestPackage 'device.profile') -ToSession $session
        Copy-Item -LiteralPath $scriptPath -Destination (Join-Path $guestPackage 'Import-DeviceProfileLab.ps1') -ToSession $session
    }
    if ($ResumeStaged) {
        $guestPatch=Join-Path $guestPackage 'Guard.Service.updated.dll'
        Invoke-Command -Session $session -ScriptBlock { param($Path) if (Test-Path -LiteralPath $Path) { throw 'Lab patch already copied; inspect before retry' } } -ArgumentList $guestPatch
        Copy-Item -LiteralPath $patch.FullName -Destination $guestPatch -ToSession $session
        Copy-Item -LiteralPath $scriptPath -Destination (Join-Path $guestPackage 'Import-DeviceProfileLab.ps1') -ToSession $session -Force
        Invoke-Command -Session $session -ScriptBlock {
            param($Uuid,$Path,$Hash,$DescriptorHash,$Package)
            if ([guid](Get-CimInstance Win32_ComputerSystemProduct).UUID -ne $Uuid -or
                (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -cne $Hash) { throw 'Service correction binding changed' }
            $service=Get-CimInstance Win32_Service -Filter "Name='Guard'"
            if ($service.PathName -cne '"C:\Program Files\Guard\Guard.Service.exe"' -or $service.StartName -ne 'LocalSystem') { throw 'Unexpected installed service' }
            $probe=Join-Path $Package 'probe\Guard.Windows.Ipc.Tests.exe'
            $observed=& $probe --installed-service-lab inspect https://guard-relay.voicepaste.workers.dev
            if ($LASTEXITCODE -ne 0 -or (($observed -join '') | ConvertFrom-Json).descriptorSha256 -cne $DescriptorHash) { throw 'Device changed before correction' }
            $target='C:\Program Files\Guard\Guard.Service.dll'
            foreach($entry in @('C:\Program Files','C:\Program Files\Guard',$target)) {
                if ((Get-Item -LiteralPath $entry).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected installed service' }
            }
            Stop-Service Guard; (Get-Service Guard).WaitForStatus('Stopped',[timespan]::FromSeconds(30))
            try { Copy-Item -LiteralPath $Path -Destination $target -Force; if ((Get-FileHash -LiteralPath $target).Hash -cne $Hash) { throw 'Installed correction mismatch' } }
            finally { Start-Service Guard }
        } -ArgumentList $biosGuid,$guestPatch,$ServiceDllSha256,$prepared.Experiment.AfterRestart.descriptorSha256,$guestPackage
        $report.ServiceDllSha256=$ServiceDllSha256
    }
    $report.Experiment=Invoke-Command -Session $session -ScriptBlock {
        param($Uuid,$HostName,$Package,$ProfileHash,$DescriptorHash,$ScriptHash,$ManifestHash,$Staged)
        if ([guid](Get-CimInstance Win32_ComputerSystemProduct).UUID -ne $Uuid) { throw 'Guest binding changed' }
        $script=Join-Path $Package 'Import-DeviceProfileLab.ps1'
        if ((Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash -cne $ScriptHash -or
            (Get-FileHash -LiteralPath (Join-Path $Package 'manifest.json') -Algorithm SHA256).Hash -cne $ManifestHash) { throw 'Transferred code/manifest changed' }
        $manifest=Get-Content -LiteralPath (Join-Path $Package 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($entry in $manifest.Files) {
            # Original package was validated by the preparation runner; pin all binaries before execution again.
            if ($entry.Path.Contains('..') -or [IO.Path]::IsPathRooted($entry.Path)) { throw 'Unsafe manifest path' }
            $target=Join-Path $Package $entry.Path
            if ((Get-Item -LiteralPath $target).Attributes -band [IO.FileAttributes]::ReparsePoint -or
                (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -cne $entry.Sha256) { throw 'Guest payload changed' }
        }
        # File execution in the remoting runspace may be Restricted. Use a process-local
        # RemoteSigned policy for this hash-verified local script, never a machine policy change.
        # The script returns one object; serialize in this child without printing arbitrary stderr.
        if ($HostName -cnotmatch '^[A-Za-z0-9-]{1,63}$') { throw 'Invalid host name' }
        $command='try { & "'+$script+'" -ExpectedUuid "'+$Uuid+'" -HostComputerName "'+$HostName+
            '" -PackageRoot "'+$Package+'" -ProfileSha256 "'+$ProfileHash+'" -DescriptorSha256 "'+$DescriptorHash+'"'+
            $(if($Staged){' -UseStaged'}else{''})+' | ConvertTo-Json -Depth 4 -Compress } catch { [pscustomobject]@{Status="FAIL";ErrorType=$_.Exception.GetType().Name;ErrorId=$_.FullyQualifiedErrorId;Line=$_.InvocationInfo.ScriptLineNumber} | ConvertTo-Json -Compress; exit 1 }'
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $policy=Get-ExecutionPolicy
        $output=& 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -EncodedCommand $encoded 2>$null
        $childExit=$LASTEXITCODE
        $facts=($output -join '') | ConvertFrom-Json
        $facts | Add-Member -NotePropertyName ChildExit -NotePropertyValue $childExit
        $facts | Add-Member -NotePropertyName PriorExecutionPolicy -NotePropertyValue ([string]$policy)
        $facts
    } -ArgumentList $biosGuid,$env:COMPUTERNAME,$guestPackage,$ProfileSha256,$prepared.Experiment.AfterRestart.descriptorSha256,$scriptHash,$prepared.ManifestSha256,([bool]$ResumeStaged)
    if ($report.Experiment.Status -cne 'PROFILE_IMPORTED' -or $report.Experiment.ChildExit -ne 0) { throw 'Profile import not confirmed' }
    $report.Status='READY_FOR_PHONE'
} catch {
    $report.ErrorType=$_.Exception.GetType().Name
    $report.ErrorId=$_.FullyQualifiedErrorId
    # Retain identity/job/snapshot after a credential may have been issued; never silently replace them.
} finally {
    if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    $report.CompletedAtUtc=[datetime]::UtcNow.ToString('o')
    $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $resultPath -Encoding UTF8
}
if ($report.Status -eq 'READY_FOR_PHONE') { exit 0 } else { exit 1 }
