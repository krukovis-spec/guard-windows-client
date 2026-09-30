param(
    [Parameter(Mandatory = $true)][guid]$ExpectedUuid,
    [Parameter(Mandatory = $true)][string]$HostComputerName
)
$ErrorActionPreference = 'Stop'
$machine = Get-CimInstance Win32_ComputerSystem
$product = Get-CimInstance Win32_ComputerSystemProduct
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($env:COMPUTERNAME -eq $HostComputerName -or
    [guid]$product.UUID -ne $ExpectedUuid -or
    $machine.Manufacturer -ne 'Microsoft Corporation' -or
    $machine.Model -ne 'Virtual Machine' -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This probe can run only in the validated disposable Hyper-V guest.'
}

$os = Get-CimInstance Win32_OperatingSystem
$version = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
$adminMembers = @(Get-LocalGroupMember -Group $adminGroup.Name | Select-Object Name,@{n='SID';e={$_.SID.Value}},@{n='ObjectClass';e={[string]$_.ObjectClass}},@{n='PrincipalSource';e={[string]$_.PrincipalSource}})
$tpm = Get-Tpm
$bitLocker = Get-BitLockerVolume -MountPoint 'C:'
$appLockerXml = Get-AppLockerPolicy -Effective -Xml
$appLocker = [xml]$appLockerXml
$sha = [Security.Cryptography.SHA256]::Create()
try { $policyHash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($appLockerXml))).Replace('-', '').ToLowerInvariant() }
finally { $sha.Dispose() }
$ciTool = 'C:\Windows\System32\CiTool.exe'
if (-not (Test-Path -LiteralPath $ciTool)) { throw 'Native App Control inventory unavailable' }
$ciOutput = & $ciTool --list-policies -json
if ($LASTEXITCODE -ne 0) { throw ('Native App Control inventory failed: ' + $LASTEXITCODE) }
$ciInventory = ($ciOutput | Out-String) | ConvertFrom-Json
if (-not ($ciInventory.PSObject.Properties.Name -contains 'Policies')) { throw 'Unknown native App Control inventory shape' }
$ciPolicies = @($ciInventory.Policies | Sort-Object PolicyID | Select-Object PolicyID,FriendlyName,IsSystemPolicy,IsSignedPolicy,IsOnDisk,IsEnforced,IsAuthorized)

[pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Uuid = $product.UUID
    Caption = $os.Caption
    EditionId = $version.EditionID
    DisplayVersion = $version.DisplayVersion
    Build = $os.BuildNumber
    UpdateBuildRevision = $version.UBR
    SecureBoot = Confirm-SecureBootUEFI
    TpmPresent = $tpm.TpmPresent
    TpmReady = $tpm.TpmReady
    BitLockerProtection = $bitLocker.ProtectionStatus.ToString()
    BitLockerVolumeStatus = $bitLocker.VolumeStatus.ToString()
    AdminMembers = $adminMembers
    LocalAccounts = @(Get-LocalUser | Select-Object Name,@{n='SID';e={$_.SID.Value}},Enabled,@{n='PrincipalSource';e={[string]$_.PrincipalSource}})
    Services = @(Get-Service -Name AppIDSvc,BFE,vmicvmsession | Select-Object Name,@{n='Status';e={$_.Status.ToString()}},@{n='StartType';e={$_.StartType.ToString()}})
    AppLockerPolicySha256 = $policyHash
    AppLockerCollections = @($appLocker.AppLockerPolicy.RuleCollection | Where-Object { $null -ne $_ } | ForEach-Object {
        [pscustomobject]@{Type=$_.Type;Mode=$_.EnforcementMode;Rules=@($_.ChildNodes | Where-Object {$_.NodeType -eq 'Element'}).Count}
    })
    HasConfigCi = [bool](Get-Module -ListAvailable ConfigCI)
    HasCiTool = $true
    AppControlPolicies = $ciPolicies
    RecoveryEnvironment = (& 'C:\Windows\System32\reagentc.exe' /info | Out-String).Trim()
    RecoveryProbeExit = $LASTEXITCODE
    FreeDiskBytes = (Get-Volume -DriveLetter C).SizeRemaining
}
