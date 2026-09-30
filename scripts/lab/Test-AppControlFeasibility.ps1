param(
    [Parameter(Mandatory = $true)][guid]$ExpectedUuid,
    [Parameter(Mandatory = $true)][string]$HostComputerName
)
$ErrorActionPreference = 'Stop'
$machine = Get-CimInstance Win32_ComputerSystem
$product = Get-CimInstance Win32_ComputerSystemProduct
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($env:COMPUTERNAME -eq $HostComputerName -or [guid]$product.UUID -ne $ExpectedUuid -or
    $machine.Manufacturer -ne 'Microsoft Corporation' -or $machine.Model -ne 'Virtual Machine' -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This probe can run only in the validated disposable Hyper-V guest.'
}
$root = 'C:\GuardLab'
if ((Get-Content -LiteralPath (Join-Path $root '.vm-identity') -Raw).Trim() -ne $ExpectedUuid.ToString()) { throw 'Unowned lab directory' }
. (Join-Path $root 'MarkerProcess.ps1')
Import-Module ConfigCI
$ciTool = 'C:\Windows\System32\CiTool.exe'
function Invoke-LabCiTool([string]$Operation, [string]$Argument) {
    $arguments = @($Operation)
    if ($Argument) { $arguments += $Argument }
    $arguments += '-json'
    $output = & $ciTool @arguments
    if ($LASTEXITCODE -ne 0) { throw ('CiTool ' + $Operation + ' failed: ' + $LASTEXITCODE) }
    ($output | Out-String) | ConvertFrom-Json
}
function Get-LabPolicy {
    @((Invoke-LabCiTool '--list-policies').Policies | Where-Object {[guid]$_.PolicyID -eq $policyId})
}
function Get-MarkerPolicyEventCount([int]$Id, [datetime]$Start) {
    $events = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational';Id=$Id;StartTime=$Start} -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {
        $xml = $_.ToXml()
        $xml -match 'GuardLab\\marker-v1\.exe' -and $xml -match [regex]::Escape($policyId.ToString())
    })
    $events.Count
}
$inventory = Invoke-LabCiTool '--list-policies'
if (-not ($inventory.PSObject.Properties.Name -contains 'Policies')) { throw 'Unknown native inventory shape; experiment refused' }
foreach ($policy in @($inventory.Policies)) {
    if (-not ($policy.PSObject.Properties.Name -contains 'IsSystemPolicy') -or -not ($policy.PSObject.Properties.Name -contains 'IsOnDisk')) { throw 'Unknown native inventory shape; experiment refused' }
}
if (@($inventory.Policies | Where-Object {$_.IsSystemPolicy -eq $false -and $_.IsOnDisk -eq $true}).Count) { throw 'Existing non-platform on-disk policy; lab experiment refused' }
$compiler = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$marker = Join-Path $root 'marker-v1.exe'
& $compiler /nologo /target:exe /optimize+ /warnaserror+ ('/out:' + $marker) (Join-Path $root 'Marker.cs')
if ($LASTEXITCODE -ne 0) { throw 'Marker compile failed' }
$policyPath = Join-Path $root 'AppControl.audit.xml'
# ponytail: the native DefaultWindows example is LAB ONLY; it is broader than the required production catalog.
Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml' -Destination $policyPath
Set-CIPolicyIdInfo -FilePath $policyPath -ResetPolicyID -PolicyName 'Guard LAB ONLY unsigned feasibility' | Out-Null
Set-CIPolicyVersion -FilePath $policyPath -Version '1.0.0.0' | Out-Null
foreach ($option in @(0,3,6,9,10,11,16)) { Set-RuleOption -FilePath $policyPath -Option $option | Out-Null }
# Script enforcement is deliberately disabled for this EXE-only experiment, not for production.
$policyXml = [xml](Get-Content -LiteralPath $policyPath -Raw)
$policyId = [guid]$policyXml.SiPolicy.PolicyID
$binaryPath = Join-Path $root ('{' + $policyId.ToString() + '}.cip')
$results = [ordered]@{PolicyIsProductionCandidate=$false;Signed=$false;PolicyId=$policyId.ToString();ScriptEnforcementTested=$false}
$deployed = $false
$failure = $null
try {
    $results.BeforePolicy = Wait-MarkerDecision $marker 'Allowed'
    ConvertFrom-CIPolicy -XmlFilePath $policyPath -BinaryFilePath $binaryPath | Out-Null
    Invoke-LabCiTool '--update-policy' $binaryPath | Out-Null
    $deployed = $true
    if (@(Get-LabPolicy).Count -ne 1) { throw 'Audit policy not present in native inventory' }
    $auditStart = Get-Date
    $results.AuditLaunch = Wait-MarkerDecision $marker 'Allowed'
    $eventDeadline = [datetime]::UtcNow.AddSeconds(10)
    do {
        $results.AuditEvents = Get-MarkerPolicyEventCount 3076 $auditStart
        if ($results.AuditEvents -gt 0) { break }
        Start-Sleep -Milliseconds 200
    } while ([datetime]::UtcNow -lt $eventDeadline)
    if ($results.AuditEvents -eq 0) { throw 'No marker-specific audit event for this policy' }

    Set-RuleOption -FilePath $policyPath -Option 3 -Delete | Out-Null
    Set-CIPolicyVersion -FilePath $policyPath -Version '2.0.0.0' | Out-Null
    ConvertFrom-CIPolicy -XmlFilePath $policyPath -BinaryFilePath $binaryPath | Out-Null
    Invoke-LabCiTool '--update-policy' $binaryPath | Out-Null
    $enforceStart = Get-Date
    $results.EnforcedLaunch = Wait-MarkerDecision $marker 'Blocked'
    $eventDeadline = [datetime]::UtcNow.AddSeconds(10)
    do {
        $results.BlockEvents = Get-MarkerPolicyEventCount 3077 $enforceStart
        if ($results.BlockEvents -gt 0) { break }
        Start-Sleep -Milliseconds 200
    } while ([datetime]::UtcNow -lt $eventDeadline)
    if ($results.BlockEvents -eq 0) { throw 'No marker-specific enforced event for this policy' }
    $results.NativeEnforcedPolicy = Get-LabPolicy | Select-Object PolicyID,FriendlyName,IsSignedPolicy,IsEnforced,IsAuthorized
    Invoke-LabCiTool '--remove-policy' ('{' + $policyId.ToString() + '}') | Out-Null
    $results.AdministratorRemovedUnsignedPolicy = $true
    $results.AfterRemoval = Wait-MarkerDecision $marker 'Allowed'
} catch { $failure = $_ }
finally {
    if ($deployed -and @(Get-LabPolicy).Count) { Invoke-LabCiTool '--remove-policy' ('{' + $policyId.ToString() + '}') | Out-Null }
}
[pscustomobject]@{Status=$(if ($failure) {'FAIL'} else {'PASS'});Results=[pscustomobject]$results;Failure=[string]$failure.Exception.Message;LabPolicyAbsent=(@(Get-LabPolicy).Count -eq 0);MarkerSha256=(Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash}
