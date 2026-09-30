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
$original = Get-AppLockerPolicy -Local -Xml
$effective = [xml](Get-AppLockerPolicy -Effective -Xml)
if ($effective.SelectNodes('//FilePathRule|//FileHashRule|//FilePublisherRule').Count) { throw 'Refusing to overwrite an existing effective policy' }
$originalPath = Join-Path $root 'AppLocker.original.xml'
$original | Set-Content -LiteralPath $originalPath -Encoding UTF8
$compiler = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$v1 = Join-Path $root 'marker-v1.exe'
$v2 = Join-Path $root 'marker-v2.exe'
& $compiler /nologo /target:exe /optimize+ /warnaserror+ ('/out:' + $v1) (Join-Path $root 'Marker.cs')
if ($LASTEXITCODE -ne 0) { throw 'Marker v1 compile failed' }
& $compiler /nologo /target:exe /optimize+ /warnaserror+ /define:VARIANT_TWO ('/out:' + $v2) (Join-Path $root 'Marker.cs')
if ($LASTEXITCODE -ne 0) { throw 'Marker v2 compile failed' }

. (Join-Path $root 'MarkerProcess.ps1')

$windowsInfo = Get-AppLockerFileInformation -Path 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$base = [xml](New-AppLockerPolicy -FileInformation $windowsInfo -RuleType Path -User 'S-1-1-0' -ServiceEnforcement Enabled -Xml)
$collection = $base.SelectSingleNode("//RuleCollection[@Type='Exe']")
$extensions = $collection.SelectSingleNode('RuleCollectionExtensions')
$template = $collection.SelectSingleNode('FilePathRule')
$template.SelectSingleNode('Conditions/FilePathCondition').SetAttribute('Path', 'C:\Windows\*')
$template.SetAttribute('Name', 'LAB ONLY Windows path')
# ponytail: broad OS paths keep this disposable experiment bootable; never use this as the production catalog.
foreach ($path in @('C:\Program Files\*', 'C:\Program Files (x86)\*')) {
    $rule = $template.CloneNode($true)
    $rule.SetAttribute('Id', [guid]::NewGuid().ToString())
    $rule.SetAttribute('Name', 'LAB ONLY ' + $path)
    $rule.SelectSingleNode('Conditions/FilePathCondition').SetAttribute('Path', $path)
    $collection.InsertBefore($rule, $extensions) | Out-Null
}
$policyPath = Join-Path $root 'AppLocker.experiment.xml'
$hold = $null
$failure = $null
$results = [ordered]@{PolicyIsProductionCandidate=$false;UserOrGroupSid='S-1-1-0';FullAdministrator=$true}
try {
    $results.BeforePolicy = Get-MarkerDecision $v1
    $collection.SetAttribute('EnforcementMode', 'AuditOnly')
    $base.Save($policyPath)
    Set-AppLockerPolicy -XmlPolicy $policyPath
    $results.AuditLaunch = Wait-MarkerDecision $v1 'Allowed'
    $collection.SetAttribute('EnforcementMode', 'Enabled')
    $base.Save($policyPath)
    Set-AppLockerPolicy -XmlPolicy $policyPath
    $results.DefaultDeny = Wait-MarkerDecision $v1 'Blocked'

    $hashPolicy = [xml](New-AppLockerPolicy -FileInformation (Get-AppLockerFileInformation -Path $v1) -RuleType Hash -User 'S-1-1-0' -ServiceEnforcement Enabled -Xml)
    $hashRule = $base.ImportNode($hashPolicy.SelectSingleNode('//FileHashRule'), $true)
    $collection.InsertBefore($hashRule, $extensions) | Out-Null
    $base.Save($policyPath)
    Set-AppLockerPolicy -XmlPolicy $policyPath
    $results.ExactGrant = Wait-MarkerDecision $v1 'Allowed'
    $results.OtherHash = Wait-MarkerDecision $v2 'Blocked'
    $holdOutput = Join-Path $root 'hold.stdout.txt'
    $hold = Start-Process -FilePath $v1 -ArgumentList '--hold-seconds 60' -WindowStyle Hidden -RedirectStandardOutput $holdOutput -RedirectStandardError (Join-Path $root 'hold.stderr.txt') -PassThru
    $startDeadline = [datetime]::UtcNow.AddSeconds(5)
    while ((Get-Content -LiteralPath $holdOutput -Raw) -notmatch 'MARKER_STARTED v1') {
        if ($hold.HasExited -or [datetime]::UtcNow -gt $startDeadline) { throw 'Held marker did not start before revoke' }
        Start-Sleep -Milliseconds 100
    }
    $collection.RemoveChild($hashRule) | Out-Null
    $base.Save($policyPath)
    Set-AppLockerPolicy -XmlPolicy $policyPath
    $results.RevokedNewLaunch = Wait-MarkerDecision $v1 'Blocked'
    Start-Sleep -Seconds 2
    $hold.Refresh()
    $results.RunningProcessSurvivedRevoke = -not $hold.HasExited
    if (-not $hold.HasExited) { $hold.Kill(); $hold.WaitForExit() }
    $hold = $null

    # The current guest identity is a real elevated administrator. Clearing the policy is the tamper probe.
    Set-AppLockerPolicy -XmlPolicy $originalPath
    $results.AdministratorClearedPolicy = (Wait-MarkerDecision $v1 'Allowed') -eq 'Allowed'
    $results.OtherHashAfterClear = Wait-MarkerDecision $v2 'Allowed'
    $results.AppLockerAloneContainsFullAdministrator = $false
} catch { $failure = $_ }
finally {
    if ($hold -and -not $hold.HasExited) { $hold.Kill(); $hold.WaitForExit() }
    Set-AppLockerPolicy -XmlPolicy $originalPath
    $restored = [xml](Get-AppLockerPolicy -Effective -Xml)
    if ($restored.SelectNodes('//FilePathRule|//FileHashRule|//FilePublisherRule').Count) { throw 'Original empty policy was not restored; use the clean VM snapshot' }
}
[pscustomobject]@{Status=$(if ($failure) {'FAIL'} else {'PASS'});Results=[pscustomobject]$results;Failure=$(if ($failure) {$failure.Exception.Message});OriginalPolicyRestored=$true;V1Sha256=(Get-FileHash -LiteralPath $v1 -Algorithm SHA256).Hash;V2Sha256=(Get-FileHash -LiteralPath $v2 -Algorithm SHA256).Hash}
