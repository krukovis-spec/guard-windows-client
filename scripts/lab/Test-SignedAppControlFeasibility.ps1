param(
    [Parameter(Mandatory = $true)][guid]$ExpectedUuid,
    [Parameter(Mandatory = $true)][string]$HostComputerName,
    [ValidateSet('Prepare','Audit','VerifyAudit','Enforce','VerifyEnforce','Tamper','Grant','VerifyGrant','Revoke','VerifyRevoke','Recovery','Remove')][string]$Phase = 'Prepare'
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
if (-not (Confirm-SecureBootUEFI)) { throw 'Signed lab policy requires Secure Boot' }
$root = 'C:\GuardLab'
if ((Get-Content -LiteralPath (Join-Path $root '.vm-identity') -Raw).Trim() -ne $ExpectedUuid.ToString()) { throw 'Unowned lab directory' }
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
. (Join-Path $root 'MarkerProcess.ps1')
$ciTool = 'C:\Windows\System32\CiTool.exe'
$marker = Join-Path $root 'marker-v1.exe'
$policyPath = Join-Path $root 'AppControl.signed.xml'
if ($Phase -eq 'Prepare') {
    Import-Module ConfigCI
    $inventory = ((& $ciTool --list-policies -json | Out-String) | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0 -or -not ($inventory.PSObject.Properties.Name -contains 'Policies')) { throw 'Native inventory failed' }
    if (@($inventory.Policies | Where-Object {$_.IsSystemPolicy -eq $false -and $_.IsOnDisk -eq $true}).Count) { throw 'Existing non-platform policy; signed experiment refused' }
    $compiler = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $compiler /nologo /target:exe /optimize+ /warnaserror+ ('/out:' + $marker) (Join-Path $root 'Marker.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Marker compile failed' }
    & $compiler /nologo /target:exe /optimize+ /warnaserror+ /define:VARIANT_TWO ('/out:' + (Join-Path $root 'marker-v2.exe')) (Join-Path $root 'Marker.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Marker v2 compile failed' }
    if ((Get-FileHash -LiteralPath $marker).Hash -eq (Get-FileHash -LiteralPath (Join-Path $root 'marker-v2.exe')).Hash) { throw 'Marker identities must differ' }
    # ponytail: native DefaultWindows and troubleshooting options are LAB ONLY, not a strict production catalog.
    Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml' -Destination $policyPath
    Set-CIPolicyIdInfo -FilePath $policyPath -ResetPolicyID -PolicyName 'Guard LAB ONLY signed feasibility' | Out-Null
    foreach ($option in @(0,3,9,10,11,16)) { Set-RuleOption -FilePath $policyPath -Option $option | Out-Null }
    Add-SignerRule -FilePath $policyPath -CertificatePath (Join-Path $root 'lab-signer.cer') -Update -Supplemental
    Set-RuleOption -FilePath $policyPath -Option 6 -Delete | Out-Null
    Set-CIPolicyVersion -FilePath $policyPath -Version '1.0.0.0' | Out-Null
    ConvertFrom-CIPolicy -XmlFilePath $policyPath -BinaryFilePath (Join-Path $root 'unsigned-audit.cip') | Out-Null
    Set-RuleOption -FilePath $policyPath -Option 3 -Delete | Out-Null
    Set-CIPolicyVersion -FilePath $policyPath -Version '2.0.0.0' | Out-Null
    ConvertFrom-CIPolicy -XmlFilePath $policyPath -BinaryFilePath (Join-Path $root 'unsigned-enforce.cip') | Out-Null
    $revokedPath = Join-Path $root 'AppControl.revoked.xml'
    Copy-Item -LiteralPath $policyPath -Destination $revokedPath
    $scanPath = Join-Path $root 'grant-target'
    New-Item -ItemType Directory -Path $scanPath -Force | Out-Null
    Copy-Item -LiteralPath $marker -Destination (Join-Path $scanPath 'marker-v1.exe')
    $hashPath = Join-Path $root 'AppControl.hash.xml'
    New-CIPolicy -ScanPath $scanPath -FilePath $hashPath -Level Hash -UserPEs -MultiplePolicyFormat | Out-Null
    $hashXml = [xml](Get-Content -LiteralPath $hashPath -Raw)
    # Keep one native SHA-256 file hash, not SHA-1/page hashes, paths or publishers.
    $hashRules = @($hashXml.SiPolicy.FileRules.ChildNodes | Where-Object {$_.NodeType -eq 'Element'})
    $keptRules = @($hashRules | Where-Object {$_.LocalName -eq 'Allow' -and $_.Hash -match '^[a-fA-F0-9]{64}$' -and $_.FriendlyName -match 'Hash Sha256$'})
    if ($keptRules.Count -ne 1) { throw 'Unexpected native SHA-256 rule shape' }
    foreach ($rule in $hashRules) {
        if ($rule.ID -eq $keptRules[0].ID) { continue }
        foreach ($reference in @($hashXml.SelectNodes("//*[local-name()='FileRuleRef']") | Where-Object {$_.RuleID -eq $rule.ID})) { $reference.ParentNode.RemoveChild($reference) | Out-Null }
        $rule.ParentNode.RemoveChild($rule) | Out-Null
    }
    $hashXml.Save($hashPath)
    $grantPath = Join-Path $root 'AppControl.granted.xml'
    Merge-CIPolicy -PolicyPaths @($revokedPath,$hashPath) -OutputFilePath $grantPath | Out-Null
    Set-RuleOption -FilePath $grantPath -Option 3 -Delete | Out-Null
    Set-RuleOption -FilePath $grantPath -Option 6 -Delete | Out-Null
    Set-CIPolicyVersion -FilePath $grantPath -Version '3.0.0.0' | Out-Null
    $grantXml = [xml](Get-Content -LiteralPath $grantPath -Raw)
    $baseXml = [xml](Get-Content -LiteralPath $policyPath -Raw)
    if ($grantXml.SiPolicy.PolicyID -ne $baseXml.SiPolicy.PolicyID -or $grantXml.SiPolicy.BasePolicyID -ne $baseXml.SiPolicy.BasePolicyID) { throw 'Grant changed base policy identity' }
    $grantedRules = @($grantXml.SiPolicy.FileRules.Allow | Where-Object {$_.Hash -eq $keptRules[0].Hash})
    $userRuleIds = @($grantXml.SiPolicy.SigningScenarios.SigningScenario | Where-Object {$_.Value -eq '12'} | ForEach-Object {$_.ProductSigners.FileRulesRef.FileRuleRef.RuleID})
    if ($grantedRules.Count -ne 1 -or $userRuleIds -notcontains $grantedRules[0].ID) { throw 'Native SHA-256 grant is not linked to UMCI' }
    ConvertFrom-CIPolicy -XmlFilePath $grantPath -BinaryFilePath (Join-Path $root 'unsigned-grant.cip') | Out-Null
    Set-CIPolicyVersion -FilePath $revokedPath -Version '4.0.0.0' | Out-Null
    ConvertFrom-CIPolicy -XmlFilePath $revokedPath -BinaryFilePath (Join-Path $root 'unsigned-revoke.cip') | Out-Null
    # Prepare the authorized higher-version recovery BEFORE deploying any signed policy.
    Set-RuleOption -FilePath $policyPath -Option 3 | Out-Null
    Set-RuleOption -FilePath $policyPath -Option 6 | Out-Null
    Set-CIPolicyVersion -FilePath $policyPath -Version '5.0.0.0' | Out-Null
    ConvertFrom-CIPolicy -XmlFilePath $policyPath -BinaryFilePath (Join-Path $root 'unsigned-recovery.cip') | Out-Null
    $xml = [xml](Get-Content -LiteralPath $policyPath -Raw)
    return [pscustomobject]@{PolicyId=$xml.SiPolicy.PolicyID;BeforePolicy=(Wait-MarkerDecision $marker 'Allowed');HasUpdateSigner=(@($xml.SiPolicy.UpdatePolicySigners.UpdatePolicySigner).Count -gt 0);NativeGrantSha256=$keptRules[0].Hash;FlatMarkerSha256=(Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash;GrantLinkedToUmci=$true}
}
$xml = [xml](Get-Content -LiteralPath $policyPath -Raw)
$policyId = [guid]$xml.SiPolicy.PolicyID
$policyName = '{' + $policyId.ToString() + '}.cip'
if ($Phase -in @('Audit','Enforce','Grant','Revoke','Recovery')) {
    $signedPath = Join-Path $root ('signed-' + $Phase.ToLowerInvariant() + '\' + $policyName)
    & $ciTool --update-policy $signedPath -json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw ('Signed ' + $Phase + ' update failed: ' + $LASTEXITCODE) }
    $efiMount = Join-Path $root 'efi'
    New-Item -ItemType Directory -Path $efiMount -Force | Out-Null
    $systemPartitions = @(Get-Partition | Where-Object IsSystem)
    if ($systemPartitions.Count -ne 1 -or $systemPartitions[0].GptType -ne '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}') { throw 'Unexpected guest EFI partition' }
    $efiVolume = @($systemPartitions[0].AccessPaths | Where-Object {$_ -match '^\\\\\?\\Volume\{[a-fA-F0-9-]+\}\\$'})
    if ($efiVolume.Count -ne 1) { throw 'Guest EFI volume identity unavailable' }
    $mountOutput = & 'C:\Windows\System32\mountvol.exe' $efiMount $efiVolume[0]
    if ($LASTEXITCODE -ne 0) { throw ('Guest EFI mount failed: ' + $LASTEXITCODE + '; ' + ($mountOutput | Out-String).Trim()) }
    try {
        $efiPolicies = Join-Path $efiMount 'EFI\Microsoft\Boot\CiPolicies\Active'
        New-Item -ItemType Directory -Path $efiPolicies -Force | Out-Null
        Copy-Item -LiteralPath $signedPath -Destination (Join-Path $efiPolicies $policyName) -Force
    } finally {
        & 'C:\Windows\System32\mountvol.exe' $efiMount /D
        if ($LASTEXITCODE -ne 0) { throw 'Guest EFI unmount failed' }
    }
} elseif ($Phase -in @('Tamper','Remove')) {
    $output = & $ciTool --remove-policy ('{' + $policyId.ToString() + '}') -json
    $removeExit = $LASTEXITCODE
    if ($Phase -eq 'Remove' -and $removeExit -ne 0) { throw ('Authorized remove failed: ' + $removeExit) }
}
$inventoryOutput = & $ciTool --list-policies -json
if ($LASTEXITCODE -ne 0) { throw 'Native inventory failed' }
$policies = @((($inventoryOutput | Out-String) | ConvertFrom-Json).Policies | Where-Object {[guid]$_.PolicyID -eq $policyId})
if ($Phase -eq 'Remove') {
    if ($policies.Count) { throw 'Lab policy remains after authorized removal' }
    return [pscustomobject]@{PolicyAbsent=$true;Marker=(Wait-MarkerDecision $marker 'Allowed')}
}
$nativeState = ($policies | Select-Object PolicyID,IsSignedPolicy,IsOnDisk,IsEnforced,IsAuthorized,Status,Version | ConvertTo-Json -Compress)
if ($policies.Count -ne 1) { throw ('Lab policy missing from native inventory: ' + $nativeState) }
# IsEnforced/IsAuthorized are not audit-activation proof. Verify audit using a policy-specific native event.
if ($Phase -notin @('Audit','Recovery') -and $policies[0].IsSignedPolicy -ne $true) { throw ('Expected signed policy missing: ' + $nativeState) }
if ($Phase -in @('Enforce','VerifyEnforce','Tamper','Grant','VerifyGrant','Revoke','VerifyRevoke') -and ($policies[0].IsEnforced -ne $true -or $policies[0].IsAuthorized -ne $true)) { throw ('Expected enforced authorized signed policy missing: ' + $nativeState) }
$expected = if ($Phase -in @('Enforce','VerifyEnforce','Tamper','Revoke','VerifyRevoke')) {'Blocked'} else {'Allowed'}
if ($Phase -eq 'Tamper' -and $removeExit -eq 0) { throw 'Administrator removed signed base policy' }
$eventStart = Get-Date
$nativeTtlGate = $null
if ($Phase -eq 'VerifyGrant') {
    $deadline = [datetime]::ParseExact((Get-Content -LiteralPath (Join-Path $root 'grant-expiry.txt') -Raw).Trim(), 'o', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
    if ([datetime]::UtcNow -lt $deadline) { throw 'Grant expiry observation ran before the deadline' }
    # No Guard/reconciler is installed. Observe native-only expiry; do not fake it with a test timer.
    $decision = Get-MarkerDecision $marker
    $nativeTtlGate = if ($decision -eq 'Blocked') {'PASS'} else {'FAIL'}
} else {
    try { $decision = Wait-MarkerDecision $marker $expected }
    catch {
        $markerFailure = $_.Exception.Message
        $markerCodes = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational';Id=3077;StartTime=$eventStart} -MaxEvents 32 -ErrorAction SilentlyContinue | Where-Object {
            $_.ToXml() -match 'GuardLab\\marker-v1\.exe' -and $_.ToXml() -match [regex]::Escape($policyId.ToString())
        } | Select-Object -First 2 | ForEach-Object {
            $eventXml = [xml]$_.ToXml()
            $codes = [ordered]@{}
            foreach ($data in @($eventXml.Event.EventData.Data)) {
                $name = $data.GetAttribute('Name')
                if ($name -in @('SHA256 Hash','SHA256 Flat Hash','SI Signing Scenario','Status','StatusCode','PolicyGUID','PolicyID')) { $codes[$name] = $data.InnerText }
            }
            [pscustomobject]$codes
        })
        throw ($markerFailure + '; native=' + $nativeState + '; markerCodes=' + (ConvertTo-Json -InputObject $markerCodes -Compress))
    }
}
if ($Phase -in @('Grant','VerifyGrant')) {
    if ((Wait-MarkerDecision (Join-Path $root 'marker-v2.exe') 'Blocked') -ne 'Blocked') { throw 'Grant expanded to variant two' }
    if ($Phase -eq 'Grant') { [datetime]::UtcNow.AddSeconds(5).ToString('o') | Set-Content -LiteralPath (Join-Path $root 'grant-expiry.txt') -Encoding ASCII }
}
$eventCount = $null
if ($Phase -in @('VerifyAudit','VerifyEnforce','VerifyRevoke')) {
    $eventId = if ($Phase -eq 'VerifyAudit') {3076} else {3077}
    $eventDeadline = [datetime]::UtcNow.AddSeconds(10)
    do {
        $eventCount = Get-MarkerPolicyEventCount $eventId $eventStart $policyId
        if ($eventCount -gt 0) { break }
        Start-Sleep -Milliseconds 200
    } while ([datetime]::UtcNow -lt $eventDeadline)
    if ($eventCount -eq 0) {
        # Only policy-correlated activation codes, never raw events, paths or certificate details.
        $activationEvents = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational';StartTime=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime} -MaxEvents 200 -ErrorAction SilentlyContinue | Where-Object {
            $_.ToXml() -match [regex]::Escape($policyId.ToString())
        } | Select-Object -First 8 | ForEach-Object {
            $eventXml = [xml]$_.ToXml()
            $codes = [ordered]@{}
            foreach ($data in @($eventXml.Event.EventData.Data)) {
                $name = $data.GetAttribute('Name')
                if ($name -in @('Status','StatusCode','ErrorCode','VerificationError','PolicyID','PolicyId')) { $codes[$name] = $data.InnerText }
            }
            [pscustomobject]@{Id=$_.Id;Codes=[pscustomobject]$codes}
        })
        throw ('No marker-specific event ' + $eventId + ' for signed policy after boot; native=' + $nativeState + '; activation=' + (ConvertTo-Json -InputObject $activationEvents -Depth 4 -Compress))
    }
}
[pscustomobject]@{PolicyId=$policyId.ToString();Phase=$Phase;Marker=$decision;PolicyEvents=$eventCount;Signed=$policies[0].IsSignedPolicy;Authorized=$policies[0].IsAuthorized;Enforced=$policies[0].IsEnforced;RemoveExit=$removeExit;NativeOnlyTtlGate=$nativeTtlGate;GrantDeadlineExpired=($Phase -eq 'VerifyGrant');ReconcilerInstalled=$false;VariantTwo=$(if ($Phase -in @('Grant','VerifyGrant')) {'Blocked'} else {$null})}
