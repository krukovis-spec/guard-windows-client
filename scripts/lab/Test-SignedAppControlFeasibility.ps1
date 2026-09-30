param(
    [Parameter(Mandatory = $true)][guid]$ExpectedUuid,
    [Parameter(Mandatory = $true)][string]$HostComputerName,
    [ValidateSet('Prepare','Audit','VerifyAudit','Enforce','VerifyEnforce','Tamper','Recovery','Remove')][string]$Phase = 'Prepare'
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
    # Prepare the authorized higher-version recovery BEFORE deploying any signed policy.
    Set-RuleOption -FilePath $policyPath -Option 3 | Out-Null
    Set-RuleOption -FilePath $policyPath -Option 6 | Out-Null
    Set-CIPolicyVersion -FilePath $policyPath -Version '3.0.0.0' | Out-Null
    ConvertFrom-CIPolicy -XmlFilePath $policyPath -BinaryFilePath (Join-Path $root 'unsigned-recovery.cip') | Out-Null
    $xml = [xml](Get-Content -LiteralPath $policyPath -Raw)
    return [pscustomobject]@{PolicyId=$xml.SiPolicy.PolicyID;BeforePolicy=(Wait-MarkerDecision $marker 'Allowed');HasUpdateSigner=(@($xml.SiPolicy.UpdatePolicySigners.UpdatePolicySigner).Count -gt 0)}
}
$xml = [xml](Get-Content -LiteralPath $policyPath -Raw)
$policyId = [guid]$xml.SiPolicy.PolicyID
$policyName = '{' + $policyId.ToString() + '}.cip'
if ($Phase -in @('Audit','Enforce','Recovery')) {
    $signedPath = Join-Path $root ('signed-' + $Phase.ToLowerInvariant() + '\' + $policyName)
    & $ciTool --update-policy $signedPath -json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw ('Signed ' + $Phase + ' update failed: ' + $LASTEXITCODE) }
    $efiMount = Join-Path $root 'efi'
    New-Item -ItemType Directory -Path $efiMount -Force | Out-Null
    & 'C:\Windows\System32\mountvol.exe' $efiMount /S
    if ($LASTEXITCODE -ne 0) { throw 'Guest EFI mount failed' }
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
if ($policies.Count -ne 1 -or $policies[0].IsSignedPolicy -ne $true -or $policies[0].IsAuthorized -ne $true) { throw 'Expected authorized signed policy missing' }
$expected = if ($Phase -in @('Enforce','VerifyEnforce','Tamper')) {'Blocked'} else {'Allowed'}
if ($Phase -eq 'Tamper' -and $removeExit -eq 0) { throw 'Administrator removed signed base policy' }
[pscustomobject]@{PolicyId=$policyId.ToString();Phase=$Phase;Marker=(Wait-MarkerDecision $marker $expected);Signed=$policies[0].IsSignedPolicy;Enforced=$policies[0].IsEnforced;RemoveExit=$removeExit}
