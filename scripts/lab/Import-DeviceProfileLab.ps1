# Guest only: stage an encrypted GDI1 using SYSTEM, import it, then open the existing setup UI.
param(
    [Parameter(Mandatory=$true)][guid]$ExpectedUuid,
    [Parameter(Mandatory=$true)][string]$HostComputerName,
    [Parameter(Mandatory=$true)][string]$PackageRoot,
    [Parameter(Mandatory=$true)][string]$ProfileSha256,
    [string]$DescriptorSha256,
    [switch]$SystemStage,
    [switch]$UseStaged
)
$ErrorActionPreference='Stop'
$machine=Get-CimInstance Win32_ComputerSystem
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if ($env:COMPUTERNAME -eq $HostComputerName -or $env:COMPUTERNAME -ne 'DESKTOP-8C2FU3H' -or
    $ExpectedUuid -ne [guid]'236ea6ef-9cc6-4295-9934-6f7497f9d262' -or
    [guid](Get-CimInstance Win32_ComputerSystemProduct).UUID -ne $ExpectedUuid -or
    $machine.Manufacturer -ne 'Microsoft Corporation' -or $machine.Model -ne 'Virtual Machine' -or
    -not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    ([bool]$SystemStage -ne $identity.IsSystem)) {
    throw 'This probe can run only in the validated disposable Hyper-V guest.'
}
$identity.Dispose()
if ($PackageRoot -cnotmatch '^C:\\GuardLab\\ServiceSmoke-[a-f0-9]{32}$' -or
    $ProfileSha256 -cnotmatch '^[A-F0-9]{64}$') { throw 'Invalid phone lab binding' }
$source=Join-Path $PackageRoot 'device.profile'
$resultFile=Join-Path $PackageRoot 'profile-stage-result.json'
foreach ($path in @('C:\GuardLab',$PackageRoot,$source)) {
    if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected phone lab input' }
}
$inputFile=Get-Item -LiteralPath $source
if ($inputFile.Length -lt 100 -or $inputFile.Length -gt 8192 -or
    (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -cne $ProfileSha256) { throw 'Encrypted profile mismatch' }

if ($SystemStage) {
    $bytes=$null
    try {
        if (Test-Path -LiteralPath $resultFile) { throw 'Stage result exists; inspect before retry' }
        foreach ($folder in @('C:\ProgramData','C:\ProgramData\Guard','C:\ProgramData\Guard\v2')) {
            if ((Get-Item -LiteralPath $folder -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected service data' }
        }
        $bytes=[IO.File]::ReadAllBytes($source)
        $hash=[Security.Cryptography.SHA256]::Create()
        try { $digest=[BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','') } finally { $hash.Dispose() }
        if ($digest -cne $ProfileSha256 -or [Text.Encoding]::ASCII.GetString($bytes,0,4) -cne 'GDI1') { throw 'Profile changed before staging' }
        $target='C:\ProgramData\Guard\v2\device.relay.install'
        $pending=$target+'.pending'
        if ([IO.File]::Exists($target) -or [IO.File]::Exists($pending) -or
            [IO.File]::Exists('C:\ProgramData\Guard\v2\device.relay')) { throw 'Existing profile; no replacement' }
        $systemSid=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
        $acl=New-Object Security.AccessControl.FileSecurity
        $acl.SetOwner($systemSid); $acl.SetAccessRuleProtection($true,$false)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($systemSid,'FullControl','Allow')))
        $stream=[IO.File]::Create($pending,4096,[IO.FileOptions]::WriteThrough,$acl)
        try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        $actual=[IO.File]::GetAccessControl($pending)
        $rules=@($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        if ($actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-18' -or
            -not $actual.AreAccessRulesProtected -or $rules.Count -ne 1 -or
            $rules[0].IdentityReference.Value -ne 'S-1-5-18' -or $rules[0].AccessControlType -ne 'Allow' -or
            $rules[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) { throw 'Staging ACL mismatch' }
        [IO.File]::Move($pending,$target)
        [IO.File]::WriteAllText($resultFile,'{"status":"STAGED","systemOnly":true}',[Text.UTF8Encoding]::new($false))
        exit 0
    } catch {
        # No raw exception messages or key/config content in reports.
        if (-not (Test-Path -LiteralPath $resultFile)) {
            [IO.File]::WriteAllText($resultFile,('{"status":"FAIL","errorType":"'+$_.Exception.GetType().Name+'"}'),[Text.UTF8Encoding]::new($false))
        }
        exit 1
    } finally { if ($bytes) { [Array]::Clear($bytes,0,$bytes.Length) } }
}

if ($DescriptorSha256 -cnotmatch '^[A-F0-9]{64}$') { throw 'Trusted descriptor required' }
$probe=Join-Path $PackageRoot 'probe\Guard.Windows.Ipc.Tests.exe'
$setup=Join-Path $PackageRoot 'setup\Guard.Setup.exe'
$binary='"C:\Program Files\Guard\Guard.Service.exe"'
function Read-Inspection {
    $text=& $probe --installed-service-lab inspect https://guard-relay.voicepaste.workers.dev
    if ($LASTEXITCODE -ne 0) { throw 'Authenticated service inspection refused' }
    $value=($text -join '') | ConvertFrom-Json
    if ($value.status -ne 'PASS' -or $value.ownerBound -ne $false -or
        $value.descriptorSha256 -cne $DescriptorSha256) { throw 'Device identity/state changed' }
    $value
}
$service=Get-CimInstance Win32_Service -Filter "Name='Guard'"
if ($service.StartName -ne 'LocalSystem' -or $service.PathName -cne $binary -or $service.State -ne 'Running') { throw 'Unexpected SCM boundary' }
$null=Read-Inspection
$taskName='GuardLab-Profile-'+[guid]::NewGuid().ToString('N')
$taskCreated=$false
try {
    Stop-Service Guard; (Get-Service Guard).WaitForStatus('Stopped',[timespan]::FromSeconds(30))
    if (-not $UseStaged) {
    $arguments='-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "'+$PSCommandPath+'" -ExpectedUuid '+$ExpectedUuid.ToString()+
        ' -HostComputerName '+$HostComputerName+' -PackageRoot "'+$PackageRoot+'" -ProfileSha256 '+$ProfileSha256+' -SystemStage'
    $action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument $arguments
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([timespan]::FromMinutes(1)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -User 'SYSTEM' -RunLevel Highest -Settings $settings | Out-Null
    $taskCreated=$true
    Start-ScheduledTask -TaskName $taskName
    $deadline=[datetime]::UtcNow.AddSeconds(70)
    while (-not (Test-Path -LiteralPath $resultFile)) {
        if ([datetime]::UtcNow -gt $deadline) { throw 'SYSTEM staging timed out; no retry' }
        Start-Sleep -Milliseconds 250
    }
    }
    $staging=Get-Content -LiteralPath $resultFile -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($staging.status -ne 'STAGED' -or $staging.systemOnly -ne $true) { throw 'SYSTEM staging failed; inspect typed result' }
    $change=Invoke-CimMethod -InputObject (Get-CimInstance Win32_Service -Filter "Name='Guard'") -MethodName Change -Arguments @{PathName=$binary+' --import-device-relay-profile'}
    if ($change.ReturnValue -ne 0) { throw 'Import startup mode failed' }
    Start-Service Guard
    Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class GuardPhonePipeWait { [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] public static extern bool WaitNamedPipe(string name, uint timeout); }'
    $deadline=[datetime]::UtcNow.AddSeconds(35)
    while (-not [GuardPhonePipeWait]::WaitNamedPipe('\\.\pipe\Guard.V2.AdminSetup.v1',500)) {
        if ([datetime]::UtcNow -gt $deadline -or (Get-Service Guard).Status -eq 'Stopped') { throw 'Import endpoint did not start' }
        Start-Sleep -Milliseconds 200
    }
    $reply=& $probe --installed-service-lab reject-bootstrap https://guard-relay.voicepaste.workers.dev
    if ($LASTEXITCODE -ne 0 -or (($reply -join '') | ConvertFrom-Json).bootstrapEndpoint -ne 'REJECTED') { throw 'One-shot endpoint accepted' }
} finally {
    if ($taskCreated) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false }
    $service=Get-CimInstance Win32_Service -Filter "Name='Guard'"
    if ($service.PathName -ceq ($binary+' --import-device-relay-profile')) {
        if ((Get-Service Guard).Status -ne 'Stopped') { Stop-Service Guard; (Get-Service Guard).WaitForStatus('Stopped',[timespan]::FromSeconds(30)) }
        $change=Invoke-CimMethod -InputObject $service -MethodName Change -Arguments @{PathName=$binary}
        if ($change.ReturnValue -ne 0) { throw 'Normal SCM mode restoration failed' }
    }
    if ((Get-CimInstance Win32_Service -Filter "Name='Guard'").PathName -ceq $binary -and (Get-Service Guard).Status -eq 'Stopped') { Start-Service Guard }
}
$inspection=Read-Inspection
$uiTask='GuardLab-Setup-'+[guid]::NewGuid().ToString('N')
$principal=New-ScheduledTaskPrincipal -UserId 'DESKTOP-8C2FU3H\GuardLabAdmin' -LogonType Interactive -RunLevel Highest
$uiAction=New-ScheduledTaskAction -Execute $setup
$uiSettings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([timespan]::FromHours(2)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $uiTask -Action $uiAction -Principal $principal -Settings $uiSettings | Out-Null
Start-ScheduledTask -TaskName $uiTask
[pscustomobject]@{Status='PROFILE_IMPORTED';DescriptorSha256=$inspection.descriptorSha256;SetupTask=$uiTask;
    GuestLoginPresent=[bool](Get-CimInstance Win32_ComputerSystem).UserName;ProtectionAccepted=$false;PolicyWrites=$false}
