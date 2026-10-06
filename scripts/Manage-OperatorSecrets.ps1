#Requires -Version 7.6
param(
    [ValidateSet('Import', 'Verify', 'ConfigureRelay', 'DisableBootstrap')][string]$Action = 'Verify',
    [Parameter(Mandatory)][string]$Directory,
    [string]$HandoffFile,
    [string]$MailboxJob
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$names = @('BOOTSTRAP_ADMIN_TOKEN', 'MAILBOX_ADMIN_TOKEN', 'SESSION_SECRET')
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$stage = 'local-validation'

function Assert-LocalPath([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or
        ($Path -split '[\\/]' | Where-Object { $_.EndsWith('.') -or $_.EndsWith(' ') })) { throw 'Invalid local path.' }
    $full = [IO.Path]::GetFullPath($Path)
    $item = if (Test-Path -LiteralPath $full) { Get-Item -LiteralPath $full -Force } else { [IO.FileInfo]::new($full) }
    while ($null -ne $item) {
        if (($item.Exists -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) -or
            (Test-Path -LiteralPath (Join-Path $item.FullName '.git'))) { throw 'Redirected or Git path.' }
        $item = if ($item -is [IO.FileInfo]) { $item.Directory } else { $item.Parent }
    }
}
function Assert-PrivateAcl($Acl, [bool]$AllowInherited = $false) {
    $rules = @($Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value -or $rules.Count -ne 1 -or
        $rules[0].IdentityReference.Value -ne $sid.Value -or $rules[0].AccessControlType -ne 'Allow' -or
        $rules[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
        (-not $AllowInherited -and (-not $Acl.AreAccessRulesProtected -or $rules[0].IsInherited))) { throw 'Non-private ACL.' }
}
function Read-Private([string]$Path, [bool]$AllowInherited = $false) {
    Assert-LocalPath $Path
    $file = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        Assert-PrivateAcl ([IO.FileSystemAclExtensions]::GetAccessControl($file)) $AllowInherited
        if ($file.Length -lt 1 -or $file.Length -gt 8192) { throw 'File size.' }
        $bytes = [byte[]]::new($file.Length); $file.ReadExactly($bytes)
        return ,$bytes
    } finally { $file.Dispose() }
}
function Save-Private([string]$Path, [byte[]]$Bytes) {
    Assert-LocalPath $Path
    $acl = [Security.AccessControl.FileSecurity]::new(); $acl.SetOwner($sid); $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
    $file = [IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new($Path), [IO.FileMode]::CreateNew,
        [Security.AccessControl.FileSystemRights]::FullControl, [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough, $acl)
    try { $file.Write($Bytes); $file.Flush($true) } finally { $file.Dispose() }
}
function Read-Secret([string]$Name) {
    $bytes = [Guard.Windows.Cryptography.LocalSystemDpapiDataProtector]::ForOperatorCredential($Name).Unprotect(
        (Read-Private (Join-Path $Directory ($Name + '.dpapi'))))
    try {
        $value = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        if ($value -cnotmatch '^[!-~]{32,512}$') { throw 'Secret format.' }
        return $value
    } finally { [Array]::Clear($bytes) }
}

try {
    Assert-LocalPath $Directory
    $assembly = Join-Path $PSScriptRoot '..\tools\Guard.Provisioning\bin\Release\net10.0-windows\Guard.Windows.dll'
    Add-Type -Path ([IO.Path]::GetFullPath($assembly))
    if ($Action -eq 'Import') {
        $stage = 'import'
        if (-not $HandoffFile) { throw 'Handoff required.' }
        $bytes = Read-Private $HandoffFile $true
        try { $note = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) } finally { [Array]::Clear($bytes) }
        $values = @{}
        foreach ($name in $names) {
            $matches = [regex]::Matches($note, '(?m)^' + $name + '\r?\n([!-~]{32,512})\r?$')
            if ($matches.Count -ne 1) { throw 'Missing or duplicate secret.' }
            $values[$name] = $matches[0].Groups[1].Value
        }
        if (@($values.Values | Select-Object -Unique).Count -ne 3) { throw 'Separate credentials required.' }
        if (-not (Test-Path -LiteralPath $Directory)) {
            $acl = [Security.AccessControl.DirectorySecurity]::new(); $acl.SetOwner($sid); $acl.SetAccessRuleProtection($true, $false)
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
            [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($Directory), $acl)
        }
        Assert-PrivateAcl (Get-Acl -LiteralPath $Directory)
        foreach ($name in $names) {
            if (Test-Path -LiteralPath (Join-Path $Directory ($name + '.dpapi'))) { throw 'Refusing overwrite; inspect existing import.' }
        }
        foreach ($name in $names) {
            $raw = [Text.Encoding]::UTF8.GetBytes($values[$name])
            try {
                Save-Private (Join-Path $Directory ($name + '.dpapi')) (
                    [Guard.Windows.Cryptography.LocalSystemDpapiDataProtector]::ForOperatorCredential($name).Protect($raw))
            } finally { [Array]::Clear($raw) }
            if ((Read-Secret $name) -cne $values[$name]) { throw 'Import roundtrip mismatch.' }
        }
        $values.Clear(); $note = $null
        Write-Output 'Imported 3 purpose-bound CurrentUser DPAPI secrets; private ACL/roundtrip verified. Plaintext source retained for explicit cleanup.'
        exit 0
    }
    Assert-PrivateAcl (Get-Acl -LiteralPath $Directory)
    foreach ($name in $names) { $null = Read-Secret $name }
    $stage = 'cloudflare'
    $deploymentPath = Join-Path $env:LOCALAPPDATA 'Codex\service-connections\secrets\cloudflare-guard-api-token.dpapi'
    $raw = [Security.Cryptography.ProtectedData]::Unprotect((Read-Private $deploymentPath), $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    try { $deploymentToken = [Text.Encoding]::UTF8.GetString($raw) } finally { [Array]::Clear($raw) }
    $handler = [Net.Http.HttpClientHandler]::new(); $handler.AllowAutoRedirect = $false; $handler.UseProxy = $false; $handler.UseCookies = $false
    $client = [Net.Http.HttpClient]::new($handler); $client.Timeout = [TimeSpan]::FromSeconds(30); $client.MaxResponseContentBufferSize = 1048576
    $client.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $deploymentToken)
    $api = 'https://api.cloudflare.com/client/v4/accounts/7135a2335784ee593d8942ef1d79525f/workers/scripts/guard-relay'
    function Invoke-GuardApi([string]$Method, [string]$Suffix, $Body = $null) {
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), $api + $Suffix)
        try {
            if ($null -ne $Body) { $request.Content = [Net.Http.StringContent]::new(($Body | ConvertTo-Json -Compress), [Text.Encoding]::UTF8, 'application/json') }
            $response = $client.SendAsync($request).GetAwaiter().GetResult()
            try {
                if (-not $response.IsSuccessStatusCode) { Write-Output ('Guard API HTTP ' + [int]$response.StatusCode) | Out-Host; throw 'Guard API refused.' }
                $result = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
                if (-not $result.success) { throw 'Guard API refused.' }
                return $result.result
            } finally { $response.Dispose() }
        } finally { $request.Dispose() }
    }
    try {
        $settings = Invoke-GuardApi GET '/settings'
        $do = @($settings.bindings | Where-Object name -eq 'DEVICE_MAILBOX')
        if ($do.Count -ne 1 -or $do[0].namespace_id -ne '78b007211e7d41608554d534d0b4b663') { throw 'Guard namespace mismatch.' }
        if ($Action -eq 'ConfigureRelay') {
            foreach ($name in @('SESSION_SECRET', 'BOOTSTRAP_ADMIN_TOKEN')) {
                if (@($settings.bindings | Where-Object name -eq $name).Count) { throw 'Secret exists; no automatic replacement.' }
            }
            foreach ($name in @('SESSION_SECRET', 'BOOTSTRAP_ADMIN_TOKEN')) {
                $null = Invoke-GuardApi PUT '/secrets' @{ name = $name; type = 'secret_text'; text = (Read-Secret $name) }
                Write-Output ('Configured ' + $name + ' on guard-relay only.')
            }
        } elseif ($Action -eq 'DisableBootstrap') {
            if (@($settings.bindings | Where-Object name -eq 'BOOTSTRAP_ADMIN_TOKEN').Count -ne 1) { throw 'Bootstrap not configured.' }
            $null = Invoke-GuardApi DELETE '/secrets/BOOTSTRAP_ADMIN_TOKEN'
            Write-Output 'Bootstrap disabled; issued mailbox credentials unchanged.'
        }
        $settings = Invoke-GuardApi GET '/settings'
        $do = @($settings.bindings | Where-Object name -eq 'DEVICE_MAILBOX')
        if ($do.Count -ne 1 -or $do[0].namespace_id -ne '78b007211e7d41608554d534d0b4b663') { throw 'Guard namespace changed.' }
        $deployments = Invoke-GuardApi GET '/deployments'
        [PSCustomObject]@{ Action=$Action; LocalSecretsVerified=3; Bindings=@($settings.bindings | ForEach-Object { $_.name + ':' + $_.type }); LatestDeployment=$deployments.deployments[0].id; Versions=$deployments.deployments[0].versions } | ConvertTo-Json -Depth 5 -Compress
        if ($MailboxJob) {
            $stage = 'mailbox-verification'
            $raw = [Guard.Windows.Cryptography.LocalSystemDpapiDataProtector]::ForOperatorMailbox().Unprotect((Read-Private $MailboxJob))
            try { $job = [Text.UTF8Encoding]::new($false, $true).GetString($raw) | ConvertFrom-Json } finally { [Array]::Clear($raw) }
            if ($job.version -ne 1 -or $job.relayOrigin -cne 'https://guard-relay.voicepaste.workers.dev' -or
                $job.mailboxId -cnotmatch '^[A-Za-z0-9._:-]{16,128}$' -or $job.mailboxId -eq 'guard:bff:auth:v1' -or
                $job.accessToken -cne (Read-Secret 'MAILBOX_ADMIN_TOKEN')) { throw 'Mailbox binding mismatch.' }
            # Never send the deployment credential to the Worker application endpoint.
            $client.DefaultRequestHeaders.Authorization = $null
            $endpoint = $job.relayOrigin + '/v1/mailboxes/' + $job.mailboxId + '/poll?recipient=guard-operator-check&after=0&limit=1'
            foreach ($mode in @('Valid', 'Missing', 'Wrong')) {
                $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $endpoint)
                try {
                    if ($mode -ne 'Missing') {
                        $credential = if ($mode -eq 'Valid') { $job.accessToken } else { 'synthetic-invalid-operator-token-000' }
                        $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $credential)
                    }
                    $response = $client.SendAsync($request).GetAwaiter().GetResult()
                    try {
                        $expected = if ($mode -eq 'Valid') { 200 } else { 401 }
                        if ([int]$response.StatusCode -ne $expected) { throw 'Mailbox authorization check failed.' }
                        if ($mode -eq 'Valid') {
                            $page = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
                            if ($page.frames.Count -ne 0 -or $page.nextCursor -ne 0) { throw 'Unexpected probe recipient data.' }
                        }
                        Write-Output ('Mailbox ' + $mode + ': HTTP ' + $expected)
                    } finally { $response.Dispose() }
                } finally { $request.Dispose() }
            }
        }
    } finally { $client.Dispose(); $deploymentToken = $null }
} catch {
    # Never print exceptions or remote response bodies: they may contain secret material.
    Write-Output ('FAILED at ' + $stage + '; no automatic retry or overwrite. Inspect state without printing secrets.')
    exit 1
}
