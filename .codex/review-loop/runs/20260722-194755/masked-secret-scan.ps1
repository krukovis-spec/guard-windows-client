$ErrorActionPreference = 'Stop'

$patterns = @(
    @{ Id = 'aws_access_key'; Regex = 'AKIA[0-9A-Z]{16}' },
    @{ Id = 'github_token'; Regex = '(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})' },
    @{ Id = 'openai_key'; Regex = 'sk-[A-Za-z0-9_-]{20,}' },
    @{ Id = 'slack_token'; Regex = 'xox[baprs]-[A-Za-z0-9-]{20,}' },
    @{ Id = 'private_key'; Regex = '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----' },
    @{ Id = 'credential_url'; Regex = 'https?://[^/\s:@]+:[^/\s@]+@' }
)

$files = & git ls-files --modified --others --exclude-standard
$files = @($files | Where-Object {
    $_ -notmatch '^"' -and
    $_ -notmatch '\\[0-9]{3}' -and
    $_ -notlike 'Output/*' -and
    $_ -notlike '.gstack/*' -and
    $_ -notmatch '\.(exe|dll|pdb)$'
})

$hits = @()
foreach ($file in $files) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { continue }
    $content = Get-Content -LiteralPath $file -Raw -Encoding UTF8
    foreach ($pattern in $patterns) {
        if ($content -match $pattern.Regex) {
            $hits += [pscustomobject]@{ Rule = $pattern.Id; File = $file }
        }
    }
}

if ($hits.Count -gt 0) {
    $hits | Sort-Object Rule, File -Unique | Format-Table -AutoSize
    exit 1
}

Write-Output 'NO_HIGH_CONFIDENCE_SECRET_PATTERNS'
