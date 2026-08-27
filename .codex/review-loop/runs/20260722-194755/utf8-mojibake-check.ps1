$ErrorActionPreference = 'Stop'

$strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
$badFiles = @()
$markdownFiles = @(& git diff --name-only -- '*.md')

foreach ($file in $markdownFiles) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { continue }
    try {
        $content = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $file).Path, $strictUtf8)
    }
    catch {
        $badFiles += "$file invalid-utf8"
        continue
    }

    if ($content.IndexOf([char]0xFFFD) -ge 0 -or
        $content.IndexOf([char]0x00C3) -ge 0 -or
        $content.IndexOf([char]0x00C2) -ge 0 -or
        $content.IndexOf([char]0x00D0) -ge 0 -or
        $content.IndexOf([char]0x00D1) -ge 0) {
        $badFiles += "$file mojibake-marker"
    }
}

if ($badFiles.Count -gt 0) {
    $badFiles
    exit 1
}

Write-Output 'UTF8_MOJIBAKE_CHECK=passed'
