$ErrorActionPreference = 'Stop'
foreach ($file in @('Get-GuestBaseline.ps1', 'Test-LabSafety.ps1', 'Test-AppLockerFeasibility.ps1', 'Invoke-AppLockerLab.ps1')) {
    $tokens = $null
    $parseErrors = $null
    [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file), [ref]$tokens, [ref]$parseErrors) | Out-Null
    if ($parseErrors.Count) { throw ('Parse failure: ' + $file) }
}
foreach ($probe in @('Get-GuestBaseline.ps1', 'Test-AppLockerFeasibility.ps1')) {
    try {
        & (Join-Path $PSScriptRoot $probe) -ExpectedUuid ([guid]::Empty) -HostComputerName $env:COMPUTERNAME
        throw 'Host guard did not reject execution'
    } catch {
        if ($_.Exception.Message -ne 'This probe can run only in the validated disposable Hyper-V guest.') { throw }
    }
}
$compiler = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw 'Existing Framework compiler unavailable' }
$tempRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
$outputRoot = [IO.Path]::GetFullPath((Join-Path $tempRoot ('guard-lab-marker-' + [guid]::NewGuid().ToString('N'))))
if (-not $outputRoot.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected temporary output root' }
New-Item -ItemType Directory -Path $outputRoot | Out-Null
$markerOne = Join-Path $outputRoot 'marker-v1.exe'
$markerTwo = Join-Path $outputRoot 'marker-v2.exe'
try {
    & $compiler /nologo /target:exe /optimize+ /warnaserror+ ('/out:' + $markerOne) (Join-Path $PSScriptRoot 'Marker.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Marker v1 compile failed' }
    & $compiler /nologo /target:exe /optimize+ /warnaserror+ /define:VARIANT_TWO ('/out:' + $markerTwo) (Join-Path $PSScriptRoot 'Marker.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Marker v2 compile failed' }
    foreach ($marker in @($markerOne, $markerTwo)) {
        $process = New-Object Diagnostics.Process
        $process.StartInfo.FileName = $marker
        $process.StartInfo.Arguments = '--self-test'
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        try {
            $process.Start() | Out-Null
            if (-not $process.WaitForExit(15000)) { $process.Kill(); throw 'Marker self-test timed out' }
            $sentinel = $process.StandardOutput.ReadToEnd().Trim()
            if ($process.ExitCode -ne 0 -or $sentinel -notmatch '^MARKER_SELF_TEST_PASS v[12]$') { throw 'Marker self-test failed' }
            $sentinel
        } finally { $process.Dispose() }
    }
    $hashOne = (Get-FileHash -LiteralPath $markerOne -Algorithm SHA256).Hash
    $hashTwo = (Get-FileHash -LiteralPath $markerTwo -Algorithm SHA256).Hash
    if ($hashOne -eq $hashTwo) { throw 'Marker variants must have distinct exact identities' }
} finally {
    $folder = Get-Item -LiteralPath $outputRoot
    if ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Temporary directory became a reparse point; cleanup refused' }
    Remove-Item -LiteralPath $folder.FullName -Recurse
}
[pscustomobject]@{Status='PASS';HostGuard='REJECTED';TemporaryFilesRemoved=(-not (Test-Path -LiteralPath $outputRoot));VariantOneSha256=$hashOne;VariantTwoSha256=$hashTwo}
