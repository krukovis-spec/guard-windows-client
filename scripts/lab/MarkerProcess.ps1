function Get-MarkerDecision([string]$Path, [switch]$SelfTest) {
    $process = New-Object Diagnostics.Process
    $process.StartInfo.FileName = $Path
    if ($SelfTest) { $process.StartInfo.Arguments = '--self-test' }
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    try {
        $process.Start() | Out-Null
        if (-not $process.WaitForExit(15000)) { $process.Kill(); throw 'Marker exceeded its bounded run time' }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $sentinel = if ($SelfTest) { '^MARKER_SELF_TEST_PASS v[12]' } else { '^MARKER_STARTED v[12]' }
        if ($process.ExitCode -ne 0 -or $stdout -notmatch $sentinel) {
            throw ('Marker sentinel failure: exit=' + $process.ExitCode + '; stdout=' + $stdout.Trim() + '; stderr=' + $stderr.Substring(0, [Math]::Min(1000, $stderr.Length)).Trim())
        }
        return 'Allowed'
    } catch {
        $exception = $_.Exception
        while ($exception) {
            if ($exception -is [ComponentModel.Win32Exception] -and $exception.NativeErrorCode -in @(1260,577,4551)) { return 'Blocked' }
            $exception = $exception.InnerException
        }
        throw
    } finally { $process.Dispose() }
}

function Wait-MarkerDecision([string]$Path, [string]$Expected) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        $decision = Get-MarkerDecision $Path
        if ($decision -eq $Expected) { return $decision }
        Start-Sleep -Milliseconds 200
    } while ($timer.Elapsed.TotalSeconds -lt 15)
    throw ('Expected marker decision ' + $Expected + ', observed ' + $decision)
}

function Get-MarkerPolicyEventCount([int]$Id, [datetime]$Start, [guid]$PolicyId) {
    $events = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational';Id=$Id;StartTime=$Start} -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {
        $xml = $_.ToXml()
        $xml -match 'GuardLab\\marker-v1\.exe' -and $xml -match [regex]::Escape($PolicyId.ToString())
    })
    $events.Count
}
