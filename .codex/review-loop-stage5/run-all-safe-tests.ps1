param(
    [Parameter(Mandatory = $true)]
    [string] $MirrorRoot
)

$ErrorActionPreference = 'Stop'
$dotnet = 'C:\Program Files\dotnet\dotnet.exe'

$cases = @(
    [pscustomobject]@{ Name = 'Guard.Tests'; Kind = 'exe'; Tfm = 'net48'; Expected = 45 },
    [pscustomobject]@{ Name = 'Guard.V2.Tests'; Kind = 'dll'; Tfm = 'net8.0'; Expected = 22 },
    [pscustomobject]@{ Name = 'Guard.Protocol.Tests'; Kind = 'dll'; Tfm = 'net8.0'; Expected = 13 },
    [pscustomobject]@{ Name = 'Guard.Policy.Tests'; Kind = 'dll'; Tfm = 'net8.0'; Expected = 6 },
    [pscustomobject]@{ Name = 'Guard.Readiness.Tests'; Kind = 'dll'; Tfm = 'net8.0'; Expected = 9 },
    [pscustomobject]@{ Name = 'Guard.Service.Tests'; Kind = 'dll'; Tfm = 'net10.0-windows'; Expected = 22 },
    [pscustomobject]@{ Name = 'Guard.Storage.Tests'; Kind = 'dll'; Tfm = 'net10.0'; Expected = 22 },
    [pscustomobject]@{ Name = 'Guard.Windows.Accounts.Tests'; Kind = 'dll'; Tfm = 'net10.0-windows'; Expected = 9 },
    [pscustomobject]@{ Name = 'Guard.Windows.Crypto.Tests'; Kind = 'dll'; Tfm = 'net10.0-windows'; Expected = 7 },
    [pscustomobject]@{ Name = 'Guard.Windows.Ipc.Tests'; Kind = 'dll'; Tfm = 'net10.0-windows'; Expected = 10 },
    [pscustomobject]@{ Name = 'Guard.Windows.Storage.Tests'; Kind = 'dll'; Tfm = 'net10.0-windows'; Expected = 4 },
    [pscustomobject]@{ Name = 'Guard.Windows.Readiness.Tests'; Kind = 'dll'; Tfm = 'net10.0-windows'; Expected = 5 },
    [pscustomobject]@{ Name = 'Guard.Windows.ServiceHealth.Tests'; Kind = 'dll'; Tfm = 'net10.0-windows'; Expected = 5 },
    [pscustomobject]@{ Name = 'Guard.Windows.PlatformReadiness.Tests'; Kind = 'dll'; Tfm = 'net10.0-windows'; Expected = 6 },
    [pscustomobject]@{ Name = 'Guard.Windows.ScmQuery.Tests'; Kind = 'dll'; Tfm = 'net10.0-windows'; Expected = 7 },
    [pscustomobject]@{ Name = 'Guard.ApplicationIdentity.Tests'; Kind = 'dll'; Tfm = 'net10.0'; Expected = 8 },
    [pscustomobject]@{ Name = 'Guard.AppControlPolicy.Tests'; Kind = 'dll'; Tfm = 'net10.0'; Expected = 6 },
    [pscustomobject]@{ Name = 'Guard.ApplicationControl.Tests'; Kind = 'dll'; Tfm = 'net10.0'; Expected = 13 },
    [pscustomobject]@{ Name = 'Guard.ApplicationRequestProtocol.Tests'; Kind = 'dll'; Tfm = 'net10.0'; Expected = 11 },
    [pscustomobject]@{ Name = 'Guard.ApplicationRequests.Tests'; Kind = 'dll'; Tfm = 'net10.0'; Expected = 6 },
    [pscustomobject]@{ Name = 'Guard.WebPolicy.Tests'; Kind = 'dll'; Tfm = 'net10.0'; Expected = 9 },
    [pscustomobject]@{ Name = 'Guard.WebProxyProtocol.Tests'; Kind = 'dll'; Tfm = 'net10.0'; Expected = 11 },
    [pscustomobject]@{ Name = 'Guard.BrowserPolicy.Tests'; Kind = 'dll'; Tfm = 'net10.0-windows'; Expected = 7 },
    [pscustomobject]@{ Name = 'Guard.WebsiteRequestProtocol.Tests'; Kind = 'dll'; Tfm = 'net10.0'; Expected = 12 },
    [pscustomobject]@{ Name = 'Guard.WebsiteRequests.Tests'; Kind = 'dll'; Tfm = 'net10.0'; Expected = 13 },
    [pscustomobject]@{ Name = 'Guard.WebProtection.Tests'; Kind = 'dll'; Tfm = 'net10.0-windows'; Expected = 19 },
    [pscustomobject]@{ Name = 'Guard.WebControl.Tests'; Kind = 'dll'; Tfm = 'net10.0'; Expected = 14 }
)

$total = 0
foreach ($case in $cases) {
    if ($case.Kind -eq 'exe') {
        $artifact = Join-Path $MirrorRoot 'Guard.Tests\bin\Release\net48\Guard.Tests.exe'
        $output = & $artifact 2>&1
    }
    else {
        $artifact = Join-Path $MirrorRoot (
            'tests\' + $case.Name + '\bin\Release\' + $case.Tfm + '\' + $case.Name + '.dll')
        $output = & $dotnet $artifact 2>&1
    }

    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $output | ForEach-Object { Write-Host $_ }
        throw $case.Name + ' failed with exit code ' + $exitCode
    }

    $count = @($output | Where-Object { $_ -match '^PASS(?:\s|$)' }).Count
    if ($count -eq 0) {
        $totalLine = $output | Where-Object { $_ -match '^TOTAL_PASS=\d+$' } | Select-Object -Last 1
        if ($null -ne $totalLine) {
            $count = [int]($totalLine -replace '^TOTAL_PASS=', '')
        }
    }

    if ($count -ne $case.Expected) {
        $output | ForEach-Object { Write-Host $_ }
        throw $case.Name + ': expected ' + $case.Expected + ' checks, observed ' + $count
    }

    $total += $count
    Write-Host ('PASS {0}: {1}' -f $case.Name, $count)
}

if ($total -ne 321) {
    throw 'Expected 321 safe checks, observed ' + $total
}

Write-Host ('TOTAL_SAFE_CHECKS={0}' -f $total)
