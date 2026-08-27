$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$dotnet = 'C:\Program Files\dotnet\dotnet.exe'
$runs = @(
    @{ Name = 'legacy'; Path = 'Guard.Tests\bin\Release\net48\Guard.Tests.exe'; Dotnet = $false },
    @{ Name = 'v2'; Path = 'tests\Guard.V2.Tests\bin\Release\net8.0\Guard.V2.Tests.dll'; Dotnet = $true },
    @{ Name = 'protocol'; Path = 'tests\Guard.Protocol.Tests\bin\Release\net8.0\Guard.Protocol.Tests.dll'; Dotnet = $true },
    @{ Name = 'policy'; Path = 'tests\Guard.Policy.Tests\bin\Release\net8.0\Guard.Policy.Tests.dll'; Dotnet = $true },
    @{ Name = 'readiness-domain'; Path = 'tests\Guard.Readiness.Tests\bin\Release\net8.0\Guard.Readiness.Tests.dll'; Dotnet = $true },
    @{ Name = 'service'; Path = 'tests\Guard.Service.Tests\bin\Release\net10.0-windows\Guard.Service.Tests.dll'; Dotnet = $true },
    @{ Name = 'storage'; Path = 'tests\Guard.Storage.Tests\bin\Release\net10.0\Guard.Storage.Tests.dll'; Dotnet = $true },
    @{ Name = 'windows-accounts'; Path = 'tests\Guard.Windows.Accounts.Tests\bin\Release\net10.0-windows\Guard.Windows.Accounts.Tests.dll'; Dotnet = $true },
    @{ Name = 'windows-crypto'; Path = 'tests\Guard.Windows.Crypto.Tests\bin\Release\net10.0-windows\Guard.Windows.Crypto.Tests.dll'; Dotnet = $true },
    @{ Name = 'windows-ipc'; Path = 'tests\Guard.Windows.Ipc.Tests\bin\Release\net10.0-windows\Guard.Windows.Ipc.Tests.dll'; Dotnet = $true },
    @{ Name = 'windows-storage'; Path = 'tests\Guard.Windows.Storage.Tests\bin\Release\net10.0-windows\Guard.Windows.Storage.Tests.dll'; Dotnet = $true },
    @{ Name = 'windows-readiness'; Path = 'tests\Guard.Windows.Readiness.Tests\bin\Release\net10.0-windows\Guard.Windows.Readiness.Tests.dll'; Dotnet = $true },
    @{ Name = 'service-health'; Path = 'tests\Guard.Windows.ServiceHealth.Tests\bin\Release\net10.0-windows\Guard.Windows.ServiceHealth.Tests.dll'; Dotnet = $true },
    @{ Name = 'platform-readiness'; Path = 'tests\Guard.Windows.PlatformReadiness.Tests\bin\Release\net10.0-windows\Guard.Windows.PlatformReadiness.Tests.dll'; Dotnet = $true },
    @{ Name = 'scm-query'; Path = 'tests\Guard.Windows.ScmQuery.Tests\bin\Release\net10.0-windows\Guard.Windows.ScmQuery.Tests.dll'; Dotnet = $true }
)

$total = 0
foreach ($testRun in $runs) {
    $target = Join-Path $repo $testRun.Path
    if ($testRun.Dotnet) {
        $output = & $dotnet $target 2>&1
    }
    else {
        $output = & $target 2>&1
    }

    if ($LASTEXITCODE -ne 0) {
        $output
        exit $LASTEXITCODE
    }

    $pass = @($output | Where-Object { $_ -match '^PASS( |$)' }).Count
    $total += $pass
    Write-Output ("{0}: pass={1}" -f $testRun.Name, $pass)
}

if ($total -ne 192) {
    Write-Error ("Expected 192 passing checks, observed {0}." -f $total)
    exit 1
}

Write-Output ("TOTAL_PASS={0}" -f $total)
