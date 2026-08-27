$ErrorActionPreference = 'Stop'
$repo = 'C:\Yandex.Disk\Projects\guard-windows-client'
$dotnet = 'C:\Program Files\dotnet\dotnet.exe'
$tests = @(
    @{ Path = 'Guard.Tests\bin\Release\net48\Guard.Tests.exe'; Dotnet = $false },
    @{ Path = 'tests\Guard.V2.Tests\bin\Release\net8.0\Guard.V2.Tests.dll'; Dotnet = $true },
    @{ Path = 'tests\Guard.Protocol.Tests\bin\Release\net8.0\Guard.Protocol.Tests.dll'; Dotnet = $true },
    @{ Path = 'tests\Guard.Policy.Tests\bin\Release\net8.0\Guard.Policy.Tests.dll'; Dotnet = $true },
    @{ Path = 'tests\Guard.Readiness.Tests\bin\Release\net8.0\Guard.Readiness.Tests.dll'; Dotnet = $true },
    @{ Path = 'tests\Guard.Service.Tests\bin\Release\net10.0-windows\Guard.Service.Tests.dll'; Dotnet = $true },
    @{ Path = 'tests\Guard.Storage.Tests\bin\Release\net10.0\Guard.Storage.Tests.dll'; Dotnet = $true },
    @{ Path = 'tests\Guard.Windows.Accounts.Tests\bin\Release\net10.0-windows\Guard.Windows.Accounts.Tests.dll'; Dotnet = $true },
    @{ Path = 'tests\Guard.Windows.Crypto.Tests\bin\Release\net10.0-windows\Guard.Windows.Crypto.Tests.dll'; Dotnet = $true },
    @{ Path = 'tests\Guard.Windows.Ipc.Tests\bin\Release\net10.0-windows\Guard.Windows.Ipc.Tests.dll'; Dotnet = $true },
    @{ Path = 'tests\Guard.Windows.Storage.Tests\bin\Release\net10.0-windows\Guard.Windows.Storage.Tests.dll'; Dotnet = $true }
)

foreach ($test in $tests) {
    $path = Join-Path $repo $test.Path
    if ($test.Dotnet) {
        & $dotnet $path
    }
    else {
        & $path
    }

    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
