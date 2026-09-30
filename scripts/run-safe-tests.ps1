param([switch]$SkipBuild)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$projects = @(
    'Guard.AppControlPolicy.Tests',
    'Guard.ApplicationControl.Tests',
    'Guard.ApplicationIdentity.Tests',
    'Guard.ApplicationRequestProtocol.Tests',
    'Guard.ApplicationRequests.Tests',
    'Guard.BrowserPolicy.Tests',
    'Guard.Policy.Tests',
    'Guard.Protocol.Tests',
    'Guard.Readiness.Tests',
    'Guard.RelayProtocol.Tests',
    'Guard.RelayState.Tests',
    'Guard.Service.Tests',
    'Guard.Storage.Tests',
    'Guard.V2.Tests',
    'Guard.WebControl.Tests',
    'Guard.WebPolicy.Tests',
    'Guard.WebProtection.Tests',
    'Guard.WebProxyProtocol.Tests',
    'Guard.WebsiteRequestProtocol.Tests',
    'Guard.WebsiteRequests.Tests',
    'Guard.Windows.Accounts.Tests',
    'Guard.Windows.Crypto.Tests',
    'Guard.Windows.Ipc.Tests',
    'Guard.Windows.PlatformReadiness.Tests',
    'Guard.Windows.Readiness.Tests',
    'Guard.Windows.RelayCrypto.Tests',
    'Guard.Windows.ScmQuery.Tests',
    'Guard.Windows.ServiceHealth.Tests',
    'Guard.Windows.Storage.Tests'
)

Push-Location $root
try {
    # --no-build is safe only if the solution actually builds every allowlisted harness.
    $solution = Get-Content -LiteralPath (Join-Path $root 'guard.sln') -Raw -Encoding UTF8
    foreach ($name in $projects) {
        $entry = [regex]::Match($solution, '"' + [regex]::Escape("tests\$name\$name.csproj") + '", "(\{[A-F0-9-]+\})"')
        if (-not $entry.Success -or -not $solution.Contains($entry.Groups[1].Value + '.Release|Any CPU.ActiveCfg = Release|Any CPU') -or
            -not $solution.Contains($entry.Groups[1].Value + '.Release|Any CPU.Build.0 = Release|Any CPU')) {
            throw "Allowlisted test project is missing from the Release solution build: $name"
        }
    }
    if (-not $SkipBuild) {
        & dotnet msbuild guard.sln /restore /p:Configuration=Release '/p:Platform=Any CPU' /verbosity:minimal /nologo
        if ($LASTEXITCODE -ne 0) { throw 'Solution build failed.' }
    }

    foreach ($name in $projects) {
        $project = Join-Path $root "tests/$name/$name.csproj"
        if (-not (Test-Path -LiteralPath $project)) { throw "Missing allowlisted project: $name" }
        Write-Host "== $name =="
        & dotnet run --project $project --configuration Release --no-build --no-launch-profile
        if ($LASTEXITCODE -ne 0) { throw "Failed: $name" }
    }

    Write-Host '== Guard.Tests (legacy P0 checks) =='
    & (Join-Path $root 'Guard.Tests/bin/Release/net48/Guard.Tests.exe')
    if ($LASTEXITCODE -ne 0) { throw 'Failed: Guard.Tests' }

    Write-Host "PASS: $($projects.Count) v2 harnesses and legacy P0 checks."
} finally {
    Pop-Location
}
