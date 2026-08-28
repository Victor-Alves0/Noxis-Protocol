[CmdletBinding()]
param(
    [string]$DataDir
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($DataDir)) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss-fff"
    $DataDir = Join-Path $repoRoot "target/noxis-demo-local/$stamp"
}

Push-Location $repoRoot
try {
    cargo run -p noxis-node --features research-testing -- demo-local --data-dir $DataDir
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
