$ErrorActionPreference = "Stop"

$clientPath = Join-Path $PSScriptRoot "client.py"
$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $clientPath)) {
    throw "client.py was not found in $PSScriptRoot"
}

if (Test-Path $venvPython) {
    $pythonPath = $venvPython
} else {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        throw "Python was not found. Install Python or create .venv first."
    }
    $pythonPath = $pythonCommand.Source
}

$previousToken = $env:TUNNEL_AGENT_TOKEN
$exitCode = 1

try {
    $secureToken = Read-Host "Enter the TUNNEL_AGENT_TOKEN from Render" -AsSecureString
    $env:TUNNEL_AGENT_TOKEN = (New-Object System.Net.NetworkCredential("", $secureToken)).Password

    if ([string]::IsNullOrWhiteSpace($env:TUNNEL_AGENT_TOKEN)) {
        throw "TUNNEL_AGENT_TOKEN cannot be empty."
    }

    Write-Host "Starting PAO tunnel client..."
    & $pythonPath $clientPath
    $exitCode = $LASTEXITCODE
} finally {
    if ($null -eq $previousToken) {
        Remove-Item Env:TUNNEL_AGENT_TOKEN -ErrorAction SilentlyContinue
    } else {
        $env:TUNNEL_AGENT_TOKEN = $previousToken
    }
}

exit $exitCode