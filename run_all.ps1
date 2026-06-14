$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DotEnvPath = Join-Path $ProjectRoot ".env"
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$AppPort = 8002
$AppUrl = "http://127.0.0.1:$AppPort"

function Import-DotEnv {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    Get-Content -LiteralPath $Path | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#") -or $line.StartsWith(";")) {
            return
        }

        $parts = $line.Split("=", 2)
        if ($parts.Count -ne 2) {
            return
        }

        $name = $parts[0].Trim()
        $value = $parts[1].Trim()
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }

        if ($name) {
            [System.Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }
}

function Get-PythonCommand {
    if (Test-Path -LiteralPath $VenvPython) {
        return @{
            Exe  = $VenvPython
            Args = @()
        }
    }

    return @{
        Exe  = "py"
        Args = @("-3.12")
    }
}

function Start-CodexCliWarmup {
    $codex = Get-Command codex -ErrorAction SilentlyContinue
    if (-not $codex) {
        Write-Host "Codex CLI not found; skipping warm-up."
        return
    }

    $warmupFile = Join-Path $env:TEMP ("codex-warmup-{0}.txt" -f ([guid]::NewGuid().ToString("N")))
    $warmupArgs = @(
        "exec",
        "--ephemeral",
        "--sandbox",
        "read-only",
        "--output-last-message",
        $warmupFile,
        'Respond with valid JSON only: {"status":"ready"}'
    )

    Write-Host "Starting Codex CLI warm-up..."
    $process = Start-Process -WindowStyle Hidden -FilePath $codex.Source -ArgumentList $warmupArgs -WorkingDirectory $ProjectRoot -PassThru
    if ($process) {
        Write-Host "Codex CLI warm-up PID $($process.Id)"
    }
}

function Stop-AppProcess {
    Write-Host "Stopping any existing app listener on port $AppPort..."

    $connections = Get-NetTCPConnection -LocalPort $AppPort -State Listen -ErrorAction SilentlyContinue
    foreach ($connection in $connections) {
        Stop-Process -Id $connection.OwningProcess -Force -ErrorAction SilentlyContinue
        Write-Host "Stopped PID $($connection.OwningProcess)"
    }

    Get-CimInstance Win32_Process |
        Where-Object { $_.CommandLine -match "uvicorn\s+app\.main:app" } |
        ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
            Write-Host "Stopped uvicorn PID $($_.ProcessId)"
        }
}

Import-DotEnv -Path $DotEnvPath

if (-not $env:PYTHONPATH) {
    $env:PYTHONPATH = Join-Path $ProjectRoot ".pythonlibs"
}

if (-not $env:SPLUNK_MCP_URL) {
    $env:SPLUNK_MCP_URL = "https://127.0.0.1:8089/services/mcp"
}

if (-not $env:SPLUNK_MCP_VERIFY_TLS) {
    $env:SPLUNK_MCP_VERIFY_TLS = "false"
}

$python = Get-PythonCommand

Write-Host "Starting application from: $ProjectRoot"
Write-Host "Python interpreter: $($python.Exe)"
Write-Host "App port: $AppPort"

Stop-AppProcess
Start-CodexCliWarmup

$arguments = @()
$arguments += $python.Args
$arguments += @(
    "-m", "uvicorn", "app.main:app",
    "--host", "127.0.0.1",
    "--port", "$AppPort"
)

Start-Process -WindowStyle Hidden -FilePath $python.Exe -ArgumentList $arguments -WorkingDirectory $ProjectRoot | Out-Null

Write-Host "Waiting for application health check..."
$health = $null
$deadline = (Get-Date).AddSeconds(60)
while (-not $health -and (Get-Date) -lt $deadline) {
    try {
        $health = Invoke-RestMethod "$AppUrl/health"
    }
    catch {
        Start-Sleep -Seconds 2
    }
}

if ($health) {
    Write-Host "Application started."
    $health | ConvertTo-Json -Depth 5
} else {
    Write-Host "Application started, but /health did not respond within 60 seconds."
}

Write-Host "Dashboard: $AppUrl/dashboard"
