$ErrorActionPreference = "SilentlyContinue"

$AppPort = 8002

function Stop-AppProcess {
    $connections = Get-NetTCPConnection -LocalPort $AppPort -State Listen -ErrorAction SilentlyContinue
    foreach ($connection in $connections) {
        Stop-Process -Id $connection.OwningProcess -Force
        Write-Host "Stopped PID $($connection.OwningProcess)"
    }

    Get-CimInstance Win32_Process |
        Where-Object { $_.CommandLine -match "uvicorn\s+app\.main:app" } |
        ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force
            Write-Host "Stopped uvicorn PID $($_.ProcessId)"
        }
}

function Stop-CodexCli {
    Get-CimInstance Win32_Process |
        Where-Object { $_.CommandLine -match "codex(\.exe)?\s+exec" } |
        ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force
            Write-Host "Stopped Codex CLI PID $($_.ProcessId)"
        }
}

Write-Host "Stopping application on port $AppPort..."
Stop-AppProcess
Stop-CodexCli
Write-Host "Application stopped."
