$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
& (Join-Path $ProjectRoot "run_all.ps1")
