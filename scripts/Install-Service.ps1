# Install-Service.ps1
# Requires Administrator privileges.
# Installs and starts the Sinkhole background Windows Service.

[CmdletBinding()]
param(
    [string]$DataDir = "$env:ProgramData\Sinkhole"
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$currentIdentity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Warning "Administrator privileges required to manage Windows Services."
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$ExePath = Join-Path $ProjectRoot "bin\sinkhole.exe"

if (-not (Test-Path $ExePath)) {
    $ExePath = Join-Path $ProjectRoot "sinkhole.exe"
}

if (-not (Test-Path $ExePath)) {
    Write-Error "Could not find sinkhole.exe. Please build the project first."
    exit 1
}

Write-Host "Installing Sinkhole Windows Service..." -ForegroundColor Cyan
Write-Host "Executable: $ExePath"
Write-Host "Data Directory: $DataDir"

# Install service via binary
& $ExePath service install --data $DataDir

# Start service
Write-Host "`nStarting Sinkhole service..." -ForegroundColor Cyan
& $ExePath service start

# Check status
Start-Sleep -Seconds 1
& $ExePath service status
Write-Host "`nSinkhole background service is running! Visit http://127.0.0.1:3002" -ForegroundColor Green
