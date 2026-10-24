# Uninstall-Service.ps1
# Requires Administrator privileges.
# Stops and removes the Sinkhole background Windows Service.

[CmdletBinding()]
param()

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
    Write-Host "sinkhole.exe not found directly; attempting sc.exe query..."
    sc.exe stop SinkholeDNS
    sc.exe delete SinkholeDNS
    Write-Host "Service deletion command sent."
    exit
}

Write-Host "Stopping and removing Sinkhole service..." -ForegroundColor Cyan
& $ExePath service uninstall
Write-Host "✓ Sinkhole service successfully uninstalled." -ForegroundColor Green
