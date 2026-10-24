# Set-LocalDNS.ps1
# Requires Administrator privileges.
# Points active Windows 11 network adapters to 127.0.0.1 (and ::1) for local sinkhole testing.
# Captures backup of current DNS servers so they can be restored via Restore-LocalDNS.ps1.

[CmdletBinding()]
param(
    [string]$InterfaceAlias = ""
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$currentIdentity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Warning "Administrator privileges required to alter Network Adapter DNS."
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$BackupFile = "$env:ProgramData\Sinkhole\dns_adapter_backup.json"
$backupDir = Split-Path -Parent $BackupFile
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
}

# Find active adapters
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface }
if ($InterfaceAlias) {
    $adapters = $adapters | Where-Object { $_.Name -eq $InterfaceAlias }
}

if (-not $adapters) {
    Write-Warning "No active physical network adapters found."
    exit
}

$backups = @()
if (Test-Path $BackupFile) {
    try { $backups = @(Get-Content $BackupFile -Raw | ConvertFrom-Json) } catch {}
}

foreach ($a in $adapters) {
    $v4 = (Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
    $v6 = (Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses

    # Save backup only if not already pointing to loopback
    $isLoopback = $false
    foreach ($addr in ($v4 + $v6)) {
        if ($addr -eq '127.0.0.1' -or $addr -eq '::1') { $isLoopback = $true }
    }

    if (-not $isLoopback) {
        $backups += [PSCustomObject]@{
            InterfaceIndex = $a.ifIndex
            InterfaceName = $a.Name
            IPv4DNS = @($v4)
            IPv6DNS = @($v6)
            Timestamp = (Get-Date).ToString("o")
        }
    }

    Write-Host "Configuring adapter '$($a.Name)' to use local Sinkhole (127.0.0.1, ::1)..." -ForegroundColor Cyan
    Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses ('127.0.0.1', '::1')
}

$backups | ConvertTo-Json -Depth 4 | Set-Content -Path $BackupFile -Encoding UTF8

Write-Host "Flushing Windows DNS client cache..."
Clear-DnsClientCache

Write-Host "`n✓ Local DNS configured! Testing resolution..." -ForegroundColor Green
try {
    $res = Resolve-DnsName -Name "example.com" -Server "127.0.0.1" -ErrorAction Stop
    Write-Host "✓ Resolution test succeeded: example.com -> $($res.IPAddress -join ', ')" -ForegroundColor Green
} catch {
    Write-Warning "Could not resolve test query through 127.0.0.1. Ensure Sinkhole is running."
}

Write-Host "To revert later, run: .\scripts\Restore-LocalDNS.ps1" -ForegroundColor Yellow
