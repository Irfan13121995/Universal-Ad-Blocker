# Restore-LocalDNS.ps1
# Requires Administrator privileges.
# Restores Windows 11 network adapter DNS settings to their original state (or DHCP).

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
$backupMap = @{}

if (Test-Path $BackupFile) {
    try {
        $saved = Get-Content $BackupFile -Raw | ConvertFrom-Json
        foreach ($b in $saved) {
            $backupMap[[string]$b.InterfaceIndex] = $b
        }
    } catch {
        Write-Warning "Could not parse backup file. Will reset adapters to DHCP."
    }
}

$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface }
if ($InterfaceAlias) {
    $adapters = $adapters | Where-Object { $_.Name -eq $InterfaceAlias }
}

foreach ($a in $adapters) {
    $b = $backupMap[[string]$a.ifIndex]
    if ($b -and $b.IPv4DNS.Count -gt 0) {
        $servers = @($b.IPv4DNS)
        Write-Host "Restoring adapter '$($a.Name)' to static DNS: $($servers -join ', ')..." -ForegroundColor Cyan
        Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $servers
    } else {
        Write-Host "Resetting adapter '$($a.Name)' to DHCP automatic DNS..." -ForegroundColor Cyan
        Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses
    }
}

if (Test-Path $BackupFile) {
    Remove-Item $BackupFile -Force -ErrorAction SilentlyContinue
}

Write-Host "Flushing Windows DNS client cache..."
Clear-DnsClientCache

Write-Host "`n✓ Original DNS settings restored successfully." -ForegroundColor Green
