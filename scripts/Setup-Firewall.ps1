# Setup-Firewall.ps1
# Requires Administrator privileges.
# Configures Windows Defender Firewall rules for the Sinkhole DNS engine & Dashboard.

[CmdletBinding()]
param(
    [int]$DnsPort = 53,
    [int]$WebPort = 3002
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$currentIdentity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Warning "This script requires Administrator privileges to configure Windows Firewall."
    Write-Host "Relaunching in an elevated PowerShell session..."
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

Write-Host "Configuring Windows Defender Firewall rules for Sinkhole..." -ForegroundColor Cyan

# 1. Inbound UDP Port 53
$ruleUdp = "Sinkhole DNS (UDP Inbound)"
Remove-NetFirewallRule -DisplayName $ruleUdp -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $ruleUdp `
    -Direction Inbound `
    -Protocol UDP `
    -LocalPort $DnsPort `
    -Action Allow `
    -Profile Any `
    -Description "Allows incoming DNS queries over UDP to the Sinkhole server." | Out-Null
Write-Host "✓ Added rule: $ruleUdp (Port $DnsPort UDP)" -ForegroundColor Green

# 2. Inbound TCP Port 53
$ruleTcp = "Sinkhole DNS (TCP Inbound)"
Remove-NetFirewallRule -DisplayName $ruleTcp -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $ruleTcp `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort $DnsPort `
    -Action Allow `
    -Profile Any `
    -Description "Allows incoming DNS queries over TCP (large responses/zone transfers) to the Sinkhole server." | Out-Null
Write-Host "✓ Added rule: $ruleTcp (Port $DnsPort TCP)" -ForegroundColor Green

# 3. Inbound TCP Web Dashboard
$ruleWeb = "Sinkhole Web Dashboard (TCP Inbound)"
Remove-NetFirewallRule -DisplayName $ruleWeb -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $ruleWeb `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort $WebPort `
    -Action Allow `
    -Profile Any `
    -Description "Allows access to the Sinkhole administration web dashboard." | Out-Null
Write-Host "✓ Added rule: $ruleWeb (Port $WebPort TCP)" -ForegroundColor Green

Write-Host "`nAll firewall rules successfully created! Home network clients can now resolve DNS queries." -ForegroundColor Cyan
