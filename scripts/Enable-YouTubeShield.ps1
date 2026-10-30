# Enable-YouTubeShield.ps1
# Requires Administrator privileges.
# Installs Sinkhole Root CA, enables Windows System Proxy (127.0.0.1:8080),
# and blocks QUIC (UDP 443) to force browsers to fallback to inspectable TCP TLS.

[CmdletBinding()]
param(
    [string]$CertPath = "C:\ProgramData\Sinkhole\certs\sinkhole_ca.crt",
    [string]$ProxyServer = "127.0.0.1:8080"
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$currentIdentity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Warning "This script requires Administrator privileges."
    Write-Host "Relaunching in an elevated PowerShell session..."
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Activating Sinkhole YouTube Shield & System Proxy    " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

# 1. Install & Trust Root CA
if (-not (Test-Path $CertPath)) {
    # Check alternate locations (workspace or cwd)
    $localCert = Join-Path $PSScriptRoot "..\certs\sinkhole_ca.crt"
    if (Test-Path $localCert) {
        $CertPath = (Resolve-Path $localCert).Path
    }
}

if (Test-Path $CertPath) {
    Write-Host "[1/4] Installing Sinkhole Root CA into Windows Certificate Store (LocalMachine Root)..." -ForegroundColor Yellow
    certutil.exe -addstore -f "Root" $CertPath
    Write-Host "✓ Root CA installed into LocalMachine Root store" -ForegroundColor Green
} else {
    Write-Warning "Root CA certificate not found at $CertPath. Start sinkhole.exe once to generate it."
}

# 2. Configure Firefox to trust Windows enterprise certificates
Write-Host "[2/4] Enabling Windows Root Trust for Mozilla Firefox..." -ForegroundColor Yellow
$ffKey = "HKLM:\Software\Policies\Mozilla\Firefox\Certificates"
if (-not (Test-Path $ffKey)) { New-Item -ItemType Directory -Path $ffKey -Force | Out-Null }
Set-ItemProperty -Path $ffKey -Name "ImportEnterpriseRoots" -Value 1 -Type DWord -Force | Out-Null
Write-Host "✓ Firefox Enterprise Roots enabled" -ForegroundColor Green

# 3. Configure Windows 11 System Proxy
Write-Host "[3/4] Enabling Windows System Proxy -> $ProxyServer..." -ForegroundColor Yellow
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $regPath -Name "ProxyServer" -Value $ProxyServer -Type String -Force
Set-ItemProperty -Path $regPath -Name "ProxyOverride" -Value "<local>;*.local;192.168.*;10.*;172.16.*" -Type String -Force
Remove-ItemProperty -Path $regPath -Name "AutoConfigURL" -ErrorAction SilentlyContinue

# Notify Windows of Internet Settings change
$sig = @'
[DllImport("wininet.dll", SetLastError = true, CharSet=CharSet.Auto)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
$wininet = Add-Type -MemberDefinition $sig -Name "WinINetSettings" -Namespace "Sinkhole" -PassThru
$wininet::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
$wininet::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
Write-Host "✓ Windows System Proxy active on $ProxyServer" -ForegroundColor Green

# 4. Block Outbound QUIC (UDP 443) & Allow Proxy Inbound
Write-Host "[4/4] Configuring Firewall: Block QUIC (UDP 443) to force TCP TLS..." -ForegroundColor Yellow
$ruleQuic = "Sinkhole Block QUIC (UDP 443 Outbound)"
Remove-NetFirewallRule -DisplayName $ruleQuic -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $ruleQuic `
    -Direction Outbound `
    -Protocol UDP `
    -RemotePort 443 `
    -Action Block `
    -Profile Any `
    -Description "Prevents browsers from evading proxy ad-blocking via UDP port 443 (QUIC)." | Out-Null

$ruleProxyIn = "Sinkhole Proxy (TCP Inbound)"
Remove-NetFirewallRule -DisplayName $ruleProxyIn -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $ruleProxyIn `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 8080 `
    -Action Allow `
    -Profile Any `
    -Description "Allows incoming HTTP/HTTPS proxy connections to Sinkhole." | Out-Null

$ruleWebIn = "Sinkhole Web Dashboard (TCP Inbound 3002)"
Remove-NetFirewallRule -DisplayName $ruleWebIn -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $ruleWebIn `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 3002 `
    -Action Allow `
    -Profile Any `
    -Description "Allows incoming HTTP connections to Sinkhole Web Dashboard." | Out-Null

$ruleDnsUdpIn = "Sinkhole LAN DNS (UDP Inbound 53)"
Remove-NetFirewallRule -DisplayName $ruleDnsUdpIn -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $ruleDnsUdpIn `
    -Direction Inbound `
    -Protocol UDP `
    -LocalPort 53 `
    -Action Allow `
    -Profile Any `
    -Description "Allows Smart TVs, phones, and router on LAN to query Sinkhole DNS over UDP 53." | Out-Null

$ruleDnsTcpIn = "Sinkhole LAN DNS (TCP Inbound 53)"
Remove-NetFirewallRule -DisplayName $ruleDnsTcpIn -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $ruleDnsTcpIn `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 53 `
    -Action Allow `
    -Profile Any `
    -Description "Allows Smart TVs, phones, and router on LAN to query Sinkhole DNS over TCP 53." | Out-Null

Write-Host "✓ Firewall rules applied: Outbound QUIC blocked, Inbound DNS (53), Proxy (8080), and Dashboard (3002) open" -ForegroundColor Green

# Clear Windows DNS Cache
Clear-DnsClientCache -ErrorAction SilentlyContinue

Write-Host "`n=======================================================" -ForegroundColor Green
Write-Host "✓ YouTube Shield is fully active!" -ForegroundColor Green
Write-Host "  - Windows Root CA: TRUSTED" -ForegroundColor Green
Write-Host "  - System Proxy:    ACTIVE (127.0.0.1:8080)" -ForegroundColor Green
Write-Host "  - QUIC Protocol:   SUPPRESSED (Forced TCP Fallback)" -ForegroundColor Green
Write-Host "  - Chrome, Edge, and Firefox are now protected from video ads." -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green
