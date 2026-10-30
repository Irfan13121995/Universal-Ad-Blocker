# Disable-YouTubeShield.ps1
# Requires Administrator privileges.
# Disables Windows System Proxy and removes QUIC firewall blocks.

[CmdletBinding()]
param()

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

Write-Host "Disabling Windows System Proxy and restoring default network settings..." -ForegroundColor Yellow

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 0 -Type DWord -Force
Remove-ItemProperty -Path $regPath -Name "AutoConfigURL" -ErrorAction SilentlyContinue

# Notify Windows of Internet Settings change
$sig = @'
[DllImport("wininet.dll", SetLastError = true, CharSet=CharSet.Auto)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
$wininet = Add-Type -MemberDefinition $sig -Name "WinINetSettingsDisable" -Namespace "Sinkhole" -PassThru
$wininet::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
$wininet::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null

# Remove QUIC firewall block
Remove-NetFirewallRule -DisplayName "Sinkhole Block QUIC (UDP 443 Outbound)" -ErrorAction SilentlyContinue

Clear-DnsClientCache -ErrorAction SilentlyContinue

Write-Host "✓ System Proxy disabled and firewall restored to standard settings." -ForegroundColor Green
