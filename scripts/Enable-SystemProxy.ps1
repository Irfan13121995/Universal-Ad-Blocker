# Enable-SystemProxy.ps1
# Configures Windows 11 system proxy settings to route browser traffic through Sinkhole.

[CmdletBinding()]
param(
    [string]$ProxyServer = "127.0.0.1:8080",
    [string]$PacUrl = "http://127.0.0.1:3002/proxy.pac"
)

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

Write-Host "Activating Windows 11 system proxy for Sinkhole HTTPS & YouTube filtering..." -ForegroundColor Cyan

Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name "ProxyServer" -Value $ProxyServer -Type String
Set-ItemProperty -Path $regPath -Name "AutoConfigURL" -Value $PacUrl -Type String
Set-ItemProperty -Path $regPath -Name "ProxyOverride" -Value "<local>;*.local;192.168.*;10.*;172.16.*" -Type String

# Refresh WinINet internet settings so browsers apply changes immediately without restart
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class WinINetHelper {
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
    public static void Refresh() {
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0); // INTERNET_OPTION_SETTINGS_CHANGED
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0); // INTERNET_OPTION_REFRESH
    }
}
"@
[WinINetHelper]::Refresh()

Write-Host "✓ Windows system proxy active! Traffic is routing through $ProxyServer (PAC: $PacUrl)" -ForegroundColor Green
Write-Host "To revert back to direct connection at any time, run: .\scripts\Disable-SystemProxy.ps1" -ForegroundColor Yellow
