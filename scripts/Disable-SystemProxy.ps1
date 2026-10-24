# Disable-SystemProxy.ps1
# Deactivates Windows 11 system proxy settings, restoring direct internet connection.

[CmdletBinding()]
param()

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

Write-Host "Deactivating Windows 11 system proxy..." -ForegroundColor Cyan

Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 0 -Type DWord
Remove-ItemProperty -Path $regPath -Name "AutoConfigURL" -ErrorAction SilentlyContinue

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class WinINetHelper {
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
    public static void Refresh() {
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
    }
}
"@
[WinINetHelper]::Refresh()

Write-Host "✓ Windows system proxy deactivated. Direct internet connection restored." -ForegroundColor Green
