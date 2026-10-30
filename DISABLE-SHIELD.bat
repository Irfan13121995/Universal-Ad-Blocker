@echo off
:: ========================================================================
::  Sinkhole 1-Click YouTube Shield Deactivation (Windows 11)
:: ========================================================================

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
title Sinkhole 1-Click YouTube Shield Deactivation

echo.
echo  =============================================================
echo    Disabling Sinkhole YouTube Shield...
echo  =============================================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$r = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; Set-ItemProperty -Path $r -Name 'ProxyEnable' -Value 0 -Type DWord -Force; Remove-NetFirewallRule -DisplayName 'Sinkhole Block QUIC (UDP 443 Outbound)' -ErrorAction SilentlyContinue; Clear-DnsClientCache -ErrorAction SilentlyContinue"

echo  System Proxy disabled and firewall restored to standard settings.
echo.
pause
