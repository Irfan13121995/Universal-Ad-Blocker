@echo off
:: ========================================================================
::  Sinkhole 1-Click YouTube Shield Setup (Windows 11)
::  Installs Root CA into Trusted Root, enables System Proxy & QUIC block
:: ========================================================================

:: Check for Administrator elevation
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  Requesting Administrator privileges...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
title Sinkhole 1-Click YouTube Shield Setup

echo.
echo  =============================================================
echo    Sinkhole 1-Click YouTube Shield Setup (Administrator)
echo  =============================================================
echo.

set CERT_PATH=C:\ProgramData\Sinkhole\certs\sinkhole_ca.crt
if not exist "%CERT_PATH%" set CERT_PATH=%~dp0certs\sinkhole_ca.crt

echo  [1/4] Installing Sinkhole Root CA into Windows Certificate Store...
certutil.exe -addstore -f Root "%CERT_PATH%"

echo.
echo  [2/4] Enabling Enterprise Roots for Mozilla Firefox...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (-not (Test-Path 'HKLM:\Software\Policies\Mozilla\Firefox\Certificates')) { New-Item -ItemType Directory -Path 'HKLM:\Software\Policies\Mozilla\Firefox\Certificates' -Force | Out-Null }; Set-ItemProperty -Path 'HKLM:\Software\Policies\Mozilla\Firefox\Certificates' -Name 'ImportEnterpriseRoots' -Value 1 -Type DWord -Force | Out-Null"

echo.
echo  [3/4] Enabling Windows System Proxy (127.0.0.1:8080)...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$r = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; Set-ItemProperty -Path $r -Name 'ProxyEnable' -Value 1 -Type DWord -Force; Set-ItemProperty -Path $r -Name 'ProxyServer' -Value '127.0.0.1:8080' -Type String -Force; Set-ItemProperty -Path $r -Name 'ProxyOverride' -Value '<local>;*.local;192.168.*;10.*;172.16.*' -Type String -Force"

echo.
echo  [4/4] Configuring Firewall: Suppress QUIC (UDP 443) and open LAN DNS (53) / Dashboard (3002)...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Remove-NetFirewallRule -DisplayName 'Sinkhole Block QUIC (UDP 443 Outbound)' -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName 'Sinkhole Block QUIC (UDP 443 Outbound)' -Direction Outbound -Protocol UDP -RemotePort 443 -Action Block -Profile Any | Out-Null; Remove-NetFirewallRule -DisplayName 'Sinkhole Proxy (TCP Inbound)' -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName 'Sinkhole Proxy (TCP Inbound)' -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow -Profile Any | Out-Null; Remove-NetFirewallRule -DisplayName 'Sinkhole Web Dashboard (TCP Inbound 3002)' -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName 'Sinkhole Web Dashboard (TCP Inbound 3002)' -Direction Inbound -Protocol TCP -LocalPort 3002 -Action Allow -Profile Any | Out-Null; Remove-NetFirewallRule -DisplayName 'Sinkhole LAN DNS (UDP Inbound 53)' -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName 'Sinkhole LAN DNS (UDP Inbound 53)' -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow -Profile Any | Out-Null; Remove-NetFirewallRule -DisplayName 'Sinkhole LAN DNS (TCP Inbound 53)' -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName 'Sinkhole LAN DNS (TCP Inbound 53)' -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow -Profile Any | Out-Null; Clear-DnsClientCache -ErrorAction SilentlyContinue"

echo.
echo  =============================================================
echo    SUCCESS: Sinkhole YouTube Shield is fully active!
echo    - Windows Root CA: TRUSTED
echo    - System Proxy:    ACTIVE (127.0.0.1:8080)
echo    - QUIC Block:      ACTIVE (Forced TLS inspection)
echo    - Browsers:        Brave, Chrome, Edge, and Firefox protected
echo  =============================================================
echo.
echo  You can now reload YouTube in Brave / Chrome / Edge!
echo.
pause
