@echo off
:: ========================================================================
::  Install Sinkhole Root CA into Windows Trusted Root Store
:: ========================================================================

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
title Install Sinkhole Root CA

echo.
echo Installing Sinkhole Root CA into Windows Trusted Root Store...
echo.

set CERT_PATH=C:\ProgramData\Sinkhole\certs\sinkhole_ca.crt
if not exist "%CERT_PATH%" set CERT_PATH=%~dp0certs\sinkhole_ca.crt

certutil.exe -addstore -f Root "%CERT_PATH%"

echo.
echo Enabling Firefox Enterprise Roots...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (-not (Test-Path 'HKLM:\Software\Policies\Mozilla\Firefox\Certificates')) { New-Item -ItemType Directory -Path 'HKLM:\Software\Policies\Mozilla\Firefox\Certificates' -Force | Out-Null }; Set-ItemProperty -Path 'HKLM:\Software\Policies\Mozilla\Firefox\Certificates' -Name 'ImportEnterpriseRoots' -Value 1 -Type DWord -Force | Out-Null"

echo.
echo Done! Root CA is trusted by Windows, Brave, Chrome, Edge, and Firefox.
echo.
pause
