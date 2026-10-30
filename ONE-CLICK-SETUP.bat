@echo off
:: ========================================================================
::  Sinkhole 1-Click YouTube Shield Setup (Windows 11)
::  Configures Root CA, Windows System Proxy (127.0.0.1:8080), and QUIC Block
:: ========================================================================

cd /d "%~dp0"
title Sinkhole 1-Click YouTube Shield Setup

echo.
echo  =============================================================
echo    Sinkhole 1-Click YouTube Shield Setup
echo  =============================================================
echo.
echo  Launching elevated setup... Please click 'Yes' on the Windows
echo  User Account Control (UAC) prompt when it appears.
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%~dp0scripts\Enable-YouTubeShield.ps1\"'"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo  Setup script launched successfully!
    echo  Open http://127.0.0.1:3002 in your browser to verify status.
) else (
    echo.
    echo  Failed to launch elevated setup. Please right-click
    echo  scripts\Enable-YouTubeShield.ps1 and choose 'Run with PowerShell'.
)

echo.
pause
