@echo off
:: ========================================================================
::  Sinkhole 1-Click YouTube Shield Deactivation (Windows 11)
:: ========================================================================

cd /d "%~dp0"
title Sinkhole 1-Click YouTube Shield Deactivation

echo.
echo  =============================================================
echo    Disabling Sinkhole YouTube Shield...
echo  =============================================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%~dp0scripts\Disable-YouTubeShield.ps1\"'"

echo.
pause
