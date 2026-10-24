# Install-RootCA.ps1
# Requires Administrator privileges.
# Installs and trusts the Sinkhole Root CA in the Windows Trusted Root Certification Authorities store.
# Also configures Mozilla Firefox to automatically trust Windows Enterprise Root Certificates.

[CmdletBinding()]
param(
    [string]$CertPath = "$env:ProgramData\Sinkhole\certs\sinkhole_ca.crt"
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$currentIdentity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Warning "Administrator privileges required to install certificates into the Trusted Root store."
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

if (-not (Test-Path $CertPath)) {
    Write-Error "Certificate not found at $CertPath. Start Sinkhole at least once to generate the Root CA."
    exit 1
}

Write-Host "Installing Sinkhole Root CA into Windows Trusted Root store..." -ForegroundColor Cyan

# 1. Install to Local Machine Root Store
certutil.exe -addstore -f "Root" $CertPath

# 2. Configure Firefox policy to trust Windows Enterprise Roots
$ffPolicy = "HKLM:\Software\Policies\Mozilla\Firefox\Certificates"
if (-not (Test-Path $ffPolicy)) {
    New-Item -ItemType Directory -Path $ffPolicy -Force | Out-Null
}
Set-ItemProperty -Path $ffPolicy -Name "ImportEnterpriseRoots" -Value 1 -Type DWord -Force

Write-Host "`n✓ Root CA successfully trusted across Chrome, Edge, Brave, and Firefox!" -ForegroundColor Green
Write-Host "HTTPS ad filtering and YouTube ad elimination are now fully active without certificate warnings." -ForegroundColor Cyan
