#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Unregisters the Titan Key Credential Provider DLL.

.DESCRIPTION
    This script removes the TitanKeyCP.dll registration from Windows.
    Must be run as Administrator.

.PARAMETER KeepCredentials
    If specified, keeps the stored user credentials in the registry.

.EXAMPLE
    .\UnregisterCredential.ps1
    
.EXAMPLE
    .\UnregisterCredential.ps1 -KeepCredentials
#>

param(
    [Parameter(Mandatory=$false)]
    [switch]$KeepCredentials
)

$ErrorActionPreference = "Stop"

# CLSID for the credential provider
$CLSID = "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"

function Unregister-CredentialProvider {
    Write-Host "Unregistering Titan Key Credential Provider..." -ForegroundColor Cyan

    # Remove Credential Provider registration
    Write-Host "Removing Credential Provider registration..." -ForegroundColor Yellow
    $cpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$CLSID"
    if (Test-Path $cpPath) {
        Remove-Item -Path $cpPath -Force -Recurse
        Write-Host "  Removed: $cpPath" -ForegroundColor Gray
    } else {
        Write-Host "  Not found: $cpPath" -ForegroundColor Gray
    }

    # Remove COM registration
    Write-Host "Removing COM registration..." -ForegroundColor Yellow
    $clsidPath = "HKCR:\CLSID\$CLSID"
    if (Test-Path $clsidPath) {
        Remove-Item -Path $clsidPath -Force -Recurse
        Write-Host "  Removed: $clsidPath" -ForegroundColor Gray
    } else {
        Write-Host "  Not found: $clsidPath" -ForegroundColor Gray
    }

    # Optionally remove stored credentials
    if (-not $KeepCredentials) {
        Write-Host "Removing stored credentials..." -ForegroundColor Yellow
        $credPath = "HKLM:\SOFTWARE\TitanKeyCP"
        if (Test-Path $credPath) {
            Remove-Item -Path $credPath -Force -Recurse
            Write-Host "  Removed: $credPath" -ForegroundColor Gray
        } else {
            Write-Host "  Not found: $credPath" -ForegroundColor Gray
        }
    } else {
        Write-Host "Keeping stored credentials (use -KeepCredentials:$false to remove)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Unregistration complete!" -ForegroundColor Green
    Write-Host ""
}

# Main execution
try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " Titan Key Credential Provider Removal" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Verify running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "This script must be run as Administrator"
    }

    # Confirm with user
    $response = Read-Host "Are you sure you want to unregister the Titan Key Credential Provider? (y/N)"
    if ($response -ne 'y' -and $response -ne 'Y') {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        exit 0
    }

    # Unregister the provider
    Unregister-CredentialProvider

} catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    exit 1
}
