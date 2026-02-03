#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Registers the Titan Key Credential Provider DLL.

.DESCRIPTION
    This script registers the TitanKeyCP.dll as a Windows Credential Provider.
    Must be run as Administrator.

.PARAMETER DllPath
    Path to the TitanKeyCP.dll file. Defaults to searching in common locations.

.EXAMPLE
    .\RegisterCredential.ps1
    
.EXAMPLE
    .\RegisterCredential.ps1 -DllPath "C:\Path\To\TitanKeyCP.dll"
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$DllPath
)

$ErrorActionPreference = "Stop"

# CLSID for the credential provider
$CLSID = "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
$ProviderName = "Titan Key Credential Provider"

function Find-DllPath {
    # Search in common locations
    $searchPaths = @(
        (Join-Path $PSScriptRoot "..\build\bin\Release\TitanKeyCP.dll"),
        (Join-Path $PSScriptRoot "..\build\bin\Debug\TitanKeyCP.dll"),
        (Join-Path $PSScriptRoot "..\build\Release\TitanKeyCP.dll"),
        (Join-Path $PSScriptRoot "..\build\Debug\TitanKeyCP.dll"),
        (Join-Path $PSScriptRoot "..\x64\Release\TitanKeyCP.dll"),
        (Join-Path $PSScriptRoot "..\x64\Debug\TitanKeyCP.dll"),
        (Join-Path $PSScriptRoot "TitanKeyCP.dll")
    )

    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            return (Resolve-Path $path).Path
        }
    }

    return $null
}

function Register-CredentialProvider {
    param([string]$Path)

    Write-Host "Registering Titan Key Credential Provider..." -ForegroundColor Cyan
    Write-Host "DLL Path: $Path"

    # Verify the DLL exists
    if (-not (Test-Path $Path)) {
        throw "DLL not found at: $Path"
    }

    # Get the full path
    $fullPath = (Resolve-Path $Path).Path

    # Register COM class
    Write-Host "Registering COM class..." -ForegroundColor Yellow

    $clsidPath = "HKCR:\CLSID\$CLSID"
    $inprocPath = "$clsidPath\InProcServer32"

    # Create CLSID key
    if (-not (Test-Path $clsidPath)) {
        New-Item -Path $clsidPath -Force | Out-Null
    }
    Set-ItemProperty -Path $clsidPath -Name "(Default)" -Value $ProviderName

    # Create InProcServer32 key
    if (-not (Test-Path $inprocPath)) {
        New-Item -Path $inprocPath -Force | Out-Null
    }
    Set-ItemProperty -Path $inprocPath -Name "(Default)" -Value $fullPath
    Set-ItemProperty -Path $inprocPath -Name "ThreadingModel" -Value "Apartment"

    # Register as Credential Provider
    Write-Host "Registering as Credential Provider..." -ForegroundColor Yellow

    $cpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$CLSID"
    if (-not (Test-Path $cpPath)) {
        New-Item -Path $cpPath -Force | Out-Null
    }
    Set-ItemProperty -Path $cpPath -Name "(Default)" -Value $ProviderName

    Write-Host ""
    Write-Host "Registration complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "1. Run SetupCredential.ps1 to store your encrypted password"
    Write-Host "2. Lock your workstation (Win+L) to test the credential provider"
    Write-Host ""
}

# Main execution
try {
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host " Titan Key Credential Provider Setup" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""

    # Find or use provided DLL path
    if ([string]::IsNullOrEmpty($DllPath)) {
        $DllPath = Find-DllPath
        if ([string]::IsNullOrEmpty($DllPath)) {
            Write-Host "ERROR: Could not find TitanKeyCP.dll" -ForegroundColor Red
            Write-Host "Please build the project first, or specify the path with -DllPath"
            exit 1
        }
    }

    # Verify running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "This script must be run as Administrator"
    }

    # Register the provider
    Register-CredentialProvider -Path $DllPath

} catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    exit 1
}
