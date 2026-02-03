#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets up Titan Key credentials for a user.

.DESCRIPTION
    This script stores the encrypted Windows password for a user and optionally
    enrolls their Titan Key for WebAuthn authentication.
    Must be run as Administrator.

.PARAMETER Username
    The Windows username to set up credentials for.

.PARAMETER Password
    The Windows password. If not provided, will prompt securely.

.PARAMETER Domain
    The domain (default is "." for local machine).

.PARAMETER SkipEnrollment
    Skip the Titan Key enrollment process (use existing enrollment).

.EXAMPLE
    .\SetupCredential.ps1 -Username "TestUser" -Password "1234"
    
.EXAMPLE
    .\SetupCredential.ps1 -Username "DOMAIN\User"

.EXAMPLE
    .\SetupCredential.ps1 -Username "TestUser" -Password "1234" -SkipEnrollment
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Username,

    [Parameter(Mandatory=$false)]
    [string]$Password,

    [Parameter(Mandatory=$false)]
    [string]$Domain = ".",

    [Parameter(Mandatory=$false)]
    [switch]$SkipEnrollment
)

$ErrorActionPreference = "Stop"

# Registry path for credential storage
$RegistryBasePath = "HKLM:\SOFTWARE\TitanKeyCP\Credentials"
$RelyingPartyId = "windows.local"

# Add necessary .NET types for DPAPI
Add-Type -AssemblyName System.Security

function Get-UserSid {
    param([string]$UserName, [string]$DomainName)

    try {
        if ($DomainName -eq ".") {
            $account = New-Object System.Security.Principal.NTAccount($UserName)
        } else {
            $account = New-Object System.Security.Principal.NTAccount($DomainName, $UserName)
        }
        $sid = $account.Translate([System.Security.Principal.SecurityIdentifier])
        return $sid.Value
    } catch {
        # Try with just the username
        try {
            $account = New-Object System.Security.Principal.NTAccount($UserName)
            $sid = $account.Translate([System.Security.Principal.SecurityIdentifier])
            return $sid.Value
        } catch {
            throw "Could not resolve SID for user: $UserName"
        }
    }
}

function Protect-Password {
    param([string]$PlainPassword)

    # Convert password to bytes
    $passwordBytes = [System.Text.Encoding]::Unicode.GetBytes($PlainPassword)

    # Encrypt using DPAPI with LocalMachine scope
    $encryptedBytes = [System.Security.Cryptography.ProtectedData]::Protect(
        $passwordBytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )

    # Clear the plain password from memory
    [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)

    return $encryptedBytes
}

function Store-Credential {
    param(
        [string]$UserSid,
        [string]$UserName,
        [string]$DomainName,
        [byte[]]$EncryptedPassword,
        [byte[]]$CredentialId,
        [byte[]]$PublicKey
    )

    # Create the registry path
    $userKeyPath = Join-Path $RegistryBasePath $UserSid

    Write-Host "Storing credentials at: $userKeyPath" -ForegroundColor Gray

    # Create the key if it doesn't exist
    if (-not (Test-Path $userKeyPath)) {
        New-Item -Path $userKeyPath -Force | Out-Null
    }

    # Store the values
    Set-ItemProperty -Path $userKeyPath -Name "Username" -Value $UserName
    Set-ItemProperty -Path $userKeyPath -Name "Domain" -Value $DomainName
    Set-ItemProperty -Path $userKeyPath -Name "EncryptedPassword" -Value $EncryptedPassword -Type Binary
    Set-ItemProperty -Path $userKeyPath -Name "RelyingPartyId" -Value $RelyingPartyId

    if ($CredentialId -and $CredentialId.Length -gt 0) {
        Set-ItemProperty -Path $userKeyPath -Name "CredentialId" -Value $CredentialId -Type Binary
    }

    if ($PublicKey -and $PublicKey.Length -gt 0) {
        Set-ItemProperty -Path $userKeyPath -Name "PublicKey" -Value $PublicKey -Type Binary
    }
}

function Generate-MockCredentialId {
    # Generate a random credential ID for testing without actual key enrollment
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    return $bytes
}

# Main execution
try {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host " Titan Key Credential Setup" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""

    # Verify running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "This script must be run as Administrator"
    }

    # Parse username if it contains domain
    if ($Username -match '(.+)\\(.+)') {
        $Domain = $Matches[1]
        $Username = $Matches[2]
    }

    Write-Host "Username: $Username"
    Write-Host "Domain: $Domain"
    Write-Host ""

    # Get password if not provided
    if ([string]::IsNullOrEmpty($Password)) {
        $securePassword = Read-Host "Enter Windows password for $Username" -AsSecureString
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
        $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }

    # Get the user's SID
    Write-Host "Resolving user SID..." -ForegroundColor Yellow
    $userSid = Get-UserSid -UserName $Username -DomainName $Domain
    Write-Host "User SID: $userSid" -ForegroundColor Gray

    # Encrypt the password
    Write-Host "Encrypting password with DPAPI..." -ForegroundColor Yellow
    $encryptedPassword = Protect-Password -PlainPassword $Password

    # Clear the plain password from memory
    $Password = $null
    [GC]::Collect()

    Write-Host "Password encrypted (${encryptedPassword.Length} bytes)" -ForegroundColor Gray

    # Handle key enrollment
    $credentialId = $null
    $publicKey = $null

    if (-not $SkipEnrollment) {
        Write-Host ""
        Write-Host "Titan Key Enrollment" -ForegroundColor Yellow
        Write-Host "====================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "NOTE: Full WebAuthn enrollment requires a Windows application with UI."
        Write-Host "For testing purposes, we'll generate a mock credential ID."
        Write-Host "In production, use a proper enrollment application."
        Write-Host ""
        
        $response = Read-Host "Generate mock credential for testing? (Y/n)"
        if ($response -ne 'n' -and $response -ne 'N') {
            $credentialId = Generate-MockCredentialId
            Write-Host "Generated mock credential ID (${credentialId.Length} bytes)" -ForegroundColor Gray
        }
    }

    # Store the credentials
    Write-Host ""
    Write-Host "Storing credentials in registry..." -ForegroundColor Yellow
    
    # Ensure base path exists
    if (-not (Test-Path $RegistryBasePath)) {
        New-Item -Path $RegistryBasePath -Force | Out-Null
    }

    Store-Credential `
        -UserSid $userSid `
        -UserName $Username `
        -DomainName $Domain `
        -EncryptedPassword $encryptedPassword `
        -CredentialId $credentialId `
        -PublicKey $publicKey

    # Clear encrypted password from memory
    [Array]::Clear($encryptedPassword, 0, $encryptedPassword.Length)

    Write-Host ""
    Write-Host "Setup complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "The credential provider is now configured for user: $Username" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "To test:" -ForegroundColor Yellow
    Write-Host "1. Make sure RegisterCredential.ps1 has been run"
    Write-Host "2. Lock your workstation (Win+L)"
    Write-Host "3. Select the 'Titan Key' tile for your user"
    Write-Host "4. Touch your Titan Key when prompted"
    Write-Host ""

} catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    exit 1
}
