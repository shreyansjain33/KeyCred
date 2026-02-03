# Titan Key Windows Credential Provider

A Windows Credential Provider that enables authentication using Google Titan Security Key (FIDO2/WebAuthn).

## Overview

This credential provider allows users to log into Windows using their Titan Security Key instead of typing a password. The Windows password is stored encrypted in the registry and is only decrypted after successful authentication with the Titan Key.

## Requirements

- Windows 10 version 1809 (Build 17763) or later
- Visual Studio 2019 or later with C++ desktop development workload
- Windows SDK 10.0.17763.0 or later
- CMake 3.16 or later
- Google Titan Security Key or any FIDO2-compatible security key

## Building

### Using CMake (Command Line)

```powershell
# Create build directory
mkdir build
cd build

# Configure (use appropriate generator for your VS version)
cmake .. -G "Visual Studio 17 2022" -A x64

# Build
cmake --build . --config Release
```

### Using Visual Studio

1. Open the folder in Visual Studio
2. CMake should automatically configure
3. Build the solution (Ctrl+Shift+B)

## Installation

### 1. Register the Credential Provider

Run as Administrator (choose one method):

**Using Batch Script:**
```batch
.\tools\Register.bat
```

**Using PowerShell:**
```powershell
.\tools\RegisterCredential.ps1
```

**Using regsvr32:**
```batch
regsvr32 TitanKeyCP.dll
```

### 2. Setup User Credentials

For each user that will use Titan Key authentication:

**Using Test Tool (recommended):**
```batch
TestTitanKeyCP.exe --setup --user "YourUsername" --password "YourPassword"
```

**Using PowerShell:**
```powershell
.\tools\SetupCredential.ps1 -Username "YourUsername" -Password "YourPassword"
```

For testing, use password "1234":
```batch
TestTitanKeyCP.exe --setup --user "TestUser" --password "1234"
```

### 3. Enroll the Titan Key

The setup process will store credentials that are released when the Titan Key is touched.

## Uninstallation

Run as Administrator:

**Using Batch Script:**
```batch
.\tools\Unregister.bat
```

**Using PowerShell:**
```powershell
.\tools\UnregisterCredential.ps1
```

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│  Windows    │────▶│  TitanKeyCP.dll  │────▶│  Titan Key  │
│  LogonUI    │     │  (Cred Provider) │     │  (FIDO2)    │
└─────────────┘     └──────────────────┘     └─────────────┘
                            │
                            ▼
                    ┌──────────────────┐
                    │  webauthn.dll    │
                    │  (Windows API)   │
                    └──────────────────┘
                            │
                            ▼
                    ┌──────────────────┐
                    │    Registry      │
                    │ (Encrypted Cred) │
                    └──────────────────┘
```

## Security Model

**hmac-secret Based Encryption:**

This credential provider uses the FIDO2 hmac-secret extension to derive encryption keys directly from your Titan Key. This provides hardware-bound security:

1. **Enrollment**: A random 32-byte salt is generated and stored
2. **Key Derivation**: The Titan Key uses its internal secret + the salt to derive a 32-byte key via hmac-secret
3. **Encryption**: Your Windows password is encrypted with AES-256-GCM using this derived key
4. **Authentication**: The same salt is sent to the Titan Key to derive the same key for decryption

**Security Guarantees:**
- Your password can ONLY be decrypted by the exact same physical Titan Key
- A different Titan Key (even with the same PIN) will derive a different key and fail decryption
- The encryption key never leaves the hardware - only the encrypted password is stored
- AES-256-GCM provides authenticated encryption (tampering detection)
- Registry keys are protected with restrictive ACLs (SYSTEM + Admins only)

## Testing

### Using the Test Tool (Without Locking System)

The `TestTitanKeyCP.exe` tool lets you verify everything works without locking your system:

```batch
:: Run all tests
TestTitanKeyCP.exe --test-all

:: Test individual components
TestTitanKeyCP.exe --test-registration    :: Check DLL is registered
TestTitanKeyCP.exe --test-storage         :: Test DPAPI encryption
TestTitanKeyCP.exe --test-webauthn        :: Test Titan Key interaction

:: Setup credentials for a user
TestTitanKeyCP.exe --setup --user "TestUser" --password "1234"

:: List stored credentials
TestTitanKeyCP.exe --list
```

### Full Integration Test (Requires Locking)

For complete end-to-end testing with password "1234":

1. Build the project (see Building section)
2. Run as Admin: `Register.bat` or `regsvr32 TitanKeyCP.dll`
3. Setup credentials: `TestTitanKeyCP.exe --setup --user "YourUser" --password "1234"`
4. Verify setup: `TestTitanKeyCP.exe --test-all`
5. Lock your workstation (Win+L)
6. Click the "Titan Key" tile for your user
7. Touch your Titan Key when prompted
8. You should be logged in

## Troubleshooting

### The credential provider doesn't appear

1. Verify the DLL is registered: Check `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`
2. Check Event Viewer for errors
3. Enable debug logging by building in Debug configuration

### Titan Key not responding

1. Ensure the key is properly connected
2. Try a different USB port
3. Check Device Manager for driver issues

### Authentication fails

1. Verify the user's credentials are stored: Check `HKLM\SOFTWARE\TitanKeyCP\Credentials`
2. Re-run SetupCredential.ps1 to re-enroll

## License

This project is provided as-is for educational purposes.
