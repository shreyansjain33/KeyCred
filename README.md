# Titan Key Credential Provider for Windows

A Windows Credential Provider that enables login to Windows using a FIDO2 security key (such as Google Titan Key) instead of typing a password.

![Windows 10/11](https://img.shields.io/badge/Windows-10%2F11-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![FIDO2](https://img.shields.io/badge/FIDO2-U2F%20%7C%20CTAP2-orange)

## Overview

This credential provider allows you to unlock your Windows workstation by simply touching your FIDO2 security key. Your Windows password is stored encrypted on your machine, protected by TPM hardware, and can only be decrypted after successful authentication with your physical security key.

### Key Features

- **Hardware-backed security**: Password encrypted with TPM-protected keys
- **FIDO2/U2F support**: Works with modern CTAP2 keys and legacy U2F keys
- **Lock screen compatible**: Direct USB HID communication bypasses Windows WebAuthn limitations
- **Multi-user support**: Each user can enroll their own security key
- **Cancellable operations**: Switch to password login if needed

## Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Windows Lock Screen                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐                    │
│  │  Titan Key Tile │    │  Password Tile  │                    │
│  │  (This Project) │    │   (Built-in)    │                    │
│  └────────┬────────┘    └─────────────────┘                    │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │  Ctap2Helper    │  Direct USB HID communication             │
│  │  (CTAP2 + U2F)  │  No Windows WebAuthn service needed       │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │  Google Titan   │  User touches key = cryptographic proof   │
│  │  Key (USB)      │  of physical possession                   │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │  TpmCrypto      │  TPM unwraps AES key, decrypts password   │
│  │  (TPM + AES)    │  Hardware-bound, non-extractable          │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │  Windows LSA    │  Standard KERB_INTERACTIVE_UNLOCK_LOGON   │
│  │  (Login)        │  Same as password login                   │
│  └─────────────────┘                                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Encryption Flow

1. **Setup (one-time)**:
   - User enrolls Titan Key via WebAuthn API
   - TPM generates RSA-2048 key pair (private key never leaves TPM)
   - Random AES-256 key encrypts the Windows password
   - AES key is wrapped (encrypted) with TPM public key
   - Encrypted blob stored in registry

2. **Login (each time)**:
   - User selects Titan Key tile on lock screen
   - Credential provider sends challenge to Titan Key via USB HID
   - User touches key → signature proves possession
   - TPM unwraps AES key using RSA private key
   - AES-GCM decrypts password
   - Password submitted to Windows for authentication

## Requirements

- Windows 10 (version 1903+) or Windows 11
- TPM 2.0 (most modern PCs have this)
- FIDO2 security key (Google Titan Key, YubiKey, etc.)
- Visual Studio 2019+ or Build Tools
- Windows SDK 10.0.18362.0+
- CMake 3.16+

## Building

### Using GitHub Actions (Recommended)

The project includes a GitHub Actions workflow that builds release binaries:

1. Push to GitHub
2. Go to Actions → Build → Download artifacts
3. Extract `TitanKeyCP.dll` and `TestTitanKeyCP.exe`

### Building Locally

```powershell
# Clone the repository
git clone https://github.com/shreyansjain33/KeyCred.git
cd KeyCred

# Create build directory
mkdir build
cd build

# Generate project files
cmake .. -G "Visual Studio 17 2022" -A x64

# Build Release
cmake --build . --config Release

# Output: build/bin/Release/TitanKeyCP.dll
#         build/bin/Release/TestTitanKeyCP.exe
```

## Installation

### Quick Install (Recommended)

1. **Build** the project (see Building section) or download from [Releases](../../releases)
2. **Copy** the downloaded `TitanKeyCP.dll` file into `C:\Windows\System32\` directory and the `TestTitanKeyCP.exe` file into the project folder.
3. **Run** `Install.bat` as **Administrator**

That's it! The installer will:
- Find the built DLL and EXE in the folders
- Enroll your Titan Key (touch when it blinks)
- Create TPM-protected encryption
- Register the credential provider
- Set Titan Key as the **default** sign-in option (instead of PIN/password)

### Testing Without Installing

```cmd
Test.bat
```

This lets you test USB communication with your Titan Key before full installation.

## Usage

### Daily Use

1. Lock your workstation (`Win + L`)
2. The **Titan Key** tile is the default sign-in option. Click it (or it may already be selected).
3. Verification starts automatically—no separate "Sign In" button. If the key is not plugged in, plug it in and wait; the screen will detect it and continue.
4. Touch your security key when it blinks.
5. Done! You're logged in.

### Switching to Password

If your Titan Key isn't available, simply click on your pin or password tile to use alternate login methods instead.

### Available Commands

```
TestTitanKeyCP.exe [options]

Options:
  --help              Show help message
  --setup             Enroll Titan Key and encrypt password
  --user <username>   Username for setup
  --password <pass>   Password for setup
  --list              List enrolled credentials
  --reset             Delete all credentials and keys
  --test-ctap2        Test direct USB HID communication
  --test-storage      Test TPM encryption
```

## Troubleshooting

### "Touch your security key" but nothing happens

- Make sure your Titan Key is properly connected
- Try unplugging and reconnecting the key
- Check Device Manager for FIDO devices

### Login fails after touching key

- Re-run setup: `TestTitanKeyCP.exe --reset` then `--setup`
- Check logs at `C:\TitanKeyCP_debug.log`
- Verify TPM is enabled in BIOS

### Credential provider doesn't appear

- Verify DLL is registered: `regsvr32 TitanKeyCP.dll`
- Check registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}`

### Custom tile icon

The lock screen shows a programmatic icon (shield + security key). To use your own 48×48 image:

- Add a 48×48 BMP under `res/` and reference it in `res/TitanKeyCP.rc` as `IDB_TILE_IMAGE`.
- In `TitanKeyCredential.cpp`, `GetBitmapValue(TKFI_TILEIMAGE)` can load that resource instead of drawing.
- Good icon styles: shield with key, USB security key silhouette, or FIDO2-style key with touch circle (e.g. search "security key" or "FIDO2" on Flaticon, Icons8, or The Noun Project at 48×48).

### Debug Logging

Logs are written to `C:\TitanKeyCP_debug.log`. View with any text editor or use:

```powershell
Get-Content C:\TitanKeyCP_debug.log -Tail 50 -Wait
```

## Uninstallation

Run `Uninstall.bat` as Administrator.

This removes:
- Credential provider registration
- Stored credentials from registry
- TPM encryption keys

You can still login with your normal Windows password after uninstalling.

## Project Structure

```
KeyCred/
├── Install.bat               # Complete installer (run as Admin)
├── Uninstall.bat             # Complete uninstaller
├── Test.bat                  # Interactive test menu
├── build/                    # Build output (created by CMake)
│   └── bin/Release/
│       ├── TitanKeyCP.dll    # The credential provider
│       └── TestTitanKeyCP.exe # Setup/test utility
├── include/
│   └── common.h              # Shared definitions
├── src/
│   ├── TitanKeyCredentialProvider.cpp/h  # Main CP implementation
│   ├── TitanKeyCredential.cpp/h          # Individual tile logic
│   ├── Ctap2Helper.cpp/h                 # USB HID FIDO2/U2F
│   ├── TpmCrypto.cpp/h                   # TPM encryption
│   ├── CredentialStorage.cpp/h           # Registry storage
│   ├── WebAuthnHelper.cpp/h              # WebAuthn for enrollment
│   ├── TestTitanKeyCP.cpp                # Test/setup utility
│   ├── dll.cpp                           # DLL entry points
│   └── guid.h                            # COM GUIDs
├── res/
│   └── TitanKeyCP.rc                     # Resources
├── CMakeLists.txt                        # Build configuration
└── TitanKeyCP.def                        # DLL exports
```

The scripts automatically find binaries in `build/bin/Release/` or `build/bin/Debug/`.

## Technical Details

### Why Direct USB HID?

Windows WebAuthn API (`webauthn.dll`) requires a window handle and shows a system UI dialog. This doesn't work on the secure desktop (lock screen) because:
- The credential provider runs as SYSTEM
- SYSTEM cannot create UI windows on the user's desktop
- The secure desktop is isolated from normal applications

By communicating directly via USB HID using the CTAPHID protocol, we bypass these limitations entirely.

### Protocol Support

- **CTAP2**: Modern FIDO2 protocol with CBOR encoding
- **U2F (CTAP1)**: Fallback for older keys that don't support CTAP2

First-generation Google Titan Keys only support U2F, so the fallback is essential.

### TPM Key Storage

Keys are stored in the machine-wide key store (`NCRYPT_MACHINE_KEY_FLAG`) because the credential provider runs as SYSTEM on the lock screen and cannot access user-specific key stores.

## Security Considerations

- **Password is stored encrypted**: Never in plaintext
- **TPM-bound encryption**: Private key cannot be extracted
- **Physical security key required**: Touch proves possession
- **No network dependency**: Works completely offline
- **Fallback available**: Password login always works

### Limitations

- Password changes require re-enrollment
- Stolen laptop with TPM could be brute-forced (use BitLocker!)
- Security key loss means password login required

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- [FIDO Alliance](https://fidoalliance.org/) for CTAP2/U2F specifications
- [Windows Credential Provider Samples](https://github.com/microsoft/Windows-classic-samples) from Microsoft
- Google Titan Key team for excellent hardware

## References

- [CTAP2 Specification](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [Windows Credential Provider Technical Reference](https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [NCrypt TPM Key Storage Provider](https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-providers)
