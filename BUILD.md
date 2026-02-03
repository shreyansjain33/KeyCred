# Build Instructions

This document provides detailed instructions for building the Titan Key Credential Provider.

## Prerequisites

### Required Software

| Software | Version | Notes |
|----------|---------|-------|
| Windows | 10 v1809+ (Build 17763) | Required for WebAuthn API |
| Visual Studio | 2019 or later | With C++ desktop development workload |
| Windows SDK | 10.0.17763.0+ | Usually installed with Visual Studio |
| CMake | 3.16+ | Optional if using Visual Studio directly |

### Installing Visual Studio

1. Download [Visual Studio 2022 Community](https://visualstudio.microsoft.com/downloads/) (free)
2. During installation, select:
   - **Desktop development with C++** workload
   - Under "Individual components", ensure:
     - Windows 10 SDK (10.0.17763.0 or later)
     - C++ CMake tools for Windows

## Building

### Option 1: Using CMake (Command Line)

```batch
:: Navigate to project directory
cd C:\path\to\KeyCred

:: Create build directory
mkdir build
cd build

:: Configure the project
:: For Visual Studio 2022:
cmake .. -G "Visual Studio 17 2022" -A x64

:: For Visual Studio 2019:
cmake .. -G "Visual Studio 16 2019" -A x64

:: Build Release version
cmake --build . --config Release

:: Build Debug version (includes debug logging)
cmake --build . --config Debug
```

### Option 2: Using Visual Studio IDE

1. Open Visual Studio
2. Select **File → Open → Folder**
3. Navigate to the `KeyCred` folder and open it
4. Visual Studio will auto-detect CMake and configure
5. Wait for CMake configuration to complete (see Output window)
6. Select **Build → Build All** (or press `Ctrl+Shift+B`)
7. Choose configuration: **Release** or **Debug** from toolbar

### Option 3: Using Developer Command Prompt

```batch
:: Open "Developer Command Prompt for VS 2022" from Start Menu

:: Navigate to project
cd C:\path\to\KeyCred

:: Create and enter build directory
mkdir build && cd build

:: Configure and build
cmake .. -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
nmake
```

## Build Output

After successful build, you'll find these files:

```
KeyCred/
└── build/
    └── bin/
        ├── Release/
        │   ├── TitanKeyCP.dll      # The credential provider DLL
        │   └── TestTitanKeyCP.exe  # Test utility
        └── Debug/
            ├── TitanKeyCP.dll      # Debug build with logging
            └── TestTitanKeyCP.exe  # Debug test utility
```

## Verifying the Build

After building, verify the DLL exports:

```batch
:: Check DLL exports
dumpbin /exports build\bin\Release\TitanKeyCP.dll
```

Expected exports:
- `DllCanUnloadNow`
- `DllGetClassObject`
- `DllMain`
- `DllRegisterServer`
- `DllUnregisterServer`

## Quick Start After Building

```batch
:: 1. Register the DLL (run as Administrator)
cd build\bin\Release
regsvr32 TitanKeyCP.dll

:: 2. Setup test credentials
TestTitanKeyCP.exe --setup --user "YourUsername" --password "1234"

:: 3. Verify everything works
TestTitanKeyCP.exe --test-all

:: 4. Test full flow by locking workstation (Win+L)
```

## Build Configurations

| Configuration | Use Case | Debug Logging | Optimization |
|---------------|----------|---------------|--------------|
| **Release** | Production/Testing | No | Yes |
| **Debug** | Development | Yes (OutputDebugString) | No |

To view debug logs, use [DebugView](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview) from Sysinternals.

## Troubleshooting Build Issues

### CMake not found

```
'cmake' is not recognized as an internal or external command
```

**Solution:** Add CMake to PATH or use Visual Studio's built-in CMake.

### Windows SDK not found

```
Could not find Windows SDK
```

**Solution:** Install Windows 10 SDK via Visual Studio Installer.

### WebAuthn header not found

```
fatal error C1083: Cannot open include file: 'webauthn.h'
```

**Solution:** Update Windows SDK to version 10.0.17763.0 or later.

### Link errors for webauthn.lib

```
LINK : fatal error LNK1181: cannot open input file 'webauthn.lib'
```

**Solution:** Ensure Windows SDK 10.0.17763.0+ is installed. The WebAuthn API was added in Windows 10 1809.

## Cross-Compilation Note

This project **must** be built on Windows. It cannot be cross-compiled from macOS or Linux because:

1. It requires Windows-specific headers (`credentialprovider.h`, `webauthn.h`)
2. It links against Windows system libraries
3. The resulting DLL must run in the Windows logon context

## Next Steps

After building successfully:

1. See [README.md](README.md) for installation and usage
2. Run `TestTitanKeyCP.exe --help` for test tool options
3. Run `tools\Register.bat` to register the credential provider
