@echo off
:: Setup Titan Key Credentials for a user
:: Must be run as Administrator

setlocal enabledelayedexpansion

echo ==========================================
echo  Titan Key Credential Setup
echo ==========================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator
    pause
    exit /b 1
)

:: Get username
if "%~1"=="" (
    set /p USERNAME="Enter Windows username: "
) else (
    set "USERNAME=%~1"
)

:: Get password
if "%~2"=="" (
    set /p PASSWORD="Enter Windows password: "
) else (
    set "PASSWORD=%~2"
)

if "%USERNAME%"=="" (
    echo ERROR: Username is required
    pause
    exit /b 1
)

if "%PASSWORD%"=="" (
    echo ERROR: Password is required
    pause
    exit /b 1
)

echo.
echo Setting up credentials for: %USERNAME%
echo.

:: Note: This batch script cannot do DPAPI encryption directly.
:: We need to use the test tool or a helper executable.
:: For now, we'll store a marker and rely on the test tool.

echo NOTE: For full credential setup with DPAPI encryption,
echo       please use the TestTitanKeyCP.exe tool:
echo.
echo       TestTitanKeyCP.exe --setup --user %USERNAME% --password %PASSWORD%
echo.
echo This batch script can only verify the DLL registration.
echo.

:: Check if DLL is registered
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Credential Provider is registered
) else (
    echo [!!] Credential Provider is NOT registered
    echo      Run Register.bat first
)

echo.
pause
