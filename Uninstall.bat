@echo off
:: Uninstall Titan Key Credential Provider
:: Must be run as Administrator

setlocal enabledelayedexpansion

echo.
echo =====================================================
echo  Titan Key Credential Provider - Uninstaller
echo =====================================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator
    echo.
    echo Right-click on Uninstall.bat and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo This will:
echo   - Unregister the credential provider DLL
echo   - Remove stored credentials from registry
echo   - Delete TPM encryption keys
echo.
echo You will still be able to login with your normal password.
echo.

set /p CONFIRM="Are you sure you want to uninstall? (y/N): "
if /i not "%CONFIRM%"=="y" (
    echo.
    echo Uninstall cancelled.
    pause
    exit /b 0
)

echo.
echo Unregistering DLL...

:: Find and unregister the DLL
set "DLL_PATH="
if exist "%~dp0TitanKeyCP.dll" set "DLL_PATH=%~dp0TitanKeyCP.dll"
if "%DLL_PATH%"=="" if exist "%~dp0build\bin\Release\TitanKeyCP.dll" set "DLL_PATH=%~dp0build\bin\Release\TitanKeyCP.dll"

if not "%DLL_PATH%"=="" (
    regsvr32 /u /s "%DLL_PATH%"
)

echo Removing registry entries...

:: Remove credential provider registration
set "CLSID={A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\%CLSID%" /f >nul 2>&1
reg delete "HKCR\CLSID\%CLSID%" /f >nul 2>&1

echo Removing stored credentials...
reg delete "HKLM\SOFTWARE\TitanKeyCP" /f >nul 2>&1

echo.
echo Deleting TPM keys...

:: Find and run reset
set "EXE_PATH="
if exist "%~dp0TestTitanKeyCP.exe" set "EXE_PATH=%~dp0TestTitanKeyCP.exe"
if "%EXE_PATH%"=="" if exist "%~dp0build\bin\Release\TestTitanKeyCP.exe" set "EXE_PATH=%~dp0build\bin\Release\TestTitanKeyCP.exe"

if not "%EXE_PATH%"=="" (
    "%EXE_PATH%" --reset >nul 2>&1
)

echo.
echo =====================================================
echo  UNINSTALL COMPLETE
echo =====================================================
echo.
echo The Titan Key Credential Provider has been removed.
echo You can still login with your normal Windows password.
echo.
echo To reinstall, run: Install.bat
echo.
pause
