@echo off
:: Install Titan Key Credential Provider
:: This script does everything: register DLL, setup credentials
:: Must be run as Administrator

setlocal enabledelayedexpansion

echo.
echo =====================================================
echo  Titan Key Credential Provider - Complete Installer
echo =====================================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator
    echo.
    echo Right-click on Install.bat and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

:: Find the required files
set "DLL_PATH="
set "EXE_PATH="

:: Check current folder first, then build folder
if exist "%~dp0TitanKeyCP.dll" set "DLL_PATH=%~dp0TitanKeyCP.dll"
if "%DLL_PATH%"=="" if exist "C:\Windows\System32\TitanKeyCP.dll" set "DLL_PATH=C:\Windows\System32\TitanKeyCP.dll"
if "%DLL_PATH%"=="" if exist "%~dp0build\bin\Release\TitanKeyCP.dll" set "DLL_PATH=%~dp0build\bin\Release\TitanKeyCP.dll"
if "%DLL_PATH%"=="" if exist "%~dp0build\bin\Debug\TitanKeyCP.dll" set "DLL_PATH=%~dp0build\bin\Debug\TitanKeyCP.dll"

if exist "%~dp0TestTitanKeyCP.exe" set "EXE_PATH=%~dp0TestTitanKeyCP.exe"
if "%EXE_PATH%"=="" if exist "%~dp0\TestTitanKeyCP.exe" set "EXE_PATH=%~dp0\TestTitanKeyCP.exe"
if "%EXE_PATH%"=="" if exist "%~dp0build\bin\Release\TestTitanKeyCP.exe" set "EXE_PATH=%~dp0build\bin\Release\TestTitanKeyCP.exe"
if "%EXE_PATH%"=="" if exist "%~dp0build\bin\Debug\TestTitanKeyCP.exe" set "EXE_PATH=%~dp0build\bin\Debug\TestTitanKeyCP.exe"

if "%DLL_PATH%"=="" (
    echo ERROR: TitanKeyCP.dll not found
    echo.
    echo Please build the project first, or copy the DLL here.
    echo Expected location: C:\Windows\System32\TitanKeyCP.dll
    echo.
    pause
    exit /b 1
)

if "%EXE_PATH%"=="" (
    echo ERROR: TestTitanKeyCP.exe not found
    echo.
    echo Please build the project first, or copy the EXE here.
    echo Expected location: <cloned repo>\TestTitanKeyCP.exe
    echo.
    pause
    exit /b 1
)

echo Found:
echo   DLL: %DLL_PATH%
echo   EXE: %EXE_PATH%
echo.

:: Step 1: Get user credentials
echo STEP 1: Enter your Windows credentials
echo ----------------------------------------
echo.
echo * Username should match the user directory name present here: C:\Users\<username>
echo * If logged-in using Microsoft account, then use the Microsoft Account's password.
echo.
set /p USERNAME="Windows Username: "
set /p PASSWORD="Windows Password: "

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
echo STEP 2: Enrolling your Titan Key
echo ----------------------------------------
echo.
echo When your Titan Key blinks, TOUCH IT to enroll.
echo.

"%EXE_PATH%" --setup --user %USERNAME% --password %PASSWORD%

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Setup failed. See error above.
    pause
    exit /b 1
)

echo.
echo STEP 3: Registering Credential Provider
echo ----------------------------------------
echo.

regsvr32 /s "%DLL_PATH%"
if %errorlevel% neq 0 (
    echo ERROR: Failed to register DLL
    regsvr32 "%DLL_PATH%"
    pause
    exit /b 1
)

echo DLL registered successfully!
echo.

:: Step 4: Set Titan Key as default sign-in (instead of PIN/password)
echo STEP 4: Setting Titan Key as default sign-in option
echo ----------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v DefaultCredentialProvider /t REG_SZ /d "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}" /f >nul 2>&1
if %errorlevel% equ 0 (
    echo Default sign-in set to Titan Key.
) else (
    echo Note: Could not set default provider via policy. Titan Key tile will still appear; select it to sign in.
)
echo.

echo =====================================================
echo  INSTALLATION COMPLETE!
echo =====================================================
echo.
echo Your Titan Key is now set up as the default Windows sign-in.
echo.
echo To sign in:
echo   1. Lock your workstation: Win + L
echo   2. The Titan Key tile is selected by default; verification starts automatically.
echo   3. If the key is not plugged in, plug it in and wait - it will be detected.
echo   4. Touch your Titan Key when it blinks to complete sign-in.
echo.
echo To uninstall later, run: Uninstall.bat
echo.
pause
