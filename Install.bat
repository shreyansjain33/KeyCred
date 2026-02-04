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
if "%DLL_PATH%"=="" if exist "%~dp0build\bin\Release\TitanKeyCP.dll" set "DLL_PATH=%~dp0build\bin\Release\TitanKeyCP.dll"
if "%DLL_PATH%"=="" if exist "%~dp0build\bin\Debug\TitanKeyCP.dll" set "DLL_PATH=%~dp0build\bin\Debug\TitanKeyCP.dll"

if exist "%~dp0TestTitanKeyCP.exe" set "EXE_PATH=%~dp0TestTitanKeyCP.exe"
if "%EXE_PATH%"=="" if exist "%~dp0build\bin\Release\TestTitanKeyCP.exe" set "EXE_PATH=%~dp0build\bin\Release\TestTitanKeyCP.exe"
if "%EXE_PATH%"=="" if exist "%~dp0build\bin\Debug\TestTitanKeyCP.exe" set "EXE_PATH=%~dp0build\bin\Debug\TestTitanKeyCP.exe"

if "%DLL_PATH%"=="" (
    echo ERROR: TitanKeyCP.dll not found
    echo.
    echo Please build the project first, or copy the DLL here.
    echo Expected location: build\bin\Release\TitanKeyCP.dll
    echo.
    pause
    exit /b 1
)

if "%EXE_PATH%"=="" (
    echo ERROR: TestTitanKeyCP.exe not found
    echo.
    echo Please build the project first, or copy the EXE here.
    echo Expected location: build\bin\Release\TestTitanKeyCP.exe
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
set /p USERNAME="Windows username: "
set /p PASSWORD="Windows password: "

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

echo =====================================================
echo  INSTALLATION COMPLETE!
echo =====================================================
echo.
echo Your Titan Key is now set up for Windows login.
echo.
echo To test:
echo   1. Lock your workstation: Win + L
echo   2. Select the "Titan Key Login" tile
echo   3. Touch your Titan Key when it blinks
echo.
echo To uninstall later, run: Uninstall.bat
echo.
pause
