@echo off
:: Test Titan Key Credential Provider
:: Can be run without admin for basic tests

echo.
echo ==========================================
echo  Titan Key Credential Provider - Tests
echo ==========================================
echo.

:: Find the test executable
set "EXE_PATH="
if exist "%~dp0TestTitanKeyCP.exe" set "EXE_PATH=%~dp0TestTitanKeyCP.exe"
if "%EXE_PATH%"=="" if exist "%~dp0build\bin\Release\TestTitanKeyCP.exe" set "EXE_PATH=%~dp0build\bin\Release\TestTitanKeyCP.exe"
if "%EXE_PATH%"=="" if exist "%~dp0build\bin\Debug\TestTitanKeyCP.exe" set "EXE_PATH=%~dp0build\bin\Debug\TestTitanKeyCP.exe"

if "%EXE_PATH%"=="" (
    echo ERROR: Could not find TestTitanKeyCP.exe
    echo.
    echo Please build the project first.
    echo Expected: build\bin\Release\TestTitanKeyCP.exe
    echo.
    pause
    exit /b 1
)

echo Using: %EXE_PATH%
echo.
echo Available tests:
echo.
echo   1. Test CTAP2/USB communication (touch your key)
echo   2. Test TPM encryption
echo   3. List stored credentials
echo   4. Show help
echo   5. Exit
echo.

:menu
set /p CHOICE="Select test (1-5): "

if "%CHOICE%"=="1" (
    echo.
    echo Testing direct USB HID communication...
    echo Touch your Titan Key when it blinks!
    echo.
    "%EXE_PATH%" --test-ctap2
    echo.
    goto menu
)

if "%CHOICE%"=="2" (
    echo.
    echo Testing TPM encryption...
    "%EXE_PATH%" --test-storage
    echo.
    goto menu
)

if "%CHOICE%"=="3" (
    echo.
    "%EXE_PATH%" --list
    echo.
    goto menu
)

if "%CHOICE%"=="4" (
    echo.
    "%EXE_PATH%" --help
    echo.
    goto menu
)

if "%CHOICE%"=="5" (
    exit /b 0
)

echo Invalid choice. Please enter 1-5.
goto menu
