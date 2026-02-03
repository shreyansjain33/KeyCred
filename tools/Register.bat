@echo off
:: Register Titan Key Credential Provider
:: Must be run as Administrator

echo ==========================================
echo  Titan Key Credential Provider Setup
echo ==========================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

:: Find the DLL
set "DLL_PATH="
if exist "%~dp0..\build\bin\Release\TitanKeyCP.dll" set "DLL_PATH=%~dp0..\build\bin\Release\TitanKeyCP.dll"
if exist "%~dp0..\build\bin\Debug\TitanKeyCP.dll" set "DLL_PATH=%~dp0..\build\bin\Debug\TitanKeyCP.dll"
if exist "%~dp0..\build\Release\TitanKeyCP.dll" set "DLL_PATH=%~dp0..\build\Release\TitanKeyCP.dll"
if exist "%~dp0..\build\Debug\TitanKeyCP.dll" set "DLL_PATH=%~dp0..\build\Debug\TitanKeyCP.dll"
if exist "%~dp0..\x64\Release\TitanKeyCP.dll" set "DLL_PATH=%~dp0..\x64\Release\TitanKeyCP.dll"
if exist "%~dp0..\x64\Debug\TitanKeyCP.dll" set "DLL_PATH=%~dp0..\x64\Debug\TitanKeyCP.dll"
if exist "%~dp0TitanKeyCP.dll" set "DLL_PATH=%~dp0TitanKeyCP.dll"

if "%DLL_PATH%"=="" (
    echo ERROR: Could not find TitanKeyCP.dll
    echo Please build the project first using CMake or Visual Studio
    echo.
    echo Expected locations:
    echo   - build\bin\Release\TitanKeyCP.dll
    echo   - build\bin\Debug\TitanKeyCP.dll
    echo   - x64\Release\TitanKeyCP.dll
    pause
    exit /b 1
)

echo Found DLL: %DLL_PATH%
echo.

:: Register using regsvr32
echo Registering DLL...
regsvr32 /s "%DLL_PATH%"
if %errorlevel% neq 0 (
    echo ERROR: Failed to register DLL
    pause
    exit /b 1
)

echo.
echo Registration complete!
echo.
echo Next steps:
echo   1. Run SetupCredential.bat to store your encrypted password
echo   2. Lock your workstation (Win+L) to test
echo.
pause
