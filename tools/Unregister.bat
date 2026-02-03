@echo off
:: Unregister Titan Key Credential Provider
:: Must be run as Administrator

echo ============================================
echo  Titan Key Credential Provider Removal
echo ============================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator
    pause
    exit /b 1
)

set "CLSID={A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"

echo Removing Credential Provider registration...
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\%CLSID%" /f >nul 2>&1

echo Removing COM registration...
reg delete "HKCR\CLSID\%CLSID%" /f >nul 2>&1

echo Removing stored credentials...
reg delete "HKLM\SOFTWARE\TitanKeyCP" /f >nul 2>&1

echo.
echo Unregistration complete!
echo.
pause
