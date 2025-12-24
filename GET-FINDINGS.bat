@echo off
echo.
echo ============================================
echo   FETCHING ALL SECURITY FINDINGS
echo ============================================
echo.

REM Get the directory where this script is located
set SCRIPT_DIR=%~dp0

REM Run the PowerShell script
powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%scripts\get-findings.ps1" %*

pause
