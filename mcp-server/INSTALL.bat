@echo off
echo.
echo ============================================
echo   CI/CD Security MCP Server Installer
echo ============================================
echo.

powershell -ExecutionPolicy Bypass -File "%~dp0install.ps1"

pause
