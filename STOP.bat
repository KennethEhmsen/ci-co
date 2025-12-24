@echo off
echo.
echo ============================================
echo   LOCAL CI/CD PLATFORM - STOP
echo ============================================
echo.
echo Stopping all services...
echo.

cd /d "%~dp0"
docker compose down

echo.
echo All services stopped.
echo.
echo To start again, run START.bat
echo.
pause
