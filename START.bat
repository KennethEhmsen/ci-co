@echo off
echo.
echo ============================================
echo   LOCAL CI/CD PLATFORM - ONE-CLICK START
echo ============================================
echo.
echo Starting all services...
echo This will take about 60-90 seconds on first run.
echo.

cd /d "%~dp0"
docker compose up -d

echo.
echo ============================================
echo   WAITING FOR SERVICES TO BE READY...
echo ============================================
echo.

timeout /t 60 /nobreak > nul

echo.
echo ============================================
echo   YOUR CI/CD PLATFORM IS READY!
echo ============================================
echo.
echo   Gitea (Git Server):
echo     URL:      http://localhost:3000
echo     Username: localadmin
echo     Password: admin123
echo.
echo   Drone CI (Pipelines):
echo     URL:      http://localhost:8085
echo     Login:    Click 'Continue' to auth via Gitea
echo.
echo   Docker Registry:
echo     Push to:  localhost:5000/your-image
echo     UI:       http://localhost:5001
echo.
echo ============================================
echo.
echo Opening Gitea in your browser...
start http://localhost:3000

pause
