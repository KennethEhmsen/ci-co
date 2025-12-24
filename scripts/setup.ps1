# =============================================================================
# LOCAL CI/CD PLATFORM - Setup Script
# =============================================================================
# This script automates the initial setup of the CI/CD platform
# =============================================================================

param(
    [switch]$SkipSecrets,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Local CI/CD Platform Setup Script    " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Docker is running
Write-Host "[1/6] Checking Docker..." -ForegroundColor Yellow
try {
    docker info | Out-Null
    Write-Host "  Docker is running" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Docker is not running. Please start Docker Desktop." -ForegroundColor Red
    exit 1
}

# Check Docker Compose
Write-Host "[2/6] Checking Docker Compose..." -ForegroundColor Yellow
try {
    docker compose version | Out-Null
    Write-Host "  Docker Compose is available" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Docker Compose not found." -ForegroundColor Red
    exit 1
}

# Generate secrets if .env doesn't exist or Force flag is set
Write-Host "[3/6] Setting up environment..." -ForegroundColor Yellow
$envFile = Join-Path $PSScriptRoot "..\\.env"

if ((Test-Path $envFile) -and -not $Force) {
    Write-Host "  .env file already exists. Use -Force to regenerate." -ForegroundColor Yellow
} else {
    if (-not $SkipSecrets) {
        Write-Host "  Generating secrets..." -ForegroundColor Cyan

        # Generate random strings
        $POSTGRES_PASSWORD = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
        $GITEA_SECRET = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 64 | ForEach-Object {[char]$_})
        $DRONE_RPC = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})

        $envContent = @"
# =============================================================================
# LOCAL CI/CD PLATFORM - Environment Variables
# Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# =============================================================================

# PostgreSQL Database
POSTGRES_PASSWORD=$POSTGRES_PASSWORD

# Gitea Configuration
GITEA_SECRET_KEY=$GITEA_SECRET

# Drone CI Configuration
DRONE_RPC_SECRET=$DRONE_RPC

# Gitea OAuth Application credentials
# IMPORTANT: Update these after creating OAuth app in Gitea
DRONE_GITEA_CLIENT_ID=
DRONE_GITEA_CLIENT_SECRET=

# First admin user (must match your Gitea username)
DRONE_ADMIN_USER=admin
"@

        $envContent | Out-File -FilePath $envFile -Encoding UTF8
        Write-Host "  .env file created with generated secrets" -ForegroundColor Green
    }
}

# Check insecure registry configuration
Write-Host "[4/6] Checking Docker insecure registry..." -ForegroundColor Yellow
$dockerConfig = docker info --format '{{json .RegistryConfig.InsecureRegistryCIDRs}}'
if ($dockerConfig -match "localhost:5000" -or $dockerConfig -match "127.0.0.1") {
    Write-Host "  Insecure registry configured" -ForegroundColor Green
} else {
    Write-Host "  WARNING: localhost:5000 not in insecure registries!" -ForegroundColor Yellow
    Write-Host "  Please add 'localhost:5000' to Docker Desktop insecure registries" -ForegroundColor Yellow
    Write-Host "  Settings > Docker Engine > Add to 'insecure-registries' array" -ForegroundColor Yellow
}

# Pull images
Write-Host "[5/6] Pulling Docker images (this may take a while)..." -ForegroundColor Yellow
$composeDir = Join-Path $PSScriptRoot ".."
Push-Location $composeDir
try {
    docker compose pull
    Write-Host "  Images pulled successfully" -ForegroundColor Green
} catch {
    Write-Host "  WARNING: Some images may have failed to pull" -ForegroundColor Yellow
}
Pop-Location

# Start services
Write-Host "[6/6] Starting services..." -ForegroundColor Yellow
Push-Location $composeDir
try {
    # Start database and Gitea first
    docker compose up -d postgres gitea registry registry-ui

    Write-Host "  Waiting for Gitea to be ready..." -ForegroundColor Cyan
    $attempts = 0
    $maxAttempts = 30
    while ($attempts -lt $maxAttempts) {
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:3000" -TimeoutSec 2 -UseBasicParsing
            if ($response.StatusCode -eq 200) {
                Write-Host "  Gitea is ready!" -ForegroundColor Green
                break
            }
        } catch {
            $attempts++
            Start-Sleep -Seconds 2
        }
    }

    if ($attempts -ge $maxAttempts) {
        Write-Host "  WARNING: Gitea may not be fully ready yet" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ERROR: Failed to start services" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}
Pop-Location

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!                       " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Open Gitea:        http://localhost:3000" -ForegroundColor White
Write-Host "2. Complete Gitea installation wizard" -ForegroundColor White
Write-Host "3. Create admin account" -ForegroundColor White
Write-Host "4. Create OAuth app for Drone (Settings > Applications)" -ForegroundColor White
Write-Host "5. Update .env with OAuth credentials" -ForegroundColor White
Write-Host "6. Run: docker compose up -d" -ForegroundColor White
Write-Host "7. Open Drone CI:     http://localhost:8080" -ForegroundColor White
Write-Host ""
Write-Host "Registry UI:          http://localhost:5001" -ForegroundColor Gray
Write-Host ""
