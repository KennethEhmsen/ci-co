# =============================================================================
# LOCAL CI/CD PLATFORM - Backup Script
# =============================================================================

param(
    [string]$BackupDir = "backups"
)

$ErrorActionPreference = "Stop"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$targetDir = Join-Path $PSScriptRoot "..\$BackupDir\$timestamp"
$composeDir = Join-Path $PSScriptRoot ".."

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CI/CD Platform Backup                 " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Backup location: $targetDir" -ForegroundColor Yellow
Write-Host ""

# Create backup directory
New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

Push-Location $composeDir

try {
    # Backup PostgreSQL
    Write-Host "[1/5] Backing up PostgreSQL database..." -ForegroundColor Yellow
    docker compose exec -T postgres pg_dump -U gitea gitea > "$targetDir\gitea-db.sql"
    Write-Host "  Database backup complete" -ForegroundColor Green

    # Backup Gitea data
    Write-Host "[2/5] Backing up Gitea data..." -ForegroundColor Yellow
    docker run --rm -v gitea-data:/data -v "${targetDir}:/backup" alpine tar czf /backup/gitea-data.tar.gz -C /data .
    Write-Host "  Gitea backup complete" -ForegroundColor Green

    # Backup Drone data
    Write-Host "[3/5] Backing up Drone data..." -ForegroundColor Yellow
    docker run --rm -v drone-data:/data -v "${targetDir}:/backup" alpine tar czf /backup/drone-data.tar.gz -C /data .
    Write-Host "  Drone backup complete" -ForegroundColor Green

    # Backup Registry data
    Write-Host "[4/5] Backing up Registry data..." -ForegroundColor Yellow
    docker run --rm -v registry-data:/data -v "${targetDir}:/backup" alpine tar czf /backup/registry-data.tar.gz -C /data .
    Write-Host "  Registry backup complete" -ForegroundColor Green

    # Backup configuration
    Write-Host "[5/5] Backing up configuration files..." -ForegroundColor Yellow
    Copy-Item -Path ".env" -Destination "$targetDir\" -ErrorAction SilentlyContinue
    Copy-Item -Path "docker-compose.yml" -Destination "$targetDir\"
    if (Test-Path "config") {
        Copy-Item -Path "config" -Destination "$targetDir\" -Recurse
    }
    Write-Host "  Configuration backup complete" -ForegroundColor Green

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Backup Complete!                      " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Backup files:" -ForegroundColor Yellow
    Get-ChildItem $targetDir | ForEach-Object {
        $size = if ($_.Length -gt 1MB) { "{0:N2} MB" -f ($_.Length / 1MB) } else { "{0:N2} KB" -f ($_.Length / 1KB) }
        Write-Host "  $($_.Name) - $size" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "Location: $targetDir" -ForegroundColor Green

} catch {
    Write-Host "ERROR: Backup failed" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
} finally {
    Pop-Location
}
