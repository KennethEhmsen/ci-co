# =============================================================================
# LOCAL CI/CD PLATFORM - Restore Script
# =============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$BackupPath
)

$ErrorActionPreference = "Stop"
$composeDir = Join-Path $PSScriptRoot ".."

# Resolve backup path
if (-not [System.IO.Path]::IsPathRooted($BackupPath)) {
    $BackupPath = Join-Path $composeDir $BackupPath
}

if (-not (Test-Path $BackupPath)) {
    Write-Host "ERROR: Backup directory not found: $BackupPath" -ForegroundColor Red
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CI/CD Platform Restore                " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Restore from: $BackupPath" -ForegroundColor Yellow
Write-Host ""
Write-Host "WARNING: This will replace all current data!" -ForegroundColor Red
$confirm = Read-Host "Type 'yes' to continue"
if ($confirm -ne "yes") {
    Write-Host "Restore cancelled." -ForegroundColor Yellow
    exit 0
}

Push-Location $composeDir

try {
    # Stop services
    Write-Host "[1/6] Stopping services..." -ForegroundColor Yellow
    docker compose down
    Write-Host "  Services stopped" -ForegroundColor Green

    # Restore PostgreSQL
    Write-Host "[2/6] Restoring PostgreSQL database..." -ForegroundColor Yellow
    docker compose up -d postgres
    Start-Sleep -Seconds 10
    Get-Content "$BackupPath\gitea-db.sql" | docker compose exec -T postgres psql -U gitea gitea
    Write-Host "  Database restored" -ForegroundColor Green

    # Restore Gitea data
    Write-Host "[3/6] Restoring Gitea data..." -ForegroundColor Yellow
    docker run --rm -v gitea-data:/data -v "${BackupPath}:/backup" alpine sh -c "rm -rf /data/* && tar xzf /backup/gitea-data.tar.gz -C /data"
    Write-Host "  Gitea data restored" -ForegroundColor Green

    # Restore Drone data
    Write-Host "[4/6] Restoring Drone data..." -ForegroundColor Yellow
    docker run --rm -v drone-data:/data -v "${BackupPath}:/backup" alpine sh -c "rm -rf /data/* && tar xzf /backup/drone-data.tar.gz -C /data"
    Write-Host "  Drone data restored" -ForegroundColor Green

    # Restore Registry data
    Write-Host "[5/6] Restoring Registry data..." -ForegroundColor Yellow
    docker run --rm -v registry-data:/data -v "${BackupPath}:/backup" alpine sh -c "rm -rf /data/* && tar xzf /backup/registry-data.tar.gz -C /data"
    Write-Host "  Registry data restored" -ForegroundColor Green

    # Start all services
    Write-Host "[6/6] Starting all services..." -ForegroundColor Yellow
    docker compose up -d
    Write-Host "  Services started" -ForegroundColor Green

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Restore Complete!                     " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Services should be available at:" -ForegroundColor Yellow
    Write-Host "  Gitea:        http://localhost:3000" -ForegroundColor White
    Write-Host "  Drone CI:     http://localhost:8080" -ForegroundColor White
    Write-Host "  Registry UI:  http://localhost:5001" -ForegroundColor White

} catch {
    Write-Host "ERROR: Restore failed" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
} finally {
    Pop-Location
}
