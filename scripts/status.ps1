# =============================================================================
# LOCAL CI/CD PLATFORM - Status Check Script
# =============================================================================

$ErrorActionPreference = "SilentlyContinue"
$composeDir = Join-Path $PSScriptRoot ".."

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CI/CD Platform Status                 " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check Docker
Write-Host "Docker Status:" -ForegroundColor Yellow
try {
    $dockerVersion = docker --version
    Write-Host "  Version: $dockerVersion" -ForegroundColor Green
    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Status: Running" -ForegroundColor Green
    } else {
        Write-Host "  Status: Not Running" -ForegroundColor Red
    }
} catch {
    Write-Host "  Status: Not Installed or Not Running" -ForegroundColor Red
}
Write-Host ""

# Check services
Write-Host "Services Status:" -ForegroundColor Yellow
Push-Location $composeDir

$services = @(
    @{Name="Gitea"; Container="ci-gitea"; Port=3000; HealthUrl="http://localhost:3000"},
    @{Name="Drone CI"; Container="ci-drone-server"; Port=8080; HealthUrl="http://localhost:8080"},
    @{Name="Drone Runner"; Container="ci-drone-runner"; Port=$null; HealthUrl=$null},
    @{Name="PostgreSQL"; Container="ci-postgres"; Port=5432; HealthUrl=$null},
    @{Name="Registry"; Container="ci-registry"; Port=5000; HealthUrl="http://localhost:5000/v2/"},
    @{Name="Registry UI"; Container="ci-registry-ui"; Port=5001; HealthUrl="http://localhost:5001"}
)

foreach ($service in $services) {
    $status = docker ps --filter "name=$($service.Container)" --format "{{.Status}}" 2>&1
    if ($status -match "Up") {
        $statusText = "Running"
        $statusColor = "Green"

        # Try to check health endpoint if available
        if ($service.HealthUrl) {
            try {
                $response = Invoke-WebRequest -Uri $service.HealthUrl -TimeoutSec 2 -UseBasicParsing
                if ($response.StatusCode -eq 200) {
                    $statusText = "Healthy"
                }
            } catch {
                $statusText = "Running (health check failed)"
                $statusColor = "Yellow"
            }
        }
    } else {
        $statusText = "Stopped"
        $statusColor = "Red"
    }

    $portInfo = if ($service.Port) { ":$($service.Port)" } else { "" }
    Write-Host ("  {0,-15} {1,-20} {2}" -f $service.Name, $statusText, $portInfo) -ForegroundColor $statusColor
}

Pop-Location
Write-Host ""

# Check volumes
Write-Host "Volumes:" -ForegroundColor Yellow
$volumes = @("gitea-data", "postgres-data", "drone-data", "registry-data")
foreach ($vol in $volumes) {
    $exists = docker volume ls --filter "name=$vol" --format "{{.Name}}" 2>&1
    if ($exists -eq $vol) {
        Write-Host "  $vol : Exists" -ForegroundColor Green
    } else {
        Write-Host "  $vol : Not Found" -ForegroundColor Yellow
    }
}
Write-Host ""

# Check network
Write-Host "Network:" -ForegroundColor Yellow
$network = docker network ls --filter "name=ci-co_ci-cd-network" --format "{{.Name}}" 2>&1
if ($network -match "ci-cd-network") {
    Write-Host "  ci-cd-network: Exists" -ForegroundColor Green
} else {
    Write-Host "  ci-cd-network: Not Found" -ForegroundColor Yellow
}
Write-Host ""

# Resource usage
Write-Host "Resource Usage:" -ForegroundColor Yellow
$stats = docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>&1 |
    Where-Object { $_ -match "ci-" }
if ($stats) {
    foreach ($line in $stats) {
        Write-Host "  $line" -ForegroundColor White
    }
} else {
    Write-Host "  No running containers" -ForegroundColor Yellow
}
Write-Host ""

# URLs
Write-Host "Access URLs:" -ForegroundColor Yellow
Write-Host "  Gitea:        http://localhost:3000" -ForegroundColor White
Write-Host "  Drone CI:     http://localhost:8080" -ForegroundColor White
Write-Host "  Registry:     http://localhost:5000" -ForegroundColor White
Write-Host "  Registry UI:  http://localhost:5001" -ForegroundColor White
Write-Host ""
