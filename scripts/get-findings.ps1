# =============================================================================
# GET ALL SECURITY FINDINGS
# =============================================================================
# Usage: .\get-findings.ps1 [-ProjectPath "C:\path\to\project"] [-ProjectKey "my-project"]
# =============================================================================

param(
    [string]$ProjectPath = ".",
    [string]$ProjectKey = "",
    [string]$SonarUser = "admin",
    [string]$SonarPass = "admin",
    [string]$DTrackApiKey = ""
)

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  SECURITY FINDINGS REPORT" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# TRIVY - Dependency & Container Vulnerabilities
# =============================================================================
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "  TRIVY - Vulnerability Scan" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

$trivyPath = (Resolve-Path $ProjectPath).Path -replace '\\', '/'
if ($trivyPath -match '^([A-Za-z]):(.*)$') {
    $trivyPath = "/" + $matches[1].ToLower() + $matches[2]
}

Write-Host "Scanning: $ProjectPath" -ForegroundColor Gray
Write-Host ""

# Run Trivy scan
docker run --rm -v "${ProjectPath}:/app" aquasec/trivy:latest fs --scanners vuln --severity HIGH,CRITICAL /app 2>$null

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "Trivy scan complete!" -ForegroundColor Green
} else {
    Write-Host "Trivy scan completed with findings or warnings" -ForegroundColor Yellow
}

Write-Host ""

# =============================================================================
# SONARQUBE - Code Quality & Security Issues
# =============================================================================
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "  SONARQUBE - Code Analysis" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

$sonarBase = "http://localhost:9000"
$sonarAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${SonarUser}:${SonarPass}"))

# Check if SonarQube is running
try {
    $sonarHealth = Invoke-RestMethod -Uri "$sonarBase/api/system/health" -Method Get -TimeoutSec 5 -ErrorAction Stop
    Write-Host "SonarQube Status: $($sonarHealth.health)" -ForegroundColor Green
    Write-Host ""

    # Get projects if no specific project key
    if ([string]::IsNullOrEmpty($ProjectKey)) {
        Write-Host "Available Projects:" -ForegroundColor Cyan
        $projects = Invoke-RestMethod -Uri "$sonarBase/api/projects/search" -Headers @{Authorization = "Basic $sonarAuth"} -ErrorAction Stop

        if ($projects.components.Count -eq 0) {
            Write-Host "  No projects found. Run a SonarQube scan first." -ForegroundColor Gray
        } else {
            foreach ($proj in $projects.components) {
                Write-Host "  - $($proj.key): $($proj.name)" -ForegroundColor White

                # Get issues for each project
                $issues = Invoke-RestMethod -Uri "$sonarBase/api/issues/search?componentKeys=$($proj.key)&statuses=OPEN&types=VULNERABILITY,BUG" -Headers @{Authorization = "Basic $sonarAuth"} -ErrorAction SilentlyContinue

                if ($issues.total -gt 0) {
                    Write-Host "    Vulnerabilities & Bugs: $($issues.total)" -ForegroundColor Red

                    $vulns = ($issues.issues | Where-Object { $_.type -eq "VULNERABILITY" }).Count
                    $bugs = ($issues.issues | Where-Object { $_.type -eq "BUG" }).Count

                    if ($vulns -gt 0) { Write-Host "      - Vulnerabilities: $vulns" -ForegroundColor Red }
                    if ($bugs -gt 0) { Write-Host "      - Bugs: $bugs" -ForegroundColor Yellow }

                    # Show top 5 issues
                    Write-Host "    Top Issues:" -ForegroundColor Cyan
                    $issues.issues | Select-Object -First 5 | ForEach-Object {
                        Write-Host "      [$($_.severity)] $($_.message)" -ForegroundColor $(if ($_.severity -eq "CRITICAL" -or $_.severity -eq "BLOCKER") { "Red" } else { "Yellow" })
                        Write-Host "        File: $($_.component.Split(':')[-1]):$($_.line)" -ForegroundColor Gray
                    }
                } else {
                    Write-Host "    No open vulnerabilities or bugs!" -ForegroundColor Green
                }
            }
        }
    } else {
        # Get issues for specific project
        Write-Host "Issues for project: $ProjectKey" -ForegroundColor Cyan
        $issues = Invoke-RestMethod -Uri "$sonarBase/api/issues/search?componentKeys=$ProjectKey&statuses=OPEN" -Headers @{Authorization = "Basic $sonarAuth"}

        Write-Host "Total Issues: $($issues.total)" -ForegroundColor $(if ($issues.total -gt 0) { "Yellow" } else { "Green" })

        $issues.issues | ForEach-Object {
            Write-Host "  [$($_.severity)] [$($_.type)] $($_.message)" -ForegroundColor $(if ($_.severity -eq "CRITICAL") { "Red" } else { "Yellow" })
            Write-Host "    File: $($_.component.Split(':')[-1]):$($_.line)" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "SonarQube not available or no projects found" -ForegroundColor Gray
    Write-Host "URL: $sonarBase" -ForegroundColor Gray
}

Write-Host ""

# =============================================================================
# DEPENDENCY-TRACK - SBOM & CVE Tracking
# =============================================================================
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "  DEPENDENCY-TRACK - Dependency Analysis" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

$dtrackBase = "http://localhost:8081/api/v1"

if ([string]::IsNullOrEmpty($DTrackApiKey)) {
    Write-Host "No API key provided. Get it from:" -ForegroundColor Gray
    Write-Host "  http://localhost:8082 -> Administration -> Teams -> Automation" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Then run:" -ForegroundColor Gray
    Write-Host "  .\get-findings.ps1 -DTrackApiKey 'YOUR_KEY'" -ForegroundColor White
} else {
    try {
        $projects = Invoke-RestMethod -Uri "$dtrackBase/project" -Headers @{"X-Api-Key" = $DTrackApiKey} -TimeoutSec 10 -ErrorAction Stop

        if ($projects.Count -eq 0) {
            Write-Host "No projects found. Upload an SBOM first." -ForegroundColor Gray
        } else {
            Write-Host "Projects with Vulnerabilities:" -ForegroundColor Cyan
            Write-Host ""

            foreach ($proj in $projects) {
                $metrics = $proj.metrics
                $totalVulns = $metrics.critical + $metrics.high + $metrics.medium + $metrics.low

                Write-Host "  $($proj.name) (v$($proj.version))" -ForegroundColor White
                Write-Host "    Components: $($metrics.components)" -ForegroundColor Gray

                if ($totalVulns -gt 0) {
                    Write-Host "    Vulnerabilities:" -ForegroundColor Red
                    if ($metrics.critical -gt 0) { Write-Host "      Critical: $($metrics.critical)" -ForegroundColor Red }
                    if ($metrics.high -gt 0) { Write-Host "      High: $($metrics.high)" -ForegroundColor Red }
                    if ($metrics.medium -gt 0) { Write-Host "      Medium: $($metrics.medium)" -ForegroundColor Yellow }
                    if ($metrics.low -gt 0) { Write-Host "      Low: $($metrics.low)" -ForegroundColor Gray }

                    # Get detailed findings
                    $findings = Invoke-RestMethod -Uri "$dtrackBase/finding/project/$($proj.uuid)" -Headers @{"X-Api-Key" = $DTrackApiKey} -ErrorAction SilentlyContinue

                    if ($findings.Count -gt 0) {
                        Write-Host "    Top Findings:" -ForegroundColor Cyan
                        $findings | Select-Object -First 5 | ForEach-Object {
                            $sev = $_.vulnerability.severity
                            $color = switch ($sev) { "CRITICAL" { "Red" } "HIGH" { "Red" } "MEDIUM" { "Yellow" } default { "Gray" } }
                            Write-Host "      [$sev] $($_.vulnerability.vulnId): $($_.component.name)@$($_.component.version)" -ForegroundColor $color
                        }
                    }
                } else {
                    Write-Host "    No vulnerabilities found!" -ForegroundColor Green
                }
                Write-Host ""
            }
        }
    } catch {
        Write-Host "Could not connect to Dependency-Track" -ForegroundColor Gray
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Dashboards:" -ForegroundColor White
Write-Host "  SonarQube:        http://localhost:9000" -ForegroundColor Gray
Write-Host "  Dependency-Track: http://localhost:8082" -ForegroundColor Gray
Write-Host ""
