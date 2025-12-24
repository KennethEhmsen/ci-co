# =============================================================================
# CI/CD Security MCP Server - Installation Script for Claude Code
# =============================================================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  CI/CD Security MCP Server Installer" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Get the script directory (where the MCP server is located)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ServerPath = Join-Path $ScriptDir "dist\index.js"

# Convert to forward slashes for JSON
$ServerPathJson = $ServerPath -replace '\\', '/'

Write-Host "MCP Server Path: $ServerPath" -ForegroundColor Gray
Write-Host ""

# Check if server is built
if (-not (Test-Path $ServerPath)) {
    Write-Host "Building MCP server..." -ForegroundColor Yellow
    Set-Location $ScriptDir
    npm install
    npm run build
}

# Find Claude Code config file
$ConfigPaths = @(
    "$env:APPDATA\Claude\claude_desktop_config.json",
    "$env:LOCALAPPDATA\Claude\claude_desktop_config.json",
    "$env:USERPROFILE\.config\Claude\claude_desktop_config.json"
)

$ConfigPath = $null
foreach ($path in $ConfigPaths) {
    if (Test-Path (Split-Path $path -Parent)) {
        $ConfigPath = $path
        break
    }
}

if (-not $ConfigPath) {
    # Default to APPDATA
    $ConfigPath = "$env:APPDATA\Claude\claude_desktop_config.json"
    $ConfigDir = Split-Path $ConfigPath -Parent
    if (-not (Test-Path $ConfigDir)) {
        New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    }
}

Write-Host "Config Path: $ConfigPath" -ForegroundColor Gray
Write-Host ""

# Read existing config or create new
$Config = @{
    mcpServers = @{}
}

if (Test-Path $ConfigPath) {
    try {
        $ExistingConfig = Get-Content $ConfigPath -Raw | ConvertFrom-Json -AsHashtable
        if ($ExistingConfig) {
            $Config = $ExistingConfig
        }
    } catch {
        Write-Host "Warning: Could not parse existing config, creating new one" -ForegroundColor Yellow
    }
}

# Ensure mcpServers exists
if (-not $Config.ContainsKey("mcpServers")) {
    $Config.mcpServers = @{}
}

# Add our MCP server configuration
$Config.mcpServers["cicd-security"] = @{
    command = "node"
    args = @($ServerPathJson)
    env = @{
        GITEA_URL = "http://localhost:3000"
        GITEA_USER = "localadmin"
        GITEA_PASSWORD = "admin123"
        DRONE_URL = "http://localhost:8085"
        DRONE_TOKEN = ""
        SONARQUBE_URL = "http://localhost:9000"
        SONARQUBE_USER = "admin"
        SONARQUBE_PASSWORD = "admin"
        DTRACK_URL = "http://localhost:8081"
        DTRACK_API_KEY = ""
        TRIVY_URL = "http://localhost:4954"
        REGISTRY_URL = "http://localhost:5000"
    }
}

# Write config
$ConfigJson = $Config | ConvertTo-Json -Depth 10
Set-Content -Path $ConfigPath -Value $ConfigJson -Encoding UTF8

Write-Host "============================================" -ForegroundColor Green
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "MCP Server configured at:" -ForegroundColor White
Write-Host "  $ConfigPath" -ForegroundColor Gray
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Restart Claude Code" -ForegroundColor White
Write-Host "  2. Ask Claude: 'Scan this project for vulnerabilities'" -ForegroundColor White
Write-Host ""
Write-Host "Optional - Add API Keys for full functionality:" -ForegroundColor Yellow
Write-Host "  - Dependency-Track: http://localhost:8082" -ForegroundColor Gray
Write-Host "    (Admin -> Teams -> Automation -> API Key)" -ForegroundColor Gray
Write-Host "  - Drone CI: http://localhost:8085" -ForegroundColor Gray
Write-Host "    (Profile -> Token)" -ForegroundColor Gray
Write-Host ""
Write-Host "Edit config at: $ConfigPath" -ForegroundColor Gray
Write-Host ""
