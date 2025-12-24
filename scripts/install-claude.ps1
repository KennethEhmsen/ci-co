#Requires -Version 5.1
<#
.SYNOPSIS
    Installs/upgrades the CI/CD Security MCP Server and Agent into Claude Code.

.DESCRIPTION
    This script:
    1. Checks if Claude Code CLI is installed
    2. Checks if the MCP server is already registered
    3. Installs or upgrades the MCP server and agent globally
    4. Configures Claude Code to use the security tools

.PARAMETER Force
    Force reinstallation even if same version exists

.EXAMPLE
    .\install-claude.ps1
    .\install-claude.ps1 -Force
#>

param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$Version = "1.1.0"
$McpServerName = "cicd-security"
$ClaudeConfigDir = "$env:USERPROFILE\.claude"

# Colors for output
function Write-Success { param($msg) Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Blue
Write-Host "  CI/CD Security Tools - Claude Code Installer v$Version" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue
Write-Host ""

# Step 1: Check if Claude Code is installed
Write-Info "Checking for Claude Code CLI..."

$claudeCmd = Get-Command "claude" -ErrorAction SilentlyContinue
if (-not $claudeCmd) {
    Write-Err "Claude Code CLI not found!"
    Write-Host ""
    Write-Host "Please install Claude Code first:" -ForegroundColor Yellow
    Write-Host "  npm install -g @anthropic-ai/claude-code" -ForegroundColor White
    Write-Host ""
    Write-Host "Or download from: https://claude.ai/download" -ForegroundColor White
    exit 1
}

$claudeVersion = & claude --version 2>$null
Write-Success "Claude Code found: $claudeVersion"

# Step 2: Check if Claude config directory exists
if (-not (Test-Path $ClaudeConfigDir)) {
    Write-Warn "Claude config directory not found. Creating..."
    New-Item -ItemType Directory -Path $ClaudeConfigDir -Force | Out-Null
}

# Step 3: Check for existing MCP server installation
$mcpConfigPath = "$ClaudeConfigDir\mcp_servers.json"
$existingVersion = $null
$needsInstall = $true

if (Test-Path $mcpConfigPath) {
    Write-Info "Checking existing MCP configuration..."
    $mcpConfig = Get-Content $mcpConfigPath -Raw | ConvertFrom-Json

    if ($mcpConfig.PSObject.Properties.Name -contains $McpServerName) {
        $existingEntry = $mcpConfig.$McpServerName

        # Try to get version from the configured path
        $configuredPath = $null
        if ($existingEntry.args -and $existingEntry.args.Count -gt 0) {
            $configuredPath = $existingEntry.args[0]
        }

        # Check if the configured MCP server exists
        if ($configuredPath -and (Test-Path $configuredPath)) {
            # Get version from local package.json
            $mcpServerDir = Split-Path -Parent (Split-Path -Parent $configuredPath)
            $localPkgJson = "$mcpServerDir\package.json"

            if (Test-Path $localPkgJson) {
                $installedPkg = Get-Content $localPkgJson -Raw | ConvertFrom-Json
                $existingVersion = $installedPkg.version
                Write-Info "Found existing installation: v$existingVersion"

                if ($existingVersion -eq $Version -and -not $Force) {
                    Write-Success "Already at latest version (v$Version)"
                    $needsInstall = $false
                } elseif ([version]$existingVersion -lt [version]$Version) {
                    Write-Warn "Upgrade available: v$existingVersion -> v$Version"
                } elseif ($Force) {
                    Write-Warn "Force reinstall requested"
                }
            } else {
                Write-Warn "MCP server configured but package.json not found. Will reinstall."
            }
        } else {
            Write-Warn "MCP server configured but executable not found. Will reinstall."
        }
    }
} else {
    Write-Info "No existing MCP configuration found. Fresh install."
}

# Step 4: Install/Upgrade if needed
if ($needsInstall) {
    Write-Host ""
    Write-Info "Installing CI/CD Security MCP Server..."

    # Build the shared library first
    Write-Info "Building shared library..."
    Push-Location "$ProjectRoot\shared"
    npm install --silent 2>$null
    npm run build --silent 2>$null
    Pop-Location

    # Build and link MCP server globally
    Write-Info "Building MCP server..."
    Push-Location "$ProjectRoot\mcp-server"
    npm install --silent 2>$null
    npm run build --silent 2>$null

    Write-Info "Installing MCP server globally..."
    npm link --silent 2>$null
    Pop-Location

    # Build and link CICD agent globally
    Write-Info "Building CICD agent..."
    Push-Location "$ProjectRoot\cicd-agent"
    npm install --silent 2>$null
    npm run build --silent 2>$null

    Write-Info "Installing CICD agent globally..."
    npm link --silent 2>$null
    Pop-Location

    Write-Success "Packages installed globally"

    # Step 5: Configure Claude Code MCP
    Write-Info "Configuring Claude Code..."

    # Build JSON manually for PowerShell 5.1 compatibility
    $serverConfig = @{
        mcpServers = @{
            $McpServerName = @{
                command = "node"
                args = @("$ProjectRoot\mcp-server\dist\index.js")
                env = @{
                    SONAR_URL = "http://localhost:9000"
                    GITEA_URL = "http://localhost:3000"
                    DRONE_URL = "http://localhost:8085"
                    TRIVY_URL = "http://localhost:4954"
                    REGISTRY_URL = "http://localhost:5000"
                    DTRACK_URL = "http://localhost:8081"
                }
            }
        }
    }

    # Read existing config and merge if it exists
    if (Test-Path $mcpConfigPath) {
        $existingJson = Get-Content $mcpConfigPath -Raw | ConvertFrom-Json
        # Add our server to existing config
        $existingJson | Add-Member -NotePropertyName $McpServerName -NotePropertyValue $serverConfig.mcpServers.$McpServerName -Force
        $existingJson | ConvertTo-Json -Depth 10 | Out-File $mcpConfigPath -Encoding ascii -Force
    } else {
        $serverConfig.mcpServers | ConvertTo-Json -Depth 10 | Out-File $mcpConfigPath -Encoding ascii -Force
    }
    Write-Success "MCP server registered in Claude Code"

    # Step 6: Add to PATH if not already there
    $agentPath = "$ProjectRoot\cicd-agent\dist"
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")

    if ($currentPath -notlike "*$agentPath*") {
        Write-Info "Adding cicd-agent to PATH..."
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$agentPath", "User")
        Write-Success "Added to PATH (restart terminal to use)"
    }
}

# Step 7: Verify installation
Write-Host ""
Write-Info "Verifying installation..."

$globalNodeModules = & npm root -g 2>$null

# Check MCP server
if (Test-Path "$ProjectRoot\mcp-server\dist\index.js") {
    Write-Success "MCP Server: Installed"
} else {
    Write-Err "MCP Server: Not found"
}

# Check CICD agent
if (Test-Path "$ProjectRoot\cicd-agent\dist\index.js") {
    Write-Success "CICD Agent: Installed"
} else {
    Write-Err "CICD Agent: Not found"
}

# Check MCP config
if (Test-Path $mcpConfigPath) {
    $config = Get-Content $mcpConfigPath -Raw | ConvertFrom-Json
    if ($config.PSObject.Properties.Name -contains $McpServerName) {
        Write-Success "Claude MCP Config: Registered"
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "The following tools are now available in Claude Code:" -ForegroundColor White
Write-Host ""
Write-Host "  MCP Server Tools:" -ForegroundColor Cyan
Write-Host "    - trivy_scan_path      - Scan local paths for vulnerabilities"
Write-Host "    - trivy_scan_image     - Scan Docker images"
Write-Host "    - sonar_list_projects  - List SonarQube projects"
Write-Host "    - sonar_get_issues     - Get code issues"
Write-Host "    - gitea_list_repos     - List Gitea repositories"
Write-Host "    - drone_list_builds    - List CI/CD builds"
Write-Host "    - check_platform_status - Check all services"
Write-Host "    - security_scan_all    - Run comprehensive scan"
Write-Host ""
Write-Host "  CLI Agent:" -ForegroundColor Cyan
Write-Host "    - cicd-agent           - Interactive security agent"
Write-Host ""
Write-Host "Restart Claude Code to load the new MCP server." -ForegroundColor Yellow
Write-Host ""
