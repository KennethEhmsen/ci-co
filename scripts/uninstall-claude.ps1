#Requires -Version 5.1
<#
.SYNOPSIS
    Uninstalls the CI/CD Security MCP Server and Agent from Claude Code.

.DESCRIPTION
    This script:
    1. Removes the MCP server from Claude Code configuration
    2. Removes the cicd-agent from PATH
    3. Optionally removes built files

.PARAMETER KeepBuilds
    Keep the built dist/ directories (default: remove them)

.EXAMPLE
    .\uninstall-claude.ps1
    .\uninstall-claude.ps1 -KeepBuilds
#>

param(
    [switch]$KeepBuilds
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$McpServerName = "cicd-security"
$ClaudeConfigDir = "$env:USERPROFILE\.claude"

# Colors for output
function Write-Success { param($msg) Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Blue
Write-Host "  CI/CD Security Tools - Claude Code Uninstaller" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue
Write-Host ""

# Step 1: Remove from Claude Code MCP configuration
$mcpConfigPath = "$ClaudeConfigDir\mcp_servers.json"

if (Test-Path $mcpConfigPath) {
    Write-Info "Checking Claude Code MCP configuration..."
    $mcpConfig = Get-Content $mcpConfigPath -Raw | ConvertFrom-Json

    if ($mcpConfig.PSObject.Properties.Name -contains $McpServerName) {
        Write-Info "Removing $McpServerName from MCP configuration..."

        # Remove our server from the config
        $mcpConfig.PSObject.Properties.Remove($McpServerName)

        # Check if config is now empty
        $remainingServers = @($mcpConfig.PSObject.Properties.Name)

        if ($remainingServers.Count -eq 0) {
            # Remove the file if no servers left
            Remove-Item $mcpConfigPath -Force
            Write-Success "Removed MCP configuration file (no servers remaining)"
        } else {
            # Save the updated config
            $mcpConfig | ConvertTo-Json -Depth 10 | Out-File $mcpConfigPath -Encoding ascii -Force
            Write-Success "Removed $McpServerName from MCP configuration"
        }
    } else {
        Write-Warn "MCP server '$McpServerName' not found in configuration"
    }
} else {
    Write-Warn "No Claude Code MCP configuration found"
}

# Step 2: Remove from PATH
Write-Info "Checking PATH..."
$agentPath = "$ProjectRoot\cicd-agent\dist"
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")

if ($currentPath -like "*$agentPath*") {
    Write-Info "Removing cicd-agent from PATH..."
    $newPath = ($currentPath -split ';' | Where-Object { $_ -ne $agentPath }) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Success "Removed from PATH (restart terminal to take effect)"
} else {
    Write-Warn "cicd-agent not found in PATH"
}

# Step 3: Remove npm global links
Write-Info "Removing npm global links..."

Push-Location "$ProjectRoot\mcp-server"
npm unlink --silent 2>$null
Pop-Location

Push-Location "$ProjectRoot\cicd-agent"
npm unlink --silent 2>$null
Pop-Location

Write-Success "Removed npm global links"

# Step 4: Optionally remove built files
if (-not $KeepBuilds) {
    Write-Info "Removing built files..."

    $dirsToRemove = @(
        "$ProjectRoot\shared\dist",
        "$ProjectRoot\mcp-server\dist",
        "$ProjectRoot\cicd-agent\dist"
    )

    foreach ($dir in $dirsToRemove) {
        if (Test-Path $dir) {
            Remove-Item $dir -Recurse -Force
            Write-Success "Removed: $dir"
        }
    }
} else {
    Write-Info "Keeping built files (-KeepBuilds specified)"
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Uninstall Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "The CI/CD Security tools have been removed from Claude Code." -ForegroundColor White
Write-Host ""
Write-Host "To reinstall, run:" -ForegroundColor Cyan
Write-Host "  .\scripts\install-claude.ps1" -ForegroundColor White
Write-Host ""
Write-Host "Restart Claude Code to apply changes." -ForegroundColor Yellow
Write-Host ""
