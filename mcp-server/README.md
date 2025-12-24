# CI/CD Security MCP Server

A Model Context Protocol (MCP) server that provides Claude Code with direct access to your local CI/CD security tools:

- **Trivy** - Vulnerability scanning for code and containers
- **SonarQube** - Code quality and security analysis
- **Dependency-Track** - SBOM and dependency vulnerability management
- **Gitea** - Git repository management
- **Drone CI** - CI/CD pipeline management
- **Docker Registry** - Container image management

## Installation

### 1. Install Dependencies

```bash
cd mcp-server
npm install
```

### 2. Build the Server

```bash
npm run build
```

### 3. Configure Claude Code

Add the MCP server to your Claude Code configuration.

**Windows:** Edit `%APPDATA%\Claude\claude_desktop_config.json`

**macOS:** Edit `~/Library/Application Support/Claude/claude_desktop_config.json`

**Linux:** Edit `~/.config/Claude/claude_desktop_config.json`

Add this configuration:

```json
{
  "mcpServers": {
    "cicd-security": {
      "command": "node",
      "args": ["C:/Users/keeh/OneDrive - Mansoft/Skrivebord/Mock Servers/ci-co/mcp-server/dist/index.js"],
      "env": {
        "GITEA_URL": "http://localhost:3000",
        "GITEA_USER": "localadmin",
        "GITEA_PASSWORD": "admin123",
        "DRONE_URL": "http://localhost:8085",
        "DRONE_TOKEN": "",
        "SONARQUBE_URL": "http://localhost:9000",
        "SONARQUBE_USER": "admin",
        "SONARQUBE_PASSWORD": "admin",
        "DTRACK_URL": "http://localhost:8081",
        "DTRACK_API_KEY": "",
        "TRIVY_URL": "http://localhost:4954",
        "REGISTRY_URL": "http://localhost:5000"
      }
    }
  }
}
```

### 4. Get API Keys (Optional but Recommended)

**Dependency-Track API Key:**
1. Go to http://localhost:8082
2. Login (admin/admin)
3. Administration → Access Management → Teams → Automation
4. Copy the API Key
5. Add to `DTRACK_API_KEY` in config

**Drone CI Token:**
1. Go to http://localhost:8085
2. Login via Gitea
3. Click your profile → Token
4. Copy the token
5. Add to `DRONE_TOKEN` in config

### 5. Restart Claude Code

After saving the configuration, restart Claude Code to load the MCP server.

## Available Tools

### Trivy (Vulnerability Scanning)

| Tool | Description |
|------|-------------|
| `trivy_scan_path` | Scan a local directory for vulnerabilities |
| `trivy_scan_image` | Scan a Docker image for vulnerabilities |

### SonarQube (Code Quality)

| Tool | Description |
|------|-------------|
| `sonar_list_projects` | List all SonarQube projects |
| `sonar_get_issues` | Get bugs, vulnerabilities, code smells |
| `sonar_get_security_hotspots` | Get security hotspots |
| `sonar_get_metrics` | Get quality metrics |

### Dependency-Track (SBOM & CVE)

| Tool | Description |
|------|-------------|
| `dtrack_list_projects` | List all projects |
| `dtrack_get_vulnerabilities` | Get vulnerabilities for a project |
| `dtrack_get_findings` | Get all security findings |
| `dtrack_get_components` | Get all dependencies |

### Gitea (Git Server)

| Tool | Description |
|------|-------------|
| `gitea_list_repos` | List all repositories |
| `gitea_get_repo` | Get repository details |
| `gitea_get_branches` | List branches |
| `gitea_get_commits` | Get commit history |
| `gitea_create_repo` | Create a new repository |
| `gitea_migrate_repo` | Migrate from GitHub |

### Drone CI (Pipelines)

| Tool | Description |
|------|-------------|
| `drone_list_repos` | List synced repositories |
| `drone_get_builds` | Get build history |
| `drone_get_build` | Get build details |
| `drone_get_build_logs` | Get build step logs |
| `drone_trigger_build` | Trigger a new build |

### Docker Registry

| Tool | Description |
|------|-------------|
| `registry_list_images` | List all images |
| `registry_get_tags` | Get image tags |

### Combined Tools

| Tool | Description |
|------|-------------|
| `security_scan_all` | Run comprehensive security scan with all tools |

## Usage Examples

Once configured, you can ask Claude Code:

### Security Scanning
- "Scan this project for vulnerabilities"
- "Check for security issues in my code"
- "What CVEs affect my dependencies?"
- "Scan the nginx:latest image for vulnerabilities"

### Code Quality
- "Show me the SonarQube issues for my project"
- "What security hotspots were found?"
- "Get the code quality metrics"

### Git Operations
- "List my Gitea repositories"
- "Migrate my-repo from GitHub to Gitea"
- "Show recent commits for my-project"
- "Create a new repository called my-app"

### CI/CD
- "Show me the recent builds for my-project"
- "Why did the last build fail?"
- "Get the logs for build #5"
- "Trigger a new build"

### Combined
- "Run a full security scan on this project"
- "Check the status of all CI/CD services"

## Resources

The MCP server also provides these resources:

| Resource URI | Description |
|--------------|-------------|
| `cicd://status` | Health status of all services |
| `cicd://config` | Current configuration |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GITEA_URL` | http://localhost:3000 | Gitea server URL |
| `GITEA_USER` | localadmin | Gitea username |
| `GITEA_PASSWORD` | admin123 | Gitea password |
| `DRONE_URL` | http://localhost:8085 | Drone CI URL |
| `DRONE_TOKEN` | (empty) | Drone API token |
| `SONARQUBE_URL` | http://localhost:9000 | SonarQube URL |
| `SONARQUBE_USER` | admin | SonarQube username |
| `SONARQUBE_PASSWORD` | admin | SonarQube password |
| `DTRACK_URL` | http://localhost:8081 | Dependency-Track API URL |
| `DTRACK_API_KEY` | (empty) | Dependency-Track API key |
| `TRIVY_URL` | http://localhost:4954 | Trivy server URL |
| `REGISTRY_URL` | http://localhost:5000 | Docker Registry URL |

## Troubleshooting

### MCP Server not loading
1. Check the path in claude_desktop_config.json is correct
2. Ensure the server is built (`npm run build`)
3. Check Claude Code logs for errors

### Cannot connect to services
1. Ensure Docker containers are running: `docker compose ps`
2. Check service URLs in environment variables
3. Verify credentials are correct

### Dependency-Track errors
1. Get API key from http://localhost:8082
2. Add to `DTRACK_API_KEY` environment variable

### Drone CI errors
1. Get token from http://localhost:8085 (Profile → Token)
2. Add to `DRONE_TOKEN` environment variable
