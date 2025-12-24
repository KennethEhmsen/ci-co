# Local CI/CD Platform

[![Build Status](http://localhost:8085/api/badges/localadmin/ci-co/status.svg)](http://localhost:8085/localadmin/ci-co)
[![Quality Gate Status](http://localhost:9000/api/project_badges/measure?project=ci-co&metric=alert_status)](http://localhost:9000/dashboard?id=ci-co)
[![Coverage](http://localhost:9000/api/project_badges/measure?project=ci-co&metric=coverage)](http://localhost:9000/component_measures?id=ci-co&metric=coverage)
[![Duplicated Lines (%)](http://localhost:9000/api/project_badges/measure?project=ci-co&metric=duplicated_lines_density)](http://localhost:9000/component_measures?id=ci-co&metric=duplicated_lines_density)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A complete, self-hosted CI/CD platform with **security scanning** that runs entirely on your local machine with Docker Desktop. **One-click install - no manual configuration required!**

## Features

- **Git Server** (Gitea) - Repository hosting, pull requests, issues, wikis
- **CI/CD Engine** (Drone CI) - Automated builds, tests, and deployments
- **Docker Registry** - Private container image storage
- **Security Scanning** - Vulnerability, SAST, SCA, and secret detection
- **Web UI** - Browser-based management for all components
- **Zero Configuration** - Everything auto-configures on first run!

### Security Tools Included

| Tool | Purpose |
|------|---------|
| **Trivy** | Container & dependency vulnerability scanning, secret detection |
| **SonarQube** | Code quality & security analysis (SAST) |
| **Dependency-Track** | Software composition analysis (SCA/SBOM) |

---

## Quick Start (One Click!)

### Prerequisites
- Docker Desktop installed and running
- 16 GB RAM recommended (8 GB minimum without SonarQube)

### Start Everything

**Option 1: Double-click**
```
Double-click START.bat
```

**Option 2: Command line**
```powershell
docker compose up -d
```

Wait ~90 seconds, then everything is ready!

### Stop Everything
```
Double-click STOP.bat
```
or
```powershell
docker compose down
```

---

## Access Your Platform

| Service | URL | Credentials |
|---------|-----|-------------|
| **Gitea** (Git) | http://localhost:3000 | `localadmin` / `admin123` |
| **Drone CI** | http://localhost:8085 | Login via Gitea |
| **Registry UI** | http://localhost:5001 | None required |
| **SonarQube** | http://localhost:9000 | `admin` / `admin` |
| **Dependency-Track** | http://localhost:8082 | `admin` / `admin` |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                      LOCAL CI/CD PLATFORM                                 │
│                                                                           │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐           │
│  │  Gitea   │◄──►│ Drone CI │◄──►│ Registry │    │  Trivy   │           │
│  │  :3000   │    │  :8080   │    │  :5000   │    │  :4954   │           │
│  └────┬─────┘    └────┬─────┘    └──────────┘    └──────────┘           │
│       │               │                                                  │
│       │               │          ┌──────────┐    ┌──────────┐           │
│       │               ├─────────►│SonarQube │    │Dep-Track │           │
│       │               │          │  :9000   │    │  :8082   │           │
│  ┌────┴─────┐    ┌────┴─────┐    └──────────┘    └──────────┘           │
│  │PostgreSQL│    │  Runner  │                                            │
│  └──────────┘    └──────────┘                                            │
│                                                                           │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Security Pipeline Example

Add this `.drone.yml` to enable security scanning:

```yaml
kind: pipeline
type: docker
name: secure-build

steps:
  # Scan for secrets in code
  - name: secret-scan
    image: aquasec/trivy:latest
    commands:
      - trivy fs --scanners secret --exit-code 1 .

  # Scan dependencies for vulnerabilities
  - name: dependency-scan
    image: aquasec/trivy:latest
    commands:
      - trivy fs --scanners vuln --severity HIGH,CRITICAL .

  # Code quality & security (SAST)
  - name: sonarqube
    image: sonarsource/sonar-scanner-cli:latest
    environment:
      SONAR_HOST_URL: http://sonarqube:9000
      SONAR_TOKEN:
        from_secret: sonar_token
    commands:
      - sonar-scanner -Dsonar.projectKey=${DRONE_REPO_NAME}

  # Build Docker image
  - name: build
    image: plugins/docker
    settings:
      repo: localhost:5000/my-app
      registry: localhost:5000
      insecure: true
      tags: ${DRONE_COMMIT_SHA:0:8}

  # Scan container for vulnerabilities
  - name: container-scan
    image: aquasec/trivy:latest
    commands:
      - trivy image --server http://trivy-server:4954
        --severity CRITICAL
        --exit-code 1
        localhost:5000/my-app:${DRONE_COMMIT_SHA:0:8}
```

See [SECURITY-SCANNING.md](SECURITY-SCANNING.md) for complete documentation.

---

## Your First Pipeline

### 1. Create a Repository in Gitea

1. Go to http://localhost:3000
2. Login with `localadmin` / `admin123`
3. Click **+** → **New Repository**
4. Name it `my-app` and create

### 2. Clone and Add Pipeline

```bash
git clone http://localhost:3000/localadmin/my-app.git
cd my-app
```

Create `.drone.yml`:

```yaml
kind: pipeline
type: docker
name: default

steps:
  - name: build
    image: alpine
    commands:
      - echo "Hello from CI/CD!"

  - name: security-scan
    image: aquasec/trivy:latest
    commands:
      - trivy fs --scanners vuln,secret .
```

Push it:
```bash
git add .
git commit -m "Add CI pipeline"
git push
```

### 3. Activate in Drone

1. Go to http://localhost:8080
2. Click **Continue** to login via Gitea
3. Authorize the app
4. Find `my-app` and click **Activate**
5. Push another commit to trigger a build!

---

## Using the Docker Registry

```powershell
# Build your image
docker build -t my-app .

# Tag for local registry
docker tag my-app localhost:5000/my-app:latest

# Push to registry
docker push localhost:5000/my-app:latest
```

---

## Claude Code Integration

This platform includes an MCP server that integrates with [Claude Code](https://claude.ai/download), giving you AI-assisted security scanning directly in your terminal.

### Install into Claude Code

```powershell
.\scripts\install-claude.ps1
```

The installer will:
- Check if Claude Code is installed
- Detect existing installations and compare versions
- Build and configure the MCP server automatically
- Skip installation if already at the latest version

**Force reinstall:**
```powershell
.\scripts\install-claude.ps1 -Force
```

### Available Tools in Claude Code

After installation, restart Claude Code and these tools become available:

| Tool | Description |
|------|-------------|
| `trivy_scan_path` | Scan local paths for vulnerabilities |
| `trivy_scan_image` | Scan Docker images |
| `sonar_list_projects` | List SonarQube projects |
| `sonar_get_issues` | Get code quality issues |
| `gitea_list_repos` | List Gitea repositories |
| `drone_get_builds` | Get CI/CD build history |
| `check_platform_status` | Check all service health |
| `security_scan_all` | Run comprehensive security scan |

### Example Usage

Once installed, you can ask Claude Code things like:
- "Scan this project for vulnerabilities"
- "Check the CI/CD platform status"
- "Show me the latest build results"
- "List security issues in SonarQube"

### Uninstall from Claude Code

```powershell
.\scripts\uninstall-claude.ps1
```

This removes:
- MCP server from Claude Code configuration
- cicd-agent from PATH
- npm global links
- Built files (dist/ directories)

**Keep built files:**
```powershell
.\scripts\uninstall-claude.ps1 -KeepBuilds
```

---

## Troubleshooting

### Services not starting?
```powershell
docker compose ps
docker compose logs -f
```

### SonarQube won't start?
SonarQube needs more memory. Run:
```powershell
wsl -d docker-desktop
sysctl -w vm.max_map_count=262144
```

### Registry push fails?
Add `localhost:5000` to Docker Desktop insecure registries:
1. Docker Desktop → Settings → Docker Engine
2. Add `"insecure-registries": ["localhost:5000"]`
3. Apply & Restart

### Reset everything?
```powershell
docker compose down -v
docker compose up -d
```

---

## Files

```
ci-co/
├── START.bat              # One-click start
├── STOP.bat               # One-click stop
├── docker-compose.yml     # Main configuration
├── README.md              # This file
├── SECURITY-SCANNING.md   # Security scanning guide
├── ARCHITECTURE.md        # System design
├── INSTALLATION.md        # Detailed setup
├── CONFIGURATION.md       # Advanced config
├── USAGE.md               # Workflows & examples
├── mcp-server/            # Claude Code MCP server
├── cicd-agent/            # CLI security agent
├── shared/                # Shared library
└── scripts/
    ├── install-claude.ps1   # Claude Code installer
    ├── uninstall-claude.ps1 # Claude Code uninstaller
    ├── backup.ps1           # Backup data
    ├── restore.ps1          # Restore data
    └── status.ps1           # Check status
```

---

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| Gitea | `localadmin` | `admin123` |
| SonarQube | `admin` | `admin` |
| Dependency-Track | `admin` | `admin` |

**Change all passwords after first login!**

---

## Resource Requirements

| Profile | RAM | CPU | Storage |
|---------|-----|-----|---------|
| **Full** (with security) | 16 GB | 6 cores | 25 GB |
| **Minimal** (no SonarQube) | 8 GB | 4 cores | 15 GB |

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
