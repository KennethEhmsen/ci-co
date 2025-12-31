# Local CI/CD Platform

[![CI](https://github.com/KennethEhmsen/ci-co/actions/workflows/ci.yml/badge.svg)](https://github.com/KennethEhmsen/ci-co/actions/workflows/ci.yml)
[![Security Scan](https://img.shields.io/badge/security-Trivy-00C9A7)](https://github.com/KennethEhmsen/ci-co/security)
[![semantic-release](https://img.shields.io/badge/semantic--release-conventionalcommits-e10079?logo=semantic-release)](https://github.com/semantic-release/semantic-release)
[![GitHub release](https://img.shields.io/github/v/release/KennethEhmsen/ci-co)](https://github.com/KennethEhmsen/ci-co/releases)
[![GitHub stars](https://img.shields.io/github/stars/KennethEhmsen/ci-co)](https://github.com/KennethEhmsen/ci-co/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Required-blue)](https://www.docker.com/products/docker-desktop)

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

### CI Security Features

The GitHub Actions CI workflow includes comprehensive security checks:

| Check | Description | Fails On |
|-------|-------------|----------|
| **Trivy Scan** | Vulnerabilities, secrets, misconfigurations | HIGH/CRITICAL findings |
| **npm audit** | Dependency vulnerability scanning | HIGH severity |
| **License Check** | Ensures permissive licenses only | GPL/copyleft licenses |
| **Coverage Thresholds** | Maintains code quality | Coverage drops below minimum |

Results are automatically uploaded to the [GitHub Security tab](https://github.com/KennethEhmsen/ci-co/security).

### What's New in v1.17.0

| Feature | Description |
|---------|-------------|
| **Security Dashboard** | Unified security posture view aggregating Trivy, SonarQube, and Dependency-Track results in a single call |

```typescript
// Get unified security overview
const dashboard = await getSecurityDashboard({
  image: 'nginx:latest',
  sonarProject: 'my-project',
  dtrackProjectUuid: '12345-uuid'
});

console.log(dashboard.summary);     // { critical: 5, high: 12, medium: 8, low: 3, total: 28 }
console.log(dashboard.topFindings); // Top 10 most severe findings across all sources
```

### What's New in v1.16.1

| Feature | Description |
|---------|-------------|
| **Trivy Server API** | Image scans now use the Trivy server for faster scanning and centralized vulnerability database management |

### What's New in v1.16.0

| Feature | Description |
|---------|-------------|
| **PR Management** | Create, list, merge pull requests via Gitea API |
| **Issue Tracking** | Create and list issues with labels |
| **Quality Gates** | Check SonarQube quality gate pass/fail status |
| **SBOM Upload** | Upload SBOMs to Dependency-Track for analysis |
| **Caching** | Scan result caching with TTL for faster repeated scans |
| **Circuit Breaker** | Automatic failure handling for external services |
| **Rate Limiting** | Token bucket rate limiting to prevent API overload |
| **Audit Logging** | Structured logging for all security operations |
| **Config Files** | Load settings from `.cicd-agent.yaml` or `.cicd-agent.json` |
| **Output Formats** | JSON, table, markdown, and text output options |

See [CHANGELOG.md](CHANGELOG.md) for full details.

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

After installation, restart Claude Code and these tools become available (**406 total** as of v1.31.0):

> **Note:** The platform has grown significantly from the initial 41 tools to 406 enterprise-grade security tools. See [docs/API.md](docs/API.md) for the complete tool reference and [docs/FEATURES.md](docs/FEATURES.md) for the full feature overview.

### Tool Categories Overview (406 Tools)

| Category | Tools | Description |
|----------|-------|-------------|
| Vulnerability Scanning | 11 | Trivy container/dependency scanning |
| Code Quality | 5 | SonarQube SAST |
| Software Composition | 5 | Dependency-Track SCA/SBOM |
| Source Control | 12 | Gitea repository management |
| CI/CD Automation | 5 | Drone CI pipelines |
| SSO Integration | 20 | SAML/OIDC enterprise auth |
| RBAC System | 12 | Role-based access control |
| API Key Management | 8 | Scoped keys with rotation |
| Team Management | 15 | Organizations and teams |
| Audit Trail | 20 | Comprehensive audit logging |
| Executive Dashboard | 10 | Security KPIs |
| Compliance Reporting | 12 | SOC2, HIPAA, PCI-DSS, CIS |
| K8s Security | 15 | Kubernetes cluster scanning |
| GitOps Integration | 12 | ArgoCD/Flux security gates |
| Zero-Trust Security | 12 | Sigstore verification |
| SIEM Integration | 14 | Splunk/Elastic/Sentinel |
| + 34 more categories | 218+ | See docs/API.md |

### Core Security Tools (Sample)

#### Trivy Security Scanning (11 tools)

> **Note:** Image-based scans use the Trivy server API for faster scanning and centralized vulnerability database management. Path-based scans use local Docker execution.

| Tool | Description |
|------|-------------|
| `trivy_scan_path` | Scan local paths for vulnerabilities |
| `trivy_scan_image` | Scan Docker images for vulnerabilities (server API) |
| `trivy_generate_sbom` | Generate SBOM (CycloneDX/SPDX) for local paths |
| `trivy_generate_sbom_image` | Generate SBOM for Docker images (server API) |
| `trivy_scan_iac` | Scan IaC files (Terraform, K8s, Docker, etc.) |
| `trivy_scan_secrets` | Scan local paths for hardcoded secrets |
| `trivy_scan_secrets_image` | Scan Docker images for secrets (server API) |
| `trivy_scan_licenses` | Scan local paths for license compliance |
| `trivy_scan_licenses_image` | Scan Docker images for licenses (server API) |
| `trivy_scan_image_full` | **Combined scan**: vuln + secret + license + SBOM |
| `trivy_scan_path_full` | **Combined scan**: vuln + secret + license + IaC + SBOM |

#### SonarQube (5 tools)

| Tool | Description |
|------|-------------|
| `sonar_list_projects` | List all SonarQube projects |
| `sonar_get_issues` | Get code quality issues (bugs, vulnerabilities, smells) |
| `sonar_get_security_hotspots` | Get security hotspots requiring review |
| `sonar_get_metrics` | Get project metrics (coverage, duplication, etc.) |
| `sonar_get_quality_gate_status` | Check if project passes quality gate |

#### Dependency-Track (5 tools)

| Tool | Description |
|------|-------------|
| `dtrack_list_projects` | List all Dependency-Track projects |
| `dtrack_get_vulnerabilities` | Get vulnerabilities for a project |
| `dtrack_get_findings` | Get detailed findings with analysis |
| `dtrack_get_components` | Get component inventory (SBOM) |
| `dtrack_upload_sbom` | Upload SBOM for vulnerability analysis |

#### Gitea (12 tools)

| Tool | Description |
|------|-------------|
| `gitea_list_repos` | List all repositories |
| `gitea_get_repo` | Get repository details |
| `gitea_get_branches` | List branches in a repository |
| `gitea_get_commits` | Get recent commits |
| `gitea_create_repo` | Create a new repository |
| `gitea_migrate_repo` | Migrate/mirror external repository |
| `gitea_list_pull_requests` | List PRs with state filtering |
| `gitea_get_pull_request` | Get pull request details |
| `gitea_create_pull_request` | Create a new pull request |
| `gitea_merge_pull_request` | Merge a pull request |
| `gitea_create_issue` | Create an issue with labels |
| `gitea_list_issues` | List issues with state filtering |

#### Drone CI (5 tools)

| Tool | Description |
|------|-------------|
| `drone_list_repos` | List repositories with CI enabled |
| `drone_get_builds` | Get build history |
| `drone_get_build` | Get specific build details |
| `drone_get_build_logs` | Get build logs |
| `drone_trigger_build` | Trigger a new build |

#### Docker Registry (2 tools)

| Tool | Description |
|------|-------------|
| `registry_get_catalog` | List all images in registry |
| `registry_get_tags` | Get tags for an image |

#### Platform Tools (1 tool)

| Tool | Description |
|------|-------------|
| `check_platform_status` | Check health of all services |

### Example Usage

Once installed, you can ask Claude Code things like:
- "Scan this project for vulnerabilities"
- "Check the CI/CD platform status"
- "Show me the latest build results"
- "List security issues in SonarQube"
- "Create a pull request from feature branch to main"
- "Check if the project passes the quality gate"
- "Upload the SBOM to Dependency-Track"
- "List all open issues in this repository"

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

## Contributing

### Conventional Commits

This project uses [Conventional Commits](https://www.conventionalcommits.org/) for automated versioning and changelog generation. All commit messages must follow this format:

```
<type>(<scope>): <subject>

[optional body]

[optional footer]
```

#### Commit Types

| Type | Description | Version Bump |
|------|-------------|--------------|
| `feat` | New feature | Minor (1.x.0) |
| `fix` | Bug fix | Patch (1.0.x) |
| `docs` | Documentation only | None |
| `style` | Formatting, no code change | None |
| `refactor` | Code restructuring | None |
| `perf` | Performance improvement | Patch |
| `test` | Adding tests | None |
| `build` | Build system or dependencies | None |
| `ci` | CI configuration | None |
| `chore` | Maintenance tasks | None |
| `revert` | Revert a commit | Patch |

#### Breaking Changes

For breaking changes, add `!` after the type or include `BREAKING CHANGE:` in the footer:

```bash
feat!: remove deprecated API endpoints

# or

feat: redesign authentication system

BREAKING CHANGE: JWT tokens now expire after 1 hour instead of 24 hours
```

Breaking changes trigger a **major version bump** (x.0.0).

#### Examples

```bash
# Feature (minor bump)
git commit -m "feat(auth): add oauth2 support"

# Bug fix (patch bump)
git commit -m "fix(scanner): resolve timeout on large files"

# Documentation (no bump)
git commit -m "docs: update installation guide"

# Breaking change (major bump)
git commit -m "feat!: change api response format"
```

### Pre-commit Hooks

The project uses Husky to run pre-commit hooks:

- **lint-staged**: Runs ESLint and Prettier on staged `.ts` files
- **commitlint**: Validates commit messages follow conventional commits

If your commit is rejected, check the error message and fix the format.

---

## Documentation

| Document | Description |
|----------|-------------|
| [README.md](README.md) | Quick start guide (this file) |
| [INSTALLATION.md](INSTALLATION.md) | Detailed setup instructions |
| [CONFIGURATION.md](CONFIGURATION.md) | Advanced configuration options |
| [USAGE.md](USAGE.md) | Workflows and usage examples |
| [SECURITY-SCANNING.md](SECURITY-SCANNING.md) | Security scanning guide |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design and architecture |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [SECURITY.md](SECURITY.md) | Security policy |

### Developer & Admin Docs

| Document | Description |
|----------|-------------|
| [docs/API.md](docs/API.md) | Complete API reference (406 tools) |
| [docs/CLI.md](docs/CLI.md) | CI/CD Agent CLI reference |
| [docs/DEVELOPER.md](docs/DEVELOPER.md) | Developer guide & extension |
| [docs/ADMIN.md](docs/ADMIN.md) | Administrator operations guide |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Troubleshooting guide |

### Package Documentation

| Package | README |
|---------|--------|
| MCP Server | [mcp-server/README.md](mcp-server/README.md) |
| CI/CD Agent | [cicd-agent/README.md](cicd-agent/README.md) |
| Shared Library | [shared/README.md](shared/README.md) |

---

## Files

```
ci-co/
├── START.bat              # One-click start
├── STOP.bat               # One-click stop
├── docker-compose.yml     # Main configuration
├── README.md              # This file
├── CHANGELOG.md           # Version history
├── SECURITY.md            # Security policy
├── SECURITY-SCANNING.md   # Security scanning guide
├── ARCHITECTURE.md        # System design
├── INSTALLATION.md        # Detailed setup
├── CONFIGURATION.md       # Advanced config
├── USAGE.md               # Workflows & examples
├── docs/                  # Additional documentation
│   ├── API.md             # API reference
│   ├── CLI.md             # CLI reference
│   ├── DEVELOPER.md       # Developer guide
│   ├── ADMIN.md           # Admin operations
│   └── TROUBLESHOOTING.md # Troubleshooting
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
