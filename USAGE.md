# Usage Guide - Local CI/CD Platform

## Table of Contents

1. [Quick Start](#quick-start)
2. [Working with Gitea](#working-with-gitea)
3. [Creating CI/CD Pipelines](#creating-cicd-pipelines)
4. [Using the Docker Registry](#using-the-docker-registry)
5. [Pipeline Examples](#pipeline-examples)
6. [Secrets Management](#secrets-management)
7. [Multi-Stage Pipelines](#multi-stage-pipelines)
8. [Advanced Workflows](#advanced-workflows)
9. [MCP Server Usage](#mcp-server-usage)
10. [CICD Agent Usage](#cicd-agent-usage)
11. [Security Tools Reference](#security-tools-reference)

---

## Quick Start

### Starting the Platform

```powershell
# Navigate to project directory
cd "C:\Users\keeh\OneDrive - Mansoft\Skrivebord\Mock Servers\ci-co"

# Start all services
docker compose up -d

# Check status
docker compose ps
```

### Stopping the Platform

```powershell
# Stop all services
docker compose down

# Stop and remove volumes (WARNING: deletes all data)
docker compose down -v
```

### Service URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| Gitea | http://localhost:3000 | Your admin account |
| Drone CI | http://localhost:8080 | OAuth via Gitea |
| Registry UI | http://localhost:5001 | None |
| Registry API | http://localhost:5000/v2/ | None |

---

## Working with Gitea

### Creating a New Repository

1. Log in to Gitea at http://localhost:3000
2. Click the **+** icon → **New Repository**
3. Fill in:
   - Repository Name: `my-app`
   - Visibility: Private/Public
   - Initialize with: README, .gitignore, License
4. Click **Create Repository**

### Cloning a Repository

**Via HTTPS:**
```powershell
git clone http://localhost:3000/username/my-app.git
cd my-app
```

**Via SSH:**
```powershell
git clone ssh://git@localhost:2222/username/my-app.git
cd my-app
```

### Configuring Git

```powershell
# Set your identity
git config user.name "Your Name"
git config user.email "your-email@example.com"

# For this repo only, use local Gitea
git config credential.helper store
```

### Working with Branches

```powershell
# Create feature branch
git checkout -b feature/new-feature

# Make changes and commit
git add .
git commit -m "Add new feature"

# Push to remote
git push -u origin feature/new-feature
```

### Creating a Pull Request

1. Push your feature branch
2. Go to Gitea → Your Repository
3. Click **New Pull Request**
4. Select source and target branches
5. Add title and description
6. Click **Create Pull Request**

---

## Creating CI/CD Pipelines

### Basic .drone.yml Structure

Create a `.drone.yml` file in your repository root:

```yaml
kind: pipeline
type: docker
name: default

steps:
  - name: build
    image: node:18-alpine
    commands:
      - npm install
      - npm run build

  - name: test
    image: node:18-alpine
    commands:
      - npm test

trigger:
  branch:
    - main
    - develop
  event:
    - push
    - pull_request
```

### Activating CI/CD for a Repository

1. Go to Drone CI at http://localhost:8080
2. Click **Sync** to refresh repository list
3. Find your repository
4. Click **Activate**
5. Push a commit to trigger the first build

### Viewing Build Results

1. Go to Drone CI
2. Click on your repository
3. View build history and logs
4. Click on any build for detailed step logs

---

## Using the Docker Registry

### Pushing Images to Registry

```powershell
# Build your image
docker build -t my-app:latest .

# Tag for local registry
docker tag my-app:latest localhost:5000/my-app:latest
docker tag my-app:latest localhost:5000/my-app:v1.0.0

# Push to registry
docker push localhost:5000/my-app:latest
docker push localhost:5000/my-app:v1.0.0
```

### Pulling Images from Registry

```powershell
docker pull localhost:5000/my-app:latest
```

### Listing Images in Registry

```powershell
# List all repositories
curl http://localhost:5000/v2/_catalog

# List tags for a repository
curl http://localhost:5000/v2/my-app/tags/list
```

### Using Registry in CI/CD

```yaml
kind: pipeline
type: docker
name: default

steps:
  - name: build
    image: plugins/docker
    settings:
      repo: localhost:5000/my-app
      registry: localhost:5000
      insecure: true
      tags:
        - latest
        - ${DRONE_COMMIT_SHA:0:8}
```

---

## Pipeline Examples

### Node.js Application

```yaml
kind: pipeline
type: docker
name: nodejs-pipeline

steps:
  - name: install
    image: node:18-alpine
    commands:
      - npm ci

  - name: lint
    image: node:18-alpine
    commands:
      - npm run lint
    depends_on:
      - install

  - name: test
    image: node:18-alpine
    commands:
      - npm test
    depends_on:
      - install

  - name: build
    image: node:18-alpine
    commands:
      - npm run build
    depends_on:
      - lint
      - test

  - name: docker
    image: plugins/docker
    settings:
      repo: localhost:5000/my-node-app
      registry: localhost:5000
      insecure: true
      tags:
        - latest
        - ${DRONE_TAG:-${DRONE_COMMIT_SHA:0:8}}
    depends_on:
      - build
    when:
      branch:
        - main

trigger:
  event:
    - push
    - pull_request
```

### Python Application

```yaml
kind: pipeline
type: docker
name: python-pipeline

steps:
  - name: install
    image: python:3.11-slim
    commands:
      - pip install -r requirements.txt
      - pip install pytest pytest-cov flake8

  - name: lint
    image: python:3.11-slim
    commands:
      - flake8 src/
    depends_on:
      - install

  - name: test
    image: python:3.11-slim
    commands:
      - pytest --cov=src tests/
    depends_on:
      - install

  - name: build
    image: plugins/docker
    settings:
      repo: localhost:5000/my-python-app
      registry: localhost:5000
      insecure: true
      tags:
        - latest
    depends_on:
      - lint
      - test
    when:
      branch:
        - main

trigger:
  event:
    - push
    - pull_request
```

### .NET Application

```yaml
kind: pipeline
type: docker
name: dotnet-pipeline

steps:
  - name: restore
    image: mcr.microsoft.com/dotnet/sdk:8.0
    commands:
      - dotnet restore

  - name: build
    image: mcr.microsoft.com/dotnet/sdk:8.0
    commands:
      - dotnet build --no-restore --configuration Release
    depends_on:
      - restore

  - name: test
    image: mcr.microsoft.com/dotnet/sdk:8.0
    commands:
      - dotnet test --no-build --configuration Release
    depends_on:
      - build

  - name: publish
    image: mcr.microsoft.com/dotnet/sdk:8.0
    commands:
      - dotnet publish --no-build --configuration Release -o ./publish
    depends_on:
      - test

  - name: docker
    image: plugins/docker
    settings:
      repo: localhost:5000/my-dotnet-app
      registry: localhost:5000
      insecure: true
      dockerfile: Dockerfile
      tags:
        - latest
        - ${DRONE_TAG:-${DRONE_COMMIT_SHA:0:8}}
    depends_on:
      - publish
    when:
      branch:
        - main

trigger:
  event:
    - push
    - pull_request
```

### Go Application

```yaml
kind: pipeline
type: docker
name: go-pipeline

steps:
  - name: test
    image: golang:1.21-alpine
    commands:
      - go test -v ./...

  - name: build
    image: golang:1.21-alpine
    commands:
      - CGO_ENABLED=0 go build -o app .
    depends_on:
      - test

  - name: docker
    image: plugins/docker
    settings:
      repo: localhost:5000/my-go-app
      registry: localhost:5000
      insecure: true
      tags:
        - latest
    depends_on:
      - build
    when:
      branch:
        - main
```

### Multi-Architecture Build

```yaml
kind: pipeline
type: docker
name: multi-arch

platform:
  os: linux
  arch: amd64

steps:
  - name: build-amd64
    image: plugins/docker
    settings:
      repo: localhost:5000/my-app
      registry: localhost:5000
      insecure: true
      auto_tag: true
      auto_tag_suffix: amd64
```

---

## Secrets Management

### Adding Secrets in Drone

1. Go to Drone CI → Your Repository → Settings
2. Click **Secrets**
3. Add a new secret:
   - Name: `docker_password`
   - Value: `your-secret-value`
4. Click **Save**

### Using Secrets in Pipeline

```yaml
kind: pipeline
type: docker
name: default

steps:
  - name: deploy
    image: alpine
    environment:
      API_KEY:
        from_secret: api_key
      DATABASE_URL:
        from_secret: database_url
    commands:
      - echo "Deploying with API key..."
```

### Organization Secrets

For secrets shared across repositories:

1. Go to Drone → Organization Settings
2. Add organization-level secrets
3. Reference in pipelines the same way

---

## Multi-Stage Pipelines

### Pipeline with Multiple Stages

```yaml
kind: pipeline
type: docker
name: build

steps:
  - name: build
    image: node:18-alpine
    commands:
      - npm ci
      - npm run build

  - name: test
    image: node:18-alpine
    commands:
      - npm test

---
kind: pipeline
type: docker
name: deploy-staging

steps:
  - name: deploy
    image: alpine
    commands:
      - echo "Deploying to staging..."

depends_on:
  - build

trigger:
  branch:
    - develop

---
kind: pipeline
type: docker
name: deploy-production

steps:
  - name: deploy
    image: alpine
    commands:
      - echo "Deploying to production..."

depends_on:
  - build

trigger:
  branch:
    - main
  event:
    - tag
```

### Conditional Steps

```yaml
steps:
  - name: notify-slack
    image: plugins/slack
    settings:
      webhook:
        from_secret: slack_webhook
      channel: builds
    when:
      status:
        - success
        - failure

  - name: deploy
    image: alpine
    commands:
      - echo "Deploying..."
    when:
      branch:
        - main
      event:
        exclude:
          - pull_request
```

---

## Advanced Workflows

### Services (Databases, Redis, etc.)

```yaml
kind: pipeline
type: docker
name: default

services:
  - name: database
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: test
      POSTGRES_PASSWORD: test
      POSTGRES_DB: testdb

  - name: redis
    image: redis:7-alpine

steps:
  - name: test
    image: node:18-alpine
    environment:
      DATABASE_URL: postgres://test:test@database:5432/testdb
      REDIS_URL: redis://redis:6379
    commands:
      - npm test
```

### Caching Dependencies

```yaml
kind: pipeline
type: docker
name: default

steps:
  - name: restore-cache
    image: meltwater/drone-cache
    settings:
      backend: filesystem
      restore: true
      cache_key: "{{ .Repo.Name }}_{{ checksum \"package-lock.json\" }}"
      mount:
        - node_modules
    volumes:
      - name: cache
        path: /tmp/cache

  - name: build
    image: node:18-alpine
    commands:
      - npm ci
      - npm run build

  - name: save-cache
    image: meltwater/drone-cache
    settings:
      backend: filesystem
      rebuild: true
      cache_key: "{{ .Repo.Name }}_{{ checksum \"package-lock.json\" }}"
      mount:
        - node_modules
    volumes:
      - name: cache
        path: /tmp/cache

volumes:
  - name: cache
    host:
      path: /tmp/drone-cache
```

### Matrix Builds

```yaml
kind: pipeline
type: docker
name: test-matrix

steps:
  - name: test
    image: node:${NODE_VERSION}-alpine
    commands:
      - node --version
      - npm test

trigger:
  event:
    - push

---
kind: pipeline
type: docker
name: node-16

steps:
  - name: test
    image: node:16-alpine
    commands:
      - npm test

---
kind: pipeline
type: docker
name: node-18

steps:
  - name: test
    image: node:18-alpine
    commands:
      - npm test

---
kind: pipeline
type: docker
name: node-20

steps:
  - name: test
    image: node:20-alpine
    commands:
      - npm test
```

### Cron Jobs (Scheduled Builds)

1. Go to Drone → Repository → Settings → Cron
2. Add a cron job:
   - Name: `nightly-build`
   - Branch: `main`
   - Schedule: `0 0 * * *` (midnight daily)

```yaml
kind: pipeline
type: docker
name: default

steps:
  - name: nightly-tasks
    image: alpine
    commands:
      - echo "Running nightly tasks..."
    when:
      event:
        - cron
      cron:
        - nightly-build

trigger:
  event:
    - push
    - cron
```

### Promoting Builds

```yaml
kind: pipeline
type: docker
name: deploy

steps:
  - name: deploy-staging
    image: alpine
    commands:
      - echo "Deploying to staging..."
    when:
      target:
        - staging

  - name: deploy-production
    image: alpine
    commands:
      - echo "Deploying to production..."
    when:
      target:
        - production

trigger:
  event:
    - promote
```

Promote a build via CLI:
```powershell
drone build promote owner/repo 42 production
```

---

## CLI Commands Reference

### Drone CLI Installation

```powershell
# Download Drone CLI (Windows)
Invoke-WebRequest -Uri "https://github.com/harness/drone-cli/releases/latest/download/drone_windows_amd64.tar.gz" -OutFile "drone-cli.tar.gz"
tar -xzf drone-cli.tar.gz
Move-Item drone.exe C:\Windows\System32\
```

### Configure Drone CLI

```powershell
# Set environment variables
$env:DRONE_SERVER = "http://localhost:8080"
$env:DRONE_TOKEN = "your-token-from-drone-ui"  # Get from Drone UI → Account → Token
```

### Common Drone CLI Commands

```powershell
# List builds
drone build ls owner/repo

# View build details
drone build info owner/repo 42

# Restart a build
drone build restart owner/repo 42

# Promote a build
drone build promote owner/repo 42 production

# List secrets
drone secret ls owner/repo

# Add a secret
drone secret add owner/repo --name my_secret --data "secret-value"

# Sync repositories
drone repo sync

# Enable/disable repository
drone repo enable owner/repo
drone repo disable owner/repo
```

---

## Best Practices

### 1. Pipeline Design
- Keep steps focused and single-purpose
- Use `depends_on` for explicit dependencies
- Add `when` conditions to skip unnecessary steps

### 2. Security
- Never hardcode secrets in `.drone.yml`
- Use Drone secrets for sensitive values
- Limit secret scope when possible

### 3. Performance
- Use caching for dependencies
- Run independent steps in parallel
- Use appropriate base images (alpine when possible)

### 4. Reliability
- Add health checks to services
- Set reasonable timeouts
- Handle failures gracefully with notifications

---

## MCP Server Usage

The MCP (Model Context Protocol) server enables Claude AI to interact directly with the CI/CD platform through 60+ tools.

### Installation

```powershell
cd mcp-server
npm install
npm run build
```

### Configuration for Claude Desktop

Add to your Claude Desktop configuration (`%APPDATA%\Claude\claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "cicd-platform": {
      "command": "node",
      "args": ["C:/path/to/ci-co/mcp-server/dist/index.js"],
      "env": {
        "CICD_TRIVY_URL": "http://localhost:4954",
        "CICD_SONARQUBE_URL": "http://localhost:9000",
        "CICD_DTRACK_URL": "http://localhost:8082",
        "CICD_GITEA_URL": "http://localhost:3000",
        "CICD_DRONE_URL": "http://localhost:8080",
        "CICD_REGISTRY_URL": "http://localhost:5000"
      }
    }
  }
}
```

### Configuration for Cline/Continue

```json
{
  "mcpServers": {
    "cicd-platform": {
      "command": "node",
      "args": ["./mcp-server/dist/index.js"]
    }
  }
}
```

### Available Tool Categories

| Category | Tool Count | Description |
|----------|------------|-------------|
| Trivy Scanning | 11 | Image and path vulnerability scanning |
| SonarQube | 5 | Code quality and SAST |
| Dependency-Track | 5 | SCA and SBOM management |
| Gitea | 11 | Git repository management |
| Drone CI | 5 | CI/CD pipeline control |
| Registry | 6 | Docker registry operations |
| Compliance | 7 | Framework compliance reporting |
| OPA/Rego | 5 | Policy evaluation |
| Scheduler | 7 | Automated scan scheduling |
| VulnDB | 6 | Offline vulnerability database |

### Example Conversation with Claude

```
User: Scan the nginx:latest image for vulnerabilities

Claude: I'll scan the nginx:latest image using Trivy.
[Uses trivy_scan_image tool]

Found 23 vulnerabilities:
- 0 CRITICAL
- 5 HIGH
- 18 MEDIUM

Would you like me to check compliance status or generate a report?
```

---

## CICD Agent Usage

The CICD Agent is a standalone CLI tool that can be used in scripts, CI/CD pipelines, or interactively.

### Installation

```powershell
cd cicd-agent
npm install
npm run build

# Global install (optional)
npm link
```

### Environment Variables

```powershell
# Required for API access
$env:ANTHROPIC_API_KEY = "sk-ant-xxx"

# Service URLs (optional, uses defaults)
$env:CICD_TRIVY_URL = "http://localhost:4954"
$env:CICD_SONARQUBE_URL = "http://localhost:9000"
$env:CICD_DTRACK_URL = "http://localhost:8082"
$env:CICD_GITEA_URL = "http://localhost:3000"
$env:CICD_DRONE_URL = "http://localhost:8080"
$env:CICD_REGISTRY_URL = "http://localhost:5000"

# Optional authentication
$env:CICD_SONAR_TOKEN = "your-token"
$env:CICD_DTRACK_API_KEY = "your-key"
$env:CICD_GITEA_TOKEN = "your-token"
$env:CICD_DRONE_TOKEN = "your-token"
```

### Interactive Mode

```powershell
# Start interactive agent
node dist/index.js

# Example prompts:
> Scan nginx:latest for vulnerabilities
> Check SOC2 compliance for the scan results
> Create a nightly scan schedule for production images
> Generate a compliance report in HTML format
```

### Script Mode

```powershell
# Single command execution
node dist/index.js "Scan localhost:5000/myapp:latest and check PCI-DSS compliance"

# Piped input
echo "List all scheduled scans" | node dist/index.js
```

### CI/CD Pipeline Integration

```yaml
# Drone CI example
steps:
  - name: security-scan
    image: node:20-alpine
    environment:
      ANTHROPIC_API_KEY:
        from_secret: anthropic_key
    commands:
      - npm install -g @cicd/agent
      - cicd-agent "Scan ${DRONE_REPO}:${DRONE_COMMIT_SHA:0:8} and fail if critical vulnerabilities found"
```

---

## Security Tools Reference

### Quick Reference Table

| Tool | Purpose | Example |
|------|---------|---------|
| `trivy_scan_image` | Scan Docker image | `{"image": "nginx:latest"}` |
| `trivy_scan_path` | Scan local directory | `{"path": "/app/src"}` |
| `compliance_check_status` | Check framework compliance | `{"image": "app:v1", "frameworks": ["SOC2"]}` |
| `compliance_generate_report` | Generate audit report | `{"image": "app:v1", "format": "html"}` |
| `opa_evaluate_policy` | Evaluate security policy | `{"image": "app:v1", "policy": "vulnerability-threshold"}` |
| `scheduler_create_job` | Create scheduled scan | `{"name": "nightly", "cron": "@daily"}` |
| `vuln_db_sync` | Download vuln database | `{"force": true}` |
| `trivy_scan_offline` | Scan without internet | `{"image": "app:v1"}` |

### Detailed Documentation

- **Feature Overview**: [docs/FEATURES.md](docs/FEATURES.md)
- **Tool Cheat Sheet**: [docs/CHEAT-SHEET.md](docs/CHEAT-SHEET.md)
- **Security Scanning**: [SECURITY-SCANNING.md](SECURITY-SCANNING.md)

### Common Workflows

#### 1. Basic Security Scan

```json
// Step 1: Scan image
{ "tool": "trivy_scan_image", "input": { "image": "myapp:latest" } }

// Step 2: Check compliance
{ "tool": "compliance_check_status", "input": { "image": "myapp:latest", "frameworks": ["SOC2"] } }
```

#### 2. Policy-Gated Pipeline

```json
// Evaluate against vulnerability thresholds
{
  "tool": "opa_evaluate_policy",
  "input": {
    "image": "myapp:latest",
    "policy": "vulnerability-threshold",
    "thresholds": { "critical": 0, "high": 5 }
  }
}
```

#### 3. Scheduled Monitoring

```json
// Create nightly scan
{
  "tool": "scheduler_create_job",
  "input": {
    "name": "production-nightly",
    "cron": "0 2 * * *",
    "target": { "type": "image", "value": "production:latest" },
    "notifications": {
      "webhooks": [{
        "url": "https://hooks.slack.com/xxx",
        "type": "slack",
        "onFailure": true
      }]
    }
  }
}
```

#### 4. Compliance Trending

```json
// Record daily snapshot
{ "tool": "compliance_trend_record", "input": { "target": "prod-api", "image": "prod-api:latest" } }

// Get 30-day trend
{ "tool": "compliance_trend_get", "input": { "target": "prod-api", "days": 30 } }
```

#### 5. Air-Gapped Scanning

```json
// Sync database (requires internet)
{ "tool": "vuln_db_sync", "input": {} }

// Scan offline (no internet required)
{ "tool": "trivy_scan_offline", "input": { "image": "internal:latest" } }
```
