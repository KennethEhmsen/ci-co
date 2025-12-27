# Security & Vulnerability Scanning Guide

Your CI/CD platform now includes enterprise-grade security scanning tools!

## New Features (v2.0)

In addition to basic scanning, the platform now includes:

| Feature | Description | Documentation |
|---------|-------------|---------------|
| **Compliance Reporting** | Map findings to SOC2, HIPAA, PCI-DSS, CIS | [Features Guide](docs/FEATURES.md#1-compliance-reporting-issue-15) |
| **OPA/Rego Policies** | Custom security policies in Rego | [Features Guide](docs/FEATURES.md#2-oparego-policy-engine-issue-16) |
| **Scheduled Scanning** | Automated cron-based scans | [Features Guide](docs/FEATURES.md#3-scheduled-scanning-issue-17) |
| **Offline VulnDB** | Air-gapped environment support | [Features Guide](docs/FEATURES.md#4-offline-vulnerability-database-issue-18) |

See the [Cheat Sheet](docs/CHEAT-SHEET.md) for quick tool reference.

## Security Tools Overview

| Tool | Purpose | URL | Default Login |
|------|---------|-----|---------------|
| **Trivy** | Container & filesystem vulnerability scanning | http://localhost:4954 | API only |
| **SonarQube** | Code quality & security analysis (SAST) | http://localhost:9000 | `admin` / `admin` |
| **Dependency-Track** | Software composition analysis (SCA/SBOM) | http://localhost:8082 | `admin` / `admin` |

## What Each Tool Does

### 1. Trivy (Container Security)
- Scans Docker images for vulnerabilities
- Scans filesystem for misconfigurations
- Scans IaC (Terraform, CloudFormation, Kubernetes)
- Detects secrets in code
- Generates SBOM (Software Bill of Materials)

### 2. SonarQube (Code Security - SAST)
- Static Application Security Testing
- Detects SQL injection, XSS, CSRF vulnerabilities
- Code quality metrics (bugs, code smells, duplication)
- Security hotspots review
- Supports 30+ programming languages

### 3. Dependency-Track (Dependency Security - SCA)
- Software Composition Analysis
- Tracks all dependencies across projects
- Monitors known vulnerabilities (CVE)
- Policy enforcement
- License compliance
- SBOM management

---

## Quick Start: Security Pipeline

Add this `.drone.yml` to enable full security scanning:

```yaml
kind: pipeline
type: docker
name: security-scan

steps:
  # ===========================================================================
  # STAGE 1: Secret Detection
  # ===========================================================================
  - name: detect-secrets
    image: aquasec/trivy:latest
    commands:
      - trivy fs --scanners secret --exit-code 1 .
    failure: ignore  # Remove to fail pipeline on secrets

  # ===========================================================================
  # STAGE 2: Code Quality & SAST (SonarQube)
  # ===========================================================================
  - name: sonarqube-scan
    image: sonarsource/sonar-scanner-cli:latest
    environment:
      SONAR_HOST_URL: http://sonarqube:9000
      SONAR_TOKEN:
        from_secret: sonar_token
    commands:
      - sonar-scanner
        -Dsonar.projectKey=$${DRONE_REPO_NAME}
        -Dsonar.sources=.
        -Dsonar.host.url=$${SONAR_HOST_URL}
        -Dsonar.login=$${SONAR_TOKEN}

  # ===========================================================================
  # STAGE 3: Dependency Vulnerability Scan
  # ===========================================================================
  - name: dependency-scan
    image: aquasec/trivy:latest
    commands:
      - trivy fs --scanners vuln --exit-code 0 --severity HIGH,CRITICAL .
      - trivy fs --scanners vuln --format json -o trivy-deps.json .

  # ===========================================================================
  # STAGE 4: Build Docker Image
  # ===========================================================================
  - name: build-image
    image: plugins/docker
    settings:
      repo: localhost:5000/my-app
      registry: localhost:5000
      insecure: true
      tags: scan-${DRONE_COMMIT_SHA:0:8}
      dry_run: true  # Don't push yet
    when:
      event:
        exclude:
          - pull_request

  # ===========================================================================
  # STAGE 5: Container Vulnerability Scan
  # ===========================================================================
  - name: container-scan
    image: aquasec/trivy:latest
    commands:
      - trivy image --server http://trivy-server:4954
        --exit-code 1
        --severity CRITICAL
        localhost:5000/my-app:scan-${DRONE_COMMIT_SHA:0:8}
    failure: ignore  # Remove to fail on CRITICAL vulns

  # ===========================================================================
  # STAGE 6: Generate SBOM & Upload to Dependency-Track
  # ===========================================================================
  - name: generate-sbom
    image: aquasec/trivy:latest
    commands:
      - trivy image --format cyclonedx
        -o sbom.json
        localhost:5000/my-app:scan-${DRONE_COMMIT_SHA:0:8}

  - name: upload-sbom
    image: curlimages/curl:latest
    environment:
      DTRACK_API_KEY:
        from_secret: dtrack_api_key
    commands:
      - |
        curl -X POST "http://dependency-track-apiserver:8080/api/v1/bom" \
          -H "X-Api-Key: $${DTRACK_API_KEY}" \
          -H "Content-Type: application/json" \
          -d @sbom.json

  # ===========================================================================
  # STAGE 7: Push Image (only if scans pass)
  # ===========================================================================
  - name: push-image
    image: plugins/docker
    settings:
      repo: localhost:5000/my-app
      registry: localhost:5000
      insecure: true
      tags:
        - latest
        - ${DRONE_COMMIT_SHA:0:8}
    when:
      branch:
        - main

trigger:
  event:
    - push
    - pull_request
```

---

## Individual Scan Examples

### Trivy: Scan Docker Image

```yaml
steps:
  - name: scan-image
    image: aquasec/trivy:latest
    commands:
      # Use local Trivy server for faster scans (cached DB)
      - trivy image --server http://trivy-server:4954
        --severity HIGH,CRITICAL
        --exit-code 1
        your-image:tag
```

### Trivy: Scan Filesystem for Vulnerabilities

```yaml
steps:
  - name: scan-deps
    image: aquasec/trivy:latest
    commands:
      - trivy fs --scanners vuln .
```

### Trivy: Scan for Secrets

```yaml
steps:
  - name: scan-secrets
    image: aquasec/trivy:latest
    commands:
      - trivy fs --scanners secret --exit-code 1 .
```

### Trivy: Scan IaC (Terraform/Kubernetes)

```yaml
steps:
  - name: scan-iac
    image: aquasec/trivy:latest
    commands:
      - trivy config --exit-code 1 ./terraform/
      - trivy config --exit-code 1 ./k8s/
```

### SonarQube: Full Analysis

```yaml
steps:
  - name: sonar-scan
    image: sonarsource/sonar-scanner-cli:latest
    environment:
      SONAR_HOST_URL: http://sonarqube:9000
      SONAR_TOKEN:
        from_secret: sonar_token
    commands:
      - sonar-scanner
        -Dsonar.projectKey=${DRONE_REPO_NAME}
        -Dsonar.projectName="${DRONE_REPO_NAME}"
        -Dsonar.sources=src
        -Dsonar.tests=tests
        -Dsonar.language=js
```

### Generate SBOM (Software Bill of Materials)

```yaml
steps:
  - name: sbom
    image: aquasec/trivy:latest
    commands:
      # CycloneDX format (industry standard)
      - trivy image --format cyclonedx -o sbom-cyclonedx.json my-image:tag

      # SPDX format
      - trivy image --format spdx-json -o sbom-spdx.json my-image:tag

      # Trivy's native format
      - trivy image --format json -o sbom-trivy.json my-image:tag
```

---

## Language-Specific Examples

### Node.js Project

```yaml
kind: pipeline
type: docker
name: nodejs-security

steps:
  - name: install
    image: node:18-alpine
    commands:
      - npm ci

  - name: audit
    image: node:18-alpine
    commands:
      - npm audit --audit-level=high

  - name: trivy-scan
    image: aquasec/trivy:latest
    commands:
      - trivy fs --scanners vuln,secret .

  - name: sonar
    image: sonarsource/sonar-scanner-cli:latest
    environment:
      SONAR_HOST_URL: http://sonarqube:9000
      SONAR_TOKEN:
        from_secret: sonar_token
    commands:
      - sonar-scanner
        -Dsonar.projectKey=${DRONE_REPO_NAME}
        -Dsonar.sources=src
        -Dsonar.javascript.lcov.reportPaths=coverage/lcov.info
```

### Python Project

```yaml
kind: pipeline
type: docker
name: python-security

steps:
  - name: install
    image: python:3.11-slim
    commands:
      - pip install -r requirements.txt
      - pip install safety bandit

  - name: safety-check
    image: python:3.11-slim
    commands:
      - safety check -r requirements.txt

  - name: bandit-scan
    image: python:3.11-slim
    commands:
      - bandit -r src/ -f json -o bandit-report.json || true

  - name: trivy-scan
    image: aquasec/trivy:latest
    commands:
      - trivy fs --scanners vuln,secret .

  - name: sonar
    image: sonarsource/sonar-scanner-cli:latest
    environment:
      SONAR_HOST_URL: http://sonarqube:9000
      SONAR_TOKEN:
        from_secret: sonar_token
    commands:
      - sonar-scanner
        -Dsonar.projectKey=${DRONE_REPO_NAME}
        -Dsonar.sources=src
        -Dsonar.python.coverage.reportPaths=coverage.xml
```

### .NET Project

```yaml
kind: pipeline
type: docker
name: dotnet-security

steps:
  - name: restore
    image: mcr.microsoft.com/dotnet/sdk:8.0
    commands:
      - dotnet restore

  - name: security-scan
    image: mcr.microsoft.com/dotnet/sdk:8.0
    commands:
      - dotnet list package --vulnerable --include-transitive

  - name: trivy-scan
    image: aquasec/trivy:latest
    commands:
      - trivy fs --scanners vuln,secret .

  - name: sonar
    image: sonarsource/sonar-scanner-cli:latest
    environment:
      SONAR_HOST_URL: http://sonarqube:9000
      SONAR_TOKEN:
        from_secret: sonar_token
    commands:
      - sonar-scanner
        -Dsonar.projectKey=${DRONE_REPO_NAME}
        -Dsonar.sources=.
```

### Go Project

```yaml
kind: pipeline
type: docker
name: go-security

steps:
  - name: gosec
    image: securego/gosec:latest
    commands:
      - gosec -fmt=json -out=gosec-report.json ./... || true

  - name: govulncheck
    image: golang:1.21
    commands:
      - go install golang.org/x/vuln/cmd/govulncheck@latest
      - govulncheck ./...

  - name: trivy-scan
    image: aquasec/trivy:latest
    commands:
      - trivy fs --scanners vuln,secret .

  - name: sonar
    image: sonarsource/sonar-scanner-cli:latest
    environment:
      SONAR_HOST_URL: http://sonarqube:9000
      SONAR_TOKEN:
        from_secret: sonar_token
    commands:
      - sonar-scanner
        -Dsonar.projectKey=${DRONE_REPO_NAME}
        -Dsonar.sources=.
        -Dsonar.go.coverage.reportPaths=coverage.out
```

---

## Setting Up Security Tools

### 1. SonarQube Initial Setup

1. Open http://localhost:9000
2. Login with `admin` / `admin`
3. Change the password when prompted
4. Go to **Administration** → **Security** → **Users**
5. Generate a token for CI/CD:
   - Click your user → **Security** → **Generate Token**
   - Name: `drone-ci`
   - Copy the token

6. Add token to Drone:
   - Go to Drone → Repository → Settings → Secrets
   - Add secret: `sonar_token` = `your-token`

### 2. Dependency-Track Initial Setup

1. Open http://localhost:8082
2. Default login: `admin` / `admin`
3. Change password when prompted
4. Create API key:
   - Go to **Administration** → **Access Management** → **Teams**
   - Click **Automation** team
   - Generate API key
   - Copy the key

5. Add key to Drone:
   - Add secret: `dtrack_api_key` = `your-key`

### 3. Trivy Server

Trivy server is already running and caches the vulnerability database.
Use it in your scans for faster results:

```yaml
- name: scan
  image: aquasec/trivy:latest
  commands:
    - trivy image --server http://trivy-server:4954 my-image:tag
```

---

## Security Policies

### Fail Pipeline on Critical Vulnerabilities

```yaml
- name: security-gate
  image: aquasec/trivy:latest
  commands:
    # Fail on any CRITICAL vulnerability
    - trivy image --exit-code 1 --severity CRITICAL my-image:tag
```

### Fail on High and Critical

```yaml
- name: security-gate
  image: aquasec/trivy:latest
  commands:
    - trivy image --exit-code 1 --severity HIGH,CRITICAL my-image:tag
```

### Allow Known Vulnerabilities (Ignore List)

Create `.trivyignore` in your repo:

```
# Ignore specific CVEs
CVE-2023-12345
CVE-2023-67890

# Ignore by package
pkg:npm/lodash@4.17.20
```

```yaml
- name: scan
  image: aquasec/trivy:latest
  commands:
    - trivy image --ignorefile .trivyignore my-image:tag
```

### SonarQube Quality Gate

```yaml
- name: quality-gate
  image: sonarsource/sonar-scanner-cli:latest
  commands:
    - sonar-scanner ...
    - |
      # Wait for analysis and check quality gate
      sleep 10
      STATUS=$(curl -s -u ${SONAR_TOKEN}: \
        "${SONAR_HOST_URL}/api/qualitygates/project_status?projectKey=${DRONE_REPO_NAME}" \
        | jq -r '.projectStatus.status')
      if [ "$STATUS" != "OK" ]; then
        echo "Quality Gate FAILED!"
        exit 1
      fi
```

---

## Vulnerability Reports

### Generate HTML Report

```yaml
- name: report
  image: aquasec/trivy:latest
  commands:
    - trivy image --format template
      --template "@contrib/html.tpl"
      -o report.html
      my-image:tag
```

### Generate JSON Report

```yaml
- name: report
  image: aquasec/trivy:latest
  commands:
    - trivy image --format json -o report.json my-image:tag
```

### Generate SARIF (GitHub/GitLab Compatible)

```yaml
- name: report
  image: aquasec/trivy:latest
  commands:
    - trivy image --format sarif -o report.sarif my-image:tag
```

---

## Resource Requirements

| Tool | CPU | Memory | Storage |
|------|-----|--------|---------|
| Trivy Server | 0.5 cores | 512 MB | 2 GB (cache) |
| SonarQube | 2 cores | 4 GB | 5 GB |
| Dependency-Track | 2 cores | 4 GB | 2 GB |
| **Total Additional** | **4.5 cores** | **8.5 GB** | **9 GB** |

**Note**: SonarQube requires more memory. If you have limited RAM, you can skip it and use Trivy + Dependency-Track only.

---

## Minimal Security Pipeline (Low Resources)

If you have limited resources, use just Trivy:

```yaml
kind: pipeline
type: docker
name: security-minimal

steps:
  - name: full-scan
    image: aquasec/trivy:latest
    commands:
      # Scan for vulnerabilities, secrets, and misconfigs
      - trivy fs --scanners vuln,secret,misconfig
        --exit-code 1
        --severity HIGH,CRITICAL
        .

  - name: container-scan
    image: aquasec/trivy:latest
    commands:
      - trivy image --server http://trivy-server:4954
        --exit-code 1
        --severity CRITICAL
        my-image:tag
```

This gives you:
- Dependency vulnerability scanning
- Secret detection
- Infrastructure as Code scanning
- Container image scanning

All with minimal resource usage!

---

## Advanced Features

### Compliance Reporting

Check compliance status against industry frameworks:

```yaml
steps:
  - name: compliance-check
    image: node:20-alpine
    commands:
      # Using the CICD Agent
      - npx cicd-agent compliance_check_status \
          --image my-image:tag \
          --frameworks SOC2,PCI-DSS
```

Or generate HTML reports for audits:

```yaml
  - name: compliance-report
    image: node:20-alpine
    commands:
      - npx cicd-agent compliance_generate_report \
          --image my-image:tag \
          --format html \
          --title "Release Compliance Report"
```

### OPA/Rego Policy Enforcement

Enforce custom security policies:

```yaml
steps:
  - name: policy-gate
    image: node:20-alpine
    commands:
      # Block builds with critical vulnerabilities
      - npx cicd-agent opa_evaluate_policy \
          --image my-image:tag \
          --policy vulnerability-threshold \
          --thresholds.critical 0 \
          --thresholds.high 5
```

Available built-in policies:
- `vulnerability-threshold` - Enforce vuln count limits
- `license-compliance` - Block forbidden licenses
- `secrets-detection` - Zero tolerance for secrets
- `container-security` - Container best practices
- `quality-gate` - Code quality requirements

### Scheduled Security Scans

Set up automated nightly scans:

```yaml
# Using MCP tools or CICD Agent
scheduler_create_job:
  name: "nightly-prod-scan"
  cron: "@daily"
  target:
    type: image
    value: production:latest
  notifications:
    webhooks:
      - url: https://hooks.slack.com/services/xxx
        type: slack
        onFailure: true
```

### Offline Scanning (Air-Gapped Environments)

For environments without internet access:

```yaml
# Step 1: Sync database (on connected machine)
steps:
  - name: sync-vuln-db
    image: node:20-alpine
    commands:
      - npx cicd-agent vuln_db_sync

# Step 2: Scan offline (no internet required)
  - name: offline-scan
    image: node:20-alpine
    commands:
      - npx cicd-agent trivy_scan_offline \
          --image my-image:tag \
          --ignoreUnfixed true
```

---

## MCP and Agent Tool Integration

All scanning capabilities are available through two interfaces:

### MCP Server (Claude Integration)

Configure in Claude Desktop or Cline:

```json
{
  "mcpServers": {
    "cicd-security": {
      "command": "node",
      "args": ["path/to/mcp-server/dist/index.js"]
    }
  }
}
```

### CICD Agent (CLI/CI Integration)

Use in pipelines or command line:

```bash
# Install
npm install -g @cicd/agent

# Configure
export CICD_TRIVY_URL=http://localhost:4954
export CICD_SONARQUBE_URL=http://localhost:9000

# Run scans
cicd-agent trivy_scan_image --image nginx:latest
cicd-agent compliance_check_status --image nginx:latest --frameworks SOC2
```

### Full Tool Reference

See the [Cheat Sheet](docs/CHEAT-SHEET.md) for all 25 security tools.
