# CI/CD Security Scanner - GitHub Action

Comprehensive security scanning for containers, code, and dependencies using Trivy. Integrates with GitHub Code Scanning (SARIF), PR comments, and badge generation.

## Features

- **Vulnerability Scanning**: Scan code, dependencies, and container images
- **SARIF Upload**: Automatic upload to GitHub Code Scanning
- **PR Comments**: Summary comments on pull requests
- **Badge Generation**: Dynamic security status badges
- **Configurable Thresholds**: Fail builds based on severity levels
- **Suppression Support**: Ignore known vulnerabilities

## Quick Start

```yaml
- name: Security Scan
  uses: your-org/cicd-security-scanner@v1
  with:
    scan-type: path
    severity: 'CRITICAL,HIGH'
    fail-on: 'CRITICAL'
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Inputs

### Scan Configuration

| Input | Description | Default |
|-------|-------------|---------|
| `scan-type` | Type of scan: `image`, `path`, or `both` | `path` |
| `image` | Docker image to scan (for image scans) | - |
| `path` | Path to scan (for path scans) | `.` |
| `severity` | Severity levels to report (comma-separated) | `CRITICAL,HIGH` |
| `fail-on` | Fail if vulnerabilities of this severity or higher are found | `CRITICAL` |

### Output Configuration

| Input | Description | Default |
|-------|-------------|---------|
| `output-format` | Output format: `json`, `sarif`, `table`, `markdown` | `sarif` |
| `output-file` | File path to write scan results | `security-results.sarif` |

### GitHub Integration

| Input | Description | Default |
|-------|-------------|---------|
| `upload-sarif` | Upload SARIF to GitHub Code Scanning | `true` |
| `sarif-category` | Category for SARIF upload | `security-scan` |
| `comment-on-pr` | Post scan summary as PR comment | `true` |
| `comment-title` | Title for PR comment | `Security Scan Results` |
| `github-token` | GitHub token for API access | `${{ github.token }}` |

### Badge Generation

| Input | Description | Default |
|-------|-------------|---------|
| `generate-badge` | Generate a security status badge | `false` |
| `badge-path` | Path to save the badge SVG | `.github/badges/security.svg` |

### Advanced Options

| Input | Description | Default |
|-------|-------------|---------|
| `ignore-unfixed` | Ignore vulnerabilities without fixes | `false` |
| `skip-dirs` | Directories to skip (comma-separated) | - |
| `skip-files` | Files to skip (comma-separated) | - |
| `trivy-config` | Path to Trivy configuration file | - |
| `policy-file` | Path to security policy file | - |
| `suppression-file` | Path to suppression file | - |

### Registry Authentication

| Input | Description | Default |
|-------|-------------|---------|
| `registry-username` | Container registry username | - |
| `registry-password` | Container registry password | - |

## Outputs

| Output | Description |
|--------|-------------|
| `vulnerabilities-count` | Total number of vulnerabilities found |
| `critical-count` | Number of CRITICAL vulnerabilities |
| `high-count` | Number of HIGH vulnerabilities |
| `medium-count` | Number of MEDIUM vulnerabilities |
| `low-count` | Number of LOW vulnerabilities |
| `sarif-file` | Path to the SARIF output file |
| `scan-passed` | Whether the scan passed based on fail-on threshold |
| `badge-url` | URL to the generated badge (if enabled) |
| `summary` | JSON summary of scan results |

## Examples

### Basic Path Scan

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run security scan
        uses: your-org/cicd-security-scanner@v1
        with:
          scan-type: path
          severity: 'CRITICAL,HIGH,MEDIUM'
          fail-on: 'HIGH'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Container Image Scan

```yaml
name: Container Security
on:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Scan container
        uses: your-org/cicd-security-scanner@v1
        with:
          scan-type: image
          image: 'myapp:${{ github.sha }}'
          severity: 'CRITICAL,HIGH'
          fail-on: 'CRITICAL'
          upload-sarif: 'true'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### With Badge Generation

```yaml
- name: Security scan with badge
  uses: your-org/cicd-security-scanner@v1
  with:
    scan-type: path
    generate-badge: 'true'
    badge-path: '.github/badges/security.svg'
    github-token: ${{ secrets.GITHUB_TOKEN }}

- name: Commit badge
  if: github.ref == 'refs/heads/main'
  run: |
    git config user.name github-actions
    git config user.email github-actions@github.com
    git add .github/badges/security.svg
    git commit -m "Update security badge" || true
    git push
```

### With Suppression File

Create `.security-suppressions.yml`:

```yaml
suppressions:
  - type: cve
    id: CVE-2023-12345
    reason: "False positive - not exploitable in our configuration"
    expires: "2024-12-31"

  - type: package
    name: lodash
    version: "<4.17.21"
    reason: "Upgrading in next sprint"
```

```yaml
- name: Scan with suppressions
  uses: your-org/cicd-security-scanner@v1
  with:
    scan-type: path
    suppression-file: '.security-suppressions.yml'
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Matrix Strategy for Multiple Targets

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - name: Code
            type: path
            target: '.'
          - name: Frontend
            type: path
            target: './frontend'
          - name: Backend
            type: path
            target: './backend'

    steps:
      - uses: actions/checkout@v4

      - name: Scan ${{ matrix.name }}
        uses: your-org/cicd-security-scanner@v1
        with:
          scan-type: ${{ matrix.type }}
          path: ${{ matrix.target }}
          sarif-category: ${{ matrix.name }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## PR Comment Example

When scanning a pull request, the action posts a comment like:

---

## Security Scan Results

✅ **Status: Passed**

### Vulnerability Summary

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 Critical | 0 | ✅ |
| 🟠 High | 2 | ⚠️ |
| 🟡 Medium | 5 | ⚠️ |
| 🟢 Low | 12 | ℹ️ |
| **Total** | **19** | |

---

## Permissions

The action requires these permissions:

```yaml
permissions:
  contents: read          # Read repository contents
  security-events: write  # Upload SARIF
  pull-requests: write    # Post PR comments
```

## Troubleshooting

### SARIF upload fails

Ensure the `security-events: write` permission is set and you're using a valid GitHub token.

### Container scan authentication errors

For private registries, provide credentials:

```yaml
with:
  registry-username: ${{ secrets.REGISTRY_USER }}
  registry-password: ${{ secrets.REGISTRY_PASSWORD }}
```

### Scan times out

For large repositories, consider:
- Using `skip-dirs` to exclude large directories
- Running scans on specific paths
- Increasing the job timeout

## License

MIT License - See [LICENSE](../../../LICENSE) for details.
