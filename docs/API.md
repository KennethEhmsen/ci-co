# API Reference

This document provides a complete reference for all tools and handlers available in the CI/CD Security Platform.

**Version:** 1.22.0 | **Total Tools:** 82

## Table of Contents

- [Overview](#overview)
- [MCP Server Tools](#mcp-server-tools)
  - [Trivy Tools](#trivy-tools)
  - [SonarQube Tools](#sonarqube-tools)
  - [Dependency-Track Tools](#dependency-track-tools)
  - [Gitea Tools](#gitea-tools)
  - [Drone CI Tools](#drone-ci-tools)
  - [Docker Registry Tools](#docker-registry-tools)
  - [Security Dashboard Tools](#security-dashboard-tools)
  - [SARIF Reporting Tools](#sarif-reporting-tools)
  - [Scheduler Tools](#scheduler-tools)
  - [Remediation Tools](#remediation-tools)
  - [Compliance Tools](#compliance-tools)
  - [OPA/Rego Policy Tools](#oparego-policy-tools)
  - [Vulnerability Database Tools](#vulnerability-database-tools)
  - [Cache Tools](#cache-tools)
- [MCP Resources](#mcp-resources)
- [Handler Functions](#handler-functions)
- [Configuration](#configuration)
- [Error Handling](#error-handling)

---

## Overview

The CI/CD Security Platform provides **82 tools** for security scanning, compliance reporting, and DevOps automation. These tools are available through:

1. **MCP Server** - For Claude Code integration via Model Context Protocol
2. **CI/CD Agent** - Standalone CLI with Anthropic SDK integration

All tools share the same underlying handlers from the `@cicd/shared` package.

### Tool Summary by Category

| Category | Tools | Description |
|----------|-------|-------------|
| **Trivy** | 11 | Vulnerability, secret, license, IaC scanning + SBOM |
| **SonarQube** | 4 | Code quality, SAST analysis, security hotspots |
| **Dependency-Track** | 5 | Software composition analysis + SBOM upload |
| **Gitea** | 6 | Git repos, branches, commits |
| **Drone CI** | 5 | CI/CD pipeline management |
| **Container Registry** | 10 | Multi-cloud registry scanning (ECR, ACR, GCR, GHCR) |
| **Security Dashboard** | 2 | Unified security aggregation |
| **SARIF Reporting** | 2 | GitHub Code Scanning integration |
| **Scheduler** | 9 | Cron-based automated security scans |
| **Remediation** | 5 | Fix generation and prioritization |
| **Compliance** | 7 | SOC2, HIPAA, PCI-DSS, CIS frameworks |
| **OPA/Rego Policy** | 4 | Declarative policy enforcement |
| **Vulnerability Database** | 6 | Offline scanning and CVE management |
| **Cache** | 6 | Redis/memory distributed caching |
| **Total** | **82** | |

---

## MCP Server Tools

### Trivy Tools

> **Note:** Image-based scans (`trivy_scan_image`, `trivy_generate_sbom_image`, `trivy_scan_secrets_image`, `trivy_scan_licenses_image`) use the Trivy server API for faster scanning and centralized vulnerability database management. Path-based scans use local Docker execution.

#### `trivy_scan_path`

Scan a local file path for vulnerabilities using Trivy.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Absolute path to the directory to scan"
    },
    "severity": {
      "type": "string",
      "description": "Severity levels: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL (default: HIGH,CRITICAL)"
    }
  },
  "required": ["path"]
}
```

**Example:**
```json
{
  "path": "/home/user/myproject",
  "severity": "MEDIUM,HIGH,CRITICAL"
}
```

**Response:** Trivy JSON report with vulnerabilities and secrets found.

---

#### `trivy_scan_image`

Scan a Docker image for vulnerabilities using Trivy server API.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": {
      "type": "string",
      "description": "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)"
    },
    "severity": {
      "type": "string",
      "description": "Severity levels to report (default: HIGH,CRITICAL)"
    }
  },
  "required": ["image"]
}
```

**Example:**
```json
{
  "image": "nginx:1.25",
  "severity": "HIGH,CRITICAL"
}
```

---

#### `trivy_generate_sbom`

Generate a Software Bill of Materials (SBOM) for a local path using Trivy.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Absolute path to the directory to scan"
    },
    "format": {
      "type": "string",
      "description": "SBOM format: cyclonedx (default) or spdx-json",
      "enum": ["cyclonedx", "spdx-json"]
    }
  },
  "required": ["path"]
}
```

---

#### `trivy_generate_sbom_image`

Generate a Software Bill of Materials (SBOM) for a Docker image using Trivy server API.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": {
      "type": "string",
      "description": "Docker image to scan"
    },
    "format": {
      "type": "string",
      "description": "SBOM format: cyclonedx (default) or spdx-json",
      "enum": ["cyclonedx", "spdx-json"]
    }
  },
  "required": ["image"]
}
```

---

#### `trivy_scan_iac`

Scan Infrastructure as Code (IaC) files for misconfigurations. Supports Terraform, Kubernetes, Docker, CloudFormation, and more.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Absolute path to the directory containing IaC files"
    },
    "severity": {
      "type": "string",
      "description": "Severity levels to report (default: MEDIUM,HIGH,CRITICAL)"
    }
  },
  "required": ["path"]
}
```

---

#### `trivy_scan_secrets`

Scan a local path for hardcoded secrets (API keys, passwords, tokens, private keys).

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Absolute path to the directory to scan"
    },
    "severity": {
      "type": "string",
      "description": "Severity levels to report (default: MEDIUM,HIGH,CRITICAL)"
    }
  },
  "required": ["path"]
}
```

---

#### `trivy_scan_secrets_image`

Scan a Docker image for hardcoded secrets using Trivy server API.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": {
      "type": "string",
      "description": "Docker image to scan"
    },
    "severity": {
      "type": "string",
      "description": "Severity levels to report (default: MEDIUM,HIGH,CRITICAL)"
    }
  },
  "required": ["image"]
}
```

---

#### `trivy_scan_licenses`

Scan a local path for license information. Detects licenses in dependencies and flags problematic licenses.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Absolute path to the directory to scan"
    },
    "severity": {
      "type": "string",
      "description": "Severity levels to report (default: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL)"
    }
  },
  "required": ["path"]
}
```

---

#### `trivy_scan_licenses_image`

Scan a Docker image for license information using Trivy server API.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": {
      "type": "string",
      "description": "Docker image to scan"
    },
    "severity": {
      "type": "string",
      "description": "Severity levels to report (default: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL)"
    }
  },
  "required": ["image"]
}
```

---

#### `trivy_scan_image_full`

Run a comprehensive security scan on a Docker image. Combines vulnerability, secret, license scanning, and SBOM generation in one operation.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": {
      "type": "string",
      "description": "Docker image to scan"
    },
    "severity": {
      "type": "string",
      "description": "Severity levels to report (default: HIGH,CRITICAL)"
    },
    "sbomFormat": {
      "type": "string",
      "description": "SBOM format: cyclonedx (default) or spdx-json",
      "enum": ["cyclonedx", "spdx-json"]
    }
  },
  "required": ["image"]
}
```

**Response:**
```json
{
  "image": "nginx:1.25",
  "timestamp": "2024-12-25T12:00:00.000Z",
  "vulnerabilities": { "Results": [...] },
  "secrets": { "Results": [...] },
  "licenses": { "Results": [...] },
  "sbom": { "bomFormat": "CycloneDX", "components": [...] }
}
```

---

#### `trivy_scan_path_full`

Run a comprehensive security scan on a local path. Combines vulnerability, secret, license, IaC scanning, and SBOM generation in one operation.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Absolute path to the directory to scan"
    },
    "severity": {
      "type": "string",
      "description": "Severity levels to report (default: HIGH,CRITICAL)"
    },
    "sbomFormat": {
      "type": "string",
      "description": "SBOM format: cyclonedx (default) or spdx-json",
      "enum": ["cyclonedx", "spdx-json"]
    }
  },
  "required": ["path"]
}
```

**Response:**
```json
{
  "path": "/home/user/project",
  "timestamp": "2024-12-25T12:00:00.000Z",
  "vulnerabilities": { "Results": [...] },
  "secrets": { "Results": [...] },
  "licenses": { "Results": [...] },
  "iac": { "Results": [...] },
  "sbom": { "bomFormat": "CycloneDX", "components": [...] }
}
```

---

### SonarQube Tools

#### `sonar_list_projects`

List all projects analyzed in SonarQube.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

**Response:**
```json
{
  "paging": {
    "pageIndex": 1,
    "pageSize": 100,
    "total": 2
  },
  "components": [
    {
      "key": "my-project",
      "name": "My Project",
      "qualifier": "TRK",
      "visibility": "public",
      "lastAnalysisDate": "2024-12-20T10:30:00+0000"
    }
  ]
}
```

---

#### `sonar_get_issues`

Get code issues (bugs, vulnerabilities, code smells) for a SonarQube project.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "projectKey": {
      "type": "string",
      "description": "The SonarQube project key"
    },
    "types": {
      "type": "string",
      "description": "Issue types: VULNERABILITY, BUG, CODE_SMELL (comma-separated)"
    }
  },
  "required": ["projectKey"]
}
```

**Example:**
```json
{
  "projectKey": "my-project",
  "types": "VULNERABILITY,BUG"
}
```

---

#### `sonar_get_security_hotspots`

Get security hotspots (potential security issues requiring review) for a project.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "projectKey": {
      "type": "string",
      "description": "The SonarQube project key"
    }
  },
  "required": ["projectKey"]
}
```

---

#### `sonar_get_metrics`

Get quality metrics for a project.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "projectKey": {
      "type": "string",
      "description": "The SonarQube project key"
    }
  },
  "required": ["projectKey"]
}
```

**Response includes:** bugs, vulnerabilities, security_hotspots, code_smells, coverage, duplicated_lines_density

---

#### `sonar_get_quality_gate_status`

Get the quality gate status for a SonarQube project. Returns whether the project passes or fails the configured quality gate.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "projectKey": {
      "type": "string",
      "description": "The SonarQube project key"
    }
  },
  "required": ["projectKey"]
}
```

**Response:**
```json
{
  "projectStatus": {
    "status": "OK",
    "conditions": [
      {
        "status": "OK",
        "metricKey": "new_reliability_rating",
        "comparator": "GT",
        "errorThreshold": "1",
        "actualValue": "1"
      }
    ]
  }
}
```

**Status values:** `OK` (passed), `ERROR` (failed), `WARN` (warning)

---

### Dependency-Track Tools

#### `dtrack_list_projects`

List all projects in Dependency-Track with their vulnerability counts.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

**Response:**
```json
[
  {
    "uuid": "a1b2c3d4-...",
    "name": "my-application",
    "version": "1.0.0",
    "lastBomImport": "2024-12-20T10:00:00Z",
    "metrics": {
      "critical": 0,
      "high": 2,
      "medium": 5,
      "low": 10,
      "unassigned": 0,
      "vulnerabilities": 17
    }
  }
]
```

---

#### `dtrack_get_vulnerabilities`

Get all vulnerabilities affecting a Dependency-Track project.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "projectUuid": {
      "type": "string",
      "description": "The project UUID (get from dtrack_list_projects)"
    }
  },
  "required": ["projectUuid"]
}
```

---

#### `dtrack_get_findings`

Get detailed security findings for a project including component and vulnerability info.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "projectUuid": {
      "type": "string",
      "description": "The project UUID"
    }
  },
  "required": ["projectUuid"]
}
```

---

#### `dtrack_get_components`

Get all components (dependencies) for a project with their details.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "projectUuid": {
      "type": "string",
      "description": "The project UUID"
    }
  },
  "required": ["projectUuid"]
}
```

---

#### `dtrack_upload_sbom`

Upload a Software Bill of Materials (SBOM) to Dependency-Track for analysis.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "projectName": {
      "type": "string",
      "description": "Name of the project in Dependency-Track"
    },
    "projectVersion": {
      "type": "string",
      "description": "Version of the project"
    },
    "sbom": {
      "type": "string",
      "description": "SBOM content as a JSON string (CycloneDX or SPDX format)"
    },
    "autoCreate": {
      "type": "boolean",
      "description": "Auto-create the project if it doesn't exist (default: true)"
    }
  },
  "required": ["projectName", "projectVersion", "sbom"]
}
```

**Example:**
```json
{
  "projectName": "my-application",
  "projectVersion": "1.0.0",
  "sbom": "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.4\",...}",
  "autoCreate": true
}
```

**Response:**
```json
{
  "token": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

The token can be used to check the processing status of the uploaded SBOM.

---

### Gitea Tools

#### `gitea_list_repos`

List all Git repositories in Gitea for the current user.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

**Response:**
```json
[
  {
    "id": 1,
    "name": "my-repo",
    "full_name": "localadmin/my-repo",
    "description": "My repository",
    "html_url": "http://localhost:3000/localadmin/my-repo",
    "clone_url": "http://localhost:3000/localadmin/my-repo.git",
    "default_branch": "main",
    "private": false,
    "stars_count": 0,
    "forks_count": 0
  }
]
```

---

#### `gitea_get_repo`

Get detailed information about a specific repository.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "owner": {
      "type": "string",
      "description": "Repository owner username"
    },
    "repo": {
      "type": "string",
      "description": "Repository name"
    }
  },
  "required": ["owner", "repo"]
}
```

---

#### `gitea_get_branches`

List all branches in a repository.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "owner": { "type": "string", "description": "Repository owner" },
    "repo": { "type": "string", "description": "Repository name" }
  },
  "required": ["owner", "repo"]
}
```

---

#### `gitea_get_commits`

Get recent commits for a repository.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "owner": { "type": "string", "description": "Repository owner" },
    "repo": { "type": "string", "description": "Repository name" },
    "limit": {
      "type": "number",
      "description": "Number of commits to retrieve (default: 10)"
    }
  },
  "required": ["owner", "repo"]
}
```

---

#### `gitea_create_repo`

Create a new Git repository in Gitea.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "name": { "type": "string", "description": "Repository name" },
    "description": { "type": "string", "description": "Repository description" },
    "private": {
      "type": "boolean",
      "description": "Whether the repository is private (default: false)"
    }
  },
  "required": ["name"]
}
```

---

#### `gitea_migrate_repo`

Migrate a repository from GitHub to Gitea (preserves issues, PRs, releases).

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "cloneUrl": {
      "type": "string",
      "description": "GitHub clone URL (e.g., https://github.com/user/repo.git)"
    },
    "repoName": {
      "type": "string",
      "description": "Name for the new repository in Gitea"
    },
    "authToken": {
      "type": "string",
      "description": "GitHub personal access token (required for private repos)"
    }
  },
  "required": ["cloneUrl", "repoName"]
}
```

---

#### `gitea_list_pull_requests`

List pull requests in a Gitea repository with optional state filtering.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "owner": {
      "type": "string",
      "description": "Repository owner username"
    },
    "repo": {
      "type": "string",
      "description": "Repository name"
    },
    "state": {
      "type": "string",
      "description": "Filter by state: open, closed, or all (default: open)",
      "enum": ["open", "closed", "all"]
    }
  },
  "required": ["owner", "repo"]
}
```

**Response:**
```json
[
  {
    "id": 1,
    "number": 42,
    "title": "Add new feature",
    "body": "This PR adds...",
    "state": "open",
    "user": { "login": "developer" },
    "created_at": "2024-12-20T10:00:00Z",
    "merged": false,
    "mergeable": true,
    "html_url": "http://localhost:3000/owner/repo/pulls/42",
    "head": { "ref": "feature-branch" },
    "base": { "ref": "main" }
  }
]
```

---

#### `gitea_get_pull_request`

Get detailed information about a specific pull request.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "owner": {
      "type": "string",
      "description": "Repository owner username"
    },
    "repo": {
      "type": "string",
      "description": "Repository name"
    },
    "pullNumber": {
      "type": "number",
      "description": "Pull request number"
    }
  },
  "required": ["owner", "repo", "pullNumber"]
}
```

---

#### `gitea_create_pull_request`

Create a new pull request in a Gitea repository.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "owner": {
      "type": "string",
      "description": "Repository owner username"
    },
    "repo": {
      "type": "string",
      "description": "Repository name"
    },
    "title": {
      "type": "string",
      "description": "Pull request title"
    },
    "head": {
      "type": "string",
      "description": "Source branch name"
    },
    "base": {
      "type": "string",
      "description": "Target branch name (e.g., main)"
    },
    "body": {
      "type": "string",
      "description": "Pull request description (optional)"
    }
  },
  "required": ["owner", "repo", "title", "head", "base"]
}
```

**Example:**
```json
{
  "owner": "localadmin",
  "repo": "my-project",
  "title": "Add user authentication",
  "head": "feature/auth",
  "base": "main",
  "body": "This PR implements user login and registration."
}
```

---

#### `gitea_merge_pull_request`

Merge an open pull request using the specified merge strategy.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "owner": {
      "type": "string",
      "description": "Repository owner username"
    },
    "repo": {
      "type": "string",
      "description": "Repository name"
    },
    "pullNumber": {
      "type": "number",
      "description": "Pull request number to merge"
    },
    "mergeStyle": {
      "type": "string",
      "description": "Merge strategy: merge, rebase, or squash (default: merge)",
      "enum": ["merge", "rebase", "squash"]
    }
  },
  "required": ["owner", "repo", "pullNumber"]
}
```

**Response:**
```json
{
  "merged": true
}
```

---

#### `gitea_create_issue`

Create a new issue in a Gitea repository.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "owner": {
      "type": "string",
      "description": "Repository owner username"
    },
    "repo": {
      "type": "string",
      "description": "Repository name"
    },
    "title": {
      "type": "string",
      "description": "Issue title"
    },
    "body": {
      "type": "string",
      "description": "Issue description (optional)"
    },
    "labels": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Labels to apply (optional)"
    }
  },
  "required": ["owner", "repo", "title"]
}
```

**Example:**
```json
{
  "owner": "localadmin",
  "repo": "my-project",
  "title": "Bug: Login fails on mobile",
  "body": "Steps to reproduce:\n1. Open app on mobile\n2. Try to login\n3. Error appears",
  "labels": ["bug", "mobile"]
}
```

**Response:**
```json
{
  "id": 1,
  "number": 15,
  "title": "Bug: Login fails on mobile",
  "body": "Steps to reproduce...",
  "state": "open",
  "html_url": "http://localhost:3000/owner/repo/issues/15",
  "created_at": "2024-12-20T10:00:00Z",
  "user": { "login": "localadmin" }
}
```

---

#### `gitea_list_issues`

List issues in a Gitea repository with optional state filtering.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "owner": {
      "type": "string",
      "description": "Repository owner username"
    },
    "repo": {
      "type": "string",
      "description": "Repository name"
    },
    "state": {
      "type": "string",
      "description": "Filter by state: open, closed, or all (default: open)",
      "enum": ["open", "closed", "all"]
    }
  },
  "required": ["owner", "repo"]
}
```

---

### Drone CI Tools

#### `drone_list_repos`

List all repositories synced with Drone CI.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

---

#### `drone_get_builds`

Get build history for a repository.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "owner": { "type": "string", "description": "Repository owner" },
    "repo": { "type": "string", "description": "Repository name" }
  },
  "required": ["owner", "repo"]
}
```

**Response:**
```json
[
  {
    "id": 1,
    "number": 1,
    "status": "success",
    "event": "push",
    "message": "Initial commit",
    "ref": "refs/heads/main",
    "author_login": "localadmin",
    "created": 1703070000,
    "started": 1703070001,
    "finished": 1703070060
  }
]
```

---

#### `drone_get_build`

Get detailed information about a specific build.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "owner": { "type": "string", "description": "Repository owner" },
    "repo": { "type": "string", "description": "Repository name" },
    "build": { "type": "number", "description": "Build number" }
  },
  "required": ["owner", "repo", "build"]
}
```

---

#### `drone_get_build_logs`

Get logs for a specific build step.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "owner": { "type": "string", "description": "Repository owner" },
    "repo": { "type": "string", "description": "Repository name" },
    "build": { "type": "number", "description": "Build number" },
    "stage": { "type": "number", "description": "Stage number (default: 1)" },
    "step": { "type": "number", "description": "Step number (default: 1)" }
  },
  "required": ["owner", "repo", "build"]
}
```

---

#### `drone_trigger_build`

Trigger a new CI/CD build for a repository.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "owner": { "type": "string", "description": "Repository owner" },
    "repo": { "type": "string", "description": "Repository name" },
    "branch": {
      "type": "string",
      "description": "Branch to build (default: main)"
    }
  },
  "required": ["owner", "repo"]
}
```

> **Note:** Requires `DRONE_TOKEN` environment variable to be set.

---

### Docker Registry Tools

#### `registry_list_images`

List all images in the local Docker registry.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

**Response:**
```json
{
  "repositories": ["myapp", "nginx-custom", "api-server"]
}
```

---

#### `registry_get_tags`

Get all tags for an image in the registry.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": { "type": "string", "description": "Image name" }
  },
  "required": ["image"]
}
```

**Response:**
```json
{
  "name": "myapp",
  "tags": ["latest", "v1.0.0", "v1.1.0"]
}
```

---

### Platform Tools

#### `check_platform_status`

Check the health status of all CI/CD platform services.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

**Response:**
```json
{
  "timestamp": "2024-12-20T12:00:00.000Z",
  "services": {
    "gitea": { "status": "healthy", "statusCode": 200 },
    "drone": { "status": "healthy", "statusCode": 200 },
    "sonarqube": { "status": "healthy", "statusCode": 200 },
    "dependencyTrack": { "status": "healthy", "statusCode": 200 },
    "trivy": { "status": "healthy", "statusCode": 200 },
    "registry": { "status": "healthy", "statusCode": 200 }
  }
}
```

---

### Security Dashboard Tools

#### `security_scan_all`

Run comprehensive security scan using all available tools.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": { "type": "string", "description": "Docker image to scan" },
    "sonarProject": { "type": "string", "description": "SonarQube project key" }
  }
}
```

---

#### `get_security_dashboard`

Get unified security dashboard aggregating all security sources.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": { "type": "string", "description": "Docker image to scan" },
    "sonarProject": { "type": "string", "description": "SonarQube project key" },
    "severity": { "type": "string", "description": "Severity filter (default: HIGH,CRITICAL)" }
  }
}
```

---

### SARIF Reporting Tools

#### `sarif_generate`

Generate SARIF 2.1.0 report from scan results.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": { "type": "string", "description": "Docker image to scan" },
    "sources": { "type": "array", "items": { "type": "string" }, "description": "Sources: trivy, sonarqube, dtrack" },
    "outputPath": { "type": "string", "description": "Output file path" }
  }
}
```

---

#### `sarif_upload_github`

Upload SARIF report to GitHub Code Scanning.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "sarifPath": { "type": "string", "description": "Path to SARIF file" },
    "owner": { "type": "string", "description": "GitHub repo owner" },
    "repo": { "type": "string", "description": "GitHub repo name" },
    "ref": { "type": "string", "description": "Git ref (e.g., refs/heads/main)" },
    "commitSha": { "type": "string", "description": "Commit SHA" },
    "token": { "type": "string", "description": "GitHub token" }
  },
  "required": ["sarifPath", "owner", "repo", "ref", "commitSha", "token"]
}
```

---

### Scheduler Tools

#### `schedule_create`

Create a scheduled security scan job.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "name": { "type": "string", "description": "Job name" },
    "cron": { "type": "string", "description": "Cron expression or alias (@daily, @weekly)" },
    "target": {
      "type": "object",
      "properties": {
        "type": { "type": "string", "enum": ["image", "path", "registry"] },
        "value": { "type": "string" },
        "severity": { "type": "string" }
      }
    },
    "enabled": { "type": "boolean" },
    "notifications": { "type": "object" }
  },
  "required": ["name", "cron", "target"]
}
```

---

#### `schedule_list`

List all scheduled scan jobs.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "enabled": { "type": "boolean", "description": "Filter by enabled status" }
  }
}
```

---

#### `schedule_get`

Get schedule details by ID.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "id": { "type": "string", "description": "Schedule ID" }
  },
  "required": ["id"]
}
```

---

#### `schedule_update`

Update schedule configuration.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "id": { "type": "string", "description": "Schedule ID" },
    "cron": { "type": "string" },
    "enabled": { "type": "boolean" }
  },
  "required": ["id"]
}
```

---

#### `schedule_delete`

Delete a scheduled job.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "id": { "type": "string", "description": "Schedule ID" }
  },
  "required": ["id"]
}
```

---

#### `schedule_trigger`

Manually trigger a scheduled scan.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "id": { "type": "string", "description": "Schedule ID" }
  },
  "required": ["id"]
}
```

---

#### `schedule_history`

Get execution history for a schedule.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "id": { "type": "string", "description": "Schedule ID" },
    "limit": { "type": "number", "description": "Max results (default: 10)" }
  },
  "required": ["id"]
}
```

---

#### `cron_validate`

Validate a cron expression.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "expression": { "type": "string", "description": "Cron expression to validate" }
  },
  "required": ["expression"]
}
```

---

#### `scheduler_control`

Start or stop the scheduler engine.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "action": { "type": "string", "enum": ["start", "stop", "status"] }
  },
  "required": ["action"]
}
```

---

### Remediation Tools

#### `generate_remediations`

Generate fix commands for vulnerabilities.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": { "type": "string", "description": "Docker image to analyze" }
  },
  "required": ["image"]
}
```

---

#### `get_remediation_summary`

Get text summary of remediations.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": { "type": "string", "description": "Docker image to analyze" }
  },
  "required": ["image"]
}
```

---

#### `get_remediation_markdown`

Get Markdown-formatted remediation report.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": { "type": "string", "description": "Docker image to analyze" }
  },
  "required": ["image"]
}
```

---

#### `get_high_priority_fixes`

Get CRITICAL and HIGH severity fixes only.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": { "type": "string", "description": "Docker image to analyze" }
  },
  "required": ["image"]
}
```

---

#### `get_safe_fixes`

Get non-breaking upgrades only.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": { "type": "string", "description": "Docker image to analyze" },
    "excludeBreaking": { "type": "boolean", "description": "Exclude breaking changes" }
  },
  "required": ["image"]
}
```

---

### Compliance Tools

#### `compliance_get_frameworks`

List available compliance frameworks.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

**Response:** SOC2, HIPAA, PCI-DSS, CIS frameworks with control counts.

---

#### `compliance_get_controls`

Get controls for a specific framework.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "framework": { "type": "string", "description": "Framework ID (SOC2, HIPAA, PCI-DSS, CIS)" },
    "controlId": { "type": "string", "description": "Optional specific control ID" }
  },
  "required": ["framework"]
}
```

---

#### `compliance_check_status`

Check compliance pass/fail status.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": { "type": "string", "description": "Docker image to scan" },
    "frameworks": { "type": "array", "items": { "type": "string" } },
    "severity": { "type": "string" }
  },
  "required": ["image", "frameworks"]
}
```

---

#### `compliance_generate_report`

Generate compliance report in JSON or HTML.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": { "type": "string", "description": "Docker image to scan" },
    "frameworks": { "type": "array", "items": { "type": "string" } },
    "format": { "type": "string", "enum": ["json", "html"] },
    "title": { "type": "string" },
    "organization": { "type": "string" }
  },
  "required": ["image", "frameworks"]
}
```

---

#### `compliance_trend_record`

Record compliance snapshot for trend tracking.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "target": { "type": "string", "description": "Target identifier" },
    "image": { "type": "string", "description": "Docker image" },
    "frameworks": { "type": "array", "items": { "type": "string" } }
  },
  "required": ["target", "image"]
}
```

---

#### `compliance_trend_get`

Get compliance trends over time.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "target": { "type": "string", "description": "Target identifier" },
    "days": { "type": "number", "description": "Number of days (default: 30)" }
  },
  "required": ["target"]
}
```

---

#### `compliance_trend_list_targets`

List all targets with trend data.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

---

### OPA/Rego Policy Tools

#### `opa_list_policies`

List all built-in OPA/Rego policies.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

**Response:** vulnerability-threshold, license-compliance, secrets-detection, container-security, quality-gate

---

#### `opa_get_policy_info`

Get policy details and Rego source code.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "name": { "type": "string", "description": "Policy name" }
  },
  "required": ["name"]
}
```

---

#### `opa_validate_policy`

Validate Rego policy syntax.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "policy": { "type": "string", "description": "Rego policy source code" }
  },
  "required": ["policy"]
}
```

---

#### `opa_evaluate_policy`

Evaluate scan results against a policy.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": { "type": "string", "description": "Docker image to scan" },
    "policy": { "type": "string", "description": "Policy name or inline Rego" },
    "thresholds": {
      "type": "object",
      "properties": {
        "critical": { "type": "number" },
        "high": { "type": "number" },
        "medium": { "type": "number" }
      }
    }
  },
  "required": ["image", "policy"]
}
```

---

### Vulnerability Database Tools

#### `vuln_db_sync`

Download/update the vulnerability database.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "force": { "type": "boolean", "description": "Force sync regardless of age" },
    "skipIfRecent": { "type": "number", "description": "Skip if synced within N hours" }
  }
}
```

---

#### `vuln_db_status`

Get database status and statistics.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

---

#### `vuln_db_lookup`

Look up a vulnerability by CVE ID.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "id": { "type": "string", "description": "CVE ID (e.g., CVE-2024-1234)" }
  },
  "required": ["id"]
}
```

---

#### `vuln_db_search`

Search vulnerabilities by criteria.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "packageName": { "type": "string" },
    "ecosystem": { "type": "string", "description": "npm, pypi, go, maven, etc." },
    "severity": { "type": "array", "items": { "type": "string" } },
    "limit": { "type": "number" }
  }
}
```

---

#### `trivy_scan_offline`

Scan using local database only (no internet required).

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "image": { "type": "string", "description": "Docker image to scan" },
    "path": { "type": "string", "description": "Path to scan (alternative to image)" },
    "severity": { "type": "string" },
    "ignoreUnfixed": { "type": "boolean" }
  }
}
```

---

#### `vuln_db_annotate`

Annotate vulnerability status (false positive, acknowledged, etc.).

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "vulnId": { "type": "string", "description": "CVE ID" },
    "status": { "type": "string", "enum": ["active", "acknowledged", "false_positive", "mitigated"] },
    "notes": { "type": "string" }
  },
  "required": ["vulnId", "status"]
}
```

---

### Cache Tools

Distributed caching with Redis backend and automatic memory fallback for improved performance.

#### `cache_init`

Initialize distributed caching with optional Redis backend.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "useRedis": {
      "type": "boolean",
      "description": "Try to connect to Redis (default: true)",
      "default": true
    }
  }
}
```

**Response:**
```json
{
  "initialized": true,
  "redis": { "connected": true, "attempted": true },
  "memory": { "available": true },
  "mode": "hybrid"
}
```

---

#### `cache_status`

Get cache health and connection status.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

**Response:**
```json
{
  "redis": { "connected": true, "latencyMs": 2 },
  "memory": { "available": true, "cacheCount": 4 },
  "mode": "hybrid"
}
```

---

#### `cache_stats`

Get hit/miss statistics for all scan types.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

**Response:**
```json
{
  "trivy": { "hits": 150, "misses": 23, "hitRate": 0.867 },
  "sonarqube": { "hits": 45, "misses": 12, "hitRate": 0.789 },
  "dtrack": { "hits": 30, "misses": 8, "hitRate": 0.789 },
  "registry": { "hits": 200, "misses": 15, "hitRate": 0.930 },
  "redis": { "type": "redis", "connected": true, "keys": 438 }
}
```

---

#### `cache_clear`

Clear all cached data.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "confirm": {
      "type": "boolean",
      "description": "Must be true to confirm clearing"
    }
  },
  "required": ["confirm"]
}
```

---

#### `cache_invalidate`

Invalidate cache entries matching a pattern.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "pattern": {
      "type": "string",
      "description": "Glob pattern (e.g., 'trivy:*', 'sonarqube:project-*')"
    }
  },
  "required": ["pattern"]
}
```

**Response:**
```json
{
  "pattern": "trivy:*",
  "deleted": 25,
  "message": "Invalidated 25 cache entries matching pattern \"trivy:*\""
}
```

---

#### `cache_config`

Get current cache configuration.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

**Response:**
```json
{
  "redis": {
    "host": "localhost",
    "port": 6379,
    "db": 0,
    "keyPrefix": "cicd:",
    "connected": true
  },
  "ttl": {
    "trivy": "300s",
    "sonarqube": "600s",
    "dtrack": "600s",
    "registry": "1800s",
    "default": "300s"
  },
  "environmentVariables": {
    "redis": ["REDIS_HOST", "REDIS_PORT", "REDIS_PASSWORD", "..."],
    "ttl": ["CACHE_TTL_TRIVY", "CACHE_TTL_SONARQUBE", "..."]
  }
}
```

---

## MCP Resources

The MCP server exposes two resources:

### `cicd://config`

Returns the current platform configuration (with sensitive values masked).

```json
{
  "gitea": {
    "url": "http://localhost:3000",
    "user": "localadmin",
    "hasPassword": true
  },
  "drone": {
    "url": "http://localhost:8080",
    "hasToken": true
  },
  "sonarqube": {
    "url": "http://localhost:9000",
    "user": "admin",
    "hasPassword": true
  },
  "dependencyTrack": {
    "url": "http://localhost:8081",
    "hasApiKey": true
  },
  "trivy": {
    "url": "http://localhost:8082"
  },
  "registry": {
    "url": "http://localhost:5000"
  }
}
```

### `cicd://status`

Returns real-time health status of all platform services (same as `check_platform_status` tool).

---

## Handler Functions

All handlers are exported from `@cicd/shared`:

```typescript
import {
  // Trivy - Scanning
  trivyScanPath,
  trivyScanImage,
  trivyScanIac,
  trivyScanSecrets,
  trivyScanSecretsImage,
  trivyScanLicenses,
  trivyScanLicensesImage,

  // Trivy - SBOM Generation
  trivyGenerateSbom,
  trivyGenerateSbomImage,

  // Trivy - Combined Scans
  trivyScanImageFull,
  trivyScanPathFull,

  // SonarQube
  sonarGetProjects,
  sonarGetIssues,
  sonarGetSecurityHotspots,
  sonarGetMetrics,
  sonarGetQualityGateStatus,

  // Dependency-Track
  dtrackGetProjects,
  dtrackGetVulnerabilities,
  dtrackGetFindings,
  dtrackGetComponents,
  dtrackUploadSbom,

  // Gitea - Repositories
  giteaGetRepos,
  giteaGetRepo,
  giteaGetBranches,
  giteaGetCommits,
  giteaCreateRepo,
  giteaMigrateRepo,

  // Gitea - Pull Requests
  giteaListPullRequests,
  giteaGetPullRequest,
  giteaCreatePullRequest,
  giteaMergePullRequest,

  // Gitea - Issues
  giteaCreateIssue,
  giteaListIssues,

  // Drone CI
  droneGetRepos,
  droneGetBuilds,
  droneGetBuild,
  droneGetBuildLogs,
  droneTriggerBuild,

  // Registry
  registryGetCatalog,
  registryGetTags,

  // Platform
  securityScanAll,
  checkPlatformStatus,
} from "@cicd/shared";
```

---

## Configuration

Configuration is loaded from environment variables. See `.env.example` for all options.

```typescript
import { config } from "@cicd/shared";

// Access configuration
console.log(config.gitea.url);      // http://localhost:3000
console.log(config.drone.token);    // Bearer token
console.log(config.sonarqube.user); // admin
```

---

## Error Handling

All tools return errors in a consistent format:

```json
{
  "error": "Error message describing what went wrong"
}
```

Common error scenarios:

| Error | Cause | Solution |
|-------|-------|----------|
| `Invalid path provided` | Path is empty or too short | Provide a valid absolute path |
| `Invalid image name provided` | Image name is empty or invalid | Use format `name:tag` |
| `Dependency-Track API key not configured` | Missing `DTRACK_API_KEY` | Set the environment variable |
| `Drone token required to trigger builds` | Missing `DRONE_TOKEN` | Set the environment variable |
| `Unknown tool: <name>` | Tool name not recognized | Check tool name spelling |
