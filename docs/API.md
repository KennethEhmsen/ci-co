# API Reference

This document provides a complete reference for all tools and handlers available in the CI/CD Security Platform.

## Table of Contents

- [Overview](#overview)
- [MCP Server Tools](#mcp-server-tools)
  - [Trivy Tools](#trivy-tools)
  - [SonarQube Tools](#sonarqube-tools)
  - [Dependency-Track Tools](#dependency-track-tools)
  - [Gitea Tools](#gitea-tools)
  - [Drone CI Tools](#drone-ci-tools)
  - [Docker Registry Tools](#docker-registry-tools)
  - [Platform Tools](#platform-tools)
- [MCP Resources](#mcp-resources)
- [Handler Functions](#handler-functions)
- [Configuration](#configuration)
- [Error Handling](#error-handling)

---

## Overview

The CI/CD Security Platform provides 23 tools for security scanning and DevOps automation. These tools are available through:

1. **MCP Server** - For Claude Code integration via Model Context Protocol
2. **CI/CD Agent** - Standalone CLI with Anthropic SDK integration

All tools share the same underlying handlers from the `@cicd/shared` package.

---

## MCP Server Tools

### Trivy Tools

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

Scan a Docker image for vulnerabilities using Trivy.

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
  // Trivy
  trivyScanPath,
  trivyScanImage,

  // SonarQube
  sonarGetProjects,
  sonarGetIssues,
  sonarGetSecurityHotspots,
  sonarGetMetrics,

  // Dependency-Track
  dtrackGetProjects,
  dtrackGetVulnerabilities,
  dtrackGetFindings,
  dtrackGetComponents,

  // Gitea
  giteaGetRepos,
  giteaGetRepo,
  giteaGetBranches,
  giteaGetCommits,
  giteaCreateRepo,
  giteaMigrateRepo,

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
