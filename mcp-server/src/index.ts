#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import {
  config,
  trivyScanPath,
  trivyScanImage,
  trivyGenerateSbom,
  trivyGenerateSbomImage,
  trivyScanIac,
  trivyScanSecrets,
  trivyScanSecretsImage,
  trivyScanLicenses,
  trivyScanLicensesImage,
  trivyScanImageFull,
  trivyScanPathFull,
  sonarGetProjects,
  sonarGetIssues,
  sonarGetSecurityHotspots,
  sonarGetMetrics,
  dtrackGetProjects,
  dtrackGetVulnerabilities,
  dtrackGetFindings,
  dtrackGetComponents,
  uploadSbomToDtrack,
  giteaGetRepos,
  giteaGetRepo,
  giteaGetBranches,
  giteaGetCommits,
  giteaCreateRepo,
  giteaMigrateRepo,
  droneGetRepos,
  droneGetBuilds,
  droneGetBuild,
  droneGetBuildLogs,
  droneTriggerBuild,
  registryGetCatalog,
  registryGetTags,
  securityScanAll,
  checkPlatformStatus,
  getSecurityDashboard,
  scanRegistry,
  // SARIF
  trivyToSarif,
  sonarToSarif,
  dtrackToSarif,
  mergeSarifLogs,
  getSarifSummary,
  uploadSarifToGitHub,
  writeSarifFile,
  // Scheduler
  validateCronExpression,
  describeCronExpression,
  getNextRunTimes,
  createSchedule,
  getSchedule,
  listSchedules,
  updateSchedule,
  deleteSchedule,
  triggerSchedule,
  getScheduleHistory,
  startScheduler,
  stopScheduler,
} from "./handlers.js";

// Re-export for backwards compatibility
export { validateSeverity, sanitizePath, sanitizeImageName } from "./handlers.js";

// =============================================================================
// Tool Definitions (exported for testing)
// =============================================================================
export const toolDefinitions = [
  // Trivy Tools
  {
    name: "trivy_scan_path",
    description:
      "Scan a local file path for vulnerabilities using Trivy. Detects vulnerabilities in dependencies (npm, pip, go, etc.) and secrets.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory to scan",
        },
        severity: {
          type: "string",
          description: "Severity levels to report (default: HIGH,CRITICAL)",
          default: "HIGH,CRITICAL",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "trivy_scan_image",
    description: "Scan a Docker image for vulnerabilities using Trivy",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)",
        },
        severity: {
          type: "string",
          description: "Severity levels to report (default: HIGH,CRITICAL)",
          default: "HIGH,CRITICAL",
        },
      },
      required: ["image"],
    },
  },
  {
    name: "trivy_generate_sbom",
    description:
      "Generate a Software Bill of Materials (SBOM) for a local path using Trivy. Creates a CycloneDX format SBOM listing all components and dependencies.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory to scan",
        },
        format: {
          type: "string",
          description: "SBOM format: cyclonedx (default) or spdx-json",
          default: "cyclonedx",
          enum: ["cyclonedx", "spdx-json"],
        },
      },
      required: ["path"],
    },
  },
  {
    name: "trivy_generate_sbom_image",
    description:
      "Generate a Software Bill of Materials (SBOM) for a Docker image using Trivy. Creates a CycloneDX format SBOM listing all components in the container.",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)",
        },
        format: {
          type: "string",
          description: "SBOM format: cyclonedx (default) or spdx-json",
          default: "cyclonedx",
          enum: ["cyclonedx", "spdx-json"],
        },
      },
      required: ["image"],
    },
  },
  {
    name: "trivy_scan_iac",
    description:
      "Scan Infrastructure as Code (IaC) files for misconfigurations using Trivy. Detects security issues in Terraform, Kubernetes, Docker, CloudFormation, and other IaC files.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory containing IaC files",
        },
        severity: {
          type: "string",
          description: "Severity levels to report (default: MEDIUM,HIGH,CRITICAL)",
          default: "MEDIUM,HIGH,CRITICAL",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "trivy_scan_secrets",
    description:
      "Scan a local path for hardcoded secrets using Trivy. Detects API keys, passwords, tokens, private keys, and other sensitive data in code.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory to scan for secrets",
        },
        severity: {
          type: "string",
          description: "Severity levels to report (default: MEDIUM,HIGH,CRITICAL)",
          default: "MEDIUM,HIGH,CRITICAL",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "trivy_scan_secrets_image",
    description:
      "Scan a Docker image for hardcoded secrets using Trivy. Detects API keys, passwords, tokens, private keys, and other sensitive data in container images.",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)",
        },
        severity: {
          type: "string",
          description: "Severity levels to report (default: MEDIUM,HIGH,CRITICAL)",
          default: "MEDIUM,HIGH,CRITICAL",
        },
      },
      required: ["image"],
    },
  },
  {
    name: "trivy_scan_licenses",
    description:
      "Scan a local path for license information using Trivy. Detects licenses in dependencies and flags potentially problematic licenses (forbidden, restricted, etc.).",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory to scan for licenses",
        },
        severity: {
          type: "string",
          description: "Severity levels to report (default: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL)",
          default: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "trivy_scan_licenses_image",
    description:
      "Scan a Docker image for license information using Trivy. Detects licenses in dependencies and flags potentially problematic licenses (forbidden, restricted, etc.).",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)",
        },
        severity: {
          type: "string",
          description: "Severity levels to report (default: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL)",
          default: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
        },
      },
      required: ["image"],
    },
  },
  {
    name: "trivy_scan_image_full",
    description:
      "Run a comprehensive security scan on a Docker image using Trivy. Combines vulnerability, secret, license scanning, and SBOM generation in one operation for complete image analysis.",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)",
        },
        severity: {
          type: "string",
          description: "Severity levels to report (default: HIGH,CRITICAL)",
          default: "HIGH,CRITICAL",
        },
        sbomFormat: {
          type: "string",
          description: "SBOM format: cyclonedx (default) or spdx-json",
          default: "cyclonedx",
          enum: ["cyclonedx", "spdx-json"],
        },
      },
      required: ["image"],
    },
  },
  {
    name: "trivy_scan_path_full",
    description:
      "Run a comprehensive security scan on a local path using Trivy. Combines vulnerability, secret, license, IaC scanning, and SBOM generation in one operation for complete codebase analysis.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory to scan",
        },
        severity: {
          type: "string",
          description: "Severity levels to report (default: HIGH,CRITICAL)",
          default: "HIGH,CRITICAL",
        },
        sbomFormat: {
          type: "string",
          description: "SBOM format: cyclonedx (default) or spdx-json",
          default: "cyclonedx",
          enum: ["cyclonedx", "spdx-json"],
        },
      },
      required: ["path"],
    },
  },

  // SonarQube Tools
  {
    name: "sonar_list_projects",
    description: "List all projects in SonarQube",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "sonar_get_issues",
    description: "Get code issues (bugs, vulnerabilities, code smells) for a SonarQube project",
    inputSchema: {
      type: "object",
      properties: {
        projectKey: {
          type: "string",
          description: "The SonarQube project key",
        },
        types: {
          type: "string",
          description: "Issue types to filter (VULNERABILITY, BUG, CODE_SMELL)",
        },
      },
      required: ["projectKey"],
    },
  },
  {
    name: "sonar_get_security_hotspots",
    description: "Get security hotspots for a SonarQube project",
    inputSchema: {
      type: "object",
      properties: {
        projectKey: {
          type: "string",
          description: "The SonarQube project key",
        },
      },
      required: ["projectKey"],
    },
  },
  {
    name: "sonar_get_metrics",
    description:
      "Get quality metrics (bugs, vulnerabilities, coverage, etc.) for a SonarQube project",
    inputSchema: {
      type: "object",
      properties: {
        projectKey: {
          type: "string",
          description: "The SonarQube project key",
        },
      },
      required: ["projectKey"],
    },
  },

  // Dependency-Track Tools
  {
    name: "dtrack_list_projects",
    description: "List all projects in Dependency-Track",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "dtrack_get_vulnerabilities",
    description: "Get vulnerabilities for a Dependency-Track project",
    inputSchema: {
      type: "object",
      properties: {
        projectUuid: {
          type: "string",
          description: "The project UUID (get from dtrack_list_projects)",
        },
      },
      required: ["projectUuid"],
    },
  },
  {
    name: "dtrack_get_findings",
    description: "Get all security findings for a Dependency-Track project",
    inputSchema: {
      type: "object",
      properties: {
        projectUuid: {
          type: "string",
          description: "The project UUID",
        },
      },
      required: ["projectUuid"],
    },
  },
  {
    name: "dtrack_get_components",
    description: "Get all components (dependencies) for a Dependency-Track project",
    inputSchema: {
      type: "object",
      properties: {
        projectUuid: {
          type: "string",
          description: "The project UUID",
        },
      },
      required: ["projectUuid"],
    },
  },
  {
    name: "dtrack_upload_sbom",
    description:
      "Generate SBOM for a Docker image or path and upload to Dependency-Track. " +
      "Creates or uses existing project, then tracks vulnerabilities.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target to scan - Docker image name (e.g., 'nginx:latest') or file path",
        },
        targetType: {
          type: "string",
          enum: ["image", "path"],
          description: "Type of target: 'image' for Docker images, 'path' for local directories",
        },
        projectName: {
          type: "string",
          description: "Project name in Dependency-Track (defaults to target name)",
        },
        projectVersion: {
          type: "string",
          description: "Project version (defaults to 'latest')",
        },
        autoCreateProject: {
          type: "boolean",
          description: "Auto-create project if it doesn't exist (default: true)",
        },
        tags: {
          type: "array",
          items: { type: "string" },
          description: "Tags to apply to the project",
        },
        waitForProcessing: {
          type: "boolean",
          description: "Wait for SBOM processing to complete before returning",
        },
      },
      required: ["target"],
    },
  },

  // Gitea Tools
  {
    name: "gitea_list_repos",
    description: "List all repositories in Gitea for the current user",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "gitea_get_repo",
    description: "Get details of a specific Gitea repository",
    inputSchema: {
      type: "object",
      properties: {
        owner: {
          type: "string",
          description: "Repository owner",
        },
        repo: {
          type: "string",
          description: "Repository name",
        },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "gitea_get_branches",
    description: "List branches of a Gitea repository",
    inputSchema: {
      type: "object",
      properties: {
        owner: {
          type: "string",
          description: "Repository owner",
        },
        repo: {
          type: "string",
          description: "Repository name",
        },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "gitea_get_commits",
    description: "Get recent commits for a Gitea repository",
    inputSchema: {
      type: "object",
      properties: {
        owner: {
          type: "string",
          description: "Repository owner",
        },
        repo: {
          type: "string",
          description: "Repository name",
        },
        limit: {
          type: "number",
          description: "Number of commits to retrieve (default: 10)",
          default: 10,
        },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "gitea_create_repo",
    description: "Create a new repository in Gitea",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Repository name",
        },
        description: {
          type: "string",
          description: "Repository description",
        },
        private: {
          type: "boolean",
          description: "Whether the repository is private",
          default: false,
        },
      },
      required: ["name"],
    },
  },
  {
    name: "gitea_migrate_repo",
    description: "Migrate a repository from GitHub to Gitea",
    inputSchema: {
      type: "object",
      properties: {
        cloneUrl: {
          type: "string",
          description: "GitHub clone URL (e.g., https://github.com/user/repo.git)",
        },
        repoName: {
          type: "string",
          description: "Name for the new repository in Gitea",
        },
        authToken: {
          type: "string",
          description: "GitHub personal access token (required for private repos)",
        },
      },
      required: ["cloneUrl", "repoName"],
    },
  },

  // Drone CI Tools
  {
    name: "drone_list_repos",
    description: "List all repositories synced with Drone CI",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "drone_get_builds",
    description: "Get build history for a Drone CI repository",
    inputSchema: {
      type: "object",
      properties: {
        owner: {
          type: "string",
          description: "Repository owner",
        },
        repo: {
          type: "string",
          description: "Repository name",
        },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "drone_get_build",
    description: "Get details of a specific Drone CI build",
    inputSchema: {
      type: "object",
      properties: {
        owner: {
          type: "string",
          description: "Repository owner",
        },
        repo: {
          type: "string",
          description: "Repository name",
        },
        build: {
          type: "number",
          description: "Build number",
        },
      },
      required: ["owner", "repo", "build"],
    },
  },
  {
    name: "drone_get_build_logs",
    description: "Get logs for a Drone CI build step",
    inputSchema: {
      type: "object",
      properties: {
        owner: {
          type: "string",
          description: "Repository owner",
        },
        repo: {
          type: "string",
          description: "Repository name",
        },
        build: {
          type: "number",
          description: "Build number",
        },
        stage: {
          type: "number",
          description: "Stage number (default: 1)",
          default: 1,
        },
        step: {
          type: "number",
          description: "Step number (default: 1)",
          default: 1,
        },
      },
      required: ["owner", "repo", "build"],
    },
  },
  {
    name: "drone_trigger_build",
    description: "Trigger a new build in Drone CI",
    inputSchema: {
      type: "object",
      properties: {
        owner: {
          type: "string",
          description: "Repository owner",
        },
        repo: {
          type: "string",
          description: "Repository name",
        },
        branch: {
          type: "string",
          description: "Branch to build (default: main)",
          default: "main",
        },
      },
      required: ["owner", "repo"],
    },
  },

  // Registry Tools
  {
    name: "registry_list_images",
    description: "List all images in the local Docker registry",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "registry_get_tags",
    description: "Get all tags for an image in the local Docker registry",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Image name",
        },
      },
      required: ["image"],
    },
  },
  {
    name: "registry_scan",
    description:
      "Scan all images in the container registry for vulnerabilities. " +
      "Supports filtering by repository pattern, tag pattern, and parallel scanning.",
    inputSchema: {
      type: "object",
      properties: {
        repositories: {
          type: "array",
          items: { type: "string" },
          description: "Filter repositories by glob patterns (e.g., ['myapp/*', 'library/**'])",
        },
        tagFilter: {
          type: "string",
          description: "Regex pattern to filter tags (e.g., '^v\\d+' for version tags)",
        },
        allTags: {
          type: "boolean",
          description: "Include all tags or just 'latest' (default: true)",
        },
        limit: {
          type: "number",
          description: "Maximum number of images to scan",
        },
        concurrency: {
          type: "number",
          description: "Number of parallel scans (default: 3)",
        },
        severity: {
          type: "string",
          description: "Severity levels to report (default: HIGH,CRITICAL)",
        },
        listOnly: {
          type: "boolean",
          description: "Only list images without scanning",
        },
        failFast: {
          type: "boolean",
          description: "Stop on first scan error",
        },
      },
    },
  },

  // Combined Tools
  {
    name: "security_scan_all",
    description:
      "Run a comprehensive security scan using all available tools (Trivy, SonarQube findings, Dependency-Track)",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Path to scan with Trivy",
        },
        sonarProjectKey: {
          type: "string",
          description: "SonarQube project key (optional)",
        },
        dtrackProjectUuid: {
          type: "string",
          description: "Dependency-Track project UUID (optional)",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "get_security_dashboard",
    description:
      "Get unified security dashboard aggregating Trivy, SonarQube, and Dependency-Track results. Provides a single-call overview of security posture with aggregated counts and top findings.",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan with Trivy (optional)",
        },
        path: {
          type: "string",
          description: "Local path to scan with Trivy (optional)",
        },
        sonarProject: {
          type: "string",
          description: "SonarQube project key (optional)",
        },
        dtrackProjectUuid: {
          type: "string",
          description: "Dependency-Track project UUID (optional)",
        },
        severity: {
          type: "string",
          description: "Severity filter for Trivy (default: HIGH,CRITICAL)",
          default: "HIGH,CRITICAL",
        },
      },
    },
  },

  // SARIF Tools
  {
    name: "sarif_generate",
    description:
      "Generate a SARIF (Static Analysis Results Interchange Format) report from scan results. " +
      "SARIF is the standard format for GitHub Code Scanning, GitLab SAST, and other security tools. " +
      "Can scan an image or path and convert results to SARIF format.",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan with Trivy",
        },
        path: {
          type: "string",
          description: "Local path to scan with Trivy",
        },
        sonarProject: {
          type: "string",
          description: "SonarQube project key to include issues from",
        },
        dtrackProjectUuid: {
          type: "string",
          description: "Dependency-Track project UUID to include findings from",
        },
        severity: {
          type: "string",
          description: "Severity filter (default: HIGH,CRITICAL)",
          default: "HIGH,CRITICAL",
        },
        outputFile: {
          type: "string",
          description: "Path to write SARIF file (optional, returns JSON if not specified)",
        },
        toolName: {
          type: "string",
          description: "Tool name for SARIF metadata (default: CI/CD Security Scanner)",
        },
        toolVersion: {
          type: "string",
          description: "Tool version for SARIF metadata",
        },
      },
    },
  },
  {
    name: "sarif_upload_github",
    description:
      "Upload a SARIF report to GitHub Code Scanning API. Requires GitHub token with security_events scope. " +
      "After upload, vulnerabilities appear in GitHub's Security tab.",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan with Trivy",
        },
        path: {
          type: "string",
          description: "Local path to scan with Trivy",
        },
        sonarProject: {
          type: "string",
          description: "SonarQube project key to include issues from",
        },
        dtrackProjectUuid: {
          type: "string",
          description: "Dependency-Track project UUID to include findings from",
        },
        severity: {
          type: "string",
          description: "Severity filter (default: HIGH,CRITICAL)",
          default: "HIGH,CRITICAL",
        },
        owner: {
          type: "string",
          description: "GitHub repository owner",
        },
        repo: {
          type: "string",
          description: "GitHub repository name",
        },
        commitSha: {
          type: "string",
          description: "Git commit SHA to associate with the scan",
        },
        ref: {
          type: "string",
          description: "Git ref (e.g., refs/heads/main)",
        },
        token: {
          type: "string",
          description: "GitHub token with security_events scope",
        },
        apiUrl: {
          type: "string",
          description: "GitHub API URL (default: https://api.github.com)",
        },
      },
      required: ["owner", "repo", "commitSha", "ref", "token"],
    },
  },

  // Scheduler Tools
  {
    name: "schedule_create",
    description:
      "Create a new scheduled security scan. Supports cron expressions for flexible scheduling. " +
      "Scans can target Docker images, local paths, SonarQube projects, or Dependency-Track projects.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Human-readable name for the schedule",
        },
        cron: {
          type: "string",
          description:
            "Cron expression (e.g., '0 2 * * *' for daily at 2 AM, '0 */6 * * *' for every 6 hours)",
        },
        timezone: {
          type: "string",
          description: "Timezone for schedule (default: UTC)",
          default: "UTC",
        },
        targets: {
          type: "array",
          items: {
            type: "object",
            properties: {
              type: {
                type: "string",
                enum: ["image", "path", "registry"],
                description:
                  "Target type: 'image' for Docker images, 'path' for local directories, 'registry' for all images in registry",
              },
              value: {
                type: "string",
                description: "Target value (image name, local path, or registry URL)",
              },
            },
            required: ["type", "value"],
          },
          description: "Scan targets",
        },
        options: {
          type: "object",
          properties: {
            severity: {
              type: "string",
              description: "Severity filter (default: HIGH,CRITICAL)",
            },
            generateSarif: {
              type: "boolean",
              description: "Generate SARIF report",
            },
            uploadSbom: {
              type: "boolean",
              description: "Upload SBOM to Dependency-Track",
            },
          },
          description: "Scan options",
        },
        notifications: {
          type: "array",
          items: {
            type: "object",
            properties: {
              url: {
                type: "string",
                description: "Webhook URL",
              },
              onSuccess: {
                type: "boolean",
                description: "Notify on success",
              },
              onFailure: {
                type: "boolean",
                description: "Notify on failure",
              },
              onVulnerabilities: {
                type: "boolean",
                description: "Notify when vulnerabilities found",
              },
            },
            required: ["url"],
          },
          description: "Webhook notifications",
        },
        enabled: {
          type: "boolean",
          description: "Whether schedule is enabled (default: true)",
          default: true,
        },
      },
      required: ["name", "cron", "targets"],
    },
  },
  {
    name: "schedule_list",
    description: "List all scheduled security scans with their status and next run times",
    inputSchema: {
      type: "object",
      properties: {
        enabled: {
          type: "boolean",
          description: "Filter by enabled status",
        },
        targetType: {
          type: "string",
          enum: ["image", "path", "registry"],
          description: "Filter by target type",
        },
      },
    },
  },
  {
    name: "schedule_get",
    description: "Get details of a specific scheduled scan",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Schedule ID",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "schedule_update",
    description: "Update an existing scheduled scan",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Schedule ID",
        },
        name: {
          type: "string",
          description: "New name for the schedule",
        },
        cron: {
          type: "string",
          description: "New cron expression",
        },
        timezone: {
          type: "string",
          description: "New timezone",
        },
        targets: {
          type: "array",
          items: {
            type: "object",
            properties: {
              type: {
                type: "string",
                enum: ["image", "path", "registry"],
              },
              value: { type: "string" },
            },
            required: ["type", "value"],
          },
          description: "New scan targets",
        },
        options: {
          type: "object",
          description: "New scan options",
        },
        enabled: {
          type: "boolean",
          description: "Enable or disable the schedule",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "schedule_delete",
    description: "Delete a scheduled scan",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Schedule ID",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "schedule_trigger",
    description: "Manually trigger a scheduled scan immediately",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Schedule ID",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "schedule_history",
    description: "Get execution history for a scheduled scan",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Schedule ID",
        },
        limit: {
          type: "number",
          description: "Maximum number of history entries to return (default: 10)",
          default: 10,
        },
      },
      required: ["id"],
    },
  },
  {
    name: "cron_validate",
    description:
      "Validate a cron expression and get human-readable description with next run times",
    inputSchema: {
      type: "object",
      properties: {
        expression: {
          type: "string",
          description: "Cron expression to validate",
        },
        timezone: {
          type: "string",
          description: "Timezone for calculating run times (default: UTC)",
          default: "UTC",
        },
        count: {
          type: "number",
          description: "Number of upcoming run times to show (default: 5)",
          default: 5,
        },
      },
      required: ["expression"],
    },
  },
  {
    name: "scheduler_control",
    description: "Start or stop the scheduler execution engine",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["start", "stop", "status"],
          description: "Action to perform",
        },
      },
      required: ["action"],
    },
  },
];

// =============================================================================
// Resource Definitions (exported for testing)
// =============================================================================
export const resourceDefinitions = [
  {
    uri: "cicd://status",
    name: "CI/CD Platform Status",
    description: "Current status of all CI/CD services",
    mimeType: "application/json",
  },
  {
    uri: "cicd://config",
    name: "CI/CD Configuration",
    description: "Current MCP server configuration (URLs and settings)",
    mimeType: "application/json",
  },
];

// =============================================================================
// Handler Functions (exported for testing)
// =============================================================================
export function handleListTools() {
  return { tools: toolDefinitions };
}

// Tool handler type
type ToolHandler = (args?: Record<string, unknown>) => Promise<unknown>;

// Trivy handlers
const trivyHandlers: Record<string, ToolHandler> = {
  trivy_scan_path: (args) => trivyScanPath(args?.path as string, args?.severity as string),
  trivy_scan_image: (args) => trivyScanImage(args?.image as string, args?.severity as string),
  trivy_generate_sbom: (args) =>
    trivyGenerateSbom(args?.path as string, args?.format as "cyclonedx" | "spdx-json"),
  trivy_generate_sbom_image: (args) =>
    trivyGenerateSbomImage(args?.image as string, args?.format as "cyclonedx" | "spdx-json"),
  trivy_scan_iac: (args) => trivyScanIac(args?.path as string, args?.severity as string),
  trivy_scan_secrets: (args) => trivyScanSecrets(args?.path as string, args?.severity as string),
  trivy_scan_secrets_image: (args) =>
    trivyScanSecretsImage(args?.image as string, args?.severity as string),
  trivy_scan_licenses: (args) => trivyScanLicenses(args?.path as string, args?.severity as string),
  trivy_scan_licenses_image: (args) =>
    trivyScanLicensesImage(args?.image as string, args?.severity as string),
  trivy_scan_image_full: (args) =>
    trivyScanImageFull(
      args?.image as string,
      args?.severity as string,
      args?.sbomFormat as "cyclonedx" | "spdx-json"
    ),
  trivy_scan_path_full: (args) =>
    trivyScanPathFull(
      args?.path as string,
      args?.severity as string,
      args?.sbomFormat as "cyclonedx" | "spdx-json"
    ),
};

// SonarQube handlers
const sonarHandlers: Record<string, ToolHandler> = {
  sonar_list_projects: () => sonarGetProjects(),
  sonar_get_issues: (args) => sonarGetIssues(args?.projectKey as string, args?.types as string),
  sonar_get_security_hotspots: (args) => sonarGetSecurityHotspots(args?.projectKey as string),
  sonar_get_metrics: (args) => sonarGetMetrics(args?.projectKey as string),
};

// Dependency-Track handlers
const dtrackHandlers: Record<string, ToolHandler> = {
  dtrack_list_projects: () => dtrackGetProjects(),
  dtrack_get_vulnerabilities: (args) => dtrackGetVulnerabilities(args?.projectUuid as string),
  dtrack_get_findings: (args) => dtrackGetFindings(args?.projectUuid as string),
  dtrack_get_components: (args) => dtrackGetComponents(args?.projectUuid as string),
  dtrack_upload_sbom: (args) =>
    uploadSbomToDtrack({
      target: args?.target as string,
      targetType: args?.targetType as "image" | "path",
      projectName: args?.projectName as string,
      projectVersion: args?.projectVersion as string,
      autoCreateProject: args?.autoCreateProject as boolean,
      tags: args?.tags as string[],
      waitForProcessing: args?.waitForProcessing as boolean,
    }),
};

// Gitea handlers
const giteaHandlers: Record<string, ToolHandler> = {
  gitea_list_repos: () => giteaGetRepos(),
  gitea_get_repo: (args) => giteaGetRepo(args?.owner as string, args?.repo as string),
  gitea_get_branches: (args) => giteaGetBranches(args?.owner as string, args?.repo as string),
  gitea_get_commits: (args) =>
    giteaGetCommits(args?.owner as string, args?.repo as string, args?.limit as number),
  gitea_create_repo: (args) =>
    giteaCreateRepo(args?.name as string, args?.description as string, args?.private as boolean),
  gitea_migrate_repo: (args) =>
    giteaMigrateRepo(args?.cloneUrl as string, args?.repoName as string, args?.authToken as string),
};

// Drone handlers
const droneHandlers: Record<string, ToolHandler> = {
  drone_list_repos: () => droneGetRepos(),
  drone_get_builds: (args) => droneGetBuilds(args?.owner as string, args?.repo as string),
  drone_get_build: (args) =>
    droneGetBuild(args?.owner as string, args?.repo as string, args?.build as number),
  drone_get_build_logs: (args) =>
    droneGetBuildLogs(
      args?.owner as string,
      args?.repo as string,
      args?.build as number,
      args?.stage as number,
      args?.step as number
    ),
  drone_trigger_build: (args) =>
    droneTriggerBuild(args?.owner as string, args?.repo as string, args?.branch as string),
};

// Other handlers
const otherHandlers: Record<string, ToolHandler> = {
  registry_list_images: () => registryGetCatalog(),
  registry_get_tags: (args) => registryGetTags(args?.image as string),
  registry_scan: (args) =>
    scanRegistry({
      repositories: args?.repositories as string[] | undefined,
      tagFilter: args?.tagFilter as string | undefined,
      allTags: args?.allTags as boolean | undefined,
      limit: args?.limit as number | undefined,
      concurrency: args?.concurrency as number | undefined,
      severity: args?.severity as string | undefined,
      listOnly: args?.listOnly as boolean | undefined,
      failFast: args?.failFast as boolean | undefined,
    }),
  security_scan_all: (args) =>
    securityScanAll(
      args?.path as string,
      args?.sonarProjectKey as string,
      args?.dtrackProjectUuid as string
    ),
  get_security_dashboard: (args) =>
    getSecurityDashboard({
      image: args?.image as string | undefined,
      path: args?.path as string | undefined,
      sonarProject: args?.sonarProject as string | undefined,
      dtrackProjectUuid: args?.dtrackProjectUuid as string | undefined,
      severity: args?.severity as string | undefined,
    }),
};

// Helper to check if result is an error response
function isErrorResponse(result: unknown): result is { error: string } {
  return typeof result === "object" && result !== null && "error" in result;
}

// SARIF handlers
const sarifHandlers: Record<string, ToolHandler> = {
  sarif_generate: async (args) => {
    const severity = (args?.severity as string) || "HIGH,CRITICAL";
    const options = {
      toolName: args?.toolName as string | undefined,
      toolVersion: args?.toolVersion as string | undefined,
    };

    // Collect scan results from specified sources
    const logs = [];

    // Trivy scan
    if (args?.image) {
      const trivyResult = await trivyScanImage(args.image as string, severity);
      if (!isErrorResponse(trivyResult)) {
        logs.push(trivyToSarif(trivyResult, options));
      }
    } else if (args?.path) {
      const trivyResult = await trivyScanPath(args.path as string, severity);
      if (!isErrorResponse(trivyResult)) {
        logs.push(trivyToSarif(trivyResult, options));
      }
    }

    // SonarQube issues
    if (args?.sonarProject) {
      const issues = await sonarGetIssues(args.sonarProject as string);
      logs.push(sonarToSarif(issues.issues, options));
    }

    // Dependency-Track findings
    if (args?.dtrackProjectUuid) {
      const findings = await dtrackGetFindings(args.dtrackProjectUuid as string);
      logs.push(dtrackToSarif(findings, options));
    }

    // Merge all logs
    const mergedLog =
      logs.length > 0
        ? mergeSarifLogs(...logs)
        : { $schema: "", version: "2.1.0" as const, runs: [] };

    // Write to file if specified
    if (args?.outputFile) {
      await writeSarifFile(mergedLog, args.outputFile as string);
      return {
        success: true,
        outputFile: args.outputFile,
        summary: getSarifSummary(mergedLog),
      };
    }

    // Return SARIF as JSON
    return {
      sarif: mergedLog,
      summary: getSarifSummary(mergedLog),
    };
  },

  sarif_upload_github: async (args) => {
    const severity = (args?.severity as string) || "HIGH,CRITICAL";
    const options = {
      toolName: "CI/CD Security Scanner",
      toolVersion: "1.0.0",
    };

    // Collect scan results from specified sources
    const logs = [];

    // Trivy scan
    if (args?.image) {
      const trivyResult = await trivyScanImage(args.image as string, severity);
      if (!isErrorResponse(trivyResult)) {
        logs.push(trivyToSarif(trivyResult, options));
      }
    } else if (args?.path) {
      const trivyResult = await trivyScanPath(args.path as string, severity);
      if (!isErrorResponse(trivyResult)) {
        logs.push(trivyToSarif(trivyResult, options));
      }
    }

    // SonarQube issues
    if (args?.sonarProject) {
      const issues = await sonarGetIssues(args.sonarProject as string);
      logs.push(sonarToSarif(issues.issues, options));
    }

    // Dependency-Track findings
    if (args?.dtrackProjectUuid) {
      const findings = await dtrackGetFindings(args.dtrackProjectUuid as string);
      logs.push(dtrackToSarif(findings, options));
    }

    if (logs.length === 0) {
      throw new Error(
        "No scan sources specified. Provide image, path, sonarProject, or dtrackProjectUuid."
      );
    }

    // Merge all logs
    const mergedLog = mergeSarifLogs(...logs);

    // Upload to GitHub
    const result = await uploadSarifToGitHub(mergedLog, {
      owner: args?.owner as string,
      repo: args?.repo as string,
      commitSha: args?.commitSha as string,
      ref: args?.ref as string,
      token: args?.token as string,
      apiUrl: args?.apiUrl as string | undefined,
    });

    return {
      success: true,
      uploadId: result.id,
      url: result.url,
      summary: getSarifSummary(mergedLog),
    };
  },
};

// Scheduler state tracking
let schedulerRunning = false;

// Scheduler handlers
const schedulerHandlers: Record<string, ToolHandler> = {
  schedule_create: async (args) => {
    // Convert input targets to the expected format
    const inputTargets = args?.targets as Array<{ type: string; value: string }> | undefined;
    const targets = inputTargets?.map((t) => ({
      target: t.value,
      type: t.type as "image" | "path" | "registry",
    }));

    // Convert notifications to the expected format
    const inputNotifications = args?.notifications as
      | Array<{
          url: string;
          onSuccess?: boolean;
          onFailure?: boolean;
          onVulnerabilities?: boolean;
        }>
      | undefined;
    const notifications = inputNotifications?.map((n) => ({
      url: n.url,
      format: "slack" as const,
      notifyOn: [
        ...(n.onSuccess ? ["success" as const] : []),
        ...(n.onFailure ? ["failure" as const] : []),
        ...(n.onVulnerabilities ? ["vulnerabilities" as const] : []),
      ],
    }));

    const schedule = createSchedule({
      name: args?.name as string,
      cron: args?.cron as string,
      timezone: args?.timezone as string | undefined,
      targets: targets || [],
      options: args?.options as { severity?: string; concurrency?: number } | undefined,
      notifications,
      enabled: args?.enabled !== false,
    });
    return {
      success: true,
      schedule,
      message: "Schedule '" + schedule.name + "' created with ID " + schedule.id,
    };
  },

  schedule_list: async (args) => {
    const schedules = listSchedules({
      enabled: args?.enabled as boolean | undefined,
      targetType: args?.targetType as "image" | "path" | "registry" | undefined,
    });
    return {
      count: schedules.length,
      schedules,
    };
  },

  schedule_get: async (args) => {
    const schedule = getSchedule(args?.id as string);
    if (!schedule) {
      throw new Error("Schedule not found: " + args?.id);
    }
    return schedule;
  },

  schedule_update: async (args) => {
    // Convert input targets to the expected format
    const inputTargets = args?.targets as Array<{ type: string; value: string }> | undefined;
    const targets = inputTargets?.map((t) => ({
      target: t.value,
      type: t.type as "image" | "path" | "registry",
    }));

    const schedule = updateSchedule(args?.id as string, {
      name: args?.name as string | undefined,
      cron: args?.cron as string | undefined,
      timezone: args?.timezone as string | undefined,
      targets,
      options: args?.options as { severity?: string; concurrency?: number } | undefined,
      enabled: args?.enabled as boolean | undefined,
    });
    return {
      success: true,
      schedule,
      message: "Schedule '" + schedule.name + "' updated",
    };
  },

  schedule_delete: async (args) => {
    const schedule = getSchedule(args?.id as string);
    if (!schedule) {
      throw new Error("Schedule not found: " + args?.id);
    }
    const name = schedule.name;
    deleteSchedule(args?.id as string);
    return {
      success: true,
      message: "Schedule '" + name + "' deleted",
    };
  },

  schedule_trigger: async (args) => {
    const result = await triggerSchedule(args?.id as string);
    return {
      success: result.success,
      scheduleId: result.scheduleId,
      scheduleName: result.scheduleName,
      targetsScanned: result.targetsScanned,
      targetsFailed: result.targetsFailed,
      vulnerabilities: result.vulnerabilities,
      error: result.error,
    };
  },

  schedule_history: async (args) => {
    const history = getScheduleHistory(args?.id as string, args?.limit as number | undefined);
    return {
      scheduleId: args?.id,
      count: history.length,
      history,
    };
  },

  cron_validate: async (args) => {
    const result = validateCronExpression(args?.expression as string, {
      allowSeconds: false,
      allowHash: false,
    });

    if (!result.valid) {
      return {
        valid: false,
        error: result.error,
      };
    }

    const nextRuns = getNextRunTimes(
      args?.expression as string,
      (args?.count as number) || 5,
      args?.timezone as string
    );

    return {
      valid: true,
      description: describeCronExpression(result.parsed!),
      nextRuns: nextRuns.map((d) => d.toISOString()),
    };
  },

  scheduler_control: async (args) => {
    const action = args?.action as string;
    switch (action) {
      case "start":
        if (!schedulerRunning) {
          startScheduler();
          schedulerRunning = true;
        }
        return { success: true, status: "running", message: "Scheduler started" };

      case "stop":
        if (schedulerRunning) {
          stopScheduler();
          schedulerRunning = false;
        }
        return { success: true, status: "stopped", message: "Scheduler stopped" };

      case "status":
        return {
          success: true,
          status: schedulerRunning ? "running" : "stopped",
          schedules: listSchedules().length,
        };

      default:
        throw new Error(`Unknown action: ${action}`);
    }
  },
};

// Combined handler map
const toolHandlers: Record<string, ToolHandler> = {
  ...trivyHandlers,
  ...sonarHandlers,
  ...dtrackHandlers,
  ...giteaHandlers,
  ...droneHandlers,
  ...otherHandlers,
  ...sarifHandlers,
  ...schedulerHandlers,
};

export async function handleCallTool(
  name: string,
  args?: Record<string, unknown>
): Promise<{
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}> {
  try {
    const handler = toolHandlers[name];
    if (!handler) {
      throw new Error(`Unknown tool: ${name}`);
    }

    const result = await handler(args);

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ error: errorMessage }, null, 2),
        },
      ],
      isError: true,
    };
  }
}

export function handleListResources() {
  return { resources: resourceDefinitions };
}

export async function handleReadResource(uri: string): Promise<{
  contents: Array<{ uri: string; mimeType: string; text: string }>;
}> {
  if (uri === "cicd://status") {
    const status = await checkPlatformStatus();
    return {
      contents: [
        {
          uri,
          mimeType: "application/json",
          text: JSON.stringify(status, null, 2),
        },
      ],
    };
  }

  if (uri === "cicd://config") {
    const safeConfig = {
      gitea: { url: config.gitea.url, user: config.gitea.user },
      drone: { url: config.drone.url, hasToken: !!config.drone.token },
      sonarqube: { url: config.sonarqube.url, user: config.sonarqube.user },
      dependencyTrack: {
        url: config.dependencyTrack.url,
        hasApiKey: !!config.dependencyTrack.apiKey,
      },
      trivy: { url: config.trivy.url },
      registry: { url: config.registry.url },
    };

    return {
      contents: [
        {
          uri,
          mimeType: "application/json",
          text: JSON.stringify(safeConfig, null, 2),
        },
      ],
    };
  }

  throw new Error(`Unknown resource: ${uri}`);
}

// =============================================================================
// MCP Server Setup (only runs when module is executed directly)
// =============================================================================
const mcpServer = new McpServer(
  {
    name: "cicd-security-mcp-server",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
      resources: {},
    },
  }
);

// Access the underlying server for low-level request handlers
const server = mcpServer.server;

// Register handlers using exported functions
server.setRequestHandler(ListToolsRequestSchema, async () => handleListTools());
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  return handleCallTool(name, args as Record<string, unknown>);
});
server.setRequestHandler(ListResourcesRequestSchema, async () => handleListResources());
server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  return handleReadResource(request.params.uri);
});

// =============================================================================
// Start Server
// =============================================================================
const transport = new StdioServerTransport();
try {
  await mcpServer.connect(transport);
  console.error("CI/CD Security MCP Server running on stdio");
} catch (error) {
  console.error(error);
  process.exit(1);
}
