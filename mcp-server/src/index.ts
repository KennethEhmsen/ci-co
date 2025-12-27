#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { CloudRegistryType, ComplianceFramework, RegistryAuth } from "@cicd/shared";
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
  // Multi-Registry
  detectRegistryType,
  configureRegistry,
  getRegistryConfig,
  listRegistryConfigs,
  removeRegistryConfig,
  scanMultipleRegistries,
  testRegistryConnection,
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
  // Remediation
  generateRemediations,
  getRemediationSummary,
  formatRemediationAsMarkdown,
  getHighPriorityRemediations,
  getSafeRemediations,
  // Compliance
  getComplianceFrameworks,
  getComplianceControls,
  generateComplianceReport,
  generateComplianceHtml,
  recordComplianceTrend,
  getComplianceTrend,
  checkComplianceStatus,
  // OPA/Rego
  listBuiltinPolicies,
  getBuiltinPolicyInfo,
  getBuiltinPolicy,
  validateRegoSyntax,
  evaluateOpaPolicy,
  trivyResultToOpaInput,
  createOpaInput,
  // Vulnerability Database
  initVulnDatabase,
  isVulnDbInitialized,
  lookupVulnerability,
  searchVulnerabilities,
  getVulnDbStats,
  annotateVulnerability,
  // Database Sync
  getTrivyDbStatus,
  syncVulnDatabase,
  isOfflineScanAvailable,
  // Offline Scanner
  offlineScanImage,
  offlineScanPath,
  getOfflineScanCapabilities,
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

  // Multi-Registry Tools
  {
    name: "registry_detect_type",
    description:
      "Auto-detect the type of container registry from its URL. " +
      "Identifies ECR, ACR, GCR, GHCR, Harbor, GitLab, and standard Docker registries.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description:
            "Registry URL or hostname (e.g., 123456789.dkr.ecr.us-east-1.amazonaws.com, ghcr.io)",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "registry_configure",
    description:
      "Configure a container registry for scanning. Supports multiple registry types with their specific authentication methods.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Unique identifier for this registry configuration",
        },
        name: {
          type: "string",
          description: "Display name for the registry",
        },
        url: {
          type: "string",
          description:
            "Registry URL (e.g., registry.example.com, 123456789.dkr.ecr.us-east-1.amazonaws.com)",
        },
        type: {
          type: "string",
          enum: ["docker-registry", "harbor", "gitlab", "ecr", "acr", "gcr", "gar", "ghcr"],
          description: "Registry type (auto-detected if not provided)",
        },
        auth: {
          type: "object",
          description: "Authentication configuration",
          properties: {
            type: {
              type: "string",
              enum: ["basic", "ecr", "acr", "gcr", "ghcr", "anonymous"],
              description: "Authentication type",
            },
            username: { type: "string", description: "Username for basic auth" },
            password: { type: "string", description: "Password for basic auth" },
            region: { type: "string", description: "AWS region for ECR" },
            accessKeyId: { type: "string", description: "AWS access key ID" },
            secretAccessKey: { type: "string", description: "AWS secret access key" },
            tenantId: { type: "string", description: "Azure tenant ID" },
            clientId: { type: "string", description: "Azure client ID" },
            clientSecret: { type: "string", description: "Azure client secret" },
            serviceAccountKey: {
              type: "string",
              description: "GCP service account key (JSON or base64)",
            },
            token: { type: "string", description: "GitHub token for GHCR" },
          },
        },
        isDefault: {
          type: "boolean",
          description: "Set as the default registry",
        },
        description: {
          type: "string",
          description: "Optional description",
        },
      },
      required: ["id", "name", "url"],
    },
  },
  {
    name: "registry_list_configs",
    description: "List all configured container registries",
    inputSchema: {
      type: "object",
      properties: {
        enabled: {
          type: "boolean",
          description: "Filter by enabled status",
        },
        type: {
          type: "string",
          enum: ["docker-registry", "harbor", "gitlab", "ecr", "acr", "gcr", "gar", "ghcr"],
          description: "Filter by registry type",
        },
      },
    },
  },
  {
    name: "registry_get_config",
    description: "Get a specific registry configuration by ID",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Registry configuration ID",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "registry_remove_config",
    description: "Remove a registry configuration",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Registry configuration ID to remove",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "registry_test_connection",
    description: "Test connectivity to a configured registry",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Registry configuration ID to test",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "registry_scan_multiple",
    description:
      "Scan images across multiple configured registries. Aggregates results from all registries into a unified report.",
    inputSchema: {
      type: "object",
      properties: {
        registries: {
          type: "array",
          items: { type: "string" },
          description: "Registry IDs or URLs to scan",
        },
        repositories: {
          type: "array",
          items: { type: "string" },
          description: "Filter repositories by glob patterns",
        },
        tagFilter: {
          type: "string",
          description: "Regex pattern to filter tags",
        },
        concurrency: {
          type: "number",
          description: "Number of parallel scans per registry (default: 3)",
        },
        severity: {
          type: "string",
          description: "Severity levels to report (default: HIGH,CRITICAL)",
        },
        limitPerRegistry: {
          type: "number",
          description: "Maximum images to scan per registry",
        },
        latestOnly: {
          type: "boolean",
          description: "Only scan 'latest' tags",
        },
        continueOnError: {
          type: "boolean",
          description: "Continue scanning other registries on error (default: true)",
        },
      },
      required: ["registries"],
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

  // Remediation Tools
  {
    name: "generate_remediations",
    description:
      "Generate remediation suggestions for vulnerabilities found in a Trivy scan. " +
      "Returns actionable fix commands for npm, pip, go, and other package managers.",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan and generate remediations for",
        },
        path: {
          type: "string",
          description: "Local path to scan and generate remediations for",
        },
        severity: {
          type: "string",
          description: "Severity filter for scan (default: HIGH,CRITICAL)",
        },
        minSeverity: {
          type: "string",
          enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
          description: "Minimum severity for remediation suggestions",
        },
        includeBreaking: {
          type: "boolean",
          description:
            "Include breaking changes (major version bumps) in suggestions (default: true)",
        },
        limit: {
          type: "number",
          description: "Maximum number of suggestions to return",
        },
        sortBy: {
          type: "string",
          enum: ["severity", "cvesFixed", "package"],
          description: "Sort order for suggestions (default: severity)",
        },
      },
    },
  },
  {
    name: "get_remediation_summary",
    description: "Get a text summary of remediation suggestions for a scanned image or path",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan",
        },
        path: {
          type: "string",
          description: "Local path to scan",
        },
        severity: {
          type: "string",
          description: "Severity filter for scan",
        },
      },
    },
  },
  {
    name: "get_remediation_markdown",
    description:
      "Get remediation suggestions formatted as Markdown, suitable for PRs or documentation",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan",
        },
        path: {
          type: "string",
          description: "Local path to scan",
        },
        severity: {
          type: "string",
          description: "Severity filter for scan",
        },
      },
    },
  },
  {
    name: "get_high_priority_fixes",
    description: "Get high-priority remediation suggestions (CRITICAL and HIGH severity only)",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan",
        },
        path: {
          type: "string",
          description: "Local path to scan",
        },
        limit: {
          type: "number",
          description: "Maximum number of suggestions (default: 10)",
        },
      },
    },
  },
  {
    name: "get_safe_fixes",
    description:
      "Get safe remediation suggestions (non-breaking changes only, sorted by CVEs fixed)",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan",
        },
        path: {
          type: "string",
          description: "Local path to scan",
        },
        limit: {
          type: "number",
          description: "Maximum number of suggestions (default: 20)",
        },
      },
    },
  },
  // ==========================================================================
  // Compliance Reporting Tools
  // ==========================================================================
  {
    name: "compliance_get_frameworks",
    description:
      "List all supported compliance frameworks (SOC2, HIPAA, PCI-DSS, CIS) with their control counts",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "compliance_get_controls",
    description:
      "Get all controls for a specific compliance framework with their requirements and SLAs",
    inputSchema: {
      type: "object",
      properties: {
        framework: {
          type: "string",
          enum: ["SOC2", "HIPAA", "PCI-DSS", "CIS"],
          description: "The compliance framework to get controls for",
        },
      },
      required: ["framework"],
    },
  },
  {
    name: "compliance_check_status",
    description:
      "Check compliance status against security scan results. Returns pass/fail status and violation counts.",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan for compliance check",
        },
        path: {
          type: "string",
          description: "Local path to scan for compliance check",
        },
        sonarProject: {
          type: "string",
          description: "SonarQube project key to include",
        },
        dtrackProjectUuid: {
          type: "string",
          description: "Dependency-Track project UUID to include",
        },
        frameworks: {
          type: "array",
          items: { type: "string", enum: ["SOC2", "HIPAA", "PCI-DSS", "CIS"] },
          description: "Frameworks to check (default: all)",
        },
        severity: {
          type: "string",
          description: "Severity filter (default: HIGH,CRITICAL)",
        },
      },
    },
  },
  {
    name: "compliance_generate_report",
    description:
      "Generate a compliance report mapping vulnerabilities to regulatory controls. Supports JSON and HTML output.",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan",
        },
        path: {
          type: "string",
          description: "Local path to scan",
        },
        sonarProject: {
          type: "string",
          description: "SonarQube project key to include",
        },
        dtrackProjectUuid: {
          type: "string",
          description: "Dependency-Track project UUID to include",
        },
        frameworks: {
          type: "array",
          items: { type: "string", enum: ["SOC2", "HIPAA", "PCI-DSS", "CIS"] },
          description: "Frameworks to include (default: all)",
        },
        format: {
          type: "string",
          enum: ["json", "html"],
          description: "Output format (default: json)",
        },
        title: {
          type: "string",
          description: "Report title",
        },
        organization: {
          type: "string",
          description: "Organization name for the report",
        },
        severity: {
          type: "string",
          description: "Severity filter (default: HIGH,CRITICAL)",
        },
      },
    },
  },
  {
    name: "compliance_trend_record",
    description:
      "Record a compliance trend snapshot for a target. Used to track compliance improvements over time.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target identifier (e.g., image name, project path)",
        },
        image: {
          type: "string",
          description: "Docker image to scan",
        },
        path: {
          type: "string",
          description: "Local path to scan",
        },
        sonarProject: {
          type: "string",
          description: "SonarQube project key",
        },
        dtrackProjectUuid: {
          type: "string",
          description: "Dependency-Track project UUID",
        },
        frameworks: {
          type: "array",
          items: { type: "string", enum: ["SOC2", "HIPAA", "PCI-DSS", "CIS"] },
          description: "Frameworks to track",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "compliance_trend_get",
    description:
      "Get compliance trend data for a target over a time period. Shows if compliance is improving or declining.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target identifier to get trends for",
        },
        days: {
          type: "number",
          description: "Number of days to look back (default: 30)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "compliance_trend_list_targets",
    description: "List all targets that have compliance trend data recorded",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  // ==========================================================================
  // OPA/Rego Policy Tools
  // ==========================================================================
  {
    name: "opa_list_policies",
    description:
      "List all available built-in OPA/Rego security policies. " +
      "Returns policy names, descriptions, entrypoints, and rule counts.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "opa_get_policy_info",
    description:
      "Get detailed information about a specific built-in OPA/Rego policy including its Rego source code.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description:
            "Policy name (e.g., 'vulnerability-threshold', 'license-compliance', 'secrets-detection', 'container-security', 'quality-gate')",
        },
      },
      required: ["name"],
    },
  },
  {
    name: "opa_validate_policy",
    description:
      "Validate Rego policy syntax. Checks for common syntax errors like missing package declarations, unbalanced braces, and missing rule definitions.",
    inputSchema: {
      type: "object",
      properties: {
        policy: {
          type: "string",
          description: "Rego policy source code to validate",
        },
      },
      required: ["policy"],
    },
  },
  {
    name: "opa_evaluate_policy",
    description:
      "Evaluate scan results against an OPA/Rego policy. " +
      "Can use a built-in policy name or provide inline Rego code. " +
      "Scans an image or path first, then evaluates the policy against the results.",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan before policy evaluation",
        },
        path: {
          type: "string",
          description: "Local path to scan before policy evaluation",
        },
        policy: {
          type: "string",
          description:
            "Policy name (built-in) or inline Rego code. " +
            "Built-in policies: 'vulnerability-threshold', 'license-compliance', 'secrets-detection', 'container-security', 'quality-gate'",
        },
        severity: {
          type: "string",
          description: "Severity filter for scan (default: HIGH,CRITICAL)",
        },
        thresholds: {
          type: "object",
          properties: {
            critical: { type: "number", description: "Max critical vulnerabilities" },
            high: { type: "number", description: "Max high vulnerabilities" },
            medium: { type: "number", description: "Max medium vulnerabilities" },
            low: { type: "number", description: "Max low vulnerabilities" },
            coverage: { type: "number", description: "Min code coverage percentage" },
          },
          description: "Threshold values for policy evaluation",
        },
        licenses: {
          type: "array",
          items: { type: "string" },
          description: "License identifiers to check (for license-compliance policy)",
        },
        secretsFound: {
          type: "boolean",
          description: "Whether secrets were found (for secrets-detection policy)",
        },
        codeCoverage: {
          type: "number",
          description: "Code coverage percentage (for quality-gate policy)",
        },
        qualityGatePassed: {
          type: "boolean",
          description: "Whether quality gate passed (for quality-gate policy)",
        },
      },
      required: ["policy"],
    },
  },
  // Vulnerability Database Tools
  {
    name: "vuln_db_sync",
    description:
      "Download and sync vulnerability database for offline scanning. " +
      "Downloads the Trivy vulnerability database to enable scanning without internet access.",
    inputSchema: {
      type: "object",
      properties: {
        force: {
          type: "boolean",
          description: "Force sync even if recently synced (default: false)",
        },
        skipIfRecent: {
          type: "number",
          description: "Skip sync if synced within this many hours (default: 24)",
        },
      },
    },
  },
  {
    name: "vuln_db_status",
    description:
      "Get status of the local vulnerability database including last sync time, version, and statistics.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "vuln_db_lookup",
    description: "Look up a specific vulnerability by CVE ID from the local database.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Vulnerability ID (e.g., CVE-2024-1234)",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "vuln_db_search",
    description:
      "Search vulnerabilities in the local database by package name, ecosystem, severity, or CVE pattern.",
    inputSchema: {
      type: "object",
      properties: {
        packageName: {
          type: "string",
          description: "Filter by package name (partial match)",
        },
        ecosystem: {
          type: "string",
          description: "Filter by ecosystem (npm, pypi, go, etc.)",
        },
        severity: {
          type: "array",
          items: { type: "string" },
          description: "Filter by severity levels (CRITICAL, HIGH, MEDIUM, LOW)",
        },
        cvePattern: {
          type: "string",
          description: "Filter by CVE pattern (partial match)",
        },
        limit: {
          type: "number",
          description: "Maximum results to return (default: 100)",
        },
        offset: {
          type: "number",
          description: "Offset for pagination",
        },
      },
    },
  },
  {
    name: "trivy_scan_offline",
    description:
      "Scan a Docker image or path using the locally cached vulnerability database. " +
      "Requires vuln_db_sync to be run first. Works without internet connectivity.",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest)",
        },
        path: {
          type: "string",
          description: "Local path to scan (alternative to image)",
        },
        severity: {
          type: "string",
          description: "Severity levels to report (default: HIGH,CRITICAL)",
        },
        ignoreUnfixed: {
          type: "boolean",
          description: "Ignore vulnerabilities without fixes (default: false)",
        },
      },
    },
  },
  {
    name: "vuln_db_annotate",
    description:
      "Annotate a vulnerability with a status and notes. " +
      "Use to mark vulnerabilities as false positives, acknowledged, or mitigated.",
    inputSchema: {
      type: "object",
      properties: {
        vulnId: {
          type: "string",
          description: "Vulnerability ID (e.g., CVE-2024-1234)",
        },
        status: {
          type: "string",
          enum: ["acknowledged", "false_positive", "mitigated", "active"],
          description: "Status to assign to the vulnerability",
        },
        notes: {
          type: "string",
          description: "Optional notes about the annotation",
        },
      },
      required: ["vulnId", "status"],
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

// Multi-registry handlers
const multiRegistryHandlers: Record<string, ToolHandler> = {
  registry_detect_type: async (args) => {
    const url = args?.url as string;
    if (!url) {
      return { error: "url is required" };
    }
    return detectRegistryType(url);
  },

  registry_configure: async (args) => {
    const id = args?.id as string;
    const name = args?.name as string;
    const url = args?.url as string;

    if (!id || !name || !url) {
      return { error: "id, name, and url are required" };
    }

    const auth = args?.auth as Record<string, unknown> | undefined;
    const detected = detectRegistryType(url);

    configureRegistry({
      id,
      name,
      url,
      type: (args?.type as CloudRegistryType) || detected.type,
      auth: auth as RegistryAuth | undefined,
      isDefault: args?.isDefault as boolean | undefined,
      description: args?.description as string | undefined,
      enabled: true,
    });

    return {
      success: true,
      message: `Registry '${name}' configured successfully`,
      detectedType: detected.type,
      confidence: detected.confidence,
    };
  },

  registry_list_configs: async (args) => {
    const configs = listRegistryConfigs({
      enabled: args?.enabled as boolean | undefined,
      type: args?.type as CloudRegistryType | undefined,
    });
    return { registries: configs, count: configs.length };
  },

  registry_get_config: async (args) => {
    const id = args?.id as string;
    if (!id) {
      return { error: "id is required" };
    }
    const registryConf = getRegistryConfig(id);
    if (!registryConf) {
      return { error: `Registry '${id}' not found` };
    }
    return registryConf;
  },

  registry_remove_config: async (args) => {
    const id = args?.id as string;
    if (!id) {
      return { error: "id is required" };
    }
    const removed = removeRegistryConfig(id);
    return {
      success: removed,
      message: removed ? `Registry '${id}' removed` : `Registry '${id}' not found`,
    };
  },

  registry_test_connection: async (args) => {
    const id = args?.id as string;
    if (!id) {
      return { error: "id is required" };
    }
    const registryConf = getRegistryConfig(id);
    if (!registryConf) {
      return { error: `Registry '${id}' not found` };
    }
    return testRegistryConnection(registryConf);
  },

  registry_scan_multiple: async (args) => {
    const registries = args?.registries as string[];
    if (!registries || registries.length === 0) {
      return { error: "registries array is required" };
    }
    return scanMultipleRegistries({
      registries,
      repositories: args?.repositories as string[] | undefined,
      tagFilter: args?.tagFilter as string | undefined,
      concurrency: args?.concurrency as number | undefined,
      severity: args?.severity as string | undefined,
      limitPerRegistry: args?.limitPerRegistry as number | undefined,
      latestOnly: args?.latestOnly as boolean | undefined,
      continueOnError: args?.continueOnError as boolean | undefined,
    });
  },
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

// Remediation handlers
const remediationHandlers: Record<string, ToolHandler> = {
  generate_remediations: async (args) => {
    const severity = (args?.severity as string) || "HIGH,CRITICAL";

    // Scan first
    let scanResult;
    if (args?.image) {
      scanResult = await trivyScanImage(args.image as string, severity);
    } else if (args?.path) {
      scanResult = await trivyScanPath(args.path as string, severity);
    } else {
      return { error: "Either image or path is required" };
    }

    if ("error" in scanResult) {
      return scanResult;
    }

    // Generate remediations
    const plan = generateRemediations(scanResult, {
      minSeverity: args?.minSeverity as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | undefined,
      includeBreaking: args?.includeBreaking as boolean | undefined,
      limit: args?.limit as number | undefined,
      sortBy: args?.sortBy as "severity" | "cvesFixed" | "package" | undefined,
    });

    return plan;
  },

  get_remediation_summary: async (args) => {
    const severity = (args?.severity as string) || "HIGH,CRITICAL";

    let scanResult;
    if (args?.image) {
      scanResult = await trivyScanImage(args.image as string, severity);
    } else if (args?.path) {
      scanResult = await trivyScanPath(args.path as string, severity);
    } else {
      return { error: "Either image or path is required" };
    }

    if ("error" in scanResult) {
      return scanResult;
    }

    const plan = generateRemediations(scanResult);
    return { summary: getRemediationSummary(plan) };
  },

  get_remediation_markdown: async (args) => {
    const severity = (args?.severity as string) || "HIGH,CRITICAL";

    let scanResult;
    if (args?.image) {
      scanResult = await trivyScanImage(args.image as string, severity);
    } else if (args?.path) {
      scanResult = await trivyScanPath(args.path as string, severity);
    } else {
      return { error: "Either image or path is required" };
    }

    if ("error" in scanResult) {
      return scanResult;
    }

    const plan = generateRemediations(scanResult);
    return { markdown: formatRemediationAsMarkdown(plan) };
  },

  get_high_priority_fixes: async (args) => {
    const limit = (args?.limit as number) || 10;

    let scanResult;
    if (args?.image) {
      scanResult = await trivyScanImage(args.image as string, "HIGH,CRITICAL");
    } else if (args?.path) {
      scanResult = await trivyScanPath(args.path as string, "HIGH,CRITICAL");
    } else {
      return { error: "Either image or path is required" };
    }

    if ("error" in scanResult) {
      return scanResult;
    }

    return getHighPriorityRemediations(scanResult, limit);
  },

  get_safe_fixes: async (args) => {
    const limit = (args?.limit as number) || 20;

    let scanResult;
    if (args?.image) {
      scanResult = await trivyScanImage(args.image as string, "HIGH,CRITICAL,MEDIUM,LOW");
    } else if (args?.path) {
      scanResult = await trivyScanPath(args.path as string, "HIGH,CRITICAL,MEDIUM,LOW");
    } else {
      return { error: "Either image or path is required" };
    }

    if ("error" in scanResult) {
      return scanResult;
    }

    return getSafeRemediations(scanResult, limit);
  },
};

// Compliance handlers
const complianceHandlers: Record<string, ToolHandler> = {
  compliance_get_frameworks: async () => {
    const frameworks = getComplianceFrameworks();
    return {
      frameworks: frameworks.map((f) => ({
        name: f,
        controlCount: getComplianceControls(f).length,
      })),
    };
  },

  compliance_get_controls: async (args) => {
    const framework = args?.framework as string;
    if (!framework) {
      return { error: "framework is required" };
    }
    const controls = getComplianceControls(framework as ComplianceFramework);
    return { framework, controls, count: controls.length };
  },

  compliance_check_status: async (args) => {
    const dashboardResult = await getSecurityDashboard({
      image: args?.image as string | undefined,
      path: args?.path as string | undefined,
      sonarProject: args?.sonarProject as string | undefined,
      dtrackProjectUuid: args?.dtrackProjectUuid as string | undefined,
      severity: (args?.severity as string) || "HIGH,CRITICAL",
    });

    return checkComplianceStatus(dashboardResult, {
      frameworks: args?.frameworks as ComplianceFramework[] | undefined,
    });
  },

  compliance_generate_report: async (args) => {
    const dashboardResult = await getSecurityDashboard({
      image: args?.image as string | undefined,
      path: args?.path as string | undefined,
      sonarProject: args?.sonarProject as string | undefined,
      dtrackProjectUuid: args?.dtrackProjectUuid as string | undefined,
      severity: (args?.severity as string) || "HIGH,CRITICAL",
    });

    const report = generateComplianceReport(dashboardResult, {
      frameworks: args?.frameworks as ("SOC2" | "HIPAA" | "PCI-DSS" | "CIS")[] | undefined,
      title: args?.title as string | undefined,
      organization: args?.organization as string | undefined,
    });

    if (args?.format === "html") {
      return {
        format: "html",
        html: generateComplianceHtml(report, {
          title: args?.title as string | undefined,
          organization: args?.organization as string | undefined,
        }),
        summary: report.summary,
      };
    }

    return report;
  },

  compliance_trend_record: async (args) => {
    const target = args?.target as string;
    if (!target) {
      return { error: "target is required" };
    }

    const dashboardResult = await getSecurityDashboard({
      image: args?.image as string | undefined,
      path: args?.path as string | undefined,
      sonarProject: args?.sonarProject as string | undefined,
      dtrackProjectUuid: args?.dtrackProjectUuid as string | undefined,
    });

    const report = generateComplianceReport(dashboardResult, {
      frameworks: args?.frameworks as ("SOC2" | "HIPAA" | "PCI-DSS" | "CIS")[] | undefined,
    });

    const entry = recordComplianceTrend(target, report);
    return { success: true, entry };
  },

  compliance_trend_get: async (args) => {
    const target = args?.target as string;
    if (!target) {
      return { error: "target is required" };
    }
    const days = (args?.days as number) || 30;
    return getComplianceTrend(target, days);
  },

  compliance_trend_list_targets: async () => {
    const targets = await import("@cicd/shared").then((m) => m.getComplianceTrendTargets());
    return { targets, count: targets.length };
  },
};

// OPA/Rego handlers
const opaHandlers: Record<string, ToolHandler> = {
  opa_list_policies: async () => {
    const policies = listBuiltinPolicies();
    return {
      count: policies.length,
      policies,
    };
  },

  opa_get_policy_info: async (args) => {
    const name = args?.name as string;
    if (!name) {
      return { error: "name is required" };
    }

    const info = getBuiltinPolicyInfo(name);
    if (!info) {
      return {
        error: `Policy '${name}' not found. Available policies: vulnerability-threshold, license-compliance, secrets-detection, container-security, quality-gate`,
      };
    }

    const source = getBuiltinPolicy(name);
    return {
      ...info,
      source: source,
    };
  },

  opa_validate_policy: async (args) => {
    const policy = args?.policy as string;
    if (!policy) {
      return { error: "policy is required" };
    }

    const result = validateRegoSyntax(policy);
    return result;
  },

  opa_evaluate_policy: async (args) => {
    const policy = args?.policy as string;
    if (!policy) {
      return { error: "policy is required" };
    }

    const severity = (args?.severity as string) || "HIGH,CRITICAL";
    let opaInput;

    // If image or path specified, scan first
    if (args?.image || args?.path) {
      let scanResult;
      if (args?.image) {
        scanResult = await trivyScanImage(args.image as string, severity);
      } else {
        scanResult = await trivyScanPath(args.path as string, severity);
      }

      if ("error" in scanResult) {
        return scanResult;
      }

      // Convert Trivy result to OPA input
      opaInput = trivyResultToOpaInput(
        scanResult,
        args?.image as string | undefined,
        args?.path as string | undefined
      );

      // Add additional fields from args
      if (args?.licenses) {
        opaInput.scan.licenses = args.licenses as string[];
      }
      if (args?.secretsFound !== undefined) {
        opaInput.scan.secretsFound = args.secretsFound as boolean;
      }
      if (args?.codeCoverage !== undefined) {
        opaInput.scan.codeCoverage = args.codeCoverage as number;
      }
      if (args?.qualityGatePassed !== undefined) {
        opaInput.scan.qualityGatePassed = args.qualityGatePassed as boolean;
      }
      if (args?.thresholds) {
        opaInput.thresholds = args.thresholds as {
          critical?: number;
          high?: number;
          medium?: number;
          low?: number;
          coverage?: number;
        };
      }
    } else {
      // Create OPA input from provided args (no scan)
      opaInput = createOpaInput({
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        licenses: args?.licenses as string[] | undefined,
        secretsFound: args?.secretsFound as boolean | undefined,
        codeCoverage: args?.codeCoverage as number | undefined,
        qualityGatePassed: args?.qualityGatePassed as boolean | undefined,
        image: args?.image as string | undefined,
        path: args?.path as string | undefined,
        thresholds: args?.thresholds as {
          critical?: number;
          high?: number;
          medium?: number;
          low?: number;
          coverage?: number;
        },
      });
    }

    // Evaluate the policy
    const result = await evaluateOpaPolicy(opaInput, { policy });
    return result;
  },
};

// Vulnerability Database handlers
const vulnDbHandlers: Record<string, ToolHandler> = {
  vuln_db_sync: async (args) => {
    // Initialize database if not already done
    if (!isVulnDbInitialized()) {
      const initResult = initVulnDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize database: ${initResult.error}` };
      }
    }

    const result = await syncVulnDatabase({
      force: args?.force as boolean | undefined,
      skipIfRecent: args?.skipIfRecent as number | undefined,
    });
    return result;
  },

  vuln_db_status: async () => {
    const trivyStatus = await getTrivyDbStatus();
    const offlineAvailable = await isOfflineScanAvailable();
    const capabilities = await getOfflineScanCapabilities();

    let dbStats = null;
    if (isVulnDbInitialized()) {
      dbStats = getVulnDbStats();
    }

    return {
      trivyDatabase: trivyStatus,
      offlineScanAvailable: offlineAvailable.available,
      capabilities,
      localCache: dbStats,
    };
  },

  vuln_db_lookup: async (args) => {
    const id = args?.id as string;
    if (!id) {
      return { error: "id is required" };
    }

    if (!isVulnDbInitialized()) {
      const initResult = initVulnDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize database: ${initResult.error}` };
      }
    }

    const vuln = lookupVulnerability(id);
    if (!vuln) {
      return { error: `Vulnerability ${id} not found in local database` };
    }

    return vuln;
  },

  vuln_db_search: async (args) => {
    if (!isVulnDbInitialized()) {
      const initResult = initVulnDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize database: ${initResult.error}` };
      }
    }

    const result = searchVulnerabilities({
      packageName: args?.packageName as string | undefined,
      ecosystem: args?.ecosystem as string | undefined,
      severity: args?.severity as string[] | undefined,
      cvePattern: args?.cvePattern as string | undefined,
      limit: args?.limit as number | undefined,
      offset: args?.offset as number | undefined,
    });

    return result;
  },

  trivy_scan_offline: async (args) => {
    const image = args?.image as string | undefined;
    const path = args?.path as string | undefined;

    if (!image && !path) {
      return { error: "Either image or path is required" };
    }

    const options = {
      severity: args?.severity as string | undefined,
      ignoreUnfixed: args?.ignoreUnfixed as boolean | undefined,
    };

    if (image) {
      return offlineScanImage(image, options as Parameters<typeof offlineScanImage>[1]);
    } else {
      return offlineScanPath(path!, options as Parameters<typeof offlineScanPath>[1]);
    }
  },

  vuln_db_annotate: async (args) => {
    const vulnId = args?.vulnId as string;
    const status = args?.status as "acknowledged" | "false_positive" | "mitigated" | "active";
    const notes = args?.notes as string | undefined;

    if (!vulnId) {
      return { error: "vulnId is required" };
    }
    if (!status) {
      return { error: "status is required" };
    }

    if (!isVulnDbInitialized()) {
      const initResult = initVulnDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize database: ${initResult.error}` };
      }
    }

    const result = annotateVulnerability(vulnId, status, notes);
    return result;
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
  ...multiRegistryHandlers,
  ...sarifHandlers,
  ...schedulerHandlers,
  ...remediationHandlers,
  ...complianceHandlers,
  ...opaHandlers,
  ...vulnDbHandlers,
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
