#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type {
  CloudRegistryType,
  ComplianceFramework,
  RegistryAuth,
  TrivyScanResult,
  PackageManager,
} from "@cicd/shared";
import { evaluatePolicyWithScan } from "@cicd/shared";
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
  // Redis Cache
  getRedisConfig,
  getTTLConfig,
  isRedisConnected,
  initDistributedCaches,
  getAllCacheStats,
  clearAllCaches,
  invalidateCacheByPattern,
  getCacheHealth,
  // Suppression Database
  initSuppressionDatabase,
  isSuppressionDbInitialized,
  createDbSuppression,
  getDbSuppression,
  listDbSuppressions,
  deleteDbSuppression,
  getSuppressionAuditLog,
  getSuppressionDbStats,
  applyDbSuppressions,
  // Prometheus Metrics
  getMetrics,
  getMetricsSnapshot,
  pushToGateway,
  deleteFromGateway,
  recordScanMetrics,
  resetMetrics,
  // Scan Comparison
  compareTrivyScans,
  getScanHistory,
  storeTrivyScan,
  storeAndCompare,
  // SSO Configuration
  initSsoDatabase,
  configureSamlProvider,
  configureOidcProvider,
  getSsoProvider,
  listSsoProviders,
  deleteSsoProvider,
  setSsoProviderEnabled,
  getSsoSession,
  validateSsoSession,
  terminateSsoSession,
  terminateAllUserSessions,
  listUserSessions,
  listAllSessions,
  cleanupExpiredSessions,
  getSsoAuditEvents,
  // SSO SAML
  generateSpMetadata,
  validateSamlAssertion,
  generateSamlLogoutRequest,
  // SSO OIDC
  validateOidcToken,
  validateOidcTokenByIssuer,
  refreshOidcToken,
  getOidcUserInfo,
  // RBAC
  initRbacDatabase,
  isRbacDbInitialized,
  createRole,
  getRoleByName,
  listRoles,
  listPermissions,
  assignRoleToUser,
  getUserRoles,
  checkPermission,
  listUserPermissions,
  // API Key Management
  VALID_SCOPES,
  initApiKeyDatabase,
  isApiKeyDbInitialized,
  createApiKey,
  listApiKeys,
  revokeApiKey,
  rotateApiKey,
  // Team Management
  initTeamDatabase,
  isTeamDbInitialized,
  createOrganization,
  createTeam,
  addTeamMember,
  listTeams,
  isTeamMember,
  hasTeamRole,
  getTeamMember,
  // Session Management
  initSessionDatabase,
  isSessionDbInitialized,
  listSessions,
  getSession,
  revokeSession,
  revokeAllUserSessions,
  getSessionStats,
  // Audit Trail
  initAuditDatabase,
  isAuditDbInitialized,
  searchAuditEvents,
  exportAuditLogs,
  getAuditStats,
  // Executive Dashboard
  initDashboardDatabase,
  isDashboardDbInitialized,
  getDashboardSummary,
  getHealthScore,
  getTopRisks,
  // Report Templates
  initReportDatabase,
  isReportDbInitialized,
  listTemplates,
  generateReport,
  createReportSchedule,
  // Trend Analysis
  initTrendDatabase,
  isTrendDbInitialized,
  getVulnerabilityHistory,
  getTrendForecast,
  detectTrendAnomalies,
  compareTrendPeriods,
  // Risk Scoring
  initRiskDatabase,
  isRiskDbInitialized,
  setRiskAssetConfig,
  calculateRiskScore,
  storeRiskScore,
  getPrioritizedList,
  type RiskAssetCriticality,
  type RiskExposureLevel,
  type RiskTier,
  // Report Export (PDF, Excel, CSV)
  exportReportToPdf,
  exportReportToExcel,
  exportVulnerabilitiesToCsv,
  type ReportData,
  // Comparison
  initComparisonDb,
  compareProjects,
  compareTeams,
  compareToBaseline,
  type EntityMetrics,
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
          description: String.raw`Regex pattern to filter tags (e.g., '^v\d+' for version tags)`,
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

  // Redis Cache Tools
  {
    name: "cache_init",
    description:
      "Initialize distributed caching with optional Redis backend. " +
      "Falls back to in-memory cache if Redis is unavailable.",
    inputSchema: {
      type: "object",
      properties: {
        useRedis: {
          type: "boolean",
          description: "Try to connect to Redis (default: true)",
          default: true,
        },
      },
    },
  },
  {
    name: "cache_status",
    description:
      "Get cache health and connection status. " +
      "Shows Redis connection state, latency, and memory cache availability.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "cache_stats",
    description:
      "Get cache statistics for all scan types (trivy, sonarqube, dtrack, registry). " +
      "Shows hits, misses, and hit rate.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "cache_clear",
    description: "Clear all cached data from all cache types.",
    inputSchema: {
      type: "object",
      properties: {
        confirm: {
          type: "boolean",
          description: "Must be true to confirm clearing all caches",
        },
      },
      required: ["confirm"],
    },
  },
  {
    name: "cache_invalidate",
    description:
      "Invalidate cache entries matching a pattern. " +
      "Use glob patterns like 'trivy:*' or 'sonarqube:project-*'.",
    inputSchema: {
      type: "object",
      properties: {
        pattern: {
          type: "string",
          description: "Glob pattern to match cache keys (e.g., 'trivy:*')",
        },
      },
      required: ["pattern"],
    },
  },
  {
    name: "cache_config",
    description:
      "Get current cache configuration including Redis settings and TTL values per scan type.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },

  // Suppression Management Tools
  {
    name: "suppression_create",
    description:
      "Create a new vulnerability suppression rule. Suppressions can target specific CVEs, packages, or file paths. Use to mark false positives or accepted risks with audit trail.",
    inputSchema: {
      type: "object",
      properties: {
        type: {
          type: "string",
          enum: ["cve", "package", "path"],
          description:
            "Type of suppression: 'cve' for specific CVE IDs, 'package' for package names, 'path' for file path patterns",
        },
        pattern: {
          type: "string",
          description:
            "Pattern to match. For CVE: 'CVE-2024-1234' or 'CVE-2024-*'. For package: 'lodash' or 'lodash@<4.17.21'. For path: 'src/legacy/*'",
        },
        reason: {
          type: "string",
          description:
            "Required justification for the suppression (e.g., 'False positive - not exploitable in our configuration')",
        },
        expires: {
          type: "string",
          description:
            "Optional ISO 8601 expiration date (e.g., '2025-03-01'). Suppression auto-expires after this date.",
        },
        createdBy: {
          type: "string",
          description: "User or team creating the suppression",
        },
        notes: {
          type: "string",
          description: "Additional notes or context",
        },
      },
      required: ["type", "pattern", "reason"],
    },
  },
  {
    name: "suppression_list",
    description:
      "List all active vulnerability suppressions with optional filters. Returns suppressions from the database with their status and metadata.",
    inputSchema: {
      type: "object",
      properties: {
        type: {
          type: "string",
          enum: ["cve", "package", "path"],
          description: "Filter by suppression type",
        },
        status: {
          type: "string",
          enum: ["active", "expired"],
          description: "Filter by status (default: active)",
        },
        pattern: {
          type: "string",
          description: "Filter by pattern (partial match)",
        },
        createdBy: {
          type: "string",
          description: "Filter by creator",
        },
        includeExpired: {
          type: "boolean",
          description: "Include expired suppressions (default: false)",
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
    name: "suppression_delete",
    description:
      "Delete (soft-delete) a suppression rule by ID. The suppression is marked as deleted and remains in the audit trail.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Suppression ID to delete",
        },
        deletedBy: {
          type: "string",
          description: "User performing the deletion",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "suppression_audit",
    description:
      "Get the audit log for suppressions. Shows history of all suppression actions including creation, application, and deletion.",
    inputSchema: {
      type: "object",
      properties: {
        suppressionId: {
          type: "string",
          description: "Filter by specific suppression ID",
        },
        action: {
          type: "string",
          enum: ["created", "updated", "deleted", "applied", "expired"],
          description: "Filter by action type",
        },
        user: {
          type: "string",
          description: "Filter by user",
        },
        since: {
          type: "string",
          description: "Show entries since this ISO 8601 date",
        },
        until: {
          type: "string",
          description: "Show entries until this ISO 8601 date",
        },
        limit: {
          type: "number",
          description: "Maximum entries to return (default: 100)",
        },
      },
    },
  },
  {
    name: "suppression_apply",
    description:
      "Apply all active suppressions to a Trivy scan result. Returns filtered results with suppressed vulnerabilities removed and a summary of what was suppressed.",
    inputSchema: {
      type: "object",
      properties: {
        scanResult: {
          type: "object",
          description: "Trivy scan result object to filter",
        },
        includeExpired: {
          type: "boolean",
          description: "Include expired suppressions (default: false)",
        },
        user: {
          type: "string",
          description: "User applying suppressions (for audit)",
        },
        audit: {
          type: "boolean",
          description: "Log suppression applications to audit trail (default: true)",
        },
      },
      required: ["scanResult"],
    },
  },

  // Prometheus Metrics Tools
  {
    name: "metrics_get",
    description:
      "Get current metrics in Prometheus exposition format. Returns all collected scan metrics, vulnerability counts, cache stats, and circuit breaker states formatted for Prometheus scraping.",
    inputSchema: {
      type: "object",
      properties: {
        format: {
          type: "string",
          enum: ["prometheus", "json"],
          description:
            "Output format: 'prometheus' for exposition format (default), 'json' for raw snapshot",
        },
      },
    },
  },
  {
    name: "metrics_record_scan",
    description:
      "Record metrics from a security scan. Call this after each scan to track scan duration, success/failure rates, and vulnerability counts.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Scan target (image name or path)",
        },
        type: {
          type: "string",
          enum: ["image", "path"],
          description: "Type of scan performed",
        },
        durationSeconds: {
          type: "number",
          description: "Scan duration in seconds",
        },
        success: {
          type: "boolean",
          description: "Whether the scan succeeded",
        },
        vulnerabilities: {
          type: "object",
          description: "Vulnerability counts by severity",
          properties: {
            critical: { type: "number" },
            high: { type: "number" },
            medium: { type: "number" },
            low: { type: "number" },
          },
        },
        error: {
          type: "string",
          description: "Error message if scan failed",
        },
      },
      required: ["target", "type", "durationSeconds", "success"],
    },
  },
  {
    name: "metrics_push",
    description:
      "Push current metrics to a Prometheus Pushgateway. Use this to send metrics to a central monitoring system in environments where Prometheus cannot scrape directly.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Pushgateway URL (e.g., http://pushgateway:9091)",
        },
        job: {
          type: "string",
          description: "Job name for grouping metrics",
        },
        instance: {
          type: "string",
          description: "Instance label for identifying the source",
        },
        username: {
          type: "string",
          description: "Basic auth username (if required)",
        },
        password: {
          type: "string",
          description: "Basic auth password (if required)",
        },
        labels: {
          type: "object",
          description: "Additional labels to add to all metrics",
          additionalProperties: { type: "string" },
        },
      },
      required: ["url", "job"],
    },
  },
  {
    name: "metrics_delete",
    description:
      "Delete metrics from a Prometheus Pushgateway. Removes all metrics for a specific job/instance combination.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Pushgateway URL",
        },
        job: {
          type: "string",
          description: "Job name to delete",
        },
        instance: {
          type: "string",
          description: "Instance label to delete",
        },
        username: {
          type: "string",
          description: "Basic auth username (if required)",
        },
        password: {
          type: "string",
          description: "Basic auth password (if required)",
        },
      },
      required: ["url", "job"],
    },
  },
  {
    name: "metrics_reset",
    description:
      "Reset all collected metrics. Clears all counters, gauges, and histograms. Useful for testing or when restarting metric collection.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },

  // Scan Comparison Tools
  {
    name: "scan_compare",
    description:
      "Compare two Trivy scan results to identify new, fixed, and unchanged vulnerabilities. Uses fingerprinting to reliably track vulnerabilities across scans.",
    inputSchema: {
      type: "object",
      properties: {
        current: {
          type: "object",
          description: "Current Trivy scan result object",
        },
        baseline: {
          type: "object",
          description: "Baseline Trivy scan result to compare against",
        },
        minSeverity: {
          type: "string",
          enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
          description: "Minimum severity to include in comparison (default: all)",
        },
        includeUnchanged: {
          type: "boolean",
          description: "Include unchanged vulnerabilities in results (default: true)",
        },
      },
      required: ["current", "baseline"],
    },
  },
  {
    name: "scan_store",
    description:
      "Store a Trivy scan result in history for later comparison. Scans are stored per-target and can be compared using scan_compare_with_previous.",
    inputSchema: {
      type: "object",
      properties: {
        scanResult: {
          type: "object",
          description: "Trivy scan result object to store",
        },
        identifier: {
          type: "string",
          description: "Optional identifier (e.g., git commit, version, branch)",
        },
      },
      required: ["scanResult"],
    },
  },
  {
    name: "scan_compare_with_previous",
    description:
      "Compare a current scan with the most recent stored scan for the same target. Automatically stores the current scan after comparison.",
    inputSchema: {
      type: "object",
      properties: {
        scanResult: {
          type: "object",
          description: "Current Trivy scan result object",
        },
        identifier: {
          type: "string",
          description: "Optional identifier for this scan (e.g., git commit)",
        },
        minSeverity: {
          type: "string",
          enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
          description: "Minimum severity to include in comparison",
        },
        includeUnchanged: {
          type: "boolean",
          description: "Include unchanged vulnerabilities in results (default: true)",
        },
      },
      required: ["scanResult"],
    },
  },
  {
    name: "scan_history_list",
    description:
      "List stored scan records for a target. Returns scan metadata and vulnerability summaries.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target name (image or path) to get history for",
        },
        limit: {
          type: "number",
          description: "Maximum number of records to return (default: 10)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "scan_history_get",
    description:
      "Get a specific stored scan record by ID. Returns full scan details including all fingerprinted vulnerabilities.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Scan record ID to retrieve",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "scan_history_clear",
    description: "Clear scan history. Can clear all history or just for a specific target.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target to clear history for. If not provided, clears all history.",
        },
      },
    },
  },
  {
    name: "scan_history_targets",
    description: "List all targets that have stored scan history.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  // SSO Tools
  {
    name: "sso_init_database",
    description:
      "Initialize the SSO database for storing provider configurations and sessions. Call this before using other SSO tools.",
    inputSchema: {
      type: "object",
      properties: {
        dbPath: {
          type: "string",
          description:
            "Optional path for the SQLite database file. Defaults to sso.db in current directory.",
        },
      },
    },
  },
  {
    name: "sso_configure_saml",
    description:
      "Configure a SAML 2.0 identity provider. Stores IDP certificate, SSO URL, and attribute mappings.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Unique identifier for this provider",
        },
        name: {
          type: "string",
          description: "Display name for the provider (e.g., 'Corporate ADFS')",
        },
        idpCertificate: {
          type: "string",
          description: "X.509 certificate from the IdP for signature validation (PEM format)",
        },
        idpSsoUrl: {
          type: "string",
          description: "IdP Single Sign-On URL where SAML requests are sent",
        },
        idpSloUrl: {
          type: "string",
          description: "Optional IdP Single Logout URL",
        },
        spEntityId: {
          type: "string",
          description: "Service Provider Entity ID (your application identifier)",
        },
        spAcsUrl: {
          type: "string",
          description: "Assertion Consumer Service URL where SAML responses are received",
        },
        attributeMapping: {
          type: "object",
          description: "Mapping of SAML attributes to user properties",
          properties: {
            email: { type: "string", description: "Attribute name for email" },
            name: { type: "string", description: "Attribute name for display name" },
            groups: { type: "string", description: "Attribute name for group membership" },
          },
        },
        wantAssertionsSigned: {
          type: "boolean",
          description: "Require signed assertions (default: true)",
        },
      },
      required: ["id", "name", "idpCertificate", "idpSsoUrl", "spEntityId", "spAcsUrl"],
    },
  },
  {
    name: "sso_configure_oidc",
    description:
      "Configure an OpenID Connect identity provider. Stores client credentials and discovery settings.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Unique identifier for this provider",
        },
        name: {
          type: "string",
          description: "Display name for the provider (e.g., 'Google Workspace')",
        },
        issuer: {
          type: "string",
          description: "OIDC issuer URL (e.g., https://accounts.google.com)",
        },
        clientId: {
          type: "string",
          description: "OAuth 2.0 client ID",
        },
        clientSecret: {
          type: "string",
          description: "OAuth 2.0 client secret",
        },
        redirectUri: {
          type: "string",
          description: "Callback URL for OAuth flow",
        },
        scopes: {
          type: "array",
          items: { type: "string" },
          description: "OAuth scopes to request (default: openid, profile, email)",
        },
        discoveryUrl: {
          type: "string",
          description:
            "Optional discovery URL (defaults to issuer/.well-known/openid-configuration)",
        },
        attributeMapping: {
          type: "object",
          description: "Mapping of OIDC claims to user properties",
          properties: {
            email: { type: "string" },
            name: { type: "string" },
            groups: { type: "string" },
          },
        },
      },
      required: ["id", "name", "issuer", "clientId", "clientSecret", "redirectUri"],
    },
  },
  {
    name: "sso_list_providers",
    description: "List all configured SSO providers (SAML and OIDC).",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "sso_get_provider",
    description: "Get detailed configuration for a specific SSO provider.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Provider ID to retrieve",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "sso_delete_provider",
    description: "Delete an SSO provider configuration.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Provider ID to delete",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "sso_set_provider_enabled",
    description: "Enable or disable an SSO provider.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Provider ID",
        },
        enabled: {
          type: "boolean",
          description: "Whether to enable or disable the provider",
        },
      },
      required: ["id", "enabled"],
    },
  },
  {
    name: "sso_get_metadata",
    description:
      "Generate SAML Service Provider metadata XML for configuring your IdP. Returns the SP entity ID and ACS URL.",
    inputSchema: {
      type: "object",
      properties: {
        providerId: {
          type: "string",
          description: "SAML provider ID to generate metadata for",
        },
      },
      required: ["providerId"],
    },
  },
  {
    name: "sso_validate_saml",
    description:
      "Validate a SAML assertion and create a session. The assertion should be the Base64-encoded SAMLResponse.",
    inputSchema: {
      type: "object",
      properties: {
        providerId: {
          type: "string",
          description: "SAML provider ID",
        },
        samlResponse: {
          type: "string",
          description: "Base64-encoded SAML response from IdP",
        },
        ipAddress: {
          type: "string",
          description: "Optional IP address for audit logging",
        },
        userAgent: {
          type: "string",
          description: "Optional user agent for audit logging",
        },
      },
      required: ["providerId", "samlResponse"],
    },
  },
  {
    name: "sso_validate_oidc",
    description: "Validate an OIDC token (ID token or access token) and create a session.",
    inputSchema: {
      type: "object",
      properties: {
        providerId: {
          type: "string",
          description: "OIDC provider ID",
        },
        token: {
          type: "string",
          description: "JWT token to validate",
        },
        tokenType: {
          type: "string",
          enum: ["id_token", "access_token"],
          description: "Type of token being validated (default: id_token)",
        },
        nonce: {
          type: "string",
          description: "Optional nonce to verify against token claims",
        },
        ipAddress: {
          type: "string",
          description: "Optional IP address for audit logging",
        },
        userAgent: {
          type: "string",
          description: "Optional user agent for audit logging",
        },
      },
      required: ["providerId", "token"],
    },
  },
  {
    name: "sso_validate_token_by_issuer",
    description:
      "Validate an OIDC token by automatically detecting the provider from the issuer claim.",
    inputSchema: {
      type: "object",
      properties: {
        token: {
          type: "string",
          description: "JWT token to validate",
        },
        tokenType: {
          type: "string",
          enum: ["id_token", "access_token"],
          description: "Type of token being validated (default: id_token)",
        },
      },
      required: ["token"],
    },
  },
  {
    name: "sso_refresh_token",
    description: "Refresh an OIDC access token using a refresh token.",
    inputSchema: {
      type: "object",
      properties: {
        providerId: {
          type: "string",
          description: "OIDC provider ID",
        },
        refreshToken: {
          type: "string",
          description: "Refresh token from previous authentication",
        },
      },
      required: ["providerId", "refreshToken"],
    },
  },
  {
    name: "sso_get_user_info",
    description: "Get user information from the OIDC userinfo endpoint.",
    inputSchema: {
      type: "object",
      properties: {
        providerId: {
          type: "string",
          description: "OIDC provider ID",
        },
        accessToken: {
          type: "string",
          description: "Access token for the user",
        },
      },
      required: ["providerId", "accessToken"],
    },
  },
  {
    name: "sso_get_session",
    description: "Get details of an SSO session by ID.",
    inputSchema: {
      type: "object",
      properties: {
        sessionId: {
          type: "string",
          description: "Session ID to retrieve",
        },
      },
      required: ["sessionId"],
    },
  },
  {
    name: "sso_validate_session",
    description: "Check if an SSO session is still valid (not expired).",
    inputSchema: {
      type: "object",
      properties: {
        sessionId: {
          type: "string",
          description: "Session ID to validate",
        },
      },
      required: ["sessionId"],
    },
  },
  {
    name: "sso_logout",
    description: "Terminate an SSO session. For SAML, can generate a logout request.",
    inputSchema: {
      type: "object",
      properties: {
        sessionId: {
          type: "string",
          description: "Session ID to terminate",
        },
        generateLogoutRequest: {
          type: "boolean",
          description: "For SAML sessions, generate an IdP logout request URL",
        },
      },
      required: ["sessionId"],
    },
  },
  {
    name: "sso_logout_user",
    description: "Terminate all sessions for a specific user across all providers.",
    inputSchema: {
      type: "object",
      properties: {
        userId: {
          type: "string",
          description: "User ID to logout",
        },
      },
      required: ["userId"],
    },
  },
  {
    name: "sso_list_sessions",
    description: "List active SSO sessions. Can filter by user.",
    inputSchema: {
      type: "object",
      properties: {
        userId: {
          type: "string",
          description: "Optional user ID to filter by",
        },
        includeExpired: {
          type: "boolean",
          description: "Include expired sessions (default: false)",
        },
      },
    },
  },
  {
    name: "sso_cleanup_sessions",
    description: "Remove expired SSO sessions from the database.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "sso_get_audit_log",
    description: "Get SSO audit events for security monitoring.",
    inputSchema: {
      type: "object",
      properties: {
        userId: {
          type: "string",
          description: "Filter by user ID",
        },
        providerId: {
          type: "string",
          description: "Filter by provider ID",
        },
        eventType: {
          type: "string",
          enum: [
            "LOGIN",
            "LOGOUT",
            "TOKEN_REFRESH",
            "TOKEN_VALIDATION",
            "CONFIG_CHANGE",
            "SESSION_EXPIRED",
          ],
          description: "Filter by event type",
        },
        status: {
          type: "string",
          enum: ["SUCCESS", "FAILURE"],
          description: "Filter by status",
        },
        limit: {
          type: "number",
          description: "Maximum number of events to return (default: 100)",
        },
      },
    },
  },

  // RBAC Tools
  {
    name: "rbac_create_role",
    description:
      "Create a custom RBAC role with specified permissions. Predefined roles (Admin, Auditor, Developer, Viewer) are created automatically on database initialization.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Unique name for the role",
        },
        description: {
          type: "string",
          description: "Description of the role's purpose",
        },
        permissions: {
          type: "array",
          items: { type: "string" },
          description:
            "List of permission names to grant (e.g., scan:read, scan:execute, report:generate). Use rbac_list_roles to see available permissions.",
        },
      },
      required: ["name"],
    },
  },
  {
    name: "rbac_list_roles",
    description:
      "List all RBAC roles and available permissions. Returns predefined roles (Admin, Auditor, Developer, Viewer) plus any custom roles.",
    inputSchema: {
      type: "object",
      properties: {
        includePermissions: {
          type: "boolean",
          description: "Include permissions for each role (default: true)",
          default: true,
        },
      },
    },
  },
  {
    name: "rbac_assign_role",
    description:
      "Assign an RBAC role to a user. Optionally set an expiration date for temporary access.",
    inputSchema: {
      type: "object",
      properties: {
        userId: {
          type: "string",
          description: "User ID to assign the role to (e.g., SSO user ID or email)",
        },
        roleName: {
          type: "string",
          description: "Name of the role to assign (e.g., Admin, Developer, Viewer)",
        },
        expiresAt: {
          type: "string",
          description: "Optional ISO 8601 expiration date for temporary access",
        },
      },
      required: ["userId", "roleName"],
    },
  },
  {
    name: "rbac_check_permission",
    description:
      "Check if a user has a specific permission. Returns whether allowed and which role granted it.",
    inputSchema: {
      type: "object",
      properties: {
        userId: {
          type: "string",
          description: "User ID to check",
        },
        permission: {
          type: "string",
          description: "Permission to check (e.g., scan:execute, report:read, system:admin)",
        },
      },
      required: ["userId", "permission"],
    },
  },
  {
    name: "rbac_list_user_permissions",
    description: "List all effective permissions for a user based on their assigned roles.",
    inputSchema: {
      type: "object",
      properties: {
        userId: {
          type: "string",
          description: "User ID to get permissions for",
        },
      },
      required: ["userId"],
    },
  },

  // =========================================================================
  // API Key Management Tools
  // =========================================================================
  {
    name: "apikey_create",
    description:
      "Create a new API key with specified scopes and expiration. Returns the full key only once at creation time.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Human-readable name for the API key",
        },
        description: {
          type: "string",
          description: "Optional description of the key's purpose",
        },
        scopes: {
          type: "array",
          items: {
            type: "string",
            enum: [
              "scan:read",
              "scan:write",
              "policy:read",
              "policy:write",
              "suppression:read",
              "suppression:write",
              "report:read",
              "report:write",
              "admin:*",
            ],
          },
          description: "Scopes to grant to the key",
        },
        expiresInDays: {
          type: "number",
          description: "Days until expiration (default: 90)",
        },
        createdBy: {
          type: "string",
          description: "User ID creating the key",
        },
        rateLimit: {
          type: "number",
          description: "Rate limit in requests per minute (default: 100)",
        },
        ipAllowlist: {
          type: "array",
          items: { type: "string" },
          description: "Optional list of allowed IP addresses",
        },
      },
      required: ["name", "scopes", "createdBy"],
    },
  },
  {
    name: "apikey_list",
    description:
      "List all API keys (masked for security). Shows key prefix, scopes, status, and expiration.",
    inputSchema: {
      type: "object",
      properties: {
        status: {
          type: "string",
          enum: ["active", "revoked", "expired"],
          description: "Filter by status",
        },
        createdBy: {
          type: "string",
          description: "Filter by creator",
        },
        includeExpired: {
          type: "boolean",
          description: "Include expired keys (default: false)",
        },
      },
    },
  },
  {
    name: "apikey_revoke",
    description:
      "Revoke an API key immediately. The key will no longer be valid for authentication.",
    inputSchema: {
      type: "object",
      properties: {
        keyId: {
          type: "string",
          description: "ID of the API key to revoke",
        },
        actorId: {
          type: "string",
          description: "User ID performing the revocation (for audit)",
        },
      },
      required: ["keyId"],
    },
  },
  {
    name: "apikey_rotate",
    description:
      "Rotate an API key, generating a new key while preserving the ID and settings. Returns the new key only once.",
    inputSchema: {
      type: "object",
      properties: {
        keyId: {
          type: "string",
          description: "ID of the API key to rotate",
        },
        actorId: {
          type: "string",
          description: "User ID performing the rotation (for audit)",
        },
      },
      required: ["keyId"],
    },
  },
  // =========================================================================
  // Team Management Tools
  // =========================================================================
  {
    name: "team_create_org",
    description:
      "Create a new organization. Organizations contain teams and have settings like max teams and members per team.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Unique organization name (slug format, lowercase, no spaces)",
        },
        displayName: {
          type: "string",
          description: "Human-readable display name",
        },
        description: {
          type: "string",
          description: "Organization description",
        },
        ownerId: {
          type: "string",
          description: "User ID of the organization owner",
        },
        maxTeams: {
          type: "number",
          description: "Maximum number of teams allowed (default: 100)",
        },
        maxMembersPerTeam: {
          type: "number",
          description: "Maximum members per team (default: 100)",
        },
      },
      required: ["name", "ownerId"],
    },
  },
  {
    name: "team_create_team",
    description:
      "Create a new team within an organization. Teams group users together for access control.",
    inputSchema: {
      type: "object",
      properties: {
        organizationId: {
          type: "string",
          description: "ID of the organization to create the team in",
        },
        name: {
          type: "string",
          description: "Unique team name within the organization (slug format)",
        },
        displayName: {
          type: "string",
          description: "Human-readable display name",
        },
        description: {
          type: "string",
          description: "Team description",
        },
        visibility: {
          type: "string",
          enum: ["public", "private"],
          description: "Team visibility (default: private)",
        },
        createdBy: {
          type: "string",
          description: "User ID of the creator (for audit)",
        },
      },
      required: ["organizationId", "name"],
    },
  },
  {
    name: "team_add_member",
    description:
      "Add a user as a member of a team with a specific role. Roles: owner, admin, member, viewer.",
    inputSchema: {
      type: "object",
      properties: {
        teamId: {
          type: "string",
          description: "ID of the team",
        },
        userId: {
          type: "string",
          description: "ID of the user to add",
        },
        role: {
          type: "string",
          enum: ["owner", "admin", "member", "viewer"],
          description: "Member role (default: member)",
        },
        addedBy: {
          type: "string",
          description: "User ID of who is adding the member (for audit)",
        },
        expiresAt: {
          type: "string",
          description: "ISO date when membership expires (optional)",
        },
      },
      required: ["teamId", "userId"],
    },
  },
  {
    name: "team_list_teams",
    description:
      "List teams with optional filtering. Can filter by organization, visibility, or search by name.",
    inputSchema: {
      type: "object",
      properties: {
        organizationId: {
          type: "string",
          description: "Filter by organization ID",
        },
        visibility: {
          type: "string",
          enum: ["public", "private"],
          description: "Filter by visibility",
        },
        search: {
          type: "string",
          description: "Search by team name",
        },
        includeStats: {
          type: "boolean",
          description: "Include member count statistics (default: false)",
        },
        limit: {
          type: "number",
          description: "Maximum results to return",
        },
        offset: {
          type: "number",
          description: "Results offset for pagination",
        },
      },
    },
  },
  {
    name: "team_check_membership",
    description:
      "Check if a user is a member of a team and optionally verify they have a specific role or higher.",
    inputSchema: {
      type: "object",
      properties: {
        teamId: {
          type: "string",
          description: "ID of the team",
        },
        userId: {
          type: "string",
          description: "ID of the user to check",
        },
        requiredRole: {
          type: "string",
          enum: ["owner", "admin", "member", "viewer"],
          description: "Minimum role required (checks if user has this role or higher)",
        },
      },
      required: ["teamId", "userId"],
    },
  },
  // =============================================================================
  // Session Management Tools
  // =============================================================================
  {
    name: "session_list",
    description:
      "List active sessions for a user or all users. Returns session details including device info, IP address, and last activity.",
    inputSchema: {
      type: "object",
      properties: {
        userId: {
          type: "string",
          description: "Filter sessions by user ID (optional - lists all if not provided)",
        },
        activeOnly: {
          type: "boolean",
          description: "Only return active sessions (default: true)",
        },
        includeExpired: {
          type: "boolean",
          description: "Include expired sessions in results (default: false)",
        },
        limit: {
          type: "number",
          description: "Maximum number of sessions to return",
        },
        offset: {
          type: "number",
          description: "Results offset for pagination",
        },
      },
    },
  },
  {
    name: "session_revoke",
    description:
      "Revoke a specific session, immediately invalidating all associated tokens. The user will be forced to re-authenticate.",
    inputSchema: {
      type: "object",
      properties: {
        sessionId: {
          type: "string",
          description: "ID of the session to revoke",
        },
        reason: {
          type: "string",
          description: "Reason for revoking the session (for audit logging)",
        },
      },
      required: ["sessionId"],
    },
  },
  {
    name: "session_revoke_all",
    description:
      "Revoke all sessions for a user, forcing them to re-authenticate on all devices. Useful for security incidents or password changes.",
    inputSchema: {
      type: "object",
      properties: {
        userId: {
          type: "string",
          description: "ID of the user whose sessions should be revoked",
        },
        reason: {
          type: "string",
          description: "Reason for revoking all sessions (for audit logging)",
        },
      },
      required: ["userId"],
    },
  },
  // =============================================================================
  // Audit Trail Tools
  // =============================================================================
  {
    name: "audit_search",
    description:
      "Search audit logs with filters. Supports filtering by actor, action, resource, outcome, and time range. Returns matching audit events for compliance and forensics.",
    inputSchema: {
      type: "object",
      properties: {
        actorId: {
          type: "string",
          description: "Filter by actor ID (user ID, API key ID, or 'system')",
        },
        actorType: {
          type: "string",
          enum: ["user", "apikey", "system"],
          description: "Filter by actor type",
        },
        action: {
          type: "string",
          description: "Filter by specific action (e.g., 'auth.login', 'scan.triggered')",
        },
        actionCategory: {
          type: "string",
          enum: [
            "authentication",
            "authorization",
            "scan",
            "policy",
            "suppression",
            "admin",
            "data",
          ],
          description: "Filter by action category",
        },
        resourceType: {
          type: "string",
          description: "Filter by resource type (e.g., 'user', 'image', 'scan')",
        },
        resourceId: {
          type: "string",
          description: "Filter by resource ID",
        },
        outcome: {
          type: "string",
          enum: ["success", "failure"],
          description: "Filter by outcome",
        },
        startTime: {
          type: "string",
          description: "Filter events after this ISO timestamp",
        },
        endTime: {
          type: "string",
          description: "Filter events before this ISO timestamp",
        },
        query: {
          type: "string",
          description: "Full-text search query across event fields",
        },
        limit: {
          type: "number",
          description: "Maximum events to return (default: 100)",
        },
        offset: {
          type: "number",
          description: "Offset for pagination",
        },
      },
    },
  },
  {
    name: "audit_export",
    description:
      "Export audit logs to JSON, CSV, or NDJSON format. Supports the same filters as audit_search. Useful for compliance reporting and SIEM integration.",
    inputSchema: {
      type: "object",
      properties: {
        format: {
          type: "string",
          enum: ["json", "csv", "ndjson"],
          description: "Export format (default: json)",
        },
        actorId: {
          type: "string",
          description: "Filter by actor ID",
        },
        actorType: {
          type: "string",
          enum: ["user", "apikey", "system"],
          description: "Filter by actor type",
        },
        actionCategory: {
          type: "string",
          enum: [
            "authentication",
            "authorization",
            "scan",
            "policy",
            "suppression",
            "admin",
            "data",
          ],
          description: "Filter by action category",
        },
        outcome: {
          type: "string",
          enum: ["success", "failure"],
          description: "Filter by outcome",
        },
        startTime: {
          type: "string",
          description: "Filter events after this ISO timestamp",
        },
        endTime: {
          type: "string",
          description: "Filter events before this ISO timestamp",
        },
        includeChecksum: {
          type: "boolean",
          description: "Include tamper-detection checksum in export (default: false)",
        },
        outputPath: {
          type: "string",
          description: "Write to file path instead of returning data",
        },
      },
    },
  },
  {
    name: "audit_stats",
    description:
      "Get audit log statistics including event counts by outcome, category, actor type, and time periods. Also reports tamper detection status.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  // =========================================================================
  // Executive Dashboard Tools
  // =========================================================================
  {
    name: "dashboard_get_summary",
    description:
      "Get executive dashboard summary with health score, vulnerability counts, compliance status, top risks, MTTR metrics, and scan coverage. Provides a comprehensive security posture overview.",
    inputSchema: {
      type: "object",
      properties: {
        timeRange: {
          type: "string",
          enum: ["24h", "7d", "30d", "90d"],
          description: "Time range for dashboard data (default: 30d)",
        },
      },
    },
  },
  {
    name: "dashboard_get_health_score",
    description:
      "Get overall security health score (0-100) with grade (A-F), component breakdown (vulnerability, compliance, coverage, remediation scores), and trend compared to previous period.",
    inputSchema: {
      type: "object",
      properties: {
        timeRange: {
          type: "string",
          enum: ["24h", "7d", "30d", "90d"],
          description: "Time range for health score calculation (default: 30d)",
        },
      },
    },
  },
  {
    name: "dashboard_get_top_risks",
    description:
      "Get top N riskiest projects/images based on vulnerability severity weighted by asset criticality. Returns risk scores, vulnerability counts, and days since last scan.",
    inputSchema: {
      type: "object",
      properties: {
        count: {
          type: "number",
          description: "Number of top risks to return (default: 10)",
        },
      },
    },
  },
  // =========================================================================
  // Report Templates Tools
  // =========================================================================
  {
    name: "report_list_templates",
    description:
      "List available report templates including built-in templates (Executive Summary, Technical Detail, Compliance Audit, Trend Analysis, Vulnerability List) and custom templates.",
    inputSchema: {
      type: "object",
      properties: {
        includeBuiltin: {
          type: "boolean",
          description: "Include built-in templates (default: true)",
        },
        format: {
          type: "string",
          enum: ["html", "markdown", "json"],
          description: "Filter by output format",
        },
      },
    },
  },
  {
    name: "report_generate",
    description:
      "Generate a security report from a template. Supports HTML, Markdown, and JSON output formats. Reports include sections like health score, vulnerability summary, compliance status, and top risks.",
    inputSchema: {
      type: "object",
      properties: {
        templateId: {
          type: "string",
          description: "Template ID to use (e.g., 'builtin-executive-summary')",
        },
        title: {
          type: "string",
          description: "Custom report title (optional)",
        },
        timeRange: {
          type: "string",
          enum: ["24h", "7d", "30d", "90d"],
          description: "Time range for report data",
        },
        includeToc: {
          type: "boolean",
          description: "Include table of contents",
        },
      },
      required: ["templateId"],
    },
  },
  {
    name: "report_create_template",
    description:
      "Create a custom report template with configurable sections. Available sections: health-score, vulnerability-summary, vulnerability-list, compliance-status, top-risks, trend-chart, mttr-metrics, scan-coverage, remediation-status, custom-text.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Template name",
        },
        description: {
          type: "string",
          description: "Template description",
        },
        format: {
          type: "string",
          enum: ["html", "markdown", "json"],
          description: "Output format (default: html)",
        },
        sections: {
          type: "array",
          description: "Sections to include in the report",
          items: {
            type: "object",
            properties: {
              type: {
                type: "string",
                enum: [
                  "health-score",
                  "vulnerability-summary",
                  "vulnerability-list",
                  "compliance-status",
                  "top-risks",
                  "trend-chart",
                  "mttr-metrics",
                  "scan-coverage",
                  "remediation-status",
                  "custom-text",
                ],
              },
              enabled: {
                type: "boolean",
                description: "Whether section is enabled",
              },
              title: {
                type: "string",
                description: "Custom section title",
              },
            },
          },
        },
      },
      required: ["name", "sections"],
    },
  },
  {
    name: "report_schedule",
    description:
      "Schedule recurring report generation. Supports daily, weekly, and monthly schedules with webhook delivery.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Schedule name",
        },
        templateId: {
          type: "string",
          description: "Template ID to use",
        },
        frequency: {
          type: "string",
          enum: ["once", "daily", "weekly", "monthly"],
          description: "Schedule frequency",
        },
        dayOfWeek: {
          type: "number",
          description: "Day of week for weekly (0=Sunday, 1=Monday, etc.)",
        },
        dayOfMonth: {
          type: "number",
          description: "Day of month for monthly (1-31)",
        },
        hour: {
          type: "number",
          description: "Hour to run (0-23, default: 8)",
        },
        webhookUrl: {
          type: "string",
          description: "Webhook URL for report delivery",
        },
        enabled: {
          type: "boolean",
          description: "Whether schedule is enabled (default: true)",
        },
      },
      required: ["name", "templateId", "frequency"],
    },
  },

  // ===========================================================================
  // Trend Analysis Tools
  // ===========================================================================
  {
    name: "trend_get_vulnerability_history",
    description:
      "Get historical vulnerability counts for a target (image, project, or organization). " +
      "Returns daily/weekly/monthly data points with counts by severity, new/fixed rates, " +
      "and summary statistics including trend direction.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target identifier (image name, project name, or organization)",
        },
        targetType: {
          type: "string",
          enum: ["image", "project", "organization"],
          description: "Type of target (default: image)",
        },
        startDate: {
          type: "string",
          description: "Start date (ISO format or relative like '30d', '90d')",
        },
        endDate: {
          type: "string",
          description: "End date (ISO format, default: today)",
        },
        granularity: {
          type: "string",
          enum: ["daily", "weekly", "monthly"],
          description: "Data point granularity (default: daily)",
        },
        includeMovingAverages: {
          type: "boolean",
          description: "Include 7-day and 30-day moving averages (default: false)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "trend_get_forecast",
    description:
      "Predict future vulnerability counts using linear regression. " +
      "Returns predicted totals with confidence intervals, days to reach zero, " +
      "and risk trend assessment.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target identifier (image name, project name, or organization)",
        },
        targetType: {
          type: "string",
          enum: ["image", "project", "organization"],
          description: "Type of target (default: image)",
        },
        horizonDays: {
          type: "number",
          description: "Number of days to forecast (default: 30)",
        },
        confidenceLevel: {
          type: "number",
          description: "Confidence level 0-1 (default: 0.95)",
        },
        historicalDays: {
          type: "number",
          description: "Days of historical data to use for model (default: 90)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "trend_detect_anomalies",
    description:
      "Detect unusual spikes or drops in vulnerability counts using Z-score analysis. " +
      "Identifies anomalies in total, critical, high, new, and fixed counts.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target identifier (image name, project name, or organization)",
        },
        targetType: {
          type: "string",
          enum: ["image", "project", "organization"],
          description: "Type of target (default: image)",
        },
        startDate: {
          type: "string",
          description: "Start date (ISO format or relative like '90d')",
        },
        endDate: {
          type: "string",
          description: "End date (ISO format, default: today)",
        },
        zScoreThreshold: {
          type: "number",
          description: "Z-score threshold for anomaly detection (default: 2.0)",
        },
        minDeviationPercent: {
          type: "number",
          description: "Minimum percentage deviation to flag (default: 20)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "trend_compare_periods",
    description:
      "Compare vulnerability metrics between two time periods. " +
      "Returns comparison of totals by severity, new/fix rates, and overall assessment.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target identifier (image name, project name, or organization)",
        },
        targetType: {
          type: "string",
          enum: ["image", "project", "organization"],
          description: "Type of target (default: image)",
        },
        period1Start: {
          type: "string",
          description: "Period 1 start date (ISO format)",
        },
        period1End: {
          type: "string",
          description: "Period 1 end date (ISO format)",
        },
        period1Label: {
          type: "string",
          description: "Label for period 1 (default: 'Period 1')",
        },
        period2Start: {
          type: "string",
          description: "Period 2 start date (ISO format)",
        },
        period2End: {
          type: "string",
          description: "Period 2 end date (ISO format)",
        },
        period2Label: {
          type: "string",
          description: "Label for period 2 (default: 'Period 2')",
        },
      },
      required: ["target", "period1Start", "period1End", "period2Start", "period2End"],
    },
  },
  // Risk Scoring Tools
  {
    name: "risk_calculate_score",
    description:
      "Calculate risk score for a vulnerability based on CVSS, asset criticality, " +
      "exposure level, exploitability factors, and age. Returns a prioritized risk score (0-100) " +
      "with risk tier classification and remediation recommendation.",
    inputSchema: {
      type: "object",
      properties: {
        vulnId: {
          type: "string",
          description: "Vulnerability ID (e.g., CVE-2024-1234)",
        },
        cvssScore: {
          type: "number",
          description: "Base CVSS score (0-10)",
        },
        asset: {
          type: "string",
          description: "Asset identifier (image name, project name)",
        },
        assetType: {
          type: "string",
          enum: ["image", "project", "repository", "service"],
          description: "Type of asset (default: image)",
        },
        criticality: {
          type: "string",
          enum: ["critical", "high", "medium", "low", "minimal"],
          description: "Asset business criticality (default: medium)",
        },
        exposure: {
          type: "string",
          enum: ["internet-facing", "internal-only", "air-gapped", "development"],
          description: "Asset network exposure level (default: internal-only)",
        },
        exploitInWild: {
          type: "boolean",
          description: "Whether exploit exists in the wild",
        },
        pocAvailable: {
          type: "boolean",
          description: "Whether proof of concept is available",
        },
        activelyExploited: {
          type: "boolean",
          description: "Whether being actively exploited",
        },
        cisaKev: {
          type: "boolean",
          description: "Whether listed in CISA KEV catalog",
        },
        epssScore: {
          type: "number",
          description: "EPSS score (0-1) if available",
        },
        firstDetected: {
          type: "string",
          description: "Date vulnerability was first detected (ISO format)",
        },
        storeResult: {
          type: "boolean",
          description: "Whether to store the calculated score in database (default: false)",
        },
      },
      required: ["vulnId", "cvssScore", "asset"],
    },
  },
  {
    name: "risk_set_asset_criticality",
    description:
      "Configure asset criticality and exposure for risk scoring. " +
      "Sets business context that affects risk score calculations for all vulnerabilities " +
      "on that asset. Higher criticality and exposure increase risk scores.",
    inputSchema: {
      type: "object",
      properties: {
        asset: {
          type: "string",
          description: "Asset identifier (image name, project name)",
        },
        assetType: {
          type: "string",
          enum: ["image", "project", "repository", "service"],
          description: "Type of asset",
        },
        criticality: {
          type: "string",
          enum: ["critical", "high", "medium", "low", "minimal"],
          description: "Business criticality level",
        },
        exposure: {
          type: "string",
          enum: ["internet-facing", "internal-only", "air-gapped", "development"],
          description: "Network exposure level",
        },
        businessContext: {
          type: "string",
          description: "Description of asset's business purpose",
        },
        owner: {
          type: "string",
          description: "Team or person responsible for the asset",
        },
        complianceFrameworks: {
          type: "array",
          items: { type: "string" },
          description: "Compliance frameworks applicable (e.g., 'SOC2', 'HIPAA')",
        },
        customMultiplier: {
          type: "number",
          description: "Custom risk multiplier (default: 1.0)",
        },
      },
      required: ["asset", "assetType", "criticality", "exposure"],
    },
  },
  {
    name: "risk_get_prioritized_list",
    description:
      "Get a prioritized list of vulnerabilities sorted by risk score. " +
      "Returns vulnerabilities with full risk context including tier classification, " +
      "contributing factors, and remediation recommendations. Supports filtering by " +
      "assets, minimum score, and risk tiers.",
    inputSchema: {
      type: "object",
      properties: {
        assets: {
          type: "array",
          items: { type: "string" },
          description: "Filter to specific assets (optional, all if not specified)",
        },
        minRiskScore: {
          type: "number",
          description: "Minimum risk score to include (0-100)",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return",
        },
        includeTiers: {
          type: "array",
          items: {
            type: "string",
            enum: ["critical", "high", "medium", "low", "minimal"],
          },
          description: "Risk tiers to include (optional, all if not specified)",
        },
        groupByAsset: {
          type: "boolean",
          description: "Include asset-level summary statistics",
        },
      },
      required: [],
    },
  },
  // Report Export (PDF, Excel, CSV) Tools
  {
    name: "export_to_pdf",
    description:
      "Export security report data to a professional PDF document. " +
      "Supports branding, table of contents, headers/footers, and page customization. " +
      "Ideal for executive summaries and compliance documentation.",
    inputSchema: {
      type: "object",
      properties: {
        data: {
          type: "object",
          description:
            "Report data containing title, summary, vulnerabilities, compliance, and trends",
          properties: {
            title: { type: "string", description: "Report title" },
            generatedAt: { type: "string", description: "Generation timestamp" },
            target: { type: "string", description: "Target being reported on" },
            summary: {
              type: "object",
              description: "Summary statistics",
              properties: {
                totalVulnerabilities: { type: "number" },
                criticalCount: { type: "number" },
                highCount: { type: "number" },
                mediumCount: { type: "number" },
                lowCount: { type: "number" },
                healthScore: { type: "number" },
              },
            },
            vulnerabilities: {
              type: "array",
              description: "List of vulnerabilities",
              items: {
                type: "object",
                properties: {
                  id: { type: "string" },
                  severity: { type: "string" },
                  package: { type: "string" },
                  version: { type: "string" },
                  fixedVersion: { type: "string" },
                  cvss: { type: "number" },
                },
              },
            },
          },
          required: ["title", "generatedAt"],
        },
        outputPath: {
          type: "string",
          description: "Output file path for the PDF",
        },
        pageSize: {
          type: "string",
          enum: ["A4", "Letter", "Legal", "A3", "Tabloid"],
          description: "Page size (default: A4)",
        },
        orientation: {
          type: "string",
          enum: ["portrait", "landscape"],
          description: "Page orientation (default: portrait)",
        },
        includeTableOfContents: {
          type: "boolean",
          description: "Include table of contents (default: true)",
        },
        branding: {
          type: "object",
          description: "Branding configuration",
          properties: {
            logo: { type: "string", description: "Logo URL or base64 data URI" },
            companyName: { type: "string", description: "Company name for header" },
            primaryColor: { type: "string", description: "Primary color (hex)" },
          },
        },
      },
      required: ["data", "outputPath"],
    },
  },
  {
    name: "export_to_excel",
    description:
      "Export security report data to an Excel spreadsheet with multiple worksheets. " +
      "Includes summary, vulnerability details, and compliance status. " +
      "Supports filtering, conditional formatting by severity, and charts.",
    inputSchema: {
      type: "object",
      properties: {
        data: {
          type: "object",
          description: "Report data (same structure as export_to_pdf)",
          properties: {
            title: { type: "string" },
            generatedAt: { type: "string" },
            summary: { type: "object" },
            vulnerabilities: { type: "array" },
            compliance: { type: "array" },
            trends: { type: "array" },
          },
          required: ["title", "generatedAt"],
        },
        outputPath: {
          type: "string",
          description: "Output file path for the Excel file (.xlsx)",
        },
        author: {
          type: "string",
          description: "Document author",
        },
        company: {
          type: "string",
          description: "Company name for document properties",
        },
        includeCharts: {
          type: "boolean",
          description: "Include trend charts if trend data available (default: true)",
        },
      },
      required: ["data", "outputPath"],
    },
  },
  {
    name: "export_to_csv",
    description:
      "Export vulnerability data to CSV format for import into other tools. " +
      "Supports custom delimiters, UTF-8 BOM for Excel compatibility, and configurable columns.",
    inputSchema: {
      type: "object",
      properties: {
        data: {
          type: "object",
          description: "Report data with vulnerabilities array",
          properties: {
            vulnerabilities: {
              type: "array",
              items: { type: "object" },
            },
          },
        },
        outputPath: {
          type: "string",
          description: "Output file path for the CSV file",
        },
        delimiter: {
          type: "string",
          enum: [",", ";", "\t", "|"],
          description: "Field delimiter (default: comma)",
        },
        includeBom: {
          type: "boolean",
          description: "Include UTF-8 BOM for Excel compatibility (default: true)",
        },
      },
      required: ["data", "outputPath"],
    },
  },
  // Cross-Project Comparative Analysis Tools
  {
    name: "compare_projects",
    description:
      "Compare security metrics between two projects. " +
      "Provides detailed analysis of vulnerability counts, risk scores, compliance, and trends. " +
      "Identifies which project has better security posture and generates recommendations.",
    inputSchema: {
      type: "object",
      properties: {
        projectIdA: {
          type: "string",
          description: "First project ID",
        },
        projectIdB: {
          type: "string",
          description: "Second project ID",
        },
        metricsA: {
          type: "object",
          description: "Security metrics for first project",
          properties: {
            entityId: { type: "string" },
            entityName: { type: "string" },
            entityType: { type: "string", enum: ["project", "team", "image", "repository"] },
            timestamp: { type: "string" },
            vulnerabilityCount: { type: "number" },
            criticalCount: { type: "number" },
            highCount: { type: "number" },
            mediumCount: { type: "number" },
            lowCount: { type: "number" },
            riskScore: { type: "number" },
            healthScore: { type: "number" },
            complianceScore: { type: "number" },
            mttr: { type: "number", description: "Mean time to remediate in hours" },
            remediationVelocity: { type: "number", description: "Vulnerabilities fixed per day" },
            scanCoverage: { type: "number", description: "Percentage of assets scanned" },
            assetCount: { type: "number" },
          },
          required: [
            "entityId",
            "entityName",
            "entityType",
            "timestamp",
            "vulnerabilityCount",
            "criticalCount",
            "highCount",
            "mediumCount",
            "lowCount",
            "riskScore",
            "healthScore",
            "complianceScore",
          ],
        },
        metricsB: {
          type: "object",
          description: "Security metrics for second project (same structure as metricsA)",
        },
        normalize: {
          type: "boolean",
          description: "Normalize metrics by asset count for fair comparison (default: false)",
        },
      },
      required: ["projectIdA", "projectIdB", "metricsA", "metricsB"],
    },
  },
  {
    name: "compare_teams",
    description:
      "Compare security metrics between two teams. " +
      "Analyzes aggregate security posture across all projects owned by each team. " +
      "Useful for organizational security benchmarking and identifying teams that need support.",
    inputSchema: {
      type: "object",
      properties: {
        teamIdA: {
          type: "string",
          description: "First team ID",
        },
        teamIdB: {
          type: "string",
          description: "Second team ID",
        },
        metricsA: {
          type: "object",
          description: "Aggregate security metrics for first team",
        },
        metricsB: {
          type: "object",
          description: "Aggregate security metrics for second team",
        },
        normalize: {
          type: "boolean",
          description: "Normalize by project count for fair comparison (default: false)",
        },
      },
      required: ["teamIdA", "teamIdB", "metricsA", "metricsB"],
    },
  },
  {
    name: "compare_to_baseline",
    description:
      "Compare current security metrics against a saved baseline snapshot. " +
      "Useful for tracking security progress over time and detecting regressions. " +
      "Can use a specific baseline ID or the default baseline for an entity.",
    inputSchema: {
      type: "object",
      properties: {
        currentMetrics: {
          type: "object",
          description: "Current entity metrics to compare",
        },
        baselineId: {
          type: "string",
          description: "Specific baseline ID to compare against",
        },
        useDefaultBaseline: {
          type: "boolean",
          description: "Use the default baseline for the entity (requires entityId)",
        },
        entityId: {
          type: "string",
          description: "Entity ID when using default baseline",
        },
      },
      required: ["currentMetrics"],
    },
  },
  // =========================================================================
  // Remediation Automation Tools (v1.24.0)
  // =========================================================================
  {
    name: "remediation_create_pr",
    description:
      "Create a pull request with automated fixes for vulnerabilities. " +
      "Generates a branch, commits the changes, and opens a PR on Gitea.",
    inputSchema: {
      type: "object",
      properties: {
        owner: {
          type: "string",
          description: "Repository owner (user or organization)",
        },
        repo: {
          type: "string",
          description: "Repository name",
        },
        vulnIds: {
          type: "array",
          items: { type: "string" },
          description: "List of vulnerability IDs to fix (e.g., ['CVE-2024-1234'])",
        },
        baseBranch: {
          type: "string",
          description: "Base branch for the PR (default: main)",
        },
        dryRun: {
          type: "boolean",
          description: "Preview the PR without actually creating it",
        },
      },
      required: ["owner", "repo", "vulnIds"],
    },
  },
  {
    name: "remediation_batch_create",
    description:
      "Create multiple PRs for batch vulnerability remediation. " +
      "Groups fixes by package manager and creates separate PRs for each.",
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
        scanTarget: {
          type: "string",
          description: "Path or image to scan for vulnerabilities",
        },
        severity: {
          type: "string",
          description: "Minimum severity to include (CRITICAL, HIGH, MEDIUM, LOW)",
        },
        maxPrs: {
          type: "number",
          description: "Maximum number of PRs to create (default: 10)",
        },
        dryRun: {
          type: "boolean",
          description: "Preview without creating PRs",
        },
      },
      required: ["owner", "repo", "scanTarget"],
    },
  },
  {
    name: "remediation_get_status",
    description: "Get the status of a remediation pull request including merge state and checks.",
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
        prNumber: {
          type: "number",
          description: "Pull request number",
        },
      },
      required: ["owner", "repo", "prNumber"],
    },
  },
  // =========================================================================
  // IDE Integration Tools (v1.24.0)
  // =========================================================================
  {
    name: "ide_get_diagnostics",
    description:
      "Get LSP-compatible diagnostics from scan results for IDE integration. " +
      "Returns diagnostics mapped to file locations for VS Code, JetBrains, etc.",
    inputSchema: {
      type: "object",
      properties: {
        scanTarget: {
          type: "string",
          description: "Path to scan for vulnerabilities",
        },
        minSeverity: {
          type: "string",
          description: "Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW)",
        },
        basePath: {
          type: "string",
          description: "Base path for relative file URIs",
        },
      },
      required: ["scanTarget"],
    },
  },
  {
    name: "ide_get_code_actions",
    description:
      "Get LSP code actions (quick fixes) for vulnerabilities in a file. " +
      "Returns actions that can be applied to fix security issues.",
    inputSchema: {
      type: "object",
      properties: {
        filePath: {
          type: "string",
          description: "Path to the file to get actions for",
        },
        scanTarget: {
          type: "string",
          description: "Path or image that was scanned",
        },
      },
      required: ["filePath", "scanTarget"],
    },
  },
  {
    name: "ide_apply_fix",
    description:
      "Apply a security fix to a file. Generates the text edit needed to update a vulnerable dependency.",
    inputSchema: {
      type: "object",
      properties: {
        filePath: {
          type: "string",
          description: "Path to the file to modify",
        },
        vulnId: {
          type: "string",
          description: "Vulnerability ID to fix",
        },
        packageName: {
          type: "string",
          description: "Package name to update",
        },
        targetVersion: {
          type: "string",
          description: "Version to update to",
        },
      },
      required: ["filePath", "vulnId", "packageName", "targetVersion"],
    },
  },
  // =========================================================================
  // Dependency Update Tools (v1.24.0)
  // =========================================================================
  {
    name: "deps_check_updates",
    description:
      "Check for available dependency updates in a project. " +
      "Supports npm, pip, go, and other package managers.",
    inputSchema: {
      type: "object",
      properties: {
        projectPath: {
          type: "string",
          description: "Path to the project directory",
        },
        packageManager: {
          type: "string",
          description: "Package manager to use (npm, yarn, pnpm, pip, go, cargo)",
        },
      },
      required: ["projectPath"],
    },
  },
  {
    name: "deps_preview_update",
    description:
      "Preview the impact of updating a dependency including risk assessment and breaking changes.",
    inputSchema: {
      type: "object",
      properties: {
        packageName: {
          type: "string",
          description: "Package name to preview",
        },
        targetVersion: {
          type: "string",
          description: "Target version to update to",
        },
        currentVersion: {
          type: "string",
          description: "Current version installed",
        },
        projectPath: {
          type: "string",
          description: "Project path for context",
        },
      },
      required: ["packageName", "targetVersion"],
    },
  },
  {
    name: "deps_apply_updates",
    description: "Apply dependency updates to a project. Creates a backup for rollback.",
    inputSchema: {
      type: "object",
      properties: {
        projectPath: {
          type: "string",
          description: "Path to the project directory",
        },
        updates: {
          type: "array",
          items: {
            type: "object",
            properties: {
              package: { type: "string" },
              version: { type: "string" },
            },
          },
          description: "List of updates to apply [{package, version}]",
        },
        packageManager: {
          type: "string",
          description: "Package manager to use",
        },
        dryRun: {
          type: "boolean",
          description: "Preview without applying",
        },
        stopOnError: {
          type: "boolean",
          description: "Stop on first error",
        },
      },
      required: ["projectPath", "updates"],
    },
  },
  {
    name: "deps_rollback",
    description: "Rollback to the previous dependency state using the backup lockfile.",
    inputSchema: {
      type: "object",
      properties: {
        projectPath: {
          type: "string",
          description: "Path to the project directory",
        },
        packageManager: {
          type: "string",
          description: "Package manager to use",
        },
      },
      required: ["projectPath"],
    },
  },
  // =========================================================================
  // Fix Verification Tools (v1.24.0)
  // =========================================================================
  {
    name: "fix_verify",
    description:
      "Verify that vulnerability fixes have been successfully applied by comparing before/after scans.",
    inputSchema: {
      type: "object",
      properties: {
        fixes: {
          type: "array",
          items: {
            type: "object",
            properties: {
              vulnId: { type: "string" },
              packageName: { type: "string" },
            },
          },
          description: "List of fixes to verify [{vulnId, packageName}]",
        },
        beforeScan: {
          type: "object",
          description: "Scan results before the fix",
        },
        afterScan: {
          type: "object",
          description: "Scan results after the fix",
        },
      },
      required: ["fixes", "beforeScan", "afterScan"],
    },
  },
  {
    name: "fix_rescan",
    description:
      "Re-scan a target after applying fixes to confirm vulnerabilities are resolved. " +
      "Compares with previous scan to show what was fixed.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Path or image to scan",
        },
        scanType: {
          type: "string",
          enum: ["path", "image"],
          description: "Type of scan to perform",
        },
        previousScan: {
          type: "object",
          description: "Previous scan results to compare against",
        },
        vulnIds: {
          type: "array",
          items: { type: "string" },
          description: "Specific CVE IDs to check (optional)",
        },
      },
      required: ["target", "scanType"],
    },
  },
  // =========================================================================
  // SLA Tracking Tools (v1.25.0)
  // =========================================================================
  {
    name: "sla_configure",
    description:
      "Configure SLA targets for vulnerability remediation. Define acknowledgment and remediation " +
      "time targets per severity level with warning thresholds.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Name for this SLA configuration",
        },
        description: {
          type: "string",
          description: "Description of the SLA policy",
        },
        setAsDefault: {
          type: "boolean",
          description: "Set this as the default SLA configuration",
        },
        targets: {
          type: "array",
          items: {
            type: "object",
            properties: {
              severity: {
                type: "string",
                enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
              },
              acknowledgeHours: {
                type: "number",
                description: "Hours to acknowledge vulnerability",
              },
              remediateHours: {
                type: "number",
                description: "Hours to remediate vulnerability",
              },
              warningThresholdPercent: {
                type: "number",
                description: "Warning threshold as percentage (0-100)",
              },
            },
            required: ["severity", "acknowledgeHours", "remediateHours"],
          },
          description: "SLA targets per severity level",
        },
      },
      required: ["name", "targets"],
    },
  },
  {
    name: "sla_get_status",
    description:
      "Get SLA compliance status for tracked vulnerabilities. Shows compliant, warning, " +
      "and breached counts with breakdown by severity.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Filter by specific target (image/project path)",
        },
        severity: {
          type: "array",
          items: {
            type: "string",
            enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
          },
          description: "Filter by severity levels",
        },
        configId: {
          type: "string",
          description: "SLA config ID to use (uses default if not specified)",
        },
        includeDetails: {
          type: "boolean",
          description: "Include individual vulnerability statuses",
        },
      },
      required: [],
    },
  },
  {
    name: "sla_get_breaches",
    description:
      "Get current SLA breaches and vulnerabilities approaching breach. " +
      "Returns breached items and those in warning zone.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Filter by specific target",
        },
        severity: {
          type: "array",
          items: {
            type: "string",
            enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
          },
          description: "Filter by severity levels",
        },
        configId: {
          type: "string",
          description: "SLA config ID to use",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return",
        },
      },
      required: [],
    },
  },
  // =========================================================================
  // Governance Workflow Tools (v1.26.0)
  // =========================================================================
  {
    name: "governance_create_policy",
    description:
      "Create a security governance policy with rules for enforcement. " +
      "Policies can be advisory (warn) or blocking (fail builds).",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Unique policy name" },
        description: { type: "string", description: "Policy description" },
        version: { type: "string", description: "Policy version (default: 1.0)" },
        enforcementLevel: {
          type: "string",
          enum: ["advisory", "blocking"],
          description: "Enforcement level (default: advisory)",
        },
        owner: { type: "string", description: "Policy owner" },
        rules: {
          type: "array",
          items: { type: "object" },
          description: "Policy rules array",
        },
      },
      required: ["name"],
    },
  },
  {
    name: "governance_list_policies",
    description: "List all governance policies with optional status filter.",
    inputSchema: {
      type: "object",
      properties: {
        status: {
          type: "string",
          enum: ["draft", "active", "deprecated"],
          description: "Filter by policy status",
        },
      },
      required: [],
    },
  },
  {
    name: "governance_activate_policy",
    description: "Activate a draft policy to make it enforceable.",
    inputSchema: {
      type: "object",
      properties: {
        policyId: { type: "string", description: "Policy ID to activate" },
        actor: { type: "string", description: "User activating the policy" },
      },
      required: ["policyId"],
    },
  },
  {
    name: "governance_request_exception",
    description: "Request an exception to a governance policy with justification.",
    inputSchema: {
      type: "object",
      properties: {
        policyId: { type: "string", description: "Policy ID for exception" },
        requester: { type: "string", description: "User requesting exception" },
        reason: { type: "string", description: "Justification for exception" },
        scope: { type: "object", description: "Scope of exception (targets, etc.)" },
        expiresAt: { type: "string", description: "Exception expiration date (ISO)" },
      },
      required: ["policyId", "requester", "reason"],
    },
  },
  {
    name: "governance_approve_exception",
    description: "Approve a pending policy exception request.",
    inputSchema: {
      type: "object",
      properties: {
        exceptionId: { type: "string", description: "Exception ID to approve" },
        approver: { type: "string", description: "User approving the exception" },
      },
      required: ["exceptionId", "approver"],
    },
  },
  {
    name: "governance_list_exceptions",
    description: "List policy exceptions with optional filters.",
    inputSchema: {
      type: "object",
      properties: {
        policyId: { type: "string", description: "Filter by policy ID" },
        status: {
          type: "string",
          enum: ["pending", "approved", "rejected", "expired"],
          description: "Filter by exception status",
        },
      },
      required: [],
    },
  },
  // =========================================================================
  // Evidence Collection Tools (v1.26.0)
  // =========================================================================
  {
    name: "evidence_collect",
    description: "Collect compliance evidence with metadata, linked to frameworks and controls.",
    inputSchema: {
      type: "object",
      properties: {
        type: {
          type: "string",
          enum: [
            "scan_result",
            "configuration",
            "policy",
            "attestation",
            "log",
            "screenshot",
            "document",
          ],
          description: "Type of evidence",
        },
        title: { type: "string", description: "Evidence title" },
        description: { type: "string", description: "Evidence description" },
        framework: { type: "string", description: "Compliance framework (SOC2, HIPAA, etc.)" },
        controlId: { type: "string", description: "Control ID within framework" },
        source: { type: "string", description: "Source system or tool" },
        collectedBy: { type: "string", description: "User collecting evidence" },
        content: { type: "object", description: "Evidence content/data" },
        tags: {
          type: "array",
          items: { type: "string" },
          description: "Tags for categorization",
        },
      },
      required: ["type", "title", "source"],
    },
  },
  {
    name: "evidence_attach",
    description: "Attach a file to existing evidence record.",
    inputSchema: {
      type: "object",
      properties: {
        evidenceId: { type: "string", description: "Evidence record ID" },
        filename: { type: "string", description: "Attachment filename" },
        mimeType: { type: "string", description: "MIME type" },
        storagePath: { type: "string", description: "Path where file is stored" },
        uploadedBy: { type: "string", description: "User uploading attachment" },
      },
      required: ["evidenceId", "filename"],
    },
  },
  {
    name: "evidence_export",
    description: "Export evidence package for a framework or set of controls.",
    inputSchema: {
      type: "object",
      properties: {
        framework: { type: "string", description: "Filter by framework" },
        controlIds: {
          type: "array",
          items: { type: "string" },
          description: "Filter by control IDs",
        },
        includeContent: { type: "boolean", description: "Include evidence content" },
        includeAttachments: { type: "boolean", description: "Include attachment metadata" },
      },
      required: [],
    },
  },
  // =========================================================================
  // Audit Preparation Tools (v1.26.0)
  // =========================================================================
  {
    name: "audit_prepare_package",
    description: "Prepare an audit package with evidence, findings, and remediations.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Audit package name" },
        type: {
          type: "string",
          enum: ["internal", "external", "certification", "assessment"],
          description: "Audit type",
        },
        framework: { type: "string", description: "Compliance framework" },
        preparedBy: { type: "string", description: "Preparer name" },
        evidenceIds: {
          type: "array",
          items: { type: "string" },
          description: "Evidence record IDs to include",
        },
        controlIds: {
          type: "array",
          items: { type: "string" },
          description: "Control IDs covered",
        },
        scope: { type: "object", description: "Audit scope details" },
      },
      required: ["name", "type"],
    },
  },
  {
    name: "audit_generate_attestation",
    description: "Generate a signed attestation statement for compliance assertion.",
    inputSchema: {
      type: "object",
      properties: {
        type: { type: "string", description: "Attestation type" },
        statement: { type: "string", description: "Attestation statement text" },
        attester: { type: "string", description: "Person attesting" },
        attesterRole: { type: "string", description: "Role of attester" },
        auditPackageId: { type: "string", description: "Link to audit package" },
        evidenceIds: {
          type: "array",
          items: { type: "string" },
          description: "Supporting evidence IDs",
        },
        scope: { type: "object", description: "Scope of attestation" },
        validUntil: { type: "string", description: "Attestation validity end (ISO)" },
      },
      required: ["type", "statement", "attester"],
    },
  },
  {
    name: "audit_timeline",
    description: "Get compliance timeline showing events and changes over time.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target to get timeline for" },
        framework: { type: "string", description: "Filter by framework" },
        eventTypes: {
          type: "array",
          items: { type: "string" },
          description: "Filter by event types",
        },
        startDate: { type: "string", description: "Start date (ISO)" },
        endDate: { type: "string", description: "End date (ISO)" },
        limit: { type: "number", description: "Maximum events to return" },
      },
      required: [],
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
      description: result.parsed ? describeCronExpression(result.parsed) : "",
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

    return evaluatePolicyWithScan({
      policy,
      severity: args?.severity as string | undefined,
      image: args?.image as string | undefined,
      path: args?.path as string | undefined,
      licenses: args?.licenses as string[] | undefined,
      secretsFound: args?.secretsFound as boolean | undefined,
      codeCoverage: args?.codeCoverage as number | undefined,
      qualityGatePassed: args?.qualityGatePassed as boolean | undefined,
      thresholds: args?.thresholds as {
        critical?: number;
        high?: number;
        medium?: number;
        low?: number;
        coverage?: number;
      },
    });
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

// Redis Cache Handlers
const cacheHandlers: Record<string, ToolHandler> = {
  cache_init: async (args) => {
    const useRedis = (args?.useRedis as boolean) ?? true;
    const result = await initDistributedCaches(useRedis);
    return {
      initialized: true,
      redis: {
        connected: result.redis,
        attempted: useRedis,
      },
      memory: {
        available: result.memory,
      },
      mode: result.redis ? "hybrid" : "memory",
    };
  },

  cache_status: async () => {
    const health = await getCacheHealth();
    return health;
  },

  cache_stats: async () => {
    const stats = await getAllCacheStats();
    return stats;
  },

  cache_clear: async (args) => {
    const confirm = args?.confirm as boolean;
    if (!confirm) {
      return {
        error: "Must set confirm=true to clear all caches",
        cleared: false,
      };
    }
    await clearAllCaches();
    return {
      cleared: true,
      message: "All caches cleared successfully",
    };
  },

  cache_invalidate: async (args) => {
    const pattern = args?.pattern as string;
    if (!pattern) {
      return { error: "pattern is required" };
    }
    const deleted = await invalidateCacheByPattern(pattern);
    return {
      pattern,
      deleted,
      message: `Invalidated ${deleted} cache entries matching pattern "${pattern}"`,
    };
  },

  cache_config: async () => {
    const redisConfig = getRedisConfig();
    const ttlConfig = getTTLConfig();
    const connected = isRedisConnected();

    // Mask password if present
    const safeRedisConfig = {
      ...redisConfig,
      password: redisConfig.password ? "***" : undefined,
    };

    return {
      redis: {
        ...safeRedisConfig,
        connected,
      },
      ttl: {
        trivy: `${ttlConfig.trivy}s`,
        sonarqube: `${ttlConfig.sonarqube}s`,
        dtrack: `${ttlConfig.dtrack}s`,
        registry: `${ttlConfig.registry}s`,
        default: `${ttlConfig.default}s`,
      },
      environmentVariables: {
        redis: [
          "REDIS_HOST",
          "REDIS_PORT",
          "REDIS_PASSWORD",
          "REDIS_DB",
          "REDIS_KEY_PREFIX",
          "REDIS_CONNECT_TIMEOUT",
          "REDIS_MAX_RETRIES",
          "REDIS_OFFLINE_QUEUE",
        ],
        ttl: [
          "CACHE_TTL_TRIVY",
          "CACHE_TTL_SONARQUBE",
          "CACHE_TTL_DTRACK",
          "CACHE_TTL_REGISTRY",
          "CACHE_TTL_DEFAULT",
        ],
      },
    };
  },
};

// Suppression handlers
const suppressionHandlers: Record<string, ToolHandler> = {
  suppression_create: async (args) => {
    // Auto-initialize database if not already
    if (!isSuppressionDbInitialized()) {
      const initResult = initSuppressionDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize suppression database: ${initResult.error}` };
      }
    }

    const type = args?.type as "cve" | "package" | "path";
    const pattern = args?.pattern as string;
    const reason = args?.reason as string;

    if (!type || !pattern || !reason) {
      return { error: "type, pattern, and reason are required" };
    }

    const result = createDbSuppression(type, pattern, reason, {
      expires: args?.expires as string | undefined,
      createdBy: args?.createdBy as string | undefined,
      notes: args?.notes as string | undefined,
    });

    if (!result.success) {
      return { error: result.error };
    }

    return {
      success: true,
      suppression: result.suppression,
      message: `Created ${type} suppression for pattern "${pattern}"`,
    };
  },

  suppression_list: async (args) => {
    // Auto-initialize database if not already
    if (!isSuppressionDbInitialized()) {
      const initResult = initSuppressionDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize suppression database: ${initResult.error}` };
      }
    }

    const result = listDbSuppressions({
      type: args?.type as "cve" | "package" | "path" | undefined,
      status: args?.status as "active" | "expired" | undefined,
      pattern: args?.pattern as string | undefined,
      createdBy: args?.createdBy as string | undefined,
      includeExpired: args?.includeExpired as boolean | undefined,
      limit: args?.limit as number | undefined,
      offset: args?.offset as number | undefined,
    });

    const stats = getSuppressionDbStats();

    return {
      suppressions: result.suppressions,
      total: result.total,
      stats: {
        active: stats.active,
        expired: stats.expired,
        byType: stats.byType,
      },
    };
  },

  suppression_delete: async (args) => {
    // Auto-initialize database if not already
    if (!isSuppressionDbInitialized()) {
      const initResult = initSuppressionDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize suppression database: ${initResult.error}` };
      }
    }

    const id = args?.id as string;
    if (!id) {
      return { error: "id is required" };
    }

    // Get suppression details before deletion for response
    const suppression = getDbSuppression(id);
    if (!suppression) {
      return { error: `Suppression not found: ${id}` };
    }

    const result = deleteDbSuppression(id, args?.deletedBy as string | undefined);

    if (!result.success) {
      return { error: result.error };
    }

    return {
      success: true,
      deleted: {
        id: suppression.id,
        type: suppression.type,
        pattern: suppression.pattern,
      },
      message: `Deleted suppression for pattern "${suppression.pattern}"`,
    };
  },

  suppression_audit: async (args) => {
    // Auto-initialize database if not already
    if (!isSuppressionDbInitialized()) {
      const initResult = initSuppressionDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize suppression database: ${initResult.error}` };
      }
    }

    const result = getSuppressionAuditLog({
      suppressionId: args?.suppressionId as string | undefined,
      action: args?.action as "created" | "updated" | "deleted" | "applied" | "expired" | undefined,
      user: args?.user as string | undefined,
      since: args?.since as string | undefined,
      until: args?.until as string | undefined,
      limit: args?.limit as number | undefined,
    });

    return {
      entries: result.entries,
      total: result.total,
    };
  },

  suppression_apply: async (args) => {
    // Auto-initialize database if not already
    if (!isSuppressionDbInitialized()) {
      const initResult = initSuppressionDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize suppression database: ${initResult.error}` };
      }
    }

    const scanResult = args?.scanResult as Record<string, unknown>;
    if (!scanResult) {
      return { error: "scanResult is required" };
    }

    const result = applyDbSuppressions(scanResult as Parameters<typeof applyDbSuppressions>[0], {
      includeExpired: args?.includeExpired as boolean | undefined,
      user: args?.user as string | undefined,
      audit: args?.audit as boolean | undefined,
    });

    return {
      result: result.result,
      summary: result.suppressionResult.summary,
      appliedSuppressions: result.suppressionResult.appliedSuppressions.map((s) => ({
        suppressionId: s.suppression.id,
        type: s.suppression.type,
        pattern: s.suppression.pattern,
        vulnerabilityId: s.vulnerabilityId,
        package: s.package,
      })),
      suppressed: result.suppressionResult.suppressed.map((v) => ({
        id: v.id,
        package: v.package,
        severity: v.severity,
        reason: v.suppression.reason,
      })),
    };
  },
};

// Prometheus Metrics handlers
const metricsHandlers: Record<string, ToolHandler> = {
  metrics_get: async (args) => {
    const format = (args?.format as string) || "prometheus";

    if (format === "json") {
      const snapshot = getMetricsSnapshot();
      return {
        format: "json",
        timestamp: snapshot.timestamp,
        metrics: snapshot.metrics.map((m) => ({
          name: m.definition.name,
          type: m.definition.type,
          help: m.definition.help,
          values: m.values,
        })),
      };
    }

    // Default: Prometheus exposition format
    const prometheusOutput = getMetrics();
    return {
      format: "prometheus",
      contentType: "text/plain; version=0.0.4; charset=utf-8",
      data: prometheusOutput,
    };
  },

  metrics_record_scan: async (args) => {
    const target = args?.target as string;
    const type = args?.type as "image" | "path";
    const durationSeconds = args?.durationSeconds as number;
    const success = args?.success as boolean;

    if (!target || !type || durationSeconds === undefined || success === undefined) {
      return { error: "target, type, durationSeconds, and success are required" };
    }

    const vulns = args?.vulnerabilities as
      | { critical?: number; high?: number; medium?: number; low?: number }
      | undefined;

    recordScanMetrics({
      target,
      type,
      durationSeconds,
      success,
      vulnerabilities: vulns
        ? {
            critical: vulns.critical || 0,
            high: vulns.high || 0,
            medium: vulns.medium || 0,
            low: vulns.low || 0,
          }
        : undefined,
      error: args?.error as string | undefined,
    });

    return {
      success: true,
      message: `Recorded metrics for ${type} scan of ${target}`,
      recorded: {
        target,
        type,
        durationSeconds,
        success,
        vulnerabilities: vulns,
      },
    };
  },

  metrics_push: async (args) => {
    const url = args?.url as string;
    const job = args?.job as string;

    if (!url || !job) {
      return { error: "url and job are required" };
    }

    const result = await pushToGateway({
      url,
      job,
      instance: args?.instance as string | undefined,
      username: args?.username as string | undefined,
      password: args?.password as string | undefined,
      labels: args?.labels as Record<string, string> | undefined,
    });

    if (result.success) {
      return {
        success: true,
        message: `Pushed metrics to ${url} for job ${job}`,
        statusCode: result.statusCode,
      };
    }

    return {
      success: false,
      error: result.error,
      statusCode: result.statusCode,
    };
  },

  metrics_delete: async (args) => {
    const url = args?.url as string;
    const job = args?.job as string;

    if (!url || !job) {
      return { error: "url and job are required" };
    }

    const result = await deleteFromGateway({
      url,
      job,
      instance: args?.instance as string | undefined,
      username: args?.username as string | undefined,
      password: args?.password as string | undefined,
    });

    if (result.success) {
      return {
        success: true,
        message: `Deleted metrics from ${url} for job ${job}`,
        statusCode: result.statusCode,
      };
    }

    return {
      success: false,
      error: result.error,
      statusCode: result.statusCode,
    };
  },

  metrics_reset: async () => {
    resetMetrics();
    return {
      success: true,
      message: "All metrics have been reset",
    };
  },
};

// Scan Comparison handlers
const scanCompareHandlers: Record<string, ToolHandler> = {
  scan_compare: async (args) => {
    const current = args?.current as Record<string, unknown>;
    const baseline = args?.baseline as Record<string, unknown>;

    if (!current || !baseline) {
      return { error: "current and baseline scan results are required" };
    }

    const result = compareTrivyScans(
      current as Parameters<typeof compareTrivyScans>[0],
      baseline as Parameters<typeof compareTrivyScans>[1],
      {
        minSeverity: args?.minSeverity as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | undefined,
        includeUnchanged: args?.includeUnchanged as boolean | undefined,
      }
    );

    return {
      timestamp: result.timestamp,
      current: result.current,
      baseline: result.baseline,
      summary: result.summary,
      newVulnerabilities: result.newVulnerabilities,
      fixedVulnerabilities: result.fixedVulnerabilities,
      unchangedCount: result.unchangedVulnerabilities.length,
    };
  },

  scan_store: async (args) => {
    const scanResult = args?.scanResult as Record<string, unknown>;
    if (!scanResult) {
      return { error: "scanResult is required" };
    }

    const record = storeTrivyScan(
      scanResult as Parameters<typeof storeTrivyScan>[0],
      args?.identifier as string | undefined
    );

    return {
      success: true,
      record: {
        id: record.id,
        target: record.target,
        scannedAt: record.scannedAt,
        identifier: record.identifier,
        summary: record.summary,
      },
      message: `Stored scan for ${record.target} with ${record.summary.total} vulnerabilities`,
    };
  },

  scan_compare_with_previous: async (args) => {
    const scanResult = args?.scanResult as Record<string, unknown>;
    if (!scanResult) {
      return { error: "scanResult is required" };
    }

    const { record, diff } = storeAndCompare(
      scanResult as Parameters<typeof storeAndCompare>[0],
      args?.identifier as string | undefined,
      {
        minSeverity: args?.minSeverity as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | undefined,
        includeUnchanged: args?.includeUnchanged as boolean | undefined,
      }
    );

    if (!diff) {
      return {
        success: true,
        isFirstScan: true,
        record: {
          id: record.id,
          target: record.target,
          scannedAt: record.scannedAt,
          identifier: record.identifier,
          summary: record.summary,
        },
        message: `First scan for ${record.target}. Stored for future comparison.`,
      };
    }

    return {
      success: true,
      isFirstScan: false,
      record: {
        id: record.id,
        target: record.target,
        scannedAt: record.scannedAt,
        identifier: record.identifier,
        summary: record.summary,
      },
      diff: {
        timestamp: diff.timestamp,
        current: diff.current,
        baseline: diff.baseline,
        summary: diff.summary,
        newVulnerabilities: diff.newVulnerabilities,
        fixedVulnerabilities: diff.fixedVulnerabilities,
        unchangedCount: diff.unchangedVulnerabilities.length,
      },
    };
  },

  scan_history_list: async (args) => {
    const target = args?.target as string;
    if (!target) {
      return { error: "target is required" };
    }

    const limit = args?.limit as number | undefined;
    const history = getScanHistory();
    const records = history.getHistory(target, limit);

    return {
      target,
      count: records.length,
      records: records.map((r) => ({
        id: r.id,
        target: r.target,
        scannedAt: r.scannedAt,
        identifier: r.identifier,
        summary: r.summary,
      })),
    };
  },

  scan_history_get: async (args) => {
    const id = args?.id as string;
    if (!id) {
      return { error: "id is required" };
    }

    const history = getScanHistory();
    const record = history.getById(id);

    if (!record) {
      return { error: `Scan record not found: ${id}` };
    }

    return {
      id: record.id,
      target: record.target,
      scannedAt: record.scannedAt,
      identifier: record.identifier,
      summary: record.summary,
      vulnerabilityCount: record.vulnerabilities.length,
      vulnerabilities: record.vulnerabilities,
    };
  },

  scan_history_clear: async (args) => {
    const target = args?.target as string | undefined;
    const history = getScanHistory();

    if (target) {
      history.clearTarget(target);
      return {
        success: true,
        message: `Cleared scan history for ${target}`,
      };
    }

    history.clear();
    return {
      success: true,
      message: "Cleared all scan history",
    };
  },

  scan_history_targets: async () => {
    const history = getScanHistory();
    const targets = history.getTargets();

    return {
      count: targets.length,
      targets,
    };
  },
};

// SSO handlers
const ssoHandlers: Record<string, ToolHandler> = {
  sso_init_database: async (args) => {
    const result = initSsoDatabase(args?.dbPath as string | undefined);
    return {
      success: result.success,
      path: result.path,
      created: result.created,
      error: result.error,
    };
  },

  sso_configure_saml: async (args) => {
    const inputMapping = args?.attributeMapping as
      | { email?: string; name?: string; groups?: string }
      | undefined;
    const config = {
      id: args?.id as string,
      name: args?.name as string,
      enabled: args?.enabled !== false, // Default to enabled
      idpCertificate: args?.idpCertificate as string,
      idpSsoUrl: args?.idpSsoUrl as string,
      idpSloUrl: args?.idpSloUrl as string | undefined,
      spEntityId: args?.spEntityId as string,
      spAcsUrl: args?.spAcsUrl as string,
      spSloUrl: args?.spSloUrl as string | undefined,
      attributeMapping: {
        email: inputMapping?.email || "email",
        name: inputMapping?.name || "name",
        groups: inputMapping?.groups,
      },
      wantAssertionsSigned: args?.wantAssertionsSigned as boolean | undefined,
      wantResponseSigned: args?.wantResponseSigned as boolean | undefined,
    };

    const result = configureSamlProvider(config);
    return result;
  },

  sso_configure_oidc: async (args) => {
    const inputMapping = args?.attributeMapping as
      | { email?: string; name?: string; groups?: string }
      | undefined;
    const config = {
      id: args?.id as string,
      name: args?.name as string,
      enabled: args?.enabled !== false, // Default to enabled
      issuer: args?.issuer as string,
      clientId: args?.clientId as string,
      clientSecret: args?.clientSecret as string,
      redirectUri: args?.redirectUri as string,
      scopes: (args?.scopes as string[]) || ["openid", "profile", "email"],
      discoveryUrl: args?.discoveryUrl as string | undefined,
      jwksUri: args?.jwksUri as string | undefined,
      attributeMapping: {
        email: inputMapping?.email || "email",
        name: inputMapping?.name || "name",
        groups: inputMapping?.groups,
      },
    };

    const result = configureOidcProvider(config);
    return result;
  },

  sso_list_providers: async () => {
    return listSsoProviders();
  },

  sso_get_provider: async (args) => {
    const id = args?.id as string;
    if (!id) {
      return { error: "Provider ID is required" };
    }
    const provider = getSsoProvider(id);
    if (!provider) {
      return { error: `Provider not found: ${id}` };
    }
    return provider;
  },

  sso_delete_provider: async (args) => {
    const id = args?.id as string;
    if (!id) {
      return { error: "Provider ID is required" };
    }
    const success = deleteSsoProvider(id);
    return { success, id };
  },

  sso_set_provider_enabled: async (args) => {
    const id = args?.id as string;
    const enabled = args?.enabled as boolean;
    if (!id) {
      return { error: "Provider ID is required" };
    }
    if (typeof enabled !== "boolean") {
      return { error: "enabled must be a boolean" };
    }
    const success = setSsoProviderEnabled(id, enabled);
    return { success, id, enabled };
  },

  sso_get_metadata: async (args) => {
    const providerId = args?.providerId as string;
    if (!providerId) {
      return { error: "Provider ID is required" };
    }
    const metadata = generateSpMetadata(providerId);
    if (!metadata) {
      return { error: `Provider not found or not a SAML provider: ${providerId}` };
    }
    return metadata;
  },

  sso_validate_saml: async (args) => {
    const providerId = args?.providerId as string;
    const samlResponse = args?.samlResponse as string;
    if (!providerId || !samlResponse) {
      return { error: "providerId and samlResponse are required" };
    }
    const result = await validateSamlAssertion(providerId, samlResponse, {
      ipAddress: args?.ipAddress as string | undefined,
      userAgent: args?.userAgent as string | undefined,
    });
    return result;
  },

  sso_validate_oidc: async (args) => {
    const providerId = args?.providerId as string;
    const token = args?.token as string;
    if (!providerId || !token) {
      return { error: "providerId and token are required" };
    }
    const result = await validateOidcToken(providerId, token, {
      tokenType: args?.tokenType as "id_token" | "access_token" | undefined,
      nonce: args?.nonce as string | undefined,
      ipAddress: args?.ipAddress as string | undefined,
      userAgent: args?.userAgent as string | undefined,
    });
    return result;
  },

  sso_validate_token_by_issuer: async (args) => {
    const token = args?.token as string;
    if (!token) {
      return { error: "token is required" };
    }
    const result = await validateOidcTokenByIssuer(token, {
      tokenType: args?.tokenType as "id_token" | "access_token" | undefined,
    });
    return result;
  },

  sso_refresh_token: async (args) => {
    const providerId = args?.providerId as string;
    const refreshToken = args?.refreshToken as string;
    if (!providerId || !refreshToken) {
      return { error: "providerId and refreshToken are required" };
    }
    const result = await refreshOidcToken(providerId, refreshToken);
    return result;
  },

  sso_get_user_info: async (args) => {
    const providerId = args?.providerId as string;
    const accessToken = args?.accessToken as string;
    if (!providerId || !accessToken) {
      return { error: "providerId and accessToken are required" };
    }
    const result = await getOidcUserInfo(providerId, accessToken);
    return result;
  },

  sso_get_session: async (args) => {
    const sessionId = args?.sessionId as string;
    if (!sessionId) {
      return { error: "Session ID is required" };
    }
    const session = getSsoSession(sessionId);
    if (!session) {
      return { error: `Session not found: ${sessionId}` };
    }
    return session;
  },

  sso_validate_session: async (args) => {
    const sessionId = args?.sessionId as string;
    if (!sessionId) {
      return { error: "Session ID is required" };
    }
    const result = validateSsoSession(sessionId);
    return result;
  },

  sso_logout: async (args) => {
    const sessionId = args?.sessionId as string;
    if (!sessionId) {
      return { error: "Session ID is required" };
    }

    // Get session first if we need to generate logout request
    const generateLogoutRequest = args?.generateLogoutRequest as boolean;
    let logoutRequest = null;

    if (generateLogoutRequest) {
      const session = getSsoSession(sessionId);
      if (session && session.providerType === "saml") {
        logoutRequest = await generateSamlLogoutRequest(session.providerId, session);
      }
    }

    const success = terminateSsoSession(sessionId);
    return {
      success,
      sessionId,
      logoutRequest,
    };
  },

  sso_logout_user: async (args) => {
    const userId = args?.userId as string;
    if (!userId) {
      return { error: "User ID is required" };
    }
    const count = terminateAllUserSessions(userId);
    return {
      success: true,
      userId,
      terminatedSessions: count,
    };
  },

  sso_list_sessions: async (args) => {
    const userId = args?.userId as string | undefined;
    const includeExpired = args?.includeExpired as boolean | undefined;

    if (userId) {
      const sessions = listUserSessions(userId);
      const filtered = includeExpired
        ? sessions
        : sessions.filter((s) => new Date(s.expiresAt) > new Date());
      return {
        count: filtered.length,
        sessions: filtered,
      };
    } else {
      const sessions = listAllSessions();
      const filtered = includeExpired
        ? sessions
        : sessions.filter((s) => new Date(s.expiresAt) > new Date());
      return {
        count: filtered.length,
        sessions: filtered,
      };
    }
  },

  sso_cleanup_sessions: async () => {
    const count = cleanupExpiredSessions();
    return {
      success: true,
      removedSessions: count,
    };
  },

  sso_get_audit_log: async (args) => {
    const events = getSsoAuditEvents({
      userId: args?.userId as string | undefined,
      providerId: args?.providerId as string | undefined,
      eventType: args?.eventType as
        | "LOGIN"
        | "LOGOUT"
        | "TOKEN_REFRESH"
        | "TOKEN_VALIDATION"
        | "CONFIG_CHANGE"
        | "SESSION_EXPIRED"
        | undefined,
      status: args?.status as "SUCCESS" | "FAILURE" | undefined,
      limit: args?.limit as number | undefined,
    });
    return {
      count: events.length,
      events,
    };
  },
};

// RBAC handlers
const rbacHandlers: Record<string, ToolHandler> = {
  rbac_create_role: async (args) => {
    // Initialize RBAC database if not already done
    if (!isRbacDbInitialized()) {
      const result = initRbacDatabase();
      if (!result.success) {
        return { error: `Failed to initialize RBAC database: ${result.error}` };
      }
    }

    const name = args?.name as string;
    const description = args?.description as string | undefined;
    const permissions = args?.permissions as string[] | undefined;

    if (!name) {
      return { error: "Role name is required" };
    }

    try {
      const role = createRole(name, description, permissions);
      return {
        success: true,
        role,
        message: `Role '${name}' created successfully`,
      };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  rbac_list_roles: async (args) => {
    // Initialize RBAC database if not already done
    if (!isRbacDbInitialized()) {
      const result = initRbacDatabase();
      if (!result.success) {
        return { error: `Failed to initialize RBAC database: ${result.error}` };
      }
    }

    const includePermissions = args?.includePermissions !== false;
    const roles = listRoles(includePermissions);
    const permissions = listPermissions();

    return {
      roles,
      availablePermissions: permissions.map((p) => ({
        name: p.name,
        description: p.description,
        resource: p.resource,
        action: p.action,
      })),
    };
  },

  rbac_assign_role: async (args) => {
    // Initialize RBAC database if not already done
    if (!isRbacDbInitialized()) {
      const result = initRbacDatabase();
      if (!result.success) {
        return { error: `Failed to initialize RBAC database: ${result.error}` };
      }
    }

    const userId = args?.userId as string;
    const roleName = args?.roleName as string;
    const expiresAt = args?.expiresAt as string | undefined;

    if (!userId || !roleName) {
      return { error: "userId and roleName are required" };
    }

    // Look up role by name
    const role = getRoleByName(roleName);
    if (!role) {
      return { error: `Role not found: ${roleName}` };
    }

    const success = assignRoleToUser(userId, role.id, undefined, expiresAt);
    if (success) {
      return {
        success: true,
        userId,
        role: roleName,
        expiresAt,
        message: `Role '${roleName}' assigned to user '${userId}'`,
      };
    } else {
      return { error: "Failed to assign role" };
    }
  },

  rbac_check_permission: async (args) => {
    // Initialize RBAC database if not already done
    if (!isRbacDbInitialized()) {
      const result = initRbacDatabase();
      if (!result.success) {
        return { error: `Failed to initialize RBAC database: ${result.error}` };
      }
    }

    const userId = args?.userId as string;
    const permission = args?.permission as string;

    if (!userId || !permission) {
      return { error: "userId and permission are required" };
    }

    const result = checkPermission(userId, permission);
    return result;
  },

  rbac_list_user_permissions: async (args) => {
    // Initialize RBAC database if not already done
    if (!isRbacDbInitialized()) {
      const result = initRbacDatabase();
      if (!result.success) {
        return { error: `Failed to initialize RBAC database: ${result.error}` };
      }
    }

    const userId = args?.userId as string;

    if (!userId) {
      return { error: "userId is required" };
    }

    const roles = getUserRoles(userId);
    const permissions = listUserPermissions(userId);

    return {
      userId,
      roles: roles.map((r) => ({
        name: r.roleName,
        assignedAt: r.assignedAt,
        expiresAt: r.expiresAt,
      })),
      permissions: permissions.map((p) => ({
        name: p.name,
        description: p.description,
        resource: p.resource,
        action: p.action,
      })),
    };
  },
};

// API Key handlers
const apiKeyHandlers: Record<string, ToolHandler> = {
  apikey_create: async (args) => {
    // Initialize API key database if not already done
    if (!isApiKeyDbInitialized()) {
      const result = initApiKeyDatabase();
      if (!result.success) {
        return { error: `Failed to initialize API key database: ${result.error}` };
      }
    }

    const name = args?.name as string;
    const scopes = args?.scopes as string[];
    const createdBy = args?.createdBy as string;

    if (!name || !scopes || !createdBy) {
      return { error: "name, scopes, and createdBy are required" };
    }

    // Validate scopes
    for (const scope of scopes) {
      if (!VALID_SCOPES.includes(scope as any)) {
        return { error: `Invalid scope: ${scope}. Valid scopes: ${VALID_SCOPES.join(", ")}` };
      }
    }

    try {
      const result = createApiKey({
        name,
        description: args?.description as string | undefined,
        scopes: scopes as any,
        expiresInDays: args?.expiresInDays as number | undefined,
        createdBy,
        rateLimit: args?.rateLimit as number | undefined,
        ipAllowlist: args?.ipAllowlist as string[] | undefined,
      });

      return {
        message:
          "API key created successfully. IMPORTANT: Save the fullKey now - it will not be shown again!",
        key: {
          id: result.key.id,
          name: result.key.name,
          keyPrefix: result.key.keyPrefix,
          scopes: result.key.scopes,
          expiresAt: result.key.expiresAt,
          rateLimit: result.key.rateLimit,
        },
        fullKey: result.fullKey,
      };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  apikey_list: async (args) => {
    // Initialize API key database if not already done
    if (!isApiKeyDbInitialized()) {
      const result = initApiKeyDatabase();
      if (!result.success) {
        return { error: `Failed to initialize API key database: ${result.error}` };
      }
    }

    const keys = listApiKeys({
      status: args?.status as "active" | "revoked" | "expired" | undefined,
      createdBy: args?.createdBy as string | undefined,
      includeExpired: args?.includeExpired as boolean | undefined,
    });

    return {
      count: keys.length,
      keys: keys.map((k) => ({
        id: k.id,
        name: k.name,
        keyPrefix: k.keyPrefix,
        scopes: k.scopes,
        status: k.status,
        expiresAt: k.expiresAt,
        lastUsedAt: k.lastUsedAt,
        daysUntilExpiration: k.daysUntilExpiration,
        createdBy: k.createdBy,
        createdAt: k.createdAt,
      })),
    };
  },

  apikey_revoke: async (args) => {
    // Initialize API key database if not already done
    if (!isApiKeyDbInitialized()) {
      const result = initApiKeyDatabase();
      if (!result.success) {
        return { error: `Failed to initialize API key database: ${result.error}` };
      }
    }

    const keyId = args?.keyId as string;

    if (!keyId) {
      return { error: "keyId is required" };
    }

    const revoked = revokeApiKey(keyId, args?.actorId as string | undefined);

    if (revoked) {
      return { success: true, message: "API key revoked successfully" };
    } else {
      return { error: "Failed to revoke API key. It may not exist or is already revoked." };
    }
  },

  apikey_rotate: async (args) => {
    // Initialize API key database if not already done
    if (!isApiKeyDbInitialized()) {
      const result = initApiKeyDatabase();
      if (!result.success) {
        return { error: `Failed to initialize API key database: ${result.error}` };
      }
    }

    const keyId = args?.keyId as string;

    if (!keyId) {
      return { error: "keyId is required" };
    }

    try {
      const result = rotateApiKey(keyId, args?.actorId as string | undefined);

      if (!result) {
        return { error: "API key not found" };
      }

      return {
        message:
          "API key rotated successfully. IMPORTANT: Save the new key now - it will not be shown again!",
        previousKeyPrefix: result.previousKeyPrefix,
        key: {
          id: result.key.id,
          name: result.key.name,
          keyPrefix: result.key.keyPrefix,
          scopes: result.key.scopes,
          expiresAt: result.key.expiresAt,
        },
        newFullKey: result.newFullKey,
      };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },
};

// Team Management handlers
const teamHandlers: Record<string, ToolHandler> = {
  team_create_org: async (args) => {
    // Initialize Team database if not already done
    if (!isTeamDbInitialized()) {
      const result = initTeamDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Team database: ${result.error}` };
      }
    }

    const name = args?.name as string;
    const ownerId = args?.ownerId as string;

    if (!name || !ownerId) {
      return { error: "name and ownerId are required" };
    }

    try {
      const org = createOrganization({
        name,
        displayName: args?.displayName as string | undefined,
        description: args?.description as string | undefined,
        ownerId,
        settings: {
          maxTeams: (args?.maxTeams as number) || 100,
          maxMembersPerTeam: (args?.maxMembersPerTeam as number) || 100,
        },
      });

      return {
        message: "Organization created successfully",
        organization: org,
      };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  team_create_team: async (args) => {
    // Initialize Team database if not already done
    if (!isTeamDbInitialized()) {
      const result = initTeamDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Team database: ${result.error}` };
      }
    }

    const organizationId = args?.organizationId as string;
    const name = args?.name as string;

    if (!organizationId || !name) {
      return { error: "organizationId and name are required" };
    }

    try {
      const team = createTeam({
        organizationId,
        name,
        displayName: args?.displayName as string | undefined,
        description: args?.description as string | undefined,
        visibility: (args?.visibility as "public" | "private") || "private",
        createdBy: args?.createdBy as string | undefined,
      });

      return {
        message: "Team created successfully",
        team,
      };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  team_add_member: async (args) => {
    // Initialize Team database if not already done
    if (!isTeamDbInitialized()) {
      const result = initTeamDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Team database: ${result.error}` };
      }
    }

    const teamId = args?.teamId as string;
    const userId = args?.userId as string;

    if (!teamId || !userId) {
      return { error: "teamId and userId are required" };
    }

    try {
      const member = addTeamMember({
        teamId,
        userId,
        role: (args?.role as "owner" | "admin" | "member" | "viewer") || "member",
        addedBy: args?.addedBy as string | undefined,
        expiresAt: args?.expiresAt as string | undefined,
      });

      return {
        message: "Member added to team successfully",
        member,
      };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  team_list_teams: async (args) => {
    // Initialize Team database if not already done
    if (!isTeamDbInitialized()) {
      const result = initTeamDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Team database: ${result.error}` };
      }
    }

    const teams = listTeams({
      organizationId: args?.organizationId as string | undefined,
      visibility: args?.visibility as "public" | "private" | undefined,
      search: args?.search as string | undefined,
      includeStats: args?.includeStats as boolean | undefined,
      limit: args?.limit as number | undefined,
      offset: args?.offset as number | undefined,
    });

    return {
      count: teams.length,
      teams,
    };
  },

  team_check_membership: async (args) => {
    // Initialize Team database if not already done
    if (!isTeamDbInitialized()) {
      const result = initTeamDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Team database: ${result.error}` };
      }
    }

    const teamId = args?.teamId as string;
    const userId = args?.userId as string;

    if (!teamId || !userId) {
      return { error: "teamId and userId are required" };
    }

    const isMember = isTeamMember(teamId, userId);
    const requiredRole = args?.requiredRole as "owner" | "admin" | "member" | "viewer" | undefined;

    if (requiredRole) {
      const hasRole = hasTeamRole(teamId, userId, requiredRole);
      const member = getTeamMember(teamId, userId);
      return {
        isMember,
        hasRequiredRole: hasRole,
        requiredRole,
        actualRole: member?.role || null,
        userId,
        teamId,
      };
    }

    const member = getTeamMember(teamId, userId);
    return {
      isMember,
      role: member?.role || null,
      joinedAt: member?.joinedAt || null,
      expiresAt: member?.expiresAt || null,
      userId,
      teamId,
    };
  },
};

// =============================================================================
// Session Management Handlers
// =============================================================================

const sessionHandlers: Record<string, ToolHandler> = {
  session_list: async (args) => {
    // Initialize Session database if not already done
    if (!isSessionDbInitialized()) {
      const result = initSessionDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Session database: ${result.error}` };
      }
    }

    const sessions = listSessions({
      userId: args?.userId as string | undefined,
      activeOnly: args?.activeOnly !== false, // default true
      includeExpired: args?.includeExpired as boolean | undefined,
      limit: args?.limit as number | undefined,
      offset: args?.offset as number | undefined,
    });

    const stats = getSessionStats(args?.userId as string | undefined);

    return {
      count: sessions.length,
      sessions: sessions.map((s) => ({
        id: s.id,
        userId: s.userId,
        device: s.device,
        ipAddress: s.ipAddress,
        createdAt: s.createdAt,
        lastActivity: s.lastActivity,
        expiresAt: s.expiresAt,
        isActive: s.isActive,
      })),
      stats,
    };
  },

  session_revoke: async (args) => {
    // Initialize Session database if not already done
    if (!isSessionDbInitialized()) {
      const result = initSessionDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Session database: ${result.error}` };
      }
    }

    const sessionId = args?.sessionId as string;
    if (!sessionId) {
      return { error: "sessionId is required" };
    }

    const session = getSession(sessionId);
    if (!session) {
      return { error: `Session not found: ${sessionId}` };
    }

    const reason = args?.reason as string | undefined;
    const revoked = revokeSession(sessionId, reason);

    return {
      success: revoked,
      sessionId,
      userId: session.userId,
      reason: reason || "Session revoked",
      message: revoked
        ? "Session has been revoked"
        : "Session could not be revoked (may already be inactive)",
    };
  },

  session_revoke_all: async (args) => {
    // Initialize Session database if not already done
    if (!isSessionDbInitialized()) {
      const result = initSessionDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Session database: ${result.error}` };
      }
    }

    const userId = args?.userId as string;
    if (!userId) {
      return { error: "userId is required" };
    }

    const reason = args?.reason as string | undefined;
    const revokedCount = revokeAllUserSessions(userId, reason);

    return {
      success: revokedCount > 0,
      userId,
      revokedCount,
      reason: reason || "All sessions revoked",
      message: `${revokedCount} session(s) have been revoked for user`,
    };
  },
};

// =============================================================================
// Audit Trail Handlers
// =============================================================================

const auditHandlers: Record<string, ToolHandler> = {
  audit_search: async (args) => {
    // Initialize Audit database if not already done
    if (!isAuditDbInitialized()) {
      const result = initAuditDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Audit database: ${result.error}` };
      }
    }

    const events = searchAuditEvents({
      actorId: args?.actorId as string | undefined,
      actorType: args?.actorType as "user" | "apikey" | "system" | undefined,
      action: args?.action as
        | "auth.login"
        | "auth.logout"
        | "auth.login_failed"
        | "scan.triggered"
        | "scan.completed"
        | "scan.failed"
        | undefined,
      actionCategory: args?.actionCategory as
        | "authentication"
        | "authorization"
        | "scan"
        | "policy"
        | "suppression"
        | "admin"
        | "data"
        | undefined,
      resourceType: args?.resourceType as
        | "user"
        | "session"
        | "apikey"
        | "role"
        | "image"
        | "scan"
        | "policy"
        | undefined,
      resourceId: args?.resourceId as string | undefined,
      outcome: args?.outcome as "success" | "failure" | undefined,
      startTime: args?.startTime as string | undefined,
      endTime: args?.endTime as string | undefined,
      query: args?.query as string | undefined,
      limit: args?.limit as number | undefined,
      offset: args?.offset as number | undefined,
    });

    return {
      count: events.length,
      events: events.map((e) => ({
        id: e.id,
        timestamp: e.timestamp,
        actor: e.actor,
        action: e.action,
        resource: e.resource,
        outcome: e.outcome,
        details: e.details,
      })),
    };
  },

  audit_export: async (args) => {
    // Initialize Audit database if not already done
    if (!isAuditDbInitialized()) {
      const result = initAuditDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Audit database: ${result.error}` };
      }
    }

    const result = exportAuditLogs({
      format: args?.format as "json" | "csv" | "ndjson" | undefined,
      filters: {
        actorId: args?.actorId as string | undefined,
        actorType: args?.actorType as "user" | "apikey" | "system" | undefined,
        actionCategory: args?.actionCategory as
          | "authentication"
          | "authorization"
          | "scan"
          | "policy"
          | "suppression"
          | "admin"
          | "data"
          | undefined,
        outcome: args?.outcome as "success" | "failure" | undefined,
        startTime: args?.startTime as string | undefined,
        endTime: args?.endTime as string | undefined,
      },
      includeChecksum: args?.includeChecksum as boolean | undefined,
      outputPath: args?.outputPath as string | undefined,
    });

    return result;
  },

  audit_stats: async () => {
    // Initialize Audit database if not already done
    if (!isAuditDbInitialized()) {
      const result = initAuditDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Audit database: ${result.error}` };
      }
    }

    return getAuditStats();
  },
};

// Executive Dashboard handlers
const dashboardHandlers: Record<string, ToolHandler> = {
  dashboard_get_summary: async (args) => {
    // Initialize Dashboard database if not already done
    if (!isDashboardDbInitialized()) {
      const result = initDashboardDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Dashboard database: ${result.error}` };
      }
    }

    const timeRange = (args?.timeRange as "24h" | "7d" | "30d" | "90d") || "30d";
    return getDashboardSummary(timeRange);
  },

  dashboard_get_health_score: async (args) => {
    // Initialize Dashboard database if not already done
    if (!isDashboardDbInitialized()) {
      const result = initDashboardDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Dashboard database: ${result.error}` };
      }
    }

    const timeRange = (args?.timeRange as "24h" | "7d" | "30d" | "90d") || "30d";
    return getHealthScore(timeRange);
  },

  dashboard_get_top_risks: async (args) => {
    // Initialize Dashboard database if not already done
    if (!isDashboardDbInitialized()) {
      const result = initDashboardDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Dashboard database: ${result.error}` };
      }
    }

    const count = (args?.count as number) || 10;
    return getTopRisks(count);
  },
};

// Report Templates handlers
const reportHandlers: Record<string, ToolHandler> = {
  report_list_templates: async (args) => {
    // Initialize Report database if not already done
    if (!isReportDbInitialized()) {
      const result = initReportDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Report database: ${result.error}` };
      }
    }

    const templates = listTemplates({
      includeBuiltin: args?.includeBuiltin as boolean | undefined,
      format: args?.format as "html" | "markdown" | "json" | undefined,
    });

    return {
      count: templates.length,
      templates: templates.map((t) => ({
        id: t.id,
        name: t.name,
        description: t.description,
        format: t.format,
        isBuiltin: t.isBuiltin,
        sectionCount: t.sections.filter((s) => s.enabled).length,
      })),
    };
  },

  report_generate: async (args) => {
    // Initialize Report database if not already done
    if (!isReportDbInitialized()) {
      const result = initReportDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Report database: ${result.error}` };
      }
    }

    const templateId = args?.templateId as string;
    if (!templateId) {
      return { error: "templateId is required" };
    }

    try {
      const report = generateReport({
        templateId,
        title: args?.title as string | undefined,
        filters: {
          timeRange: args?.timeRange as "24h" | "7d" | "30d" | "90d" | undefined,
        },
        includeToc: args?.includeToc as boolean | undefined,
      });

      return {
        id: report.id,
        templateName: report.templateName,
        title: report.title,
        format: report.format,
        generatedAt: report.generatedAt,
        durationMs: report.durationMs,
        summary: report.summary,
        contentLength: report.content.length,
        content: report.content,
      };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  report_create_template: async (args) => {
    // Initialize Report database if not already done
    if (!isReportDbInitialized()) {
      const result = initReportDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Report database: ${result.error}` };
      }
    }

    const name = args?.name as string;
    const sections = args?.sections as Array<{ type: string; enabled?: boolean; title?: string }>;

    if (!name) {
      return { error: "name is required" };
    }
    if (!sections || !Array.isArray(sections) || sections.length === 0) {
      return { error: "sections array is required and must not be empty" };
    }

    try {
      // Import createTemplate from handlers
      const { createTemplate } = await import("./handlers.js");

      const template = createTemplate({
        name,
        description: args?.description as string | undefined,
        format: (args?.format as "html" | "markdown" | "json") || "html",
        sections: sections.map((s) => ({
          type: s.type as Parameters<typeof createTemplate>[0]["sections"][0]["type"],
          enabled: s.enabled !== false,
          title: s.title,
        })),
      });

      return {
        id: template.id,
        name: template.name,
        description: template.description,
        format: template.format,
        sectionCount: template.sections.filter((s) => s.enabled).length,
        createdAt: template.createdAt,
      };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  report_schedule: async (args) => {
    // Initialize Report database if not already done
    if (!isReportDbInitialized()) {
      const result = initReportDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Report database: ${result.error}` };
      }
    }

    const name = args?.name as string;
    const templateId = args?.templateId as string;
    const frequency = args?.frequency as "once" | "daily" | "weekly" | "monthly";

    if (!name) {
      return { error: "name is required" };
    }
    if (!templateId) {
      return { error: "templateId is required" };
    }
    if (!frequency) {
      return { error: "frequency is required" };
    }

    try {
      const schedule = createReportSchedule({
        name,
        templateId,
        frequency,
        dayOfWeek: args?.dayOfWeek as number | undefined,
        dayOfMonth: args?.dayOfMonth as number | undefined,
        hour: args?.hour as number | undefined,
        webhook: args?.webhookUrl ? { url: args.webhookUrl as string } : undefined,
        enabled: args?.enabled !== false,
      });

      return {
        id: schedule.id,
        name: schedule.name,
        templateId: schedule.templateId,
        frequency: schedule.frequency,
        enabled: schedule.enabled,
        nextRunAt: schedule.nextRunAt,
        createdAt: schedule.createdAt,
      };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },
};

// Trend Analysis handlers
const trendHandlers: Record<string, ToolHandler> = {
  trend_get_vulnerability_history: async (args) => {
    if (!isTrendDbInitialized()) {
      initTrendDatabase();
    }

    const target = args?.target as string;
    if (!target) {
      return { error: "target is required" };
    }

    try {
      const history = getVulnerabilityHistory({
        target,
        targetType: args?.targetType as "image" | "project" | "organization" | undefined,
        startDate: args?.startDate as string | undefined,
        endDate: args?.endDate as string | undefined,
        granularity: args?.granularity as "daily" | "weekly" | "monthly" | undefined,
        includeMovingAverages: args?.includeMovingAverages as boolean | undefined,
      });

      return history;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  trend_get_forecast: async (args) => {
    if (!isTrendDbInitialized()) {
      initTrendDatabase();
    }

    const target = args?.target as string;
    if (!target) {
      return { error: "target is required" };
    }

    try {
      const forecast = getTrendForecast({
        target,
        targetType: args?.targetType as "image" | "project" | "organization" | undefined,
        horizonDays: args?.horizonDays as number | undefined,
        confidenceLevel: args?.confidenceLevel as number | undefined,
        historicalDays: args?.historicalDays as number | undefined,
      });

      return forecast;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  trend_detect_anomalies: async (args) => {
    if (!isTrendDbInitialized()) {
      initTrendDatabase();
    }

    const target = args?.target as string;
    if (!target) {
      return { error: "target is required" };
    }

    try {
      const anomalies = detectTrendAnomalies({
        target,
        targetType: args?.targetType as "image" | "project" | "organization" | undefined,
        startDate: args?.startDate as string | undefined,
        endDate: args?.endDate as string | undefined,
        zScoreThreshold: args?.zScoreThreshold as number | undefined,
        minDeviationPercent: args?.minDeviationPercent as number | undefined,
      });

      return anomalies;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  trend_compare_periods: async (args) => {
    if (!isTrendDbInitialized()) {
      initTrendDatabase();
    }

    const target = args?.target as string;
    const period1Start = args?.period1Start as string;
    const period1End = args?.period1End as string;
    const period2Start = args?.period2Start as string;
    const period2End = args?.period2End as string;

    if (!target) {
      return { error: "target is required" };
    }
    if (!period1Start || !period1End) {
      return { error: "period1Start and period1End are required" };
    }
    if (!period2Start || !period2End) {
      return { error: "period2Start and period2End are required" };
    }

    try {
      const comparison = compareTrendPeriods({
        target,
        targetType: args?.targetType as "image" | "project" | "organization" | undefined,
        period1Start,
        period1End,
        period1Label: args?.period1Label as string | undefined,
        period2Start,
        period2End,
        period2Label: args?.period2Label as string | undefined,
      });

      return comparison;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },
};

// Risk Scoring handlers
const riskHandlers: Record<string, ToolHandler> = {
  risk_calculate_score: async (args) => {
    if (!isRiskDbInitialized()) {
      const result = initRiskDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Risk database: ${result.error}` };
      }
    }

    const vulnId = args?.vulnId as string;
    const cvssScore = args?.cvssScore as number;
    const asset = args?.asset as string;

    if (!vulnId) {
      return { error: "vulnId is required" };
    }
    if (cvssScore === undefined || cvssScore === null) {
      return { error: "cvssScore is required" };
    }
    if (!asset) {
      return { error: "asset is required" };
    }

    try {
      // Build asset config if criticality/exposure provided
      const assetConfig =
        args?.criticality || args?.exposure
          ? {
              asset,
              assetType:
                (args?.assetType as "image" | "project" | "repository" | "service") || "image",
              criticality: (args?.criticality as RiskAssetCriticality) || "medium",
              exposure: (args?.exposure as RiskExposureLevel) || "internal-only",
            }
          : asset;

      // Build exploitability factors
      const exploitability =
        args?.exploitInWild ||
        args?.pocAvailable ||
        args?.activelyExploited ||
        args?.cisaKev ||
        args?.epssScore !== undefined
          ? {
              exploitInWild: (args?.exploitInWild as boolean) || false,
              pocAvailable: (args?.pocAvailable as boolean) || false,
              weaponized: false,
              activelyExploited: (args?.activelyExploited as boolean) || false,
              cisaKev: (args?.cisaKev as boolean) || false,
              epssScore: args?.epssScore as number | undefined,
            }
          : undefined;

      const score = calculateRiskScore({
        vulnId,
        cvss: { baseScore: cvssScore },
        asset: assetConfig,
        exploitability,
        firstDetected: args?.firstDetected as string | undefined,
      });

      // Store if requested
      if (args?.storeResult) {
        storeRiskScore(score, asset, args?.firstDetected as string | undefined);
      }

      return score;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  risk_set_asset_criticality: async (args) => {
    if (!isRiskDbInitialized()) {
      const result = initRiskDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Risk database: ${result.error}` };
      }
    }

    const asset = args?.asset as string;
    const assetType = args?.assetType as "image" | "project" | "repository" | "service";
    const criticality = args?.criticality as RiskAssetCriticality;
    const exposure = args?.exposure as RiskExposureLevel;

    if (!asset) {
      return { error: "asset is required" };
    }
    if (!assetType) {
      return { error: "assetType is required" };
    }
    if (!criticality) {
      return { error: "criticality is required" };
    }
    if (!exposure) {
      return { error: "exposure is required" };
    }

    try {
      const config = setRiskAssetConfig({
        asset,
        assetType,
        criticality,
        exposure,
        businessContext: args?.businessContext as string | undefined,
        owner: args?.owner as string | undefined,
        complianceFrameworks: args?.complianceFrameworks as string[] | undefined,
        customMultiplier: args?.customMultiplier as number | undefined,
      });

      return config;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  risk_get_prioritized_list: async (args) => {
    if (!isRiskDbInitialized()) {
      const result = initRiskDatabase();
      if (!result.success) {
        return { error: `Failed to initialize Risk database: ${result.error}` };
      }
    }

    try {
      const result = getPrioritizedList({
        assets: args?.assets as string[] | undefined,
        minRiskScore: args?.minRiskScore as number | undefined,
        limit: args?.limit as number | undefined,
        includeTiers: args?.includeTiers as RiskTier[] | undefined,
        groupByAsset: args?.groupByAsset as boolean | undefined,
      });

      return result;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },
};

// Report Export (PDF, Excel, CSV) handlers
const exportHandlers: Record<string, ToolHandler> = {
  export_to_pdf: async (args) => {
    const data = args?.data as ReportData;
    const outputPath = args?.outputPath as string;

    if (!data) {
      return { error: "data is required" };
    }
    if (!outputPath) {
      return { error: "outputPath is required" };
    }

    try {
      const result = await exportReportToPdf(data, outputPath, {
        pageSize: args?.pageSize as "A4" | "Letter" | "Legal" | "A3" | "Tabloid",
        orientation: args?.orientation as "portrait" | "landscape",
        includeTableOfContents: args?.includeTableOfContents as boolean | undefined,
        branding: args?.branding as
          | { logo?: string; companyName?: string; primaryColor?: string }
          | undefined,
      });

      return result;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  export_to_excel: async (args) => {
    const data = args?.data as ReportData;
    const outputPath = args?.outputPath as string;

    if (!data) {
      return { error: "data is required" };
    }
    if (!outputPath) {
      return { error: "outputPath is required" };
    }

    try {
      const result = await exportReportToExcel(data, outputPath, {
        author: args?.author as string | undefined,
        company: args?.company as string | undefined,
        includeCharts: args?.includeCharts as boolean | undefined,
      });

      return result;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  export_to_csv: async (args) => {
    const data = args?.data as ReportData;
    const outputPath = args?.outputPath as string;

    if (!data) {
      return { error: "data is required" };
    }
    if (!outputPath) {
      return { error: "outputPath is required" };
    }

    try {
      const result = await exportVulnerabilitiesToCsv(data, outputPath, {
        delimiter: args?.delimiter as "," | ";" | "\t" | "|" | undefined,
        includeBom: args?.includeBom as boolean | undefined,
      });

      return result;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },
};

// Cross-Project Comparative Analysis handlers
let comparisonDbInitialized = false;

function ensureComparisonDb() {
  if (!comparisonDbInitialized) {
    const result = initComparisonDb();
    if (!result.success) {
      throw new Error(`Failed to initialize comparison database: ${result.error}`);
    }
    comparisonDbInitialized = true;
  }
}

const comparisonHandlers: Record<string, ToolHandler> = {
  compare_projects: async (args) => {
    ensureComparisonDb();

    const projectIdA = args?.projectIdA as string;
    const projectIdB = args?.projectIdB as string;
    const metricsA = args?.metricsA as EntityMetrics;
    const metricsB = args?.metricsB as EntityMetrics;

    if (!projectIdA) {
      return { error: "projectIdA is required" };
    }
    if (!projectIdB) {
      return { error: "projectIdB is required" };
    }
    if (!metricsA) {
      return { error: "metricsA is required" };
    }
    if (!metricsB) {
      return { error: "metricsB is required" };
    }

    try {
      const result = compareProjects({
        projectIdA,
        projectIdB,
        metricsA,
        metricsB,
        normalize: args?.normalize as boolean | undefined,
      });

      return result;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  compare_teams: async (args) => {
    ensureComparisonDb();

    const teamIdA = args?.teamIdA as string;
    const teamIdB = args?.teamIdB as string;
    const metricsA = args?.metricsA as EntityMetrics;
    const metricsB = args?.metricsB as EntityMetrics;

    if (!teamIdA) {
      return { error: "teamIdA is required" };
    }
    if (!teamIdB) {
      return { error: "teamIdB is required" };
    }
    if (!metricsA) {
      return { error: "metricsA is required" };
    }
    if (!metricsB) {
      return { error: "metricsB is required" };
    }

    try {
      const result = compareTeams({
        teamIdA,
        teamIdB,
        metricsA,
        metricsB,
        normalize: args?.normalize as boolean | undefined,
      });

      return result;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  compare_to_baseline: async (args) => {
    ensureComparisonDb();

    const currentMetrics = args?.currentMetrics as EntityMetrics;

    if (!currentMetrics) {
      return { error: "currentMetrics is required" };
    }

    try {
      const result = compareToBaseline({
        currentMetrics,
        baselineId: args?.baselineId as string | undefined,
        useDefaultBaseline: args?.useDefaultBaseline as boolean | undefined,
        entityId: args?.entityId as string | undefined,
      });

      return result;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },
};

// =============================================================================
// Remediation Automation Handlers (v1.24.0)
// =============================================================================
const remediationAutomationHandlers: Record<string, ToolHandler> = {
  remediation_create_pr: async (args) => {
    const owner = args?.owner as string;
    const repo = args?.repo as string;
    const vulnIds = args?.vulnIds as string[];

    if (!owner || !repo || !vulnIds?.length) {
      return { error: "owner, repo, and vulnIds are required" };
    }

    try {
      // Get remediation suggestions for the vulnIds
      const { createPullRequest } = await import("./handlers.js");

      // For now, create a simple PR with the vuln IDs
      const result = await createPullRequest(
        vulnIds.map((vulnId) => ({
          vulnerability: { id: vulnId, severity: "UNKNOWN" as const },
          package: "unknown",
          currentVersion: "unknown",
          fixedVersion: "unknown",
          command: "",
          packageManager: "npm" as const,
          breaking: false,
          cvesFixed: [vulnId],
          confidence: "low" as const,
        })),
        {
          owner,
          repo,
          baseBranch: args?.baseBranch as string,
          dryRun: args?.dryRun as boolean,
        }
      );

      return result;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  remediation_batch_create: async (args) => {
    const owner = args?.owner as string;
    const repo = args?.repo as string;
    const scanTarget = args?.scanTarget as string;

    if (!owner || !repo || !scanTarget) {
      return { error: "owner, repo, and scanTarget are required" };
    }

    try {
      const { trivyScanPath, generateRemediations, createBatchPullRequests } =
        await import("./handlers.js");

      // Scan for vulnerabilities
      const scanResult = await trivyScanPath(
        scanTarget,
        (args?.severity as string) || "CRITICAL,HIGH"
      );

      // Generate remediation plan
      const plan = generateRemediations(scanResult as TrivyScanResult);

      // Create batch PRs
      const result = await createBatchPullRequests(plan, {
        owner,
        repo,
        maxPrs: (args?.maxPrs as number) || 10,
        dryRun: args?.dryRun as boolean,
      });

      return result;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  remediation_get_status: async (args) => {
    const owner = args?.owner as string;
    const repo = args?.repo as string;
    const prNumber = args?.prNumber as number;

    if (!owner || !repo || !prNumber) {
      return { error: "owner, repo, and prNumber are required" };
    }

    try {
      const { getPrStatus } = await import("./handlers.js");
      const status = await getPrStatus(prNumber, { owner, repo });
      return status || { error: "PR not found" };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  ide_get_diagnostics: async (args) => {
    const scanTarget = args?.scanTarget as string;

    if (!scanTarget) {
      return { error: "scanTarget is required" };
    }

    try {
      const { trivyScanPath, generateDiagnostics } = await import("./handlers.js");

      const scanResult = await trivyScanPath(
        scanTarget,
        (args?.minSeverity as string) || "LOW,MEDIUM,HIGH,CRITICAL"
      );

      const diagnostics = generateDiagnostics(scanResult as TrivyScanResult, {
        minSeverity: args?.minSeverity as string,
        basePath: args?.basePath as string,
      });

      return diagnostics;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  ide_get_code_actions: async (args) => {
    const filePath = args?.filePath as string;
    const scanTarget = args?.scanTarget as string;

    if (!filePath || !scanTarget) {
      return { error: "filePath and scanTarget are required" };
    }

    try {
      const { trivyScanPath, generateRemediations, generateCodeActions } =
        await import("./handlers.js");

      const scanResult = await trivyScanPath(scanTarget);
      const plan = generateRemediations(scanResult as TrivyScanResult);
      const actions = generateCodeActions(plan.suggestions, { filePath });

      return { actions };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  ide_apply_fix: async (args) => {
    const filePath = args?.filePath as string;
    const vulnId = args?.vulnId as string;
    const packageName = args?.packageName as string;
    const targetVersion = args?.targetVersion as string;

    if (!filePath || !vulnId || !packageName || !targetVersion) {
      return { error: "filePath, vulnId, packageName, and targetVersion are required" };
    }

    try {
      const fs = await import("fs");
      const { generateFixEdit } = await import("./handlers.js");

      const fileContent = fs.readFileSync(filePath, "utf-8");
      const suggestion = {
        vulnerability: { id: vulnId, severity: "UNKNOWN" as const },
        package: packageName,
        currentVersion: "unknown",
        fixedVersion: targetVersion,
        command: "",
        packageManager: "npm" as const,
        breaking: false,
        cvesFixed: [vulnId],
        confidence: "high" as const,
      };

      const edit = generateFixEdit(suggestion, fileContent, filePath);

      if (edit) {
        // Apply the edit
        const lines = fileContent.split("\n");
        lines[edit.range.start.line] = edit.newText;
        fs.writeFileSync(filePath, lines.join("\n"));
        return { success: true, edit };
      }

      return { success: false, error: "Could not generate fix edit" };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  deps_check_updates: async (args) => {
    const projectPath = args?.projectPath as string;

    if (!projectPath) {
      return { error: "projectPath is required" };
    }

    try {
      const { checkUpdates } = await import("./handlers.js");
      const result = await checkUpdates(projectPath, {
        packageManager: args?.packageManager as PackageManager | undefined,
      });
      return result;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  deps_preview_update: async (args) => {
    const packageName = args?.packageName as string;
    const targetVersion = args?.targetVersion as string;

    if (!packageName || !targetVersion) {
      return { error: "packageName and targetVersion are required" };
    }

    try {
      const { previewUpdate } = await import("./handlers.js");
      const preview = await previewUpdate(packageName, targetVersion, {
        projectPath: args?.projectPath as string,
        currentVersion: args?.currentVersion as string,
      });
      return preview;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  deps_apply_updates: async (args) => {
    const projectPath = args?.projectPath as string;
    const updates = args?.updates as Array<{ package: string; version: string }>;

    if (!projectPath || !updates?.length) {
      return { error: "projectPath and updates are required" };
    }

    try {
      const { applyUpdates } = await import("./handlers.js");
      const result = await applyUpdates(updates, {
        projectPath,
        packageManager: args?.packageManager as PackageManager | undefined,
        dryRun: args?.dryRun as boolean,
        stopOnError: args?.stopOnError as boolean,
      });
      return result;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  deps_rollback: async (args) => {
    const projectPath = args?.projectPath as string;

    if (!projectPath) {
      return { error: "projectPath is required" };
    }

    try {
      const { rollbackUpdates } = await import("./handlers.js");
      const result = await rollbackUpdates({
        projectPath,
        packageManager: args?.packageManager as PackageManager | undefined,
      });
      return result;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  fix_verify: async (args) => {
    const fixes = args?.fixes as Array<{ vulnId: string; packageName: string }>;
    const beforeScan = args?.beforeScan as TrivyScanResult;
    const afterScan = args?.afterScan as TrivyScanResult;

    if (!fixes?.length || !beforeScan || !afterScan) {
      return { error: "fixes, beforeScan, and afterScan are required" };
    }

    try {
      const { verifyFixes } = await import("./handlers.js");
      const result = verifyFixes(fixes, beforeScan, afterScan);
      return result;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  fix_rescan: async (args) => {
    const target = args?.target as string;
    const scanType = args?.scanType as "path" | "image";

    if (!target || !scanType) {
      return { error: "target and scanType are required" };
    }

    try {
      const { trivyScanPath, trivyScanImage, compareScanResultsForVerification } =
        await import("./handlers.js");

      // Perform new scan
      const newScan =
        scanType === "path" ? await trivyScanPath(target) : await trivyScanImage(target);

      // Compare with previous if provided
      if (args?.previousScan) {
        const comparison = compareScanResultsForVerification(
          args.previousScan as TrivyScanResult,
          newScan as TrivyScanResult
        );
        return {
          scan: newScan,
          comparison,
          fixedCount: comparison.fixed.length,
          newCount: comparison.new.length,
        };
      }

      return { scan: newScan };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },
};

// =============================================================================
// SLA Tracking Handlers (v1.25.0)
// =============================================================================
const slaHandlers: Record<string, ToolHandler> = {
  sla_configure: async (args) => {
    const name = args?.name as string;
    const targets = args?.targets as Array<{
      severity: string;
      acknowledgeHours: number;
      remediateHours: number;
      warningThresholdPercent?: number;
    }>;

    if (!name || !targets?.length) {
      return { error: "name and targets are required" };
    }

    try {
      const { configureSla } = await import("./handlers.js");
      const result = configureSla({
        name,
        description: args?.description as string,
        setAsDefault: args?.setAsDefault as boolean,
        targets: targets.map((t) => ({
          severity: t.severity as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
          acknowledgeHours: t.acknowledgeHours,
          remediateHours: t.remediateHours,
          warningThresholdPercent: t.warningThresholdPercent ?? 75,
        })),
      });
      return result;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  sla_get_status: async (args) => {
    try {
      const { getSlaStatus } = await import("./handlers.js");
      const severity = args?.severity as Array<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW"> | undefined;
      const result = getSlaStatus({
        target: args?.target as string,
        severity,
        configId: args?.configId as string,
        includeDetails: args?.includeDetails as boolean,
      });
      return result;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  sla_get_breaches: async (args) => {
    try {
      const { getSlaBreaches } = await import("./handlers.js");
      const severity = args?.severity as Array<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW"> | undefined;
      const result = getSlaBreaches({
        target: args?.target as string,
        severity,
        configId: args?.configId as string,
        limit: args?.limit as number,
      });
      return result;
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },
};

// =============================================================================
// Governance Workflow Handlers (v1.26.0)
// =============================================================================
const governanceHandlers: Record<string, ToolHandler> = {
  governance_create_policy: async (args) => {
    try {
      const { createGovernancePolicy, initGovernanceDatabase } = await import("./handlers.js");
      initGovernanceDatabase();
      return createGovernancePolicy({
        name: args?.name as string,
        description: args?.description as string,
        version: args?.version as string,
        enforcementLevel: args?.enforcementLevel as "advisory" | "blocking",
        owner: args?.owner as string,
        rules: args?.rules as Array<{ type: string; condition: string; action: string }>,
      });
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  governance_list_policies: async (args) => {
    try {
      const { listGovernancePolicies, initGovernanceDatabase } = await import("./handlers.js");
      initGovernanceDatabase();
      return listGovernancePolicies(args?.status as "draft" | "active" | "deprecated");
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  governance_activate_policy: async (args) => {
    try {
      const { activateGovernancePolicy, initGovernanceDatabase } = await import("./handlers.js");
      initGovernanceDatabase();
      return activateGovernancePolicy(args?.policyId as string, args?.actor as string);
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  governance_request_exception: async (args) => {
    try {
      const { requestPolicyException, initGovernanceDatabase } = await import("./handlers.js");
      initGovernanceDatabase();
      return requestPolicyException({
        policyId: args?.policyId as string,
        requester: args?.requester as string,
        reason: args?.reason as string,
        scope: args?.scope as Record<string, unknown>,
        expiresAt: args?.expiresAt as string,
      });
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  governance_approve_exception: async (args) => {
    try {
      const { approvePolicyException, initGovernanceDatabase } = await import("./handlers.js");
      initGovernanceDatabase();
      return approvePolicyException(args?.exceptionId as string, args?.approver as string);
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  governance_list_exceptions: async (args) => {
    try {
      const { listPolicyExceptions, initGovernanceDatabase } = await import("./handlers.js");
      initGovernanceDatabase();
      return listPolicyExceptions(
        args?.policyId as string,
        args?.status as "pending" | "approved" | "rejected" | "expired"
      );
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },
};

// =============================================================================
// Evidence Collection Handlers (v1.26.0)
// =============================================================================
const evidenceHandlers: Record<string, ToolHandler> = {
  evidence_collect: async (args) => {
    try {
      const { collectEvidence, initEvidenceDatabase } = await import("./handlers.js");
      initEvidenceDatabase();
      return collectEvidence({
        type: args?.type as
          | "scan_result"
          | "configuration"
          | "policy"
          | "attestation"
          | "log"
          | "screenshot"
          | "document",
        title: args?.title as string,
        description: args?.description as string,
        framework: args?.framework as string,
        controlId: args?.controlId as string,
        source: args?.source as string,
        collectedBy: args?.collectedBy as string,
        content: args?.content as Record<string, unknown>,
        tags: args?.tags as string[],
      });
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  evidence_attach: async (args) => {
    try {
      const { attachToEvidence, initEvidenceDatabase } = await import("./handlers.js");
      initEvidenceDatabase();
      return attachToEvidence(args?.evidenceId as string, {
        filename: args?.filename as string,
        mimeType: args?.mimeType as string,
        storagePath: args?.storagePath as string,
        uploadedBy: args?.uploadedBy as string,
      });
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  evidence_export: async (args) => {
    try {
      const { exportEvidencePackage, initEvidenceDatabase } = await import("./handlers.js");
      initEvidenceDatabase();
      return exportEvidencePackage({
        framework: args?.framework as string,
        controlIds: args?.controlIds as string[],
        includeContent: args?.includeContent as boolean,
        includeAttachments: args?.includeAttachments as boolean,
      });
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },
};

// =============================================================================
// Audit Preparation Handlers (v1.26.0)
// =============================================================================
const auditPrepHandlers: Record<string, ToolHandler> = {
  audit_prepare_package: async (args) => {
    try {
      const { prepareAuditPackage, initAuditDatabase } = await import("./handlers.js");
      initAuditDatabase();
      return prepareAuditPackage({
        name: args?.name as string,
        type: args?.type as "internal" | "external" | "certification" | "assessment",
        framework: args?.framework as string,
        preparedBy: args?.preparedBy as string,
        evidenceIds: args?.evidenceIds as string[],
        controlIds: args?.controlIds as string[],
        scope: args?.scope as Record<string, unknown>,
      });
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  audit_generate_attestation: async (args) => {
    try {
      const { generateAttestation, initAuditDatabase } = await import("./handlers.js");
      initAuditDatabase();
      return generateAttestation({
        type: args?.type as string,
        statement: args?.statement as string,
        attester: args?.attester as string,
        attesterRole: args?.attesterRole as string,
        auditPackageId: args?.auditPackageId as string,
        evidenceIds: args?.evidenceIds as string[],
        scope: args?.scope as Record<string, unknown>,
        validUntil: args?.validUntil as string,
      });
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  audit_timeline: async (args) => {
    try {
      const { getComplianceTimeline, initAuditDatabase } = await import("./handlers.js");
      initAuditDatabase();
      return getComplianceTimeline({
        target: args?.target as string,
        framework: args?.framework as string,
        eventTypes: args?.eventTypes as string[],
        startDate: args?.startDate as string,
        endDate: args?.endDate as string,
        limit: args?.limit as number,
      });
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
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
  ...multiRegistryHandlers,
  ...sarifHandlers,
  ...schedulerHandlers,
  ...remediationHandlers,
  ...complianceHandlers,
  ...opaHandlers,
  ...vulnDbHandlers,
  ...cacheHandlers,
  ...suppressionHandlers,
  ...metricsHandlers,
  ...scanCompareHandlers,
  ...ssoHandlers,
  ...rbacHandlers,
  ...apiKeyHandlers,
  ...teamHandlers,
  ...sessionHandlers,
  ...auditHandlers,
  ...dashboardHandlers,
  ...reportHandlers,
  ...trendHandlers,
  ...riskHandlers,
  ...exportHandlers,
  ...comparisonHandlers,
  ...remediationAutomationHandlers,
  ...slaHandlers,
  ...governanceHandlers,
  ...evidenceHandlers,
  ...auditPrepHandlers,
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
