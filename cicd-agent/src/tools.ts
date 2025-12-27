import Anthropic from "@anthropic-ai/sdk";
import {
  // Handlers
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
  sonarGetQualityGateStatus,
  dtrackGetProjects,
  dtrackGetVulnerabilities,
  dtrackGetFindings,
  dtrackGetComponents,
  dtrackUploadSbom,
  giteaGetRepos,
  giteaGetRepo,
  giteaGetBranches,
  giteaGetCommits,
  giteaCreateRepo,
  giteaMigrateRepo,
  giteaListPullRequests,
  giteaGetPullRequest,
  giteaCreatePullRequest,
  giteaMergePullRequest,
  giteaCreateIssue,
  giteaListIssues,
  droneGetRepos,
  droneGetBuilds,
  droneGetBuild,
  droneGetBuildLogs,
  droneTriggerBuild,
  registryGetCatalog,
  registryGetTags,
  checkPlatformStatus,
  getSecurityDashboard,
  // Compliance
  getComplianceFrameworks,
  getComplianceControls,
  getComplianceControl,
  generateComplianceReport,
  generateComplianceHtml,
  recordComplianceTrend,
  getComplianceTrend,
  getComplianceTrendTargets,
  checkComplianceStatus,
  // Types
  type ComplianceFramework,
} from "@cicd/shared";

// Re-export validation functions and config for tests
export { validateSeverity, sanitizePath, sanitizeImageName, config } from "@cicd/shared";

// =============================================================================
// Tool Handler Map
// =============================================================================
type ToolHandler = (input: Record<string, unknown>) => Promise<unknown>;

const toolHandlers: Record<string, ToolHandler> = {
  // Trivy
  trivy_scan_path: async (input) => trivyScanPath(input.path as string, input.severity as string),
  trivy_scan_image: async (input) =>
    trivyScanImage(input.image as string, input.severity as string),
  trivy_generate_sbom: async (input) =>
    trivyGenerateSbom(input.path as string, input.format as "cyclonedx" | "spdx-json"),
  trivy_generate_sbom_image: async (input) =>
    trivyGenerateSbomImage(input.image as string, input.format as "cyclonedx" | "spdx-json"),
  trivy_scan_iac: async (input) => trivyScanIac(input.path as string, input.severity as string),
  trivy_scan_secrets: async (input) =>
    trivyScanSecrets(input.path as string, input.severity as string),
  trivy_scan_secrets_image: async (input) =>
    trivyScanSecretsImage(input.image as string, input.severity as string),
  trivy_scan_licenses: async (input) =>
    trivyScanLicenses(input.path as string, input.severity as string),
  trivy_scan_licenses_image: async (input) =>
    trivyScanLicensesImage(input.image as string, input.severity as string),
  trivy_scan_image_full: async (input) =>
    trivyScanImageFull(
      input.image as string,
      input.severity as string,
      input.sbomFormat as "cyclonedx" | "spdx-json"
    ),
  trivy_scan_path_full: async (input) =>
    trivyScanPathFull(
      input.path as string,
      input.severity as string,
      input.sbomFormat as "cyclonedx" | "spdx-json"
    ),
  // SonarQube
  sonar_list_projects: async () => sonarGetProjects(),
  sonar_get_issues: async (input) =>
    sonarGetIssues(input.projectKey as string, input.types as string),
  sonar_get_security_hotspots: async (input) =>
    sonarGetSecurityHotspots(input.projectKey as string),
  sonar_get_metrics: async (input) => sonarGetMetrics(input.projectKey as string),
  sonar_get_quality_gate_status: async (input) =>
    sonarGetQualityGateStatus(input.projectKey as string),
  // Dependency-Track
  dtrack_list_projects: async () => dtrackGetProjects(),
  dtrack_get_vulnerabilities: async (input) =>
    dtrackGetVulnerabilities(input.projectUuid as string),
  dtrack_get_findings: async (input) => dtrackGetFindings(input.projectUuid as string),
  dtrack_get_components: async (input) => dtrackGetComponents(input.projectUuid as string),
  dtrack_upload_sbom: async (input) =>
    dtrackUploadSbom(
      input.projectName as string,
      input.projectVersion as string,
      input.sbom as string,
      input.autoCreate as boolean
    ),
  // Gitea
  gitea_list_repos: async () => giteaGetRepos(),
  gitea_get_repo: async (input) => giteaGetRepo(input.owner as string, input.repo as string),
  gitea_get_branches: async (input) =>
    giteaGetBranches(input.owner as string, input.repo as string),
  gitea_get_commits: async (input) =>
    giteaGetCommits(input.owner as string, input.repo as string, input.limit as number),
  gitea_create_repo: async (input) =>
    giteaCreateRepo(input.name as string, input.description as string, input.private as boolean),
  gitea_migrate_repo: async (input) =>
    giteaMigrateRepo(input.cloneUrl as string, input.repoName as string, input.authToken as string),
  gitea_list_pull_requests: async (input) =>
    giteaListPullRequests(
      input.owner as string,
      input.repo as string,
      input.state as "open" | "closed" | "all" | undefined
    ),
  gitea_get_pull_request: async (input) =>
    giteaGetPullRequest(input.owner as string, input.repo as string, input.pullNumber as number),
  gitea_create_pull_request: async (input) =>
    giteaCreatePullRequest(
      input.owner as string,
      input.repo as string,
      input.title as string,
      input.head as string,
      input.base as string,
      input.body as string
    ),
  gitea_merge_pull_request: async (input) =>
    giteaMergePullRequest(
      input.owner as string,
      input.repo as string,
      input.pullNumber as number,
      input.mergeStyle as "merge" | "rebase" | "squash"
    ),
  gitea_create_issue: async (input) =>
    giteaCreateIssue(
      input.owner as string,
      input.repo as string,
      input.title as string,
      input.body as string,
      input.labels as string[]
    ),
  gitea_list_issues: async (input) =>
    giteaListIssues(
      input.owner as string,
      input.repo as string,
      input.state as "open" | "closed" | "all" | undefined
    ),
  // Drone
  drone_list_repos: async () => droneGetRepos(),
  drone_get_builds: async (input) => droneGetBuilds(input.owner as string, input.repo as string),
  drone_get_build: async (input) =>
    droneGetBuild(input.owner as string, input.repo as string, input.build as number),
  drone_get_build_logs: async (input) =>
    droneGetBuildLogs(
      input.owner as string,
      input.repo as string,
      input.build as number,
      input.stage as number,
      input.step as number
    ),
  drone_trigger_build: async (input) =>
    droneTriggerBuild(input.owner as string, input.repo as string, input.branch as string),
  // Registry
  registry_list_images: async () => registryGetCatalog(),
  registry_get_tags: async (input) => registryGetTags(input.image as string),
  // Platform
  check_platform_status: async () => checkPlatformStatus(),
  // Security Dashboard
  get_security_dashboard: async (input) =>
    getSecurityDashboard({
      image: input.image as string | undefined,
      path: input.path as string | undefined,
      sonarProject: input.sonarProject as string | undefined,
      dtrackProjectUuid: input.dtrackProjectUuid as string | undefined,
      severity: input.severity as string | undefined,
    }),
  // Compliance
  compliance_get_frameworks: async () => getComplianceFrameworks(),
  compliance_get_controls: async (input) => {
    const framework = input.framework as ComplianceFramework;
    const controlId = input.controlId as string | undefined;
    if (controlId) {
      return getComplianceControl(framework, controlId);
    }
    return getComplianceControls(framework);
  },
  compliance_check_status: async (input) => {
    const dashboardResult = await getSecurityDashboard({
      image: input.image as string | undefined,
      path: input.path as string | undefined,
      sonarProject: input.sonarProject as string | undefined,
      dtrackProjectUuid: input.dtrackProjectUuid as string | undefined,
      severity: input.severity as string | undefined,
    });
    return checkComplianceStatus(dashboardResult, {
      frameworks: input.frameworks as ComplianceFramework[] | undefined,
      severity: input.severity as string | undefined,
    });
  },
  compliance_generate_report: async (input) => {
    const dashboardResult = await getSecurityDashboard({
      image: input.image as string | undefined,
      path: input.path as string | undefined,
      sonarProject: input.sonarProject as string | undefined,
      dtrackProjectUuid: input.dtrackProjectUuid as string | undefined,
      severity: input.severity as string | undefined,
    });
    const options = {
      frameworks: input.frameworks as ComplianceFramework[] | undefined,
      title: input.title as string | undefined,
      organization: input.organization as string | undefined,
    };
    const report = generateComplianceReport(dashboardResult, options);
    if (input.format === "html") {
      return { html: generateComplianceHtml(report, options) };
    }
    return report;
  },
  compliance_trend_record: async (input) => {
    const target = input.target as string;
    const dashboardResult = await getSecurityDashboard({
      image: input.image as string | undefined,
      path: input.path as string | undefined,
      sonarProject: input.sonarProject as string | undefined,
      dtrackProjectUuid: input.dtrackProjectUuid as string | undefined,
      severity: input.severity as string | undefined,
    });
    const report = generateComplianceReport(dashboardResult, {
      frameworks: input.frameworks as ComplianceFramework[] | undefined,
    });
    return recordComplianceTrend(target, report);
  },
  compliance_trend_get: async (input) => {
    const target = input.target as string;
    const days = (input.days as number) || 30;
    return getComplianceTrend(target, days);
  },
  compliance_trend_list_targets: async () => getComplianceTrendTargets(),
};

// =============================================================================
// Tool Definitions for Claude
// =============================================================================
export const tools: Anthropic.Tool[] = [
  // Trivy Tools
  {
    name: "trivy_scan_path",
    description:
      "Scan a local file path for vulnerabilities using Trivy. Detects vulnerabilities in dependencies (npm, pip, go, maven, etc.) and secrets in code.",
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory to scan",
        },
        severity: {
          type: "string",
          description:
            "Severity levels to report: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL (default: HIGH,CRITICAL)",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "trivy_scan_image",
    description:
      "Scan a Docker image for vulnerabilities using Trivy. Works with local images and registry images.",
    input_schema: {
      type: "object" as const,
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)",
        },
        severity: {
          type: "string",
          description: "Severity levels to report (default: HIGH,CRITICAL)",
        },
      },
      required: ["image"],
    },
  },
  {
    name: "trivy_generate_sbom",
    description:
      "Generate a Software Bill of Materials (SBOM) for a local path using Trivy. Creates a CycloneDX format SBOM listing all components and dependencies.",
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory to scan",
        },
        format: {
          type: "string",
          description: "SBOM format: cyclonedx (default) or spdx-json",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "trivy_generate_sbom_image",
    description:
      "Generate a Software Bill of Materials (SBOM) for a Docker image using Trivy. Creates a CycloneDX format SBOM listing all components in the container.",
    input_schema: {
      type: "object" as const,
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)",
        },
        format: {
          type: "string",
          description: "SBOM format: cyclonedx (default) or spdx-json",
        },
      },
      required: ["image"],
    },
  },
  {
    name: "trivy_scan_iac",
    description:
      "Scan Infrastructure as Code (IaC) files for misconfigurations using Trivy. Detects security issues in Terraform, Kubernetes, Docker, CloudFormation, and other IaC files.",
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory containing IaC files",
        },
        severity: {
          type: "string",
          description:
            "Severity levels to report: LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM,HIGH,CRITICAL)",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "trivy_scan_secrets",
    description:
      "Scan a local path for hardcoded secrets using Trivy. Detects API keys, passwords, tokens, private keys, and other sensitive data in code.",
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory to scan for secrets",
        },
        severity: {
          type: "string",
          description:
            "Severity levels to report: LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM,HIGH,CRITICAL)",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "trivy_scan_secrets_image",
    description:
      "Scan a Docker image for hardcoded secrets using Trivy. Detects API keys, passwords, tokens, private keys, and other sensitive data in container images.",
    input_schema: {
      type: "object" as const,
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)",
        },
        severity: {
          type: "string",
          description:
            "Severity levels to report: LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM,HIGH,CRITICAL)",
        },
      },
      required: ["image"],
    },
  },
  {
    name: "trivy_scan_licenses",
    description:
      "Scan a local path for license information using Trivy. Detects licenses in dependencies and flags potentially problematic licenses (forbidden, restricted, etc.).",
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory to scan for licenses",
        },
        severity: {
          type: "string",
          description:
            "Severity levels to report: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL (default: all)",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "trivy_scan_licenses_image",
    description:
      "Scan a Docker image for license information using Trivy. Detects licenses in dependencies and flags potentially problematic licenses (forbidden, restricted, etc.).",
    input_schema: {
      type: "object" as const,
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)",
        },
        severity: {
          type: "string",
          description:
            "Severity levels to report: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL (default: all)",
        },
      },
      required: ["image"],
    },
  },
  {
    name: "trivy_scan_image_full",
    description:
      "Run a comprehensive security scan on a Docker image using Trivy. Combines vulnerability, secret, license scanning, and SBOM generation in one operation for complete image analysis.",
    input_schema: {
      type: "object" as const,
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)",
        },
        severity: {
          type: "string",
          description: "Severity levels to report: HIGH, CRITICAL (default: HIGH,CRITICAL)",
        },
        sbomFormat: {
          type: "string",
          description: "SBOM format: cyclonedx (default) or spdx-json",
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
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory to scan",
        },
        severity: {
          type: "string",
          description: "Severity levels to report: HIGH, CRITICAL (default: HIGH,CRITICAL)",
        },
        sbomFormat: {
          type: "string",
          description: "SBOM format: cyclonedx (default) or spdx-json",
          enum: ["cyclonedx", "spdx-json"],
        },
      },
      required: ["path"],
    },
  },

  // SonarQube Tools
  {
    name: "sonar_list_projects",
    description: "List all projects analyzed in SonarQube",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "sonar_get_issues",
    description: "Get code issues (bugs, vulnerabilities, code smells) for a SonarQube project",
    input_schema: {
      type: "object" as const,
      properties: {
        projectKey: {
          type: "string",
          description: "The SonarQube project key",
        },
        types: {
          type: "string",
          description: "Issue types to filter: VULNERABILITY, BUG, CODE_SMELL (comma-separated)",
        },
      },
      required: ["projectKey"],
    },
  },
  {
    name: "sonar_get_security_hotspots",
    description: "Get security hotspots (potential security issues requiring review) for a project",
    input_schema: {
      type: "object" as const,
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
      "Get quality metrics (bugs count, vulnerabilities, coverage, duplication) for a project",
    input_schema: {
      type: "object" as const,
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
    name: "sonar_get_quality_gate_status",
    description:
      "Get the quality gate status for a SonarQube project. Returns whether the project passes or fails the quality gate with condition details.",
    input_schema: {
      type: "object" as const,
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
    description: "List all projects in Dependency-Track with their vulnerability counts",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "dtrack_get_vulnerabilities",
    description: "Get all vulnerabilities affecting a Dependency-Track project",
    input_schema: {
      type: "object" as const,
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
    description:
      "Get detailed security findings for a project including component and vulnerability info",
    input_schema: {
      type: "object" as const,
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
    description: "Get all components (dependencies) for a project with their details",
    input_schema: {
      type: "object" as const,
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
      "Upload a Software Bill of Materials (SBOM) to Dependency-Track for vulnerability analysis. Supports CycloneDX and SPDX formats.",
    input_schema: {
      type: "object" as const,
      properties: {
        projectName: {
          type: "string",
          description: "Name of the project in Dependency-Track",
        },
        projectVersion: {
          type: "string",
          description: "Version of the project (e.g., 1.0.0)",
        },
        sbom: {
          type: "string",
          description: "The SBOM content as JSON string (CycloneDX or SPDX format)",
        },
        autoCreate: {
          type: "boolean",
          description: "Auto-create project if it doesn't exist (default: true)",
        },
      },
      required: ["projectName", "projectVersion", "sbom"],
    },
  },

  // Gitea Tools
  {
    name: "gitea_list_repos",
    description: "List all Git repositories in Gitea for the current user",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "gitea_get_repo",
    description: "Get detailed information about a specific repository",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: {
          type: "string",
          description: "Repository owner username",
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
    description: "List all branches in a repository",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "gitea_get_commits",
    description: "Get recent commits for a repository",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        limit: {
          type: "number",
          description: "Number of commits to retrieve (default: 10)",
        },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "gitea_create_repo",
    description: "Create a new Git repository in Gitea",
    input_schema: {
      type: "object" as const,
      properties: {
        name: { type: "string", description: "Repository name" },
        description: { type: "string", description: "Repository description" },
        private: {
          type: "boolean",
          description: "Whether the repository is private (default: false)",
        },
      },
      required: ["name"],
    },
  },
  {
    name: "gitea_migrate_repo",
    description: "Migrate a repository from GitHub to Gitea (preserves issues, PRs, releases)",
    input_schema: {
      type: "object" as const,
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
  {
    name: "gitea_list_pull_requests",
    description: "List pull requests for a repository in Gitea",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        state: {
          type: "string",
          description: "PR state filter: open, closed, all (default: open)",
        },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "gitea_get_pull_request",
    description: "Get details of a specific pull request",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        pullNumber: { type: "number", description: "Pull request number" },
      },
      required: ["owner", "repo", "pullNumber"],
    },
  },
  {
    name: "gitea_create_pull_request",
    description: "Create a new pull request in Gitea",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        title: { type: "string", description: "Pull request title" },
        head: { type: "string", description: "Source branch (e.g., feature-branch)" },
        base: { type: "string", description: "Target branch (e.g., main)" },
        body: { type: "string", description: "Pull request description" },
      },
      required: ["owner", "repo", "title", "head", "base"],
    },
  },
  {
    name: "gitea_merge_pull_request",
    description: "Merge a pull request in Gitea",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        pullNumber: { type: "number", description: "Pull request number" },
        mergeStyle: {
          type: "string",
          description: "Merge style: merge, rebase, or squash (default: merge)",
          enum: ["merge", "rebase", "squash"],
        },
      },
      required: ["owner", "repo", "pullNumber"],
    },
  },
  {
    name: "gitea_create_issue",
    description: "Create a new issue in a Gitea repository",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        title: { type: "string", description: "Issue title" },
        body: { type: "string", description: "Issue description" },
        labels: {
          type: "array",
          items: { type: "string" },
          description: "Labels to apply to the issue",
        },
      },
      required: ["owner", "repo", "title"],
    },
  },
  {
    name: "gitea_list_issues",
    description: "List issues for a repository in Gitea",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        state: {
          type: "string",
          description: "Issue state filter: open, closed, all (default: open)",
        },
      },
      required: ["owner", "repo"],
    },
  },

  // Drone CI Tools
  {
    name: "drone_list_repos",
    description: "List all repositories synced with Drone CI",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "drone_get_builds",
    description: "Get build history for a repository",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "drone_get_build",
    description: "Get detailed information about a specific build",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        build: { type: "number", description: "Build number" },
      },
      required: ["owner", "repo", "build"],
    },
  },
  {
    name: "drone_get_build_logs",
    description: "Get logs for a specific build step",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        build: { type: "number", description: "Build number" },
        stage: { type: "number", description: "Stage number (default: 1)" },
        step: { type: "number", description: "Step number (default: 1)" },
      },
      required: ["owner", "repo", "build"],
    },
  },
  {
    name: "drone_trigger_build",
    description: "Trigger a new CI/CD build for a repository",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        branch: {
          type: "string",
          description: "Branch to build (default: main)",
        },
      },
      required: ["owner", "repo"],
    },
  },

  // Registry Tools
  {
    name: "registry_list_images",
    description: "List all images in the local Docker registry",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "registry_get_tags",
    description: "Get all tags for an image in the registry",
    input_schema: {
      type: "object" as const,
      properties: {
        image: { type: "string", description: "Image name" },
      },
      required: ["image"],
    },
  },

  // Platform Status
  {
    name: "check_platform_status",
    description:
      "Check the health status of all CI/CD platform services (Gitea, Drone, SonarQube, etc.)",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  // Security Dashboard
  {
    name: "get_security_dashboard",
    description:
      "Get unified security dashboard aggregating Trivy, SonarQube, and Dependency-Track results. Provides a single-call overview of security posture with aggregated counts and top findings.",
    input_schema: {
      type: "object" as const,
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
        },
      },
    },
  },

  // Compliance Tools
  {
    name: "compliance_get_frameworks",
    description:
      "Get list of all available compliance frameworks with their descriptions. Returns SOC2, HIPAA, PCI-DSS, and CIS framework information.",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "compliance_get_controls",
    description:
      "Get compliance controls for a specific framework. Optionally get a single control by ID. Controls define security requirements and remediation SLAs.",
    input_schema: {
      type: "object" as const,
      properties: {
        framework: {
          type: "string",
          description: "Compliance framework: SOC2, HIPAA, PCI-DSS, or CIS",
          enum: ["SOC2", "HIPAA", "PCI-DSS", "CIS"],
        },
        controlId: {
          type: "string",
          description: "Optional: specific control ID to retrieve (e.g., CC7.1, 164.308(a)(1))",
        },
      },
      required: ["framework"],
    },
  },
  {
    name: "compliance_check_status",
    description:
      "Check compliance status for scan results. Returns pass/fail status, compliance percentage, and violations by framework.",
    input_schema: {
      type: "object" as const,
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
          description: "SonarQube project key",
        },
        dtrackProjectUuid: {
          type: "string",
          description: "Dependency-Track project UUID",
        },
        severity: {
          type: "string",
          description: "Severity filter (default: HIGH,CRITICAL)",
        },
        frameworks: {
          type: "array",
          items: { type: "string", enum: ["SOC2", "HIPAA", "PCI-DSS", "CIS"] },
          description: "Frameworks to check (default: all)",
        },
      },
    },
  },
  {
    name: "compliance_generate_report",
    description:
      "Generate a compliance report for scan results. Can output JSON or styled HTML for audit documentation.",
    input_schema: {
      type: "object" as const,
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
          description: "SonarQube project key",
        },
        dtrackProjectUuid: {
          type: "string",
          description: "Dependency-Track project UUID",
        },
        severity: {
          type: "string",
          description: "Severity filter (default: HIGH,CRITICAL)",
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
          description: "Organization name for report header",
        },
      },
    },
  },
  {
    name: "compliance_trend_record",
    description:
      "Record a compliance snapshot for trend tracking. Call periodically to build compliance trend history.",
    input_schema: {
      type: "object" as const,
      properties: {
        target: {
          type: "string",
          description: "Target identifier (e.g., image name, project key)",
        },
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
          description: "SonarQube project key",
        },
        dtrackProjectUuid: {
          type: "string",
          description: "Dependency-Track project UUID",
        },
        severity: {
          type: "string",
          description: "Severity filter (default: HIGH,CRITICAL)",
        },
        frameworks: {
          type: "array",
          items: { type: "string", enum: ["SOC2", "HIPAA", "PCI-DSS", "CIS"] },
          description: "Frameworks to track (default: all)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "compliance_trend_get",
    description:
      "Get compliance trend data for a target over time. Shows improvement, decline, or stability.",
    input_schema: {
      type: "object" as const,
      properties: {
        target: {
          type: "string",
          description: "Target identifier to get trends for",
        },
        days: {
          type: "number",
          description: "Number of days to include (default: 30)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "compliance_trend_list_targets",
    description: "List all targets that have compliance trend data recorded.",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
];

// =============================================================================
// Tool Executor
// =============================================================================
export async function executeTool(name: string, input: Record<string, unknown>): Promise<string> {
  try {
    const handler = toolHandlers[name];
    if (!handler) {
      throw new Error(`Unknown tool: ${name}`);
    }
    const result = await handler(input);
    return JSON.stringify(result, null, 2);
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return JSON.stringify({ error: errorMessage }, null, 2);
  }
}
