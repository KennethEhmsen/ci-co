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
  dtrackGetProjects,
  dtrackGetVulnerabilities,
  dtrackGetFindings,
  dtrackGetComponents,
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
  checkPlatformStatus,
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
  // Dependency-Track
  dtrack_list_projects: async () => dtrackGetProjects(),
  dtrack_get_vulnerabilities: async (input) =>
    dtrackGetVulnerabilities(input.projectUuid as string),
  dtrack_get_findings: async (input) => dtrackGetFindings(input.projectUuid as string),
  dtrack_get_components: async (input) => dtrackGetComponents(input.projectUuid as string),
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
