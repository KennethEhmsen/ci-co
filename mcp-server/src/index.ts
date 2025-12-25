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
  trivyScanLicenses,
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
  securityScanAll,
  checkPlatformStatus,
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

export async function handleCallTool(
  name: string,
  args?: Record<string, unknown>
): Promise<{
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}> {
  try {
    let result: unknown;

    switch (name) {
      // Trivy
      case "trivy_scan_path":
        result = await trivyScanPath(args?.path as string, args?.severity as string);
        break;
      case "trivy_scan_image":
        result = await trivyScanImage(args?.image as string, args?.severity as string);
        break;
      case "trivy_generate_sbom":
        result = await trivyGenerateSbom(
          args?.path as string,
          args?.format as "cyclonedx" | "spdx-json"
        );
        break;
      case "trivy_generate_sbom_image":
        result = await trivyGenerateSbomImage(
          args?.image as string,
          args?.format as "cyclonedx" | "spdx-json"
        );
        break;
      case "trivy_scan_iac":
        result = await trivyScanIac(args?.path as string, args?.severity as string);
        break;
      case "trivy_scan_secrets":
        result = await trivyScanSecrets(args?.path as string, args?.severity as string);
        break;
      case "trivy_scan_licenses":
        result = await trivyScanLicenses(args?.path as string, args?.severity as string);
        break;

      // SonarQube
      case "sonar_list_projects":
        result = await sonarGetProjects();
        break;
      case "sonar_get_issues":
        result = await sonarGetIssues(args?.projectKey as string, args?.types as string);
        break;
      case "sonar_get_security_hotspots":
        result = await sonarGetSecurityHotspots(args?.projectKey as string);
        break;
      case "sonar_get_metrics":
        result = await sonarGetMetrics(args?.projectKey as string);
        break;

      // Dependency-Track
      case "dtrack_list_projects":
        result = await dtrackGetProjects();
        break;
      case "dtrack_get_vulnerabilities":
        result = await dtrackGetVulnerabilities(args?.projectUuid as string);
        break;
      case "dtrack_get_findings":
        result = await dtrackGetFindings(args?.projectUuid as string);
        break;
      case "dtrack_get_components":
        result = await dtrackGetComponents(args?.projectUuid as string);
        break;

      // Gitea
      case "gitea_list_repos":
        result = await giteaGetRepos();
        break;
      case "gitea_get_repo":
        result = await giteaGetRepo(args?.owner as string, args?.repo as string);
        break;
      case "gitea_get_branches":
        result = await giteaGetBranches(args?.owner as string, args?.repo as string);
        break;
      case "gitea_get_commits":
        result = await giteaGetCommits(
          args?.owner as string,
          args?.repo as string,
          args?.limit as number
        );
        break;
      case "gitea_create_repo":
        result = await giteaCreateRepo(
          args?.name as string,
          args?.description as string,
          args?.private as boolean
        );
        break;
      case "gitea_migrate_repo":
        result = await giteaMigrateRepo(
          args?.cloneUrl as string,
          args?.repoName as string,
          args?.authToken as string
        );
        break;

      // Drone
      case "drone_list_repos":
        result = await droneGetRepos();
        break;
      case "drone_get_builds":
        result = await droneGetBuilds(args?.owner as string, args?.repo as string);
        break;
      case "drone_get_build":
        result = await droneGetBuild(
          args?.owner as string,
          args?.repo as string,
          args?.build as number
        );
        break;
      case "drone_get_build_logs":
        result = await droneGetBuildLogs(
          args?.owner as string,
          args?.repo as string,
          args?.build as number,
          args?.stage as number,
          args?.step as number
        );
        break;
      case "drone_trigger_build":
        result = await droneTriggerBuild(
          args?.owner as string,
          args?.repo as string,
          args?.branch as string
        );
        break;

      // Registry
      case "registry_list_images":
        result = await registryGetCatalog();
        break;
      case "registry_get_tags":
        result = await registryGetTags(args?.image as string);
        break;

      // Combined security scan
      case "security_scan_all":
        result = await securityScanAll(
          args?.path as string,
          args?.sonarProjectKey as string,
          args?.dtrackProjectUuid as string
        );
        break;

      default:
        throw new Error(`Unknown tool: ${name}`);
    }

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
