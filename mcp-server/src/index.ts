#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { exec } from "node:child_process";
import { promisify } from "node:util";

const execAsync = promisify(exec);

// =============================================================================
// Configuration
// =============================================================================
const config = {
  gitea: {
    url: process.env.GITEA_URL || "http://localhost:3000",
    user: process.env.GITEA_USER || "localadmin",
    password: process.env.GITEA_PASSWORD || "admin123",
  },
  drone: {
    url: process.env.DRONE_URL || "http://localhost:8085",
    token: process.env.DRONE_TOKEN || "",
  },
  sonarqube: {
    url: process.env.SONARQUBE_URL || "http://localhost:9000",
    user: process.env.SONARQUBE_USER || "admin",
    password: process.env.SONARQUBE_PASSWORD || "admin",
  },
  dependencyTrack: {
    url: process.env.DTRACK_URL || "http://localhost:8081",
    apiKey: process.env.DTRACK_API_KEY || "",
  },
  trivy: {
    url: process.env.TRIVY_URL || "http://localhost:4954",
  },
  registry: {
    url: process.env.REGISTRY_URL || "http://localhost:5000",
  },
};

// =============================================================================
// Input Validation & Sanitization
// =============================================================================
const ALLOWED_SEVERITY_LEVELS = new Set(["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);

export function validateSeverity(severity: string): string {
  const levels = severity.split(",").map((s) => s.trim().toUpperCase());
  const validLevels = levels.filter((l) => ALLOWED_SEVERITY_LEVELS.has(l));
  if (validLevels.length === 0) {
    return "HIGH,CRITICAL"; // Default safe value
  }
  return validLevels.join(",");
}

export function sanitizePath(path: string): string {
  // Remove any shell metacharacters that could be used for injection
  // Allow only alphanumeric, forward slash, backslash, dot, hyphen, underscore, colon (for Windows drives), and space
  const sanitized = path.replaceAll(/[^a-zA-Z0-9/\\.:\-_ ]/g, "");

  // Prevent path traversal attempts
  const normalized = sanitized.replaceAll("../", "").replaceAll("..\\", "");

  return normalized;
}

export function sanitizeImageName(image: string): string {
  // Docker image names: alphanumeric, forward slash, colon, dot, hyphen, underscore
  // Pattern: [registry/]name[:tag]
  const sanitized = image.replaceAll(/[^a-zA-Z0-9/:.@\-_]/g, "");
  return sanitized;
}

// =============================================================================
// Helper Functions
// =============================================================================
async function fetchJson(url: string, options: RequestInit = {}): Promise<any> {
  const response = await fetch(url, {
    ...options,
    signal: AbortSignal.timeout(30000), // 30 second timeout
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  return response.json();
}

function basicAuth(user: string, pass: string): string {
  return "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");
}

// =============================================================================
// Trivy Functions
// =============================================================================
async function trivyScanPath(path: string, severity: string = "HIGH,CRITICAL"): Promise<any> {
  // Sanitize inputs to prevent command injection
  const safePath = sanitizePath(path);
  const safeSeverity = validateSeverity(severity);

  if (!safePath || safePath.length < 2) {
    throw new Error("Invalid path provided");
  }

  try {
    const { stdout } = await execAsync(
      `docker run --rm -v "${safePath}:/app" aquasec/trivy:latest fs --format json --severity ${safeSeverity} /app`,
      { maxBuffer: 10 * 1024 * 1024 }
    );
    return JSON.parse(stdout);
  } catch (error: any) {
    if (error.stdout) {
      try {
        return JSON.parse(error.stdout);
      } catch {
        return { error: error.message, output: error.stdout };
      }
    }
    throw error;
  }
}

async function trivyScanImage(image: string, severity: string = "HIGH,CRITICAL"): Promise<any> {
  // Sanitize inputs to prevent command injection
  const safeImage = sanitizeImageName(image);
  const safeSeverity = validateSeverity(severity);

  if (!safeImage || safeImage.length < 2) {
    throw new Error("Invalid image name provided");
  }

  try {
    const { stdout } = await execAsync(
      `docker run --rm aquasec/trivy:latest image --format json --severity ${safeSeverity} ${safeImage}`,
      { maxBuffer: 10 * 1024 * 1024 }
    );
    return JSON.parse(stdout);
  } catch (error: any) {
    if (error.stdout) {
      try {
        return JSON.parse(error.stdout);
      } catch {
        return { error: error.message, output: error.stdout };
      }
    }
    throw error;
  }
}

// =============================================================================
// SonarQube Functions
// =============================================================================
async function sonarGetProjects(): Promise<any> {
  return fetchJson(`${config.sonarqube.url}/api/projects/search`, {
    headers: {
      Authorization: basicAuth(config.sonarqube.user, config.sonarqube.password),
    },
  });
}

async function sonarGetIssues(projectKey: string, types?: string): Promise<any> {
  let url = `${config.sonarqube.url}/api/issues/search?componentKeys=${projectKey}&statuses=OPEN`;
  if (types) url += `&types=${types}`;

  return fetchJson(url, {
    headers: {
      Authorization: basicAuth(config.sonarqube.user, config.sonarqube.password),
    },
  });
}

async function sonarGetSecurityHotspots(projectKey: string): Promise<any> {
  return fetchJson(
    `${config.sonarqube.url}/api/hotspots/search?projectKey=${projectKey}`,
    {
      headers: {
        Authorization: basicAuth(config.sonarqube.user, config.sonarqube.password),
      },
    }
  );
}

async function sonarGetMetrics(projectKey: string): Promise<any> {
  return fetchJson(
    `${config.sonarqube.url}/api/measures/component?component=${projectKey}&metricKeys=bugs,vulnerabilities,security_hotspots,code_smells,coverage,duplicated_lines_density`,
    {
      headers: {
        Authorization: basicAuth(config.sonarqube.user, config.sonarqube.password),
      },
    }
  );
}

// =============================================================================
// Dependency-Track Functions
// =============================================================================
async function dtrackGetProjects(): Promise<any> {
  if (!config.dependencyTrack.apiKey) {
    throw new Error("Dependency-Track API key not configured. Set DTRACK_API_KEY environment variable.");
  }
  return fetchJson(`${config.dependencyTrack.url}/api/v1/project`, {
    headers: { "X-Api-Key": config.dependencyTrack.apiKey },
  });
}

async function dtrackGetVulnerabilities(projectUuid: string): Promise<any> {
  if (!config.dependencyTrack.apiKey) {
    throw new Error("Dependency-Track API key not configured. Set DTRACK_API_KEY environment variable.");
  }
  return fetchJson(
    `${config.dependencyTrack.url}/api/v1/vulnerability/project/${projectUuid}`,
    {
      headers: { "X-Api-Key": config.dependencyTrack.apiKey },
    }
  );
}

async function dtrackGetFindings(projectUuid: string): Promise<any> {
  if (!config.dependencyTrack.apiKey) {
    throw new Error("Dependency-Track API key not configured. Set DTRACK_API_KEY environment variable.");
  }
  return fetchJson(
    `${config.dependencyTrack.url}/api/v1/finding/project/${projectUuid}`,
    {
      headers: { "X-Api-Key": config.dependencyTrack.apiKey },
    }
  );
}

async function dtrackGetComponents(projectUuid: string): Promise<any> {
  if (!config.dependencyTrack.apiKey) {
    throw new Error("Dependency-Track API key not configured. Set DTRACK_API_KEY environment variable.");
  }
  return fetchJson(
    `${config.dependencyTrack.url}/api/v1/component/project/${projectUuid}`,
    {
      headers: { "X-Api-Key": config.dependencyTrack.apiKey },
    }
  );
}

// =============================================================================
// Gitea Functions
// =============================================================================
async function giteaGetRepos(): Promise<any> {
  return fetchJson(`${config.gitea.url}/api/v1/user/repos`, {
    headers: {
      Authorization: basicAuth(config.gitea.user, config.gitea.password),
    },
  });
}

async function giteaGetRepo(owner: string, repo: string): Promise<any> {
  return fetchJson(`${config.gitea.url}/api/v1/repos/${owner}/${repo}`, {
    headers: {
      Authorization: basicAuth(config.gitea.user, config.gitea.password),
    },
  });
}

async function giteaGetBranches(owner: string, repo: string): Promise<any> {
  return fetchJson(`${config.gitea.url}/api/v1/repos/${owner}/${repo}/branches`, {
    headers: {
      Authorization: basicAuth(config.gitea.user, config.gitea.password),
    },
  });
}

async function giteaGetCommits(owner: string, repo: string, limit: number = 10): Promise<any> {
  return fetchJson(
    `${config.gitea.url}/api/v1/repos/${owner}/${repo}/commits?limit=${limit}`,
    {
      headers: {
        Authorization: basicAuth(config.gitea.user, config.gitea.password),
      },
    }
  );
}

async function giteaCreateRepo(name: string, description: string = "", isPrivate: boolean = false): Promise<any> {
  return fetchJson(`${config.gitea.url}/api/v1/user/repos`, {
    method: "POST",
    headers: {
      Authorization: basicAuth(config.gitea.user, config.gitea.password),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      name,
      description,
      private: isPrivate,
      auto_init: true,
    }),
  });
}

async function giteaMigrateRepo(
  cloneUrl: string,
  repoName: string,
  authToken?: string
): Promise<any> {
  const body: any = {
    clone_addr: cloneUrl,
    repo_name: repoName,
    service: "github",
    mirror: false,
    private: false,
    issues: true,
    pull_requests: true,
    releases: true,
    milestones: true,
    labels: true,
  };

  if (authToken) {
    body.auth_token = authToken;
  }

  return fetchJson(`${config.gitea.url}/api/v1/repos/migrate`, {
    method: "POST",
    headers: {
      Authorization: basicAuth(config.gitea.user, config.gitea.password),
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

// =============================================================================
// Drone CI Functions
// =============================================================================
async function droneGetRepos(): Promise<any> {
  if (!config.drone.token) {
    // Try to get repos without token (may work for public)
    return fetchJson(`${config.drone.url}/api/user/repos`);
  }
  return fetchJson(`${config.drone.url}/api/user/repos`, {
    headers: { Authorization: `Bearer ${config.drone.token}` },
  });
}

async function droneGetBuilds(owner: string, repo: string): Promise<any> {
  const headers: any = {};
  if (config.drone.token) {
    headers.Authorization = `Bearer ${config.drone.token}`;
  }
  return fetchJson(`${config.drone.url}/api/repos/${owner}/${repo}/builds`, {
    headers,
  });
}

async function droneGetBuild(owner: string, repo: string, build: number): Promise<any> {
  const headers: any = {};
  if (config.drone.token) {
    headers.Authorization = `Bearer ${config.drone.token}`;
  }
  return fetchJson(
    `${config.drone.url}/api/repos/${owner}/${repo}/builds/${build}`,
    { headers }
  );
}

async function droneGetBuildLogs(
  owner: string,
  repo: string,
  build: number,
  stage: number = 1,
  step: number = 1
): Promise<any> {
  const headers: any = {};
  if (config.drone.token) {
    headers.Authorization = `Bearer ${config.drone.token}`;
  }
  return fetchJson(
    `${config.drone.url}/api/repos/${owner}/${repo}/builds/${build}/logs/${stage}/${step}`,
    { headers }
  );
}

async function droneTriggerBuild(owner: string, repo: string, branch: string = "main"): Promise<any> {
  if (!config.drone.token) {
    throw new Error("Drone token required to trigger builds. Set DRONE_TOKEN environment variable.");
  }
  return fetchJson(
    `${config.drone.url}/api/repos/${owner}/${repo}/builds?branch=${branch}`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${config.drone.token}` },
    }
  );
}

// =============================================================================
// Registry Functions
// =============================================================================
async function registryGetCatalog(): Promise<any> {
  return fetchJson(`${config.registry.url}/v2/_catalog`);
}

async function registryGetTags(image: string): Promise<any> {
  return fetchJson(`${config.registry.url}/v2/${image}/tags/list`);
}

// =============================================================================
// Combined Security Scan
// =============================================================================
async function securityScanAll(
  path?: string,
  sonarProjectKey?: string,
  dtrackProjectUuid?: string
): Promise<any> {
  const scanResults: any = {
    timestamp: new Date().toISOString(),
    trivy: null,
    sonarqube: null,
    dependencyTrack: null,
  };

  if (path) {
    try {
      scanResults.trivy = await trivyScanPath(path);
    } catch (e: any) {
      scanResults.trivy = { error: e.message };
    }
  }

  if (sonarProjectKey) {
    try {
      scanResults.sonarqube = await sonarGetIssues(sonarProjectKey);
    } catch (e: any) {
      scanResults.sonarqube = { error: e.message };
    }
  }

  if (dtrackProjectUuid) {
    try {
      scanResults.dependencyTrack = await dtrackGetFindings(dtrackProjectUuid);
    } catch (e: any) {
      scanResults.dependencyTrack = { error: e.message };
    }
  }

  return scanResults;
}

// =============================================================================
// MCP Server Setup
// =============================================================================
const server = new Server(
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

// =============================================================================
// Tool Definitions
// =============================================================================
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      // Trivy Tools
      {
        name: "trivy_scan_path",
        description: "Scan a local file path for vulnerabilities using Trivy. Detects vulnerabilities in dependencies (npm, pip, go, etc.) and secrets.",
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
        description: "Get quality metrics (bugs, vulnerabilities, coverage, etc.) for a SonarQube project",
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
        description: "Run a comprehensive security scan using all available tools (Trivy, SonarQube findings, Dependency-Track)",
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
    ],
  };
});

// =============================================================================
// Tool Handlers
// =============================================================================
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    let result: any;

    switch (name) {
      // Trivy
      case "trivy_scan_path":
        result = await trivyScanPath(args?.path as string, args?.severity as string);
        break;
      case "trivy_scan_image":
        result = await trivyScanImage(args?.image as string, args?.severity as string);
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
  } catch (error: any) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ error: error.message }, null, 2),
        },
      ],
      isError: true,
    };
  }
});

// =============================================================================
// Resource Definitions
// =============================================================================
server.setRequestHandler(ListResourcesRequestSchema, async () => {
  return {
    resources: [
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
    ],
  };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;

  if (uri === "cicd://status") {
    const status: any = {
      timestamp: new Date().toISOString(),
      services: {},
    };

    // Check each service
    const checks = [
      { name: "gitea", url: `${config.gitea.url}/api/v1/version` },
      { name: "drone", url: `${config.drone.url}/api/user` },
      { name: "sonarqube", url: `${config.sonarqube.url}/api/system/health` },
      { name: "dependencyTrack", url: `${config.dependencyTrack.url}/api/version` },
      { name: "trivy", url: `${config.trivy.url}/healthz` },
      { name: "registry", url: `${config.registry.url}/v2/` },
    ];

    for (const check of checks) {
      try {
        const response = await fetch(check.url, {
          method: "GET",
          signal: AbortSignal.timeout(5000),
        });
        status.services[check.name] = {
          status: response.ok ? "healthy" : "unhealthy",
          statusCode: response.status,
        };
      } catch (e: any) {
        status.services[check.name] = {
          status: "unreachable",
          error: e.message,
        };
      }
    }

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
});

// =============================================================================
// Start Server
// =============================================================================
const transport = new StdioServerTransport();
try {
  await server.connect(transport);
  console.error("CI/CD Security MCP Server running on stdio");
} catch (error) {
  console.error(error);
  process.exit(1);
}
