import Anthropic from "@anthropic-ai/sdk";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

// =============================================================================
// Input Validation & Sanitization
// =============================================================================
const ALLOWED_SEVERITY_LEVELS = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

function validateSeverity(severity: string): string {
  const levels = severity.split(",").map((s) => s.trim().toUpperCase());
  const validLevels = levels.filter((l) => ALLOWED_SEVERITY_LEVELS.includes(l));
  if (validLevels.length === 0) {
    return "HIGH,CRITICAL"; // Default safe value
  }
  return validLevels.join(",");
}

function sanitizePath(path: string): string {
  // Remove any shell metacharacters that could be used for injection
  // Allow only alphanumeric, forward slash, backslash, dot, hyphen, underscore, colon (for Windows drives), and space
  const sanitized = path.replace(/[^a-zA-Z0-9\/\\.:\-_ ]/g, "");

  // Prevent path traversal attempts
  const normalized = sanitized.replace(/\.\.\//g, "").replace(/\.\.\\/g, "");

  return normalized;
}

function sanitizeImageName(image: string): string {
  // Docker image names: alphanumeric, forward slash, colon, dot, hyphen, underscore
  // Pattern: [registry/]name[:tag]
  const sanitized = image.replace(/[^a-zA-Z0-9\/:.@\-_]/g, "");
  return sanitized;
}

// =============================================================================
// Configuration
// =============================================================================
export const config = {
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
// Helper Functions
// =============================================================================
async function fetchJson(url: string, options: RequestInit = {}): Promise<any> {
  const response = await fetch(url, {
    ...options,
    signal: AbortSignal.timeout(30000),
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
          description:
            "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)",
        },
        severity: {
          type: "string",
          description: "Severity levels to report (default: HIGH,CRITICAL)",
        },
      },
      required: ["image"],
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
    description:
      "Get code issues (bugs, vulnerabilities, code smells) for a SonarQube project",
    input_schema: {
      type: "object" as const,
      properties: {
        projectKey: {
          type: "string",
          description: "The SonarQube project key",
        },
        types: {
          type: "string",
          description:
            "Issue types to filter: VULNERABILITY, BUG, CODE_SMELL (comma-separated)",
        },
      },
      required: ["projectKey"],
    },
  },
  {
    name: "sonar_get_security_hotspots",
    description:
      "Get security hotspots (potential security issues requiring review) for a project",
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
    description:
      "List all projects in Dependency-Track with their vulnerability counts",
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
    description:
      "Get all components (dependencies) for a project with their details",
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
    description:
      "Migrate a repository from GitHub to Gitea (preserves issues, PRs, releases)",
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
// Tool Implementations
// =============================================================================
export async function executeTool(
  name: string,
  input: Record<string, unknown>
): Promise<string> {
  try {
    let result: any;

    switch (name) {
      // Trivy
      case "trivy_scan_path": {
        const path = sanitizePath(input.path as string);
        const severity = validateSeverity((input.severity as string) || "HIGH,CRITICAL");

        if (!path || path.length < 2) {
          throw new Error("Invalid path provided");
        }

        try {
          const { stdout } = await execAsync(
            `docker run --rm -v "${path}:/app" aquasec/trivy:latest fs --format json --severity ${severity} /app`,
            { maxBuffer: 10 * 1024 * 1024 }
          );
          result = JSON.parse(stdout);
        } catch (error: any) {
          if (error.stdout) {
            try {
              result = JSON.parse(error.stdout);
            } catch {
              result = { output: error.stdout, error: error.message };
            }
          } else {
            throw error;
          }
        }
        break;
      }

      case "trivy_scan_image": {
        const image = sanitizeImageName(input.image as string);
        const severity = validateSeverity((input.severity as string) || "HIGH,CRITICAL");

        if (!image || image.length < 2) {
          throw new Error("Invalid image name provided");
        }

        try {
          const { stdout } = await execAsync(
            `docker run --rm aquasec/trivy:latest image --format json --severity ${severity} ${image}`,
            { maxBuffer: 10 * 1024 * 1024 }
          );
          result = JSON.parse(stdout);
        } catch (error: any) {
          if (error.stdout) {
            try {
              result = JSON.parse(error.stdout);
            } catch {
              result = { output: error.stdout, error: error.message };
            }
          } else {
            throw error;
          }
        }
        break;
      }

      // SonarQube
      case "sonar_list_projects":
        result = await fetchJson(`${config.sonarqube.url}/api/projects/search`, {
          headers: {
            Authorization: basicAuth(
              config.sonarqube.user,
              config.sonarqube.password
            ),
          },
        });
        break;

      case "sonar_get_issues": {
        let url = `${config.sonarqube.url}/api/issues/search?componentKeys=${input.projectKey}&statuses=OPEN`;
        if (input.types) url += `&types=${input.types}`;
        result = await fetchJson(url, {
          headers: {
            Authorization: basicAuth(
              config.sonarqube.user,
              config.sonarqube.password
            ),
          },
        });
        break;
      }

      case "sonar_get_security_hotspots":
        result = await fetchJson(
          `${config.sonarqube.url}/api/hotspots/search?projectKey=${input.projectKey}`,
          {
            headers: {
              Authorization: basicAuth(
                config.sonarqube.user,
                config.sonarqube.password
              ),
            },
          }
        );
        break;

      case "sonar_get_metrics":
        result = await fetchJson(
          `${config.sonarqube.url}/api/measures/component?component=${input.projectKey}&metricKeys=bugs,vulnerabilities,security_hotspots,code_smells,coverage,duplicated_lines_density`,
          {
            headers: {
              Authorization: basicAuth(
                config.sonarqube.user,
                config.sonarqube.password
              ),
            },
          }
        );
        break;

      // Dependency-Track
      case "dtrack_list_projects":
        if (!config.dependencyTrack.apiKey) {
          throw new Error(
            "Dependency-Track API key not configured. Set DTRACK_API_KEY."
          );
        }
        result = await fetchJson(`${config.dependencyTrack.url}/api/v1/project`, {
          headers: { "X-Api-Key": config.dependencyTrack.apiKey },
        });
        break;

      case "dtrack_get_vulnerabilities":
        if (!config.dependencyTrack.apiKey) {
          throw new Error("Dependency-Track API key not configured.");
        }
        result = await fetchJson(
          `${config.dependencyTrack.url}/api/v1/vulnerability/project/${input.projectUuid}`,
          {
            headers: { "X-Api-Key": config.dependencyTrack.apiKey },
          }
        );
        break;

      case "dtrack_get_findings":
        if (!config.dependencyTrack.apiKey) {
          throw new Error("Dependency-Track API key not configured.");
        }
        result = await fetchJson(
          `${config.dependencyTrack.url}/api/v1/finding/project/${input.projectUuid}`,
          {
            headers: { "X-Api-Key": config.dependencyTrack.apiKey },
          }
        );
        break;

      case "dtrack_get_components":
        if (!config.dependencyTrack.apiKey) {
          throw new Error("Dependency-Track API key not configured.");
        }
        result = await fetchJson(
          `${config.dependencyTrack.url}/api/v1/component/project/${input.projectUuid}`,
          {
            headers: { "X-Api-Key": config.dependencyTrack.apiKey },
          }
        );
        break;

      // Gitea
      case "gitea_list_repos":
        result = await fetchJson(`${config.gitea.url}/api/v1/user/repos`, {
          headers: {
            Authorization: basicAuth(config.gitea.user, config.gitea.password),
          },
        });
        break;

      case "gitea_get_repo":
        result = await fetchJson(
          `${config.gitea.url}/api/v1/repos/${input.owner}/${input.repo}`,
          {
            headers: {
              Authorization: basicAuth(config.gitea.user, config.gitea.password),
            },
          }
        );
        break;

      case "gitea_get_branches":
        result = await fetchJson(
          `${config.gitea.url}/api/v1/repos/${input.owner}/${input.repo}/branches`,
          {
            headers: {
              Authorization: basicAuth(config.gitea.user, config.gitea.password),
            },
          }
        );
        break;

      case "gitea_get_commits": {
        const limit = (input.limit as number) || 10;
        result = await fetchJson(
          `${config.gitea.url}/api/v1/repos/${input.owner}/${input.repo}/commits?limit=${limit}`,
          {
            headers: {
              Authorization: basicAuth(config.gitea.user, config.gitea.password),
            },
          }
        );
        break;
      }

      case "gitea_create_repo":
        result = await fetchJson(`${config.gitea.url}/api/v1/user/repos`, {
          method: "POST",
          headers: {
            Authorization: basicAuth(config.gitea.user, config.gitea.password),
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            name: input.name,
            description: input.description || "",
            private: input.private || false,
            auto_init: true,
          }),
        });
        break;

      case "gitea_migrate_repo": {
        const body: any = {
          clone_addr: input.cloneUrl,
          repo_name: input.repoName,
          service: "github",
          mirror: false,
          private: false,
          issues: true,
          pull_requests: true,
          releases: true,
          milestones: true,
          labels: true,
        };
        if (input.authToken) body.auth_token = input.authToken;

        result = await fetchJson(`${config.gitea.url}/api/v1/repos/migrate`, {
          method: "POST",
          headers: {
            Authorization: basicAuth(config.gitea.user, config.gitea.password),
            "Content-Type": "application/json",
          },
          body: JSON.stringify(body),
        });
        break;
      }

      // Drone
      case "drone_list_repos": {
        const headers: any = {};
        if (config.drone.token) {
          headers.Authorization = `Bearer ${config.drone.token}`;
        }
        result = await fetchJson(`${config.drone.url}/api/user/repos`, {
          headers,
        });
        break;
      }

      case "drone_get_builds": {
        const headers: any = {};
        if (config.drone.token) {
          headers.Authorization = `Bearer ${config.drone.token}`;
        }
        result = await fetchJson(
          `${config.drone.url}/api/repos/${input.owner}/${input.repo}/builds`,
          { headers }
        );
        break;
      }

      case "drone_get_build": {
        const headers: any = {};
        if (config.drone.token) {
          headers.Authorization = `Bearer ${config.drone.token}`;
        }
        result = await fetchJson(
          `${config.drone.url}/api/repos/${input.owner}/${input.repo}/builds/${input.build}`,
          { headers }
        );
        break;
      }

      case "drone_get_build_logs": {
        const headers: any = {};
        if (config.drone.token) {
          headers.Authorization = `Bearer ${config.drone.token}`;
        }
        const stage = (input.stage as number) || 1;
        const step = (input.step as number) || 1;
        result = await fetchJson(
          `${config.drone.url}/api/repos/${input.owner}/${input.repo}/builds/${input.build}/logs/${stage}/${step}`,
          { headers }
        );
        break;
      }

      case "drone_trigger_build": {
        if (!config.drone.token) {
          throw new Error("Drone token required. Set DRONE_TOKEN.");
        }
        const branch = (input.branch as string) || "main";
        result = await fetchJson(
          `${config.drone.url}/api/repos/${input.owner}/${input.repo}/builds?branch=${branch}`,
          {
            method: "POST",
            headers: { Authorization: `Bearer ${config.drone.token}` },
          }
        );
        break;
      }

      // Registry
      case "registry_list_images":
        result = await fetchJson(`${config.registry.url}/v2/_catalog`);
        break;

      case "registry_get_tags":
        result = await fetchJson(
          `${config.registry.url}/v2/${input.image}/tags/list`
        );
        break;

      // Platform Status
      case "check_platform_status": {
        const status: any = {
          timestamp: new Date().toISOString(),
          services: {},
        };

        const checks = [
          { name: "gitea", url: `${config.gitea.url}/api/v1/version` },
          { name: "drone", url: `${config.drone.url}/healthz` },
          { name: "sonarqube", url: `${config.sonarqube.url}/api/system/health` },
          { name: "dependencyTrack", url: `${config.dependencyTrack.url}/api/version` },
          { name: "registry", url: `${config.registry.url}/v2/` },
        ];

        for (const check of checks) {
          try {
            const response = await fetch(check.url, {
              signal: AbortSignal.timeout(5000),
            });
            status.services[check.name] = {
              status: response.ok ? "healthy" : "degraded",
              statusCode: response.status,
            };
          } catch (e: any) {
            status.services[check.name] = {
              status: "unreachable",
              error: e.message,
            };
          }
        }
        result = status;
        break;
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return JSON.stringify(result, null, 2);
  } catch (error: any) {
    return JSON.stringify({ error: error.message }, null, 2);
  }
}
