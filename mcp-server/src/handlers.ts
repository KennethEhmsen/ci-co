import { exec } from "node:child_process";
import { promisify } from "node:util";

const execAsync = promisify(exec);

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
// Input Validation & Sanitization
// =============================================================================
const ALLOWED_SEVERITY_LEVELS = new Set(["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);

export function validateSeverity(severity: string): string {
  const levels = severity.split(",").map((s) => s.trim().toUpperCase());
  const validLevels = levels.filter((l) => ALLOWED_SEVERITY_LEVELS.has(l));
  if (validLevels.length === 0) {
    return "HIGH,CRITICAL";
  }
  return validLevels.join(",");
}

export function sanitizePath(path: string): string {
  const sanitized = path.replaceAll(/[^a-zA-Z0-9/\\.:\-_ ]/g, "");
  const normalized = sanitized.replaceAll("../", "").replaceAll("..\\", "");
  return normalized;
}

export function sanitizeImageName(image: string): string {
  const sanitized = image.replaceAll(/[^a-zA-Z0-9/:.@\-_]/g, "");
  return sanitized;
}

// =============================================================================
// Helper Functions
// =============================================================================
export async function fetchJson(url: string, options: RequestInit = {}): Promise<any> {
  const response = await fetch(url, {
    ...options,
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  return response.json();
}

export function basicAuth(user: string, pass: string): string {
  return "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");
}

// =============================================================================
// Trivy Functions
// =============================================================================
export async function trivyScanPath(path: string, severity: string = "HIGH,CRITICAL"): Promise<any> {
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

export async function trivyScanImage(image: string, severity: string = "HIGH,CRITICAL"): Promise<any> {
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
export async function sonarGetProjects(): Promise<any> {
  return fetchJson(`${config.sonarqube.url}/api/projects/search`, {
    headers: {
      Authorization: basicAuth(config.sonarqube.user, config.sonarqube.password),
    },
  });
}

export async function sonarGetIssues(projectKey: string, types?: string): Promise<any> {
  let url = `${config.sonarqube.url}/api/issues/search?componentKeys=${projectKey}&statuses=OPEN`;
  if (types) url += `&types=${types}`;

  return fetchJson(url, {
    headers: {
      Authorization: basicAuth(config.sonarqube.user, config.sonarqube.password),
    },
  });
}

export async function sonarGetSecurityHotspots(projectKey: string): Promise<any> {
  return fetchJson(
    `${config.sonarqube.url}/api/hotspots/search?projectKey=${projectKey}`,
    {
      headers: {
        Authorization: basicAuth(config.sonarqube.user, config.sonarqube.password),
      },
    }
  );
}

export async function sonarGetMetrics(projectKey: string): Promise<any> {
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
export async function dtrackGetProjects(): Promise<any> {
  if (!config.dependencyTrack.apiKey) {
    throw new Error("Dependency-Track API key not configured. Set DTRACK_API_KEY environment variable.");
  }
  return fetchJson(`${config.dependencyTrack.url}/api/v1/project`, {
    headers: { "X-Api-Key": config.dependencyTrack.apiKey },
  });
}

export async function dtrackGetVulnerabilities(projectUuid: string): Promise<any> {
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

export async function dtrackGetFindings(projectUuid: string): Promise<any> {
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

export async function dtrackGetComponents(projectUuid: string): Promise<any> {
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
export async function giteaGetRepos(): Promise<any> {
  return fetchJson(`${config.gitea.url}/api/v1/user/repos`, {
    headers: {
      Authorization: basicAuth(config.gitea.user, config.gitea.password),
    },
  });
}

export async function giteaGetRepo(owner: string, repo: string): Promise<any> {
  return fetchJson(`${config.gitea.url}/api/v1/repos/${owner}/${repo}`, {
    headers: {
      Authorization: basicAuth(config.gitea.user, config.gitea.password),
    },
  });
}

export async function giteaGetBranches(owner: string, repo: string): Promise<any> {
  return fetchJson(`${config.gitea.url}/api/v1/repos/${owner}/${repo}/branches`, {
    headers: {
      Authorization: basicAuth(config.gitea.user, config.gitea.password),
    },
  });
}

export async function giteaGetCommits(owner: string, repo: string, limit: number = 10): Promise<any> {
  return fetchJson(
    `${config.gitea.url}/api/v1/repos/${owner}/${repo}/commits?limit=${limit}`,
    {
      headers: {
        Authorization: basicAuth(config.gitea.user, config.gitea.password),
      },
    }
  );
}

export async function giteaCreateRepo(name: string, description: string = "", isPrivate: boolean = false): Promise<any> {
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

export async function giteaMigrateRepo(
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
export async function droneGetRepos(): Promise<any> {
  if (!config.drone.token) {
    return fetchJson(`${config.drone.url}/api/user/repos`);
  }
  return fetchJson(`${config.drone.url}/api/user/repos`, {
    headers: { Authorization: `Bearer ${config.drone.token}` },
  });
}

export async function droneGetBuilds(owner: string, repo: string): Promise<any> {
  const headers: any = {};
  if (config.drone.token) {
    headers.Authorization = `Bearer ${config.drone.token}`;
  }
  return fetchJson(`${config.drone.url}/api/repos/${owner}/${repo}/builds`, {
    headers,
  });
}

export async function droneGetBuild(owner: string, repo: string, build: number): Promise<any> {
  const headers: any = {};
  if (config.drone.token) {
    headers.Authorization = `Bearer ${config.drone.token}`;
  }
  return fetchJson(
    `${config.drone.url}/api/repos/${owner}/${repo}/builds/${build}`,
    { headers }
  );
}

export async function droneGetBuildLogs(
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

export async function droneTriggerBuild(owner: string, repo: string, branch: string = "main"): Promise<any> {
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
export async function registryGetCatalog(): Promise<any> {
  return fetchJson(`${config.registry.url}/v2/_catalog`);
}

export async function registryGetTags(image: string): Promise<any> {
  return fetchJson(`${config.registry.url}/v2/${image}/tags/list`);
}

// =============================================================================
// Combined Security Scan
// =============================================================================
export async function securityScanAll(
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
// Platform Status
// =============================================================================
export async function checkPlatformStatus(): Promise<any> {
  const status: any = {
    timestamp: new Date().toISOString(),
    services: {},
  };

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

  return status;
}
