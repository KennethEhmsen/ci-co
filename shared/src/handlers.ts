import { exec } from "node:child_process";
import { promisify } from "node:util";
import { config } from "./config.js";
import { validateSeverity, sanitizePath, sanitizeImageName } from "./validation.js";
import { fetchJson, basicAuth } from "./http.js";
import type {
  TrivyScanResult,
  TrivySbomResult,
  SonarProjectsResponse,
  SonarIssuesResponse,
  SonarHotspotsResponse,
  SonarMetricsResponse,
  DTrackProject,
  DTrackVulnerability,
  DTrackFinding,
  DTrackComponent,
  GiteaRepository,
  GiteaBranch,
  GiteaCommit,
  DroneRepository,
  DroneBuild,
  DroneLogLine,
  RegistryCatalog,
  RegistryTags,
  CombinedScanResponse,
  PlatformHealthResponse,
} from "./types.js";

const execAsync = promisify(exec);

/** Error response for failed operations */
interface ErrorResponse {
  error: string;
  output?: string;
}

/** Exec error with stdout */
interface ExecError extends Error {
  stdout?: string;
}

/** Migration request body */
interface MigrateRepoBody {
  clone_addr: string;
  repo_name: string;
  service: string;
  mirror: boolean;
  private: boolean;
  issues: boolean;
  pull_requests: boolean;
  releases: boolean;
  milestones: boolean;
  labels: boolean;
  auth_token?: string;
}

// =============================================================================
// Trivy Functions
// =============================================================================

/**
 * Scan a local filesystem path for vulnerabilities using Trivy.
 * Detects vulnerabilities in dependencies (npm, pip, go, maven, etc.) and secrets in code.
 *
 * @param path - Absolute path to the directory to scan
 * @param severity - Severity levels to report: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL (default: HIGH,CRITICAL)
 * @returns Promise resolving to Trivy scan results in JSON format
 * @throws Error if path is invalid or Trivy command fails
 *
 * @example
 * ```typescript
 * const results = await trivyScanPath('/home/user/myproject', 'MEDIUM,HIGH,CRITICAL');
 * console.log(results.Results); // Array of vulnerability findings
 * ```
 */
export async function trivyScanPath(
  path: string,
  severity: string = "HIGH,CRITICAL"
): Promise<TrivyScanResult | ErrorResponse> {
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
    return JSON.parse(stdout) as TrivyScanResult;
  } catch (error: unknown) {
    const execError = error as ExecError;
    if (execError.stdout) {
      try {
        return JSON.parse(execError.stdout) as TrivyScanResult;
      } catch {
        return { error: execError.message, output: execError.stdout };
      }
    }
    throw error;
  }
}

/**
 * Scan a Docker image for vulnerabilities using Trivy.
 * Works with local images and registry images.
 *
 * @param image - Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)
 * @param severity - Severity levels to report (default: HIGH,CRITICAL)
 * @returns Promise resolving to Trivy scan results in JSON format
 * @throws Error if image name is invalid or Trivy command fails
 *
 * @example
 * ```typescript
 * const results = await trivyScanImage('nginx:1.25', 'HIGH,CRITICAL');
 * console.log(results.Results); // Array of vulnerability findings
 * ```
 */
export async function trivyScanImage(
  image: string,
  severity: string = "HIGH,CRITICAL"
): Promise<TrivyScanResult | ErrorResponse> {
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
    return JSON.parse(stdout) as TrivyScanResult;
  } catch (error: unknown) {
    const execError = error as ExecError;
    if (execError.stdout) {
      try {
        return JSON.parse(execError.stdout) as TrivyScanResult;
      } catch {
        return { error: execError.message, output: execError.stdout };
      }
    }
    throw error;
  }
}

/**
 * Generate a Software Bill of Materials (SBOM) for a local path using Trivy.
 * Creates a CycloneDX format SBOM listing all components and dependencies.
 *
 * @param path - Absolute path to the directory to scan
 * @param format - SBOM format: cyclonedx (default) or spdx-json
 * @returns Promise resolving to SBOM in CycloneDX JSON format
 * @throws Error if path is invalid or Trivy command fails
 *
 * @example
 * ```typescript
 * const sbom = await trivyGenerateSbom('/home/user/myproject');
 * console.log(sbom.components); // Array of software components
 * ```
 */
export async function trivyGenerateSbom(
  path: string,
  format: "cyclonedx" | "spdx-json" = "cyclonedx"
): Promise<TrivySbomResult | ErrorResponse> {
  const safePath = sanitizePath(path);

  if (!safePath || safePath.length < 2) {
    throw new Error("Invalid path provided");
  }

  try {
    const { stdout } = await execAsync(
      `docker run --rm -v "${safePath}:/app" aquasec/trivy:latest fs --format ${format} /app`,
      { maxBuffer: 10 * 1024 * 1024 }
    );
    return JSON.parse(stdout) as TrivySbomResult;
  } catch (error: unknown) {
    const execError = error as ExecError;
    if (execError.stdout) {
      try {
        return JSON.parse(execError.stdout) as TrivySbomResult;
      } catch {
        return { error: execError.message, output: execError.stdout };
      }
    }
    throw error;
  }
}

/**
 * Generate a Software Bill of Materials (SBOM) for a Docker image using Trivy.
 * Creates a CycloneDX format SBOM listing all components in the container image.
 *
 * @param image - Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)
 * @param format - SBOM format: cyclonedx (default) or spdx-json
 * @returns Promise resolving to SBOM in CycloneDX JSON format
 * @throws Error if image name is invalid or Trivy command fails
 *
 * @example
 * ```typescript
 * const sbom = await trivyGenerateSbomImage('nginx:1.25');
 * console.log(sbom.components); // Array of software components
 * ```
 */
export async function trivyGenerateSbomImage(
  image: string,
  format: "cyclonedx" | "spdx-json" = "cyclonedx"
): Promise<TrivySbomResult | ErrorResponse> {
  const safeImage = sanitizeImageName(image);

  if (!safeImage || safeImage.length < 2) {
    throw new Error("Invalid image name provided");
  }

  try {
    const { stdout } = await execAsync(
      `docker run --rm aquasec/trivy:latest image --format ${format} ${safeImage}`,
      { maxBuffer: 10 * 1024 * 1024 }
    );
    return JSON.parse(stdout) as TrivySbomResult;
  } catch (error: unknown) {
    const execError = error as ExecError;
    if (execError.stdout) {
      try {
        return JSON.parse(execError.stdout) as TrivySbomResult;
      } catch {
        return { error: execError.message, output: execError.stdout };
      }
    }
    throw error;
  }
}

// =============================================================================
// SonarQube Functions
// =============================================================================

/**
 * List all projects analyzed in SonarQube.
 *
 * @returns Promise resolving to list of SonarQube projects
 *
 * @example
 * ```typescript
 * const response = await sonarGetProjects();
 * console.log(response.components); // Array of projects
 * ```
 */
export async function sonarGetProjects(): Promise<SonarProjectsResponse> {
  return fetchJson<SonarProjectsResponse>(`${config.sonarqube.url}/api/projects/search`, {
    headers: {
      Authorization: basicAuth(config.sonarqube.user, config.sonarqube.password),
    },
  });
}

/**
 * Get code issues (bugs, vulnerabilities, code smells) for a SonarQube project.
 *
 * @param projectKey - The SonarQube project key
 * @param types - Issue types to filter: VULNERABILITY, BUG, CODE_SMELL (comma-separated)
 * @returns Promise resolving to list of issues
 *
 * @example
 * ```typescript
 * const response = await sonarGetIssues('my-project', 'VULNERABILITY,BUG');
 * console.log(response.issues); // Array of issues
 * ```
 */
export async function sonarGetIssues(
  projectKey: string,
  types?: string
): Promise<SonarIssuesResponse> {
  let url = `${config.sonarqube.url}/api/issues/search?componentKeys=${projectKey}&statuses=OPEN`;
  if (types) url += `&types=${types}`;

  return fetchJson<SonarIssuesResponse>(url, {
    headers: {
      Authorization: basicAuth(config.sonarqube.user, config.sonarqube.password),
    },
  });
}

export async function sonarGetSecurityHotspots(projectKey: string): Promise<SonarHotspotsResponse> {
  return fetchJson<SonarHotspotsResponse>(
    `${config.sonarqube.url}/api/hotspots/search?projectKey=${projectKey}`,
    {
      headers: {
        Authorization: basicAuth(config.sonarqube.user, config.sonarqube.password),
      },
    }
  );
}

export async function sonarGetMetrics(projectKey: string): Promise<SonarMetricsResponse> {
  return fetchJson<SonarMetricsResponse>(
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

/**
 * List all projects in Dependency-Track with their vulnerability counts.
 *
 * @returns Promise resolving to array of Dependency-Track projects
 * @throws Error if Dependency-Track API key is not configured
 *
 * @example
 * ```typescript
 * const projects = await dtrackGetProjects();
 * projects.forEach(p => console.log(p.name, p.metrics?.vulnerabilities));
 * ```
 */
export async function dtrackGetProjects(): Promise<DTrackProject[]> {
  if (!config.dependencyTrack.apiKey) {
    throw new Error(
      "Dependency-Track API key not configured. Set DTRACK_API_KEY environment variable."
    );
  }
  return fetchJson<DTrackProject[]>(`${config.dependencyTrack.url}/api/v1/project`, {
    headers: { "X-Api-Key": config.dependencyTrack.apiKey },
  });
}

export async function dtrackGetVulnerabilities(
  projectUuid: string
): Promise<DTrackVulnerability[]> {
  if (!config.dependencyTrack.apiKey) {
    throw new Error(
      "Dependency-Track API key not configured. Set DTRACK_API_KEY environment variable."
    );
  }
  return fetchJson<DTrackVulnerability[]>(
    `${config.dependencyTrack.url}/api/v1/vulnerability/project/${projectUuid}`,
    {
      headers: { "X-Api-Key": config.dependencyTrack.apiKey },
    }
  );
}

export async function dtrackGetFindings(projectUuid: string): Promise<DTrackFinding[]> {
  if (!config.dependencyTrack.apiKey) {
    throw new Error(
      "Dependency-Track API key not configured. Set DTRACK_API_KEY environment variable."
    );
  }
  return fetchJson<DTrackFinding[]>(
    `${config.dependencyTrack.url}/api/v1/finding/project/${projectUuid}`,
    {
      headers: { "X-Api-Key": config.dependencyTrack.apiKey },
    }
  );
}

export async function dtrackGetComponents(projectUuid: string): Promise<DTrackComponent[]> {
  if (!config.dependencyTrack.apiKey) {
    throw new Error(
      "Dependency-Track API key not configured. Set DTRACK_API_KEY environment variable."
    );
  }
  return fetchJson<DTrackComponent[]>(
    `${config.dependencyTrack.url}/api/v1/component/project/${projectUuid}`,
    {
      headers: { "X-Api-Key": config.dependencyTrack.apiKey },
    }
  );
}

// =============================================================================
// Gitea Functions
// =============================================================================

/**
 * List all Git repositories in Gitea for the current user.
 *
 * @returns Promise resolving to array of Gitea repositories
 *
 * @example
 * ```typescript
 * const repos = await giteaGetRepos();
 * repos.forEach(r => console.log(r.full_name, r.html_url));
 * ```
 */
export async function giteaGetRepos(): Promise<GiteaRepository[]> {
  return fetchJson<GiteaRepository[]>(`${config.gitea.url}/api/v1/user/repos`, {
    headers: {
      Authorization: basicAuth(config.gitea.user, config.gitea.password),
    },
  });
}

export async function giteaGetRepo(owner: string, repo: string): Promise<GiteaRepository> {
  return fetchJson<GiteaRepository>(`${config.gitea.url}/api/v1/repos/${owner}/${repo}`, {
    headers: {
      Authorization: basicAuth(config.gitea.user, config.gitea.password),
    },
  });
}

export async function giteaGetBranches(owner: string, repo: string): Promise<GiteaBranch[]> {
  return fetchJson<GiteaBranch[]>(`${config.gitea.url}/api/v1/repos/${owner}/${repo}/branches`, {
    headers: {
      Authorization: basicAuth(config.gitea.user, config.gitea.password),
    },
  });
}

export async function giteaGetCommits(
  owner: string,
  repo: string,
  limit: number = 10
): Promise<GiteaCommit[]> {
  return fetchJson<GiteaCommit[]>(
    `${config.gitea.url}/api/v1/repos/${owner}/${repo}/commits?limit=${limit}`,
    {
      headers: {
        Authorization: basicAuth(config.gitea.user, config.gitea.password),
      },
    }
  );
}

export async function giteaCreateRepo(
  name: string,
  description: string = "",
  isPrivate: boolean = false
): Promise<GiteaRepository> {
  return fetchJson<GiteaRepository>(`${config.gitea.url}/api/v1/user/repos`, {
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
): Promise<GiteaRepository> {
  const body: MigrateRepoBody = {
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

  return fetchJson<GiteaRepository>(`${config.gitea.url}/api/v1/repos/migrate`, {
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
export async function droneGetRepos(): Promise<DroneRepository[]> {
  if (!config.drone.token) {
    return fetchJson<DroneRepository[]>(`${config.drone.url}/api/user/repos`);
  }
  return fetchJson<DroneRepository[]>(`${config.drone.url}/api/user/repos`, {
    headers: { Authorization: `Bearer ${config.drone.token}` },
  });
}

export async function droneGetBuilds(owner: string, repo: string): Promise<DroneBuild[]> {
  const headers: Record<string, string> = {};
  if (config.drone.token) {
    headers.Authorization = `Bearer ${config.drone.token}`;
  }
  return fetchJson<DroneBuild[]>(`${config.drone.url}/api/repos/${owner}/${repo}/builds`, {
    headers,
  });
}

export async function droneGetBuild(
  owner: string,
  repo: string,
  build: number
): Promise<DroneBuild> {
  const headers: Record<string, string> = {};
  if (config.drone.token) {
    headers.Authorization = `Bearer ${config.drone.token}`;
  }
  return fetchJson<DroneBuild>(`${config.drone.url}/api/repos/${owner}/${repo}/builds/${build}`, {
    headers,
  });
}

export async function droneGetBuildLogs(
  owner: string,
  repo: string,
  build: number,
  stage: number = 1,
  step: number = 1
): Promise<DroneLogLine[]> {
  const headers: Record<string, string> = {};
  if (config.drone.token) {
    headers.Authorization = `Bearer ${config.drone.token}`;
  }
  return fetchJson<DroneLogLine[]>(
    `${config.drone.url}/api/repos/${owner}/${repo}/builds/${build}/logs/${stage}/${step}`,
    { headers }
  );
}

export async function droneTriggerBuild(
  owner: string,
  repo: string,
  branch: string = "main"
): Promise<DroneBuild> {
  if (!config.drone.token) {
    throw new Error(
      "Drone token required to trigger builds. Set DRONE_TOKEN environment variable."
    );
  }
  return fetchJson<DroneBuild>(
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
export async function registryGetCatalog(): Promise<RegistryCatalog> {
  return fetchJson<RegistryCatalog>(`${config.registry.url}/v2/_catalog`);
}

export async function registryGetTags(image: string): Promise<RegistryTags> {
  return fetchJson<RegistryTags>(`${config.registry.url}/v2/${image}/tags/list`);
}

// =============================================================================
// Combined Security Scan
// =============================================================================
export async function securityScanAll(
  path?: string,
  sonarProjectKey?: string,
  dtrackProjectUuid?: string
): Promise<CombinedScanResponse> {
  const scanResults: CombinedScanResponse = {
    timestamp: new Date().toISOString(),
    trivy: null,
    sonarqube: null,
    dependencyTrack: null,
  };

  if (path) {
    try {
      scanResults.trivy = await trivyScanPath(path);
    } catch (e: unknown) {
      const error = e as Error;
      scanResults.trivy = { error: error.message };
    }
  }

  if (sonarProjectKey) {
    try {
      scanResults.sonarqube = await sonarGetIssues(sonarProjectKey);
    } catch (e: unknown) {
      const error = e as Error;
      scanResults.sonarqube = { error: error.message };
    }
  }

  if (dtrackProjectUuid) {
    try {
      scanResults.dependencyTrack = await dtrackGetFindings(dtrackProjectUuid);
    } catch (e: unknown) {
      const error = e as Error;
      scanResults.dependencyTrack = { error: error.message };
    }
  }

  return scanResults;
}

// =============================================================================
// Platform Status
// =============================================================================

/**
 * Check the health status of all CI/CD platform services.
 * Tests connectivity to Gitea, Drone, SonarQube, Dependency-Track, Trivy, and Registry.
 *
 * @returns Promise resolving to platform health status with each service's status
 *
 * @example
 * ```typescript
 * const status = await checkPlatformStatus();
 * console.log(status.services.gitea.status); // 'healthy' | 'unhealthy' | 'unreachable'
 * ```
 */
export async function checkPlatformStatus(): Promise<PlatformHealthResponse> {
  const status: PlatformHealthResponse = {
    timestamp: new Date().toISOString(),
    services: {
      gitea: { status: "unreachable" },
      drone: { status: "unreachable" },
      sonarqube: { status: "unreachable" },
      dependencyTrack: { status: "unreachable" },
      trivy: { status: "unreachable" },
      registry: { status: "unreachable" },
    },
  };

  const checks: Array<{ name: keyof PlatformHealthResponse["services"]; url: string }> = [
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
    } catch (e: unknown) {
      const error = e as Error;
      status.services[check.name] = {
        status: "unreachable",
        error: error.message,
      };
    }
  }

  return status;
}
