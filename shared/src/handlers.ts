import { exec } from "node:child_process";
import { promisify } from "node:util";
import { config } from "./config.js";
import { validateSeverity, sanitizePath, sanitizeImageName } from "./validation.js";
import { fetchJson, basicAuth } from "./http.js";
import type {
  TrivyScanResult,
  TrivySbomResult,
  TrivyIacScanResult,
  TrivySecretScanResult,
  TrivyLicenseScanResult,
  TrivyCombinedImageScanResult,
  TrivyCombinedPathScanResult,
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
  SecurityDashboardResult,
  SecurityDashboardSummary,
  SecurityDashboardFinding,
  SonarDashboardMetrics,
  SecurityDashboardOptions,
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
 * Uses the Trivy server API for faster scanning (offloads vulnerability DB to server).
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

  // Use Trivy server for vulnerability database lookups (faster, no local DB sync needed)
  const serverFlag = config.trivy.url ? `--server ${config.trivy.url}` : "";

  try {
    const { stdout } = await execAsync(
      `docker run --rm --network host aquasec/trivy:latest image ${serverFlag} --format json --severity ${safeSeverity} ${safeImage}`,
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
 * Uses the Trivy server API for faster scanning.
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

  // Use Trivy server for vulnerability database lookups
  const serverFlag = config.trivy.url ? `--server ${config.trivy.url}` : "";

  try {
    const { stdout } = await execAsync(
      `docker run --rm --network host aquasec/trivy:latest image ${serverFlag} --format ${format} ${safeImage}`,
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
 * Scan a local filesystem path for Infrastructure as Code (IaC) misconfigurations using Trivy.
 * Detects security issues in Terraform, Kubernetes, Docker, CloudFormation, and other IaC files.
 *
 * @param path - Absolute path to the directory to scan
 * @param severity - Severity levels to report: LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM,HIGH,CRITICAL)
 * @returns Promise resolving to Trivy IaC scan results in JSON format
 * @throws Error if path is invalid or Trivy command fails
 *
 * @example
 * ```typescript
 * const results = await trivyScanIac('/home/user/terraform');
 * console.log(results.Results); // Array of misconfiguration findings
 * ```
 */
export async function trivyScanIac(
  path: string,
  severity: string = "MEDIUM,HIGH,CRITICAL"
): Promise<TrivyIacScanResult | ErrorResponse> {
  const safePath = sanitizePath(path);
  const safeSeverity = validateSeverity(severity);

  if (!safePath || safePath.length < 2) {
    throw new Error("Invalid path provided");
  }

  try {
    const { stdout } = await execAsync(
      `docker run --rm -v "${safePath}:/app" aquasec/trivy:latest config --format json --severity ${safeSeverity} /app`,
      { maxBuffer: 10 * 1024 * 1024 }
    );
    return JSON.parse(stdout) as TrivyIacScanResult;
  } catch (error: unknown) {
    const execError = error as ExecError;
    if (execError.stdout) {
      try {
        return JSON.parse(execError.stdout) as TrivyIacScanResult;
      } catch {
        return { error: execError.message, output: execError.stdout };
      }
    }
    throw error;
  }
}

/**
 * Scan a local filesystem path for secrets using Trivy.
 * Detects hardcoded secrets, API keys, passwords, tokens, and other sensitive data.
 *
 * @param path - Absolute path to the directory to scan
 * @param severity - Severity levels to report: LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM,HIGH,CRITICAL)
 * @returns Promise resolving to Trivy secret scan results in JSON format
 * @throws Error if path is invalid or Trivy command fails
 *
 * @example
 * ```typescript
 * const results = await trivyScanSecrets('/home/user/project');
 * console.log(results.Results); // Array of secret findings
 * ```
 */
export async function trivyScanSecrets(
  path: string,
  severity: string = "MEDIUM,HIGH,CRITICAL"
): Promise<TrivySecretScanResult | ErrorResponse> {
  const safePath = sanitizePath(path);
  const safeSeverity = validateSeverity(severity);

  if (!safePath || safePath.length < 2) {
    throw new Error("Invalid path provided");
  }

  try {
    const { stdout } = await execAsync(
      `docker run --rm -v "${safePath}:/app" aquasec/trivy:latest fs --scanners secret --format json --severity ${safeSeverity} /app`,
      { maxBuffer: 10 * 1024 * 1024 }
    );
    return JSON.parse(stdout) as TrivySecretScanResult;
  } catch (error: unknown) {
    const execError = error as ExecError;
    if (execError.stdout) {
      try {
        return JSON.parse(execError.stdout) as TrivySecretScanResult;
      } catch {
        return { error: execError.message, output: execError.stdout };
      }
    }
    throw error;
  }
}

/**
 * Scan a Docker image for secrets using Trivy.
 * Uses the Trivy server API for faster scanning.
 * Detects hardcoded secrets, API keys, passwords, tokens, and other sensitive data in container images.
 *
 * @param image - Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)
 * @param severity - Severity levels to report: LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM,HIGH,CRITICAL)
 * @returns Promise resolving to Trivy secret scan results in JSON format
 * @throws Error if image name is invalid or Trivy command fails
 *
 * @example
 * ```typescript
 * const results = await trivyScanSecretsImage('nginx:1.25');
 * console.log(results.Results); // Array of secret findings
 * ```
 */
export async function trivyScanSecretsImage(
  image: string,
  severity: string = "MEDIUM,HIGH,CRITICAL"
): Promise<TrivySecretScanResult | ErrorResponse> {
  const safeImage = sanitizeImageName(image);
  const safeSeverity = validateSeverity(severity);

  if (!safeImage || safeImage.length < 2) {
    throw new Error("Invalid image name provided");
  }

  // Use Trivy server for vulnerability database lookups
  const serverFlag = config.trivy.url ? `--server ${config.trivy.url}` : "";

  try {
    const { stdout } = await execAsync(
      `docker run --rm --network host aquasec/trivy:latest image ${serverFlag} --scanners secret --format json --severity ${safeSeverity} ${safeImage}`,
      { maxBuffer: 10 * 1024 * 1024 }
    );
    return JSON.parse(stdout) as TrivySecretScanResult;
  } catch (error: unknown) {
    const execError = error as ExecError;
    if (execError.stdout) {
      try {
        return JSON.parse(execError.stdout) as TrivySecretScanResult;
      } catch {
        return { error: execError.message, output: execError.stdout };
      }
    }
    throw error;
  }
}

/**
 * Scan a local filesystem path for license information using Trivy.
 * Detects licenses in dependencies and flags potentially problematic licenses.
 *
 * @param path - Absolute path to the directory to scan
 * @param severity - Severity levels to report: LOW, MEDIUM, HIGH, CRITICAL (default: LOW,MEDIUM,HIGH,CRITICAL)
 * @returns Promise resolving to Trivy license scan results in JSON format
 * @throws Error if path is invalid or Trivy command fails
 *
 * @example
 * ```typescript
 * const results = await trivyScanLicenses('/home/user/project');
 * console.log(results.Results); // Array of license findings
 * ```
 */
export async function trivyScanLicenses(
  path: string,
  severity: string = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
): Promise<TrivyLicenseScanResult | ErrorResponse> {
  const safePath = sanitizePath(path);
  const safeSeverity = validateSeverity(severity);

  if (!safePath || safePath.length < 2) {
    throw new Error("Invalid path provided");
  }

  try {
    const { stdout } = await execAsync(
      `docker run --rm -v "${safePath}:/app" aquasec/trivy:latest fs --scanners license --format json --severity ${safeSeverity} /app`,
      { maxBuffer: 10 * 1024 * 1024 }
    );
    return JSON.parse(stdout) as TrivyLicenseScanResult;
  } catch (error: unknown) {
    const execError = error as ExecError;
    if (execError.stdout) {
      try {
        return JSON.parse(execError.stdout) as TrivyLicenseScanResult;
      } catch {
        return { error: execError.message, output: execError.stdout };
      }
    }
    throw error;
  }
}

/**
 * Scan a Docker image for license information using Trivy.
 * Uses the Trivy server API for faster scanning.
 * Detects licenses in dependencies and flags potentially problematic licenses.
 *
 * @param image - Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)
 * @param severity - Severity levels to report: LOW, MEDIUM, HIGH, CRITICAL (default: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL)
 * @returns Promise resolving to Trivy license scan results in JSON format
 * @throws Error if image name is invalid or Trivy command fails
 *
 * @example
 * ```typescript
 * const results = await trivyScanLicensesImage('nginx:1.25');
 * console.log(results.Results); // Array of license findings
 * ```
 */
export async function trivyScanLicensesImage(
  image: string,
  severity: string = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
): Promise<TrivyLicenseScanResult | ErrorResponse> {
  const safeImage = sanitizeImageName(image);
  const safeSeverity = validateSeverity(severity);

  if (!safeImage || safeImage.length < 2) {
    throw new Error("Invalid image name provided");
  }

  // Use Trivy server for vulnerability database lookups
  const serverFlag = config.trivy.url ? `--server ${config.trivy.url}` : "";

  try {
    const { stdout } = await execAsync(
      `docker run --rm --network host aquasec/trivy:latest image ${serverFlag} --scanners license --format json --severity ${safeSeverity} ${safeImage}`,
      { maxBuffer: 10 * 1024 * 1024 }
    );
    return JSON.parse(stdout) as TrivyLicenseScanResult;
  } catch (error: unknown) {
    const execError = error as ExecError;
    if (execError.stdout) {
      try {
        return JSON.parse(execError.stdout) as TrivyLicenseScanResult;
      } catch {
        return { error: execError.message, output: execError.stdout };
      }
    }
    throw error;
  }
}

/**
 * Run a comprehensive scan on a Docker image using Trivy.
 * Combines vulnerability, secret, license scanning, and SBOM generation in one operation.
 *
 * @param image - Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)
 * @param severity - Severity levels to report (default: HIGH,CRITICAL)
 * @param sbomFormat - SBOM format: cyclonedx (default) or spdx-json
 * @returns Promise resolving to combined scan results from all scanners
 * @throws Error if image name is invalid
 *
 * @example
 * ```typescript
 * const results = await trivyScanImageFull('nginx:1.25');
 * console.log(results.vulnerabilities); // Vulnerability findings
 * console.log(results.secrets); // Secret findings
 * console.log(results.licenses); // License findings
 * console.log(results.sbom); // Software Bill of Materials
 * ```
 */
export async function trivyScanImageFull(
  image: string,
  severity: string = "HIGH,CRITICAL",
  sbomFormat: "cyclonedx" | "spdx-json" = "cyclonedx"
): Promise<TrivyCombinedImageScanResult> {
  const safeImage = sanitizeImageName(image);

  if (!safeImage || safeImage.length < 2) {
    throw new Error("Invalid image name provided");
  }

  // Run all scans in parallel for 3-4x performance improvement
  const [vulnResult, secretResult, licenseResult, sbomResult] = await Promise.allSettled([
    trivyScanImage(safeImage, severity),
    trivyScanSecretsImage(safeImage, severity),
    trivyScanLicensesImage(safeImage, severity),
    trivyGenerateSbomImage(safeImage, sbomFormat),
  ]);

  return {
    image: safeImage,
    timestamp: new Date().toISOString(),
    vulnerabilities:
      vulnResult.status === "fulfilled"
        ? vulnResult.value
        : { error: (vulnResult.reason as Error).message },
    secrets:
      secretResult.status === "fulfilled"
        ? secretResult.value
        : { error: (secretResult.reason as Error).message },
    licenses:
      licenseResult.status === "fulfilled"
        ? licenseResult.value
        : { error: (licenseResult.reason as Error).message },
    sbom:
      sbomResult.status === "fulfilled"
        ? sbomResult.value
        : { error: (sbomResult.reason as Error).message },
  };
}

/**
 * Run a comprehensive scan on a local filesystem path using Trivy.
 * Combines vulnerability, secret, license, IaC scanning, and SBOM generation in one operation.
 *
 * @param path - Absolute path to the directory to scan
 * @param severity - Severity levels to report (default: HIGH,CRITICAL)
 * @param sbomFormat - SBOM format: cyclonedx (default) or spdx-json
 * @returns Promise resolving to combined scan results from all scanners
 * @throws Error if path is invalid
 *
 * @example
 * ```typescript
 * const results = await trivyScanPathFull('/home/user/project');
 * console.log(results.vulnerabilities); // Vulnerability findings
 * console.log(results.secrets); // Secret findings
 * console.log(results.licenses); // License findings
 * console.log(results.iac); // IaC misconfiguration findings
 * console.log(results.sbom); // Software Bill of Materials
 * ```
 */
export async function trivyScanPathFull(
  path: string,
  severity: string = "HIGH,CRITICAL",
  sbomFormat: "cyclonedx" | "spdx-json" = "cyclonedx"
): Promise<TrivyCombinedPathScanResult> {
  const safePath = sanitizePath(path);

  if (!safePath || safePath.length < 2) {
    throw new Error("Invalid path provided");
  }

  // Run all scans in parallel for 3-4x performance improvement
  const [vulnResult, secretResult, licenseResult, iacResult, sbomResult] = await Promise.allSettled(
    [
      trivyScanPath(safePath, severity),
      trivyScanSecrets(safePath, severity),
      trivyScanLicenses(safePath, severity),
      trivyScanIac(safePath, severity),
      trivyGenerateSbom(safePath, sbomFormat),
    ]
  );

  return {
    path: safePath,
    timestamp: new Date().toISOString(),
    vulnerabilities:
      vulnResult.status === "fulfilled"
        ? vulnResult.value
        : { error: (vulnResult.reason as Error).message },
    secrets:
      secretResult.status === "fulfilled"
        ? secretResult.value
        : { error: (secretResult.reason as Error).message },
    licenses:
      licenseResult.status === "fulfilled"
        ? licenseResult.value
        : { error: (licenseResult.reason as Error).message },
    iac:
      iacResult.status === "fulfilled"
        ? iacResult.value
        : { error: (iacResult.reason as Error).message },
    sbom:
      sbomResult.status === "fulfilled"
        ? sbomResult.value
        : { error: (sbomResult.reason as Error).message },
  };
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

/**
 * Check SonarQube quality gate status for a project.
 */
export interface QualityGateStatus {
  projectStatus: {
    status: "OK" | "WARN" | "ERROR" | "NONE";
    conditions: Array<{
      status: string;
      metricKey: string;
      comparator: string;
      errorThreshold: string;
      actualValue: string;
    }>;
  };
}

export async function sonarGetQualityGateStatus(projectKey: string): Promise<QualityGateStatus> {
  return fetchJson<QualityGateStatus>(
    `${config.sonarqube.url}/api/qualitygates/project_status?projectKey=${projectKey}`,
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

/**
 * Upload an SBOM to Dependency-Track.
 */
export interface DTrackUploadResult {
  token: string;
}

export async function dtrackUploadSbom(
  projectName: string,
  projectVersion: string,
  sbom: string,
  autoCreate: boolean = true
): Promise<DTrackUploadResult> {
  if (!config.dependencyTrack.apiKey) {
    throw new Error(
      "Dependency-Track API key not configured. Set DTRACK_API_KEY environment variable."
    );
  }

  // Encode SBOM as base64
  const sbomBase64 = Buffer.from(sbom).toString("base64");

  return fetchJson<DTrackUploadResult>(`${config.dependencyTrack.url}/api/v1/bom`, {
    method: "PUT",
    headers: {
      "X-Api-Key": config.dependencyTrack.apiKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      projectName,
      projectVersion,
      autoCreate,
      bom: sbomBase64,
    }),
  });
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

/**
 * List pull requests for a Gitea repository.
 */
export interface GiteaPullRequest {
  id: number;
  number: number;
  title: string;
  state: string;
  user: { login: string };
  body: string;
  created_at: string;
  updated_at: string;
  merged: boolean;
  mergeable: boolean;
  html_url: string;
  head: { ref: string };
  base: { ref: string };
}

export async function giteaListPullRequests(
  owner: string,
  repo: string,
  state: "open" | "closed" | "all" = "open"
): Promise<GiteaPullRequest[]> {
  return fetchJson<GiteaPullRequest[]>(
    `${config.gitea.url}/api/v1/repos/${owner}/${repo}/pulls?state=${state}`,
    {
      headers: {
        Authorization: basicAuth(config.gitea.user, config.gitea.password),
      },
    }
  );
}

/**
 * Get a specific pull request.
 */
export async function giteaGetPullRequest(
  owner: string,
  repo: string,
  pullNumber: number
): Promise<GiteaPullRequest> {
  return fetchJson<GiteaPullRequest>(
    `${config.gitea.url}/api/v1/repos/${owner}/${repo}/pulls/${pullNumber}`,
    {
      headers: {
        Authorization: basicAuth(config.gitea.user, config.gitea.password),
      },
    }
  );
}

/**
 * Create a new pull request.
 */
export async function giteaCreatePullRequest(
  owner: string,
  repo: string,
  title: string,
  head: string,
  base: string,
  body?: string
): Promise<GiteaPullRequest> {
  return fetchJson<GiteaPullRequest>(`${config.gitea.url}/api/v1/repos/${owner}/${repo}/pulls`, {
    method: "POST",
    headers: {
      Authorization: basicAuth(config.gitea.user, config.gitea.password),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ title, head, base, body: body || "" }),
  });
}

/**
 * Merge a pull request.
 */
export async function giteaMergePullRequest(
  owner: string,
  repo: string,
  pullNumber: number,
  mergeStyle: "merge" | "rebase" | "squash" = "merge"
): Promise<{ merged: boolean }> {
  await fetchJson(`${config.gitea.url}/api/v1/repos/${owner}/${repo}/pulls/${pullNumber}/merge`, {
    method: "POST",
    headers: {
      Authorization: basicAuth(config.gitea.user, config.gitea.password),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ Do: mergeStyle }),
  });
  return { merged: true };
}

/**
 * Create an issue in a Gitea repository.
 */
export interface GiteaIssue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: string;
  html_url: string;
  created_at: string;
  user: { login: string };
}

export async function giteaCreateIssue(
  owner: string,
  repo: string,
  title: string,
  body?: string,
  labels?: string[]
): Promise<GiteaIssue> {
  return fetchJson<GiteaIssue>(`${config.gitea.url}/api/v1/repos/${owner}/${repo}/issues`, {
    method: "POST",
    headers: {
      Authorization: basicAuth(config.gitea.user, config.gitea.password),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ title, body: body || "", labels: labels || [] }),
  });
}

/**
 * List issues in a Gitea repository.
 */
export async function giteaListIssues(
  owner: string,
  repo: string,
  state: "open" | "closed" | "all" = "open"
): Promise<GiteaIssue[]> {
  return fetchJson<GiteaIssue[]>(
    `${config.gitea.url}/api/v1/repos/${owner}/${repo}/issues?state=${state}&type=issues`,
    {
      headers: {
        Authorization: basicAuth(config.gitea.user, config.gitea.password),
      },
    }
  );
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
    { name: "drone", url: `${config.drone.url}/healthz` },
    { name: "sonarqube", url: `${config.sonarqube.url}/api/system/status` },
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

// =============================================================================
// Security Dashboard
// =============================================================================

/**
 * Normalize severity levels from different sources to a unified format.
 */
function normalizeSeverity(
  severity: string,
  source: "trivy" | "sonarqube" | "dtrack"
): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" {
  const upper = severity.toUpperCase();

  if (source === "sonarqube") {
    // SonarQube: BLOCKER, CRITICAL, MAJOR, MINOR, INFO
    switch (upper) {
      case "BLOCKER":
      case "CRITICAL":
        return "CRITICAL";
      case "MAJOR":
        return "HIGH";
      case "MINOR":
        return "MEDIUM";
      default:
        return "LOW";
    }
  }

  // Trivy and D-Track use similar severity levels
  switch (upper) {
    case "CRITICAL":
      return "CRITICAL";
    case "HIGH":
      return "HIGH";
    case "MEDIUM":
      return "MEDIUM";
    default:
      return "LOW";
  }
}

/**
 * Create an empty summary object.
 */
function createEmptySummary(): SecurityDashboardSummary {
  return { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
}

/**
 * Process Trivy scan results into dashboard format.
 */
function processTrivyResult(
  trivyResult: PromiseSettledResult<TrivyScanResult | ErrorResponse | null>,
  allFindings: SecurityDashboardFinding[]
): SecurityDashboardSummary | { error: string } {
  if (trivyResult.status === "rejected") {
    return { error: (trivyResult.reason as Error).message };
  }

  const trivyData = trivyResult.value;
  // Handle error response or null
  if (!trivyData) {
    return createEmptySummary();
  }
  if ("error" in trivyData) {
    return { error: trivyData.error };
  }
  if (!("Results" in trivyData) || !trivyData.Results) {
    return createEmptySummary();
  }

  const summary = createEmptySummary();
  for (const targetResult of trivyData.Results) {
    if (!targetResult.Vulnerabilities) continue;
    for (const vuln of targetResult.Vulnerabilities) {
      const normalizedSev = normalizeSeverity(vuln.Severity, "trivy");
      summary[normalizedSev.toLowerCase() as keyof SecurityDashboardSummary]++;
      summary.total++;
      allFindings.push({
        id: vuln.VulnerabilityID,
        severity: normalizedSev,
        source: "trivy",
        package: `${vuln.PkgName}@${vuln.InstalledVersion}`,
        message: vuln.Title || vuln.Description?.substring(0, 100),
      });
    }
  }
  return summary;
}

/**
 * Process SonarQube issues into dashboard format.
 */
function processSonarIssues(
  issuesResult: PromiseSettledResult<SonarIssuesResponse | null>,
  allFindings: SecurityDashboardFinding[]
): { bugs: number; vulnerabilities: number; codeSmells: number; error?: string } {
  const metrics = { bugs: 0, vulnerabilities: 0, codeSmells: 0 };

  if (issuesResult.status === "rejected") {
    return { ...metrics, error: (issuesResult.reason as Error).message };
  }

  const issuesData = issuesResult.value;
  if (!issuesData?.issues) return metrics;

  for (const issue of issuesData.issues) {
    if (issue.type === "BUG") metrics.bugs++;
    else if (issue.type === "VULNERABILITY") metrics.vulnerabilities++;
    else if (issue.type === "CODE_SMELL") metrics.codeSmells++;

    if (issue.type === "VULNERABILITY" || issue.type === "BUG") {
      allFindings.push({
        id: issue.key,
        severity: normalizeSeverity(issue.severity, "sonarqube"),
        source: "sonarqube",
        message: issue.message,
      });
    }
  }
  return metrics;
}

/**
 * Process Dependency-Track findings into dashboard format.
 */
function processDTrackResult(
  dtrackResult: PromiseSettledResult<DTrackFinding[] | null>,
  allFindings: SecurityDashboardFinding[]
): SecurityDashboardSummary | { error: string } {
  if (dtrackResult.status === "rejected") {
    return { error: (dtrackResult.reason as Error).message };
  }

  const dtrackData = dtrackResult.value;
  if (!dtrackData) return createEmptySummary();

  const summary = createEmptySummary();
  for (const finding of dtrackData) {
    const normalizedSev = normalizeSeverity(finding.vulnerability.severity, "dtrack");
    summary[normalizedSev.toLowerCase() as keyof SecurityDashboardSummary]++;
    summary.total++;
    allFindings.push({
      id: finding.vulnerability.vulnId,
      severity: normalizedSev,
      source: "dtrack",
      package: `${finding.component.name}@${finding.component.version}`,
      message: finding.vulnerability.title || finding.vulnerability.description?.substring(0, 100),
    });
  }
  return summary;
}

/**
 * Add summary counts from a source if no error.
 */
function addToSummary(
  target: SecurityDashboardSummary,
  source: SecurityDashboardSummary | { error: string }
): void {
  if ("error" in source) return;
  target.critical += source.critical;
  target.high += source.high;
  target.medium += source.medium;
  target.low += source.low;
  target.total += source.total;
}

/**
 * Get a unified security dashboard aggregating Trivy, SonarQube, and Dependency-Track results.
 * Uses parallel execution for performance with error resilience for each source.
 *
 * @param options - Options specifying what to scan
 * @param options.image - Docker image to scan with Trivy
 * @param options.path - Local path to scan with Trivy
 * @param options.sonarProject - SonarQube project key
 * @param options.dtrackProjectUuid - Dependency-Track project UUID
 * @param options.severity - Severity filter (default: HIGH,CRITICAL)
 * @returns Promise resolving to unified security dashboard
 *
 * @example
 * ```typescript
 * const dashboard = await getSecurityDashboard({
 *   image: 'nginx:latest',
 *   sonarProject: 'my-project',
 *   dtrackProjectUuid: '12345-uuid'
 * });
 * console.log(dashboard.summary); // Aggregated counts
 * console.log(dashboard.topFindings); // Top 10 findings
 * ```
 */
export async function getSecurityDashboard(
  options: SecurityDashboardOptions
): Promise<SecurityDashboardResult> {
  const { image, path, sonarProject, dtrackProjectUuid, severity = "HIGH,CRITICAL" } = options;

  // Initialize result structure
  const result: SecurityDashboardResult = {
    timestamp: new Date().toISOString(),
    summary: createEmptySummary(),
    bySource: {
      trivy: createEmptySummary(),
      sonarqube: {
        bugs: 0,
        vulnerabilities: 0,
        codeSmells: 0,
        hotspots: 0,
        qualityGateStatus: "NONE",
      },
      dependencyTrack: createEmptySummary(),
    },
    topFindings: [],
    scanTargets: {
      image,
      path,
      sonarProject,
      dtrackProject: dtrackProjectUuid,
    },
  };

  const allFindings: SecurityDashboardFinding[] = [];

  // Run all scans in parallel
  const [trivyResult, sonarIssuesResult, sonarHotspotsResult, sonarQgResult, dtrackResult] =
    await Promise.allSettled([
      // Trivy scan (image or path)
      image
        ? trivyScanImage(image, severity)
        : path
          ? trivyScanPath(path, severity)
          : Promise.resolve(null),
      // SonarQube issues
      sonarProject ? sonarGetIssues(sonarProject) : Promise.resolve(null),
      // SonarQube hotspots
      sonarProject ? sonarGetSecurityHotspots(sonarProject) : Promise.resolve(null),
      // SonarQube quality gate
      sonarProject ? sonarGetQualityGateStatus(sonarProject) : Promise.resolve(null),
      // Dependency-Track findings
      dtrackProjectUuid ? dtrackGetFindings(dtrackProjectUuid) : Promise.resolve(null),
    ]);

  // Process results using helper functions
  result.bySource.trivy = processTrivyResult(trivyResult, allFindings);
  result.bySource.dependencyTrack = processDTrackResult(dtrackResult, allFindings);

  // Process SonarQube results
  const sonarIssueMetrics = processSonarIssues(sonarIssuesResult, allFindings);
  const sonarMetrics: SonarDashboardMetrics = {
    bugs: sonarIssueMetrics.bugs,
    vulnerabilities: sonarIssueMetrics.vulnerabilities,
    codeSmells: sonarIssueMetrics.codeSmells,
    hotspots: 0,
    qualityGateStatus: "NONE",
    error: sonarIssueMetrics.error,
  };

  // Process SonarQube hotspots
  if (sonarHotspotsResult.status === "fulfilled" && sonarHotspotsResult.value) {
    const hotspotsData = sonarHotspotsResult.value as SonarHotspotsResponse;
    sonarMetrics.hotspots = hotspotsData.paging?.total || hotspotsData.hotspots?.length || 0;
  }

  // Process SonarQube quality gate
  if (sonarQgResult.status === "fulfilled" && sonarQgResult.value) {
    const qgData = sonarQgResult.value as QualityGateStatus;
    sonarMetrics.qualityGateStatus = qgData.projectStatus?.status || "NONE";
  }

  result.bySource.sonarqube = sonarMetrics;

  // Calculate total summary from successful sources
  addToSummary(result.summary, result.bySource.trivy);
  addToSummary(result.summary, result.bySource.dependencyTrack);

  // Add SonarQube vulnerabilities to summary
  result.summary.critical += sonarMetrics.vulnerabilities;
  result.summary.total += sonarMetrics.vulnerabilities + sonarMetrics.bugs;

  // Sort findings by severity and take top 10
  const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  allFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  result.topFindings = allFindings.slice(0, 10);

  return result;
}
