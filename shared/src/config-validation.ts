/**
 * Configuration Validation
 *
 * Validates configuration at startup to catch misconfigurations early.
 */

import { config, type Config } from "./config.js";

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export interface ServiceValidation {
  service: string;
  reachable: boolean;
  error?: string;
  responseTimeMs?: number;
}

/**
 * Validate URL format
 */
function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate configuration values
 */
export function validateConfig(cfg: Config = config): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Validate Gitea config
  if (!cfg.gitea.url) {
    errors.push("Gitea URL is not configured");
  } else if (!isValidUrl(cfg.gitea.url)) {
    errors.push(`Invalid Gitea URL: ${cfg.gitea.url}`);
  }
  if (!cfg.gitea.user || !cfg.gitea.password) {
    warnings.push("Gitea credentials are not configured - authenticated operations may fail");
  }

  // Validate Drone config
  if (!cfg.drone.url) {
    errors.push("Drone URL is not configured");
  } else if (!isValidUrl(cfg.drone.url)) {
    errors.push(`Invalid Drone URL: ${cfg.drone.url}`);
  }
  if (!cfg.drone.token) {
    warnings.push("Drone token is not configured - authenticated operations will fail");
  }

  // Validate SonarQube config
  if (!cfg.sonarqube.url) {
    errors.push("SonarQube URL is not configured");
  } else if (!isValidUrl(cfg.sonarqube.url)) {
    errors.push(`Invalid SonarQube URL: ${cfg.sonarqube.url}`);
  }
  if (!cfg.sonarqube.user || !cfg.sonarqube.password) {
    warnings.push("SonarQube credentials are not configured - authenticated operations may fail");
  }

  // Validate Dependency-Track config
  if (!cfg.dependencyTrack.url) {
    errors.push("Dependency-Track URL is not configured");
  } else if (!isValidUrl(cfg.dependencyTrack.url)) {
    errors.push(`Invalid Dependency-Track URL: ${cfg.dependencyTrack.url}`);
  }
  if (!cfg.dependencyTrack.apiKey) {
    warnings.push("Dependency-Track API key is not configured - operations will fail");
  }

  // Validate Registry config
  if (!cfg.registry.url) {
    errors.push("Registry URL is not configured");
  } else if (!isValidUrl(cfg.registry.url)) {
    errors.push(`Invalid Registry URL: ${cfg.registry.url}`);
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Check if a service is reachable
 */
async function checkServiceHealth(
  name: string,
  url: string,
  healthPath = ""
): Promise<ServiceValidation> {
  const startTime = Date.now();

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(`${url}${healthPath}`, {
      method: "GET",
      signal: controller.signal,
    });

    clearTimeout(timeout);

    return {
      service: name,
      reachable: response.ok || response.status < 500,
      responseTimeMs: Date.now() - startTime,
    };
  } catch (error) {
    return {
      service: name,
      reachable: false,
      error: error instanceof Error ? error.message : String(error),
      responseTimeMs: Date.now() - startTime,
    };
  }
}

/**
 * Validate service connectivity
 */
export async function validateConnectivity(cfg: Config = config): Promise<ServiceValidation[]> {
  const checks = [
    checkServiceHealth("gitea", cfg.gitea.url, "/api/v1/version"),
    checkServiceHealth("drone", cfg.drone.url, "/api/user"),
    checkServiceHealth("sonarqube", cfg.sonarqube.url, "/api/system/status"),
    checkServiceHealth("dependency-track", cfg.dependencyTrack.url, "/api/version"),
    checkServiceHealth("registry", cfg.registry.url, "/v2/"),
  ];

  return Promise.all(checks);
}

/**
 * Full startup validation
 */
export async function validateStartup(cfg: Config = config): Promise<{
  config: ValidationResult;
  connectivity: ServiceValidation[];
  ready: boolean;
}> {
  const configResult = validateConfig(cfg);
  const connectivityResults = await validateConnectivity(cfg);

  // Consider ready if config is valid and at least some services are reachable
  const reachableServices = connectivityResults.filter((s) => s.reachable).length;
  const ready = configResult.valid && reachableServices > 0;

  return {
    config: configResult,
    connectivity: connectivityResults,
    ready,
  };
}

/**
 * Log validation results
 */
export function logValidationResults(result: {
  config: ValidationResult;
  connectivity: ServiceValidation[];
  ready: boolean;
}): void {
  console.log("\n=== Configuration Validation ===\n");

  if (result.config.errors.length > 0) {
    console.log("❌ Errors:");
    result.config.errors.forEach((e) => console.log(`   - ${e}`));
  }

  if (result.config.warnings.length > 0) {
    console.log("⚠️  Warnings:");
    result.config.warnings.forEach((w) => console.log(`   - ${w}`));
  }

  console.log("\n=== Service Connectivity ===\n");

  result.connectivity.forEach((s) => {
    const status = s.reachable ? "✅" : "❌";
    const time = s.responseTimeMs ? ` (${s.responseTimeMs}ms)` : "";
    const error = s.error ? ` - ${s.error}` : "";
    console.log(`${status} ${s.service}${time}${error}`);
  });

  console.log("\n=== Summary ===\n");
  console.log(`Ready: ${result.ready ? "✅ Yes" : "❌ No"}`);
  console.log(
    `Services: ${result.connectivity.filter((s) => s.reachable).length}/${result.connectivity.length} reachable`
  );
  console.log("");
}
