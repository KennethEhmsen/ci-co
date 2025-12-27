/**
 * Offline Scanner Module
 *
 * Provides offline vulnerability scanning capabilities using
 * locally cached Trivy databases. Enables air-gapped scanning
 * without internet connectivity.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { validateSeverity, sanitizePath, sanitizeImageName } from "./validation.js";
import {
  getTrivyCacheDir,
  getTrivyDbStatus,
  isOfflineScanAvailable,
  importTrivyScanResult,
} from "./db-sync.js";
import { isVulnDbInitialized } from "./vuln-database.js";
import type { TrivyScanResult, OfflineScanOptions, TrivyDbStatus } from "./types.js";

const execFileAsync = promisify(execFile);

// =============================================================================
// ERROR TYPES
// =============================================================================

interface OfflineScanError {
  error: string;
  dbStatus?: TrivyDbStatus;
  output?: string;
}

type OfflineScanResult = TrivyScanResult | OfflineScanError;

// =============================================================================
// OFFLINE SCANNING
// =============================================================================

/**
 * Scan a Docker image using the locally cached Trivy database
 *
 * This performs a scan without downloading the vulnerability database,
 * using the cached database from a previous sync.
 *
 * @param image - Docker image to scan (e.g., nginx:latest)
 * @param options - Scan options
 * @returns Trivy scan results
 */
export async function offlineScanImage(
  image: string,
  options: Partial<OfflineScanOptions> = {}
): Promise<OfflineScanResult> {
  const safeImage = sanitizeImageName(image);

  if (!safeImage || safeImage.length < 2) {
    return { error: "Invalid image name provided" };
  }

  // Check if offline scanning is available
  const availability = await isOfflineScanAvailable();
  if (!availability.available) {
    return {
      error: availability.reason || "Offline scanning not available",
      dbStatus: availability.dbStatus,
    };
  }

  const severity = validateSeverity(options.severity || "HIGH,CRITICAL");
  const cacheDir = getTrivyCacheDir();

  try {
    const args = [
      "run",
      "--rm",
      "--network",
      "none", // No network access for true offline mode
      "-v",
      `${cacheDir}:/root/.cache/trivy`,
      "aquasec/trivy:latest",
      "image",
      "--skip-db-update", // Don't try to update the database
      "--offline-scan", // Enable offline mode
      "--format",
      "json",
      "--severity",
      severity,
    ];

    if (options.ignoreUnfixed) {
      args.push("--ignore-unfixed");
    }

    args.push(safeImage);

    const { stdout } = await execFileAsync("docker", args, {
      maxBuffer: 10 * 1024 * 1024,
    });

    const result = JSON.parse(stdout) as TrivyScanResult;

    // Optionally cache the results in our local database
    if (isVulnDbInitialized()) {
      importTrivyScanResult(result);
    }

    return result;
  } catch (error) {
    const err = error as { stdout?: string; message?: string };
    if (err.stdout) {
      try {
        return JSON.parse(err.stdout) as TrivyScanResult;
      } catch {
        return {
          error: err.message || "Scan failed",
          output: err.stdout,
          dbStatus: availability.dbStatus,
        };
      }
    }
    return {
      error: err.message || "Offline scan failed",
      dbStatus: availability.dbStatus,
    };
  }
}

/**
 * Scan a filesystem path using the locally cached Trivy database
 *
 * This performs a scan without downloading the vulnerability database,
 * using the cached database from a previous sync.
 *
 * @param scanPath - Absolute path to the directory to scan
 * @param options - Scan options
 * @returns Trivy scan results
 */
export async function offlineScanPath(
  scanPath: string,
  options: Partial<OfflineScanOptions> = {}
): Promise<OfflineScanResult> {
  const safePath = sanitizePath(scanPath);

  if (!safePath || safePath.length < 2) {
    return { error: "Invalid path provided" };
  }

  // Check if offline scanning is available
  const availability = await isOfflineScanAvailable();
  if (!availability.available) {
    return {
      error: availability.reason || "Offline scanning not available",
      dbStatus: availability.dbStatus,
    };
  }

  const severity = validateSeverity(options.severity || "HIGH,CRITICAL");
  const cacheDir = getTrivyCacheDir();

  try {
    const args = [
      "run",
      "--rm",
      "--network",
      "none", // No network access for true offline mode
      "-v",
      `${cacheDir}:/root/.cache/trivy`,
      "-v",
      `${safePath}:/app:ro`,
      "aquasec/trivy:latest",
      "fs",
      "--skip-db-update", // Don't try to update the database
      "--offline-scan", // Enable offline mode
      "--format",
      "json",
      "--severity",
      severity,
      "/app",
    ];

    if (options.ignoreUnfixed) {
      args.push("--ignore-unfixed");
    }

    const { stdout } = await execFileAsync("docker", args, {
      maxBuffer: 10 * 1024 * 1024,
    });

    const result = JSON.parse(stdout) as TrivyScanResult;

    // Optionally cache the results in our local database
    if (isVulnDbInitialized()) {
      importTrivyScanResult(result);
    }

    return result;
  } catch (error) {
    const err = error as { stdout?: string; message?: string };
    if (err.stdout) {
      try {
        return JSON.parse(err.stdout) as TrivyScanResult;
      } catch {
        return {
          error: err.message || "Scan failed",
          output: err.stdout,
          dbStatus: availability.dbStatus,
        };
      }
    }
    return {
      error: err.message || "Offline scan failed",
      dbStatus: availability.dbStatus,
    };
  }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Check if a scan result is an error
 */
export function isOfflineScanError(result: OfflineScanResult): result is OfflineScanError {
  return "error" in result;
}

/**
 * Get the age of the offline database in hours
 */
export async function getOfflineDbAge(): Promise<number | null> {
  const status = await getTrivyDbStatus();
  return status.ageHours ?? null;
}

/**
 * Check if the offline database is stale (>24 hours old)
 */
export async function isOfflineDbStale(): Promise<boolean> {
  const status = await getTrivyDbStatus();
  return status.isStale;
}

/**
 * Get a summary of offline scanning capabilities
 */
export async function getOfflineScanCapabilities(): Promise<{
  available: boolean;
  imageScanning: boolean;
  pathScanning: boolean;
  dbStatus: TrivyDbStatus;
  warnings: string[];
}> {
  const dbStatus = await getTrivyDbStatus();
  const warnings: string[] = [];

  if (!dbStatus.exists) {
    return {
      available: false,
      imageScanning: false,
      pathScanning: false,
      dbStatus,
      warnings: ["Vulnerability database not found. Run vuln_db_sync to download."],
    };
  }

  if (dbStatus.isStale) {
    warnings.push(
      `Database is ${dbStatus.ageHours} hours old. Consider syncing for latest vulnerabilities.`
    );
  }

  // Check if Docker is available
  let dockerAvailable = false;
  try {
    await execFileAsync("docker", ["version"], { timeout: 5000 });
    dockerAvailable = true;
  } catch {
    warnings.push("Docker is not available. Offline scanning requires Docker.");
  }

  return {
    available: dbStatus.exists && dockerAvailable,
    imageScanning: dockerAvailable,
    pathScanning: dockerAvailable,
    dbStatus,
    warnings,
  };
}

// =============================================================================
// BATCH OFFLINE SCANNING
// =============================================================================

/**
 * Scan multiple images offline
 */
export async function offlineScanImages(
  images: string[],
  options: Partial<OfflineScanOptions> = {}
): Promise<Map<string, OfflineScanResult>> {
  const results = new Map<string, OfflineScanResult>();

  for (const image of images) {
    const result = await offlineScanImage(image, options);
    results.set(image, result);
  }

  return results;
}

/**
 * Scan multiple paths offline
 */
export async function offlineScanPaths(
  paths: string[],
  options: Partial<OfflineScanOptions> = {}
): Promise<Map<string, OfflineScanResult>> {
  const results = new Map<string, OfflineScanResult>();

  for (const scanPath of paths) {
    const result = await offlineScanPath(scanPath, options);
    results.set(scanPath, result);
  }

  return results;
}
