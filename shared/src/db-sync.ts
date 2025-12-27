/**
 * Database Sync Module
 *
 * Handles synchronization of Trivy vulnerability databases for offline scanning.
 * Downloads and caches vulnerability data from Trivy's database.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  initVulnDatabase,
  isVulnDbInitialized,
  bulkInsertVulnerabilities,
  updateSyncStatus,
  getSyncStatus,
  getAllSyncStatuses,
} from "./vuln-database.js";
import type {
  VulnDbRecord,
  VulnDbSyncOptions,
  TrivyDbSyncResult,
  TrivyDbStatus,
  TrivyScanResult,
  TrivyVulnerability,
} from "./types.js";

const execFileAsync = promisify(execFile);

// =============================================================================
// TRIVY DATABASE PATHS
// =============================================================================

/**
 * Get the Trivy cache directory path
 */
export function getTrivyCacheDir(): string {
  // Trivy stores its cache in ~/.cache/trivy on Linux/macOS
  // or %LOCALAPPDATA%/trivy on Windows
  if (process.platform === "win32") {
    return path.join(process.env.LOCALAPPDATA || os.homedir(), "trivy");
  }
  return path.join(os.homedir(), ".cache", "trivy");
}

/**
 * Get the Trivy vulnerability database path
 */
export function getTrivyDbPath(): string {
  return path.join(getTrivyCacheDir(), "db", "trivy.db");
}

// =============================================================================
// TRIVY DATABASE STATUS
// =============================================================================

/**
 * Get the status of the Trivy vulnerability database
 */
export async function getTrivyDbStatus(): Promise<TrivyDbStatus> {
  const dbPath = getTrivyDbPath();
  const exists = fs.existsSync(dbPath);

  if (!exists) {
    return {
      exists: false,
      isStale: true,
    };
  }

  try {
    const stats = fs.statSync(dbPath);
    const lastUpdate = stats.mtime.toISOString();
    const ageMs = Date.now() - stats.mtime.getTime();
    const ageHours = Math.round(ageMs / (1000 * 60 * 60));

    // Try to get version from Trivy
    let version: string | undefined;
    try {
      const { stdout } = await execFileAsync("docker", [
        "run",
        "--rm",
        "-v",
        `${getTrivyCacheDir()}:/root/.cache/trivy`,
        "aquasec/trivy:latest",
        "version",
        "--format",
        "json",
      ]);
      const versionInfo = JSON.parse(stdout);
      version = versionInfo.VulnerabilityDB?.Version;
    } catch {
      // Version check failed, continue without it
    }

    return {
      exists: true,
      version,
      lastUpdate,
      ageHours,
      sizeBytes: stats.size,
      isStale: ageHours > 24,
    };
  } catch (error) {
    return {
      exists: true,
      isStale: true,
    };
  }
}

// =============================================================================
// TRIVY DATABASE DOWNLOAD
// =============================================================================

/**
 * Download/update the Trivy vulnerability database
 *
 * This downloads the database without performing a scan.
 * The database can then be used for offline scanning.
 */
export async function downloadTrivyDb(): Promise<TrivyDbSyncResult> {
  const startTime = Date.now();

  // Ensure cache directory exists
  const cacheDir = getTrivyCacheDir();
  if (!fs.existsSync(cacheDir)) {
    fs.mkdirSync(cacheDir, { recursive: true });
  }

  try {
    // Update sync status to syncing
    if (isVulnDbInitialized()) {
      updateSyncStatus("trivy", { status: "syncing" });
    }

    // Download database using Trivy's --download-db-only flag
    await execFileAsync(
      "docker",
      [
        "run",
        "--rm",
        "-v",
        `${cacheDir}:/root/.cache/trivy`,
        "aquasec/trivy:latest",
        "image",
        "--download-db-only",
      ],
      { maxBuffer: 50 * 1024 * 1024 }
    );

    const durationMs = Date.now() - startTime;

    // Get the database status after download
    const status = await getTrivyDbStatus();

    // Update sync status in our local database
    if (isVulnDbInitialized()) {
      updateSyncStatus("trivy", {
        status: "synced",
        lastSync: new Date().toISOString(),
        dbVersion: status.version || undefined,
      });
    }

    return {
      success: true,
      dbVersion: status.version,
      durationMs,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);

    // Update sync status to error
    if (isVulnDbInitialized()) {
      updateSyncStatus("trivy", { status: "error" });
    }

    return {
      success: false,
      error: `Failed to download Trivy database: ${message}`,
      durationMs: Date.now() - startTime,
    };
  }
}

// =============================================================================
// VULNERABILITY IMPORT FROM TRIVY SCANS
// =============================================================================

/**
 * Parse a Trivy vulnerability into our database format
 */
export function parseVulnFromTrivy(vuln: TrivyVulnerability, _target: string): VulnDbRecord {
  return {
    id: vuln.VulnerabilityID,
    source: "trivy",
    severity: vuln.Severity,
    cvssScore: undefined, // Trivy doesn't always include CVSS in the scan output
    title: vuln.Title || vuln.VulnerabilityID,
    description: vuln.Description || "",
    references: vuln.PrimaryURL ? [vuln.PrimaryURL] : [],
    publishedAt: undefined, // Not available in scan output
    modifiedAt: undefined,
  };
}

/**
 * Import vulnerabilities from a Trivy scan result into the local database
 *
 * This allows caching scan results for future lookups.
 */
export function importTrivyScanResult(scanResult: TrivyScanResult): {
  success: boolean;
  imported: number;
  error?: string;
} {
  if (!isVulnDbInitialized()) {
    return {
      success: false,
      imported: 0,
      error: "Vulnerability database not initialized",
    };
  }

  if (!scanResult.Results) {
    return {
      success: true,
      imported: 0,
    };
  }

  const vulns: VulnDbRecord[] = [];
  const seen = new Set<string>();

  for (const result of scanResult.Results) {
    if (!result.Vulnerabilities) continue;

    for (const vuln of result.Vulnerabilities) {
      // Avoid duplicates (same CVE can appear in multiple packages)
      if (seen.has(vuln.VulnerabilityID)) continue;
      seen.add(vuln.VulnerabilityID);

      vulns.push(parseVulnFromTrivy(vuln, result.Target));
    }
  }

  if (vulns.length === 0) {
    return {
      success: true,
      imported: 0,
    };
  }

  const result = bulkInsertVulnerabilities(vulns);

  return {
    success: result.success,
    imported: result.inserted + result.updated,
    error: result.errors > 0 ? `${result.errors} vulnerabilities failed to import` : undefined,
  };
}

// =============================================================================
// SYNC OPERATIONS
// =============================================================================

/**
 * Sync vulnerability database from Trivy
 *
 * This downloads the Trivy database if needed and updates our local cache.
 */
export async function syncVulnDatabase(
  options: VulnDbSyncOptions = {}
): Promise<TrivyDbSyncResult> {
  const { force = false, skipIfRecent = 24 } = options;

  // Initialize database if not already done
  if (!isVulnDbInitialized()) {
    const initResult = initVulnDatabase();
    if (!initResult.success) {
      return {
        success: false,
        error: `Failed to initialize database: ${initResult.error}`,
      };
    }
  }

  // Check if we should skip based on recent sync
  if (!force) {
    const status = getSyncStatus("trivy");
    if (status && status.ageHours !== undefined && status.ageHours < skipIfRecent) {
      return {
        success: true,
        dbVersion: status.dbVersion || undefined,
        vulnerabilitiesImported: 0,
        durationMs: 0,
      };
    }
  }

  // Download/update Trivy database
  return downloadTrivyDb();
}

/**
 * Get the current sync status for all sources
 */
export function getVulnDbSyncStatus(): {
  sources: ReturnType<typeof getAllSyncStatuses>;
  trivyDb: TrivyDbStatus | null;
} {
  if (!isVulnDbInitialized()) {
    return {
      sources: [],
      trivyDb: null,
    };
  }

  // We can't call async getTrivyDbStatus here, so just return sources
  return {
    sources: getAllSyncStatuses(),
    trivyDb: null, // Caller should use getTrivyDbStatus() separately
  };
}

/**
 * Check if offline scanning is available
 *
 * Offline scanning requires the Trivy database to be downloaded locally.
 */
export async function isOfflineScanAvailable(): Promise<{
  available: boolean;
  reason?: string;
  dbStatus?: TrivyDbStatus;
}> {
  const dbStatus = await getTrivyDbStatus();

  if (!dbStatus.exists) {
    return {
      available: false,
      reason: "Trivy database not found. Run vuln_db_sync to download.",
      dbStatus,
    };
  }

  if (dbStatus.isStale) {
    return {
      available: true, // Still available but stale
      reason: `Database is ${dbStatus.ageHours} hours old. Consider syncing for latest vulnerabilities.`,
      dbStatus,
    };
  }

  return {
    available: true,
    dbStatus,
  };
}

// =============================================================================
// SCHEDULED SYNC
// =============================================================================

/**
 * Schedule automatic database sync using the scheduler module
 *
 * This is a convenience function that creates a schedule for regular syncs.
 */
export async function scheduleDatabaseSync(
  cron: string,
  name: string = "vuln-db-sync"
): Promise<{ success: boolean; scheduleId?: string; error?: string }> {
  try {
    // Dynamically import scheduler to avoid circular dependencies
    const { createSchedule } = await import("./scheduler.js");

    const schedule = createSchedule({
      name,
      cron,
      targets: [], // No scan targets, just sync
      options: {},
      enabled: true,
    });

    return {
      success: true,
      scheduleId: schedule.id,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      error: `Failed to schedule sync: ${message}`,
    };
  }
}
