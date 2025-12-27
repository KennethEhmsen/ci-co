/**
 * Vulnerability Database Module
 *
 * Provides SQLite-based persistent storage for vulnerability data,
 * enabling offline scanning and local vulnerability lookups.
 */

import Database from "better-sqlite3";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import type {
  VulnDbRecord,
  VulnDbAffectedPackage,
  VulnDbSyncStatus,
  VulnDbSearchQuery,
  VulnDbStats,
  VulnAnnotation,
} from "./types.js";

// =============================================================================
// DATABASE INSTANCE
// =============================================================================

let db: Database.Database | null = null;
let dbPath: string | null = null;

/**
 * Get the default database path
 */
export function getDefaultDbPath(): string {
  const dataDir = path.join(os.homedir(), ".cicd-security");
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  return path.join(dataDir, "vuln-database.sqlite");
}

/**
 * Initialize the vulnerability database
 *
 * @param customPath - Optional custom path for the database file
 * @returns Information about the initialized database
 */
export function initVulnDatabase(customPath?: string): {
  success: boolean;
  path: string;
  created: boolean;
  error?: string;
} {
  try {
    dbPath = customPath || getDefaultDbPath();
    const existed = fs.existsSync(dbPath);

    db = new Database(dbPath);

    // Enable WAL mode for better concurrent performance
    db.pragma("journal_mode = WAL");

    // Create schema if needed
    createSchema();

    return {
      success: true,
      path: dbPath,
      created: !existed,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      path: customPath || getDefaultDbPath(),
      created: false,
      error: message,
    };
  }
}

/**
 * Close the database connection
 */
export function closeVulnDatabase(): void {
  if (db) {
    db.close();
    db = null;
    dbPath = null;
  }
}

/**
 * Get the current database instance (for testing/advanced use)
 */
export function getVulnDatabase(): Database.Database | null {
  return db;
}

/**
 * Check if database is initialized
 */
export function isVulnDbInitialized(): boolean {
  return db !== null;
}

// =============================================================================
// SCHEMA CREATION
// =============================================================================

function createSchema(): void {
  if (!db) throw new Error("Database not initialized");

  db.exec(`
    -- Core vulnerability data
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id TEXT PRIMARY KEY,
      source TEXT NOT NULL,
      severity TEXT,
      cvss_score REAL,
      title TEXT,
      description TEXT,
      references_json TEXT,
      published_at TEXT,
      modified_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Affected packages
    CREATE TABLE IF NOT EXISTS affected_packages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vuln_id TEXT NOT NULL,
      ecosystem TEXT,
      package_name TEXT NOT NULL,
      version_start TEXT,
      version_end TEXT,
      fixed_version TEXT,
      FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
    );

    -- Sync metadata
    CREATE TABLE IF NOT EXISTS sync_metadata (
      source TEXT PRIMARY KEY,
      last_sync TEXT,
      record_count INTEGER DEFAULT 0,
      db_version TEXT,
      status TEXT DEFAULT 'never'
    );

    -- User annotations
    CREATE TABLE IF NOT EXISTS vulnerability_annotations (
      vuln_id TEXT PRIMARY KEY,
      status TEXT,
      notes TEXT,
      updated_at TEXT,
      FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
    );

    -- Indexes for performance
    CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
    CREATE INDEX IF NOT EXISTS idx_vuln_source ON vulnerabilities(source);
    CREATE INDEX IF NOT EXISTS idx_vuln_published ON vulnerabilities(published_at);
    CREATE INDEX IF NOT EXISTS idx_affected_pkg ON affected_packages(package_name);
    CREATE INDEX IF NOT EXISTS idx_affected_eco ON affected_packages(ecosystem);
    CREATE INDEX IF NOT EXISTS idx_affected_vuln ON affected_packages(vuln_id);
  `);
}

// =============================================================================
// VULNERABILITY CRUD OPERATIONS
// =============================================================================

/**
 * Insert or update a vulnerability record
 */
export function insertVulnerability(vuln: VulnDbRecord): {
  success: boolean;
  action: "inserted" | "updated";
  error?: string;
} {
  if (!db) throw new Error("Database not initialized");

  try {
    const stmt = db.prepare(`
      INSERT INTO vulnerabilities (id, source, severity, cvss_score, title, description, references_json, published_at, modified_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        source = excluded.source,
        severity = excluded.severity,
        cvss_score = excluded.cvss_score,
        title = excluded.title,
        description = excluded.description,
        references_json = excluded.references_json,
        published_at = excluded.published_at,
        modified_at = excluded.modified_at
    `);

    const existingStmt = db.prepare("SELECT 1 FROM vulnerabilities WHERE id = ?");
    const exists = existingStmt.get(vuln.id);

    stmt.run(
      vuln.id,
      vuln.source,
      vuln.severity,
      vuln.cvssScore || null,
      vuln.title,
      vuln.description,
      JSON.stringify(vuln.references || []),
      vuln.publishedAt || null,
      vuln.modifiedAt || null
    );

    return {
      success: true,
      action: exists ? "updated" : "inserted",
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      action: "inserted",
      error: message,
    };
  }
}

/**
 * Bulk insert vulnerabilities (more efficient for large datasets)
 */
export function bulkInsertVulnerabilities(vulns: VulnDbRecord[]): {
  success: boolean;
  inserted: number;
  updated: number;
  errors: number;
} {
  if (!db) throw new Error("Database not initialized");

  let inserted = 0;
  let updated = 0;
  let errors = 0;

  const insertStmt = db.prepare(`
    INSERT INTO vulnerabilities (id, source, severity, cvss_score, title, description, references_json, published_at, modified_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      source = excluded.source,
      severity = excluded.severity,
      cvss_score = excluded.cvss_score,
      title = excluded.title,
      description = excluded.description,
      references_json = excluded.references_json,
      published_at = excluded.published_at,
      modified_at = excluded.modified_at
  `);

  const existingStmt = db.prepare("SELECT 1 FROM vulnerabilities WHERE id = ?");

  const transaction = db.transaction(() => {
    for (const vuln of vulns) {
      try {
        const exists = existingStmt.get(vuln.id);
        insertStmt.run(
          vuln.id,
          vuln.source,
          vuln.severity,
          vuln.cvssScore || null,
          vuln.title,
          vuln.description,
          JSON.stringify(vuln.references || []),
          vuln.publishedAt || null,
          vuln.modifiedAt || null
        );
        if (exists) {
          updated++;
        } else {
          inserted++;
        }
      } catch {
        errors++;
      }
    }
  });

  transaction();

  return {
    success: errors === 0,
    inserted,
    updated,
    errors,
  };
}

/**
 * Look up a vulnerability by ID
 */
export function lookupVulnerability(id: string): VulnDbRecord | null {
  if (!db) throw new Error("Database not initialized");

  const stmt = db.prepare(`
    SELECT id, source, severity, cvss_score as cvssScore, title, description,
           references_json as refsJson, published_at as publishedAt, modified_at as modifiedAt
    FROM vulnerabilities WHERE id = ?
  `);

  const row = stmt.get(id) as
    | {
        id: string;
        source: string;
        severity: string;
        cvssScore: number | null;
        title: string;
        description: string;
        refsJson: string;
        publishedAt: string | null;
        modifiedAt: string | null;
      }
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    source: row.source as VulnDbRecord["source"],
    severity: row.severity as VulnDbRecord["severity"],
    cvssScore: row.cvssScore ?? undefined,
    title: row.title,
    description: row.description,
    references: JSON.parse(row.refsJson || "[]"),
    publishedAt: row.publishedAt ?? undefined,
    modifiedAt: row.modifiedAt ?? undefined,
  };
}

/**
 * Delete a vulnerability by ID
 */
export function deleteVulnerability(id: string): boolean {
  if (!db) throw new Error("Database not initialized");

  const stmt = db.prepare("DELETE FROM vulnerabilities WHERE id = ?");
  const result = stmt.run(id);
  return result.changes > 0;
}

// =============================================================================
// AFFECTED PACKAGES OPERATIONS
// =============================================================================

/**
 * Add affected packages for a vulnerability
 */
export function addAffectedPackages(packages: VulnDbAffectedPackage[]): {
  success: boolean;
  added: number;
  error?: string;
} {
  if (!db) throw new Error("Database not initialized");

  try {
    const stmt = db.prepare(`
      INSERT INTO affected_packages (vuln_id, ecosystem, package_name, version_start, version_end, fixed_version)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    const transaction = db.transaction(() => {
      for (const pkg of packages) {
        stmt.run(
          pkg.vulnId,
          pkg.ecosystem || null,
          pkg.packageName,
          pkg.versionStart || null,
          pkg.versionEnd || null,
          pkg.fixedVersion || null
        );
      }
    });

    transaction();

    return {
      success: true,
      added: packages.length,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      added: 0,
      error: message,
    };
  }
}

/**
 * Get affected packages for a vulnerability
 */
export function getAffectedPackages(vulnId: string): VulnDbAffectedPackage[] {
  if (!db) throw new Error("Database not initialized");

  const stmt = db.prepare(`
    SELECT vuln_id as vulnId, ecosystem, package_name as packageName,
           version_start as versionStart, version_end as versionEnd, fixed_version as fixedVersion
    FROM affected_packages WHERE vuln_id = ?
  `);

  return stmt.all(vulnId) as VulnDbAffectedPackage[];
}

/**
 * Clear affected packages for a vulnerability (for re-sync)
 */
export function clearAffectedPackages(vulnId: string): number {
  if (!db) throw new Error("Database not initialized");

  const stmt = db.prepare("DELETE FROM affected_packages WHERE vuln_id = ?");
  const result = stmt.run(vulnId);
  return result.changes;
}

// =============================================================================
// SEARCH OPERATIONS
// =============================================================================

/**
 * Search vulnerabilities with various filters
 */
export function searchVulnerabilities(query: VulnDbSearchQuery): {
  results: VulnDbRecord[];
  total: number;
  hasMore: boolean;
} {
  if (!db) throw new Error("Database not initialized");

  const conditions: string[] = [];
  const params: (string | number)[] = [];

  // Build WHERE clause
  if (query.packageName) {
    conditions.push(`v.id IN (
      SELECT vuln_id FROM affected_packages WHERE package_name LIKE ?
    )`);
    params.push(`%${query.packageName}%`);
  }

  if (query.ecosystem) {
    conditions.push(`v.id IN (
      SELECT vuln_id FROM affected_packages WHERE ecosystem = ?
    )`);
    params.push(query.ecosystem);
  }

  if (query.severity && query.severity.length > 0) {
    const placeholders = query.severity.map(() => "?").join(", ");
    conditions.push(`v.severity IN (${placeholders})`);
    params.push(...query.severity);
  }

  if (query.cvePattern) {
    conditions.push("v.id LIKE ?");
    params.push(`%${query.cvePattern}%`);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

  // Count total
  const countStmt = db.prepare(`SELECT COUNT(*) as count FROM vulnerabilities v ${whereClause}`);
  const { count: total } = countStmt.get(...params) as { count: number };

  // Fetch results with pagination
  const limit = query.limit || 100;
  const offset = query.offset || 0;

  const selectStmt = db.prepare(`
    SELECT v.id, v.source, v.severity, v.cvss_score as cvssScore, v.title, v.description,
           v.references_json as refsJson, v.published_at as publishedAt, v.modified_at as modifiedAt
    FROM vulnerabilities v
    ${whereClause}
    ORDER BY
      CASE v.severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
        ELSE 5
      END,
      v.published_at DESC
    LIMIT ? OFFSET ?
  `);

  const rows = selectStmt.all(...params, limit, offset) as Array<{
    id: string;
    source: string;
    severity: string;
    cvssScore: number | null;
    title: string;
    description: string;
    refsJson: string;
    publishedAt: string | null;
    modifiedAt: string | null;
  }>;

  const results: VulnDbRecord[] = rows.map((row) => ({
    id: row.id,
    source: row.source as VulnDbRecord["source"],
    severity: row.severity as VulnDbRecord["severity"],
    cvssScore: row.cvssScore ?? undefined,
    title: row.title,
    description: row.description,
    references: JSON.parse(row.refsJson || "[]"),
    publishedAt: row.publishedAt ?? undefined,
    modifiedAt: row.modifiedAt ?? undefined,
  }));

  return {
    results,
    total,
    hasMore: offset + results.length < total,
  };
}

/**
 * Search vulnerabilities by package name (shorthand)
 */
export function findVulnerabilitiesByPackage(
  packageName: string,
  ecosystem?: string
): VulnDbRecord[] {
  const { results } = searchVulnerabilities({
    packageName,
    ecosystem,
    limit: 1000,
  });
  return results;
}

// =============================================================================
// SYNC STATUS OPERATIONS
// =============================================================================

/**
 * Update sync status for a source
 */
export function updateSyncStatus(source: string, status: Partial<VulnDbSyncStatus>): void {
  if (!db) throw new Error("Database not initialized");

  const stmt = db.prepare(`
    INSERT INTO sync_metadata (source, last_sync, record_count, db_version, status)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(source) DO UPDATE SET
      last_sync = COALESCE(excluded.last_sync, sync_metadata.last_sync),
      record_count = COALESCE(excluded.record_count, sync_metadata.record_count),
      db_version = COALESCE(excluded.db_version, sync_metadata.db_version),
      status = COALESCE(excluded.status, sync_metadata.status)
  `);

  stmt.run(
    source,
    status.lastSync || null,
    status.recordCount || null,
    status.dbVersion || null,
    status.status || "syncing"
  );
}

/**
 * Get sync status for a source
 */
export function getSyncStatus(source: string): VulnDbSyncStatus | null {
  if (!db) throw new Error("Database not initialized");

  const stmt = db.prepare(`
    SELECT source, last_sync as lastSync, record_count as recordCount,
           db_version as dbVersion, status
    FROM sync_metadata WHERE source = ?
  `);

  const row = stmt.get(source) as
    | {
        source: string;
        lastSync: string | null;
        recordCount: number;
        dbVersion: string | null;
        status: string;
      }
    | undefined;

  if (!row) return null;

  // Calculate age in hours
  let ageHours: number | undefined;
  if (row.lastSync) {
    const lastSyncDate = new Date(row.lastSync);
    const now = new Date();
    ageHours = Math.round((now.getTime() - lastSyncDate.getTime()) / (1000 * 60 * 60));
  }

  return {
    source: row.source,
    lastSync: row.lastSync,
    recordCount: row.recordCount,
    dbVersion: row.dbVersion,
    status: row.status as VulnDbSyncStatus["status"],
    ageHours,
  };
}

/**
 * Get all sync statuses
 */
export function getAllSyncStatuses(): VulnDbSyncStatus[] {
  if (!db) throw new Error("Database not initialized");

  const stmt = db.prepare(`
    SELECT source, last_sync as lastSync, record_count as recordCount,
           db_version as dbVersion, status
    FROM sync_metadata
  `);

  const rows = stmt.all() as Array<{
    source: string;
    lastSync: string | null;
    recordCount: number;
    dbVersion: string | null;
    status: string;
  }>;

  return rows.map((row) => {
    let ageHours: number | undefined;
    if (row.lastSync) {
      const lastSyncDate = new Date(row.lastSync);
      const now = new Date();
      ageHours = Math.round((now.getTime() - lastSyncDate.getTime()) / (1000 * 60 * 60));
    }

    return {
      source: row.source,
      lastSync: row.lastSync,
      recordCount: row.recordCount,
      dbVersion: row.dbVersion,
      status: row.status as VulnDbSyncStatus["status"],
      ageHours,
    };
  });
}

// =============================================================================
// ANNOTATION OPERATIONS
// =============================================================================

/**
 * Annotate a vulnerability (mark status, add notes)
 */
export function annotateVulnerability(
  vulnId: string,
  status: VulnAnnotation["status"],
  notes?: string
): { success: boolean; error?: string } {
  if (!db) throw new Error("Database not initialized");

  try {
    // Check if vulnerability exists
    const vulnStmt = db.prepare("SELECT 1 FROM vulnerabilities WHERE id = ?");
    if (!vulnStmt.get(vulnId)) {
      return { success: false, error: "Vulnerability not found" };
    }

    const stmt = db.prepare(`
      INSERT INTO vulnerability_annotations (vuln_id, status, notes, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(vuln_id) DO UPDATE SET
        status = excluded.status,
        notes = excluded.notes,
        updated_at = excluded.updated_at
    `);

    stmt.run(vulnId, status, notes || null, new Date().toISOString());

    return { success: true };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, error: message };
  }
}

/**
 * Get annotation for a vulnerability
 */
export function getVulnAnnotation(vulnId: string): VulnAnnotation | null {
  if (!db) throw new Error("Database not initialized");

  const stmt = db.prepare(`
    SELECT vuln_id as vulnId, status, notes, updated_at as updatedAt
    FROM vulnerability_annotations WHERE vuln_id = ?
  `);

  const row = stmt.get(vulnId) as
    | {
        vulnId: string;
        status: string;
        notes: string | null;
        updatedAt: string;
      }
    | undefined;

  if (!row) return null;

  return {
    vulnId: row.vulnId,
    status: row.status as VulnAnnotation["status"],
    notes: row.notes ?? undefined,
    updatedAt: row.updatedAt,
  };
}

/**
 * Get all annotations with a specific status
 */
export function getAnnotationsByStatus(status: VulnAnnotation["status"]): VulnAnnotation[] {
  if (!db) throw new Error("Database not initialized");

  const stmt = db.prepare(`
    SELECT vuln_id as vulnId, status, notes, updated_at as updatedAt
    FROM vulnerability_annotations WHERE status = ?
  `);

  return stmt.all(status) as VulnAnnotation[];
}

/**
 * Remove an annotation
 */
export function removeAnnotation(vulnId: string): boolean {
  if (!db) throw new Error("Database not initialized");

  const stmt = db.prepare("DELETE FROM vulnerability_annotations WHERE vuln_id = ?");
  const result = stmt.run(vulnId);
  return result.changes > 0;
}

// =============================================================================
// STATISTICS
// =============================================================================

/**
 * Get database statistics
 */
export function getVulnDbStats(): VulnDbStats {
  if (!db) throw new Error("Database not initialized");

  // Total vulnerabilities
  const totalStmt = db.prepare("SELECT COUNT(*) as count FROM vulnerabilities");
  const { count: totalVulnerabilities } = totalStmt.get() as { count: number };

  // By severity
  const severityStmt = db.prepare(`
    SELECT severity, COUNT(*) as count FROM vulnerabilities
    GROUP BY severity
  `);
  const severityRows = severityStmt.all() as Array<{ severity: string; count: number }>;
  const bySeverity: Record<string, number> = {};
  for (const row of severityRows) {
    bySeverity[row.severity || "UNKNOWN"] = row.count;
  }

  // By source
  const sourceStmt = db.prepare(`
    SELECT source, COUNT(*) as count FROM vulnerabilities
    GROUP BY source
  `);
  const sourceRows = sourceStmt.all() as Array<{ source: string; count: number }>;
  const bySource: Record<string, number> = {};
  for (const row of sourceRows) {
    bySource[row.source] = row.count;
  }

  // Last sync times
  const syncStmt = db.prepare("SELECT source, last_sync FROM sync_metadata");
  const syncRows = syncStmt.all() as Array<{ source: string; last_sync: string | null }>;
  const lastSync: Record<string, string> = {};
  for (const row of syncRows) {
    if (row.last_sync) {
      lastSync[row.source] = row.last_sync;
    }
  }

  // Database file size
  let dbSizeBytes = 0;
  if (dbPath && fs.existsSync(dbPath)) {
    const stats = fs.statSync(dbPath);
    dbSizeBytes = stats.size;
  }

  return {
    totalVulnerabilities,
    bySeverity,
    bySource,
    lastSync,
    dbSizeBytes,
  };
}

// =============================================================================
// MAINTENANCE OPERATIONS
// =============================================================================

/**
 * Vacuum the database (optimize storage)
 */
export function vacuumDatabase(): void {
  if (!db) throw new Error("Database not initialized");
  db.exec("VACUUM");
}

/**
 * Clear all vulnerabilities (for full re-sync)
 */
export function clearAllVulnerabilities(): number {
  if (!db) throw new Error("Database not initialized");

  const stmt = db.prepare("DELETE FROM vulnerabilities");
  const result = stmt.run();
  return result.changes;
}

/**
 * Clear vulnerabilities from a specific source
 */
export function clearVulnerabilitiesBySource(source: string): number {
  if (!db) throw new Error("Database not initialized");

  const stmt = db.prepare("DELETE FROM vulnerabilities WHERE source = ?");
  const result = stmt.run(source);
  return result.changes;
}

/**
 * Get database file path
 */
export function getVulnDbPath(): string | null {
  return dbPath;
}
