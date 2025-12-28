/**
 * Suppression Module
 *
 * Allows users to suppress known false positives or accepted risks from scan results.
 * Supports suppression by CVE ID, package name, or file path patterns with optional
 * expiration dates and audit trail integration.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";
import * as yaml from "yaml";
import Database from "better-sqlite3";
import { minimatch } from "minimatch";
import type {
  Suppression,
  SuppressionType,
  SuppressionMatch,
  SuppressedVulnerability,
  SuppressionResult,
  SuppressionFileSchema,
  SuppressionLoadOptions,
  SuppressionApplyOptions,
  TrivyVulnerability,
  TrivyScanResult,
  TrivyResult,
} from "./types.js";
import { auditSecurityEvent } from "./audit.js";

// =============================================================================
// Suppression Database Types
// =============================================================================

export type SuppressionStatus = "active" | "expired" | "deleted";
export type SuppressionAuditAction = "created" | "updated" | "deleted" | "applied" | "expired";

export interface SuppressionAuditEntry {
  id: number;
  suppressionId: string;
  action: SuppressionAuditAction;
  timestamp: string;
  user?: string;
  details?: string;
  vulnerabilityId?: string;
  target?: string;
}

export interface SuppressionListOptions {
  type?: SuppressionType;
  status?: SuppressionStatus;
  pattern?: string;
  createdBy?: string;
  includeExpired?: boolean;
  limit?: number;
  offset?: number;
}

export interface SuppressionDbStats {
  total: number;
  active: number;
  expired: number;
  deleted: number;
  byType: Record<string, number>;
  recentAuditCount: number;
}

// =============================================================================
// Constants
// =============================================================================

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
};

const SUPPRESSION_FILE_NAMES = [
  ".security-suppressions.yaml",
  ".security-suppressions.yml",
  ".security-suppressions.json",
  "security-suppressions.yaml",
  "security-suppressions.yml",
  "security-suppressions.json",
  ".vuln-suppressions.yaml",
  ".vuln-suppressions.yml",
  ".vuln-suppressions.json",
];

// =============================================================================
// Suppression Creation
// =============================================================================

/**
 * Create a new suppression rule
 */
export function createSuppression(
  type: SuppressionType,
  pattern: string,
  reason: string,
  options?: {
    expires?: string;
    versionConstraint?: string;
    createdBy?: string;
    notes?: string;
  }
): Suppression {
  return {
    id: crypto.randomUUID(),
    type,
    pattern,
    reason,
    expires: options?.expires,
    versionConstraint: options?.versionConstraint,
    createdBy: options?.createdBy || "unknown",
    createdAt: new Date().toISOString(),
    notes: options?.notes,
  };
}

/**
 * Create a CVE suppression
 */
export function suppressCve(
  cveId: string,
  reason: string,
  options?: { expires?: string; createdBy?: string; notes?: string }
): Suppression {
  return createSuppression("cve", cveId.toUpperCase(), reason, options);
}

/**
 * Create a package suppression
 */
export function suppressPackage(
  packageName: string,
  reason: string,
  options?: { version?: string; expires?: string; createdBy?: string; notes?: string }
): Suppression {
  return createSuppression("package", packageName, reason, {
    ...options,
    versionConstraint: options?.version,
  });
}

/**
 * Create a path suppression
 */
export function suppressPath(
  pathPattern: string,
  reason: string,
  options?: { expires?: string; createdBy?: string; notes?: string }
): Suppression {
  return createSuppression("path", pathPattern, reason, options);
}

// =============================================================================
// Expiration Checking
// =============================================================================

/**
 * Check if a suppression has expired
 */
export function isExpired(suppression: Suppression): boolean {
  if (!suppression.expires) {
    return false;
  }

  try {
    const expirationDate = new Date(suppression.expires);
    return expirationDate < new Date();
  } catch {
    // Invalid date format, treat as not expired
    return false;
  }
}

/**
 * Get days until expiration (negative if expired)
 */
export function getDaysUntilExpiration(suppression: Suppression): number | null {
  if (!suppression.expires) {
    return null;
  }

  try {
    const expirationDate = new Date(suppression.expires);
    const now = new Date();
    const diffMs = expirationDate.getTime() - now.getTime();
    return Math.ceil(diffMs / (1000 * 60 * 60 * 24));
  } catch {
    return null;
  }
}

/**
 * Filter out expired suppressions
 */
export function filterExpired(suppressions: Suppression[]): Suppression[] {
  return suppressions.filter((s) => !isExpired(s));
}

/**
 * Get all expired suppressions
 */
export function getExpiredSuppressions(suppressions: Suppression[]): Suppression[] {
  return suppressions.filter(isExpired);
}

// =============================================================================
// Pattern Matching
// =============================================================================

/**
 * Check if a CVE ID matches a pattern
 * Supports exact match and wildcard patterns like CVE-2023-*
 */
export function matchesCve(cveId: string, pattern: string): boolean {
  const normalizedCve = cveId.toUpperCase();
  const normalizedPattern = pattern.toUpperCase();

  // Exact match
  if (normalizedCve === normalizedPattern) {
    return true;
  }

  // Wildcard match
  if (normalizedPattern.includes("*")) {
    return minimatch(normalizedCve, normalizedPattern, { nocase: true });
  }

  return false;
}

/**
 * Check if a package name matches a pattern
 * Supports exact match and glob patterns
 */
export function matchesPackage(
  packageName: string,
  pattern: string,
  version?: string,
  versionConstraint?: string
): boolean {
  // Package name match
  const nameMatches =
    packageName.toLowerCase() === pattern.toLowerCase() ||
    minimatch(packageName.toLowerCase(), pattern.toLowerCase());

  if (!nameMatches) {
    return false;
  }

  // Version constraint check (if specified)
  if (versionConstraint && version) {
    return matchesVersion(version, versionConstraint);
  }

  return true;
}

/**
 * Simple version matching
 * Supports: exact, *, >=, <=, >, <
 */
export function matchesVersion(version: string, constraint: string): boolean {
  if (constraint === "*") {
    return true;
  }

  // Exact match
  if (!/^[<>=]/.exec(constraint)) {
    return version === constraint;
  }

  // Parse constraint - use \S+ instead of .+ to avoid backtracking on whitespace
  const match = /^([<>=]+)(\S+)$/.exec(constraint);
  if (!match) {
    return version === constraint;
  }

  const [, operator, constraintVersion] = match;

  // Simple version comparison (works for semver-like versions)
  const comp = version.localeCompare(constraintVersion, undefined, {
    numeric: true,
    sensitivity: "base",
  });

  switch (operator) {
    case ">=":
      return comp >= 0;
    case "<=":
      return comp <= 0;
    case ">":
      return comp > 0;
    case "<":
      return comp < 0;
    case "=":
    case "==":
      return comp === 0;
    default:
      return false;
  }
}

/**
 * Check if a file path matches a pattern
 * Supports glob patterns
 */
export function matchesPath(filePath: string, pattern: string): boolean {
  // Normalize paths
  const normalizedPath = filePath.replaceAll("\\", "/");
  const normalizedPattern = pattern.replaceAll("\\", "/");

  return minimatch(normalizedPath, normalizedPattern, { dot: true });
}

/**
 * Check if a suppression matches a vulnerability
 */
export function matchesSuppression(
  suppression: Suppression,
  vulnerability: {
    id: string;
    package: string;
    version: string;
    target: string;
  }
): boolean {
  switch (suppression.type) {
    case "cve":
      return matchesCve(vulnerability.id, suppression.pattern);

    case "package":
      return matchesPackage(
        vulnerability.package,
        suppression.pattern,
        vulnerability.version,
        suppression.versionConstraint
      );

    case "path":
      return matchesPath(vulnerability.target, suppression.pattern);

    default:
      return false;
  }
}

// =============================================================================
// File Loading
// =============================================================================

/**
 * Find suppression file in directory
 */
export function findSuppressionFile(directory: string): string | null {
  for (const fileName of SUPPRESSION_FILE_NAMES) {
    const filePath = path.join(directory, fileName);
    if (fs.existsSync(filePath)) {
      return filePath;
    }
  }
  return null;
}

/**
 * Parse suppression file content
 */
export function parseSuppressionFile(content: string, filePath: string): SuppressionFileSchema {
  const ext = path.extname(filePath).toLowerCase();

  if (ext === ".json") {
    return JSON.parse(content) as SuppressionFileSchema;
  }

  // YAML
  return yaml.parse(content) as SuppressionFileSchema;
}

/**
 * Validate a suppression
 */
export function validateSuppression(suppression: Suppression): string[] {
  const errors: string[] = [];

  if (!suppression.id) {
    errors.push("Suppression must have an id");
  }

  if (!suppression.type || !["cve", "package", "path"].includes(suppression.type)) {
    errors.push(`Invalid suppression type: ${suppression.type}`);
  }

  if (!suppression.pattern) {
    errors.push("Suppression must have a pattern");
  }

  if (!suppression.reason) {
    errors.push("Suppression must have a reason");
  }

  if (suppression.expires) {
    const date = new Date(suppression.expires);
    if (Number.isNaN(date.getTime())) {
      errors.push(`Invalid expiration date: ${suppression.expires}`);
    }
  }

  // Type-specific validation
  if (suppression.type === "cve" && suppression.pattern) {
    if (!/^CVE-\d{4}-\d+\*?$/i.exec(suppression.pattern) && !suppression.pattern.includes("*")) {
      errors.push(`Invalid CVE pattern: ${suppression.pattern}`);
    }
  }

  return errors;
}

/**
 * Load suppressions from a file
 */
export function loadSuppressions(
  filePath: string,
  options?: SuppressionLoadOptions
): Suppression[] {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Suppression file not found: ${filePath}`);
  }

  const content = fs.readFileSync(filePath, "utf-8");
  const schema = parseSuppressionFile(content, filePath);

  let suppressions = schema.suppressions || [];

  // Add IDs if missing
  suppressions = suppressions.map((s) => ({
    ...s,
    id: s.id || crypto.randomUUID(),
    createdBy: s.createdBy || options?.defaultCreatedBy || "unknown",
    createdAt: s.createdAt || new Date().toISOString(),
  }));

  // Validate if requested
  if (options?.validatePatterns) {
    for (const suppression of suppressions) {
      const errors = validateSuppression(suppression);
      if (errors.length > 0) {
        throw new Error(`Invalid suppression ${suppression.id}: ${errors.join(", ")}`);
      }
    }
  }

  // Skip expired if requested
  if (options?.skipExpired) {
    suppressions = filterExpired(suppressions);
  }

  return suppressions;
}

/**
 * Load suppressions from directory (find file automatically)
 */
export function loadSuppressionsFromDirectory(
  directory: string,
  options?: SuppressionLoadOptions
): Suppression[] {
  const filePath = findSuppressionFile(directory);
  if (!filePath) {
    return [];
  }
  return loadSuppressions(filePath, options);
}

// =============================================================================
// Apply Suppressions
// =============================================================================

/**
 * Check if severity can be suppressed based on max severity option
 */
function canSuppressSeverity(
  severity: string,
  maxSeverity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
): boolean {
  if (!maxSeverity) {
    return true;
  }

  const severityLevel = SEVERITY_ORDER[severity.toUpperCase()] || 0;
  const maxLevel = SEVERITY_ORDER[maxSeverity] || 4;

  return severityLevel <= maxLevel;
}

/**
 * Find a matching suppression for a vulnerability
 */
function findMatchingSuppression(
  vuln: TrivyVulnerability,
  target: string,
  suppressions: Suppression[]
): Suppression | null {
  for (const suppression of suppressions) {
    const matches = matchesSuppression(suppression, {
      id: vuln.VulnerabilityID,
      package: vuln.PkgName,
      version: vuln.InstalledVersion,
      target,
    });
    if (matches) {
      return suppression;
    }
  }
  return null;
}

/**
 * Record a suppression match with optional audit logging
 */
function recordSuppressionMatch(
  vuln: TrivyVulnerability,
  target: string,
  suppression: Suppression,
  options?: SuppressionApplyOptions
): { match: SuppressionMatch; expired: boolean } {
  const expired = isExpired(suppression);

  if (options?.audit) {
    auditSecurityEvent("vulnerability_suppressed", "suppression", {
      target: vuln.VulnerabilityID,
      reason: `Suppressed ${vuln.VulnerabilityID} in ${vuln.PkgName}: ${suppression.reason}`,
      metadata: {
        package: vuln.PkgName,
        suppressionId: suppression.id,
        suppressionType: suppression.type,
      },
    });
  }

  return {
    match: {
      suppression,
      vulnerabilityId: vuln.VulnerabilityID,
      package: vuln.PkgName,
      path: target,
      expired,
    },
    expired,
  };
}

/**
 * Create a suppressed vulnerability record
 */
function createSuppressedVulnerability(
  vuln: TrivyVulnerability,
  target: string,
  suppression: Suppression
): SuppressedVulnerability {
  return {
    id: vuln.VulnerabilityID,
    package: vuln.PkgName,
    version: vuln.InstalledVersion,
    severity: vuln.Severity,
    target,
    suppression,
  };
}

/**
 * Apply suppressions to Trivy vulnerabilities
 */
export function applySuppressionsToVulnerabilities(
  vulnerabilities: TrivyVulnerability[],
  target: string,
  suppressions: Suppression[],
  options?: SuppressionApplyOptions
): SuppressionResult {
  const remaining: TrivyVulnerability[] = [];
  const suppressed: SuppressedVulnerability[] = [];
  const appliedSuppressions: SuppressionMatch[] = [];
  let expiredCount = 0;

  const activeSuppressions = options?.includeExpired ? suppressions : filterExpired(suppressions);

  for (const vuln of vulnerabilities) {
    // Check if severity can be suppressed
    if (!canSuppressSeverity(vuln.Severity, options?.maxSeverityToSuppress)) {
      remaining.push(vuln);
      continue;
    }

    const matchedSuppression = findMatchingSuppression(vuln, target, activeSuppressions);

    if (matchedSuppression) {
      const { match, expired } = recordSuppressionMatch(vuln, target, matchedSuppression, options);
      appliedSuppressions.push(match);
      if (expired) expiredCount++;
      suppressed.push(createSuppressedVulnerability(vuln, target, matchedSuppression));
    } else {
      remaining.push(vuln);
    }
  }

  return {
    remaining,
    suppressed,
    summary: {
      total: vulnerabilities.length,
      suppressed: suppressed.length,
      remaining: remaining.length,
      expiredSuppressions: expiredCount,
    },
    appliedSuppressions,
  };
}

/**
 * Apply suppressions to a Trivy scan result
 * Returns a new scan result with suppressed vulnerabilities removed
 */
export function applySuppressions(
  scanResult: TrivyScanResult,
  suppressions: Suppression[],
  options?: SuppressionApplyOptions
): {
  result: TrivyScanResult;
  suppressionResult: SuppressionResult;
} {
  const allRemaining: TrivyVulnerability[] = [];
  const allSuppressed: SuppressedVulnerability[] = [];
  const allApplied: SuppressionMatch[] = [];
  let totalExpired = 0;
  let totalVulns = 0;

  const newResults: TrivyResult[] = [];

  if (scanResult.Results) {
    for (const result of scanResult.Results) {
      if (!result.Vulnerabilities || result.Vulnerabilities.length === 0) {
        newResults.push(result);
        continue;
      }

      totalVulns += result.Vulnerabilities.length;

      const suppressionResult = applySuppressionsToVulnerabilities(
        result.Vulnerabilities,
        result.Target,
        suppressions,
        options
      );

      allRemaining.push(...suppressionResult.remaining);
      allSuppressed.push(...suppressionResult.suppressed);
      allApplied.push(...suppressionResult.appliedSuppressions);
      totalExpired += suppressionResult.summary.expiredSuppressions;

      // Create new result with remaining vulnerabilities
      newResults.push({
        ...result,
        Vulnerabilities:
          suppressionResult.remaining.length > 0 ? suppressionResult.remaining : undefined,
      });
    }
  }

  return {
    result: {
      ...scanResult,
      Results: newResults,
    },
    suppressionResult: {
      remaining: allRemaining,
      suppressed: allSuppressed,
      summary: {
        total: totalVulns,
        suppressed: allSuppressed.length,
        remaining: allRemaining.length,
        expiredSuppressions: totalExpired,
      },
      appliedSuppressions: allApplied,
    },
  };
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Format a single suppression as markdown lines.
 */
function formatSuppressionItem(s: Suppression): string[] {
  const expiredTag = isExpired(s) ? " [EXPIRED]" : "";
  const expiresTag = s.expires ? ` (expires: ${s.expires})` : "";

  const lines = [`- **${s.pattern}**${expiredTag}${expiresTag}`, `  - Reason: ${s.reason}`];

  if (s.createdBy) {
    lines.push(`  - Created by: ${s.createdBy}`);
  }
  if (s.notes) {
    lines.push(`  - Notes: ${s.notes}`);
  }
  lines.push("");

  return lines;
}

/**
 * Group suppressions by type.
 */
function groupSuppressionsByType(suppressions: Suppression[]): Record<string, Suppression[]> {
  return {
    cve: suppressions.filter((s) => s.type === "cve"),
    package: suppressions.filter((s) => s.type === "package"),
    path: suppressions.filter((s) => s.type === "path"),
  };
}

/**
 * Format a suppression type section.
 */
function formatTypeSection(type: string, items: Suppression[]): string[] {
  if (items.length === 0) return [];

  const lines = [`## ${type.toUpperCase()} Suppressions (${items.length})`, ""];
  for (const s of items) {
    lines.push(...formatSuppressionItem(s));
  }
  return lines;
}

/**
 * Generate a suppression report
 */
export function generateSuppressionReport(suppressions: Suppression[]): string {
  const active = filterExpired(suppressions);
  const expired = getExpiredSuppressions(suppressions);

  const lines = [
    "# Vulnerability Suppression Report",
    `Generated: ${new Date().toISOString()}`,
    `Total Suppressions: ${suppressions.length}`,
    "",
    `Active: ${active.length}`,
    `Expired: ${expired.length}`,
    "",
  ];

  const byType = groupSuppressionsByType(suppressions);
  for (const [type, items] of Object.entries(byType)) {
    lines.push(...formatTypeSection(type, items));
  }

  return lines.join("\n");
}

/**
 * Write suppressions to a file
 */
export function writeSuppressions(
  suppressions: Suppression[],
  filePath: string,
  settings?: SuppressionFileSchema["settings"]
): void {
  const schema: SuppressionFileSchema = {
    version: "1.0",
    suppressions,
    settings,
  };

  const ext = path.extname(filePath).toLowerCase();
  let content: string;

  if (ext === ".json") {
    content = JSON.stringify(schema, null, 2);
  } else {
    content = yaml.stringify(schema);
  }

  fs.writeFileSync(filePath, content, "utf-8");
}

// =============================================================================
// SQLite Database Management
// =============================================================================

let suppressionDb: Database.Database | null = null;
let suppressionDbPath: string | null = null;

/**
 * Get the default suppression database path
 */
export function getDefaultSuppressionDbPath(): string {
  const dataDir = path.join(os.homedir(), ".cicd-security");
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  return path.join(dataDir, "suppressions.sqlite");
}

/**
 * Initialize the suppression database
 */
export function initSuppressionDatabase(customPath?: string): {
  success: boolean;
  path: string;
  created: boolean;
  error?: string;
} {
  try {
    suppressionDbPath = customPath || getDefaultSuppressionDbPath();
    const existed = fs.existsSync(suppressionDbPath);

    suppressionDb = new Database(suppressionDbPath);
    suppressionDb.pragma("journal_mode = WAL");

    createSuppressionSchema();

    return {
      success: true,
      path: suppressionDbPath,
      created: !existed,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      path: customPath || getDefaultSuppressionDbPath(),
      created: false,
      error: message,
    };
  }
}

/**
 * Close the suppression database connection
 */
export function closeSuppressionDatabase(): void {
  if (suppressionDb) {
    suppressionDb.close();
    suppressionDb = null;
    suppressionDbPath = null;
  }
}

/**
 * Get the current database instance
 */
export function getSuppressionDatabase(): Database.Database | null {
  return suppressionDb;
}

/**
 * Check if database is initialized
 */
export function isSuppressionDbInitialized(): boolean {
  return suppressionDb !== null;
}

/**
 * Create the suppression database schema
 */
function createSuppressionSchema(): void {
  if (!suppressionDb) throw new Error("Suppression database not initialized");

  suppressionDb.exec(`
    -- Suppressions table
    CREATE TABLE IF NOT EXISTS suppressions (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL CHECK(type IN ('cve', 'package', 'path')),
      pattern TEXT NOT NULL,
      reason TEXT NOT NULL,
      expires TEXT,
      version_constraint TEXT,
      created_by TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT,
      notes TEXT,
      status TEXT DEFAULT 'active' CHECK(status IN ('active', 'expired', 'deleted'))
    );

    -- Audit log table
    CREATE TABLE IF NOT EXISTS suppression_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      suppression_id TEXT NOT NULL,
      action TEXT NOT NULL CHECK(action IN ('created', 'updated', 'deleted', 'applied', 'expired')),
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
      user TEXT,
      details TEXT,
      vulnerability_id TEXT,
      target TEXT
    );

    -- Indexes
    CREATE INDEX IF NOT EXISTS idx_supp_type ON suppressions(type);
    CREATE INDEX IF NOT EXISTS idx_supp_status ON suppressions(status);
    CREATE INDEX IF NOT EXISTS idx_supp_pattern ON suppressions(pattern);
    CREATE INDEX IF NOT EXISTS idx_supp_created_by ON suppressions(created_by);
    CREATE INDEX IF NOT EXISTS idx_audit_suppression_id ON suppression_audit(suppression_id);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON suppression_audit(action);
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON suppression_audit(timestamp);
  `);
}

// =============================================================================
// Suppression CRUD Operations
// =============================================================================

/**
 * Create a suppression in the database
 */
export function createDbSuppression(
  type: SuppressionType,
  pattern: string,
  reason: string,
  options?: {
    expires?: string;
    versionConstraint?: string;
    createdBy?: string;
    notes?: string;
  }
): { success: boolean; suppression?: Suppression; error?: string } {
  if (!suppressionDb) throw new Error("Suppression database not initialized");

  try {
    const id = crypto.randomUUID();
    const createdAt = new Date().toISOString();

    const stmt = suppressionDb.prepare(`
      INSERT INTO suppressions (id, type, pattern, reason, expires, version_constraint, created_by, created_at, notes, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
    `);

    stmt.run(
      id,
      type,
      pattern,
      reason,
      options?.expires || null,
      options?.versionConstraint || null,
      options?.createdBy || "unknown",
      createdAt,
      options?.notes || null
    );

    // Log audit entry
    logSuppressionAuditInternal(
      id,
      "created",
      options?.createdBy,
      `Created ${type} suppression: ${pattern}`
    );

    const suppression: Suppression = {
      id,
      type,
      pattern,
      reason,
      expires: options?.expires,
      versionConstraint: options?.versionConstraint,
      createdBy: options?.createdBy || "unknown",
      createdAt,
      notes: options?.notes,
    };

    return { success: true, suppression };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, error: message };
  }
}

/**
 * Get a suppression by ID
 */
export function getDbSuppression(id: string): Suppression | null {
  if (!suppressionDb) throw new Error("Suppression database not initialized");

  const stmt = suppressionDb.prepare(`
    SELECT id, type, pattern, reason, expires, version_constraint as versionConstraint,
           created_by as createdBy, created_at as createdAt, notes, status
    FROM suppressions
    WHERE id = ? AND status != 'deleted'
  `);

  const row = stmt.get(id) as
    | {
        id: string;
        type: SuppressionType;
        pattern: string;
        reason: string;
        expires: string | null;
        versionConstraint: string | null;
        createdBy: string | null;
        createdAt: string;
        notes: string | null;
        status: string;
      }
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    type: row.type,
    pattern: row.pattern,
    reason: row.reason,
    expires: row.expires ?? undefined,
    versionConstraint: row.versionConstraint ?? undefined,
    createdBy: row.createdBy ?? undefined,
    createdAt: row.createdAt,
    notes: row.notes ?? undefined,
  };
}

/**
 * List suppressions with filters
 */
export function listDbSuppressions(options?: SuppressionListOptions): {
  suppressions: Suppression[];
  total: number;
} {
  if (!suppressionDb) throw new Error("Suppression database not initialized");

  const conditions: string[] = ["status != 'deleted'"];
  const params: (string | number)[] = [];

  if (options?.type) {
    conditions.push("type = ?");
    params.push(options.type);
  }

  if (options?.status === "active") {
    conditions.push("(expires IS NULL OR expires > datetime('now'))");
  } else if (options?.status === "expired") {
    conditions.push("expires IS NOT NULL AND expires <= datetime('now')");
  }

  if (options?.pattern) {
    conditions.push("pattern LIKE ?");
    params.push(`%${options.pattern}%`);
  }

  if (options?.createdBy) {
    conditions.push("created_by = ?");
    params.push(options.createdBy);
  }

  if (!options?.includeExpired) {
    conditions.push("(expires IS NULL OR expires > datetime('now'))");
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

  // Count total
  const countStmt = suppressionDb.prepare(
    `SELECT COUNT(*) as count FROM suppressions ${whereClause}`
  );
  const { count: total } = countStmt.get(...params) as { count: number };

  // Fetch results
  const limit = options?.limit || 100;
  const offset = options?.offset || 0;

  const selectStmt = suppressionDb.prepare(`
    SELECT id, type, pattern, reason, expires, version_constraint as versionConstraint,
           created_by as createdBy, created_at as createdAt, notes, status
    FROM suppressions
    ${whereClause}
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `);

  const rows = selectStmt.all(...params, limit, offset) as Array<{
    id: string;
    type: SuppressionType;
    pattern: string;
    reason: string;
    expires: string | null;
    versionConstraint: string | null;
    createdBy: string | null;
    createdAt: string;
    notes: string | null;
    status: string;
  }>;

  const suppressions: Suppression[] = rows.map((row) => ({
    id: row.id,
    type: row.type,
    pattern: row.pattern,
    reason: row.reason,
    expires: row.expires ?? undefined,
    versionConstraint: row.versionConstraint ?? undefined,
    createdBy: row.createdBy ?? undefined,
    createdAt: row.createdAt,
    notes: row.notes ?? undefined,
  }));

  return { suppressions, total };
}

/**
 * Update a suppression
 */
export function updateDbSuppression(
  id: string,
  updates: {
    reason?: string;
    expires?: string | null;
    notes?: string;
  },
  updatedBy?: string
): { success: boolean; error?: string } {
  if (!suppressionDb) throw new Error("Suppression database not initialized");

  try {
    const existing = getDbSuppression(id);
    if (!existing) {
      return { success: false, error: "Suppression not found" };
    }

    const setClauses: string[] = ["updated_at = ?"];
    const params: (string | null)[] = [new Date().toISOString()];

    if (updates.reason !== undefined) {
      setClauses.push("reason = ?");
      params.push(updates.reason);
    }

    if (updates.expires !== undefined) {
      setClauses.push("expires = ?");
      params.push(updates.expires);
    }

    if (updates.notes !== undefined) {
      setClauses.push("notes = ?");
      params.push(updates.notes);
    }

    params.push(id);

    const stmt = suppressionDb.prepare(`
      UPDATE suppressions SET ${setClauses.join(", ")} WHERE id = ?
    `);

    stmt.run(...params);

    logSuppressionAuditInternal(
      id,
      "updated",
      updatedBy,
      `Updated suppression: ${JSON.stringify(updates)}`
    );

    return { success: true };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, error: message };
  }
}

/**
 * Delete a suppression (soft delete)
 */
export function deleteDbSuppression(
  id: string,
  deletedBy?: string
): { success: boolean; error?: string } {
  if (!suppressionDb) throw new Error("Suppression database not initialized");

  try {
    const existing = getDbSuppression(id);
    if (!existing) {
      return { success: false, error: "Suppression not found" };
    }

    const stmt = suppressionDb.prepare(`
      UPDATE suppressions SET status = 'deleted', updated_at = ? WHERE id = ?
    `);

    stmt.run(new Date().toISOString(), id);

    logSuppressionAuditInternal(
      id,
      "deleted",
      deletedBy,
      `Deleted suppression: ${existing.pattern}`
    );

    return { success: true };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, error: message };
  }
}

// =============================================================================
// Audit Log Operations
// =============================================================================

/**
 * Internal function to log audit entries
 */
function logSuppressionAuditInternal(
  suppressionId: string,
  action: SuppressionAuditAction,
  user?: string,
  details?: string,
  vulnerabilityId?: string,
  target?: string
): void {
  if (!suppressionDb) return;

  try {
    const stmt = suppressionDb.prepare(`
      INSERT INTO suppression_audit (suppression_id, action, timestamp, user, details, vulnerability_id, target)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      suppressionId,
      action,
      new Date().toISOString(),
      user || null,
      details || null,
      vulnerabilityId || null,
      target || null
    );
  } catch {
    // Silently fail audit logging to not break main operations
  }
}

/**
 * Log a suppression application (when a vulnerability is suppressed)
 */
export function logSuppressionApplication(
  suppressionId: string,
  vulnerabilityId: string,
  target: string,
  user?: string
): void {
  logSuppressionAuditInternal(
    suppressionId,
    "applied",
    user,
    `Applied to ${vulnerabilityId}`,
    vulnerabilityId,
    target
  );
}

/**
 * Get audit log entries
 */
export function getSuppressionAuditLog(options?: {
  suppressionId?: string;
  action?: SuppressionAuditAction;
  user?: string;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}): { entries: SuppressionAuditEntry[]; total: number } {
  if (!suppressionDb) throw new Error("Suppression database not initialized");

  const conditions: string[] = [];
  const params: (string | number)[] = [];

  if (options?.suppressionId) {
    conditions.push("suppression_id = ?");
    params.push(options.suppressionId);
  }

  if (options?.action) {
    conditions.push("action = ?");
    params.push(options.action);
  }

  if (options?.user) {
    conditions.push("user = ?");
    params.push(options.user);
  }

  if (options?.since) {
    conditions.push("timestamp >= ?");
    params.push(options.since);
  }

  if (options?.until) {
    conditions.push("timestamp <= ?");
    params.push(options.until);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

  // Count total
  const countStmt = suppressionDb.prepare(
    `SELECT COUNT(*) as count FROM suppression_audit ${whereClause}`
  );
  const { count: total } = countStmt.get(...params) as { count: number };

  // Fetch results
  const limit = options?.limit || 100;
  const offset = options?.offset || 0;

  const selectStmt = suppressionDb.prepare(`
    SELECT id, suppression_id as suppressionId, action, timestamp, user, details,
           vulnerability_id as vulnerabilityId, target
    FROM suppression_audit
    ${whereClause}
    ORDER BY timestamp DESC
    LIMIT ? OFFSET ?
  `);

  const rows = selectStmt.all(...params, limit, offset) as Array<{
    id: number;
    suppressionId: string;
    action: SuppressionAuditAction;
    timestamp: string;
    user: string | null;
    details: string | null;
    vulnerabilityId: string | null;
    target: string | null;
  }>;

  const entries: SuppressionAuditEntry[] = rows.map((row) => ({
    id: row.id,
    suppressionId: row.suppressionId,
    action: row.action,
    timestamp: row.timestamp,
    user: row.user ?? undefined,
    details: row.details ?? undefined,
    vulnerabilityId: row.vulnerabilityId ?? undefined,
    target: row.target ?? undefined,
  }));

  return { entries, total };
}

/**
 * Get suppression database statistics
 */
export function getSuppressionDbStats(): SuppressionDbStats {
  if (!suppressionDb) throw new Error("Suppression database not initialized");

  // Total by status
  const statusStmt = suppressionDb.prepare(`
    SELECT status, COUNT(*) as count FROM suppressions GROUP BY status
  `);
  const statusRows = statusStmt.all() as Array<{ status: string; count: number }>;

  let total = 0;
  let active = 0;
  let expired = 0;
  let deleted = 0;

  for (const row of statusRows) {
    total += row.count;
    if (row.status === "active") active = row.count;
    if (row.status === "expired") expired = row.count;
    if (row.status === "deleted") deleted = row.count;
  }

  // Count expired by date (status may not be updated)
  const expiredByDateStmt = suppressionDb.prepare(`
    SELECT COUNT(*) as count FROM suppressions
    WHERE status = 'active' AND expires IS NOT NULL AND expires <= datetime('now')
  `);
  const { count: expiredByDate } = expiredByDateStmt.get() as { count: number };
  expired += expiredByDate;
  active -= expiredByDate;

  // By type
  const typeStmt = suppressionDb.prepare(`
    SELECT type, COUNT(*) as count FROM suppressions WHERE status != 'deleted' GROUP BY type
  `);
  const typeRows = typeStmt.all() as Array<{ type: string; count: number }>;
  const byType: Record<string, number> = {};
  for (const row of typeRows) {
    byType[row.type] = row.count;
  }

  // Recent audit count (last 24 hours)
  const auditStmt = suppressionDb.prepare(`
    SELECT COUNT(*) as count FROM suppression_audit
    WHERE timestamp >= datetime('now', '-1 day')
  `);
  const { count: recentAuditCount } = auditStmt.get() as { count: number };

  return {
    total,
    active,
    expired,
    deleted,
    byType,
    recentAuditCount,
  };
}

// =============================================================================
// Apply Database Suppressions
// =============================================================================

/**
 * Apply database suppressions to Trivy scan results
 */
export function applyDbSuppressions(
  scanResult: TrivyScanResult,
  options?: SuppressionApplyOptions & { user?: string }
): {
  result: TrivyScanResult;
  suppressionResult: SuppressionResult;
} {
  if (!suppressionDb) throw new Error("Suppression database not initialized");

  // Get active suppressions from database
  const { suppressions } = listDbSuppressions({
    status: "active",
    includeExpired: options?.includeExpired,
  });

  // Apply suppressions
  const result = applySuppressions(scanResult, suppressions, options);

  // Log applications to audit trail
  if (options?.audit !== false) {
    for (const applied of result.suppressionResult.appliedSuppressions) {
      logSuppressionApplication(
        applied.suppression.id,
        applied.vulnerabilityId,
        applied.path || "",
        options?.user
      );
    }
  }

  return result;
}

/**
 * Import suppressions from file to database
 */
export function importSuppressionsToDb(
  filePath: string,
  options?: SuppressionLoadOptions & { importedBy?: string }
): { imported: number; skipped: number; errors: string[] } {
  if (!suppressionDb) throw new Error("Suppression database not initialized");

  const suppressions = loadSuppressions(filePath, options);
  let imported = 0;
  let skipped = 0;
  const errors: string[] = [];

  for (const s of suppressions) {
    try {
      // Check if already exists by pattern
      const existing = suppressionDb
        .prepare(
          `
        SELECT id FROM suppressions WHERE type = ? AND pattern = ? AND status != 'deleted'
      `
        )
        .get(s.type, s.pattern);

      if (existing) {
        skipped++;
        continue;
      }

      const result = createDbSuppression(s.type, s.pattern, s.reason, {
        expires: s.expires,
        versionConstraint: s.versionConstraint,
        createdBy: options?.importedBy || s.createdBy,
        notes: s.notes,
      });

      if (result.success) {
        imported++;
      } else {
        errors.push(`Failed to import ${s.pattern}: ${result.error}`);
      }
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      errors.push(`Error importing ${s.pattern}: ${msg}`);
    }
  }

  return { imported, skipped, errors };
}

/**
 * Export database suppressions to file
 */
export function exportSuppressionsFromDb(
  filePath: string,
  _options?: { includeDeleted?: boolean }
): { exported: number; error?: string } {
  if (!suppressionDb) throw new Error("Suppression database not initialized");

  try {
    const { suppressions } = listDbSuppressions({
      includeExpired: true,
      limit: 10000,
    });

    writeSuppressions(suppressions, filePath);

    return { exported: suppressions.length };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { exported: 0, error: message };
  }
}

/**
 * Mark expired suppressions in database
 */
export function markExpiredSuppressions(): number {
  if (!suppressionDb) throw new Error("Suppression database not initialized");

  const stmt = suppressionDb.prepare(`
    UPDATE suppressions
    SET status = 'expired', updated_at = ?
    WHERE status = 'active' AND expires IS NOT NULL AND expires <= datetime('now')
  `);

  const result = stmt.run(new Date().toISOString());
  return result.changes;
}

/**
 * Get suppression database path
 */
export function getSuppressionDbPath(): string | null {
  return suppressionDbPath;
}
