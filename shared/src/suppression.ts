/**
 * Suppression Module
 *
 * Allows users to suppress known false positives or accepted risks from scan results.
 * Supports suppression by CVE ID, package name, or file path patterns with optional
 * expiration dates and audit trail integration.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import * as yaml from "yaml";
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
  if (!constraint.match(/^[<>=]/)) {
    return version === constraint;
  }

  // Parse constraint - use \S+ instead of .+ to avoid backtracking on whitespace
  const match = constraint.match(/^([<>=]+)(\S+)$/);
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
    if (!suppression.pattern.match(/^CVE-\d{4}-\d+\*?$/i) && !suppression.pattern.includes("*")) {
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

  // Filter suppressions based on expiration
  const activeSuppressions = options?.includeExpired ? suppressions : filterExpired(suppressions);

  for (const vuln of vulnerabilities) {
    let wasSuppressed = false;
    let matchedSuppression: Suppression | null = null;

    // Check if severity can be suppressed
    if (!canSuppressSeverity(vuln.Severity, options?.maxSeverityToSuppress)) {
      remaining.push(vuln);
      continue;
    }

    // Try to find a matching suppression
    for (const suppression of activeSuppressions) {
      const matches = matchesSuppression(suppression, {
        id: vuln.VulnerabilityID,
        package: vuln.PkgName,
        version: vuln.InstalledVersion,
        target,
      });

      if (matches) {
        wasSuppressed = true;
        matchedSuppression = suppression;

        const expired = isExpired(suppression);
        if (expired) {
          expiredCount++;
        }

        appliedSuppressions.push({
          suppression,
          vulnerabilityId: vuln.VulnerabilityID,
          package: vuln.PkgName,
          path: target,
          expired,
        });

        // Audit if requested
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

        break;
      }
    }

    if (wasSuppressed && matchedSuppression) {
      suppressed.push({
        id: vuln.VulnerabilityID,
        package: vuln.PkgName,
        version: vuln.InstalledVersion,
        severity: vuln.Severity,
        target,
        suppression: matchedSuppression,
      });
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
 * Generate a suppression report
 */
export function generateSuppressionReport(suppressions: Suppression[]): string {
  const lines: string[] = [];

  lines.push(
    "# Vulnerability Suppression Report",
    `Generated: ${new Date().toISOString()}`,
    `Total Suppressions: ${suppressions.length}`,
    ""
  );

  const active = filterExpired(suppressions);
  const expired = getExpiredSuppressions(suppressions);

  lines.push(`Active: ${active.length}`, `Expired: ${expired.length}`, "");

  // Group by type
  const byType = {
    cve: suppressions.filter((s) => s.type === "cve"),
    package: suppressions.filter((s) => s.type === "package"),
    path: suppressions.filter((s) => s.type === "path"),
  };

  for (const [type, items] of Object.entries(byType)) {
    if (items.length === 0) continue;

    lines.push(`## ${type.toUpperCase()} Suppressions (${items.length})`, "");

    for (const s of items) {
      const expiredTag = isExpired(s) ? " [EXPIRED]" : "";
      const expiresTag = s.expires ? ` (expires: ${s.expires})` : "";
      const itemLines = [`- **${s.pattern}**${expiredTag}${expiresTag}`, `  - Reason: ${s.reason}`];
      if (s.createdBy) itemLines.push(`  - Created by: ${s.createdBy}`);
      if (s.notes) itemLines.push(`  - Notes: ${s.notes}`);
      itemLines.push("");
      lines.push(...itemLines);
    }
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
