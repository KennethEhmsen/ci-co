/**
 * Fix Verification Module
 *
 * Verifies that vulnerability fixes have been successfully applied
 * by re-scanning and comparing results.
 */

import type { TrivyScanResult, TrivyVulnerability } from "./types.js";

// =============================================================================
// Types
// =============================================================================

/** Verification result for a single vulnerability */
export interface VulnVerificationResult {
  vulnId: string;
  packageName: string;
  verified: boolean;
  status: "fixed" | "still_present" | "new_issue" | "unknown";
  previousVersion?: string;
  currentVersion?: string;
  fixedVersion?: string;
  message: string;
}

/** Overall verification result */
export interface FixVerificationResult {
  success: boolean;
  totalChecked: number;
  verified: number;
  stillPresent: number;
  newIssues: number;
  unknown: number;
  results: VulnVerificationResult[];
  scanBefore?: TrivyScanResult;
  scanAfter?: TrivyScanResult;
  message: string;
}

/** Rescan options */
export interface RescanOptions {
  /** Target path or image */
  target: string;
  /** Scan type */
  scanType: "path" | "image";
  /** Severity filter */
  severity?: string;
  /** Specific vulnerabilities to check */
  vulnIds?: string[];
}

// =============================================================================
// Vulnerability Extraction
// =============================================================================

/**
 * Extract all vulnerabilities from a scan result
 */
export function extractVulnerabilities(
  scanResult: TrivyScanResult
): Map<string, TrivyVulnerability> {
  const vulns = new Map<string, TrivyVulnerability>();

  for (const result of scanResult.Results || []) {
    for (const vuln of result.Vulnerabilities || []) {
      // Key by vuln ID + package name for uniqueness
      const key = `${vuln.VulnerabilityID}:${vuln.PkgName}`;
      vulns.set(key, vuln);
    }
  }

  return vulns;
}

/**
 * Get vulnerability by ID and optional package name
 */
export function findVulnerability(
  scanResult: TrivyScanResult,
  vulnId: string,
  packageName?: string
): TrivyVulnerability | null {
  for (const result of scanResult.Results || []) {
    for (const vuln of result.Vulnerabilities || []) {
      if (vuln.VulnerabilityID === vulnId) {
        if (!packageName || vuln.PkgName === packageName) {
          return vuln;
        }
      }
    }
  }
  return null;
}

// =============================================================================
// Verification Logic
// =============================================================================

/**
 * Verify a single vulnerability fix
 */
export function verifySingleFix(
  vulnId: string,
  packageName: string,
  beforeScan: TrivyScanResult,
  afterScan: TrivyScanResult
): VulnVerificationResult {
  const beforeVuln = findVulnerability(beforeScan, vulnId, packageName);
  const afterVuln = findVulnerability(afterScan, vulnId, packageName);

  // Vulnerability was present before, now gone = fixed
  if (beforeVuln && !afterVuln) {
    return {
      vulnId,
      packageName,
      verified: true,
      status: "fixed",
      previousVersion: beforeVuln.InstalledVersion,
      fixedVersion: beforeVuln.FixedVersion,
      message: `${vulnId} in ${packageName} has been fixed`,
    };
  }

  // Vulnerability still present
  if (beforeVuln && afterVuln) {
    // Check if version changed
    if (beforeVuln.InstalledVersion !== afterVuln.InstalledVersion) {
      return {
        vulnId,
        packageName,
        verified: false,
        status: "still_present",
        previousVersion: beforeVuln.InstalledVersion,
        currentVersion: afterVuln.InstalledVersion,
        fixedVersion: afterVuln.FixedVersion,
        message: `${vulnId} still present after update (${beforeVuln.InstalledVersion} → ${afterVuln.InstalledVersion})`,
      };
    }
    return {
      vulnId,
      packageName,
      verified: false,
      status: "still_present",
      currentVersion: afterVuln.InstalledVersion,
      fixedVersion: afterVuln.FixedVersion,
      message: `${vulnId} is still present in ${packageName}`,
    };
  }

  // Vulnerability wasn't present before (shouldn't happen in normal flow)
  if (!beforeVuln && afterVuln) {
    return {
      vulnId,
      packageName,
      verified: false,
      status: "new_issue",
      currentVersion: afterVuln.InstalledVersion,
      message: `${vulnId} is a new vulnerability in ${packageName}`,
    };
  }

  // Neither present (edge case)
  return {
    vulnId,
    packageName,
    verified: true,
    status: "unknown",
    message: `${vulnId} was not found in either scan`,
  };
}

/**
 * Verify multiple vulnerability fixes
 */
export function verifyFixes(
  fixes: Array<{ vulnId: string; packageName: string }>,
  beforeScan: TrivyScanResult,
  afterScan: TrivyScanResult
): FixVerificationResult {
  const results: VulnVerificationResult[] = [];
  let verified = 0;
  let stillPresent = 0;
  let newIssues = 0;
  let unknown = 0;

  for (const fix of fixes) {
    const result = verifySingleFix(fix.vulnId, fix.packageName, beforeScan, afterScan);
    results.push(result);

    switch (result.status) {
      case "fixed":
        verified++;
        break;
      case "still_present":
        stillPresent++;
        break;
      case "new_issue":
        newIssues++;
        break;
      case "unknown":
        unknown++;
        break;
    }
  }

  const success = stillPresent === 0 && newIssues === 0;

  let message: string;
  if (success) {
    message = `All ${verified} vulnerabilities have been fixed`;
  } else if (stillPresent > 0) {
    message = `${stillPresent} of ${fixes.length} vulnerabilities are still present`;
  } else {
    message = `Verification completed with ${newIssues} new issues`;
  }

  return {
    success,
    totalChecked: fixes.length,
    verified,
    stillPresent,
    newIssues,
    unknown,
    results,
    scanBefore: beforeScan,
    scanAfter: afterScan,
    message,
  };
}

// =============================================================================
// Scan Comparison
// =============================================================================

/**
 * Compare two scans and find differences
 */
export function compareScanResults(
  beforeScan: TrivyScanResult,
  afterScan: TrivyScanResult
): {
  fixed: TrivyVulnerability[];
  new: TrivyVulnerability[];
  unchanged: TrivyVulnerability[];
} {
  const beforeVulns = extractVulnerabilities(beforeScan);
  const afterVulns = extractVulnerabilities(afterScan);

  const fixed: TrivyVulnerability[] = [];
  const newVulns: TrivyVulnerability[] = [];
  const unchanged: TrivyVulnerability[] = [];

  // Find fixed (in before, not in after)
  for (const [key, vuln] of beforeVulns) {
    if (!afterVulns.has(key)) {
      fixed.push(vuln);
    } else {
      unchanged.push(vuln);
    }
  }

  // Find new (in after, not in before)
  for (const [key, vuln] of afterVulns) {
    if (!beforeVulns.has(key)) {
      newVulns.push(vuln);
    }
  }

  return {
    fixed,
    new: newVulns,
    unchanged,
  };
}

/**
 * Generate verification summary
 */
export function generateVerificationSummary(result: FixVerificationResult): string {
  const lines: string[] = [];

  lines.push("# Fix Verification Summary\n");
  lines.push(`**Status:** ${result.success ? "✅ All fixes verified" : "⚠️ Some issues remain"}\n`);

  lines.push("## Results\n");
  lines.push(`| Metric | Count |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total Checked | ${result.totalChecked} |`);
  lines.push(`| Verified Fixed | ${result.verified} |`);
  lines.push(`| Still Present | ${result.stillPresent} |`);
  lines.push(`| New Issues | ${result.newIssues} |`);
  lines.push("");

  if (result.results.length > 0) {
    lines.push("## Details\n");
    lines.push("| Vulnerability | Package | Status | Message |");
    lines.push("|---------------|---------|--------|---------|");

    for (const r of result.results) {
      const statusIcon =
        r.status === "fixed"
          ? "✅"
          : r.status === "still_present"
            ? "❌"
            : r.status === "new_issue"
              ? "⚠️"
              : "❓";
      lines.push(`| ${r.vulnId} | ${r.packageName} | ${statusIcon} ${r.status} | ${r.message} |`);
    }
  }

  return lines.join("\n");
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Check if a specific CVE is present in scan results
 */
export function isCvePresent(scanResult: TrivyScanResult, cveId: string): boolean {
  for (const result of scanResult.Results || []) {
    for (const vuln of result.Vulnerabilities || []) {
      if (vuln.VulnerabilityID === cveId) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Get all CVE IDs from scan results
 */
export function getAllCveIds(scanResult: TrivyScanResult): string[] {
  const cves = new Set<string>();
  for (const result of scanResult.Results || []) {
    for (const vuln of result.Vulnerabilities || []) {
      cves.add(vuln.VulnerabilityID);
    }
  }
  return Array.from(cves).sort();
}

/**
 * Count vulnerabilities by severity
 */
export function countBySeverity(scanResult: TrivyScanResult): Record<string, number> {
  const counts: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    UNKNOWN: 0,
  };

  for (const result of scanResult.Results || []) {
    for (const vuln of result.Vulnerabilities || []) {
      const severity = vuln.Severity?.toUpperCase() || "UNKNOWN";
      counts[severity] = (counts[severity] || 0) + 1;
    }
  }

  return counts;
}

/**
 * Calculate fix success rate
 */
export function calculateFixRate(result: FixVerificationResult): number {
  if (result.totalChecked === 0) {
    return 100;
  }
  return Math.round((result.verified / result.totalChecked) * 100);
}
