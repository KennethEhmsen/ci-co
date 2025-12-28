/**
 * Scan Diff Module
 *
 * Compares scan results between runs to identify new, fixed, and unchanged
 * vulnerabilities. Supports scan history storage for tracking changes over time.
 */

import * as crypto from "node:crypto";
import type {
  TrivyScanResult,
  TrivyVulnerability,
  DTrackFinding,
  SonarIssue,
  FingerprintedVulnerability,
  ScanDiffResult,
  ScanDiffSummary,
  StoredScanRecord,
  ScanCompareOptions,
  ScanHistoryOptions,
} from "./types.js";

// =============================================================================
// Constants
// =============================================================================

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
  INFO: 0,
};

const DEFAULT_MAX_RECORDS = 10;

// =============================================================================
// Fingerprinting
// =============================================================================

/**
 * Create a unique fingerprint for a vulnerability
 * Uses SHA-256 hash of key identifying fields
 */
export function createFingerprint(
  id: string,
  pkg: string,
  version: string,
  target: string,
  source: "trivy" | "sonarqube" | "dtrack"
): string {
  const data = `${source}:${id}:${pkg}:${version}:${target}`;
  return crypto.createHash("sha256").update(data).digest("hex").substring(0, 16);
}

/**
 * Convert Trivy vulnerability to fingerprinted vulnerability
 */
export function fingerprintTrivyVulnerability(
  vuln: TrivyVulnerability,
  target: string
): FingerprintedVulnerability {
  const fingerprint = createFingerprint(
    vuln.VulnerabilityID,
    vuln.PkgName,
    vuln.InstalledVersion,
    target,
    "trivy"
  );

  return {
    fingerprint,
    id: vuln.VulnerabilityID,
    package: vuln.PkgName,
    version: vuln.InstalledVersion,
    severity: vuln.Severity,
    title: vuln.Title,
    fixedVersion: vuln.FixedVersion,
    target,
    source: "trivy",
  };
}

/**
 * Convert Dependency-Track finding to fingerprinted vulnerability
 */
export function fingerprintDtrackFinding(finding: DTrackFinding): FingerprintedVulnerability {
  const vuln = finding.vulnerability;
  const comp = finding.component;
  const target = `${comp.name}:${comp.version}`;

  const fingerprint = createFingerprint(vuln.vulnId, comp.name, comp.version, target, "dtrack");

  return {
    fingerprint,
    id: vuln.vulnId,
    package: comp.name,
    version: comp.version,
    severity: vuln.severity,
    title: vuln.title,
    target,
    source: "dtrack",
  };
}

/**
 * Convert SonarQube issue to fingerprinted vulnerability
 */
export function fingerprintSonarIssue(issue: SonarIssue): FingerprintedVulnerability {
  const target = issue.component || "unknown";

  const fingerprint = createFingerprint(
    issue.key,
    issue.rule,
    "1.0", // SonarQube issues don't have versions
    target,
    "sonarqube"
  );

  // Map SonarQube severity to standard levels
  const severityMap: Record<string, string> = {
    BLOCKER: "CRITICAL",
    CRITICAL: "HIGH",
    MAJOR: "MEDIUM",
    MINOR: "LOW",
    INFO: "LOW",
  };

  return {
    fingerprint,
    id: issue.key,
    package: issue.rule,
    version: "1.0",
    severity: severityMap[issue.severity] || issue.severity,
    title: issue.message,
    target,
    source: "sonarqube",
  };
}

/**
 * Extract all fingerprinted vulnerabilities from a Trivy scan result
 */
export function extractTrivyVulnerabilities(
  scanResult: TrivyScanResult
): FingerprintedVulnerability[] {
  const vulnerabilities: FingerprintedVulnerability[] = [];

  if (!scanResult.Results) {
    return vulnerabilities;
  }

  for (const result of scanResult.Results) {
    if (!result.Vulnerabilities) continue;

    for (const vuln of result.Vulnerabilities) {
      vulnerabilities.push(fingerprintTrivyVulnerability(vuln, result.Target));
    }
  }

  return vulnerabilities;
}

/**
 * Extract fingerprinted vulnerabilities from Dependency-Track findings
 */
export function extractDtrackVulnerabilities(
  findings: DTrackFinding[]
): FingerprintedVulnerability[] {
  return findings.map(fingerprintDtrackFinding);
}

/**
 * Extract fingerprinted vulnerabilities from SonarQube issues
 */
export function extractSonarVulnerabilities(issues: SonarIssue[]): FingerprintedVulnerability[] {
  // Only include vulnerability and security hotspot types
  return issues
    .filter((issue) => issue.type === "VULNERABILITY" || issue.type === "SECURITY_HOTSPOT")
    .map(fingerprintSonarIssue);
}

// =============================================================================
// Comparison
// =============================================================================

/**
 * Check if a vulnerability meets the minimum severity threshold
 */
function meetsSeverityThreshold(
  severity: string,
  minSeverity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
): boolean {
  if (!minSeverity) return true;

  const vulnLevel = SEVERITY_ORDER[severity.toUpperCase()] || 0;
  const minLevel = SEVERITY_ORDER[minSeverity] || 0;

  return vulnLevel >= minLevel;
}

/**
 * Create empty severity breakdown
 */
function createEmptySeverityBreakdown(): ScanDiffSummary["bySeverity"] {
  return {
    critical: { new: 0, fixed: 0, unchanged: 0 },
    high: { new: 0, fixed: 0, unchanged: 0 },
    medium: { new: 0, fixed: 0, unchanged: 0 },
    low: { new: 0, fixed: 0, unchanged: 0 },
  };
}

/**
 * Update severity breakdown for a vulnerability
 */
function updateSeverityBreakdown(
  breakdown: ScanDiffSummary["bySeverity"],
  severity: string,
  status: "new" | "fixed" | "unchanged"
): void {
  const normalizedSeverity = severity.toLowerCase();

  if (normalizedSeverity === "critical") {
    breakdown.critical[status]++;
  } else if (normalizedSeverity === "high") {
    breakdown.high[status]++;
  } else if (normalizedSeverity === "medium") {
    breakdown.medium[status]++;
  } else {
    breakdown.low[status]++;
  }
}

/**
 * Compare two sets of fingerprinted vulnerabilities
 *
 * @param current - Current scan vulnerabilities
 * @param baseline - Baseline scan vulnerabilities
 * @param options - Comparison options
 * @returns Categorized vulnerabilities (new, fixed, unchanged)
 */
export function compareVulnerabilities(
  current: FingerprintedVulnerability[],
  baseline: FingerprintedVulnerability[],
  options?: ScanCompareOptions
): {
  new: FingerprintedVulnerability[];
  fixed: FingerprintedVulnerability[];
  unchanged: FingerprintedVulnerability[];
} {
  const currentMap = new Map(current.map((v) => [v.fingerprint, v]));
  const baselineMap = new Map(baseline.map((v) => [v.fingerprint, v]));

  const newVulns: FingerprintedVulnerability[] = [];
  const fixedVulns: FingerprintedVulnerability[] = [];
  const unchangedVulns: FingerprintedVulnerability[] = [];

  // Find new and unchanged vulnerabilities
  for (const [fingerprint, vuln] of currentMap) {
    if (!meetsSeverityThreshold(vuln.severity, options?.minSeverity)) {
      continue;
    }

    if (baselineMap.has(fingerprint)) {
      if (options?.includeUnchanged !== false) {
        unchangedVulns.push(vuln);
      }
    } else {
      newVulns.push(vuln);
    }
  }

  // Find fixed vulnerabilities
  for (const [fingerprint, vuln] of baselineMap) {
    if (!meetsSeverityThreshold(vuln.severity, options?.minSeverity)) {
      continue;
    }

    if (!currentMap.has(fingerprint)) {
      fixedVulns.push(vuln);
    }
  }

  return {
    new: newVulns,
    fixed: fixedVulns,
    unchanged: unchangedVulns,
  };
}

/**
 * Compare two scan results and generate a diff report
 *
 * @param currentVulns - Vulnerabilities from current scan
 * @param baselineVulns - Vulnerabilities from baseline scan
 * @param currentMeta - Metadata about current scan
 * @param baselineMeta - Metadata about baseline scan
 * @param options - Comparison options
 * @returns Full diff result with summary and categorized vulnerabilities
 */
export function compareScanResults(
  currentVulns: FingerprintedVulnerability[],
  baselineVulns: FingerprintedVulnerability[],
  currentMeta: { target: string; scannedAt: string; identifier?: string },
  baselineMeta: { target: string; scannedAt: string; identifier?: string },
  options?: ScanCompareOptions
): ScanDiffResult {
  const comparison = compareVulnerabilities(currentVulns, baselineVulns, options);

  // Build severity breakdown
  const bySeverity = createEmptySeverityBreakdown();

  for (const vuln of comparison.new) {
    updateSeverityBreakdown(bySeverity, vuln.severity, "new");
  }
  for (const vuln of comparison.fixed) {
    updateSeverityBreakdown(bySeverity, vuln.severity, "fixed");
  }
  for (const vuln of comparison.unchanged) {
    updateSeverityBreakdown(bySeverity, vuln.severity, "unchanged");
  }

  const summary: ScanDiffSummary = {
    currentTotal: currentVulns.length,
    baselineTotal: baselineVulns.length,
    new: comparison.new.length,
    fixed: comparison.fixed.length,
    unchanged: comparison.unchanged.length,
    bySeverity,
  };

  return {
    timestamp: new Date().toISOString(),
    current: currentMeta,
    baseline: baselineMeta,
    summary,
    newVulnerabilities: comparison.new,
    fixedVulnerabilities: comparison.fixed,
    unchangedVulnerabilities: comparison.unchanged,
  };
}

/**
 * Compare two Trivy scan results directly
 */
export function compareTrivyScans(
  current: TrivyScanResult,
  baseline: TrivyScanResult,
  options?: ScanCompareOptions
): ScanDiffResult {
  const currentVulns = extractTrivyVulnerabilities(current);
  const baselineVulns = extractTrivyVulnerabilities(baseline);

  const currentMeta = {
    target: current.ArtifactName || "unknown",
    scannedAt: new Date().toISOString(),
  };

  const baselineMeta = {
    target: baseline.ArtifactName || "unknown",
    scannedAt: new Date().toISOString(),
  };

  return compareScanResults(currentVulns, baselineVulns, currentMeta, baselineMeta, options);
}

// =============================================================================
// Scan History Storage
// =============================================================================

/**
 * In-memory scan history store
 */
class MemoryScanHistory {
  private readonly records: Map<string, StoredScanRecord[]> = new Map();
  private readonly maxRecords: number;

  constructor(maxRecords: number = DEFAULT_MAX_RECORDS) {
    this.maxRecords = maxRecords;
  }

  /**
   * Store a scan record
   */
  store(record: StoredScanRecord): void {
    const key = this.normalizeTarget(record.target);
    const existing = this.records.get(key) || [];

    existing.unshift(record);

    // Trim to max records
    if (existing.length > this.maxRecords) {
      existing.length = this.maxRecords;
    }

    this.records.set(key, existing);
  }

  /**
   * Get scan history for a target
   */
  getHistory(target: string, limit?: number): StoredScanRecord[] {
    const key = this.normalizeTarget(target);
    const records = this.records.get(key) || [];

    if (limit && limit > 0) {
      return records.slice(0, limit);
    }

    return [...records];
  }

  /**
   * Get the latest scan for a target
   */
  getLatest(target: string): StoredScanRecord | undefined {
    const history = this.getHistory(target, 1);
    return history[0];
  }

  /**
   * Get a specific scan by ID
   */
  getById(id: string): StoredScanRecord | undefined {
    for (const records of this.records.values()) {
      const found = records.find((r) => r.id === id);
      if (found) return found;
    }
    return undefined;
  }

  /**
   * Clear all history
   */
  clear(): void {
    this.records.clear();
  }

  /**
   * Clear history for a specific target
   */
  clearTarget(target: string): void {
    const key = this.normalizeTarget(target);
    this.records.delete(key);
  }

  /**
   * Get all targets with stored history
   */
  getTargets(): string[] {
    return Array.from(this.records.keys());
  }

  /**
   * Export all records (for persistence)
   */
  export(): Record<string, StoredScanRecord[]> {
    const result: Record<string, StoredScanRecord[]> = {};
    for (const [key, records] of this.records) {
      result[key] = records;
    }
    return result;
  }

  /**
   * Import records (from persistence)
   */
  import(data: Record<string, StoredScanRecord[]>): void {
    this.records.clear();
    for (const [key, records] of Object.entries(data)) {
      this.records.set(key, records);
    }
  }

  private normalizeTarget(target: string): string {
    // Normalize target names for consistent lookups
    return target.toLowerCase().trim();
  }
}

// Global scan history instance
let scanHistory: MemoryScanHistory | null = null;

/**
 * Initialize or get the scan history store
 */
export function getScanHistory(options?: ScanHistoryOptions): MemoryScanHistory {
  scanHistory ??= new MemoryScanHistory(options?.maxRecordsPerTarget ?? DEFAULT_MAX_RECORDS);
  return scanHistory;
}

/**
 * Reset the scan history store (mainly for testing)
 */
export function resetScanHistory(): void {
  scanHistory = null;
}

/**
 * Create a stored scan record from Trivy results
 */
export function createScanRecord(
  target: string,
  vulnerabilities: FingerprintedVulnerability[],
  identifier?: string
): StoredScanRecord {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, total: vulnerabilities.length };

  for (const vuln of vulnerabilities) {
    const severity = vuln.severity.toLowerCase();
    if (severity === "critical") summary.critical++;
    else if (severity === "high") summary.high++;
    else if (severity === "medium") summary.medium++;
    else summary.low++;
  }

  return {
    id: crypto.randomUUID(),
    target,
    scannedAt: new Date().toISOString(),
    identifier,
    vulnerabilities,
    summary,
  };
}

/**
 * Store a Trivy scan result in history
 */
export function storeTrivyScan(scanResult: TrivyScanResult, identifier?: string): StoredScanRecord {
  const target = scanResult.ArtifactName || "unknown";
  const vulnerabilities = extractTrivyVulnerabilities(scanResult);
  const record = createScanRecord(target, vulnerabilities, identifier);

  getScanHistory().store(record);
  return record;
}

/**
 * Compare current scan with the previous scan for the same target
 */
export function compareWithPrevious(
  current: TrivyScanResult,
  identifier?: string,
  options?: ScanCompareOptions
): ScanDiffResult | null {
  const target = current.ArtifactName || "unknown";
  const history = getScanHistory();

  // Get the previous scan
  const previous = history.getLatest(target);
  if (!previous) {
    return null;
  }

  const currentVulns = extractTrivyVulnerabilities(current);

  return compareScanResults(
    currentVulns,
    previous.vulnerabilities,
    { target, scannedAt: new Date().toISOString(), identifier },
    { target: previous.target, scannedAt: previous.scannedAt, identifier: previous.identifier },
    options
  );
}

/**
 * Store current scan and compare with previous
 */
export function storeAndCompare(
  current: TrivyScanResult,
  identifier?: string,
  options?: ScanCompareOptions
): { record: StoredScanRecord; diff: ScanDiffResult | null } {
  const diff = compareWithPrevious(current, identifier, options);
  const record = storeTrivyScan(current, identifier);

  return { record, diff };
}
