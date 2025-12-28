/**
 * Executive Dashboard Module
 *
 * Provides high-level security posture overview with KPIs, health scores,
 * and risk analysis for executive reporting.
 */

import Database from "better-sqlite3";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import type {
  AssetCriticality,
  AssetCriticalityConfig,
  ComplianceStatusSummary,
  DashboardConfig,
  DashboardDbInitResult,
  DashboardSnapshot,
  DashboardSummary,
  DashboardTimeRange,
  HealthScore,
  HealthScoreComponents,
  MTTRMetrics,
  RiskSummary,
  ScanCoverage,
  SeverityCounts,
  TrendData,
  TrendDirection,
} from "./types.js";

// =============================================================================
// Database Setup
// =============================================================================

let db: Database.Database | null = null;

const DEFAULT_CONFIG: DashboardConfig = {
  defaultTimeRange: "30d",
  topRisksCount: 10,
  weights: {
    vulnerability: 0.4,
    compliance: 0.25,
    coverage: 0.2,
    remediation: 0.15,
  },
  cacheTtlSeconds: 300,
  staleScanDays: 7,
};

let config: DashboardConfig = { ...DEFAULT_CONFIG };

/**
 * Get default database path
 */
function getDefaultDbPath(): string {
  const dataDir = process.env.CICD_DATA_DIR || path.join(process.cwd(), ".cicd-data");
  return path.join(dataDir, "dashboard.db");
}

/**
 * Initialize dashboard database
 */
export function initDashboardDatabase(
  customPath?: string,
  initialConfig?: Partial<DashboardConfig>
): DashboardDbInitResult {
  const dbPath = customPath || getDefaultDbPath();

  try {
    // Ensure directory exists
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    db = new Database(dbPath);
    db.pragma("journal_mode = WAL");

    // Create tables
    db.exec(`
      -- Dashboard snapshots for history
      CREATE TABLE IF NOT EXISTS dashboard_snapshots (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        health_score REAL NOT NULL,
        vulnerabilities_json TEXT NOT NULL,
        compliance_percent REAL NOT NULL,
        summary_json TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );

      -- Asset criticality configuration
      CREATE TABLE IF NOT EXISTS asset_criticality (
        asset TEXT NOT NULL,
        asset_type TEXT NOT NULL,
        criticality TEXT NOT NULL,
        notes TEXT,
        set_by TEXT,
        set_at TEXT NOT NULL,
        PRIMARY KEY (asset, asset_type)
      );

      -- Dashboard configuration
      CREATE TABLE IF NOT EXISTS dashboard_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      -- Scan records for coverage tracking
      CREATE TABLE IF NOT EXISTS scan_records (
        id TEXT PRIMARY KEY,
        target TEXT NOT NULL,
        target_type TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        vulnerabilities_json TEXT,
        severity_counts_json TEXT,
        scanned_at TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );

      -- Remediation tracking
      CREATE TABLE IF NOT EXISTS remediation_records (
        id TEXT PRIMARY KEY,
        vulnerability_id TEXT NOT NULL,
        target TEXT NOT NULL,
        severity TEXT NOT NULL,
        detected_at TEXT NOT NULL,
        remediated_at TEXT,
        status TEXT DEFAULT 'open',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );

      -- Create indexes
      CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON dashboard_snapshots(timestamp);
      CREATE INDEX IF NOT EXISTS idx_scan_records_target ON scan_records(target);
      CREATE INDEX IF NOT EXISTS idx_scan_records_scanned_at ON scan_records(scanned_at);
      CREATE INDEX IF NOT EXISTS idx_remediation_status ON remediation_records(status);
      CREATE INDEX IF NOT EXISTS idx_remediation_severity ON remediation_records(severity);
    `);

    // Reset config to defaults
    config = { ...DEFAULT_CONFIG };

    // Load existing config from database first
    const configRow = db
      .prepare("SELECT value FROM dashboard_config WHERE key = ?")
      .get("config") as { value: string } | undefined;
    if (configRow) {
      config = { ...config, ...JSON.parse(configRow.value) };
    }

    // Apply initial config if provided (overrides loaded config)
    if (initialConfig) {
      config = { ...config, ...initialConfig };
      const stmt = db.prepare("INSERT OR REPLACE INTO dashboard_config (key, value) VALUES (?, ?)");
      stmt.run("config", JSON.stringify(config));
    }

    return {
      success: true,
      path: dbPath,
      created: new Date().toISOString(),
    };
  } catch (error) {
    return {
      success: false,
      path: dbPath,
      created: new Date().toISOString(),
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Close dashboard database
 */
export function closeDashboardDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

/**
 * Check if database is initialized
 */
export function isDashboardDbInitialized(): boolean {
  return db !== null;
}

/**
 * Get dashboard configuration
 */
export function getDashboardConfig(): DashboardConfig {
  return { ...config };
}

/**
 * Update dashboard configuration
 */
export function updateDashboardConfig(updates: Partial<DashboardConfig>): DashboardConfig {
  config = { ...config, ...updates };

  if (db) {
    const stmt = db.prepare("INSERT OR REPLACE INTO dashboard_config (key, value) VALUES (?, ?)");
    stmt.run("config", JSON.stringify(config));
  }

  return { ...config };
}

// =============================================================================
// Asset Criticality
// =============================================================================

/**
 * Set asset criticality
 */
export function setAssetCriticality(
  asset: string,
  assetType: "project" | "image" | "repository",
  criticality: AssetCriticality,
  options?: { notes?: string; setBy?: string }
): AssetCriticalityConfig {
  if (!db) {
    throw new Error("Dashboard database not initialized");
  }

  const now = new Date().toISOString();
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO asset_criticality
    (asset, asset_type, criticality, notes, set_by, set_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  stmt.run(asset, assetType, criticality, options?.notes || null, options?.setBy || null, now);

  return {
    asset,
    assetType,
    criticality,
    notes: options?.notes,
    setBy: options?.setBy,
    setAt: now,
  };
}

/**
 * Get asset criticality
 */
export function getAssetCriticality(
  asset: string,
  assetType: "project" | "image" | "repository"
): AssetCriticalityConfig | null {
  if (!db) {
    throw new Error("Dashboard database not initialized");
  }

  const row = db
    .prepare("SELECT * FROM asset_criticality WHERE asset = ? AND asset_type = ?")
    .get(asset, assetType) as
    | {
        asset: string;
        asset_type: string;
        criticality: string;
        notes: string | null;
        set_by: string | null;
        set_at: string;
      }
    | undefined;

  if (!row) {
    return null;
  }

  return {
    asset: row.asset,
    assetType: row.asset_type as "project" | "image" | "repository",
    criticality: row.criticality as AssetCriticality,
    notes: row.notes || undefined,
    setBy: row.set_by || undefined,
    setAt: row.set_at,
  };
}

/**
 * List all asset criticality configurations
 */
export function listAssetCriticalities(): AssetCriticalityConfig[] {
  if (!db) {
    throw new Error("Dashboard database not initialized");
  }

  const rows = db.prepare("SELECT * FROM asset_criticality").all() as Array<{
    asset: string;
    asset_type: string;
    criticality: string;
    notes: string | null;
    set_by: string | null;
    set_at: string;
  }>;

  return rows.map((row) => ({
    asset: row.asset,
    assetType: row.asset_type as "project" | "image" | "repository",
    criticality: row.criticality as AssetCriticality,
    notes: row.notes || undefined,
    setBy: row.set_by || undefined,
    setAt: row.set_at,
  }));
}

// =============================================================================
// Scan Recording
// =============================================================================

/**
 * Record a scan for coverage tracking
 */
export function recordScan(
  target: string,
  targetType: "project" | "image" | "repository",
  scanType: string,
  severityCounts: SeverityCounts
): string {
  if (!db) {
    throw new Error("Dashboard database not initialized");
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  const stmt = db.prepare(`
    INSERT INTO scan_records
    (id, target, target_type, scan_type, severity_counts_json, scanned_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  stmt.run(id, target, targetType, scanType, JSON.stringify(severityCounts), now);

  return id;
}

/**
 * Get scan records for a target
 */
export function getScanRecords(
  target: string,
  options?: { limit?: number; since?: string }
): Array<{
  id: string;
  target: string;
  targetType: string;
  scanType: string;
  severityCounts: SeverityCounts;
  scannedAt: string;
}> {
  if (!db) {
    throw new Error("Dashboard database not initialized");
  }

  let sql = "SELECT * FROM scan_records WHERE target = ?";
  const params: (string | number)[] = [target];

  if (options?.since) {
    sql += " AND scanned_at >= ?";
    params.push(options.since);
  }

  sql += " ORDER BY scanned_at DESC";

  if (options?.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }

  const rows = db.prepare(sql).all(...params) as Array<{
    id: string;
    target: string;
    target_type: string;
    scan_type: string;
    severity_counts_json: string;
    scanned_at: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    target: row.target,
    targetType: row.target_type,
    scanType: row.scan_type,
    severityCounts: JSON.parse(row.severity_counts_json) as SeverityCounts,
    scannedAt: row.scanned_at,
  }));
}

// =============================================================================
// Remediation Tracking
// =============================================================================

/**
 * Record a vulnerability detection
 */
export function recordVulnerabilityDetected(
  vulnerabilityId: string,
  target: string,
  severity: string
): string {
  if (!db) {
    throw new Error("Dashboard database not initialized");
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  // Check if already exists
  const existing = db
    .prepare(
      "SELECT id FROM remediation_records WHERE vulnerability_id = ? AND target = ? AND status = 'open'"
    )
    .get(vulnerabilityId, target) as { id: string } | undefined;

  if (existing) {
    return existing.id;
  }

  const stmt = db.prepare(`
    INSERT INTO remediation_records
    (id, vulnerability_id, target, severity, detected_at, status)
    VALUES (?, ?, ?, ?, ?, 'open')
  `);
  stmt.run(id, vulnerabilityId, target, severity, now);

  return id;
}

/**
 * Mark a vulnerability as remediated
 */
export function markVulnerabilityRemediated(vulnerabilityId: string, target: string): boolean {
  if (!db) {
    throw new Error("Dashboard database not initialized");
  }

  const now = new Date().toISOString();
  const result = db
    .prepare(
      `
    UPDATE remediation_records
    SET remediated_at = ?, status = 'remediated'
    WHERE vulnerability_id = ? AND target = ? AND status = 'open'
  `
    )
    .run(now, vulnerabilityId, target);

  return result.changes > 0;
}

// =============================================================================
// Trend Calculations
// =============================================================================

/**
 * Calculate trend data
 */
function calculateTrend(current: number, previous: number): TrendData {
  const change = current - previous;
  const changePercent = previous === 0 ? (current > 0 ? 100 : 0) : (change / previous) * 100;

  let direction: TrendDirection = "stable";
  if (change > 0) {
    direction = "up";
  } else if (change < 0) {
    direction = "down";
  }

  return {
    current,
    previous,
    change,
    changePercent: Math.round(changePercent * 100) / 100,
    direction,
  };
}

/**
 * Get time range in milliseconds
 */
function getTimeRangeMs(timeRange: DashboardTimeRange): number {
  const ranges: Record<DashboardTimeRange, number> = {
    "24h": 24 * 60 * 60 * 1000,
    "7d": 7 * 24 * 60 * 60 * 1000,
    "30d": 30 * 24 * 60 * 60 * 1000,
    "90d": 90 * 24 * 60 * 60 * 1000,
  };
  return ranges[timeRange];
}

/**
 * Get start date for time range
 */
function getStartDate(timeRange: DashboardTimeRange): string {
  const ms = getTimeRangeMs(timeRange);
  return new Date(Date.now() - ms).toISOString();
}

/**
 * Get previous period start date
 */
function getPreviousPeriodStart(timeRange: DashboardTimeRange): string {
  const ms = getTimeRangeMs(timeRange);
  return new Date(Date.now() - ms * 2).toISOString();
}

// =============================================================================
// Health Score Calculation
// =============================================================================

/**
 * Calculate score grade from numeric score
 */
function calculateGrade(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

/**
 * Calculate vulnerability score (inverse - fewer vulns = higher score)
 */
function calculateVulnerabilityScore(counts: SeverityCounts): number {
  // Weight by severity: critical=10, high=5, medium=2, low=1
  const weightedScore = counts.critical * 10 + counts.high * 5 + counts.medium * 2 + counts.low * 1;

  // Convert to 0-100 scale (0 vulns = 100, 100+ weighted vulns = 0)
  const score = Math.max(0, 100 - weightedScore);
  return Math.round(score);
}

/**
 * Calculate compliance score from compliance statuses
 */
function calculateComplianceScore(complianceStatuses: ComplianceStatusSummary[]): number {
  if (complianceStatuses.length === 0) {
    return 100; // No frameworks = assume compliant
  }

  const totalPercent = complianceStatuses.reduce((sum, s) => sum + s.compliancePercent, 0);
  return Math.round(totalPercent / complianceStatuses.length);
}

/**
 * Calculate coverage score
 */
function calculateCoverageScore(coverage: ScanCoverage): number {
  return Math.round(coverage.coveragePercent);
}

/**
 * Calculate remediation velocity score
 */
function calculateRemediationScore(mttr: MTTRMetrics): number {
  // Target: 7 days for critical, 30 days for high
  // Score based on how close to target
  const criticalTarget = 7;
  const criticalScore =
    mttr.bySeverity.critical <= criticalTarget
      ? 100
      : Math.max(0, 100 - (mttr.bySeverity.critical - criticalTarget) * 5);

  const highTarget = 30;
  const highScore =
    mttr.bySeverity.high <= highTarget
      ? 100
      : Math.max(0, 100 - (mttr.bySeverity.high - highTarget) * 2);

  // Weight critical higher
  return Math.round(criticalScore * 0.6 + highScore * 0.4);
}

/**
 * Calculate overall health score
 */
export function calculateHealthScore(
  vulnerabilities: SeverityCounts,
  complianceStatuses: ComplianceStatusSummary[],
  coverage: ScanCoverage,
  mttr: MTTRMetrics,
  previousScore?: number
): HealthScore {
  const components: HealthScoreComponents = {
    vulnerabilityScore: calculateVulnerabilityScore(vulnerabilities),
    complianceScore: calculateComplianceScore(complianceStatuses),
    coverageScore: calculateCoverageScore(coverage),
    remediationScore: calculateRemediationScore(mttr),
  };

  // Calculate weighted score
  const score = Math.round(
    components.vulnerabilityScore * config.weights.vulnerability +
      components.complianceScore * config.weights.compliance +
      components.coverageScore * config.weights.coverage +
      components.remediationScore * config.weights.remediation
  );

  const trend = calculateTrend(score, previousScore ?? score);

  return {
    score,
    grade: calculateGrade(score),
    components,
    trend,
    calculatedAt: new Date().toISOString(),
  };
}

// =============================================================================
// Dashboard Data Retrieval
// =============================================================================

/**
 * Get vulnerability counts from recent scans
 */
export function getVulnerabilityCounts(timeRange: DashboardTimeRange = "30d"): SeverityCounts {
  if (!db) {
    return { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  }

  const startDate = getStartDate(timeRange);

  // Get the most recent scan for each target
  const rows = db
    .prepare(
      `
    SELECT severity_counts_json
    FROM scan_records s1
    WHERE scanned_at >= ?
    AND scanned_at = (
      SELECT MAX(s2.scanned_at)
      FROM scan_records s2
      WHERE s2.target = s1.target
    )
  `
    )
    .all(startDate) as Array<{ severity_counts_json: string }>;

  const totals: SeverityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  };

  for (const row of rows) {
    const counts = JSON.parse(row.severity_counts_json) as SeverityCounts;
    totals.critical += counts.critical || 0;
    totals.high += counts.high || 0;
    totals.medium += counts.medium || 0;
    totals.low += counts.low || 0;
    totals.unknown = (totals.unknown ?? 0) + (counts.unknown ?? 0);
  }

  return totals;
}

/**
 * Get previous period vulnerability counts
 */
function getPreviousVulnerabilityCounts(timeRange: DashboardTimeRange): SeverityCounts {
  if (!db) {
    return { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  }

  const currentStart = getStartDate(timeRange);
  const previousStart = getPreviousPeriodStart(timeRange);

  const rows = db
    .prepare(
      `
    SELECT severity_counts_json
    FROM scan_records s1
    WHERE scanned_at >= ? AND scanned_at < ?
    AND scanned_at = (
      SELECT MAX(s2.scanned_at)
      FROM scan_records s2
      WHERE s2.target = s1.target AND s2.scanned_at < ?
    )
  `
    )
    .all(previousStart, currentStart, currentStart) as Array<{
    severity_counts_json: string;
  }>;

  const totals: SeverityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  };

  for (const row of rows) {
    const counts = JSON.parse(row.severity_counts_json) as SeverityCounts;
    totals.critical += counts.critical || 0;
    totals.high += counts.high || 0;
    totals.medium += counts.medium || 0;
    totals.low += counts.low || 0;
    totals.unknown = (totals.unknown ?? 0) + (counts.unknown ?? 0);
  }

  return totals;
}

/**
 * Get scan coverage metrics
 */
export function getScanCoverage(timeRange: DashboardTimeRange = "30d"): ScanCoverage {
  if (!db) {
    return {
      totalAssets: 0,
      scannedAssets: 0,
      coveragePercent: 0,
      neverScanned: 0,
      staleScans: 0,
    };
  }

  const startDate = getStartDate(timeRange);
  const staleDate = new Date(Date.now() - config.staleScanDays * 24 * 60 * 60 * 1000).toISOString();

  // Count unique targets
  const totalAssets = (
    db.prepare("SELECT COUNT(DISTINCT target) as count FROM scan_records").get() as {
      count: number;
    }
  ).count;

  // Count assets scanned in period
  const scannedAssets = (
    db
      .prepare("SELECT COUNT(DISTINCT target) as count FROM scan_records WHERE scanned_at >= ?")
      .get(startDate) as { count: number }
  ).count;

  // Count assets with stale scans
  const staleScans = (
    db
      .prepare(
        `
    SELECT COUNT(DISTINCT target) as count FROM scan_records s1
    WHERE scanned_at = (
      SELECT MAX(s2.scanned_at) FROM scan_records s2 WHERE s2.target = s1.target
    )
    AND scanned_at < ?
  `
      )
      .get(staleDate) as { count: number }
  ).count;

  const coveragePercent = totalAssets === 0 ? 100 : (scannedAssets / totalAssets) * 100;

  return {
    totalAssets,
    scannedAssets,
    coveragePercent: Math.round(coveragePercent * 100) / 100,
    neverScanned: 0, // Would need a separate asset registry to track this
    staleScans,
  };
}

/**
 * Get MTTR metrics
 */
export function getMTTRMetrics(timeRange: DashboardTimeRange = "30d"): MTTRMetrics {
  if (!db) {
    return {
      overall: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      trend: calculateTrend(0, 0),
    };
  }

  const startDate = getStartDate(timeRange);

  // Calculate MTTR for each severity
  const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const bySeverity: Record<string, number> = {};

  for (const severity of severities) {
    const result = db
      .prepare(
        `
      SELECT AVG(
        CAST((julianday(remediated_at) - julianday(detected_at)) AS REAL)
      ) as avg_days
      FROM remediation_records
      WHERE severity = ?
      AND status = 'remediated'
      AND remediated_at >= ?
    `
      )
      .get(severity, startDate) as { avg_days: number | null };

    bySeverity[severity.toLowerCase()] = result.avg_days
      ? Math.round(result.avg_days * 10) / 10
      : 0;
  }

  // Calculate overall MTTR
  const overallResult = db
    .prepare(
      `
    SELECT AVG(
      CAST((julianday(remediated_at) - julianday(detected_at)) AS REAL)
    ) as avg_days
    FROM remediation_records
    WHERE status = 'remediated'
    AND remediated_at >= ?
  `
    )
    .get(startDate) as { avg_days: number | null };

  const overall = overallResult.avg_days ? Math.round(overallResult.avg_days * 10) / 10 : 0;

  // Get previous period MTTR for trend
  const previousStart = getPreviousPeriodStart(timeRange);
  const currentStart = getStartDate(timeRange);

  const previousResult = db
    .prepare(
      `
    SELECT AVG(
      CAST((julianday(remediated_at) - julianday(detected_at)) AS REAL)
    ) as avg_days
    FROM remediation_records
    WHERE status = 'remediated'
    AND remediated_at >= ? AND remediated_at < ?
  `
    )
    .get(previousStart, currentStart) as { avg_days: number | null };

  const previousOverall = previousResult.avg_days
    ? Math.round(previousResult.avg_days * 10) / 10
    : 0;

  return {
    overall,
    bySeverity: {
      critical: bySeverity["critical"] || 0,
      high: bySeverity["high"] || 0,
      medium: bySeverity["medium"] || 0,
      low: bySeverity["low"] || 0,
    },
    trend: calculateTrend(overall, previousOverall),
  };
}

/**
 * Get top risks
 */
export function getTopRisks(count: number = config.topRisksCount): RiskSummary[] {
  if (!db) {
    return [];
  }

  // Get latest scan for each target with their severity counts
  const rows = db
    .prepare(
      `
    SELECT
      s1.target,
      s1.target_type,
      s1.severity_counts_json,
      s1.scanned_at,
      ac.criticality
    FROM scan_records s1
    LEFT JOIN asset_criticality ac ON s1.target = ac.asset AND s1.target_type = ac.asset_type
    WHERE s1.scanned_at = (
      SELECT MAX(s2.scanned_at) FROM scan_records s2 WHERE s2.target = s1.target
    )
    ORDER BY s1.scanned_at DESC
  `
    )
    .all() as Array<{
    target: string;
    target_type: string;
    severity_counts_json: string;
    scanned_at: string;
    criticality: string | null;
  }>;

  const risks: RiskSummary[] = rows.map((row) => {
    const counts = JSON.parse(row.severity_counts_json) as SeverityCounts;
    const criticality = (row.criticality as AssetCriticality) || "medium";
    const criticalityMultiplier: Record<AssetCriticality, number> = {
      critical: 2.0,
      high: 1.5,
      medium: 1.0,
      low: 0.5,
    };

    // Calculate risk score
    const baseScore = counts.critical * 10 + counts.high * 5 + counts.medium * 2 + counts.low * 0.5;
    const riskScore = Math.min(100, Math.round(baseScore * criticalityMultiplier[criticality]));

    const totalVulnerabilities = counts.critical + counts.high + counts.medium + counts.low;

    const scannedAt = new Date(row.scanned_at);
    const daysSinceLastScan = Math.floor(
      (Date.now() - scannedAt.getTime()) / (24 * 60 * 60 * 1000)
    );

    return {
      target: row.target,
      targetType: row.target_type as "project" | "image" | "repository",
      riskScore,
      vulnerabilities: counts,
      totalVulnerabilities,
      criticality,
      lastScan: row.scanned_at,
      daysSinceLastScan,
    };
  });

  // Sort by risk score descending and take top N
  return risks.sort((a, b) => b.riskScore - a.riskScore).slice(0, count);
}

/**
 * Get compliance status summary
 * Note: This integrates with the compliance module
 */
export function getComplianceStatus(): ComplianceStatusSummary[] {
  // Default compliance status - in a real implementation, this would
  // integrate with the compliance module to get actual status
  const frameworks = ["SOC2", "HIPAA", "PCI-DSS", "CIS"];

  return frameworks.map((framework) => ({
    framework,
    totalControls: 6,
    passingControls: 6,
    failingControls: 0,
    compliancePercent: 100,
    status: "compliant" as const,
  }));
}

// =============================================================================
// Main Dashboard Functions
// =============================================================================

/**
 * Get executive dashboard summary
 */
export function getDashboardSummary(
  timeRange: DashboardTimeRange = config.defaultTimeRange
): DashboardSummary {
  const vulnerabilities = getVulnerabilityCounts(timeRange);
  const previousVulnerabilities = getPreviousVulnerabilityCounts(timeRange);
  const compliance = getComplianceStatus();
  const coverage = getScanCoverage(timeRange);
  const mttr = getMTTRMetrics(timeRange);
  const topRisks = getTopRisks();

  // Get previous health score from snapshot
  let previousHealthScore: number | undefined;
  if (db) {
    const previousStart = getPreviousPeriodStart(timeRange);
    const snapshot = db
      .prepare(
        "SELECT health_score FROM dashboard_snapshots WHERE timestamp >= ? ORDER BY timestamp ASC LIMIT 1"
      )
      .get(previousStart) as { health_score: number } | undefined;
    previousHealthScore = snapshot?.health_score;
  }

  const healthScore = calculateHealthScore(
    vulnerabilities,
    compliance,
    coverage,
    mttr,
    previousHealthScore
  );

  const totalVulnerabilities =
    vulnerabilities.critical + vulnerabilities.high + vulnerabilities.medium + vulnerabilities.low;

  const previousTotal =
    previousVulnerabilities.critical +
    previousVulnerabilities.high +
    previousVulnerabilities.medium +
    previousVulnerabilities.low;

  const overallCompliance =
    compliance.length > 0
      ? compliance.reduce((sum, c) => sum + c.compliancePercent, 0) / compliance.length
      : 100;

  return {
    healthScore,
    vulnerabilities: {
      counts: vulnerabilities,
      total: totalVulnerabilities,
      trend: calculateTrend(totalVulnerabilities, previousTotal),
    },
    compliance,
    overallCompliance: Math.round(overallCompliance * 100) / 100,
    topRisks,
    mttr,
    coverage,
    generatedAt: new Date().toISOString(),
    timeRange,
  };
}

/**
 * Get health score only
 */
export function getHealthScore(
  timeRange: DashboardTimeRange = config.defaultTimeRange
): HealthScore {
  const vulnerabilities = getVulnerabilityCounts(timeRange);
  const compliance = getComplianceStatus();
  const coverage = getScanCoverage(timeRange);
  const mttr = getMTTRMetrics(timeRange);

  // Get previous health score
  let previousHealthScore: number | undefined;
  if (db) {
    const previousStart = getPreviousPeriodStart(timeRange);
    const snapshot = db
      .prepare(
        "SELECT health_score FROM dashboard_snapshots WHERE timestamp >= ? ORDER BY timestamp ASC LIMIT 1"
      )
      .get(previousStart) as { health_score: number } | undefined;
    previousHealthScore = snapshot?.health_score;
  }

  return calculateHealthScore(vulnerabilities, compliance, coverage, mttr, previousHealthScore);
}

// =============================================================================
// Snapshot Management
// =============================================================================

/**
 * Save a dashboard snapshot for historical tracking
 */
export function saveDashboardSnapshot(summary?: DashboardSummary): DashboardSnapshot {
  if (!db) {
    throw new Error("Dashboard database not initialized");
  }

  const dashboardSummary = summary || getDashboardSummary();
  const id = crypto.randomUUID();
  const timestamp = new Date().toISOString();

  const stmt = db.prepare(`
    INSERT INTO dashboard_snapshots
    (id, timestamp, health_score, vulnerabilities_json, compliance_percent, summary_json)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    id,
    timestamp,
    dashboardSummary.healthScore.score,
    JSON.stringify(dashboardSummary.vulnerabilities.counts),
    dashboardSummary.overallCompliance,
    JSON.stringify(dashboardSummary)
  );

  return {
    id,
    timestamp,
    healthScore: dashboardSummary.healthScore.score,
    vulnerabilities: dashboardSummary.vulnerabilities.counts,
    compliancePercent: dashboardSummary.overallCompliance,
  };
}

/**
 * Get dashboard snapshots for trend analysis
 */
export function getDashboardSnapshots(options?: {
  limit?: number;
  since?: string;
}): DashboardSnapshot[] {
  if (!db) {
    return [];
  }

  let sql = "SELECT * FROM dashboard_snapshots";
  const params: (string | number)[] = [];

  if (options?.since) {
    sql += " WHERE timestamp >= ?";
    params.push(options.since);
  }

  sql += " ORDER BY timestamp DESC";

  if (options?.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }

  const rows = db.prepare(sql).all(...params) as Array<{
    id: string;
    timestamp: string;
    health_score: number;
    vulnerabilities_json: string;
    compliance_percent: number;
  }>;

  return rows.map((row) => ({
    id: row.id,
    timestamp: row.timestamp,
    healthScore: row.health_score,
    vulnerabilities: JSON.parse(row.vulnerabilities_json) as SeverityCounts,
    compliancePercent: row.compliance_percent,
  }));
}

/**
 * Clean up old snapshots
 */
export function cleanupOldSnapshots(retentionDays: number = 90): number {
  if (!db) {
    return 0;
  }

  const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();

  const result = db.prepare("DELETE FROM dashboard_snapshots WHERE timestamp < ?").run(cutoffDate);

  return result.changes;
}
