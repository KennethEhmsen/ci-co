/**
 * Security Metrics & KPIs Module (v1.28.0)
 *
 * Provides security metrics tracking including:
 * - MTTR (Mean Time To Remediate) tracking
 * - Vulnerability trend analysis
 * - Baseline comparisons
 * - Security snapshots for historical analysis
 */

import Database from "better-sqlite3";
import { randomUUID } from "crypto";

// =============================================================================
// Types
// =============================================================================

export type MetricsSeverity = "critical" | "high" | "medium" | "low";
export type MetricsTrendDirection = "improving" | "stable" | "declining";

export interface SecuritySnapshot {
  id: string;
  target: string;
  targetType: "image" | "path" | "sonar_project" | "dtrack_project";
  snapshotDate: string;
  metrics: SnapshotMetrics;
  createdAt: string;
}

export interface SnapshotMetrics {
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  fixedSinceLastSnapshot?: number;
  newSinceLastSnapshot?: number;
}

export interface VulnerabilityLifecycle {
  id: string;
  vulnId: string;
  target: string;
  severity: MetricsSeverity;
  discoveredAt: string;
  resolvedAt: string | null;
  mttrHours: number | null;
}

export interface MetricsBaseline {
  id: string;
  name: string;
  target: string;
  metrics: SnapshotMetrics;
  createdAt: string;
  createdBy?: string;
}

export interface MTTRStats {
  severity: MetricsSeverity;
  count: number;
  averageHours: number;
  medianHours: number;
  minHours: number;
  maxHours: number;
}

export interface TrendAnalysis {
  target: string;
  period: string;
  startDate: string;
  endDate: string;
  direction: MetricsTrendDirection;
  snapshots: SecuritySnapshot[];
  summary: {
    startTotal: number;
    endTotal: number;
    changePercent: number;
    criticalTrend: MetricsTrendDirection;
    highTrend: MetricsTrendDirection;
  };
}

export interface BaselineComparison {
  baseline: MetricsBaseline;
  current: SnapshotMetrics;
  delta: {
    totalVulnerabilities: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
  percentChange: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  status: "better" | "same" | "worse";
}

export interface MetricsDbInitResult {
  success: boolean;
  path: string;
  created: boolean;
}

export interface RecordMetricsSnapshotOptions {
  target: string;
  targetType: "image" | "path" | "sonar_project" | "dtrack_project";
  metrics: SnapshotMetrics;
}

export interface GetMTTROptions {
  target?: string;
  severity?: MetricsSeverity;
  startDate?: string;
  endDate?: string;
}

export interface GetTrendsOptions {
  target: string;
  period: "7d" | "30d" | "90d" | "180d" | "365d";
  endDate?: string;
}

export interface SetBaselineOptions {
  name: string;
  target: string;
  metrics: SnapshotMetrics;
  createdBy?: string;
}

export interface MetricsAuditEntry {
  id: string;
  eventType: string;
  targetId: string;
  actor?: string;
  details: Record<string, unknown>;
  timestamp: string;
}

// =============================================================================
// Database Management
// =============================================================================

let db: Database.Database | null = null;
let dbPath: string = ":memory:";

function runSchema(database: Database.Database, sql: string): void {
  database.exec(sql);
}

export function initMetricsDatabase(path?: string): MetricsDbInitResult {
  if (db) {
    return { success: true, path: dbPath, created: false };
  }

  dbPath = path || ":memory:";
  db = new Database(dbPath);

  const schema = `
    CREATE TABLE IF NOT EXISTS security_snapshots (
      id TEXT PRIMARY KEY,
      target TEXT NOT NULL,
      target_type TEXT NOT NULL,
      snapshot_date TEXT NOT NULL,
      metrics_json TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_snapshots_target_date
      ON security_snapshots(target, snapshot_date);

    CREATE TABLE IF NOT EXISTS vulnerability_lifecycle (
      id TEXT PRIMARY KEY,
      vuln_id TEXT NOT NULL,
      target TEXT NOT NULL,
      severity TEXT NOT NULL,
      discovered_at TEXT NOT NULL,
      resolved_at TEXT,
      mttr_hours INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_lifecycle_target_severity
      ON vulnerability_lifecycle(target, severity);
    CREATE INDEX IF NOT EXISTS idx_lifecycle_resolved
      ON vulnerability_lifecycle(resolved_at);

    CREATE TABLE IF NOT EXISTS security_baselines (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      target TEXT NOT NULL,
      metrics_json TEXT NOT NULL,
      created_by TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(name, target)
    );

    CREATE TABLE IF NOT EXISTS metrics_audit (
      id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      target_id TEXT,
      actor TEXT,
      details_json TEXT,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_metrics_audit_timestamp
      ON metrics_audit(timestamp);
  `;

  runSchema(db, schema);

  return { success: true, path: dbPath, created: true };
}

export function closeMetricsDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

export function getMetricsDatabase(): Database.Database | null {
  return db;
}

// =============================================================================
// Audit Logging
// =============================================================================

function logAudit(
  eventType: string,
  targetId: string,
  actor?: string,
  details?: Record<string, unknown>
): void {
  if (!db) return;

  const stmt = db.prepare(`
    INSERT INTO metrics_audit (id, event_type, target_id, actor, details_json, timestamp)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    randomUUID(),
    eventType,
    targetId,
    actor || null,
    details ? JSON.stringify(details) : null,
    new Date().toISOString()
  );
}

export function getMetricsAuditLog(limit: number = 100): MetricsAuditEntry[] {
  if (!db) return [];

  const stmt = db.prepare(`
    SELECT id, event_type, target_id, actor, details_json, timestamp
    FROM metrics_audit
    ORDER BY timestamp DESC
    LIMIT ?
  `);

  const rows = stmt.all(limit) as Array<{
    id: string;
    event_type: string;
    target_id: string;
    actor: string | null;
    details_json: string | null;
    timestamp: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    eventType: row.event_type,
    targetId: row.target_id,
    actor: row.actor || undefined,
    details: row.details_json ? JSON.parse(row.details_json) : {},
    timestamp: row.timestamp,
  }));
}

// =============================================================================
// Snapshot Operations
// =============================================================================

export function recordSnapshot(options: RecordMetricsSnapshotOptions): SecuritySnapshot {
  if (!db) {
    throw new Error("Database not initialized. Call initMetricsDatabase first.");
  }

  const id = randomUUID();
  const now = new Date().toISOString();
  const snapshotDate = now.split("T")[0];

  const stmt = db.prepare(`
    INSERT INTO security_snapshots (id, target, target_type, snapshot_date, metrics_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    id,
    options.target,
    options.targetType,
    snapshotDate,
    JSON.stringify(options.metrics),
    now
  );

  logAudit("snapshot_recorded", id, undefined, {
    target: options.target,
    targetType: options.targetType,
    metrics: options.metrics,
  });

  return {
    id,
    target: options.target,
    targetType: options.targetType,
    snapshotDate,
    metrics: options.metrics,
    createdAt: now,
  };
}

export function getSnapshot(id: string): SecuritySnapshot | null {
  if (!db) return null;

  const stmt = db.prepare(`
    SELECT id, target, target_type, snapshot_date, metrics_json, created_at
    FROM security_snapshots
    WHERE id = ?
  `);

  const row = stmt.get(id) as
    | {
        id: string;
        target: string;
        target_type: string;
        snapshot_date: string;
        metrics_json: string;
        created_at: string;
      }
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    target: row.target,
    targetType: row.target_type as SecuritySnapshot["targetType"],
    snapshotDate: row.snapshot_date,
    metrics: JSON.parse(row.metrics_json),
    createdAt: row.created_at,
  };
}

export function getSnapshotsForTarget(target: string, limit: number = 100): SecuritySnapshot[] {
  if (!db) return [];

  const stmt = db.prepare(`
    SELECT id, target, target_type, snapshot_date, metrics_json, created_at
    FROM security_snapshots
    WHERE target = ?
    ORDER BY snapshot_date DESC
    LIMIT ?
  `);

  const rows = stmt.all(target, limit) as Array<{
    id: string;
    target: string;
    target_type: string;
    snapshot_date: string;
    metrics_json: string;
    created_at: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    target: row.target,
    targetType: row.target_type as SecuritySnapshot["targetType"],
    snapshotDate: row.snapshot_date,
    metrics: JSON.parse(row.metrics_json),
    createdAt: row.created_at,
  }));
}

export function getLatestSnapshot(target: string): SecuritySnapshot | null {
  if (!db) return null;

  const stmt = db.prepare(`
    SELECT id, target, target_type, snapshot_date, metrics_json, created_at
    FROM security_snapshots
    WHERE target = ?
    ORDER BY snapshot_date DESC
    LIMIT 1
  `);

  const row = stmt.get(target) as
    | {
        id: string;
        target: string;
        target_type: string;
        snapshot_date: string;
        metrics_json: string;
        created_at: string;
      }
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    target: row.target,
    targetType: row.target_type as SecuritySnapshot["targetType"],
    snapshotDate: row.snapshot_date,
    metrics: JSON.parse(row.metrics_json),
    createdAt: row.created_at,
  };
}

// =============================================================================
// Vulnerability Lifecycle (MTTR)
// =============================================================================

export function recordVulnerabilityDiscovery(
  vulnId: string,
  target: string,
  severity: MetricsSeverity
): VulnerabilityLifecycle {
  if (!db) {
    throw new Error("Database not initialized. Call initMetricsDatabase first.");
  }

  const id = randomUUID();
  const now = new Date().toISOString();

  const stmt = db.prepare(`
    INSERT INTO vulnerability_lifecycle (id, vuln_id, target, severity, discovered_at)
    VALUES (?, ?, ?, ?, ?)
  `);

  stmt.run(id, vulnId, target, severity, now);

  logAudit("vuln_discovered", id, undefined, { vulnId, target, severity });

  return {
    id,
    vulnId,
    target,
    severity,
    discoveredAt: now,
    resolvedAt: null,
    mttrHours: null,
  };
}

export function recordVulnerabilityResolution(
  vulnId: string,
  target: string
): VulnerabilityLifecycle | null {
  if (!db) return null;

  const findStmt = db.prepare(`
    SELECT id, vuln_id, target, severity, discovered_at
    FROM vulnerability_lifecycle
    WHERE vuln_id = ? AND target = ? AND resolved_at IS NULL
    ORDER BY discovered_at DESC
    LIMIT 1
  `);

  const row = findStmt.get(vulnId, target) as
    | {
        id: string;
        vuln_id: string;
        target: string;
        severity: string;
        discovered_at: string;
      }
    | undefined;

  if (!row) return null;

  const now = new Date();
  const discoveredAt = new Date(row.discovered_at);
  const mttrHours = Math.round((now.getTime() - discoveredAt.getTime()) / (1000 * 60 * 60));

  const updateStmt = db.prepare(`
    UPDATE vulnerability_lifecycle
    SET resolved_at = ?, mttr_hours = ?
    WHERE id = ?
  `);

  updateStmt.run(now.toISOString(), mttrHours, row.id);

  logAudit("vuln_resolved", row.id, undefined, { vulnId, target, mttrHours });

  return {
    id: row.id,
    vulnId: row.vuln_id,
    target: row.target,
    severity: row.severity as MetricsSeverity,
    discoveredAt: row.discovered_at,
    resolvedAt: now.toISOString(),
    mttrHours,
  };
}

export function getMTTRStats(options: GetMTTROptions = {}): MTTRStats[] {
  if (!db) return [];

  let sql = `
    SELECT
      severity,
      COUNT(*) as count,
      AVG(mttr_hours) as avg_hours,
      MIN(mttr_hours) as min_hours,
      MAX(mttr_hours) as max_hours
    FROM vulnerability_lifecycle
    WHERE resolved_at IS NOT NULL AND mttr_hours IS NOT NULL
  `;

  const params: (string | undefined)[] = [];

  if (options.target) {
    sql += " AND target = ?";
    params.push(options.target);
  }

  if (options.severity) {
    sql += " AND severity = ?";
    params.push(options.severity);
  }

  if (options.startDate) {
    sql += " AND discovered_at >= ?";
    params.push(options.startDate);
  }

  if (options.endDate) {
    sql += " AND discovered_at <= ?";
    params.push(options.endDate);
  }

  sql +=
    " GROUP BY severity ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 END";

  const stmt = db.prepare(sql);
  const rows = stmt.all(...params.filter((p): p is string => p !== undefined)) as Array<{
    severity: string;
    count: number;
    avg_hours: number;
    min_hours: number;
    max_hours: number;
  }>;

  return rows.map((row) => {
    // Calculate median
    let medianSql = `
      SELECT mttr_hours
      FROM vulnerability_lifecycle
      WHERE resolved_at IS NOT NULL AND mttr_hours IS NOT NULL AND severity = ?
    `;
    const medianParams: string[] = [row.severity];

    if (options.target) {
      medianSql += " AND target = ?";
      medianParams.push(options.target);
    }
    if (options.startDate) {
      medianSql += " AND discovered_at >= ?";
      medianParams.push(options.startDate);
    }
    if (options.endDate) {
      medianSql += " AND discovered_at <= ?";
      medianParams.push(options.endDate);
    }
    medianSql += " ORDER BY mttr_hours";

    const medianStmt = db!.prepare(medianSql);
    const mttrValues = medianStmt.all(...medianParams) as Array<{ mttr_hours: number }>;

    let medianHours = 0;
    if (mttrValues.length > 0) {
      const mid = Math.floor(mttrValues.length / 2);
      if (mttrValues.length % 2 === 0) {
        medianHours = (mttrValues[mid - 1].mttr_hours + mttrValues[mid].mttr_hours) / 2;
      } else {
        medianHours = mttrValues[mid].mttr_hours;
      }
    }

    return {
      severity: row.severity as MetricsSeverity,
      count: row.count,
      averageHours: Math.round(row.avg_hours * 100) / 100,
      medianHours: Math.round(medianHours * 100) / 100,
      minHours: row.min_hours,
      maxHours: row.max_hours,
    };
  });
}

// =============================================================================
// Trend Analysis
// =============================================================================

function calculateTrendDirection(values: number[]): MetricsTrendDirection {
  if (values.length < 2) return "stable";

  const first = values[0];
  const last = values[values.length - 1];
  const changePercent = first === 0 ? (last > 0 ? 100 : 0) : ((last - first) / first) * 100;

  if (changePercent < -5) return "improving";
  if (changePercent > 5) return "declining";
  return "stable";
}

export function getTrends(options: GetTrendsOptions): TrendAnalysis {
  if (!db) {
    throw new Error("Database not initialized. Call initMetricsDatabase first.");
  }

  const periodDays: Record<string, number> = {
    "7d": 7,
    "30d": 30,
    "90d": 90,
    "180d": 180,
    "365d": 365,
  };

  const days = periodDays[options.period] || 30;
  const endDate = options.endDate ? new Date(options.endDate) : new Date();
  const startDate = new Date(endDate);
  startDate.setDate(startDate.getDate() - days);

  const stmt = db.prepare(`
    SELECT id, target, target_type, snapshot_date, metrics_json, created_at
    FROM security_snapshots
    WHERE target = ? AND snapshot_date >= ? AND snapshot_date <= ?
    ORDER BY snapshot_date ASC
  `);

  const rows = stmt.all(
    options.target,
    startDate.toISOString().split("T")[0],
    endDate.toISOString().split("T")[0]
  ) as Array<{
    id: string;
    target: string;
    target_type: string;
    snapshot_date: string;
    metrics_json: string;
    created_at: string;
  }>;

  const snapshots: SecuritySnapshot[] = rows.map((row) => ({
    id: row.id,
    target: row.target,
    targetType: row.target_type as SecuritySnapshot["targetType"],
    snapshotDate: row.snapshot_date,
    metrics: JSON.parse(row.metrics_json),
    createdAt: row.created_at,
  }));

  const totalValues = snapshots.map((s) => s.metrics.totalVulnerabilities);
  const criticalValues = snapshots.map((s) => s.metrics.criticalCount);
  const highValues = snapshots.map((s) => s.metrics.highCount);

  const startTotal = snapshots.length > 0 ? snapshots[0].metrics.totalVulnerabilities : 0;
  const endTotal =
    snapshots.length > 0 ? snapshots[snapshots.length - 1].metrics.totalVulnerabilities : 0;
  const changePercent =
    startTotal === 0 ? (endTotal > 0 ? 100 : 0) : ((endTotal - startTotal) / startTotal) * 100;

  return {
    target: options.target,
    period: options.period,
    startDate: startDate.toISOString().split("T")[0],
    endDate: endDate.toISOString().split("T")[0],
    direction: calculateTrendDirection(totalValues),
    snapshots,
    summary: {
      startTotal,
      endTotal,
      changePercent: Math.round(changePercent * 100) / 100,
      criticalTrend: calculateTrendDirection(criticalValues),
      highTrend: calculateTrendDirection(highValues),
    },
  };
}

// =============================================================================
// Baseline Operations
// =============================================================================

export function setMetricsBaseline(options: SetBaselineOptions): MetricsBaseline {
  if (!db) {
    throw new Error("Database not initialized. Call initMetricsDatabase first.");
  }

  const id = randomUUID();
  const now = new Date().toISOString();

  const stmt = db.prepare(`
    INSERT OR REPLACE INTO security_baselines (id, name, target, metrics_json, created_by, created_at)
    VALUES (
      COALESCE((SELECT id FROM security_baselines WHERE name = ? AND target = ?), ?),
      ?, ?, ?, ?, ?
    )
  `);

  stmt.run(
    options.name,
    options.target,
    id,
    options.name,
    options.target,
    JSON.stringify(options.metrics),
    options.createdBy || null,
    now
  );

  logAudit("baseline_set", id, options.createdBy, {
    name: options.name,
    target: options.target,
    metrics: options.metrics,
  });

  return {
    id,
    name: options.name,
    target: options.target,
    metrics: options.metrics,
    createdAt: now,
    createdBy: options.createdBy,
  };
}

export function getMetricsBaseline(name: string, target: string): MetricsBaseline | null {
  if (!db) return null;

  const stmt = db.prepare(`
    SELECT id, name, target, metrics_json, created_by, created_at
    FROM security_baselines
    WHERE name = ? AND target = ?
  `);

  const row = stmt.get(name, target) as
    | {
        id: string;
        name: string;
        target: string;
        metrics_json: string;
        created_by: string | null;
        created_at: string;
      }
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    name: row.name,
    target: row.target,
    metrics: JSON.parse(row.metrics_json),
    createdAt: row.created_at,
    createdBy: row.created_by || undefined,
  };
}

export function listMetricsBaselines(target?: string): MetricsBaseline[] {
  if (!db) return [];

  let sql = `
    SELECT id, name, target, metrics_json, created_by, created_at
    FROM security_baselines
  `;

  if (target) {
    sql += " WHERE target = ?";
  }

  sql += " ORDER BY created_at DESC";

  const stmt = db.prepare(sql);
  const rows = (target ? stmt.all(target) : stmt.all()) as Array<{
    id: string;
    name: string;
    target: string;
    metrics_json: string;
    created_by: string | null;
    created_at: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    target: row.target,
    metrics: JSON.parse(row.metrics_json),
    createdAt: row.created_at,
    createdBy: row.created_by || undefined,
  }));
}

export function deleteMetricsBaseline(name: string, target: string): boolean {
  if (!db) return false;

  const stmt = db.prepare(`
    DELETE FROM security_baselines
    WHERE name = ? AND target = ?
  `);

  const result = stmt.run(name, target);

  if (result.changes > 0) {
    logAudit("baseline_deleted", name + ":" + target, undefined, { name, target });
    return true;
  }

  return false;
}

export function compareMetricsBaseline(
  baselineName: string,
  target: string,
  currentMetrics: SnapshotMetrics
): BaselineComparison | null {
  const baseline = getMetricsBaseline(baselineName, target);
  if (!baseline) return null;

  const delta = {
    totalVulnerabilities:
      currentMetrics.totalVulnerabilities - baseline.metrics.totalVulnerabilities,
    criticalCount: currentMetrics.criticalCount - baseline.metrics.criticalCount,
    highCount: currentMetrics.highCount - baseline.metrics.highCount,
    mediumCount: currentMetrics.mediumCount - baseline.metrics.mediumCount,
    lowCount: currentMetrics.lowCount - baseline.metrics.lowCount,
  };

  const calcPercent = (current: number, base: number): number => {
    if (base === 0) return current > 0 ? 100 : 0;
    return Math.round(((current - base) / base) * 10000) / 100;
  };

  const percentChange = {
    total: calcPercent(currentMetrics.totalVulnerabilities, baseline.metrics.totalVulnerabilities),
    critical: calcPercent(currentMetrics.criticalCount, baseline.metrics.criticalCount),
    high: calcPercent(currentMetrics.highCount, baseline.metrics.highCount),
    medium: calcPercent(currentMetrics.mediumCount, baseline.metrics.mediumCount),
    low: calcPercent(currentMetrics.lowCount, baseline.metrics.lowCount),
  };

  let status: "better" | "same" | "worse" = "same";
  if (delta.criticalCount < 0 || delta.highCount < 0) {
    status = "better";
  }
  if (delta.criticalCount > 0 || delta.highCount > 0) {
    status = "worse";
  }

  logAudit("baseline_compared", baselineName + ":" + target, undefined, {
    baselineName,
    target,
    status,
    delta,
  });

  return {
    baseline,
    current: currentMetrics,
    delta,
    percentChange,
    status,
  };
}

// =============================================================================
// Summary Statistics
// =============================================================================

export interface MetricsSummary {
  totalSnapshots: number;
  totalVulnerabilitiesTracked: number;
  resolvedVulnerabilities: number;
  openVulnerabilities: number;
  totalBaselines: number;
  averageMTTRHours: number | null;
  targetsTracked: number;
}

export function getMetricsSummary(): MetricsSummary {
  if (!db) {
    return {
      totalSnapshots: 0,
      totalVulnerabilitiesTracked: 0,
      resolvedVulnerabilities: 0,
      openVulnerabilities: 0,
      totalBaselines: 0,
      averageMTTRHours: null,
      targetsTracked: 0,
    };
  }

  const snapshotCount = db.prepare("SELECT COUNT(*) as count FROM security_snapshots").get() as {
    count: number;
  };
  const baselineCount = db.prepare("SELECT COUNT(*) as count FROM security_baselines").get() as {
    count: number;
  };
  const vulnStats = db
    .prepare(
      `
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN resolved_at IS NOT NULL THEN 1 ELSE 0 END) as resolved,
      SUM(CASE WHEN resolved_at IS NULL THEN 1 ELSE 0 END) as open,
      AVG(CASE WHEN mttr_hours IS NOT NULL THEN mttr_hours END) as avg_mttr
    FROM vulnerability_lifecycle
  `
    )
    .get() as { total: number; resolved: number; open: number; avg_mttr: number | null };

  const targetCount = db
    .prepare("SELECT COUNT(DISTINCT target) as count FROM security_snapshots")
    .get() as { count: number };

  return {
    totalSnapshots: snapshotCount.count,
    totalVulnerabilitiesTracked: vulnStats.total,
    resolvedVulnerabilities: vulnStats.resolved,
    openVulnerabilities: vulnStats.open,
    totalBaselines: baselineCount.count,
    averageMTTRHours: vulnStats.avg_mttr ? Math.round(vulnStats.avg_mttr * 100) / 100 : null,
    targetsTracked: targetCount.count,
  };
}
