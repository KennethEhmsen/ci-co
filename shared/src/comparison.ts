/**
 * Cross-Project Comparative Analysis Module
 *
 * Provides functionality for comparing security metrics across projects,
 * teams, and other entities. Supports baseline snapshots for historical
 * comparison and rankings/leaderboards.
 */

import Database from "better-sqlite3";
import * as crypto from "crypto";
import * as path from "path";
import * as os from "os";
import * as fs from "fs";

import type {
  ComparisonEntityType,
  ComparisonMetric,
  ComparisonTrend,
  EntityMetrics,
  ComparisonMetricResult,
  ComparisonResult,
  Baseline,
  CreateBaselineOptions,
  CompareProjectsOptions,
  CompareTeamsOptions,
  CompareToBaselineOptions,
  RankingEntry,
  GetRankingsOptions,
  RankingsResult,
  ComparisonDbInitResult,
  ListBaselinesOptions,
} from "./types.js";

// =============================================================================
// Database Management
// =============================================================================

let comparisonDb: Database.Database | null = null;

/**
 * Get default database path for comparison data
 */
export function getComparisonDbPath(): string {
  const dataDir = process.env.CICD_DATA_DIR || path.join(os.homedir(), ".cicd");
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  return path.join(dataDir, "comparison.db");
}

/**
 * Initialize the comparison database
 */
export function initComparisonDb(dbPath?: string): ComparisonDbInitResult {
  try {
    const finalPath = dbPath || getComparisonDbPath();
    comparisonDb = new Database(finalPath);

    // Create baselines table
    comparisonDb.exec(`
      CREATE TABLE IF NOT EXISTS baselines (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        entity_name TEXT NOT NULL,
        metrics_json TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        created_by TEXT,
        tags_json TEXT,
        is_default INTEGER DEFAULT 0
      );

      CREATE INDEX IF NOT EXISTS idx_baselines_entity
        ON baselines(entity_type, entity_id);
      CREATE INDEX IF NOT EXISTS idx_baselines_default
        ON baselines(entity_type, entity_id, is_default);

      -- Entity metrics history for rankings
      CREATE TABLE IF NOT EXISTS entity_metrics_history (
        id TEXT PRIMARY KEY,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        entity_name TEXT NOT NULL,
        metrics_json TEXT NOT NULL,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_metrics_history_entity
        ON entity_metrics_history(entity_type, entity_id, timestamp);

      -- Comparison cache for frequently compared entities
      CREATE TABLE IF NOT EXISTS comparison_cache (
        cache_key TEXT PRIMARY KEY,
        result_json TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_comparison_cache_expires
        ON comparison_cache(expires_at);
    `);

    return {
      success: true,
      path: finalPath,
      created: new Date().toISOString(),
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      path: dbPath || getComparisonDbPath(),
      created: new Date().toISOString(),
      error: message,
    };
  }
}

/**
 * Get the database instance, initializing if needed
 */
function getDb(): Database.Database {
  if (!comparisonDb) {
    const result = initComparisonDb();
    if (!result.success) {
      throw new Error(`Failed to initialize comparison database: ${result.error}`);
    }
  }
  return comparisonDb!;
}

/**
 * Close the database connection
 */
export function closeComparisonDb(): void {
  if (comparisonDb) {
    comparisonDb.close();
    comparisonDb = null;
  }
}

// =============================================================================
// Metric Comparison Logic
// =============================================================================

/**
 * Metrics where lower is better
 */
const LOWER_IS_BETTER_METRICS: ComparisonMetric[] = [
  "vulnerability_count",
  "critical_count",
  "high_count",
  "medium_count",
  "low_count",
  "mttr",
];

/**
 * Determine if a metric value being lower is better
 */
function isLowerBetter(metric: ComparisonMetric): boolean {
  // Risk score is special - lower is actually better
  if (metric === "risk_score") {
    return true;
  }
  return LOWER_IS_BETTER_METRICS.includes(metric);
}

/**
 * Calculate trend based on percent change and metric type
 */
function calculateTrend(percentChange: number, metric: ComparisonMetric): ComparisonTrend {
  const threshold = 5; // 5% threshold for "stable"
  const absPercentChange = Math.abs(percentChange);

  if (absPercentChange < threshold) {
    return "stable";
  }

  // For metrics where lower is better, negative change = improving
  if (isLowerBetter(metric)) {
    return percentChange < 0 ? "improving" : "declining";
  }

  // For metrics where higher is better, positive change = improving
  return percentChange > 0 ? "improving" : "declining";
}

/**
 * Determine winner for a specific metric
 */
function determineWinner(
  valueA: number,
  valueB: number,
  metric: ComparisonMetric
): "A" | "B" | "tie" {
  const threshold = 0.01; // 1% threshold for tie
  const diff = Math.abs(valueA - valueB);
  const max = Math.max(valueA, valueB);

  if (max > 0 && diff / max < threshold) {
    return "tie";
  }

  if (isLowerBetter(metric)) {
    return valueA < valueB ? "A" : "B";
  }

  return valueA > valueB ? "A" : "B";
}

/**
 * Extract metric value from EntityMetrics
 */
function getMetricValue(metrics: EntityMetrics, metric: ComparisonMetric): number {
  switch (metric) {
    case "vulnerability_count":
      return metrics.vulnerabilityCount;
    case "critical_count":
      return metrics.criticalCount;
    case "high_count":
      return metrics.highCount;
    case "medium_count":
      return metrics.mediumCount;
    case "low_count":
      return metrics.lowCount;
    case "risk_score":
      return metrics.riskScore;
    case "health_score":
      return metrics.healthScore;
    case "compliance_score":
      return metrics.complianceScore;
    case "mttr":
      return metrics.mttr ?? 0;
    case "remediation_velocity":
      return metrics.remediationVelocity ?? 0;
    case "scan_coverage":
      return metrics.scanCoverage ?? 0;
    default:
      return 0;
  }
}

/**
 * Compare two metric values
 */
function compareMetric(
  valueA: number,
  valueB: number,
  metric: ComparisonMetric
): ComparisonMetricResult {
  const delta = valueB - valueA;
  const percentChange =
    valueA !== 0 ? ((valueB - valueA) / Math.abs(valueA)) * 100 : valueB !== 0 ? 100 : 0;

  return {
    metric,
    valueA,
    valueB,
    delta,
    percentChange: Math.round(percentChange * 100) / 100,
    trend: calculateTrend(percentChange, metric),
    winner: determineWinner(valueA, valueB, metric),
  };
}

/**
 * Compare all metrics between two entities
 */
function compareAllMetrics(
  metricsA: EntityMetrics,
  metricsB: EntityMetrics
): ComparisonMetricResult[] {
  const metricsToCompare: ComparisonMetric[] = [
    "vulnerability_count",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "risk_score",
    "health_score",
    "compliance_score",
  ];

  // Add optional metrics if both have values
  if (metricsA.mttr !== undefined && metricsB.mttr !== undefined) {
    metricsToCompare.push("mttr");
  }
  if (metricsA.remediationVelocity !== undefined && metricsB.remediationVelocity !== undefined) {
    metricsToCompare.push("remediation_velocity");
  }
  if (metricsA.scanCoverage !== undefined && metricsB.scanCoverage !== undefined) {
    metricsToCompare.push("scan_coverage");
  }

  return metricsToCompare.map((metric) =>
    compareMetric(getMetricValue(metricsA, metric), getMetricValue(metricsB, metric), metric)
  );
}

/**
 * Generate key differences based on metric comparisons
 */
function generateKeyDifferences(comparisons: ComparisonMetricResult[]): string[] {
  const differences: string[] = [];

  // Find significant differences (>20% change)
  const significant = comparisons.filter(
    (c) => Math.abs(c.percentChange) > 20 && c.winner !== "tie"
  );

  // Sort by absolute percent change
  significant.sort((a, b) => Math.abs(b.percentChange) - Math.abs(a.percentChange));

  // Take top 5 differences
  for (const diff of significant.slice(0, 5)) {
    const betterEntity = diff.winner === "A" ? "Entity A" : "Entity B";
    const metric = diff.metric.replace(/_/g, " ");
    const pct = Math.abs(diff.percentChange).toFixed(1);

    if (isLowerBetter(diff.metric)) {
      differences.push(`${betterEntity} has ${pct}% fewer ${metric}`);
    } else {
      differences.push(`${betterEntity} has ${pct}% higher ${metric}`);
    }
  }

  return differences;
}

/**
 * Generate recommendations based on comparisons
 */
function generateRecommendations(
  metricsA: EntityMetrics,
  metricsB: EntityMetrics,
  comparisons: ComparisonMetricResult[]
): string[] {
  const recommendations: string[] = [];

  // Check for critical vulnerabilities
  if (metricsA.criticalCount > 0 || metricsB.criticalCount > 0) {
    const worse = metricsA.criticalCount > metricsB.criticalCount ? "Entity A" : "Entity B";
    recommendations.push(
      `${worse} should prioritize addressing ${Math.max(
        metricsA.criticalCount,
        metricsB.criticalCount
      )} critical vulnerabilities`
    );
  }

  // Check compliance scores
  const complianceComp = comparisons.find((c) => c.metric === "compliance_score");
  if (complianceComp && Math.min(metricsA.complianceScore, metricsB.complianceScore) < 80) {
    const worse = complianceComp.winner === "A" ? "Entity B" : "Entity A";
    recommendations.push(
      `${worse} should focus on improving compliance score (currently ${Math.min(
        metricsA.complianceScore,
        metricsB.complianceScore
      )}%)`
    );
  }

  // Check scan coverage
  if (metricsA.scanCoverage !== undefined && metricsB.scanCoverage !== undefined) {
    const minCoverage = Math.min(metricsA.scanCoverage, metricsB.scanCoverage);
    if (minCoverage < 90) {
      const worse = metricsA.scanCoverage < metricsB.scanCoverage ? "Entity A" : "Entity B";
      recommendations.push(
        `${worse} should increase scan coverage from ${minCoverage}% to at least 90%`
      );
    }
  }

  // Check MTTR
  if (metricsA.mttr !== undefined && metricsB.mttr !== undefined) {
    const maxMttr = Math.max(metricsA.mttr, metricsB.mttr);
    if (maxMttr > 72) {
      const worse = metricsA.mttr > metricsB.mttr ? "Entity A" : "Entity B";
      recommendations.push(
        `${worse} should improve remediation time (MTTR: ${maxMttr.toFixed(1)}h)`
      );
    }
  }

  return recommendations.slice(0, 5); // Limit to 5 recommendations
}

/**
 * Determine overall winner based on metric comparisons
 */
function determineOverallWinner(comparisons: ComparisonMetricResult[]): "A" | "B" | "tie" {
  let aWins = 0;
  let bWins = 0;

  // Weight critical metrics more heavily
  const weights: Partial<Record<ComparisonMetric, number>> = {
    critical_count: 3,
    high_count: 2,
    risk_score: 2,
    compliance_score: 2,
    vulnerability_count: 1.5,
    medium_count: 1,
    low_count: 0.5,
    health_score: 1.5,
    mttr: 1,
    remediation_velocity: 1,
    scan_coverage: 1,
  };

  for (const comp of comparisons) {
    const weight = weights[comp.metric] ?? 1;
    if (comp.winner === "A") {
      aWins += weight;
    } else if (comp.winner === "B") {
      bWins += weight;
    }
  }

  const totalWeight = aWins + bWins;
  if (totalWeight === 0) {
    return "tie";
  }

  const ratio = Math.abs(aWins - bWins) / totalWeight;
  if (ratio < 0.1) {
    return "tie";
  }

  return aWins > bWins ? "A" : "B";
}

/**
 * Calculate confidence score for comparison
 */
function calculateConfidence(
  metricsA: EntityMetrics,
  metricsB: EntityMetrics,
  comparisons: ComparisonMetricResult[]
): number {
  let confidence = 100;

  // Reduce confidence if data is incomplete
  const optionalFields = ["mttr", "remediationVelocity", "scanCoverage", "assetCount"];
  let missingFields = 0;

  for (const field of optionalFields) {
    if (
      metricsA[field as keyof EntityMetrics] === undefined ||
      metricsB[field as keyof EntityMetrics] === undefined
    ) {
      missingFields++;
    }
  }

  confidence -= missingFields * 5; // -5% per missing field

  // Reduce confidence if many ties
  const ties = comparisons.filter((c) => c.winner === "tie").length;
  confidence -= ties * 3; // -3% per tie

  // Reduce confidence for extreme differences (possible data quality issues)
  const extremeDiffs = comparisons.filter((c) => Math.abs(c.percentChange) > 500).length;
  confidence -= extremeDiffs * 10; // -10% per extreme diff

  return Math.max(0, Math.min(100, confidence));
}

// =============================================================================
// Comparison Functions
// =============================================================================

/**
 * Compare two projects
 */
export function compareProjects(options: CompareProjectsOptions): ComparisonResult {
  const { projectIdA, projectIdB, metricsA, metricsB, normalize } = options;

  if (!metricsA || !metricsB) {
    throw new Error(
      "Metrics must be provided for both projects. Use metricsA and metricsB options."
    );
  }

  let effectiveMetricsA = { ...metricsA };
  let effectiveMetricsB = { ...metricsB };

  // Normalize by asset count if requested
  if (normalize && metricsA.assetCount && metricsB.assetCount) {
    effectiveMetricsA = normalizeMetrics(metricsA, metricsA.assetCount);
    effectiveMetricsB = normalizeMetrics(metricsB, metricsB.assetCount);
  }

  const comparisons = compareAllMetrics(effectiveMetricsA, effectiveMetricsB);

  return {
    entityA: {
      ...effectiveMetricsA,
      entityId: projectIdA,
      entityType: "project",
    },
    entityB: {
      ...effectiveMetricsB,
      entityId: projectIdB,
      entityType: "project",
    },
    metrics: comparisons,
    summary: {
      betterEntity: determineOverallWinner(comparisons),
      confidence: calculateConfidence(effectiveMetricsA, effectiveMetricsB, comparisons),
      keyDifferences: generateKeyDifferences(comparisons),
      recommendations: generateRecommendations(effectiveMetricsA, effectiveMetricsB, comparisons),
    },
    comparedAt: new Date().toISOString(),
  };
}

/**
 * Compare two teams
 */
export function compareTeams(options: CompareTeamsOptions): ComparisonResult {
  const { teamIdA, teamIdB, metricsA, metricsB, normalize } = options;

  if (!metricsA || !metricsB) {
    throw new Error("Metrics must be provided for both teams. Use metricsA and metricsB options.");
  }

  let effectiveMetricsA = { ...metricsA };
  let effectiveMetricsB = { ...metricsB };

  // Normalize by asset count if requested
  if (normalize && metricsA.assetCount && metricsB.assetCount) {
    effectiveMetricsA = normalizeMetrics(metricsA, metricsA.assetCount);
    effectiveMetricsB = normalizeMetrics(metricsB, metricsB.assetCount);
  }

  const comparisons = compareAllMetrics(effectiveMetricsA, effectiveMetricsB);

  return {
    entityA: {
      ...effectiveMetricsA,
      entityId: teamIdA,
      entityType: "team",
    },
    entityB: {
      ...effectiveMetricsB,
      entityId: teamIdB,
      entityType: "team",
    },
    metrics: comparisons,
    summary: {
      betterEntity: determineOverallWinner(comparisons),
      confidence: calculateConfidence(effectiveMetricsA, effectiveMetricsB, comparisons),
      keyDifferences: generateKeyDifferences(comparisons),
      recommendations: generateRecommendations(effectiveMetricsA, effectiveMetricsB, comparisons),
    },
    comparedAt: new Date().toISOString(),
  };
}

/**
 * Normalize metrics by a divisor (e.g., asset count)
 */
function normalizeMetrics(metrics: EntityMetrics, divisor: number): EntityMetrics {
  if (divisor <= 0) {
    return metrics;
  }

  return {
    ...metrics,
    vulnerabilityCount: metrics.vulnerabilityCount / divisor,
    criticalCount: metrics.criticalCount / divisor,
    highCount: metrics.highCount / divisor,
    mediumCount: metrics.mediumCount / divisor,
    lowCount: metrics.lowCount / divisor,
    // Don't normalize scores - they're already percentages
  };
}

/**
 * Compare current metrics to a baseline
 */
export function compareToBaseline(options: CompareToBaselineOptions): ComparisonResult {
  const { currentMetrics, baselineId, useDefaultBaseline, entityId } = options;

  let baseline: Baseline | null = null;

  if (baselineId) {
    baseline = getBaseline(baselineId);
  } else if (useDefaultBaseline && entityId) {
    baseline = getDefaultBaseline(entityId);
  }

  if (!baseline) {
    throw new Error(
      baselineId ? `Baseline not found: ${baselineId}` : "Default baseline not found for entity"
    );
  }

  const comparisons = compareAllMetrics(baseline.metrics, currentMetrics);

  return {
    entityA: baseline.metrics,
    entityB: currentMetrics,
    metrics: comparisons,
    summary: {
      betterEntity: determineOverallWinner(comparisons),
      confidence: calculateConfidence(baseline.metrics, currentMetrics, comparisons),
      keyDifferences: generateKeyDifferences(comparisons),
      recommendations: generateRecommendations(baseline.metrics, currentMetrics, comparisons),
    },
    comparedAt: new Date().toISOString(),
  };
}

// =============================================================================
// Baseline Management
// =============================================================================

/**
 * Create a new baseline
 */
export function createBaseline(options: CreateBaselineOptions): Baseline {
  const db = getDb();
  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();

  // If setting as default, clear other defaults for this entity
  if (options.isDefault) {
    db.prepare(
      `UPDATE baselines SET is_default = 0
       WHERE entity_type = ? AND entity_id = ?`
    ).run(options.entityType, options.entityId);
  }

  db.prepare(
    `INSERT INTO baselines
     (id, name, description, entity_type, entity_id, entity_name,
      metrics_json, created_at, created_by, tags_json, is_default)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    options.name,
    options.description || null,
    options.entityType,
    options.entityId,
    options.entityName,
    JSON.stringify(options.metrics),
    createdAt,
    options.createdBy || null,
    options.tags ? JSON.stringify(options.tags) : null,
    options.isDefault ? 1 : 0
  );

  return {
    id,
    name: options.name,
    description: options.description,
    entityType: options.entityType,
    entityId: options.entityId,
    entityName: options.entityName,
    metrics: options.metrics,
    createdAt,
    createdBy: options.createdBy,
    tags: options.tags,
    isDefault: options.isDefault,
  };
}

/**
 * Get a baseline by ID
 */
export function getBaseline(id: string): Baseline | null {
  const db = getDb();
  const row = db.prepare("SELECT * FROM baselines WHERE id = ?").get(id) as BaselineRow | undefined;

  if (!row) {
    return null;
  }

  return rowToBaseline(row);
}

/**
 * Get the default baseline for an entity
 */
export function getDefaultBaseline(entityId: string): Baseline | null {
  const db = getDb();
  const row = db
    .prepare(
      `SELECT * FROM baselines
       WHERE entity_id = ? AND is_default = 1
       ORDER BY created_at DESC LIMIT 1`
    )
    .get(entityId) as BaselineRow | undefined;

  if (!row) {
    return null;
  }

  return rowToBaseline(row);
}

/**
 * List baselines with optional filtering
 */
export function listBaselines(options: ListBaselinesOptions = {}): Baseline[] {
  const db = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options.entityType) {
    conditions.push("entity_type = ?");
    params.push(options.entityType);
  }

  if (options.entityId) {
    conditions.push("entity_id = ?");
    params.push(options.entityId);
  }

  let query = "SELECT * FROM baselines";
  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }
  query += " ORDER BY created_at DESC";

  if (options.limit) {
    query += ` LIMIT ${options.limit}`;
  }
  if (options.offset) {
    query += ` OFFSET ${options.offset}`;
  }

  const rows = db.prepare(query).all(...params) as BaselineRow[];

  let baselines = rows.map(rowToBaseline);

  // Filter by tags if specified
  if (options.tags && options.tags.length > 0) {
    baselines = baselines.filter((b) => options.tags!.some((tag) => b.tags?.includes(tag)));
  }

  return baselines;
}

/**
 * Delete a baseline
 */
export function deleteBaseline(id: string): boolean {
  const db = getDb();
  const result = db.prepare("DELETE FROM baselines WHERE id = ?").run(id);
  return result.changes > 0;
}

/**
 * Set a baseline as the default for its entity
 */
export function setDefaultBaseline(id: string): boolean {
  const db = getDb();

  const baseline = getBaseline(id);
  if (!baseline) {
    return false;
  }

  // Clear existing defaults for this entity
  db.prepare(
    `UPDATE baselines SET is_default = 0
     WHERE entity_type = ? AND entity_id = ?`
  ).run(baseline.entityType, baseline.entityId);

  // Set new default
  const result = db.prepare("UPDATE baselines SET is_default = 1 WHERE id = ?").run(id);

  return result.changes > 0;
}

// =============================================================================
// Rankings / Leaderboard
// =============================================================================

/**
 * Record entity metrics for ranking
 */
export function recordEntityMetrics(metrics: EntityMetrics): void {
  const db = getDb();
  const id = crypto.randomUUID();

  db.prepare(
    `INSERT INTO entity_metrics_history
     (id, entity_type, entity_id, entity_name, metrics_json, timestamp)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    metrics.entityType,
    metrics.entityId,
    metrics.entityName,
    JSON.stringify(metrics),
    metrics.timestamp || new Date().toISOString()
  );
}

/**
 * Get rankings for entities
 */
export function getRankings(options: GetRankingsOptions): RankingsResult {
  const db = getDb();
  const { metric, entityType, entityIds, limit = 10, order = "desc" } = options;

  // Build query for latest metrics per entity
  let query = `
    SELECT entity_id, entity_name, metrics_json,
           MAX(timestamp) as latest_timestamp
    FROM entity_metrics_history
    WHERE entity_type = ?
  `;
  const params: unknown[] = [entityType];

  if (entityIds && entityIds.length > 0) {
    const placeholders = entityIds.map(() => "?").join(",");
    query += ` AND entity_id IN (${placeholders})`;
    params.push(...entityIds);
  }

  query += " GROUP BY entity_id";

  const rows = db.prepare(query).all(...params) as MetricsHistoryRow[];

  // Extract and score entities
  const scored: Array<{
    entityId: string;
    entityName: string;
    score: number;
    metrics: EntityMetrics;
  }> = [];

  for (const row of rows) {
    const metrics = JSON.parse(row.metrics_json) as EntityMetrics;
    const score = getMetricValue(metrics, metric);
    scored.push({
      entityId: row.entity_id,
      entityName: row.entity_name,
      score,
      metrics,
    });
  }

  // Sort by score
  const lowerBetter = isLowerBetter(metric);
  scored.sort((a, b) => {
    if (order === "asc") {
      return lowerBetter ? b.score - a.score : a.score - b.score;
    }
    return lowerBetter ? a.score - b.score : b.score - a.score;
  });

  // Calculate statistics
  const scores = scored.map((s) => s.score);
  const stats = calculateStats(scores);

  // Build rankings
  const rankings: RankingEntry[] = scored.slice(0, limit).map((s, idx) => ({
    rank: idx + 1,
    entityId: s.entityId,
    entityName: s.entityName,
    entityType,
    score: s.score,
    percentile: calculatePercentile(s.score, scores, lowerBetter),
  }));

  return {
    metric,
    entityType,
    rankings,
    stats: {
      total: scored.length,
      average: stats.average,
      median: stats.median,
      stdDev: stats.stdDev,
      best: scores.length > 0 ? scores[0] : 0,
      worst: scores.length > 0 ? scores[scores.length - 1] : 0,
    },
    generatedAt: new Date().toISOString(),
  };
}

/**
 * Calculate statistical measures
 */
function calculateStats(values: number[]): {
  average: number;
  median: number;
  stdDev: number;
} {
  if (values.length === 0) {
    return { average: 0, median: 0, stdDev: 0 };
  }

  const sum = values.reduce((a, b) => a + b, 0);
  const average = sum / values.length;

  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const median = sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];

  const squaredDiffs = values.map((v) => Math.pow(v - average, 2));
  const avgSquaredDiff = squaredDiffs.reduce((a, b) => a + b, 0) / values.length;
  const stdDev = Math.sqrt(avgSquaredDiff);

  return {
    average: Math.round(average * 100) / 100,
    median: Math.round(median * 100) / 100,
    stdDev: Math.round(stdDev * 100) / 100,
  };
}

/**
 * Calculate percentile for a value
 */
function calculatePercentile(value: number, allValues: number[], lowerBetter: boolean): number {
  if (allValues.length === 0) {
    return 100;
  }

  const countBelow = allValues.filter((v) => (lowerBetter ? v > value : v < value)).length;

  return Math.round((countBelow / allValues.length) * 100);
}

// =============================================================================
// Database Row Types
// =============================================================================

interface BaselineRow {
  id: string;
  name: string;
  description: string | null;
  entity_type: string;
  entity_id: string;
  entity_name: string;
  metrics_json: string;
  created_at: string;
  created_by: string | null;
  tags_json: string | null;
  is_default: number;
}

interface MetricsHistoryRow {
  entity_id: string;
  entity_name: string;
  metrics_json: string;
  latest_timestamp: string;
}

/**
 * Convert database row to Baseline
 */
function rowToBaseline(row: BaselineRow): Baseline {
  return {
    id: row.id,
    name: row.name,
    description: row.description || undefined,
    entityType: row.entity_type as ComparisonEntityType,
    entityId: row.entity_id,
    entityName: row.entity_name,
    metrics: JSON.parse(row.metrics_json) as EntityMetrics,
    createdAt: row.created_at,
    createdBy: row.created_by || undefined,
    tags: row.tags_json ? (JSON.parse(row.tags_json) as string[]) : undefined,
    isDefault: row.is_default === 1,
  };
}

// =============================================================================
// Comparison Cache
// =============================================================================

/**
 * Get cached comparison result
 */
export function getCachedComparison(entityIdA: string, entityIdB: string): ComparisonResult | null {
  const db = getDb();
  const cacheKey = [entityIdA, entityIdB].sort().join("::");

  const row = db
    .prepare(
      `SELECT result_json FROM comparison_cache
       WHERE cache_key = ? AND expires_at > datetime('now')`
    )
    .get(cacheKey) as { result_json: string } | undefined;

  if (!row) {
    return null;
  }

  return JSON.parse(row.result_json) as ComparisonResult;
}

/**
 * Cache a comparison result
 */
export function cacheComparison(
  entityIdA: string,
  entityIdB: string,
  result: ComparisonResult,
  ttlMinutes: number = 60
): void {
  const db = getDb();
  const cacheKey = [entityIdA, entityIdB].sort().join("::");
  const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString();

  db.prepare(
    `INSERT OR REPLACE INTO comparison_cache
     (cache_key, result_json, created_at, expires_at)
     VALUES (?, ?, datetime('now'), ?)`
  ).run(cacheKey, JSON.stringify(result), expiresAt);
}

/**
 * Clear expired cache entries
 */
export function clearExpiredCache(): number {
  const db = getDb();
  const result = db
    .prepare("DELETE FROM comparison_cache WHERE expires_at < datetime('now')")
    .run();
  return result.changes;
}
