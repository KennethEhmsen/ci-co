/**
 * Trend Analysis Module
 *
 * Provides vulnerability trend analysis with forecasting capabilities:
 * - Historical vulnerability tracking
 * - Linear regression forecasting
 * - Anomaly detection using Z-score
 * - Period comparison analysis
 */

import Database from "better-sqlite3";
import * as crypto from "crypto";
import * as path from "path";
import * as fs from "fs";
import type {
  TrendGranularity,
  TrendDataPoint,
  VulnerabilityHistory,
  TrendForecast,
  TrendForecastPoint,
  TrendAnomaly,
  AnomalyDetectionResult,
  PeriodComparison,
  MetricComparison,
  TrendSnapshot,
  GetHistoryOptions,
  GetForecastOptions,
  DetectAnomaliesOptions,
  ComparePeriodOptions,
  RecordSnapshotOptions,
  TrendDbInitResult,
} from "./types.js";

// =============================================================================
// Database Management
// =============================================================================

let db: Database.Database | null = null;

/**
 * Get database instance, throwing if not initialized
 */
function getDb(): Database.Database {
  if (!db) {
    throw new Error("Trend database not initialized. Call initTrendDatabase first.");
  }
  return db;
}

const SCHEMA_SQL = `
  -- Trend snapshots table (daily aggregates)
  CREATE TABLE IF NOT EXISTS trend_snapshots (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT 'image',
    date TEXT NOT NULL,
    total INTEGER NOT NULL DEFAULT 0,
    critical INTEGER NOT NULL DEFAULT 0,
    high INTEGER NOT NULL DEFAULT 0,
    medium INTEGER NOT NULL DEFAULT 0,
    low INTEGER NOT NULL DEFAULT 0,
    unknown INTEGER NOT NULL DEFAULT 0,
    new_count INTEGER NOT NULL DEFAULT 0,
    fixed_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(target, date)
  );

  -- Index for efficient queries
  CREATE INDEX IF NOT EXISTS idx_snapshots_target_date
    ON trend_snapshots(target, date);
  CREATE INDEX IF NOT EXISTS idx_snapshots_date
    ON trend_snapshots(date);

  -- Cached forecasts table
  CREATE TABLE IF NOT EXISTS trend_forecasts (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT 'image',
    generated_at TEXT NOT NULL,
    horizon_days INTEGER NOT NULL,
    model_type TEXT NOT NULL,
    r_squared REAL NOT NULL,
    slope REAL NOT NULL,
    intercept REAL NOT NULL,
    predictions_json TEXT NOT NULL,
    insights_json TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_forecasts_target
    ON trend_forecasts(target);
`;

/**
 * Initialize the trend analysis database
 */
export function initTrendDatabase(dbPath?: string): TrendDbInitResult {
  try {
    // Use provided path or default
    const actualPath = dbPath || path.join(process.cwd(), ".trend-data", "trends.db");

    // Ensure directory exists
    const dir = path.dirname(actualPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Close existing connection if any
    if (db) {
      db.close();
    }

    // Open database
    db = new Database(actualPath);
    db.pragma("journal_mode = WAL");

    // Create tables using the schema
    db.exec(SCHEMA_SQL);

    return {
      success: true,
      path: actualPath,
      created: new Date().toISOString(),
    };
  } catch (error) {
    return {
      success: false,
      path: dbPath || "",
      created: new Date().toISOString(),
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Close the trend database
 */
export function closeTrendDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

/**
 * Check if trend database is initialized
 */
export function isTrendDbInitialized(): boolean {
  return db !== null;
}

// =============================================================================
// Snapshot Management
// =============================================================================

interface SnapshotRow {
  id: string;
  target: string;
  target_type: string;
  date: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  new_count: number;
  fixed_count: number;
  created_at: string;
}

function rowToSnapshot(row: SnapshotRow): TrendSnapshot {
  return {
    id: row.id,
    target: row.target,
    targetType: row.target_type as "image" | "project" | "organization",
    date: row.date,
    total: row.total,
    critical: row.critical,
    high: row.high,
    medium: row.medium,
    low: row.low,
    unknown: row.unknown,
    newCount: row.new_count,
    fixedCount: row.fixed_count,
    createdAt: row.created_at,
  };
}

/**
 * Get a snapshot by ID
 */
function getSnapshot(id: string): TrendSnapshot | null {
  const database = getDb();
  const row = database.prepare("SELECT * FROM trend_snapshots WHERE id = ?").get(id) as
    | SnapshotRow
    | undefined;

  if (!row) return null;

  return rowToSnapshot(row);
}

/**
 * Record a vulnerability snapshot
 */
export function recordTrendSnapshot(options: RecordSnapshotOptions): TrendSnapshot {
  const database = getDb();
  const id = `snap-${crypto.randomUUID()}`;
  const now = new Date().toISOString();
  const snapshotDate = options.date || now.split("T")[0]; // Use date part only

  // Check for existing snapshot on same date
  const existing = database
    .prepare("SELECT id FROM trend_snapshots WHERE target = ? AND date = ?")
    .get(options.target, snapshotDate) as { id: string } | undefined;

  if (existing) {
    // Update existing snapshot
    database
      .prepare(
        `UPDATE trend_snapshots SET
          total = ?, critical = ?, high = ?, medium = ?, low = ?, unknown = ?,
          new_count = ?, fixed_count = ?
        WHERE id = ?`
      )
      .run(
        options.counts.total,
        options.counts.critical,
        options.counts.high,
        options.counts.medium,
        options.counts.low,
        options.counts.unknown || 0,
        options.newCount || 0,
        options.fixedCount || 0,
        existing.id
      );

    return getSnapshot(existing.id)!;
  }

  // Calculate new/fixed if not provided
  let newCount = options.newCount ?? 0;
  let fixedCount = options.fixedCount ?? 0;

  if (options.newCount === undefined || options.fixedCount === undefined) {
    // Get previous snapshot to calculate changes
    const previous = database
      .prepare(
        `SELECT total FROM trend_snapshots
         WHERE target = ? AND date < ?
         ORDER BY date DESC LIMIT 1`
      )
      .get(options.target, snapshotDate) as { total: number } | undefined;

    if (previous) {
      const diff = options.counts.total - previous.total;
      if (diff > 0) {
        newCount = diff;
        fixedCount = 0;
      } else {
        newCount = 0;
        fixedCount = Math.abs(diff);
      }
    }
  }

  // Insert new snapshot
  database
    .prepare(
      `INSERT INTO trend_snapshots
        (id, target, target_type, date, total, critical, high, medium, low, unknown, new_count, fixed_count, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      id,
      options.target,
      options.targetType || "image",
      snapshotDate,
      options.counts.total,
      options.counts.critical,
      options.counts.high,
      options.counts.medium,
      options.counts.low,
      options.counts.unknown || 0,
      newCount,
      fixedCount,
      now
    );

  return getSnapshot(id)!;
}

// =============================================================================
// History Retrieval
// =============================================================================

/**
 * Parse relative date string (e.g., "30d", "90d") to actual date
 */
function parseRelativeDate(dateStr: string): Date {
  const match = /^(\d+)([dhwm])$/.exec(dateStr);
  if (!match) {
    return new Date(dateStr);
  }

  const value = parseInt(match[1], 10);
  const unit = match[2];
  const now = new Date();

  switch (unit) {
    case "d":
      now.setDate(now.getDate() - value);
      break;
    case "h":
      now.setHours(now.getHours() - value);
      break;
    case "w":
      now.setDate(now.getDate() - value * 7);
      break;
    case "m":
      now.setMonth(now.getMonth() - value);
      break;
  }

  return now;
}

/**
 * Calculate moving average
 */
function calculateMovingAverage(values: number[], window: number): number[] {
  const result: number[] = [];

  for (let i = 0; i < values.length; i++) {
    if (i < window - 1) {
      result.push(NaN);
    } else {
      let sum = 0;
      for (let j = 0; j < window; j++) {
        sum += values[i - j];
      }
      result.push(sum / window);
    }
  }

  return result;
}

/**
 * Aggregate data points by granularity
 */
function aggregateByGranularity(
  points: TrendDataPoint[],
  granularity: TrendGranularity
): TrendDataPoint[] {
  if (granularity === "daily" || points.length === 0) {
    return points;
  }

  const groups = new Map<string, TrendDataPoint[]>();

  for (const point of points) {
    const date = new Date(point.date);
    let key: string;

    if (granularity === "weekly") {
      // Get start of week (Monday)
      const day = date.getDay();
      const diff = date.getDate() - day + (day === 0 ? -6 : 1);
      date.setDate(diff);
      key = date.toISOString().split("T")[0];
    } else {
      // Monthly - use first of month
      key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-01`;
    }

    const existing = groups.get(key);
    if (existing) {
      existing.push(point);
    } else {
      groups.set(key, [point]);
    }
  }

  // Aggregate each group
  const result: TrendDataPoint[] = [];
  for (const [date, groupPoints] of groups) {
    const last = groupPoints[groupPoints.length - 1];
    const totalNew = groupPoints.reduce((sum, p) => sum + p.newCount, 0);
    const totalFixed = groupPoints.reduce((sum, p) => sum + p.fixedCount, 0);

    result.push({
      date,
      total: last.total,
      critical: last.critical,
      high: last.high,
      medium: last.medium,
      low: last.low,
      unknown: last.unknown,
      newCount: totalNew,
      fixedCount: totalFixed,
      netChange: totalNew - totalFixed,
    });
  }

  return result.sort((a, b) => a.date.localeCompare(b.date));
}

/**
 * Simple linear regression
 */
function linearRegression(
  x: number[],
  y: number[]
): { slope: number; intercept: number; rSquared: number } {
  const n = x.length;
  if (n === 0) {
    return { slope: 0, intercept: 0, rSquared: 0 };
  }

  const sumX = x.reduce((a, b) => a + b, 0);
  const sumY = y.reduce((a, b) => a + b, 0);
  const sumXY = x.reduce((total, xi, i) => total + xi * y[i], 0);
  const sumX2 = x.reduce((total, xi) => total + xi * xi, 0);

  const denominator = n * sumX2 - sumX * sumX;
  if (denominator === 0) {
    return { slope: 0, intercept: sumY / n, rSquared: 0 };
  }

  const slope = (n * sumXY - sumX * sumY) / denominator;
  const intercept = (sumY - slope * sumX) / n;

  // Calculate R-squared
  const yMean = sumY / n;
  const ssTotal = y.reduce((sum, yi) => sum + Math.pow(yi - yMean, 2), 0);
  const ssResidual = y.reduce(
    (sum, yi, i) => sum + Math.pow(yi - (slope * x[i] + intercept), 2),
    0
  );
  const rSquared = ssTotal === 0 ? 1 : 1 - ssResidual / ssTotal;

  return { slope, intercept, rSquared: Math.max(0, Math.min(1, rSquared)) };
}

/**
 * Calculate summary statistics for history
 */
function calculateHistorySummary(points: TrendDataPoint[]): VulnerabilityHistory["summary"] {
  if (points.length === 0) {
    return {
      avgTotal: 0,
      peakTotal: 0,
      minTotal: 0,
      totalNew: 0,
      totalFixed: 0,
      netChange: 0,
      trend: "stable",
    };
  }

  const totals = points.map((p) => p.total);
  const avgTotal = totals.reduce((a, b) => a + b, 0) / totals.length;
  const peakTotal = Math.max(...totals);
  const minTotal = Math.min(...totals);
  const totalNew = points.reduce((sum, p) => sum + p.newCount, 0);
  const totalFixed = points.reduce((sum, p) => sum + p.fixedCount, 0);
  const netChange = points.length > 1 ? points[points.length - 1].total - points[0].total : 0;

  // Determine trend using linear regression
  let trend: "improving" | "stable" | "worsening" = "stable";
  if (points.length >= 3) {
    const regression = linearRegression(
      points.map((_, i) => i),
      totals
    );
    if (regression.slope < -0.5) {
      trend = "improving";
    } else if (regression.slope > 0.5) {
      trend = "worsening";
    }
  }

  return {
    avgTotal: Math.round(avgTotal * 100) / 100,
    peakTotal,
    minTotal,
    totalNew,
    totalFixed,
    netChange,
    trend,
  };
}

/**
 * Get vulnerability history for a target
 */
export function getVulnerabilityHistory(options: GetHistoryOptions): VulnerabilityHistory {
  const database = getDb();

  // Parse dates
  const endDate = options.endDate ? new Date(options.endDate) : new Date();
  const startDate = options.startDate
    ? parseRelativeDate(options.startDate)
    : new Date(endDate.getTime() - 30 * 24 * 60 * 60 * 1000);

  const startDateStr = startDate.toISOString().split("T")[0];
  const endDateStr = endDate.toISOString().split("T")[0];

  // Query snapshots
  const rows = database
    .prepare(
      `SELECT * FROM trend_snapshots
       WHERE target = ? AND date >= ? AND date <= ?
       ORDER BY date ASC`
    )
    .all(options.target, startDateStr, endDateStr) as SnapshotRow[];

  // Convert to data points
  const dataPoints: TrendDataPoint[] = rows.map((row) => ({
    date: row.date,
    total: row.total,
    critical: row.critical,
    high: row.high,
    medium: row.medium,
    low: row.low,
    unknown: row.unknown,
    newCount: row.new_count,
    fixedCount: row.fixed_count,
    netChange: row.new_count - row.fixed_count,
  }));

  // Aggregate if needed based on granularity
  const granularity = options.granularity || "daily";
  const aggregatedPoints = aggregateByGranularity(dataPoints, granularity);

  // Calculate summary
  const summary = calculateHistorySummary(aggregatedPoints);

  // Calculate moving averages if requested
  let movingAverages: VulnerabilityHistory["movingAverages"];
  if (options.includeMovingAverages && granularity === "daily") {
    const totals = aggregatedPoints.map((p) => p.total);
    movingAverages = {
      ma7: calculateMovingAverage(totals, 7),
      ma30: calculateMovingAverage(totals, 30),
    };
  }

  return {
    target: options.target,
    targetType: (options.targetType || "image") as "image" | "project" | "organization",
    startDate: startDateStr,
    endDate: endDateStr,
    granularity,
    dataPoints: aggregatedPoints,
    summary,
    movingAverages,
  };
}

// =============================================================================
// Forecasting
// =============================================================================

/**
 * Calculate standard error for predictions
 */
function calculateStandardError(
  x: number[],
  y: number[],
  slope: number,
  intercept: number
): number {
  const n = x.length;
  if (n <= 2) return 0;

  const residuals = y.map((yi, i) => yi - (slope * x[i] + intercept));
  const sumSquaredResiduals = residuals.reduce((sum, r) => sum + r * r, 0);

  return Math.sqrt(sumSquaredResiduals / (n - 2));
}

/**
 * Calculate days to reach zero based on regression
 */
function calculateDaysToZero(
  regression: { slope: number; intercept: number },
  currentIndex: number,
  currentValue: number
): number | null {
  if (regression.slope >= 0) {
    // Not decreasing, won't reach zero
    return null;
  }

  if (currentValue === 0) {
    return 0;
  }

  // y = slope * x + intercept
  // 0 = slope * x + intercept
  // x = -intercept / slope
  const zeroX = -regression.intercept / regression.slope;
  const daysToZero = Math.ceil(zeroX - currentIndex);

  if (daysToZero <= 0) {
    return null;
  }

  // Cap at reasonable maximum
  return Math.min(daysToZero, 365);
}

/**
 * Create empty forecast when insufficient data
 */
function createEmptyForecast(options: GetForecastOptions, horizonDays: number): TrendForecast {
  return {
    target: options.target,
    targetType: (options.targetType || "image") as "image" | "project" | "organization",
    generatedAt: new Date().toISOString(),
    horizonDays,
    predictions: [],
    model: {
      type: "linear_regression",
      rSquared: 0,
      slope: 0,
      intercept: 0,
      confidence: 0,
    },
    insights: {
      daysToZeroCritical: null,
      daysToZeroHigh: null,
      totalIn7Days: 0,
      totalIn30Days: 0,
      riskTrend: "stable",
    },
  };
}

/**
 * Get forecast for a target
 */
export function getTrendForecast(options: GetForecastOptions): TrendForecast {
  const database = getDb();

  const horizonDays = options.horizonDays || 30;
  const historicalDays = options.historicalDays || 90;
  const confidenceLevel = options.confidenceLevel || 0.95;

  // Get historical data
  const endDate = new Date();
  const startDate = new Date(endDate.getTime() - historicalDays * 24 * 60 * 60 * 1000);

  const rows = database
    .prepare(
      `SELECT * FROM trend_snapshots
       WHERE target = ? AND date >= ? AND date <= ?
       ORDER BY date ASC`
    )
    .all(
      options.target,
      startDate.toISOString().split("T")[0],
      endDate.toISOString().split("T")[0]
    ) as SnapshotRow[];

  if (rows.length < 3) {
    // Not enough data for forecasting
    return createEmptyForecast(options, horizonDays);
  }

  // Prepare data for regression
  const xTotal = rows.map((_, i) => i);
  const yTotal = rows.map((r) => r.total);
  const yCritical = rows.map((r) => r.critical);
  const yHigh = rows.map((r) => r.high);

  // Perform linear regression
  const regressionTotal = linearRegression(xTotal, yTotal);
  const regressionCritical = linearRegression(xTotal, yCritical);
  const regressionHigh = linearRegression(xTotal, yHigh);

  // Calculate standard error for confidence intervals
  const stdError = calculateStandardError(
    xTotal,
    yTotal,
    regressionTotal.slope,
    regressionTotal.intercept
  );

  // Z-score for confidence interval (1.96 for 95%, 1.645 for 90%)
  const zScore = confidenceLevel >= 0.95 ? 1.96 : confidenceLevel >= 0.9 ? 1.645 : 1.28;

  // Generate predictions
  const predictions: TrendForecastPoint[] = [];
  const lastIndex = rows.length - 1;

  for (let i = 1; i <= horizonDays; i++) {
    const futureIndex = lastIndex + i;
    const predDate = new Date(endDate.getTime() + i * 24 * 60 * 60 * 1000);

    const predictedTotal = Math.max(
      0,
      Math.round(regressionTotal.slope * futureIndex + regressionTotal.intercept)
    );
    const predictedCritical = Math.max(
      0,
      Math.round(regressionCritical.slope * futureIndex + regressionCritical.intercept)
    );
    const predictedHigh = Math.max(
      0,
      Math.round(regressionHigh.slope * futureIndex + regressionHigh.intercept)
    );

    const margin =
      zScore *
      stdError *
      Math.sqrt(
        1 + 1 / rows.length + Math.pow(futureIndex - lastIndex / 2, 2) / (rows.length * 10)
      );

    predictions.push({
      date: predDate.toISOString().split("T")[0],
      predictedTotal,
      lowerBound: Math.max(0, Math.round(predictedTotal - margin)),
      upperBound: Math.round(predictedTotal + margin),
      predictedCritical,
      predictedHigh,
    });
  }

  // Calculate insights
  const lastRow = rows[rows.length - 1];
  const daysToZeroCritical = calculateDaysToZero(regressionCritical, lastIndex, lastRow.critical);
  const daysToZeroHigh = calculateDaysToZero(regressionHigh, lastIndex, lastRow.high);

  const totalIn7Days =
    predictions.length >= 7
      ? predictions[6].predictedTotal
      : predictions[predictions.length - 1].predictedTotal;
  const totalIn30Days =
    predictions.length >= 30
      ? predictions[29].predictedTotal
      : predictions[predictions.length - 1].predictedTotal;

  let riskTrend: "decreasing" | "stable" | "increasing" = "stable";
  if (regressionTotal.slope < -0.5) {
    riskTrend = "decreasing";
  } else if (regressionTotal.slope > 0.5) {
    riskTrend = "increasing";
  }

  return {
    target: options.target,
    targetType: (options.targetType || "image") as "image" | "project" | "organization",
    generatedAt: new Date().toISOString(),
    horizonDays,
    predictions,
    model: {
      type: "linear_regression",
      rSquared: regressionTotal.rSquared,
      slope: regressionTotal.slope,
      intercept: regressionTotal.intercept,
      confidence: confidenceLevel,
    },
    insights: {
      daysToZeroCritical,
      daysToZeroHigh,
      totalIn7Days,
      totalIn30Days,
      riskTrend,
    },
  };
}

// =============================================================================
// Anomaly Detection
// =============================================================================

/**
 * Calculate mean of an array
 */
function mean(arr: number[]): number {
  if (arr.length === 0) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

/**
 * Calculate standard deviation
 */
function standardDeviation(arr: number[]): number {
  if (arr.length === 0) return 0;
  const avg = mean(arr);
  const squareDiffs = arr.map((value) => Math.pow(value - avg, 2));
  return Math.sqrt(mean(squareDiffs));
}

/**
 * Determine anomaly severity based on z-score and deviation
 */
function determineSeverity(zScore: number, deviationPercent: number): "low" | "medium" | "high" {
  if (zScore >= 3 || deviationPercent >= 100) {
    return "high";
  } else if (zScore >= 2.5 || deviationPercent >= 50) {
    return "medium";
  }
  return "low";
}

/**
 * Generate human-readable anomaly description
 */
function generateAnomalyDescription(
  metric: string,
  isSpike: boolean,
  value: number,
  expected: number,
  deviationPercent: number
): string {
  const direction = isSpike ? "increased" : "decreased";
  const metricLabel =
    metric === "new"
      ? "new vulnerabilities"
      : metric === "fixed"
        ? "fixed vulnerabilities"
        : `${metric} vulnerabilities`;

  return `${metricLabel.charAt(0).toUpperCase() + metricLabel.slice(1)} ${direction} to ${value} (expected ~${Math.round(expected)}, ${Math.round(deviationPercent)}% deviation)`;
}

/**
 * Detect anomalies in vulnerability trends
 */
export function detectTrendAnomalies(options: DetectAnomaliesOptions): AnomalyDetectionResult {
  const database = getDb();

  const zScoreThreshold = options.zScoreThreshold || 2.0;
  const minDeviationPercent = options.minDeviationPercent || 20;

  // Get historical data
  const endDate = options.endDate ? new Date(options.endDate) : new Date();
  const startDate = options.startDate
    ? parseRelativeDate(options.startDate)
    : new Date(endDate.getTime() - 90 * 24 * 60 * 60 * 1000);

  const rows = database
    .prepare(
      `SELECT * FROM trend_snapshots
       WHERE target = ? AND date >= ? AND date <= ?
       ORDER BY date ASC`
    )
    .all(
      options.target,
      startDate.toISOString().split("T")[0],
      endDate.toISOString().split("T")[0]
    ) as SnapshotRow[];

  const anomalies: TrendAnomaly[] = [];

  if (rows.length < 5) {
    // Not enough data for meaningful anomaly detection
    return {
      target: options.target,
      targetType: (options.targetType || "image") as "image" | "project" | "organization",
      startDate: startDate.toISOString().split("T")[0],
      endDate: endDate.toISOString().split("T")[0],
      anomalies: [],
      parameters: { zScoreThreshold, minDeviationPercent },
      summary: {
        totalAnomalies: 0,
        highSeverity: 0,
        spikes: 0,
        drops: 0,
      },
    };
  }

  // Analyze each metric
  const metrics: Array<{
    name: "total" | "critical" | "high" | "new" | "fixed";
    values: number[];
  }> = [
    { name: "total", values: rows.map((r) => r.total) },
    { name: "critical", values: rows.map((r) => r.critical) },
    { name: "high", values: rows.map((r) => r.high) },
    { name: "new", values: rows.map((r) => r.new_count) },
    { name: "fixed", values: rows.map((r) => r.fixed_count) },
  ];

  for (const metric of metrics) {
    const avg = mean(metric.values);
    const std = standardDeviation(metric.values);

    if (std === 0) continue; // No variation

    for (let i = 0; i < rows.length; i++) {
      const value = metric.values[i];
      const zScore = (value - avg) / std;
      const deviationPercent = avg !== 0 ? Math.abs((value - avg) / avg) * 100 : 0;

      if (Math.abs(zScore) >= zScoreThreshold && deviationPercent >= minDeviationPercent) {
        const isSpike = zScore > 0;
        const severity = determineSeverity(Math.abs(zScore), deviationPercent);

        anomalies.push({
          date: rows[i].date,
          type: isSpike ? "spike" : "drop",
          severity,
          metric: metric.name,
          actualValue: value,
          expectedValue: Math.round(avg * 100) / 100,
          zScore: Math.round(zScore * 100) / 100,
          deviationPercent: Math.round(deviationPercent * 100) / 100,
          description: generateAnomalyDescription(
            metric.name,
            isSpike,
            value,
            avg,
            deviationPercent
          ),
        });
      }
    }
  }

  // Sort by date and severity
  anomalies.sort((a, b) => {
    const dateCompare = a.date.localeCompare(b.date);
    if (dateCompare !== 0) return dateCompare;
    const severityOrder = { high: 0, medium: 1, low: 2 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });

  return {
    target: options.target,
    targetType: (options.targetType || "image") as "image" | "project" | "organization",
    startDate: startDate.toISOString().split("T")[0],
    endDate: endDate.toISOString().split("T")[0],
    anomalies,
    parameters: { zScoreThreshold, minDeviationPercent },
    summary: {
      totalAnomalies: anomalies.length,
      highSeverity: anomalies.filter((a) => a.severity === "high").length,
      spikes: anomalies.filter((a) => a.type === "spike").length,
      drops: anomalies.filter((a) => a.type === "drop").length,
    },
  };
}

// =============================================================================
// Period Comparison
// =============================================================================

interface PeriodMetrics {
  avgTotal: number;
  avgCritical: number;
  avgHigh: number;
  avgMedium: number;
  avgLow: number;
  avgNew: number;
  avgFixed: number;
}

/**
 * Calculate metrics for a period
 */
function calculatePeriodMetrics(rows: SnapshotRow[]): PeriodMetrics {
  if (rows.length === 0) {
    return {
      avgTotal: 0,
      avgCritical: 0,
      avgHigh: 0,
      avgMedium: 0,
      avgLow: 0,
      avgNew: 0,
      avgFixed: 0,
    };
  }

  return {
    avgTotal: mean(rows.map((r) => r.total)),
    avgCritical: mean(rows.map((r) => r.critical)),
    avgHigh: mean(rows.map((r) => r.high)),
    avgMedium: mean(rows.map((r) => r.medium)),
    avgLow: mean(rows.map((r) => r.low)),
    avgNew: mean(rows.map((r) => r.new_count)),
    avgFixed: mean(rows.map((r) => r.fixed_count)),
  };
}

/**
 * Compare two metric values
 */
function compareMetric(period1Value: number, period2Value: number): MetricComparison {
  const absoluteChange = period2Value - period1Value;
  const percentChange =
    period1Value !== 0 ? (absoluteChange / period1Value) * 100 : period2Value !== 0 ? 100 : 0;

  let direction: "increased" | "unchanged" | "decreased" = "unchanged";
  if (Math.abs(percentChange) >= 5) {
    direction = absoluteChange > 0 ? "increased" : "decreased";
  }

  return {
    period1Value: Math.round(period1Value * 100) / 100,
    period2Value: Math.round(period2Value * 100) / 100,
    absoluteChange: Math.round(absoluteChange * 100) / 100,
    percentChange: Math.round(percentChange * 100) / 100,
    direction,
  };
}

/**
 * Generate overall assessment for period comparison
 */
function generateAssessment(
  comparison: PeriodComparison["comparison"],
  period1Count: number,
  period2Count: number
): PeriodComparison["assessment"] {
  const observations: string[] = [];

  // Determine overall direction
  let improvedCount = 0;
  let worsenedCount = 0;

  // Critical and high are most important
  if (comparison.critical.direction === "decreased") {
    improvedCount += 2;
    observations.push(
      `Critical vulnerabilities decreased by ${Math.abs(comparison.critical.percentChange).toFixed(1)}%`
    );
  } else if (comparison.critical.direction === "increased") {
    worsenedCount += 2;
    observations.push(
      `Critical vulnerabilities increased by ${comparison.critical.percentChange.toFixed(1)}%`
    );
  }

  if (comparison.high.direction === "decreased") {
    improvedCount += 1;
    observations.push(
      `High vulnerabilities decreased by ${Math.abs(comparison.high.percentChange).toFixed(1)}%`
    );
  } else if (comparison.high.direction === "increased") {
    worsenedCount += 1;
    observations.push(
      `High vulnerabilities increased by ${comparison.high.percentChange.toFixed(1)}%`
    );
  }

  if (comparison.total.direction === "decreased") {
    improvedCount += 1;
    observations.push(
      `Total vulnerabilities decreased by ${Math.abs(comparison.total.percentChange).toFixed(1)}%`
    );
  } else if (comparison.total.direction === "increased") {
    worsenedCount += 1;
    observations.push(
      `Total vulnerabilities increased by ${comparison.total.percentChange.toFixed(1)}%`
    );
  }

  // Fix rate is positive
  if (comparison.fixRate.direction === "increased") {
    improvedCount += 1;
    observations.push(`Fix rate improved by ${comparison.fixRate.percentChange.toFixed(1)}%`);
  } else if (comparison.fixRate.direction === "decreased") {
    worsenedCount += 1;
  }

  // New rate is negative
  if (comparison.newRate.direction === "decreased") {
    improvedCount += 1;
    observations.push(
      `New vulnerability rate decreased by ${Math.abs(comparison.newRate.percentChange).toFixed(1)}%`
    );
  } else if (comparison.newRate.direction === "increased") {
    worsenedCount += 1;
  }

  // Determine overall direction
  let direction: "improved" | "unchanged" | "worsened" = "unchanged";
  if (improvedCount > worsenedCount + 1) {
    direction = "improved";
  } else if (worsenedCount > improvedCount + 1) {
    direction = "worsened";
  }

  // Determine confidence based on data availability
  let confidence: "low" | "medium" | "high" = "medium";
  const minDataPoints = Math.min(period1Count, period2Count);
  if (minDataPoints >= 14) {
    confidence = "high";
  } else if (minDataPoints < 5) {
    confidence = "low";
    observations.push("Limited data available for comparison");
  }

  if (observations.length === 0) {
    observations.push("No significant changes detected between periods");
  }

  return { direction, confidence, observations };
}

/**
 * Compare two time periods
 */
export function compareTrendPeriods(options: ComparePeriodOptions): PeriodComparison {
  const database = getDb();

  // Get data for period 1
  const period1Rows = database
    .prepare(
      `SELECT * FROM trend_snapshots
       WHERE target = ? AND date >= ? AND date <= ?
       ORDER BY date ASC`
    )
    .all(options.target, options.period1Start, options.period1End) as SnapshotRow[];

  // Get data for period 2
  const period2Rows = database
    .prepare(
      `SELECT * FROM trend_snapshots
       WHERE target = ? AND date >= ? AND date <= ?
       ORDER BY date ASC`
    )
    .all(options.target, options.period2Start, options.period2End) as SnapshotRow[];

  // Calculate metrics for each period
  const period1Metrics = calculatePeriodMetrics(period1Rows);
  const period2Metrics = calculatePeriodMetrics(period2Rows);

  // Compare metrics
  const comparison = {
    total: compareMetric(period1Metrics.avgTotal, period2Metrics.avgTotal),
    critical: compareMetric(period1Metrics.avgCritical, period2Metrics.avgCritical),
    high: compareMetric(period1Metrics.avgHigh, period2Metrics.avgHigh),
    medium: compareMetric(period1Metrics.avgMedium, period2Metrics.avgMedium),
    low: compareMetric(period1Metrics.avgLow, period2Metrics.avgLow),
    newRate: compareMetric(period1Metrics.avgNew, period2Metrics.avgNew),
    fixRate: compareMetric(period1Metrics.avgFixed, period2Metrics.avgFixed),
  };

  // Generate assessment
  const assessment = generateAssessment(comparison, period1Rows.length, period2Rows.length);

  return {
    target: options.target,
    targetType: (options.targetType || "image") as "image" | "project" | "organization",
    period1: {
      startDate: options.period1Start,
      endDate: options.period1End,
      label: options.period1Label || "Period 1",
    },
    period2: {
      startDate: options.period2Start,
      endDate: options.period2End,
      label: options.period2Label || "Period 2",
    },
    comparison,
    assessment,
  };
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * List all tracked targets
 */
export function listTrendTargets(): Array<{
  target: string;
  targetType: string;
  snapshotCount: number;
  firstDate: string;
  lastDate: string;
}> {
  const database = getDb();

  const rows = database
    .prepare(
      `SELECT
        target,
        target_type,
        COUNT(*) as snapshot_count,
        MIN(date) as first_date,
        MAX(date) as last_date
       FROM trend_snapshots
       GROUP BY target, target_type
       ORDER BY last_date DESC`
    )
    .all() as Array<{
    target: string;
    target_type: string;
    snapshot_count: number;
    first_date: string;
    last_date: string;
  }>;

  return rows.map((r) => ({
    target: r.target,
    targetType: r.target_type,
    snapshotCount: r.snapshot_count,
    firstDate: r.first_date,
    lastDate: r.last_date,
  }));
}

/**
 * Delete old snapshots
 */
export function cleanupTrendSnapshots(retentionDays: number): number {
  const database = getDb();
  const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000)
    .toISOString()
    .split("T")[0];

  const result = database.prepare("DELETE FROM trend_snapshots WHERE date < ?").run(cutoffDate);

  return result.changes;
}

/**
 * Get snapshot count for a target
 */
export function getTrendSnapshotCount(target: string): number {
  const database = getDb();
  const row = database
    .prepare("SELECT COUNT(*) as count FROM trend_snapshots WHERE target = ?")
    .get(target) as { count: number };

  return row.count;
}
