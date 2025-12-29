/**
 * Risk Scoring Module
 *
 * CVSS-based risk scoring with business context for vulnerability prioritization.
 *
 * Risk Formula:
 * risk_score = base_cvss * exploitability * asset_criticality * exposure * age_factor
 *
 * Where:
 * - base_cvss: CVSS base score (0-10)
 * - exploitability: 1.0-2.0 based on exploit availability
 * - asset_criticality: 0.5-2.0 based on business importance
 * - exposure: 0.5-2.0 based on network exposure
 * - age_factor: 1.0-1.5 based on time since first detection
 *
 * Final score is normalized to 0-100 scale.
 */

import Database from "better-sqlite3";
import { randomUUID } from "crypto";
import type {
  RiskAssetCriticality,
  RiskExposureLevel,
  RiskTier,
  RiskAssetConfig,
  ExploitabilityFactors,
  RiskScore,
  CalculateRiskOptions,
  PrioritizedVulnerability,
  GetPrioritizedListOptions,
  PrioritizedListResult,
  RiskDbInitResult,
  SetAssetCriticalityOptions,
  RiskConfig,
} from "./types.js";

// =============================================================================
// Database Schema
// =============================================================================

const SCHEMA_SQL = `
-- Asset criticality configuration
CREATE TABLE IF NOT EXISTS risk_assets (
  id TEXT PRIMARY KEY,
  asset TEXT NOT NULL UNIQUE,
  asset_type TEXT NOT NULL,
  criticality TEXT NOT NULL,
  exposure TEXT NOT NULL,
  business_context TEXT,
  owner TEXT,
  compliance_frameworks_json TEXT,
  custom_multiplier REAL DEFAULT 1.0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Cached risk scores for vulnerabilities
CREATE TABLE IF NOT EXISTS risk_scores (
  id TEXT PRIMARY KEY,
  vuln_id TEXT NOT NULL,
  asset TEXT NOT NULL,
  base_cvss REAL NOT NULL,
  exploitability_multiplier REAL NOT NULL,
  asset_criticality_multiplier REAL NOT NULL,
  exposure_multiplier REAL NOT NULL,
  age_factor REAL NOT NULL,
  risk_score REAL NOT NULL,
  risk_tier TEXT NOT NULL,
  first_detected TEXT,
  age_in_days INTEGER,
  recommendation TEXT,
  calculated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(vuln_id, asset)
);

-- Risk configuration
CREATE TABLE IF NOT EXISTS risk_config (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_risk_assets_asset ON risk_assets(asset);
CREATE INDEX IF NOT EXISTS idx_risk_scores_vuln ON risk_scores(vuln_id);
CREATE INDEX IF NOT EXISTS idx_risk_scores_asset ON risk_scores(asset);
CREATE INDEX IF NOT EXISTS idx_risk_scores_tier ON risk_scores(risk_tier);
CREATE INDEX IF NOT EXISTS idx_risk_scores_score ON risk_scores(risk_score DESC);
`;

// =============================================================================
// Default Configuration
// =============================================================================

const DEFAULT_CONFIG: RiskConfig = {
  defaultCriticality: "medium",
  defaultExposure: "internal-only",
  tierThresholds: {
    critical: 80,
    high: 60,
    medium: 40,
    low: 20,
  },
  ageFactorConfig: {
    startDays: 7,
    maxFactor: 1.5,
    maxDays: 90,
  },
  weights: {
    exploitability: 1.0,
    assetCriticality: 1.0,
    exposure: 1.0,
    age: 1.0,
  },
};

// Criticality multipliers
const CRITICALITY_MULTIPLIERS: Record<RiskAssetCriticality, number> = {
  critical: 2.0,
  high: 1.5,
  medium: 1.0,
  low: 0.7,
  minimal: 0.5,
};

// Exposure multipliers
const EXPOSURE_MULTIPLIERS: Record<RiskExposureLevel, number> = {
  "internet-facing": 2.0,
  "internal-only": 1.0,
  "air-gapped": 0.5,
  development: 0.6,
};

// =============================================================================
// Database Connection
// =============================================================================

let db: Database.Database | null = null;

/**
 * Initialize the risk scoring database
 */
export function initRiskDatabase(dbPath?: string): RiskDbInitResult {
  try {
    const path = dbPath || ":memory:";
    db = new Database(path);
    db.pragma("journal_mode = WAL");
    db.exec(SCHEMA_SQL);

    // Initialize default config if not exists
    const configStmt = db.prepare("SELECT COUNT(*) as count FROM risk_config WHERE key = 'global'");
    const result = configStmt.get() as { count: number };
    if (result.count === 0) {
      const insertStmt = db.prepare("INSERT INTO risk_config (key, value_json) VALUES (?, ?)");
      insertStmt.run("global", JSON.stringify(DEFAULT_CONFIG));
    }

    return {
      success: true,
      path,
      created: new Date().toISOString(),
    };
  } catch (error) {
    return {
      success: false,
      path: dbPath || ":memory:",
      created: new Date().toISOString(),
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Close the risk scoring database
 */
export function closeRiskDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

/**
 * Check if database is initialized
 */
export function isRiskDbInitialized(): boolean {
  return db !== null;
}

/**
 * Get database instance (throws if not initialized)
 */
function getDb(): Database.Database {
  if (!db) {
    throw new Error("Risk database not initialized. Call initRiskDatabase() first.");
  }
  return db;
}

// =============================================================================
// Configuration Management
// =============================================================================

/**
 * Get the current risk configuration
 */
export function getRiskConfig(): RiskConfig {
  const database = getDb();
  const stmt = database.prepare("SELECT value_json FROM risk_config WHERE key = 'global'");
  const row = stmt.get() as { value_json: string } | undefined;
  if (row) {
    return JSON.parse(row.value_json) as RiskConfig;
  }
  return DEFAULT_CONFIG;
}

/**
 * Update risk configuration
 */
export function updateRiskConfig(config: Partial<RiskConfig>): RiskConfig {
  const database = getDb();
  const current = getRiskConfig();
  const updated = { ...current, ...config };
  const stmt = database.prepare(
    "UPDATE risk_config SET value_json = ?, updated_at = CURRENT_TIMESTAMP WHERE key = 'global'"
  );
  stmt.run(JSON.stringify(updated));
  return updated;
}

// =============================================================================
// Asset Criticality Management
// =============================================================================

/**
 * Set or update asset criticality configuration
 */
export function setAssetCriticality(options: SetAssetCriticalityOptions): RiskAssetConfig {
  const database = getDb();

  // Check if exists
  const existsStmt = database.prepare("SELECT id FROM risk_assets WHERE asset = ?");
  const existing = existsStmt.get(options.asset) as { id: string } | undefined;

  const config: RiskAssetConfig = {
    asset: options.asset,
    assetType: options.assetType,
    criticality: options.criticality,
    exposure: options.exposure,
    businessContext: options.businessContext,
    owner: options.owner,
    complianceFrameworks: options.complianceFrameworks,
    customMultiplier: options.customMultiplier ?? 1.0,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  if (existing) {
    const updateStmt = database.prepare(`
      UPDATE risk_assets SET
        asset_type = ?,
        criticality = ?,
        exposure = ?,
        business_context = ?,
        owner = ?,
        compliance_frameworks_json = ?,
        custom_multiplier = ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE asset = ?
    `);
    updateStmt.run(
      config.assetType,
      config.criticality,
      config.exposure,
      config.businessContext || null,
      config.owner || null,
      config.complianceFrameworks ? JSON.stringify(config.complianceFrameworks) : null,
      config.customMultiplier,
      options.asset
    );
  } else {
    const insertStmt = database.prepare(`
      INSERT INTO risk_assets (
        id, asset, asset_type, criticality, exposure, business_context,
        owner, compliance_frameworks_json, custom_multiplier
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertStmt.run(
      randomUUID(),
      config.asset,
      config.assetType,
      config.criticality,
      config.exposure,
      config.businessContext || null,
      config.owner || null,
      config.complianceFrameworks ? JSON.stringify(config.complianceFrameworks) : null,
      config.customMultiplier
    );
  }

  // Invalidate cached scores for this asset
  const deleteStmt = database.prepare("DELETE FROM risk_scores WHERE asset = ?");
  deleteStmt.run(options.asset);

  return config;
}

/**
 * Get asset criticality configuration
 */
export function getAssetConfig(asset: string): RiskAssetConfig | null {
  const database = getDb();
  const stmt = database.prepare("SELECT * FROM risk_assets WHERE asset = ?");
  const row = stmt.get(asset) as
    | {
        id: string;
        asset: string;
        asset_type: string;
        criticality: string;
        exposure: string;
        business_context: string | null;
        owner: string | null;
        compliance_frameworks_json: string | null;
        custom_multiplier: number;
        created_at: string;
        updated_at: string;
      }
    | undefined;

  if (!row) {
    return null;
  }

  return {
    asset: row.asset,
    assetType: row.asset_type as RiskAssetConfig["assetType"],
    criticality: row.criticality as RiskAssetCriticality,
    exposure: row.exposure as RiskExposureLevel,
    businessContext: row.business_context || undefined,
    owner: row.owner || undefined,
    complianceFrameworks: row.compliance_frameworks_json
      ? JSON.parse(row.compliance_frameworks_json)
      : undefined,
    customMultiplier: row.custom_multiplier,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * List all asset configurations
 */
export function listAssetConfigs(): RiskAssetConfig[] {
  const database = getDb();
  const stmt = database.prepare("SELECT * FROM risk_assets ORDER BY criticality DESC, asset");
  const rows = stmt.all() as Array<{
    id: string;
    asset: string;
    asset_type: string;
    criticality: string;
    exposure: string;
    business_context: string | null;
    owner: string | null;
    compliance_frameworks_json: string | null;
    custom_multiplier: number;
    created_at: string;
    updated_at: string;
  }>;

  return rows.map((row) => ({
    asset: row.asset,
    assetType: row.asset_type as RiskAssetConfig["assetType"],
    criticality: row.criticality as RiskAssetCriticality,
    exposure: row.exposure as RiskExposureLevel,
    businessContext: row.business_context || undefined,
    owner: row.owner || undefined,
    complianceFrameworks: row.compliance_frameworks_json
      ? JSON.parse(row.compliance_frameworks_json)
      : undefined,
    customMultiplier: row.custom_multiplier,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

/**
 * Delete asset configuration
 */
export function deleteAssetConfig(asset: string): boolean {
  const database = getDb();
  const stmt = database.prepare("DELETE FROM risk_assets WHERE asset = ?");
  const result = stmt.run(asset);

  // Also delete cached scores
  const deleteScores = database.prepare("DELETE FROM risk_scores WHERE asset = ?");
  deleteScores.run(asset);

  return result.changes > 0;
}

// =============================================================================
// Risk Calculation
// =============================================================================

/**
 * Calculate exploitability multiplier based on threat intelligence
 */
function calculateExploitabilityMultiplier(factors?: ExploitabilityFactors): number {
  if (!factors) {
    return 1.0;
  }

  let multiplier = 1.0;

  // Each factor adds to the multiplier
  if (factors.pocAvailable) multiplier += 0.1;
  if (factors.exploitInWild) multiplier += 0.2;
  if (factors.weaponized) multiplier += 0.3;
  if (factors.activelyExploited) multiplier += 0.3;
  if (factors.cisaKev) multiplier += 0.3;

  // EPSS score can add up to 0.5
  if (factors.epssScore !== undefined) {
    multiplier += factors.epssScore * 0.5;
  }

  // Cap at 2.0
  return Math.min(multiplier, 2.0);
}

/**
 * Calculate age factor based on days since first detection
 */
function calculateAgeFactor(
  firstDetected?: string,
  config?: RiskConfig["ageFactorConfig"]
): { factor: number; ageInDays: number } {
  if (!firstDetected) {
    return { factor: 1.0, ageInDays: 0 };
  }

  const ageConfig = config || DEFAULT_CONFIG.ageFactorConfig;
  const firstDate = new Date(firstDetected);
  const now = new Date();
  const ageInDays = Math.floor((now.getTime() - firstDate.getTime()) / (1000 * 60 * 60 * 24));

  if (ageInDays <= ageConfig.startDays) {
    return { factor: 1.0, ageInDays };
  }

  // Linear interpolation from startDays to maxDays
  const daysAboveStart = ageInDays - ageConfig.startDays;
  const maxDaysRange = ageConfig.maxDays - ageConfig.startDays;
  const progress = Math.min(daysAboveStart / maxDaysRange, 1.0);
  const factor = 1.0 + progress * (ageConfig.maxFactor - 1.0);

  return { factor, ageInDays };
}

/**
 * Determine risk tier from score
 */
function getRiskTier(score: number, thresholds?: RiskConfig["tierThresholds"]): RiskTier {
  const t = thresholds || DEFAULT_CONFIG.tierThresholds;
  if (score >= t.critical) return "critical";
  if (score >= t.high) return "high";
  if (score >= t.medium) return "medium";
  if (score >= t.low) return "low";
  return "minimal";
}

/**
 * Generate remediation recommendation based on risk factors
 */
function generateRecommendation(
  riskScore: number,
  exploitabilityMultiplier: number,
  ageFactor: number
): string {
  const recommendations: string[] = [];

  if (riskScore >= 80) {
    recommendations.push("IMMEDIATE ACTION REQUIRED.");
  } else if (riskScore >= 60) {
    recommendations.push("High priority remediation needed.");
  } else if (riskScore >= 40) {
    recommendations.push("Schedule remediation in next sprint.");
  } else {
    recommendations.push("Monitor and remediate as resources allow.");
  }

  if (exploitabilityMultiplier > 1.5) {
    recommendations.push("Active exploitation reported - prioritize this fix.");
  }

  if (ageFactor > 1.3) {
    recommendations.push("Vulnerability has been open for extended period.");
  }

  return recommendations.join(" ");
}

/**
 * Calculate risk score for a vulnerability
 */
export function calculateRiskScore(options: CalculateRiskOptions): RiskScore {
  const config = isRiskDbInitialized() ? getRiskConfig() : DEFAULT_CONFIG;
  const weights = options.weights || config.weights;

  // Get asset configuration
  let assetConfig: RiskAssetConfig;
  if (typeof options.asset === "string") {
    const stored = isRiskDbInitialized() ? getAssetConfig(options.asset) : null;
    if (stored) {
      assetConfig = stored;
    } else {
      // Use defaults
      assetConfig = {
        asset: options.asset,
        assetType: "image",
        criticality: config.defaultCriticality,
        exposure: config.defaultExposure,
        customMultiplier: 1.0,
      };
    }
  } else {
    assetConfig = options.asset;
  }

  // Calculate multipliers
  const exploitabilityMultiplier = calculateExploitabilityMultiplier(options.exploitability);
  const assetCriticalityMultiplier =
    CRITICALITY_MULTIPLIERS[assetConfig.criticality] * (assetConfig.customMultiplier || 1.0);
  const exposureMultiplier = EXPOSURE_MULTIPLIERS[assetConfig.exposure];
  const { factor: ageFactor, ageInDays } = calculateAgeFactor(
    options.firstDetected,
    config.ageFactorConfig
  );

  // Apply weights
  const weightedExploitability =
    1 + (exploitabilityMultiplier - 1) * (weights.exploitability || 1.0);
  const weightedCriticality =
    1 + (assetCriticalityMultiplier - 1) * (weights.assetCriticality || 1.0);
  const weightedExposure = 1 + (exposureMultiplier - 1) * (weights.exposure || 1.0);
  const weightedAge = 1 + (ageFactor - 1) * (weights.age || 1.0);

  // Calculate final score (normalize CVSS to 0-100, then apply multipliers)
  const baseScore = options.cvss.baseScore * 10; // 0-100
  const rawScore =
    baseScore * weightedExploitability * weightedCriticality * weightedExposure * weightedAge;

  // Normalize to 0-100 (cap at 100)
  const riskScore = Math.min(Math.round(rawScore), 100);

  const recommendation = generateRecommendation(riskScore, exploitabilityMultiplier, ageFactor);

  return {
    vulnId: options.vulnId,
    baseCvss: options.cvss.baseScore,
    exploitabilityMultiplier,
    assetCriticalityMultiplier,
    exposureMultiplier,
    ageFactor,
    riskScore,
    riskTier: getRiskTier(riskScore, config.tierThresholds),
    recommendation,
    ageInDays,
  };
}

/**
 * Store a calculated risk score in the database
 */
export function storeRiskScore(score: RiskScore, asset: string, firstDetected?: string): void {
  const database = getDb();

  // Use upsert pattern
  const stmt = database.prepare(`
    INSERT INTO risk_scores (
      id, vuln_id, asset, base_cvss, exploitability_multiplier,
      asset_criticality_multiplier, exposure_multiplier, age_factor,
      risk_score, risk_tier, first_detected, age_in_days, recommendation
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(vuln_id, asset) DO UPDATE SET
      base_cvss = excluded.base_cvss,
      exploitability_multiplier = excluded.exploitability_multiplier,
      asset_criticality_multiplier = excluded.asset_criticality_multiplier,
      exposure_multiplier = excluded.exposure_multiplier,
      age_factor = excluded.age_factor,
      risk_score = excluded.risk_score,
      risk_tier = excluded.risk_tier,
      first_detected = excluded.first_detected,
      age_in_days = excluded.age_in_days,
      recommendation = excluded.recommendation,
      calculated_at = CURRENT_TIMESTAMP
  `);

  stmt.run(
    randomUUID(),
    score.vulnId,
    asset,
    score.baseCvss,
    score.exploitabilityMultiplier,
    score.assetCriticalityMultiplier,
    score.exposureMultiplier,
    score.ageFactor,
    score.riskScore,
    score.riskTier,
    firstDetected || null,
    score.ageInDays || null,
    score.recommendation || null
  );
}

/**
 * Get stored risk score for a vulnerability
 */
export function getStoredRiskScore(vulnId: string, asset: string): RiskScore | null {
  const database = getDb();
  const stmt = database.prepare("SELECT * FROM risk_scores WHERE vuln_id = ? AND asset = ?");
  const row = stmt.get(vulnId, asset) as
    | {
        vuln_id: string;
        base_cvss: number;
        exploitability_multiplier: number;
        asset_criticality_multiplier: number;
        exposure_multiplier: number;
        age_factor: number;
        risk_score: number;
        risk_tier: string;
        age_in_days: number | null;
        recommendation: string | null;
      }
    | undefined;

  if (!row) {
    return null;
  }

  return {
    vulnId: row.vuln_id,
    baseCvss: row.base_cvss,
    exploitabilityMultiplier: row.exploitability_multiplier,
    assetCriticalityMultiplier: row.asset_criticality_multiplier,
    exposureMultiplier: row.exposure_multiplier,
    ageFactor: row.age_factor,
    riskScore: row.risk_score,
    riskTier: row.risk_tier as RiskTier,
    ageInDays: row.age_in_days || undefined,
    recommendation: row.recommendation || undefined,
  };
}

// =============================================================================
// Prioritized Vulnerability List
// =============================================================================

/**
 * Get prioritized list of vulnerabilities based on risk scores
 */
export function getPrioritizedList(options?: GetPrioritizedListOptions): PrioritizedListResult {
  const database = getDb();
  const opts = options || {};

  // Build query
  let query = "SELECT * FROM risk_scores WHERE 1=1";
  const params: (string | number)[] = [];

  if (opts.assets && opts.assets.length > 0) {
    const placeholders = opts.assets.map(() => "?").join(", ");
    query += ` AND asset IN (${placeholders})`;
    params.push(...opts.assets);
  }

  if (opts.minRiskScore !== undefined) {
    query += " AND risk_score >= ?";
    params.push(opts.minRiskScore);
  }

  if (opts.includeTiers && opts.includeTiers.length > 0) {
    const placeholders = opts.includeTiers.map(() => "?").join(", ");
    query += ` AND risk_tier IN (${placeholders})`;
    params.push(...opts.includeTiers);
  }

  query += " ORDER BY risk_score DESC";

  if (opts.limit) {
    query += " LIMIT ?";
    params.push(opts.limit);
  }

  const stmt = database.prepare(query);
  const rows = stmt.all(...params) as Array<{
    vuln_id: string;
    asset: string;
    base_cvss: number;
    exploitability_multiplier: number;
    asset_criticality_multiplier: number;
    exposure_multiplier: number;
    age_factor: number;
    risk_score: number;
    risk_tier: string;
    first_detected: string | null;
    age_in_days: number | null;
    recommendation: string | null;
  }>;

  // Get total count
  const countStmt = database.prepare("SELECT COUNT(*) as count FROM risk_scores");
  const countResult = countStmt.get() as { count: number };

  // Build prioritized list
  const vulnerabilities: PrioritizedVulnerability[] = rows.map((row, index) => ({
    vulnId: row.vuln_id,
    asset: row.asset,
    riskScore: {
      vulnId: row.vuln_id,
      baseCvss: row.base_cvss,
      exploitabilityMultiplier: row.exploitability_multiplier,
      assetCriticalityMultiplier: row.asset_criticality_multiplier,
      exposureMultiplier: row.exposure_multiplier,
      ageFactor: row.age_factor,
      riskScore: row.risk_score,
      riskTier: row.risk_tier as RiskTier,
      priorityRank: index + 1,
      ageInDays: row.age_in_days || undefined,
      recommendation: row.recommendation || undefined,
    },
    firstDetected: row.first_detected || undefined,
    remediation: row.recommendation || undefined,
  }));

  // Calculate tier summary
  const tierSummary: Record<RiskTier, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    minimal: 0,
  };

  for (const vuln of vulnerabilities) {
    tierSummary[vuln.riskScore.riskTier]++;
  }

  // Calculate asset summary if requested
  let assetSummary: Record<string, { count: number; avgRiskScore: number }> | undefined;

  if (opts.groupByAsset) {
    assetSummary = {};
    for (const vuln of vulnerabilities) {
      if (!assetSummary[vuln.asset]) {
        assetSummary[vuln.asset] = { count: 0, avgRiskScore: 0 };
      }
      assetSummary[vuln.asset].count++;
      assetSummary[vuln.asset].avgRiskScore += vuln.riskScore.riskScore;
    }
    // Calculate averages
    for (const asset of Object.keys(assetSummary)) {
      assetSummary[asset].avgRiskScore = Math.round(
        assetSummary[asset].avgRiskScore / assetSummary[asset].count
      );
    }
  }

  return {
    totalAnalyzed: countResult.count,
    included: vulnerabilities.length,
    vulnerabilities,
    tierSummary,
    assetSummary,
    generatedAt: new Date().toISOString(),
  };
}

/**
 * Clear all cached risk scores
 */
export function clearRiskScores(): number {
  const database = getDb();
  const stmt = database.prepare("DELETE FROM risk_scores");
  const result = stmt.run();
  return result.changes;
}

/**
 * Get risk scoring statistics
 */
export function getRiskStats(): {
  totalAssets: number;
  totalScores: number;
  tierDistribution: Record<RiskTier, number>;
  avgRiskScore: number;
  criticalCount: number;
  highCount: number;
} {
  const database = getDb();

  const assetCount = database.prepare("SELECT COUNT(*) as count FROM risk_assets").get() as {
    count: number;
  };

  const scoreStats = database
    .prepare(
      `
    SELECT
      COUNT(*) as total,
      AVG(risk_score) as avg_score,
      SUM(CASE WHEN risk_tier = 'critical' THEN 1 ELSE 0 END) as critical,
      SUM(CASE WHEN risk_tier = 'high' THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN risk_tier = 'medium' THEN 1 ELSE 0 END) as medium,
      SUM(CASE WHEN risk_tier = 'low' THEN 1 ELSE 0 END) as low,
      SUM(CASE WHEN risk_tier = 'minimal' THEN 1 ELSE 0 END) as minimal
    FROM risk_scores
  `
    )
    .get() as {
    total: number;
    avg_score: number | null;
    critical: number;
    high: number;
    medium: number;
    low: number;
    minimal: number;
  };

  return {
    totalAssets: assetCount.count,
    totalScores: scoreStats.total,
    tierDistribution: {
      critical: scoreStats.critical,
      high: scoreStats.high,
      medium: scoreStats.medium,
      low: scoreStats.low,
      minimal: scoreStats.minimal,
    },
    avgRiskScore: scoreStats.avg_score ? Math.round(scoreStats.avg_score) : 0,
    criticalCount: scoreStats.critical,
    highCount: scoreStats.high,
  };
}
