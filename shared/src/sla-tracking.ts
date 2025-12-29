/**
 * SLA Tracking Module
 *
 * Provides Service Level Agreement tracking for vulnerability remediation,
 * including configurable targets, compliance monitoring, and breach alerting.
 */

import Database from "better-sqlite3";
import { randomUUID } from "crypto";
import path from "path";
import os from "os";
import fs from "fs";

// =============================================================================
// Types
// =============================================================================

/** SLA severity levels */
export type SlaSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

/** SLA target configuration */
export interface SlaTarget {
  /** Severity level */
  severity: SlaSeverity;
  /** Target hours to acknowledge vulnerability */
  acknowledgeHours: number;
  /** Target hours to remediate vulnerability */
  remediateHours: number;
  /** Warning threshold percentage (0-100) */
  warningThresholdPercent: number;
}

/** SLA configuration */
export interface SlaConfig {
  /** Configuration ID */
  id: string;
  /** Configuration name */
  name: string;
  /** Description */
  description?: string;
  /** Whether this is the default config */
  isDefault: boolean;
  /** SLA targets by severity */
  targets: SlaTarget[];
  /** Created timestamp */
  createdAt: string;
  /** Updated timestamp */
  updatedAt: string;
}

/** SLA configure options */
export interface SlaConfigureOptions {
  /** Configuration name */
  name: string;
  /** Description */
  description?: string;
  /** Set as default config */
  setAsDefault?: boolean;
  /** SLA targets */
  targets: SlaTarget[];
}

/** Vulnerability SLA status */
export interface VulnSlaStatus {
  /** Vulnerability ID (CVE) */
  vulnId: string;
  /** Affected target (image/project) */
  target: string;
  /** Severity level */
  severity: SlaSeverity;
  /** Detection timestamp */
  detectedAt: string;
  /** Acknowledgment timestamp (if acknowledged) */
  acknowledgedAt?: string;
  /** Remediation timestamp (if remediated) */
  remediatedAt?: string;
  /** SLA target hours for acknowledgment */
  acknowledgeTargetHours: number;
  /** SLA target hours for remediation */
  remediateTargetHours: number;
  /** Hours since detection */
  hoursSinceDetection: number;
  /** Acknowledgment status */
  acknowledgeStatus: "compliant" | "warning" | "breached" | "met";
  /** Remediation status */
  remediateStatus: "compliant" | "warning" | "breached" | "met";
  /** Hours until acknowledgment SLA breach (negative if breached) */
  hoursUntilAcknowledgeBreach: number;
  /** Hours until remediation SLA breach (negative if breached) */
  hoursUntilRemediateBreach: number;
}

/** SLA status summary */
export interface SlaStatusSummary {
  /** Total vulnerabilities tracked */
  total: number;
  /** Vulnerabilities meeting SLA */
  compliant: number;
  /** Vulnerabilities in warning zone */
  warning: number;
  /** Vulnerabilities breaching SLA */
  breached: number;
  /** Compliance percentage */
  compliancePercent: number;
  /** Breakdown by severity */
  bySeverity: Record<
    SlaSeverity,
    {
      total: number;
      compliant: number;
      warning: number;
      breached: number;
    }
  >;
  /** Configuration used */
  configName: string;
  /** Timestamp of status check */
  checkedAt: string;
}

/** SLA get status options */
export interface SlaGetStatusOptions {
  /** Filter by target */
  target?: string;
  /** Filter by severity */
  severity?: SlaSeverity | SlaSeverity[];
  /** Config ID to use (uses default if not specified) */
  configId?: string;
  /** Include individual vulnerability statuses */
  includeDetails?: boolean;
}

/** SLA status result */
export interface SlaStatusResult {
  /** Summary statistics */
  summary: SlaStatusSummary;
  /** Individual vulnerability statuses (if includeDetails=true) */
  vulnerabilities?: VulnSlaStatus[];
}

/** SLA breach info */
export interface SlaBreach {
  /** Vulnerability ID */
  vulnId: string;
  /** Affected target */
  target: string;
  /** Severity */
  severity: SlaSeverity;
  /** Breach type */
  breachType: "acknowledge" | "remediate";
  /** Target hours */
  targetHours: number;
  /** Actual hours */
  actualHours: number;
  /** Hours over SLA */
  hoursOver: number;
  /** Detection timestamp */
  detectedAt: string;
}

/** SLA approaching breach */
export interface SlaApproaching {
  /** Vulnerability ID */
  vulnId: string;
  /** Affected target */
  target: string;
  /** Severity */
  severity: SlaSeverity;
  /** Approaching type */
  approachingType: "acknowledge" | "remediate";
  /** Target hours */
  targetHours: number;
  /** Hours remaining */
  hoursRemaining: number;
  /** Warning threshold percentage */
  warningThreshold: number;
  /** Detection timestamp */
  detectedAt: string;
}

/** SLA breaches result */
export interface SlaBreachesResult {
  /** Current breaches */
  breaches: SlaBreach[];
  /** Approaching breaches (in warning zone) */
  approaching: SlaApproaching[];
  /** Total breach count */
  breachCount: number;
  /** Total approaching count */
  approachingCount: number;
  /** Checked timestamp */
  checkedAt: string;
}

/** SLA get breaches options */
export interface SlaGetBreachesOptions {
  /** Filter by target */
  target?: string;
  /** Filter by severity */
  severity?: SlaSeverity | SlaSeverity[];
  /** Config ID to use */
  configId?: string;
  /** Limit results */
  limit?: number;
}

// =============================================================================
// Database Initialization
// =============================================================================

let db: Database.Database | null = null;

/**
 * Get the SLA database path
 */
function getSlaDbPath(): string {
  const dataDir = process.env.CICD_DATA_DIR || path.join(os.homedir(), ".cicd-security");
  return path.join(dataDir, "sla.db");
}

/**
 * Initialize the SLA database
 */
export function initSlaDatabase(dbPath?: string): Database.Database {
  if (db) return db;

  const finalPath = dbPath || getSlaDbPath();

  // Ensure directory exists
  const dir = path.dirname(finalPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  db = new Database(finalPath);

  // Create tables
  db.exec(`
    -- SLA configurations
    CREATE TABLE IF NOT EXISTS sla_configs (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      is_default INTEGER DEFAULT 0,
      targets_json TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Tracked vulnerabilities for SLA
    CREATE TABLE IF NOT EXISTS sla_vulnerabilities (
      id TEXT PRIMARY KEY,
      vuln_id TEXT NOT NULL,
      target TEXT NOT NULL,
      severity TEXT NOT NULL,
      detected_at TEXT NOT NULL,
      acknowledged_at TEXT,
      remediated_at TEXT,
      config_id TEXT,
      UNIQUE(vuln_id, target)
    );

    -- SLA audit log
    CREATE TABLE IF NOT EXISTS sla_audit (
      id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      vuln_id TEXT,
      target TEXT,
      details_json TEXT,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Indexes
    CREATE INDEX IF NOT EXISTS idx_sla_vulns_target ON sla_vulnerabilities(target);
    CREATE INDEX IF NOT EXISTS idx_sla_vulns_severity ON sla_vulnerabilities(severity);
    CREATE INDEX IF NOT EXISTS idx_sla_vulns_detected ON sla_vulnerabilities(detected_at);
  `);

  // Seed default config if none exists
  const hasConfig = db.prepare("SELECT COUNT(*) as count FROM sla_configs").get() as {
    count: number;
  };
  if (hasConfig.count === 0) {
    seedDefaultConfig(db);
  }

  return db;
}

/**
 * Seed the default SLA configuration
 */
function seedDefaultConfig(database: Database.Database): void {
  const defaultTargets: SlaTarget[] = [
    { severity: "CRITICAL", acknowledgeHours: 4, remediateHours: 24, warningThresholdPercent: 75 },
    { severity: "HIGH", acknowledgeHours: 24, remediateHours: 72, warningThresholdPercent: 75 },
    { severity: "MEDIUM", acknowledgeHours: 72, remediateHours: 168, warningThresholdPercent: 80 },
    { severity: "LOW", acknowledgeHours: 168, remediateHours: 720, warningThresholdPercent: 80 },
  ];

  database
    .prepare(
      `
    INSERT INTO sla_configs (id, name, description, is_default, targets_json)
    VALUES (?, ?, ?, 1, ?)
  `
    )
    .run(
      randomUUID(),
      "Default SLA Policy",
      "Standard SLA targets: Critical 4h/24h, High 24h/72h, Medium 72h/168h, Low 168h/720h",
      JSON.stringify(defaultTargets)
    );
}

/**
 * Close the SLA database
 */
export function closeSlaDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

// =============================================================================
// SLA Configuration
// =============================================================================

/**
 * Configure SLA targets
 */
export function configureSla(options: SlaConfigureOptions): SlaConfig {
  const database = initSlaDatabase();
  const id = randomUUID();
  const now = new Date().toISOString();

  // If setting as default, clear existing default
  if (options.setAsDefault) {
    database.prepare("UPDATE sla_configs SET is_default = 0 WHERE is_default = 1").run();
  }

  // Check if config with same name exists
  const existing = database
    .prepare("SELECT id FROM sla_configs WHERE name = ?")
    .get(options.name) as { id: string } | undefined;

  if (existing) {
    // Update existing
    database
      .prepare(
        `
      UPDATE sla_configs
      SET description = ?, is_default = ?, targets_json = ?, updated_at = ?
      WHERE id = ?
    `
      )
      .run(
        options.description || null,
        options.setAsDefault ? 1 : 0,
        JSON.stringify(options.targets),
        now,
        existing.id
      );

    return getSlaConfig(existing.id)!;
  }

  // Insert new
  database
    .prepare(
      `
    INSERT INTO sla_configs (id, name, description, is_default, targets_json, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      id,
      options.name,
      options.description || null,
      options.setAsDefault ? 1 : 0,
      JSON.stringify(options.targets),
      now,
      now
    );

  // Log audit event
  database
    .prepare(
      `
    INSERT INTO sla_audit (id, event_type, details_json)
    VALUES (?, 'config_created', ?)
  `
    )
    .run(randomUUID(), JSON.stringify({ configId: id, name: options.name }));

  return getSlaConfig(id)!;
}

/**
 * Get SLA configuration by ID
 */
export function getSlaConfig(configId: string): SlaConfig | null {
  const database = initSlaDatabase();
  const row = database
    .prepare(
      `
    SELECT id, name, description, is_default, targets_json, created_at, updated_at
    FROM sla_configs WHERE id = ?
  `
    )
    .get(configId) as
    | {
        id: string;
        name: string;
        description: string | null;
        is_default: number;
        targets_json: string;
        created_at: string;
        updated_at: string;
      }
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    name: row.name,
    description: row.description || undefined,
    isDefault: row.is_default === 1,
    targets: JSON.parse(row.targets_json),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * Get the default SLA configuration
 */
export function getDefaultSlaConfig(): SlaConfig | null {
  const database = initSlaDatabase();
  const row = database.prepare(`SELECT id FROM sla_configs WHERE is_default = 1 LIMIT 1`).get() as
    | { id: string }
    | undefined;

  if (!row) return null;
  return getSlaConfig(row.id);
}

/**
 * List all SLA configurations
 */
export function listSlaConfigs(): SlaConfig[] {
  const database = initSlaDatabase();
  const rows = database
    .prepare(`SELECT id FROM sla_configs ORDER BY is_default DESC, name ASC`)
    .all() as { id: string }[];

  return rows.map((row) => getSlaConfig(row.id)!);
}

// =============================================================================
// Vulnerability Tracking
// =============================================================================

/**
 * Track a vulnerability for SLA monitoring
 */
export function trackVulnerability(
  vulnId: string,
  target: string,
  severity: SlaSeverity,
  detectedAt?: string
): void {
  const database = initSlaDatabase();
  const id = randomUUID();
  const detected = detectedAt || new Date().toISOString();

  database
    .prepare(
      `
    INSERT OR IGNORE INTO sla_vulnerabilities (id, vuln_id, target, severity, detected_at)
    VALUES (?, ?, ?, ?, ?)
  `
    )
    .run(id, vulnId, target, severity, detected);
}

/**
 * Acknowledge a vulnerability
 */
export function acknowledgeVulnerability(vulnId: string, target: string): boolean {
  const database = initSlaDatabase();
  const result = database
    .prepare(
      `
    UPDATE sla_vulnerabilities
    SET acknowledged_at = ?
    WHERE vuln_id = ? AND target = ? AND acknowledged_at IS NULL
  `
    )
    .run(new Date().toISOString(), vulnId, target);

  if (result.changes > 0) {
    database
      .prepare(
        `
      INSERT INTO sla_audit (id, event_type, vuln_id, target, details_json)
      VALUES (?, 'acknowledged', ?, ?, ?)
    `
      )
      .run(
        randomUUID(),
        vulnId,
        target,
        JSON.stringify({ acknowledgedAt: new Date().toISOString() })
      );
    return true;
  }
  return false;
}

/**
 * Mark a vulnerability as remediated
 */
export function remediateVulnerability(vulnId: string, target: string): boolean {
  const database = initSlaDatabase();
  const result = database
    .prepare(
      `
    UPDATE sla_vulnerabilities
    SET remediated_at = ?
    WHERE vuln_id = ? AND target = ? AND remediated_at IS NULL
  `
    )
    .run(new Date().toISOString(), vulnId, target);

  if (result.changes > 0) {
    database
      .prepare(
        `
      INSERT INTO sla_audit (id, event_type, vuln_id, target, details_json)
      VALUES (?, 'remediated', ?, ?, ?)
    `
      )
      .run(
        randomUUID(),
        vulnId,
        target,
        JSON.stringify({ remediatedAt: new Date().toISOString() })
      );
    return true;
  }
  return false;
}

// =============================================================================
// SLA Status Calculation
// =============================================================================

/**
 * Calculate hours between two timestamps
 */
function hoursBetween(start: string, end: string): number {
  const startDate = new Date(start);
  const endDate = new Date(end);
  return (endDate.getTime() - startDate.getTime()) / (1000 * 60 * 60);
}

/**
 * Calculate SLA status for a vulnerability
 */
function calculateVulnSlaStatus(
  vuln: {
    vuln_id: string;
    target: string;
    severity: string;
    detected_at: string;
    acknowledged_at: string | null;
    remediated_at: string | null;
  },
  targets: SlaTarget[]
): VulnSlaStatus {
  const severity = vuln.severity as SlaSeverity;
  const target = targets.find((t) => t.severity === severity) || targets[0];
  const now = new Date().toISOString();

  const hoursSinceDetection = hoursBetween(vuln.detected_at, now);
  const hoursUntilAcknowledgeBreach = target.acknowledgeHours - hoursSinceDetection;
  const hoursUntilRemediateBreach = target.remediateHours - hoursSinceDetection;

  // Determine acknowledge status
  let acknowledgeStatus: VulnSlaStatus["acknowledgeStatus"];
  if (vuln.acknowledged_at) {
    const ackHours = hoursBetween(vuln.detected_at, vuln.acknowledged_at);
    acknowledgeStatus = ackHours <= target.acknowledgeHours ? "met" : "breached";
  } else if (hoursUntilAcknowledgeBreach <= 0) {
    acknowledgeStatus = "breached";
  } else if (
    hoursUntilAcknowledgeBreach <=
    target.acknowledgeHours * (1 - target.warningThresholdPercent / 100)
  ) {
    acknowledgeStatus = "warning";
  } else {
    acknowledgeStatus = "compliant";
  }

  // Determine remediate status
  let remediateStatus: VulnSlaStatus["remediateStatus"];
  if (vuln.remediated_at) {
    const remHours = hoursBetween(vuln.detected_at, vuln.remediated_at);
    remediateStatus = remHours <= target.remediateHours ? "met" : "breached";
  } else if (hoursUntilRemediateBreach <= 0) {
    remediateStatus = "breached";
  } else if (
    hoursUntilRemediateBreach <=
    target.remediateHours * (1 - target.warningThresholdPercent / 100)
  ) {
    remediateStatus = "warning";
  } else {
    remediateStatus = "compliant";
  }

  return {
    vulnId: vuln.vuln_id,
    target: vuln.target,
    severity,
    detectedAt: vuln.detected_at,
    acknowledgedAt: vuln.acknowledged_at || undefined,
    remediatedAt: vuln.remediated_at || undefined,
    acknowledgeTargetHours: target.acknowledgeHours,
    remediateTargetHours: target.remediateHours,
    hoursSinceDetection: Math.round(hoursSinceDetection * 100) / 100,
    acknowledgeStatus,
    remediateStatus,
    hoursUntilAcknowledgeBreach: Math.round(hoursUntilAcknowledgeBreach * 100) / 100,
    hoursUntilRemediateBreach: Math.round(hoursUntilRemediateBreach * 100) / 100,
  };
}

/**
 * Get SLA compliance status
 */
export function getSlaStatus(options: SlaGetStatusOptions = {}): SlaStatusResult {
  const database = initSlaDatabase();

  // Get config
  let config: SlaConfig | null;
  if (options.configId) {
    config = getSlaConfig(options.configId);
  } else {
    config = getDefaultSlaConfig();
  }

  if (!config) {
    throw new Error("No SLA configuration found");
  }

  // Build query
  let query = "SELECT * FROM sla_vulnerabilities WHERE remediated_at IS NULL";
  const params: (string | number)[] = [];

  if (options.target) {
    query += " AND target = ?";
    params.push(options.target);
  }

  if (options.severity) {
    const severities = Array.isArray(options.severity) ? options.severity : [options.severity];
    query += ` AND severity IN (${severities.map(() => "?").join(", ")})`;
    params.push(...severities);
  }

  const vulns = database.prepare(query).all(...params) as Array<{
    vuln_id: string;
    target: string;
    severity: string;
    detected_at: string;
    acknowledged_at: string | null;
    remediated_at: string | null;
  }>;

  // Calculate status for each vulnerability
  const statuses = vulns.map((v) => calculateVulnSlaStatus(v, config!.targets));

  // Build summary
  const bySeverity: SlaStatusSummary["bySeverity"] = {
    CRITICAL: { total: 0, compliant: 0, warning: 0, breached: 0 },
    HIGH: { total: 0, compliant: 0, warning: 0, breached: 0 },
    MEDIUM: { total: 0, compliant: 0, warning: 0, breached: 0 },
    LOW: { total: 0, compliant: 0, warning: 0, breached: 0 },
  };

  let compliant = 0;
  let warning = 0;
  let breached = 0;

  for (const status of statuses) {
    bySeverity[status.severity].total++;

    // Use the worst status (remediate takes precedence)
    const worstStatus =
      status.remediateStatus === "breached" || status.acknowledgeStatus === "breached"
        ? "breached"
        : status.remediateStatus === "warning" || status.acknowledgeStatus === "warning"
          ? "warning"
          : "compliant";

    if (worstStatus === "breached") {
      breached++;
      bySeverity[status.severity].breached++;
    } else if (worstStatus === "warning") {
      warning++;
      bySeverity[status.severity].warning++;
    } else {
      compliant++;
      bySeverity[status.severity].compliant++;
    }
  }

  const total = statuses.length;
  const compliancePercent = total > 0 ? Math.round((compliant / total) * 10000) / 100 : 100;

  const result: SlaStatusResult = {
    summary: {
      total,
      compliant,
      warning,
      breached,
      compliancePercent,
      bySeverity,
      configName: config.name,
      checkedAt: new Date().toISOString(),
    },
  };

  if (options.includeDetails) {
    result.vulnerabilities = statuses;
  }

  return result;
}

/**
 * Get SLA breaches and approaching breaches
 */
export function getSlaBreaches(options: SlaGetBreachesOptions = {}): SlaBreachesResult {
  const database = initSlaDatabase();

  // Get config
  let config: SlaConfig | null;
  if (options.configId) {
    config = getSlaConfig(options.configId);
  } else {
    config = getDefaultSlaConfig();
  }

  if (!config) {
    throw new Error("No SLA configuration found");
  }

  // Build query for unremediated vulnerabilities
  let query = "SELECT * FROM sla_vulnerabilities WHERE remediated_at IS NULL";
  const params: (string | number)[] = [];

  if (options.target) {
    query += " AND target = ?";
    params.push(options.target);
  }

  if (options.severity) {
    const severities = Array.isArray(options.severity) ? options.severity : [options.severity];
    query += ` AND severity IN (${severities.map(() => "?").join(", ")})`;
    params.push(...severities);
  }

  query += " ORDER BY detected_at ASC";

  if (options.limit) {
    query += " LIMIT ?";
    params.push(options.limit);
  }

  const vulns = database.prepare(query).all(...params) as Array<{
    vuln_id: string;
    target: string;
    severity: string;
    detected_at: string;
    acknowledged_at: string | null;
    remediated_at: string | null;
  }>;

  const breaches: SlaBreach[] = [];
  const approaching: SlaApproaching[] = [];

  for (const vuln of vulns) {
    const status = calculateVulnSlaStatus(vuln, config.targets);
    const slaTarget = config.targets.find((t) => t.severity === status.severity)!;

    // Check for acknowledge breach/approaching
    if (!vuln.acknowledged_at) {
      if (status.acknowledgeStatus === "breached") {
        breaches.push({
          vulnId: vuln.vuln_id,
          target: vuln.target,
          severity: status.severity,
          breachType: "acknowledge",
          targetHours: slaTarget.acknowledgeHours,
          actualHours: status.hoursSinceDetection,
          hoursOver:
            Math.round((status.hoursSinceDetection - slaTarget.acknowledgeHours) * 100) / 100,
          detectedAt: vuln.detected_at,
        });
      } else if (status.acknowledgeStatus === "warning") {
        approaching.push({
          vulnId: vuln.vuln_id,
          target: vuln.target,
          severity: status.severity,
          approachingType: "acknowledge",
          targetHours: slaTarget.acknowledgeHours,
          hoursRemaining: Math.round(status.hoursUntilAcknowledgeBreach * 100) / 100,
          warningThreshold: slaTarget.warningThresholdPercent,
          detectedAt: vuln.detected_at,
        });
      }
    }

    // Check for remediate breach/approaching
    if (status.remediateStatus === "breached") {
      breaches.push({
        vulnId: vuln.vuln_id,
        target: vuln.target,
        severity: status.severity,
        breachType: "remediate",
        targetHours: slaTarget.remediateHours,
        actualHours: status.hoursSinceDetection,
        hoursOver: Math.round((status.hoursSinceDetection - slaTarget.remediateHours) * 100) / 100,
        detectedAt: vuln.detected_at,
      });
    } else if (status.remediateStatus === "warning") {
      approaching.push({
        vulnId: vuln.vuln_id,
        target: vuln.target,
        severity: status.severity,
        approachingType: "remediate",
        targetHours: slaTarget.remediateHours,
        hoursRemaining: Math.round(status.hoursUntilRemediateBreach * 100) / 100,
        warningThreshold: slaTarget.warningThresholdPercent,
        detectedAt: vuln.detected_at,
      });
    }
  }

  return {
    breaches,
    approaching,
    breachCount: breaches.length,
    approachingCount: approaching.length,
    checkedAt: new Date().toISOString(),
  };
}

/**
 * Delete an SLA configuration
 */
export function deleteSlaConfig(configId: string): boolean {
  const database = initSlaDatabase();
  const result = database
    .prepare("DELETE FROM sla_configs WHERE id = ? AND is_default = 0")
    .run(configId);
  return result.changes > 0;
}

/**
 * Clear tracked vulnerabilities (for testing)
 */
export function clearTrackedVulnerabilities(): void {
  const database = initSlaDatabase();
  database.prepare("DELETE FROM sla_vulnerabilities").run();
}
