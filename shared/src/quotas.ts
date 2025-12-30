/**
 * Resource Quotas & Limits Module
 * Manages resource consumption for multi-tenant deployments
 * Part of v1.30.0 - Enterprise Scale & Multi-Cloud Security
 */

import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";

export type QuotaType =
  | "scans_per_day"
  | "scans_per_month"
  | "storage_mb"
  | "api_requests_per_hour"
  | "concurrent_scans"
  | "reports_per_day";
export type QuotaScope = "team" | "project" | "user" | "global";

export interface QuotaConfig {
  id: string;
  scope: QuotaScope;
  scopeId: string;
  quotaType: QuotaType;
  limit: number;
  warningThreshold: number;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface QuotaUsage {
  quotaId: string;
  scope: QuotaScope;
  scopeId: string;
  quotaType: QuotaType;
  currentUsage: number;
  limit: number;
  percentUsed: number;
  resetAt: string;
  lastUpdated: string;
}

export interface QuotaBreach {
  id: string;
  quotaId: string;
  scope: QuotaScope;
  scopeId: string;
  quotaType: QuotaType;
  usageAtBreach: number;
  limit: number;
  breachedAt: string;
  resolved: boolean;
  resolvedAt?: string;
}

export interface QuotaAlert {
  id: string;
  quotaId: string;
  alertType: "warning" | "breach" | "resolved";
  message: string;
  createdAt: string;
  acknowledged: boolean;
  acknowledgedAt?: string;
  acknowledgedBy?: string;
}

let db: Database.Database | null = null;
const DEFAULT_DB_PATH = path.join(process.cwd(), ".cicd-security", "quotas.db");

export function initQuotasDb(dbPath: string = DEFAULT_DB_PATH): { path: string; tables: string[] } {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  db = new Database(dbPath);
  db.pragma("journal_mode = WAL");

  db.prepare(
    `CREATE TABLE IF NOT EXISTS quota_configs (id TEXT PRIMARY KEY, scope TEXT, scope_id TEXT,
    quota_type TEXT, limit_value INTEGER, warning_threshold INTEGER, enabled INTEGER DEFAULT 1,
    created_at TEXT, updated_at TEXT, UNIQUE(scope, scope_id, quota_type))`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS quota_usage (id INTEGER PRIMARY KEY AUTOINCREMENT, quota_id TEXT,
    scope TEXT, scope_id TEXT, quota_type TEXT, current_usage INTEGER DEFAULT 0, reset_at TEXT,
    last_updated TEXT, UNIQUE(quota_id))`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS quota_breaches (id TEXT PRIMARY KEY, quota_id TEXT, scope TEXT,
    scope_id TEXT, quota_type TEXT, usage_at_breach INTEGER, limit_value INTEGER, breached_at TEXT,
    resolved INTEGER DEFAULT 0, resolved_at TEXT)`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS quota_alerts (id TEXT PRIMARY KEY, quota_id TEXT, alert_type TEXT,
    message TEXT, created_at TEXT, acknowledged INTEGER DEFAULT 0, acknowledged_at TEXT, acknowledged_by TEXT)`
  ).run();

  return {
    path: dbPath,
    tables: ["quota_configs", "quota_usage", "quota_breaches", "quota_alerts"],
  };
}

function getDb(): Database.Database {
  if (!db) initQuotasDb();
  return db!;
}

function getResetTime(quotaType: QuotaType): string {
  const now = new Date();
  if (quotaType.includes("per_day")) {
    const tomorrow = new Date(now);
    tomorrow.setDate(tomorrow.getDate() + 1);
    tomorrow.setHours(0, 0, 0, 0);
    return tomorrow.toISOString();
  }
  if (quotaType.includes("per_month")) {
    const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1);
    return nextMonth.toISOString();
  }
  if (quotaType.includes("per_hour")) {
    const nextHour = new Date(now);
    nextHour.setHours(nextHour.getHours() + 1, 0, 0, 0);
    return nextHour.toISOString();
  }
  return new Date(now.getTime() + 86400000).toISOString();
}

export function setQuota(config: Omit<QuotaConfig, "id" | "createdAt" | "updatedAt">): QuotaConfig {
  const now = new Date().toISOString();
  const id = `quota-${config.scope}-${config.scopeId}-${config.quotaType}`;

  const quota: QuotaConfig = { ...config, id, createdAt: now, updatedAt: now };

  getDb()
    .prepare(
      `INSERT INTO quota_configs VALUES (?,?,?,?,?,?,?,?,?)
    ON CONFLICT(scope, scope_id, quota_type) DO UPDATE SET
    limit_value = excluded.limit_value, warning_threshold = excluded.warning_threshold,
    enabled = excluded.enabled, updated_at = excluded.updated_at`
    )
    .run(
      quota.id,
      quota.scope,
      quota.scopeId,
      quota.quotaType,
      quota.limit,
      quota.warningThreshold,
      quota.enabled ? 1 : 0,
      quota.createdAt,
      quota.updatedAt
    );

  // Initialize usage tracking
  getDb()
    .prepare(
      `INSERT OR IGNORE INTO quota_usage (quota_id, scope, scope_id, quota_type, current_usage, reset_at, last_updated)
    VALUES (?, ?, ?, ?, 0, ?, ?)`
    )
    .run(quota.id, quota.scope, quota.scopeId, quota.quotaType, getResetTime(quota.quotaType), now);

  return quota;
}

export function getQuota(
  scope: QuotaScope,
  scopeId: string,
  quotaType: QuotaType
): QuotaConfig | null {
  const r = getDb()
    .prepare("SELECT * FROM quota_configs WHERE scope = ? AND scope_id = ? AND quota_type = ?")
    .get(scope, scopeId, quotaType) as any;
  if (!r) return null;
  return {
    id: r.id,
    scope: r.scope,
    scopeId: r.scope_id,
    quotaType: r.quota_type,
    limit: r.limit_value,
    warningThreshold: r.warning_threshold,
    enabled: r.enabled === 1,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

export function listQuotas(scope?: QuotaScope, scopeId?: string): QuotaConfig[] {
  let sql = "SELECT * FROM quota_configs WHERE 1=1";
  const params: string[] = [];
  if (scope) {
    sql += " AND scope = ?";
    params.push(scope);
  }
  if (scopeId) {
    sql += " AND scope_id = ?";
    params.push(scopeId);
  }
  sql += " ORDER BY scope, scope_id, quota_type";

  return (
    getDb()
      .prepare(sql)
      .all(...params) as any[]
  ).map((r) => ({
    id: r.id,
    scope: r.scope,
    scopeId: r.scope_id,
    quotaType: r.quota_type,
    limit: r.limit_value,
    warningThreshold: r.warning_threshold,
    enabled: r.enabled === 1,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  }));
}

export function deleteQuota(
  scope: QuotaScope,
  scopeId: string,
  quotaType: QuotaType
): { success: boolean; deleted: boolean } {
  const quotaId = `quota-${scope}-${scopeId}-${quotaType}`;
  getDb().prepare("DELETE FROM quota_usage WHERE quota_id = ?").run(quotaId);
  const result = getDb()
    .prepare("DELETE FROM quota_configs WHERE scope = ? AND scope_id = ? AND quota_type = ?")
    .run(scope, scopeId, quotaType);
  return { success: true, deleted: result.changes > 0 };
}

export function getQuotaUsage(
  scope: QuotaScope,
  scopeId: string,
  quotaType: QuotaType
): QuotaUsage | null {
  const quota = getQuota(scope, scopeId, quotaType);
  if (!quota) return null;

  const r = getDb().prepare("SELECT * FROM quota_usage WHERE quota_id = ?").get(quota.id) as any;
  if (!r) return null;

  // Check if reset is needed
  if (new Date(r.reset_at) < new Date()) {
    const newReset = getResetTime(quotaType);
    getDb()
      .prepare(
        "UPDATE quota_usage SET current_usage = 0, reset_at = ?, last_updated = ? WHERE quota_id = ?"
      )
      .run(newReset, new Date().toISOString(), quota.id);
    return {
      quotaId: quota.id,
      scope,
      scopeId,
      quotaType,
      currentUsage: 0,
      limit: quota.limit,
      percentUsed: 0,
      resetAt: newReset,
      lastUpdated: new Date().toISOString(),
    };
  }

  return {
    quotaId: quota.id,
    scope,
    scopeId,
    quotaType,
    currentUsage: r.current_usage,
    limit: quota.limit,
    percentUsed: quota.limit > 0 ? (r.current_usage / quota.limit) * 100 : 0,
    resetAt: r.reset_at,
    lastUpdated: r.last_updated,
  };
}

export function incrementUsage(
  scope: QuotaScope,
  scopeId: string,
  quotaType: QuotaType,
  amount: number = 1
): {
  success: boolean;
  currentUsage: number;
  limit: number;
  breached: boolean;
  warning: boolean;
} {
  const quota = getQuota(scope, scopeId, quotaType);
  if (!quota || !quota.enabled)
    return { success: true, currentUsage: 0, limit: 0, breached: false, warning: false };

  // Get current usage, reset if needed
  const usage = getQuotaUsage(scope, scopeId, quotaType);
  const currentUsage = (usage?.currentUsage || 0) + amount;
  const now = new Date().toISOString();

  getDb()
    .prepare("UPDATE quota_usage SET current_usage = ?, last_updated = ? WHERE quota_id = ?")
    .run(currentUsage, now, quota.id);

  const breached = currentUsage > quota.limit;
  const warning = currentUsage >= quota.warningThreshold && !breached;

  if (breached) {
    const breachId = `breach-${Date.now()}`;
    getDb()
      .prepare(`INSERT INTO quota_breaches VALUES (?,?,?,?,?,?,?,?,0,NULL)`)
      .run(breachId, quota.id, scope, scopeId, quotaType, currentUsage, quota.limit, now);
    createAlert(
      quota.id,
      "breach",
      `Quota breached: ${quotaType} for ${scope}/${scopeId}. Usage: ${currentUsage}/${quota.limit}`
    );
  } else if (warning) {
    createAlert(
      quota.id,
      "warning",
      `Quota warning: ${quotaType} for ${scope}/${scopeId} at ${Math.round((currentUsage / quota.limit) * 100)}%`
    );
  }

  return { success: true, currentUsage, limit: quota.limit, breached, warning };
}

export function checkQuota(
  scope: QuotaScope,
  scopeId: string,
  quotaType: QuotaType
): {
  allowed: boolean;
  currentUsage: number;
  limit: number;
  remaining: number;
} {
  const usage = getQuotaUsage(scope, scopeId, quotaType);
  if (!usage) return { allowed: true, currentUsage: 0, limit: 0, remaining: 0 };

  const remaining = Math.max(0, usage.limit - usage.currentUsage);
  return {
    allowed: usage.currentUsage < usage.limit,
    currentUsage: usage.currentUsage,
    limit: usage.limit,
    remaining,
  };
}

export function listBreaches(options?: {
  scope?: QuotaScope;
  resolved?: boolean;
  limit?: number;
}): QuotaBreach[] {
  let sql = "SELECT * FROM quota_breaches WHERE 1=1";
  const params: (string | number)[] = [];
  if (options?.scope) {
    sql += " AND scope = ?";
    params.push(options.scope);
  }
  if (options?.resolved !== undefined) {
    sql += " AND resolved = ?";
    params.push(options.resolved ? 1 : 0);
  }
  sql += " ORDER BY breached_at DESC";
  if (options?.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }

  return (
    getDb()
      .prepare(sql)
      .all(...params) as any[]
  ).map((r) => ({
    id: r.id,
    quotaId: r.quota_id,
    scope: r.scope,
    scopeId: r.scope_id,
    quotaType: r.quota_type,
    usageAtBreach: r.usage_at_breach,
    limit: r.limit_value,
    breachedAt: r.breached_at,
    resolved: r.resolved === 1,
    resolvedAt: r.resolved_at,
  }));
}

export function resolveBreach(breachId: string): { success: boolean } {
  getDb()
    .prepare("UPDATE quota_breaches SET resolved = 1, resolved_at = ? WHERE id = ?")
    .run(new Date().toISOString(), breachId);
  return { success: true };
}

function createAlert(
  quotaId: string,
  alertType: "warning" | "breach" | "resolved",
  message: string
): void {
  const id = `alert-${Date.now()}`;
  getDb()
    .prepare(`INSERT INTO quota_alerts VALUES (?,?,?,?,?,0,NULL,NULL)`)
    .run(id, quotaId, alertType, message, new Date().toISOString());
}

export function listAlerts(options?: { acknowledged?: boolean; limit?: number }): QuotaAlert[] {
  let sql = "SELECT * FROM quota_alerts WHERE 1=1";
  const params: (string | number)[] = [];
  if (options?.acknowledged !== undefined) {
    sql += " AND acknowledged = ?";
    params.push(options.acknowledged ? 1 : 0);
  }
  sql += " ORDER BY created_at DESC";
  if (options?.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }

  return (
    getDb()
      .prepare(sql)
      .all(...params) as any[]
  ).map((r) => ({
    id: r.id,
    quotaId: r.quota_id,
    alertType: r.alert_type,
    message: r.message,
    createdAt: r.created_at,
    acknowledged: r.acknowledged === 1,
    acknowledgedAt: r.acknowledged_at,
    acknowledgedBy: r.acknowledged_by,
  }));
}

export function acknowledgeAlert(alertId: string, acknowledgedBy?: string): { success: boolean } {
  getDb()
    .prepare(
      "UPDATE quota_alerts SET acknowledged = 1, acknowledged_at = ?, acknowledged_by = ? WHERE id = ?"
    )
    .run(new Date().toISOString(), acknowledgedBy || null, alertId);
  return { success: true };
}

export function getQuotaSummary(
  scope: QuotaScope,
  scopeId: string
): {
  quotas: Array<{
    type: QuotaType;
    usage: number;
    limit: number;
    percent: number;
    status: "ok" | "warning" | "breached";
  }>;
  totalBreaches: number;
  activeAlerts: number;
} {
  const quotas = listQuotas(scope, scopeId);
  const summary = [];

  for (const q of quotas) {
    const usage = getQuotaUsage(scope, scopeId, q.quotaType);
    if (usage) {
      let status: "ok" | "warning" | "breached" = "ok";
      if (usage.currentUsage > q.limit) status = "breached";
      else if (usage.currentUsage >= q.warningThreshold) status = "warning";
      summary.push({
        type: q.quotaType,
        usage: usage.currentUsage,
        limit: q.limit,
        percent: usage.percentUsed,
        status,
      });
    }
  }

  const breaches = listBreaches({ scope, resolved: false });
  const alerts = listAlerts({ acknowledged: false });

  return { quotas: summary, totalBreaches: breaches.length, activeAlerts: alerts.length };
}

export const quotas = {
  initQuotasDb,
  setQuota,
  getQuota,
  listQuotas,
  deleteQuota,
  getQuotaUsage,
  incrementUsage,
  checkQuota,
  listBreaches,
  resolveBreach,
  listAlerts,
  acknowledgeAlert,
  getQuotaSummary,
};
