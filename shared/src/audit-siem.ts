/**
 * Audit/SIEM Integration Module
 * Export security audit logs to SIEM systems (Splunk, Elasticsearch, Azure Sentinel)
 * Part of v1.31.0 - GitOps & Zero-Trust Security
 */

import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";

export type SiemProvider = "splunk" | "elasticsearch" | "azure_sentinel" | "syslog" | "file";
export type AuditEventSeverity = "info" | "low" | "medium" | "high" | "critical";
export type AuditEventCategory =
  | "authentication"
  | "authorization"
  | "data_access"
  | "config_change"
  | "security_scan"
  | "policy_violation"
  | "system";

export interface SiemConfig {
  id: string;
  name: string;
  provider: SiemProvider;
  endpoint: string;
  apiKey?: string;
  index?: string;
  enabled: boolean;
  retryCount: number;
  batchSize: number;
  flushIntervalMs: number;
  createdAt: string;
  updatedAt: string;
}

export interface SecurityAuditEvent {
  id: string;
  timestamp: string;
  severity: AuditEventSeverity;
  category: AuditEventCategory;
  action: string;
  actor: string;
  actorType: "user" | "service" | "system";
  resource: string;
  resourceType: string;
  outcome: "success" | "failure" | "error";
  details: Record<string, unknown>;
  sourceIp?: string;
  userAgent?: string;
  correlationId?: string;
}

export interface SiemForwardResult {
  configId: string;
  provider: SiemProvider;
  eventsForwarded: number;
  eventsFailed: number;
  lastForwardedAt: string;
  errors: string[];
}

export interface AuditLogQuery {
  startTime?: string;
  endTime?: string;
  severity?: AuditEventSeverity[];
  category?: AuditEventCategory[];
  actor?: string;
  resource?: string;
  outcome?: "success" | "failure" | "error";
  limit?: number;
  offset?: number;
}

export interface AuditLogStats {
  totalEvents: number;
  eventsByCategory: Record<string, number>;
  eventsBySeverity: Record<string, number>;
  eventsByOutcome: Record<string, number>;
  timeRange: { start: string; end: string };
}

export interface ForwardQueue {
  pending: number;
  failed: number;
  lastFlush: string | null;
}

let db: Database.Database | null = null;
const DEFAULT_DB_PATH = path.join(process.cwd(), ".cicd-security", "audit-siem.db");

export function initAuditSiemDb(dbPath: string = DEFAULT_DB_PATH): {
  path: string;
  tables: string[];
} {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  db = new Database(dbPath);
  db.pragma("journal_mode = WAL");

  db.prepare(
    `CREATE TABLE IF NOT EXISTS siem_configs (
    id TEXT PRIMARY KEY, name TEXT, provider TEXT,
    endpoint TEXT, api_key TEXT, index_name TEXT,
    enabled INTEGER, retry_count INTEGER, batch_size INTEGER,
    flush_interval_ms INTEGER, created_at TEXT, updated_at TEXT
  )`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY, timestamp TEXT, severity TEXT,
    category TEXT, action TEXT, actor TEXT, actor_type TEXT,
    resource TEXT, resource_type TEXT, outcome TEXT,
    details TEXT, source_ip TEXT, user_agent TEXT, correlation_id TEXT,
    forwarded INTEGER DEFAULT 0
  )`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS forward_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT,
    config_id TEXT, status TEXT, attempts INTEGER,
    last_attempt TEXT, error TEXT
  )`
  ).run();

  db.prepare(`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp)`).run();
  db.prepare(`CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_events(severity)`).run();
  db.prepare(`CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_events(category)`).run();

  return { path: dbPath, tables: ["siem_configs", "audit_events", "forward_queue"] };
}

function getDb(): Database.Database {
  if (!db) initAuditSiemDb();
  return db!;
}

// SIEM Configuration Management
export function createSiemConfig(
  config: Omit<SiemConfig, "id" | "createdAt" | "updatedAt">
): SiemConfig {
  const id = `siem-${Date.now()}`;
  const now = new Date().toISOString();

  const record: SiemConfig = { ...config, id, createdAt: now, updatedAt: now };

  getDb()
    .prepare(
      `INSERT INTO siem_configs (id, name, provider, endpoint, api_key, index_name, enabled, retry_count, batch_size, flush_interval_ms, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      id,
      config.name,
      config.provider,
      config.endpoint,
      config.apiKey || null,
      config.index || null,
      config.enabled ? 1 : 0,
      config.retryCount,
      config.batchSize,
      config.flushIntervalMs,
      now,
      now
    );

  return record;
}

export function getSiemConfig(configId: string): SiemConfig | null {
  const row = getDb().prepare("SELECT * FROM siem_configs WHERE id = ?").get(configId) as
    | Record<string, unknown>
    | undefined;
  if (!row) return null;

  return {
    id: row.id as string,
    name: row.name as string,
    provider: row.provider as SiemProvider,
    endpoint: row.endpoint as string,
    apiKey: row.api_key as string | undefined,
    index: row.index_name as string | undefined,
    enabled: Boolean(row.enabled),
    retryCount: row.retry_count as number,
    batchSize: row.batch_size as number,
    flushIntervalMs: row.flush_interval_ms as number,
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
  };
}

export function listSiemConfigs(provider?: SiemProvider): SiemConfig[] {
  let sql = "SELECT * FROM siem_configs";
  const params: string[] = [];
  if (provider) {
    sql += " WHERE provider = ?";
    params.push(provider);
  }
  sql += " ORDER BY name";

  return (
    getDb()
      .prepare(sql)
      .all(...params) as Array<Record<string, unknown>>
  ).map((row) => ({
    id: row.id as string,
    name: row.name as string,
    provider: row.provider as SiemProvider,
    endpoint: row.endpoint as string,
    apiKey: row.api_key as string | undefined,
    index: row.index_name as string | undefined,
    enabled: Boolean(row.enabled),
    retryCount: row.retry_count as number,
    batchSize: row.batch_size as number,
    flushIntervalMs: row.flush_interval_ms as number,
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
  }));
}

export function updateSiemConfig(
  configId: string,
  updates: Partial<Omit<SiemConfig, "id" | "createdAt">>
): SiemConfig | null {
  const existing = getSiemConfig(configId);
  if (!existing) return null;

  const now = new Date().toISOString();
  const updated = { ...existing, ...updates, updatedAt: now };

  getDb()
    .prepare(
      `UPDATE siem_configs SET name = ?, provider = ?, endpoint = ?, api_key = ?, index_name = ?, enabled = ?, retry_count = ?, batch_size = ?, flush_interval_ms = ?, updated_at = ?
     WHERE id = ?`
    )
    .run(
      updated.name,
      updated.provider,
      updated.endpoint,
      updated.apiKey || null,
      updated.index || null,
      updated.enabled ? 1 : 0,
      updated.retryCount,
      updated.batchSize,
      updated.flushIntervalMs,
      now,
      configId
    );

  return updated;
}

export function deleteSiemConfig(configId: string): boolean {
  const result = getDb().prepare("DELETE FROM siem_configs WHERE id = ?").run(configId);
  return result.changes > 0;
}

// Audit Event Logging
export function logSecurityEvent(
  event: Omit<SecurityAuditEvent, "id" | "timestamp">
): SecurityAuditEvent {
  const id = `evt-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const timestamp = new Date().toISOString();

  const record: SecurityAuditEvent = { ...event, id, timestamp };

  getDb()
    .prepare(
      `INSERT INTO audit_events (id, timestamp, severity, category, action, actor, actor_type, resource, resource_type, outcome, details, source_ip, user_agent, correlation_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      id,
      timestamp,
      event.severity,
      event.category,
      event.action,
      event.actor,
      event.actorType,
      event.resource,
      event.resourceType,
      event.outcome,
      JSON.stringify(event.details),
      event.sourceIp || null,
      event.userAgent || null,
      event.correlationId || null
    );

  // Queue for forwarding
  const configs = listSiemConfigs().filter((c) => c.enabled);
  for (const config of configs) {
    getDb()
      .prepare(
        "INSERT INTO forward_queue (event_id, config_id, status, attempts, last_attempt) VALUES (?, ?, 'pending', 0, NULL)"
      )
      .run(id, config.id);
  }

  return record;
}

export function queryAuditLogs(query: AuditLogQuery): SecurityAuditEvent[] {
  let sql = "SELECT * FROM audit_events WHERE 1=1";
  const params: (string | number)[] = [];

  if (query.startTime) {
    sql += " AND timestamp >= ?";
    params.push(query.startTime);
  }
  if (query.endTime) {
    sql += " AND timestamp <= ?";
    params.push(query.endTime);
  }
  if (query.severity?.length) {
    sql += ` AND severity IN (${query.severity.map(() => "?").join(",")})`;
    params.push(...query.severity);
  }
  if (query.category?.length) {
    sql += ` AND category IN (${query.category.map(() => "?").join(",")})`;
    params.push(...query.category);
  }
  if (query.actor) {
    sql += " AND actor LIKE ?";
    params.push(`%${query.actor}%`);
  }
  if (query.resource) {
    sql += " AND resource LIKE ?";
    params.push(`%${query.resource}%`);
  }
  if (query.outcome) {
    sql += " AND outcome = ?";
    params.push(query.outcome);
  }

  sql += " ORDER BY timestamp DESC";

  if (query.limit) {
    sql += " LIMIT ?";
    params.push(query.limit);
  }
  if (query.offset) {
    sql += " OFFSET ?";
    params.push(query.offset);
  }

  return (
    getDb()
      .prepare(sql)
      .all(...params) as Array<Record<string, unknown>>
  ).map((row) => ({
    id: row.id as string,
    timestamp: row.timestamp as string,
    severity: row.severity as AuditEventSeverity,
    category: row.category as AuditEventCategory,
    action: row.action as string,
    actor: row.actor as string,
    actorType: row.actor_type as "user" | "service" | "system",
    resource: row.resource as string,
    resourceType: row.resource_type as string,
    outcome: row.outcome as "success" | "failure" | "error",
    details: JSON.parse(row.details as string),
    sourceIp: row.source_ip as string | undefined,
    userAgent: row.user_agent as string | undefined,
    correlationId: row.correlation_id as string | undefined,
  }));
}

export function getAuditLogStats(startTime?: string, endTime?: string): AuditLogStats {
  let whereClause = "WHERE 1=1";
  const params: string[] = [];

  if (startTime) {
    whereClause += " AND timestamp >= ?";
    params.push(startTime);
  }
  if (endTime) {
    whereClause += " AND timestamp <= ?";
    params.push(endTime);
  }

  const total = (
    getDb()
      .prepare(`SELECT COUNT(*) as count FROM audit_events ${whereClause}`)
      .get(...params) as { count: number }
  ).count;

  const categoryRows = getDb()
    .prepare(
      `SELECT category, COUNT(*) as count FROM audit_events ${whereClause} GROUP BY category`
    )
    .all(...params) as Array<{ category: string; count: number }>;
  const severityRows = getDb()
    .prepare(
      `SELECT severity, COUNT(*) as count FROM audit_events ${whereClause} GROUP BY severity`
    )
    .all(...params) as Array<{ severity: string; count: number }>;
  const outcomeRows = getDb()
    .prepare(`SELECT outcome, COUNT(*) as count FROM audit_events ${whereClause} GROUP BY outcome`)
    .all(...params) as Array<{ outcome: string; count: number }>;

  const timeRange = getDb()
    .prepare(
      `SELECT MIN(timestamp) as start, MAX(timestamp) as end FROM audit_events ${whereClause}`
    )
    .get(...params) as { start: string; end: string };

  return {
    totalEvents: total,
    eventsByCategory: Object.fromEntries(categoryRows.map((r) => [r.category, r.count])),
    eventsBySeverity: Object.fromEntries(severityRows.map((r) => [r.severity, r.count])),
    eventsByOutcome: Object.fromEntries(outcomeRows.map((r) => [r.outcome, r.count])),
    timeRange: { start: timeRange.start || "", end: timeRange.end || "" },
  };
}

// SIEM Forwarding
export async function forwardToSiem(configId: string): Promise<SiemForwardResult> {
  const config = getSiemConfig(configId);
  if (!config) throw new Error(`SIEM config not found: ${configId}`);
  if (!config.enabled) throw new Error(`SIEM config is disabled: ${configId}`);

  const pendingEvents = getDb()
    .prepare(
      `SELECT ae.*, fq.id as queue_id FROM audit_events ae
     JOIN forward_queue fq ON ae.id = fq.event_id
     WHERE fq.config_id = ? AND fq.status = 'pending'
     LIMIT ?`
    )
    .all(configId, config.batchSize) as Array<Record<string, unknown>>;

  const result: SiemForwardResult = {
    configId,
    provider: config.provider,
    eventsForwarded: 0,
    eventsFailed: 0,
    lastForwardedAt: new Date().toISOString(),
    errors: [],
  };

  for (const event of pendingEvents) {
    try {
      await forwardEvent(config, event);
      getDb()
        .prepare("UPDATE forward_queue SET status = 'sent', last_attempt = ? WHERE id = ?")
        .run(new Date().toISOString(), event.queue_id);
      result.eventsForwarded++;
    } catch (error) {
      const attempts = (event.attempts as number) + 1;
      const status = attempts >= config.retryCount ? "failed" : "pending";
      getDb()
        .prepare(
          "UPDATE forward_queue SET status = ?, attempts = ?, last_attempt = ?, error = ? WHERE id = ?"
        )
        .run(status, attempts, new Date().toISOString(), String(error), event.queue_id);
      result.eventsFailed++;
      result.errors.push(error instanceof Error ? error.message : String(error));
    }
  }

  return result;
}

async function forwardEvent(config: SiemConfig, event: Record<string, unknown>): Promise<void> {
  const payload = formatEventForProvider(config.provider, event);

  switch (config.provider) {
    case "splunk":
      await sendToSplunk(config, payload);
      break;
    case "elasticsearch":
      await sendToElasticsearch(config, payload);
      break;
    case "azure_sentinel":
      await sendToAzureSentinel(config, payload);
      break;
    case "syslog":
      await sendToSyslog(config, payload);
      break;
    case "file":
      await writeToFile(config, payload);
      break;
    default:
      throw new Error(`Unsupported SIEM provider: ${config.provider}`);
  }
}

function formatEventForProvider(provider: SiemProvider, event: Record<string, unknown>): string {
  const baseEvent = {
    id: event.id,
    timestamp: event.timestamp,
    severity: event.severity,
    category: event.category,
    action: event.action,
    actor: event.actor,
    actorType: event.actor_type,
    resource: event.resource,
    resourceType: event.resource_type,
    outcome: event.outcome,
    details: typeof event.details === "string" ? JSON.parse(event.details) : event.details,
    sourceIp: event.source_ip,
    userAgent: event.user_agent,
    correlationId: event.correlation_id,
  };

  switch (provider) {
    case "splunk":
      return JSON.stringify({ event: baseEvent, sourcetype: "cicd-security" });
    case "elasticsearch":
      return JSON.stringify(baseEvent);
    case "azure_sentinel":
      return JSON.stringify({
        TimeGenerated: event.timestamp,
        ...baseEvent,
      });
    case "syslog":
      return `<134>1 ${event.timestamp} cicd-security - - - ${JSON.stringify(baseEvent)}`;
    case "file":
    default:
      return JSON.stringify(baseEvent);
  }
}

async function sendToSplunk(config: SiemConfig, payload: string): Promise<void> {
  const response = await fetch(`${config.endpoint}/services/collector/event`, {
    method: "POST",
    headers: {
      Authorization: `Splunk ${config.apiKey}`,
      "Content-Type": "application/json",
    },
    body: payload,
  });
  if (!response.ok) throw new Error(`Splunk error: ${response.statusText}`);
}

async function sendToElasticsearch(config: SiemConfig, payload: string): Promise<void> {
  const indexName = config.index || "cicd-security";
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (config.apiKey) headers["Authorization"] = `ApiKey ${config.apiKey}`;

  const response = await fetch(`${config.endpoint}/${indexName}/_doc`, {
    method: "POST",
    headers,
    body: payload,
  });
  if (!response.ok) throw new Error(`Elasticsearch error: ${response.statusText}`);
}

async function sendToAzureSentinel(config: SiemConfig, payload: string): Promise<void> {
  const response = await fetch(config.endpoint, {
    method: "POST",
    headers: {
      Authorization: `SharedKey ${config.apiKey}`,
      "Content-Type": "application/json",
      "Log-Type": "CICDSecurity",
    },
    body: payload,
  });
  if (!response.ok) throw new Error(`Azure Sentinel error: ${response.statusText}`);
}

async function sendToSyslog(config: SiemConfig, payload: string): Promise<void> {
  // In production, would use UDP/TCP syslog client
  // For now, simulate by logging
  console.log(`[SYSLOG] ${config.endpoint}: ${payload}`);
}

async function writeToFile(config: SiemConfig, payload: string): Promise<void> {
  const logPath = config.endpoint || path.join(process.cwd(), ".cicd-security", "audit.log");
  const dir = path.dirname(logPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.appendFileSync(logPath, payload + "\n");
}

// Queue Management
export function getForwardQueue(configId?: string): ForwardQueue {
  let pendingQuery = "SELECT COUNT(*) as count FROM forward_queue WHERE status = 'pending'";
  let failedQuery = "SELECT COUNT(*) as count FROM forward_queue WHERE status = 'failed'";
  let lastFlushQuery = "SELECT MAX(last_attempt) as last FROM forward_queue WHERE status = 'sent'";
  const params: string[] = [];

  if (configId) {
    pendingQuery += " AND config_id = ?";
    failedQuery += " AND config_id = ?";
    lastFlushQuery += " AND config_id = ?";
    params.push(configId);
  }

  const pending = (
    getDb()
      .prepare(pendingQuery)
      .get(...params) as { count: number }
  ).count;
  const failed = (
    getDb()
      .prepare(failedQuery)
      .get(...params) as { count: number }
  ).count;
  const lastFlush = (
    getDb()
      .prepare(lastFlushQuery)
      .get(...params) as { last: string | null }
  ).last;

  return { pending, failed, lastFlush };
}

export function retryFailedEvents(configId: string): number {
  const result = getDb()
    .prepare(
      "UPDATE forward_queue SET status = 'pending', attempts = 0 WHERE config_id = ? AND status = 'failed'"
    )
    .run(configId);
  return result.changes;
}

export function clearForwardQueue(
  configId: string,
  status?: "pending" | "sent" | "failed"
): number {
  let sql = "DELETE FROM forward_queue WHERE config_id = ?";
  const params: string[] = [configId];
  if (status) {
    sql += " AND status = ?";
    params.push(status);
  }
  const result = getDb()
    .prepare(sql)
    .run(...params);
  return result.changes;
}

// Test Connection
export async function testSiemConnection(
  configId: string
): Promise<{ success: boolean; message: string; latencyMs: number }> {
  const config = getSiemConfig(configId);
  if (!config) return { success: false, message: "Config not found", latencyMs: 0 };

  const start = Date.now();
  try {
    const testEvent: Omit<SecurityAuditEvent, "id" | "timestamp"> = {
      severity: "info",
      category: "system",
      action: "connection_test",
      actor: "system",
      actorType: "system",
      resource: configId,
      resourceType: "siem_config",
      outcome: "success",
      details: { test: true },
    };

    // Format and forward test event
    await forwardEvent(config, {
      ...testEvent,
      id: "test",
      timestamp: new Date().toISOString(),
      details: JSON.stringify(testEvent.details),
    });

    return {
      success: true,
      message: `Successfully connected to ${config.provider}`,
      latencyMs: Date.now() - start,
    };
  } catch (error) {
    return {
      success: false,
      message: error instanceof Error ? error.message : String(error),
      latencyMs: Date.now() - start,
    };
  }
}

export const auditSiem = {
  initAuditSiemDb,
  createSiemConfig,
  getSiemConfig,
  listSiemConfigs,
  updateSiemConfig,
  deleteSiemConfig,
  logSecurityEvent,
  queryAuditLogs,
  getAuditLogStats,
  forwardToSiem,
  getForwardQueue,
  retryFailedEvents,
  clearForwardQueue,
  testSiemConnection,
};
