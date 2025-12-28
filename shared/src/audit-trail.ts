/**
 * Comprehensive Audit Trail System
 *
 * Provides audit logging for all security-relevant actions with:
 * - SQLite persistence with indexing
 * - Tamper-evident checksums
 * - Full-text search
 * - Export to JSON/CSV/NDJSON
 * - SIEM integration (Splunk, ELK)
 * - Configurable retention
 */

import Database from "better-sqlite3";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import type {
  AuditActorType,
  AuditActionCategory,
  AuditAction,
  AuditResourceType,
  AuditOutcome,
  AuditActor,
  AuditResource,
  AuditContext,
  AuditEvent,
  CreateAuditEventOptions,
  AuditSearchOptions,
  AuditExportFormat,
  AuditExportOptions,
  AuditExportResult,
  AuditSiemConfig,
  AuditConfig,
  AuditDbInitResult,
  AuditStats,
  AuditAggregateOptions,
  AuditAggregateResult,
} from "./types.js";

// =============================================================================
// Database Schema
// =============================================================================

const SCHEMA = `
-- Audit events table
CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  actor_email TEXT,
  actor_name TEXT,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  resource_name TEXT,
  context_json TEXT,
  outcome TEXT NOT NULL,
  details_json TEXT,
  checksum TEXT
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_actor_id ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor_type ON audit_events(actor_type);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_audit_resource_type ON audit_events(resource_type);
CREATE INDEX IF NOT EXISTS idx_audit_resource_id ON audit_events(resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_outcome ON audit_events(outcome);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp_actor ON audit_events(timestamp, actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp_action ON audit_events(timestamp, action);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp_resource ON audit_events(timestamp, resource_type, resource_id);

-- Configuration table
CREATE TABLE IF NOT EXISTS audit_config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- SIEM queue for batched sending
CREATE TABLE IF NOT EXISTS audit_siem_queue (
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL,
  queued_at TEXT NOT NULL,
  retry_count INTEGER DEFAULT 0,
  FOREIGN KEY (event_id) REFERENCES audit_events(id) ON DELETE CASCADE
);
`;

// =============================================================================
// Module State
// =============================================================================

let db: Database.Database | null = null;
let config: AuditConfig = {
  retentionDays: 90,
  tamperProof: true,
  realTimeStreaming: false,
};

// Event listeners for real-time streaming
type AuditEventListener = (event: AuditEvent) => void;
const eventListeners: AuditEventListener[] = [];

// =============================================================================
// Database Lifecycle
// =============================================================================

/**
 * Get default database path
 */
function getDefaultDbPath(): string {
  const dataDir = process.env.CICD_DATA_DIR || path.join(process.cwd(), ".cicd-data");
  return path.join(dataDir, "audit.db");
}

/**
 * Initialize the audit database
 */
export function initAuditDatabase(
  customPath?: string,
  initialConfig?: Partial<AuditConfig>
): AuditDbInitResult {
  const dbPath = customPath || getDefaultDbPath();
  try {
    const created = !fs.existsSync(dbPath);

    // Ensure directory exists
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    db.exec(SCHEMA);

    // Apply initial config
    if (initialConfig) {
      config = { ...config, ...initialConfig };
    }

    // Store config in database
    const upsertConfig = db.prepare(
      "INSERT OR REPLACE INTO audit_config (key, value) VALUES (?, ?)"
    );
    upsertConfig.run("retentionDays", String(config.retentionDays));
    upsertConfig.run("tamperProof", config.tamperProof ? "true" : "false");
    upsertConfig.run("realTimeStreaming", config.realTimeStreaming ? "true" : "false");

    if (config.siem) {
      upsertConfig.run("siemConfig", JSON.stringify(config.siem));
    }

    return { success: true, path: dbPath, created };
  } catch (error) {
    return {
      success: false,
      path: dbPath,
      created: false,
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}

/**
 * Close the audit database
 */
export function closeAuditDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

/**
 * Check if audit database is initialized
 */
export function isAuditDbInitialized(): boolean {
  return db !== null;
}

/**
 * Get current audit configuration
 */
export function getAuditConfig(): AuditConfig {
  return { ...config };
}

/**
 * Update audit configuration
 */
export function updateAuditConfig(updates: Partial<AuditConfig>): AuditConfig {
  config = { ...config, ...updates };

  if (db) {
    const upsertConfig = db.prepare(
      "INSERT OR REPLACE INTO audit_config (key, value) VALUES (?, ?)"
    );
    if (updates.retentionDays !== undefined) {
      upsertConfig.run("retentionDays", String(config.retentionDays));
    }
    if (updates.tamperProof !== undefined) {
      upsertConfig.run("tamperProof", config.tamperProof ? "true" : "false");
    }
    if (updates.realTimeStreaming !== undefined) {
      upsertConfig.run("realTimeStreaming", config.realTimeStreaming ? "true" : "false");
    }
    if (updates.siem !== undefined) {
      upsertConfig.run("siemConfig", JSON.stringify(config.siem));
    }
  }

  return { ...config };
}

// =============================================================================
// Checksum Functions
// =============================================================================

/**
 * Calculate checksum for an audit event (tamper detection)
 */
function calculateChecksum(event: Omit<AuditEvent, "checksum">): string {
  const data = JSON.stringify({
    id: event.id,
    timestamp: event.timestamp,
    actor: event.actor,
    action: event.action,
    resource: event.resource,
    context: event.context,
    outcome: event.outcome,
    details: event.details,
  });
  return crypto.createHash("sha256").update(data).digest("hex");
}

/**
 * Verify checksum for an audit event
 */
export function verifyEventChecksum(event: AuditEvent): boolean {
  if (!event.checksum) return true; // No checksum to verify
  const calculated = calculateChecksum(event);
  return calculated === event.checksum;
}

// =============================================================================
// Event Listeners (Real-time Streaming)
// =============================================================================

/**
 * Add event listener for real-time audit streaming
 */
export function addAuditEventListener(listener: AuditEventListener): void {
  eventListeners.push(listener);
}

/**
 * Remove event listener
 */
export function removeAuditEventListener(listener: AuditEventListener): void {
  const index = eventListeners.indexOf(listener);
  if (index > -1) {
    eventListeners.splice(index, 1);
  }
}

/**
 * Notify all listeners of new event
 */
function notifyListeners(event: AuditEvent): void {
  if (config.realTimeStreaming) {
    for (const listener of eventListeners) {
      try {
        listener(event);
      } catch {
        // Ignore listener errors
      }
    }
  }
}

// =============================================================================
// CRUD Operations
// =============================================================================

/**
 * Generate a unique ID
 */
function generateId(): string {
  return crypto.randomUUID();
}

/**
 * Log an audit event
 */
export function logAuditEvent(options: CreateAuditEventOptions): AuditEvent {
  if (!db) {
    throw new Error("Audit database not initialized");
  }

  const id = generateId();
  const timestamp = new Date().toISOString();

  const event: AuditEvent = {
    id,
    timestamp,
    actor: options.actor,
    action: options.action,
    resource: options.resource,
    context: options.context || {},
    outcome: options.outcome,
    details: options.details,
  };

  // Calculate checksum if tamper-proof is enabled
  if (config.tamperProof) {
    event.checksum = calculateChecksum(event);
  }

  const stmt = db.prepare(`
    INSERT INTO audit_events (
      id, timestamp, actor_type, actor_id, actor_email, actor_name,
      action, resource_type, resource_id, resource_name,
      context_json, outcome, details_json, checksum
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    event.id,
    event.timestamp,
    event.actor.type,
    event.actor.id,
    event.actor.email || null,
    event.actor.name || null,
    event.action,
    event.resource.type,
    event.resource.id,
    event.resource.name || null,
    JSON.stringify(event.context),
    event.outcome,
    event.details ? JSON.stringify(event.details) : null,
    event.checksum || null
  );

  // Queue for SIEM if configured
  if (config.siem?.enabled) {
    queueForSiem(event.id);
  }

  // Notify real-time listeners
  notifyListeners(event);

  return event;
}

/**
 * Get an audit event by ID
 */
export function getAuditEvent(id: string): AuditEvent | null {
  if (!db) {
    throw new Error("Audit database not initialized");
  }

  const stmt = db.prepare("SELECT * FROM audit_events WHERE id = ?");
  const row = stmt.get(id) as Record<string, unknown> | undefined;

  if (!row) return null;

  return rowToEvent(row);
}

/**
 * Convert database row to AuditEvent
 */
function rowToEvent(row: Record<string, unknown>): AuditEvent {
  return {
    id: row.id as string,
    timestamp: row.timestamp as string,
    actor: {
      type: row.actor_type as AuditActorType,
      id: row.actor_id as string,
      email: row.actor_email as string | undefined,
      name: row.actor_name as string | undefined,
    },
    action: row.action as AuditAction,
    resource: {
      type: row.resource_type as AuditResourceType,
      id: row.resource_id as string,
      name: row.resource_name as string | undefined,
    },
    context: row.context_json ? JSON.parse(row.context_json as string) : {},
    outcome: row.outcome as AuditOutcome,
    details: row.details_json ? JSON.parse(row.details_json as string) : undefined,
    checksum: row.checksum as string | undefined,
  };
}

/**
 * Get action category from action string
 */
export function getActionCategory(action: AuditAction): AuditActionCategory {
  if (action.startsWith("auth.")) return "authentication";
  if (action.startsWith("authz.")) return "authorization";
  if (action.startsWith("scan.")) return "scan";
  if (action.startsWith("policy.")) return "policy";
  if (action.startsWith("suppression.")) return "suppression";
  if (action.startsWith("admin.")) return "admin";
  if (action.startsWith("data.")) return "data";
  return "admin"; // Default fallback
}

/**
 * Search audit events with filters
 */
export function searchAuditEvents(options: AuditSearchOptions = {}): AuditEvent[] {
  if (!db) {
    throw new Error("Audit database not initialized");
  }

  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options.actorId) {
    conditions.push("actor_id = ?");
    params.push(options.actorId);
  }

  if (options.actorType) {
    conditions.push("actor_type = ?");
    params.push(options.actorType);
  }

  if (options.action) {
    conditions.push("action = ?");
    params.push(options.action);
  }

  if (options.actionCategory) {
    conditions.push("action LIKE ?");
    const prefix =
      options.actionCategory === "authentication"
        ? "auth."
        : options.actionCategory === "authorization"
          ? "authz."
          : `${options.actionCategory}.`;
    params.push(`${prefix}%`);
  }

  if (options.resourceType) {
    conditions.push("resource_type = ?");
    params.push(options.resourceType);
  }

  if (options.resourceId) {
    conditions.push("resource_id = ?");
    params.push(options.resourceId);
  }

  if (options.outcome) {
    conditions.push("outcome = ?");
    params.push(options.outcome);
  }

  if (options.startTime) {
    conditions.push("timestamp >= ?");
    params.push(options.startTime);
  }

  if (options.endTime) {
    conditions.push("timestamp <= ?");
    params.push(options.endTime);
  }

  if (options.query) {
    // Simple text search across multiple fields
    conditions.push(`(
      actor_id LIKE ? OR
      actor_email LIKE ? OR
      actor_name LIKE ? OR
      resource_id LIKE ? OR
      resource_name LIKE ? OR
      details_json LIKE ?
    )`);
    const searchPattern = `%${options.query}%`;
    params.push(
      searchPattern,
      searchPattern,
      searchPattern,
      searchPattern,
      searchPattern,
      searchPattern
    );
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const sortOrder = options.sortOrder === "asc" ? "ASC" : "DESC";
  const limit = options.limit || 100;
  const offset = options.offset || 0;

  const sql = `
    SELECT * FROM audit_events
    ${whereClause}
    ORDER BY timestamp ${sortOrder}
    LIMIT ? OFFSET ?
  `;

  params.push(limit, offset);

  const stmt = db.prepare(sql);
  const rows = stmt.all(...params) as Record<string, unknown>[];

  return rows.map(rowToEvent);
}

// =============================================================================
// Export Functions
// =============================================================================

/**
 * Export audit events to JSON
 */
function exportToJson(events: AuditEvent[], includeChecksum: boolean): string {
  const exportEvents = includeChecksum ? events : events.map(({ checksum: _, ...rest }) => rest);
  return JSON.stringify(exportEvents, null, 2);
}

/**
 * Export audit events to CSV
 */
function exportToCsv(events: AuditEvent[], includeChecksum: boolean): string {
  const headers = [
    "id",
    "timestamp",
    "actor_type",
    "actor_id",
    "actor_email",
    "actor_name",
    "action",
    "resource_type",
    "resource_id",
    "resource_name",
    "outcome",
    "context",
    "details",
  ];

  if (includeChecksum) {
    headers.push("checksum");
  }

  const rows = events.map((event) => {
    const row = [
      event.id,
      event.timestamp,
      event.actor.type,
      event.actor.id,
      event.actor.email || "",
      event.actor.name || "",
      event.action,
      event.resource.type,
      event.resource.id,
      event.resource.name || "",
      event.outcome,
      JSON.stringify(event.context),
      event.details ? JSON.stringify(event.details) : "",
    ];

    if (includeChecksum) {
      row.push(event.checksum || "");
    }

    return row.map((val) => `"${String(val).replace(/"/g, '""')}"`).join(",");
  });

  return [headers.join(","), ...rows].join("\n");
}

/**
 * Export audit events to NDJSON (newline-delimited JSON)
 */
function exportToNdjson(events: AuditEvent[], includeChecksum: boolean): string {
  return events
    .map((event) => {
      if (includeChecksum) {
        return JSON.stringify(event);
      }
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { checksum: _, ...rest } = event;
      return JSON.stringify(rest);
    })
    .join("\n");
}

/**
 * Export audit logs
 */
export function exportAuditLogs(options: AuditExportOptions = {}): AuditExportResult {
  try {
    const events = searchAuditEvents(options.filters);
    const format = options.format || "json";
    const includeChecksum = options.includeChecksum ?? false;

    let data: string;
    switch (format) {
      case "csv":
        data = exportToCsv(events, includeChecksum);
        break;
      case "ndjson":
        data = exportToNdjson(events, includeChecksum);
        break;
      default:
        data = exportToJson(events, includeChecksum);
    }

    if (options.outputPath) {
      fs.writeFileSync(options.outputPath, data);
      return {
        success: true,
        count: events.length,
        format,
        path: options.outputPath,
      };
    }

    return {
      success: true,
      count: events.length,
      format,
      data,
    };
  } catch (error) {
    return {
      success: false,
      count: 0,
      format: options.format || "json",
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}

// =============================================================================
// SIEM Integration
// =============================================================================

/**
 * Queue event for SIEM delivery
 */
function queueForSiem(eventId: string): void {
  if (!db) return;

  const stmt = db.prepare(`
    INSERT INTO audit_siem_queue (id, event_id, queued_at)
    VALUES (?, ?, ?)
  `);

  stmt.run(generateId(), eventId, new Date().toISOString());
}

/**
 * Send events to SIEM endpoint
 */
export async function flushSiemQueue(): Promise<{
  sent: number;
  failed: number;
  errors: string[];
}> {
  if (!db || !config.siem?.enabled) {
    return { sent: 0, failed: 0, errors: ["SIEM not configured"] };
  }

  const batchSize = config.siem.batchSize || 100;
  const maxRetries = config.siem.retryAttempts || 3;

  // Get queued events
  const queuedStmt = db.prepare(`
    SELECT q.id as queue_id, q.retry_count, e.*
    FROM audit_siem_queue q
    JOIN audit_events e ON q.event_id = e.id
    WHERE q.retry_count < ?
    ORDER BY q.queued_at ASC
    LIMIT ?
  `);

  const queued = queuedStmt.all(maxRetries, batchSize) as Array<
    Record<string, unknown> & { queue_id: string; retry_count: number }
  >;

  if (queued.length === 0) {
    return { sent: 0, failed: 0, errors: [] };
  }

  const events = queued.map((row) => rowToEvent(row));
  const errors: string[] = [];
  let sent = 0;
  let failed = 0;

  try {
    const response = await fetch(config.siem.endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(config.siem.authToken ? { Authorization: `Bearer ${config.siem.authToken}` } : {}),
        ...config.siem.headers,
      },
      body: JSON.stringify(events),
    });

    if (response.ok) {
      // Remove from queue on success
      const deleteStmt = db.prepare("DELETE FROM audit_siem_queue WHERE id = ?");
      for (const row of queued) {
        deleteStmt.run(row.queue_id);
      }
      sent = queued.length;
    } else {
      // Increment retry count
      const updateStmt = db.prepare(
        "UPDATE audit_siem_queue SET retry_count = retry_count + 1 WHERE id = ?"
      );
      for (const row of queued) {
        updateStmt.run(row.queue_id);
      }
      failed = queued.length;
      errors.push(`SIEM endpoint returned ${response.status}: ${response.statusText}`);
    }
  } catch (error) {
    // Increment retry count on error
    const updateStmt = db.prepare(
      "UPDATE audit_siem_queue SET retry_count = retry_count + 1 WHERE id = ?"
    );
    for (const row of queued) {
      updateStmt.run(row.queue_id);
    }
    failed = queued.length;
    errors.push(error instanceof Error ? error.message : "Unknown error");
  }

  return { sent, failed, errors };
}

/**
 * Configure SIEM integration
 */
export function configureSiem(siemConfig: AuditSiemConfig): void {
  config.siem = siemConfig;

  if (db) {
    const stmt = db.prepare("INSERT OR REPLACE INTO audit_config (key, value) VALUES (?, ?)");
    stmt.run("siemConfig", JSON.stringify(siemConfig));
  }
}

/**
 * Get SIEM queue status
 */
export function getSiemQueueStatus(): {
  pending: number;
  failed: number;
  oldestQueued?: string;
} {
  if (!db) {
    return { pending: 0, failed: 0 };
  }

  const maxRetries = config.siem?.retryAttempts || 3;

  const pendingStmt = db.prepare(
    "SELECT COUNT(*) as count FROM audit_siem_queue WHERE retry_count < ?"
  );
  const failedStmt = db.prepare(
    "SELECT COUNT(*) as count FROM audit_siem_queue WHERE retry_count >= ?"
  );
  const oldestStmt = db.prepare(
    "SELECT MIN(queued_at) as oldest FROM audit_siem_queue WHERE retry_count < ?"
  );

  const pending = (pendingStmt.get(maxRetries) as { count: number }).count;
  const failed = (failedStmt.get(maxRetries) as { count: number }).count;
  const oldest = (oldestStmt.get(maxRetries) as { oldest: string | null }).oldest;

  return {
    pending,
    failed,
    oldestQueued: oldest || undefined,
  };
}

// =============================================================================
// Statistics and Analytics
// =============================================================================

/**
 * Get audit statistics
 */
export function getAuditStats(): AuditStats {
  if (!db) {
    throw new Error("Audit database not initialized");
  }

  const now = new Date();
  const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
  const last7d = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const last30d = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();

  // Total events
  const totalStmt = db.prepare("SELECT COUNT(*) as count FROM audit_events");
  const total = (totalStmt.get() as { count: number }).count;

  // By outcome
  const outcomeStmt = db.prepare(
    "SELECT outcome, COUNT(*) as count FROM audit_events GROUP BY outcome"
  );
  const outcomeRows = outcomeStmt.all() as Array<{ outcome: string; count: number }>;
  const byOutcome = {
    success: outcomeRows.find((r) => r.outcome === "success")?.count || 0,
    failure: outcomeRows.find((r) => r.outcome === "failure")?.count || 0,
  };

  // By category (using action prefix)
  const categories: AuditActionCategory[] = [
    "authentication",
    "authorization",
    "scan",
    "policy",
    "suppression",
    "admin",
    "data",
  ];
  const byCategory: Record<AuditActionCategory, number> = {} as Record<AuditActionCategory, number>;

  for (const cat of categories) {
    const prefix =
      cat === "authentication" ? "auth." : cat === "authorization" ? "authz." : `${cat}.`;
    const stmt = db.prepare("SELECT COUNT(*) as count FROM audit_events WHERE action LIKE ?");
    byCategory[cat] = (stmt.get(`${prefix}%`) as { count: number }).count;
  }

  // By actor type
  const actorTypes: AuditActorType[] = ["user", "apikey", "system"];
  const byActorType: Record<AuditActorType, number> = {} as Record<AuditActorType, number>;

  for (const type of actorTypes) {
    const stmt = db.prepare("SELECT COUNT(*) as count FROM audit_events WHERE actor_type = ?");
    byActorType[type] = (stmt.get(type) as { count: number }).count;
  }

  // Time-based counts
  const last24hStmt = db.prepare("SELECT COUNT(*) as count FROM audit_events WHERE timestamp >= ?");
  const last7dStmt = db.prepare("SELECT COUNT(*) as count FROM audit_events WHERE timestamp >= ?");
  const last30dStmt = db.prepare("SELECT COUNT(*) as count FROM audit_events WHERE timestamp >= ?");

  // Oldest and newest
  const oldestStmt = db.prepare("SELECT MIN(timestamp) as oldest FROM audit_events");
  const newestStmt = db.prepare("SELECT MAX(timestamp) as newest FROM audit_events");

  const oldest = (oldestStmt.get() as { oldest: string | null }).oldest;
  const newest = (newestStmt.get() as { newest: string | null }).newest;

  // Tamper detection
  let tamperDetected = false;
  let tamperedCount = 0;

  if (config.tamperProof) {
    const checksumStmt = db.prepare(
      "SELECT * FROM audit_events WHERE checksum IS NOT NULL LIMIT 1000"
    );
    const eventsToCheck = checksumStmt.all() as Record<string, unknown>[];

    for (const row of eventsToCheck) {
      const event = rowToEvent(row);
      if (!verifyEventChecksum(event)) {
        tamperDetected = true;
        tamperedCount++;
      }
    }
  }

  return {
    totalEvents: total,
    byOutcome,
    byCategory,
    byActorType,
    last24Hours: (last24hStmt.get(last24h) as { count: number }).count,
    last7Days: (last7dStmt.get(last7d) as { count: number }).count,
    last30Days: (last30dStmt.get(last30d) as { count: number }).count,
    oldestEvent: oldest || undefined,
    newestEvent: newest || undefined,
    tamperDetected,
    tamperedCount,
  };
}

/**
 * Aggregate audit events
 */
export function aggregateAuditEvents(options: AuditAggregateOptions): AuditAggregateResult[] {
  if (!db) {
    throw new Error("Audit database not initialized");
  }

  let groupByColumn: string;
  let selectExpr: string;

  switch (options.groupBy) {
    case "action":
      groupByColumn = "action";
      selectExpr = "action as key";
      break;
    case "actorId":
      groupByColumn = "actor_id";
      selectExpr = "actor_id as key";
      break;
    case "actorType":
      groupByColumn = "actor_type";
      selectExpr = "actor_type as key";
      break;
    case "resourceType":
      groupByColumn = "resource_type";
      selectExpr = "resource_type as key";
      break;
    case "outcome":
      groupByColumn = "outcome";
      selectExpr = "outcome as key";
      break;
    case "hour":
      groupByColumn = "strftime('%Y-%m-%d %H:00:00', timestamp)";
      selectExpr = "strftime('%Y-%m-%d %H:00:00', timestamp) as key";
      break;
    case "day":
      groupByColumn = "date(timestamp)";
      selectExpr = "date(timestamp) as key";
      break;
    default:
      throw new Error(`Invalid groupBy: ${options.groupBy}`);
  }

  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options.startTime) {
    conditions.push("timestamp >= ?");
    params.push(options.startTime);
  }

  if (options.endTime) {
    conditions.push("timestamp <= ?");
    params.push(options.endTime);
  }

  // Apply additional filters
  if (options.filters) {
    if (options.filters.actorId) {
      conditions.push("actor_id = ?");
      params.push(options.filters.actorId);
    }
    if (options.filters.outcome) {
      conditions.push("outcome = ?");
      params.push(options.filters.outcome);
    }
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

  const sql = `
    SELECT
      ${selectExpr},
      COUNT(*) as count,
      MIN(timestamp) as firstEvent,
      MAX(timestamp) as lastEvent
    FROM audit_events
    ${whereClause}
    GROUP BY ${groupByColumn}
    ORDER BY count DESC
  `;

  const stmt = db.prepare(sql);
  const rows = stmt.all(...params) as Array<{
    key: string;
    count: number;
    firstEvent: string;
    lastEvent: string;
  }>;

  return rows.map((row) => ({
    key: row.key,
    count: row.count,
    firstEvent: row.firstEvent,
    lastEvent: row.lastEvent,
  }));
}

// =============================================================================
// Maintenance Functions
// =============================================================================

/**
 * Cleanup old audit events based on retention policy
 */
export function cleanupExpiredAuditEvents(): number {
  if (!db) {
    throw new Error("Audit database not initialized");
  }

  const cutoffDate = new Date(
    Date.now() - config.retentionDays * 24 * 60 * 60 * 1000
  ).toISOString();

  const stmt = db.prepare("DELETE FROM audit_events WHERE timestamp < ?");
  const result = stmt.run(cutoffDate);

  return result.changes;
}

/**
 * Cleanup failed SIEM queue entries
 */
export function cleanupFailedSiemQueue(): number {
  if (!db) {
    throw new Error("Audit database not initialized");
  }

  const maxRetries = config.siem?.retryAttempts || 3;
  const stmt = db.prepare("DELETE FROM audit_siem_queue WHERE retry_count >= ?");
  const result = stmt.run(maxRetries);

  return result.changes;
}

/**
 * Verify integrity of all audit events (tamper detection)
 */
export function verifyAuditIntegrity(): {
  total: number;
  verified: number;
  tampered: number;
  tamperedIds: string[];
} {
  if (!db) {
    throw new Error("Audit database not initialized");
  }

  const stmt = db.prepare("SELECT * FROM audit_events WHERE checksum IS NOT NULL");
  const rows = stmt.all() as Record<string, unknown>[];

  let verified = 0;
  let tampered = 0;
  const tamperedIds: string[] = [];

  for (const row of rows) {
    const event = rowToEvent(row);
    if (verifyEventChecksum(event)) {
      verified++;
    } else {
      tampered++;
      tamperedIds.push(event.id);
    }
  }

  return {
    total: rows.length,
    verified,
    tampered,
    tamperedIds,
  };
}

// =============================================================================
// Re-exports for types
// =============================================================================

export type {
  AuditActorType,
  AuditActionCategory,
  AuditAction,
  AuditResourceType,
  AuditOutcome,
  AuditActor,
  AuditResource,
  AuditContext,
  AuditEvent,
  CreateAuditEventOptions,
  AuditSearchOptions,
  AuditExportFormat,
  AuditExportOptions,
  AuditExportResult,
  AuditSiemConfig,
  AuditConfig,
  AuditDbInitResult,
  AuditStats,
  AuditAggregateOptions,
  AuditAggregateResult,
};
