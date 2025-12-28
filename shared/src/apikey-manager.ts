/**
 * API Key Management Module
 *
 * Provides API key lifecycle management with scopes, expiration, rate limiting,
 * and audit logging for programmatic access to the platform.
 */

import Database from "better-sqlite3";
import * as crypto from "node:crypto";
import * as path from "node:path";
import * as fs from "node:fs";
import type {
  ApiKey,
  ApiKeyScope,
  ApiKeyStatus,
  ApiKeyEventType,
  ApiKeyCreateOptions,
  ApiKeyCreateResult,
  ApiKeyDisplay,
  ApiKeyValidationResult,
  ApiKeyRotateResult,
  ApiKeyAuditEvent,
  ApiKeyListOptions,
  ApiKeyDbInitResult,
} from "./types.js";

// =============================================================================
// Constants
// =============================================================================

const KEY_PREFIX = "ci-co_";
const KEY_LENGTH = 32;
const DEFAULT_EXPIRATION_DAYS = 90;
const DEFAULT_RATE_LIMIT = 100;
const RATE_WINDOW_MS = 60 * 1000;

export const VALID_SCOPES: ApiKeyScope[] = [
  "scan:read",
  "scan:write",
  "policy:read",
  "policy:write",
  "suppression:read",
  "suppression:write",
  "report:read",
  "report:write",
  "admin:*",
];

// =============================================================================
// Database
// =============================================================================

let db: Database.Database | null = null;

export function initApiKeyDatabase(dbPath?: string): ApiKeyDbInitResult {
  const actualPath = dbPath || path.join(process.cwd(), "data", "apikeys.db");
  const dir = path.dirname(actualPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const isNew = !fs.existsSync(actualPath);

  try {
    db = new Database(actualPath);
    db.pragma("journal_mode = WAL");

    db.prepare(
      `
      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        key_prefix TEXT NOT NULL,
        key_hash TEXT NOT NULL,
        scopes_json TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        expires_at TEXT,
        last_used_at TEXT,
        created_by TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        ip_allowlist_json TEXT,
        rate_limit INTEGER DEFAULT 100,
        request_count INTEGER DEFAULT 0,
        rate_window_start TEXT
      )
    `
    ).run();

    db.prepare(
      `
      CREATE TABLE IF NOT EXISTS api_key_audit (
        id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        key_id TEXT NOT NULL,
        key_name TEXT NOT NULL,
        actor_id TEXT,
        client_ip TEXT,
        status TEXT NOT NULL,
        details_json TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
      )
    `
    ).run();

    const indexes = [
      "CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix)",
      "CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status)",
      "CREATE INDEX IF NOT EXISTS idx_api_keys_created_by ON api_keys(created_by)",
      "CREATE INDEX IF NOT EXISTS idx_api_key_audit_key_id ON api_key_audit(key_id)",
      "CREATE INDEX IF NOT EXISTS idx_api_key_audit_timestamp ON api_key_audit(timestamp)",
    ];

    for (const indexSql of indexes) {
      db.prepare(indexSql).run();
    }

    return { success: true, path: actualPath, created: isNew };
  } catch (error) {
    return {
      success: false,
      path: actualPath,
      created: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export function closeApiKeyDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

export function isApiKeyDbInitialized(): boolean {
  return db !== null;
}

function getDb(): Database.Database {
  if (!db) {
    throw new Error("API key database not initialized. Call initApiKeyDatabase() first.");
  }
  return db;
}

// =============================================================================
// Key Generation
// =============================================================================

function generateApiKey(): { fullKey: string; prefix: string; hash: string } {
  const randomBytes = crypto.randomBytes(KEY_LENGTH);
  const keyPart = randomBytes.toString("base64url");
  const fullKey = KEY_PREFIX + keyPart;
  const prefix = KEY_PREFIX + keyPart.slice(0, 12) + "...";
  const hash = crypto.createHash("sha256").update(fullKey).digest("hex");
  return { fullKey, prefix, hash };
}

function hashApiKey(key: string): string {
  return crypto.createHash("sha256").update(key).digest("hex");
}

// =============================================================================
// Audit Logging
// =============================================================================

function logApiKeyAudit(
  eventType: ApiKeyEventType,
  keyId: string,
  keyName: string,
  status: "SUCCESS" | "FAILURE",
  actorId?: string,
  clientIp?: string,
  details?: Record<string, unknown>
): void {
  const database = getDb();
  const stmt = database.prepare(`
    INSERT INTO api_key_audit (id, event_type, key_id, key_name, actor_id, client_ip, status, details_json, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    crypto.randomUUID(),
    eventType,
    keyId,
    keyName,
    actorId || null,
    clientIp || null,
    status,
    details ? JSON.stringify(details) : null,
    new Date().toISOString()
  );
}

export function getApiKeyAuditEvents(options?: {
  keyId?: string;
  eventType?: ApiKeyEventType;
  status?: "SUCCESS" | "FAILURE";
  limit?: number;
  offset?: number;
}): ApiKeyAuditEvent[] {
  const database = getDb();
  let sql = "SELECT * FROM api_key_audit WHERE 1=1";
  const params: unknown[] = [];

  if (options?.keyId) {
    sql += " AND key_id = ?";
    params.push(options.keyId);
  }
  if (options?.eventType) {
    sql += " AND event_type = ?";
    params.push(options.eventType);
  }
  if (options?.status) {
    sql += " AND status = ?";
    params.push(options.status);
  }

  sql += " ORDER BY timestamp DESC";
  if (options?.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }
  if (options?.offset) {
    sql += " OFFSET ?";
    params.push(options.offset);
  }

  const stmt = database.prepare(sql);
  const rows = stmt.all(...params) as Array<{
    id: string;
    event_type: string;
    key_id: string;
    key_name: string;
    actor_id: string | null;
    client_ip: string | null;
    status: string;
    details_json: string | null;
    timestamp: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    eventType: row.event_type as ApiKeyEventType,
    keyId: row.key_id,
    keyName: row.key_name,
    actorId: row.actor_id || undefined,
    clientIp: row.client_ip || undefined,
    status: row.status as "SUCCESS" | "FAILURE",
    details: row.details_json ? JSON.parse(row.details_json) : undefined,
    timestamp: row.timestamp,
  }));
}

// =============================================================================
// API Key CRUD Operations
// =============================================================================

export function createApiKey(options: ApiKeyCreateOptions): ApiKeyCreateResult {
  const database = getDb();

  for (const scope of options.scopes) {
    if (!VALID_SCOPES.includes(scope)) {
      throw new Error("Invalid scope: " + scope);
    }
  }

  const { fullKey, prefix, hash } = generateApiKey();

  let expiresAt: string | undefined;
  if (options.expiresAt) {
    expiresAt = options.expiresAt;
  } else {
    const days = options.expiresInDays ?? DEFAULT_EXPIRATION_DAYS;
    const expDate = new Date();
    expDate.setDate(expDate.getDate() + days);
    expiresAt = expDate.toISOString();
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  const stmt = database.prepare(`
    INSERT INTO api_keys (
      id, name, description, key_prefix, key_hash, scopes_json, status,
      expires_at, created_by, created_at, ip_allowlist_json, rate_limit
    ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
  `);

  stmt.run(
    id,
    options.name,
    options.description || null,
    prefix,
    hash,
    JSON.stringify(options.scopes),
    expiresAt,
    options.createdBy,
    now,
    options.ipAllowlist ? JSON.stringify(options.ipAllowlist) : null,
    options.rateLimit ?? DEFAULT_RATE_LIMIT
  );

  const key: ApiKey = {
    id,
    name: options.name,
    description: options.description,
    keyPrefix: prefix,
    keyHash: hash,
    scopes: options.scopes,
    status: "active",
    expiresAt,
    createdBy: options.createdBy,
    createdAt: now,
    ipAllowlist: options.ipAllowlist,
    rateLimit: options.rateLimit ?? DEFAULT_RATE_LIMIT,
  };

  logApiKeyAudit("KEY_CREATED", id, options.name, "SUCCESS", options.createdBy, undefined, {
    scopes: options.scopes,
    expiresAt,
  });

  return { key, fullKey };
}

export function getApiKey(id: string): ApiKey | null {
  const database = getDb();
  const stmt = database.prepare("SELECT * FROM api_keys WHERE id = ?");
  const row = stmt.get(id) as
    | {
        id: string;
        name: string;
        description: string | null;
        key_prefix: string;
        key_hash: string;
        scopes_json: string;
        status: string;
        expires_at: string | null;
        last_used_at: string | null;
        created_by: string;
        created_at: string;
        ip_allowlist_json: string | null;
        rate_limit: number;
        request_count: number;
        rate_window_start: string | null;
      }
    | undefined;

  if (!row) return null;
  return rowToApiKey(row);
}

function rowToApiKey(row: {
  id: string;
  name: string;
  description: string | null;
  key_prefix: string;
  key_hash: string;
  scopes_json: string;
  status: string;
  expires_at: string | null;
  last_used_at: string | null;
  created_by: string;
  created_at: string;
  ip_allowlist_json: string | null;
  rate_limit: number;
  request_count: number;
  rate_window_start: string | null;
}): ApiKey {
  return {
    id: row.id,
    name: row.name,
    description: row.description || undefined,
    keyPrefix: row.key_prefix,
    keyHash: row.key_hash,
    scopes: JSON.parse(row.scopes_json),
    status: row.status as ApiKeyStatus,
    expiresAt: row.expires_at || undefined,
    lastUsedAt: row.last_used_at || undefined,
    createdBy: row.created_by,
    createdAt: row.created_at,
    ipAllowlist: row.ip_allowlist_json ? JSON.parse(row.ip_allowlist_json) : undefined,
    rateLimit: row.rate_limit,
    requestCount: row.request_count,
    rateWindowStart: row.rate_window_start || undefined,
  };
}

export function listApiKeys(options?: ApiKeyListOptions): ApiKeyDisplay[] {
  const database = getDb();
  let sql = "SELECT * FROM api_keys WHERE 1=1";
  const params: unknown[] = [];

  if (options?.status) {
    sql += " AND status = ?";
    params.push(options.status);
  }
  if (options?.createdBy) {
    sql += " AND created_by = ?";
    params.push(options.createdBy);
  }
  if (!options?.includeExpired) {
    sql += " AND (expires_at IS NULL OR expires_at > ?)";
    params.push(new Date().toISOString());
  }

  sql += " ORDER BY created_at DESC";
  if (options?.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }
  if (options?.offset) {
    sql += " OFFSET ?";
    params.push(options.offset);
  }

  const stmt = database.prepare(sql);
  const rows = stmt.all(...params) as Array<{
    id: string;
    name: string;
    description: string | null;
    key_prefix: string;
    key_hash: string;
    scopes_json: string;
    status: string;
    expires_at: string | null;
    last_used_at: string | null;
    created_by: string;
    created_at: string;
    ip_allowlist_json: string | null;
    rate_limit: number;
    request_count: number;
    rate_window_start: string | null;
  }>;

  const now = new Date();

  return rows.map((row) => {
    let daysUntilExpiration: number | undefined;
    if (row.expires_at) {
      const expDate = new Date(row.expires_at);
      daysUntilExpiration = Math.ceil((expDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    }
    return {
      id: row.id,
      name: row.name,
      description: row.description || undefined,
      keyPrefix: row.key_prefix,
      scopes: JSON.parse(row.scopes_json),
      status: row.status as ApiKeyStatus,
      expiresAt: row.expires_at || undefined,
      lastUsedAt: row.last_used_at || undefined,
      createdBy: row.created_by,
      createdAt: row.created_at,
      daysUntilExpiration,
    };
  });
}

export function revokeApiKey(id: string, actorId?: string): boolean {
  const database = getDb();
  const key = getApiKey(id);
  if (!key) return false;
  if (key.status === "revoked") return false;

  const stmt = database.prepare("UPDATE api_keys SET status = 'revoked' WHERE id = ?");
  const result = stmt.run(id);

  if (result.changes > 0) {
    logApiKeyAudit("KEY_REVOKED", id, key.name, "SUCCESS", actorId);
    return true;
  }
  return false;
}

export function rotateApiKey(id: string, actorId?: string): ApiKeyRotateResult | null {
  const database = getDb();
  const existingKey = getApiKey(id);
  if (!existingKey) return null;

  if (existingKey.status !== "active") {
    throw new Error("Cannot rotate a revoked or expired key");
  }

  const previousPrefix = existingKey.keyPrefix;
  const { fullKey: newFullKey, prefix: newPrefix, hash: newHash } = generateApiKey();

  const stmt = database.prepare("UPDATE api_keys SET key_prefix = ?, key_hash = ? WHERE id = ?");
  stmt.run(newPrefix, newHash, id);

  logApiKeyAudit("KEY_ROTATED", id, existingKey.name, "SUCCESS", actorId, undefined, {
    previousPrefix,
    newPrefix,
  });

  const updatedKey = getApiKey(id)!;
  return { key: updatedKey, newFullKey, previousKeyPrefix: previousPrefix };
}

// =============================================================================
// Key Validation
// =============================================================================

export function validateApiKey(
  fullKey: string,
  requiredScope?: ApiKeyScope,
  clientIp?: string
): ApiKeyValidationResult {
  const database = getDb();
  const keyHash = hashApiKey(fullKey);

  const stmt = database.prepare("SELECT * FROM api_keys WHERE key_hash = ?");
  const row = stmt.get(keyHash) as
    | {
        id: string;
        name: string;
        description: string | null;
        key_prefix: string;
        key_hash: string;
        scopes_json: string;
        status: string;
        expires_at: string | null;
        last_used_at: string | null;
        created_by: string;
        created_at: string;
        ip_allowlist_json: string | null;
        rate_limit: number;
        request_count: number;
        rate_window_start: string | null;
      }
    | undefined;

  if (!row) {
    logApiKeyAudit("KEY_USED", "unknown", "unknown", "FAILURE", undefined, clientIp, {
      reason: "Key not found",
    });
    return { valid: false, reason: "Invalid API key" };
  }

  const key = rowToApiKey(row);

  if (key.status === "revoked") {
    logApiKeyAudit("KEY_USED", key.id, key.name, "FAILURE", undefined, clientIp, {
      reason: "Key revoked",
    });
    return { valid: false, key, reason: "API key has been revoked" };
  }

  if (key.expiresAt && new Date(key.expiresAt) < new Date()) {
    const updateStmt = database.prepare("UPDATE api_keys SET status = 'expired' WHERE id = ?");
    updateStmt.run(key.id);
    key.status = "expired";
    logApiKeyAudit("KEY_EXPIRED", key.id, key.name, "FAILURE", undefined, clientIp);
    return { valid: false, key, reason: "API key has expired" };
  }

  if (key.ipAllowlist && key.ipAllowlist.length > 0 && clientIp) {
    if (!key.ipAllowlist.includes(clientIp)) {
      logApiKeyAudit("KEY_USED", key.id, key.name, "FAILURE", undefined, clientIp, {
        reason: "IP not in allowlist",
      });
      return { valid: false, key, reason: "IP address not allowed" };
    }
  }

  const rateLimitResult = checkRateLimit(key);
  if (!rateLimitResult.allowed) {
    logApiKeyAudit("KEY_RATE_LIMITED", key.id, key.name, "FAILURE", undefined, clientIp, {
      rateLimit: key.rateLimit,
      currentCount: rateLimitResult.currentCount,
    });
    return { valid: false, key, reason: "Rate limit exceeded", rateLimited: true };
  }

  if (requiredScope) {
    const hasScope = checkScope(key.scopes, requiredScope);
    if (!hasScope) {
      logApiKeyAudit("KEY_USED", key.id, key.name, "FAILURE", undefined, clientIp, {
        reason: "Insufficient scope",
        requiredScope,
        keyScopes: key.scopes,
      });
      return { valid: false, key, reason: "Missing required scope: " + requiredScope };
    }
  }

  updateKeyUsage(key.id);
  logApiKeyAudit("KEY_USED", key.id, key.name, "SUCCESS", undefined, clientIp, {
    scope: requiredScope,
  });

  return { valid: true, key };
}

function checkScope(keyScopes: ApiKeyScope[], requiredScope: ApiKeyScope): boolean {
  if (keyScopes.includes("admin:*")) return true;
  if (keyScopes.includes(requiredScope)) return true;

  const [resource] = requiredScope.split(":");
  const wildcardScope = (resource + ":*") as ApiKeyScope;
  if (keyScopes.includes(wildcardScope)) return true;

  return false;
}

function checkRateLimit(key: ApiKey): { allowed: boolean; currentCount: number } {
  const now = new Date();
  const windowStart = key.rateWindowStart ? new Date(key.rateWindowStart) : null;

  if (!windowStart || now.getTime() - windowStart.getTime() > RATE_WINDOW_MS) {
    return { allowed: true, currentCount: 0 };
  }

  const currentCount = key.requestCount || 0;
  if (currentCount >= key.rateLimit) {
    return { allowed: false, currentCount };
  }

  return { allowed: true, currentCount };
}

function updateKeyUsage(keyId: string): void {
  const database = getDb();
  const now = new Date();
  const nowIso = now.toISOString();

  const key = getApiKey(keyId);
  if (!key) return;

  const windowStart = key.rateWindowStart ? new Date(key.rateWindowStart) : null;

  if (!windowStart || now.getTime() - windowStart.getTime() > RATE_WINDOW_MS) {
    const stmt = database.prepare(`
      UPDATE api_keys
      SET last_used_at = ?, request_count = 1, rate_window_start = ?
      WHERE id = ?
    `);
    stmt.run(nowIso, nowIso, keyId);
  } else {
    const stmt = database.prepare(`
      UPDATE api_keys
      SET last_used_at = ?, request_count = request_count + 1
      WHERE id = ?
    `);
    stmt.run(nowIso, keyId);
  }
}

// =============================================================================
// Maintenance
// =============================================================================

export function markExpiredApiKeys(): number {
  const database = getDb();
  const stmt = database.prepare(`
    UPDATE api_keys
    SET status = 'expired'
    WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at < ?
  `);
  const result = stmt.run(new Date().toISOString());
  return result.changes;
}

export function getApiKeyStats(): {
  total: number;
  active: number;
  revoked: number;
  expired: number;
  expiringIn7Days: number;
} {
  const database = getDb();

  const totalStmt = database.prepare("SELECT COUNT(*) as count FROM api_keys");
  const total = (totalStmt.get() as { count: number }).count;

  const activeStmt = database.prepare(
    "SELECT COUNT(*) as count FROM api_keys WHERE status = 'active'"
  );
  const active = (activeStmt.get() as { count: number }).count;

  const revokedStmt = database.prepare(
    "SELECT COUNT(*) as count FROM api_keys WHERE status = 'revoked'"
  );
  const revoked = (revokedStmt.get() as { count: number }).count;

  const expiredStmt = database.prepare(
    "SELECT COUNT(*) as count FROM api_keys WHERE status = 'expired'"
  );
  const expired = (expiredStmt.get() as { count: number }).count;

  const sevenDaysFromNow = new Date();
  sevenDaysFromNow.setDate(sevenDaysFromNow.getDate() + 7);

  const expiringStmt = database.prepare(`
    SELECT COUNT(*) as count FROM api_keys
    WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?
  `);
  const expiringIn7Days = (expiringStmt.get(sevenDaysFromNow.toISOString()) as { count: number })
    .count;

  return { total, active, revoked, expired, expiringIn7Days };
}

export function cleanupApiKeyAuditLogs(olderThanDays: number = 90): number {
  const database = getDb();
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - olderThanDays);

  const stmt = database.prepare("DELETE FROM api_key_audit WHERE timestamp < ?");
  const result = stmt.run(cutoff.toISOString());
  return result.changes;
}
