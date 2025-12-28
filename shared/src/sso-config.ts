/**
 * SSO Configuration Module
 *
 * Provides SQLite database storage for SSO provider configurations,
 * sessions, and audit logging.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import Database from "better-sqlite3";
import type {
  SsoProviderType,
  SamlProviderConfig,
  OidcProviderConfig,
  SsoSession,
  SsoAuditEvent,
  SsoEventType,
  SsoDbInitResult,
  SsoProviderSummary,
} from "./types.js";

// =============================================================================
// Database Instance
// =============================================================================

let db: Database.Database | null = null;

/**
 * Get the default SSO database path
 */
function getDefaultDbPath(): string {
  const ssoDir = process.env.SSO_DB_PATH
    ? path.dirname(process.env.SSO_DB_PATH)
    : path.join(os.homedir(), ".cicd", "sso");
  return process.env.SSO_DB_PATH || path.join(ssoDir, "sso.db");
}

/**
 * Create SSO database schema
 */
function createSchema(database: Database.Database): void {
  database.exec(`
    -- SSO Provider configurations
    CREATE TABLE IF NOT EXISTS sso_providers (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL CHECK(type IN ('saml', 'oidc')),
      name TEXT NOT NULL,
      enabled INTEGER DEFAULT 1,
      config_json TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Active sessions
    CREATE TABLE IF NOT EXISTS sso_sessions (
      id TEXT PRIMARY KEY,
      provider_id TEXT NOT NULL,
      provider_type TEXT NOT NULL,
      user_id TEXT NOT NULL,
      email TEXT,
      name TEXT,
      groups_json TEXT,
      claims_json TEXT,
      access_token TEXT,
      refresh_token TEXT,
      expires_at TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      last_activity_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (provider_id) REFERENCES sso_providers(id) ON DELETE CASCADE
    );

    -- Audit log for SSO events
    CREATE TABLE IF NOT EXISTS sso_audit (
      id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      provider_id TEXT,
      session_id TEXT,
      user_id TEXT,
      email TEXT,
      status TEXT NOT NULL,
      error_message TEXT,
      ip_address TEXT,
      user_agent TEXT,
      details_json TEXT,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Indexes for performance
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sso_sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_provider ON sso_sessions(provider_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sso_sessions(expires_at);
    CREATE INDEX IF NOT EXISTS idx_audit_user ON sso_audit(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON sso_audit(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_event_type ON sso_audit(event_type);
  `);
}

// =============================================================================
// Database Lifecycle
// =============================================================================

/**
 * Initialize the SSO database
 */
export function initSsoDatabase(customPath?: string): SsoDbInitResult {
  if (db) {
    return {
      success: true,
      path: getDefaultDbPath(),
      created: false,
    };
  }

  const dbPath = customPath || getDefaultDbPath();
  const dbDir = path.dirname(dbPath);

  try {
    // Create directory if it doesn't exist
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }

    const isNew = !fs.existsSync(dbPath);
    db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    createSchema(db);

    return {
      success: true,
      path: dbPath,
      created: isNew,
    };
  } catch (error) {
    return {
      success: false,
      path: dbPath,
      created: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Close the SSO database
 */
export function closeSsoDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

/**
 * Check if SSO database is initialized
 */
export function isSsoDbInitialized(): boolean {
  return db !== null;
}

/**
 * Get the database instance (for internal use)
 */
function getDb(): Database.Database {
  if (!db) {
    throw new Error("SSO database not initialized. Call initSsoDatabase() first.");
  }
  return db;
}

// =============================================================================
// Provider Configuration
// =============================================================================

/**
 * Configure a SAML provider
 */
export function configureSamlProvider(
  config: Omit<SamlProviderConfig, "id" | "createdAt" | "updatedAt"> & { id?: string }
): SamlProviderConfig {
  const database = getDb();
  const now = new Date().toISOString();
  const id = config.id || crypto.randomUUID();

  const fullConfig: SamlProviderConfig = {
    ...config,
    id,
    createdAt: now,
    updatedAt: now,
  };

  const stmt = database.prepare(`
    INSERT INTO sso_providers (id, type, name, enabled, config_json, created_at, updated_at)
    VALUES (?, 'saml', ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name,
      enabled = excluded.enabled,
      config_json = excluded.config_json,
      updated_at = excluded.updated_at
  `);

  stmt.run(id, config.name, config.enabled ? 1 : 0, JSON.stringify(fullConfig), now, now);

  // Log configuration change
  logSsoAudit({
    eventType: "CONFIG_CHANGE",
    providerId: id,
    status: "SUCCESS",
    details: { action: "configure_saml", providerName: config.name },
  });

  return fullConfig;
}

/**
 * Configure an OIDC provider
 */
export function configureOidcProvider(
  config: Omit<OidcProviderConfig, "id" | "createdAt" | "updatedAt"> & { id?: string }
): OidcProviderConfig {
  const database = getDb();
  const now = new Date().toISOString();
  const id = config.id || crypto.randomUUID();

  const fullConfig: OidcProviderConfig = {
    ...config,
    id,
    createdAt: now,
    updatedAt: now,
  };

  const stmt = database.prepare(`
    INSERT INTO sso_providers (id, type, name, enabled, config_json, created_at, updated_at)
    VALUES (?, 'oidc', ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name,
      enabled = excluded.enabled,
      config_json = excluded.config_json,
      updated_at = excluded.updated_at
  `);

  stmt.run(id, config.name, config.enabled ? 1 : 0, JSON.stringify(fullConfig), now, now);

  // Log configuration change
  logSsoAudit({
    eventType: "CONFIG_CHANGE",
    providerId: id,
    status: "SUCCESS",
    details: { action: "configure_oidc", providerName: config.name },
  });

  return fullConfig;
}

/**
 * Get a provider by ID
 */
export function getSsoProvider(
  id: string
): { type: SsoProviderType; config: SamlProviderConfig | OidcProviderConfig } | null {
  const database = getDb();
  const stmt = database.prepare("SELECT type, config_json FROM sso_providers WHERE id = ?");
  const row = stmt.get(id) as { type: SsoProviderType; config_json: string } | undefined;

  if (!row) {
    return null;
  }

  return {
    type: row.type,
    config: JSON.parse(row.config_json),
  };
}

/**
 * Get a SAML provider by ID
 */
export function getSamlProvider(id: string): SamlProviderConfig | null {
  const result = getSsoProvider(id);
  if (!result || result.type !== "saml") {
    return null;
  }
  return result.config as SamlProviderConfig;
}

/**
 * Get an OIDC provider by ID
 */
export function getOidcProvider(id: string): OidcProviderConfig | null {
  const result = getSsoProvider(id);
  if (!result || result.type !== "oidc") {
    return null;
  }
  return result.config as OidcProviderConfig;
}

/**
 * List all SSO providers
 */
export function listSsoProviders(): SsoProviderSummary[] {
  const database = getDb();
  const stmt = database.prepare(`
    SELECT id, type, name, enabled, config_json, created_at
    FROM sso_providers
    ORDER BY name
  `);

  const rows = stmt.all() as Array<{
    id: string;
    type: SsoProviderType;
    name: string;
    enabled: number;
    config_json: string;
    created_at: string;
  }>;

  return rows.map((row) => {
    const config = JSON.parse(row.config_json);
    return {
      id: row.id,
      type: row.type,
      name: row.name,
      enabled: row.enabled === 1,
      issuer: row.type === "oidc" ? config.issuer : config.spEntityId,
      createdAt: row.created_at,
    };
  });
}

/**
 * Delete a provider
 */
export function deleteSsoProvider(id: string): boolean {
  const database = getDb();
  const stmt = database.prepare("DELETE FROM sso_providers WHERE id = ?");
  const result = stmt.run(id);

  if (result.changes > 0) {
    logSsoAudit({
      eventType: "CONFIG_CHANGE",
      providerId: id,
      status: "SUCCESS",
      details: { action: "delete_provider" },
    });
    return true;
  }

  return false;
}

/**
 * Enable or disable a provider
 */
export function setSsoProviderEnabled(id: string, enabled: boolean): boolean {
  const database = getDb();
  const now = new Date().toISOString();

  // Get current config to update the enabled field in config_json
  const current = getSsoProvider(id);
  if (!current) {
    return false;
  }

  // Update the enabled field in the config
  const updatedConfig = { ...current.config, enabled, updatedAt: now };

  const stmt = database.prepare(`
    UPDATE sso_providers
    SET enabled = ?, config_json = ?, updated_at = ?
    WHERE id = ?
  `);

  const result = stmt.run(enabled ? 1 : 0, JSON.stringify(updatedConfig), now, id);

  if (result.changes > 0) {
    logSsoAudit({
      eventType: "CONFIG_CHANGE",
      providerId: id,
      status: "SUCCESS",
      details: { action: enabled ? "enable_provider" : "disable_provider" },
    });
    return true;
  }

  return false;
}

/**
 * Find provider by issuer (for OIDC token validation)
 */
export function getSsoProviderByIssuer(issuer: string): OidcProviderConfig | null {
  const database = getDb();
  const stmt = database.prepare(`
    SELECT config_json FROM sso_providers
    WHERE type = 'oidc' AND enabled = 1
  `);

  const rows = stmt.all() as Array<{ config_json: string }>;

  for (const row of rows) {
    const config = JSON.parse(row.config_json) as OidcProviderConfig;
    if (config.issuer === issuer) {
      return config;
    }
  }

  return null;
}

// =============================================================================
// Session Management
// =============================================================================

/**
 * Create a new session
 */
export function createSsoSession(
  session: Omit<SsoSession, "id" | "createdAt" | "lastActivityAt">
): SsoSession {
  const database = getDb();
  const now = new Date().toISOString();
  const id = crypto.randomUUID();

  const fullSession: SsoSession = {
    ...session,
    id,
    createdAt: now,
    lastActivityAt: now,
  };

  const stmt = database.prepare(`
    INSERT INTO sso_sessions (
      id, provider_id, provider_type, user_id, email, name,
      groups_json, claims_json, access_token, refresh_token,
      expires_at, created_at, last_activity_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    id,
    session.providerId,
    session.providerType,
    session.userId,
    session.email,
    session.name,
    JSON.stringify(session.groups),
    JSON.stringify(session.claims),
    session.accessToken || null,
    session.refreshToken || null,
    session.expiresAt,
    now,
    now
  );

  logSsoAudit({
    eventType: "LOGIN",
    providerId: session.providerId,
    sessionId: id,
    userId: session.userId,
    email: session.email,
    status: "SUCCESS",
  });

  return fullSession;
}

/**
 * Get a session by ID
 */
export function getSsoSession(sessionId: string): SsoSession | null {
  const database = getDb();
  const stmt = database.prepare("SELECT * FROM sso_sessions WHERE id = ?");
  const row = stmt.get(sessionId) as Record<string, unknown> | undefined;

  if (!row) {
    return null;
  }

  return rowToSession(row);
}

/**
 * Validate a session (check if exists and not expired)
 */
export function validateSsoSession(sessionId: string): {
  valid: boolean;
  session?: SsoSession;
  error?: string;
} {
  const session = getSsoSession(sessionId);

  if (!session) {
    return { valid: false, error: "Session not found" };
  }

  const now = new Date();
  const expiresAt = new Date(session.expiresAt);

  if (now > expiresAt) {
    // Log expiration
    logSsoAudit({
      eventType: "SESSION_EXPIRED",
      sessionId,
      userId: session.userId,
      email: session.email,
      status: "FAILURE",
      errorMessage: "Session expired",
    });

    // Delete expired session
    terminateSsoSession(sessionId);

    return { valid: false, error: "Session expired" };
  }

  // Update last activity
  updateSessionActivity(sessionId);

  return { valid: true, session };
}

/**
 * Update session last activity time
 */
function updateSessionActivity(sessionId: string): void {
  const database = getDb();
  const now = new Date().toISOString();
  const stmt = database.prepare("UPDATE sso_sessions SET last_activity_at = ? WHERE id = ?");
  stmt.run(now, sessionId);
}

/**
 * Terminate a session
 */
export function terminateSsoSession(sessionId: string): boolean {
  const database = getDb();

  // Get session for audit log
  const session = getSsoSession(sessionId);

  const stmt = database.prepare("DELETE FROM sso_sessions WHERE id = ?");
  const result = stmt.run(sessionId);

  if (result.changes > 0 && session) {
    logSsoAudit({
      eventType: "LOGOUT",
      providerId: session.providerId,
      sessionId,
      userId: session.userId,
      email: session.email,
      status: "SUCCESS",
    });
    return true;
  }

  return false;
}

/**
 * Terminate all sessions for a user
 */
export function terminateAllUserSessions(userId: string): number {
  const database = getDb();

  // Get sessions for audit log
  const sessions = listUserSessions(userId);

  const stmt = database.prepare("DELETE FROM sso_sessions WHERE user_id = ?");
  const result = stmt.run(userId);

  if (result.changes > 0) {
    for (const session of sessions) {
      logSsoAudit({
        eventType: "LOGOUT",
        providerId: session.providerId,
        sessionId: session.id,
        userId: session.userId,
        email: session.email,
        status: "SUCCESS",
        details: { reason: "terminate_all_sessions" },
      });
    }
  }

  return result.changes;
}

/**
 * List active sessions for a user
 */
export function listUserSessions(userId: string): SsoSession[] {
  const database = getDb();
  const now = new Date().toISOString();
  const stmt = database.prepare(`
    SELECT * FROM sso_sessions
    WHERE user_id = ? AND expires_at > ?
    ORDER BY created_at DESC
  `);

  const rows = stmt.all(userId, now) as Array<Record<string, unknown>>;
  return rows.map(rowToSession);
}

/**
 * List all active sessions
 */
export function listAllSessions(): SsoSession[] {
  const database = getDb();
  const now = new Date().toISOString();
  const stmt = database.prepare(`
    SELECT * FROM sso_sessions
    WHERE expires_at > ?
    ORDER BY created_at DESC
  `);

  const rows = stmt.all(now) as Array<Record<string, unknown>>;
  return rows.map(rowToSession);
}

/**
 * Cleanup expired sessions
 */
export function cleanupExpiredSessions(): number {
  const database = getDb();
  const now = new Date().toISOString();
  const stmt = database.prepare("DELETE FROM sso_sessions WHERE expires_at <= ?");
  const result = stmt.run(now);
  return result.changes;
}

/**
 * Update session tokens (for OIDC token refresh)
 */
export function updateSessionTokens(
  sessionId: string,
  accessToken: string,
  refreshToken?: string,
  expiresAt?: string
): boolean {
  const database = getDb();
  const now = new Date().toISOString();

  let sql = "UPDATE sso_sessions SET access_token = ?, last_activity_at = ?";
  const params: (string | null)[] = [accessToken, now];

  if (refreshToken !== undefined) {
    sql += ", refresh_token = ?";
    params.push(refreshToken);
  }

  if (expiresAt !== undefined) {
    sql += ", expires_at = ?";
    params.push(expiresAt);
  }

  sql += " WHERE id = ?";
  params.push(sessionId);

  const stmt = database.prepare(sql);
  const result = stmt.run(...params);

  if (result.changes > 0) {
    const session = getSsoSession(sessionId);
    if (session) {
      logSsoAudit({
        eventType: "TOKEN_REFRESH",
        sessionId,
        userId: session.userId,
        email: session.email,
        status: "SUCCESS",
      });
    }
    return true;
  }

  return false;
}

/**
 * Convert database row to SsoSession
 */
function rowToSession(row: Record<string, unknown>): SsoSession {
  return {
    id: row.id as string,
    providerId: row.provider_id as string,
    providerType: row.provider_type as SsoProviderType,
    userId: row.user_id as string,
    email: row.email as string,
    name: row.name as string,
    groups: JSON.parse((row.groups_json as string) || "[]"),
    claims: JSON.parse((row.claims_json as string) || "{}"),
    accessToken: row.access_token as string | undefined,
    refreshToken: row.refresh_token as string | undefined,
    expiresAt: row.expires_at as string,
    createdAt: row.created_at as string,
    lastActivityAt: row.last_activity_at as string,
  };
}

// =============================================================================
// Audit Logging
// =============================================================================

/**
 * Log an SSO audit event
 */
export function logSsoAudit(event: Omit<SsoAuditEvent, "id" | "timestamp">): void {
  const database = getDb();
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  const stmt = database.prepare(`
    INSERT INTO sso_audit (
      id, event_type, provider_id, session_id, user_id, email,
      status, error_message, ip_address, user_agent, details_json, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    id,
    event.eventType,
    event.providerId || null,
    event.sessionId || null,
    event.userId || null,
    event.email || null,
    event.status,
    event.errorMessage || null,
    event.ipAddress || null,
    event.userAgent || null,
    event.details ? JSON.stringify(event.details) : null,
    now
  );
}

/**
 * Get SSO audit events
 */
export function getSsoAuditEvents(options?: {
  userId?: string;
  providerId?: string;
  eventType?: SsoEventType;
  status?: "SUCCESS" | "FAILURE";
  limit?: number;
  offset?: number;
}): SsoAuditEvent[] {
  const database = getDb();
  let sql = "SELECT * FROM sso_audit WHERE 1=1";
  const params: (string | number)[] = [];

  if (options?.userId) {
    sql += " AND user_id = ?";
    params.push(options.userId);
  }

  if (options?.providerId) {
    sql += " AND provider_id = ?";
    params.push(options.providerId);
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

  // SQLite requires LIMIT when using OFFSET
  if (options?.limit || options?.offset) {
    sql += " LIMIT ?";
    params.push(options?.limit ?? -1); // -1 means no limit in SQLite
  }

  if (options?.offset) {
    sql += " OFFSET ?";
    params.push(options.offset);
  }

  const stmt = database.prepare(sql);
  const rows = stmt.all(...params) as Array<Record<string, unknown>>;

  return rows.map((row) => ({
    id: row.id as string,
    eventType: row.event_type as SsoEventType,
    providerId: row.provider_id as string | undefined,
    sessionId: row.session_id as string | undefined,
    userId: row.user_id as string | undefined,
    email: row.email as string | undefined,
    status: row.status as "SUCCESS" | "FAILURE",
    errorMessage: row.error_message as string | undefined,
    ipAddress: row.ip_address as string | undefined,
    userAgent: row.user_agent as string | undefined,
    details: row.details_json ? JSON.parse(row.details_json as string) : undefined,
    timestamp: row.timestamp as string,
  }));
}

/**
 * Cleanup old audit events
 */
export function cleanupOldAuditEvents(olderThanDays: number = 90): number {
  const database = getDb();
  const stmt = database.prepare(`
    DELETE FROM sso_audit
    WHERE timestamp < datetime('now', '-' || ? || ' days')
  `);
  const result = stmt.run(olderThanDays);
  return result.changes;
}
