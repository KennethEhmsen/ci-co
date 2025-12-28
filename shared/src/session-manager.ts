/**
 * Session Management Module
 *
 * Provides JWT-based session management with:
 * - Access tokens (short-lived, default 15 min)
 * - Refresh tokens (long-lived, default 7 days)
 * - Token rotation on refresh
 * - Token blacklisting for immediate revocation
 * - Concurrent session limits
 * - Session auditing
 */

import Database from "better-sqlite3";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import jwt from "jsonwebtoken";
import type {
  Session,
  SessionDevice,
  TokenClaims,
  TokenPair,
  CreateSessionOptions,
  CreateSessionResult,
  TokenValidationResult,
  RefreshTokenResult,
  SessionListOptions,
  SessionAuditEvent,
  SessionDbInitResult,
  SessionStats,
  BlacklistedToken,
  SessionConfig,
  SessionEventType,
} from "./types.js";

// =============================================================================
// Configuration
// =============================================================================

const DEFAULT_CONFIG: SessionConfig = {
  jwtSecret:
    process.env.JWT_SECRET || "change-me-in-production-" + crypto.randomBytes(16).toString("hex"),
  accessExpirySeconds: parseInt(process.env.JWT_ACCESS_EXPIRY || "900", 10),
  refreshExpirySeconds: parseInt(process.env.JWT_REFRESH_EXPIRY || "604800", 10),
  maxConcurrentSessions: parseInt(process.env.SESSION_LIMIT || "5", 10),
  rotateRefreshTokens: process.env.ROTATE_REFRESH_TOKENS !== "false",
};

let config: SessionConfig = { ...DEFAULT_CONFIG };
let db: Database.Database | null = null;

// =============================================================================
// Database Schema
// =============================================================================

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    refresh_token_hash TEXT NOT NULL,
    access_token_jti TEXT NOT NULL,
    device_json TEXT,
    ip_address TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_activity TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    is_active INTEGER DEFAULT 1
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

  CREATE TABLE IF NOT EXISTS token_blacklist (
    jti TEXT PRIMARY KEY,
    reason TEXT,
    blacklisted_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_blacklist_expires_at ON token_blacklist(expires_at);

  CREATE TABLE IF NOT EXISTS session_audit (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    session_id TEXT,
    user_id TEXT,
    ip_address TEXT,
    status TEXT NOT NULL,
    details_json TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_session_audit_user_id ON session_audit(user_id);
  CREATE INDEX IF NOT EXISTS idx_session_audit_session_id ON session_audit(session_id);
  CREATE INDEX IF NOT EXISTS idx_session_audit_timestamp ON session_audit(timestamp);
`;

// =============================================================================
// Database Lifecycle
// =============================================================================

function getDefaultDbPath(): string {
  return path.join(os.homedir(), ".cicd-security", "sessions.db");
}

function getDb(): Database.Database {
  if (!db) {
    throw new Error("Session database not initialized. Call initSessionDatabase() first.");
  }
  return db;
}

export function initSessionDatabase(
  customPath?: string,
  customConfig?: Partial<SessionConfig>
): SessionDbInitResult {
  const dbPath = customPath || getDefaultDbPath();
  if (customConfig) {
    config = { ...DEFAULT_CONFIG, ...customConfig };
  }
  try {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const isNew = !fs.existsSync(dbPath);
    db = new Database(dbPath);
    db.exec(SCHEMA);
    return { success: true, path: dbPath, created: isNew };
  } catch (error) {
    return {
      success: false,
      path: dbPath,
      created: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export function closeSessionDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

export function isSessionDbInitialized(): boolean {
  return db !== null;
}

export function getSessionConfig(): SessionConfig {
  return { ...config };
}

export function updateSessionConfig(updates: Partial<SessionConfig>): SessionConfig {
  config = { ...config, ...updates };
  return { ...config };
}

// =============================================================================
// Helper Functions
// =============================================================================

function generateId(): string {
  return crypto.randomUUID();
}

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function rowToSession(row: Record<string, unknown>): Session {
  return {
    id: row.id as string,
    userId: row.user_id as string,
    refreshTokenHash: row.refresh_token_hash as string,
    accessTokenJti: row.access_token_jti as string,
    device: row.device_json ? JSON.parse(row.device_json as string) : undefined,
    ipAddress: row.ip_address as string | undefined,
    createdAt: row.created_at as string,
    lastActivity: row.last_activity as string,
    expiresAt: row.expires_at as string,
    isActive: (row.is_active as number) === 1,
  };
}

function rowToAuditEvent(row: Record<string, unknown>): SessionAuditEvent {
  return {
    id: row.id as string,
    eventType: row.event_type as SessionEventType,
    sessionId: row.session_id as string | undefined,
    userId: row.user_id as string | undefined,
    ipAddress: row.ip_address as string | undefined,
    status: row.status as "SUCCESS" | "FAILURE",
    details: row.details_json ? JSON.parse(row.details_json as string) : undefined,
    timestamp: row.timestamp as string,
  };
}

// =============================================================================
// Token Generation
// =============================================================================

function generateTokenPair(
  sessionId: string,
  userId: string,
  options: {
    email?: string;
    roles?: string[];
    teams?: string[];
    permissions?: string[];
    accessExpirySeconds?: number;
    refreshExpirySeconds?: number;
  }
): { tokens: TokenPair; accessJti: string; refreshToken: string } {
  const now = Math.floor(Date.now() / 1000);
  const accessJti = generateId();
  const refreshJti = generateId();
  const accessExpiry = options.accessExpirySeconds || config.accessExpirySeconds;
  const refreshExpiry = options.refreshExpirySeconds || config.refreshExpirySeconds;

  const accessClaims: TokenClaims = {
    sub: userId,
    email: options.email,
    roles: options.roles,
    teams: options.teams,
    permissions: options.permissions,
    sid: sessionId,
    jti: accessJti,
    iat: now,
    exp: now + accessExpiry,
    type: "access",
  };

  const refreshClaims: TokenClaims = {
    sub: userId,
    sid: sessionId,
    jti: refreshJti,
    iat: now,
    exp: now + refreshExpiry,
    type: "refresh",
  };

  const accessToken = jwt.sign(accessClaims, config.jwtSecret);
  const refreshToken = jwt.sign(refreshClaims, config.jwtSecret);

  return {
    tokens: {
      accessToken,
      refreshToken,
      accessExpiresAt: new Date((now + accessExpiry) * 1000).toISOString(),
      refreshExpiresAt: new Date((now + refreshExpiry) * 1000).toISOString(),
      tokenType: "Bearer",
    },
    accessJti,
    refreshToken,
  };
}

// =============================================================================
// Audit Logging
// =============================================================================

export function logSessionAudit(event: {
  eventType: SessionEventType;
  sessionId?: string;
  userId?: string;
  ipAddress?: string;
  status: "SUCCESS" | "FAILURE";
  details?: Record<string, unknown>;
}): void {
  const database = getDb();
  const id = generateId();
  const timestamp = new Date().toISOString();
  database
    .prepare(
      `INSERT INTO session_audit (id, event_type, session_id, user_id, ip_address, status, details_json, timestamp)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      id,
      event.eventType,
      event.sessionId || null,
      event.userId || null,
      event.ipAddress || null,
      event.status,
      event.details ? JSON.stringify(event.details) : null,
      timestamp
    );
}

export function getSessionAuditEvents(options?: {
  userId?: string;
  sessionId?: string;
  eventType?: SessionEventType;
  limit?: number;
  offset?: number;
}): SessionAuditEvent[] {
  const database = getDb();
  let sql = "SELECT * FROM session_audit";
  const params: (string | number)[] = [];
  const conditions: string[] = [];
  if (options?.userId) {
    conditions.push("user_id = ?");
    params.push(options.userId);
  }
  if (options?.sessionId) {
    conditions.push("session_id = ?");
    params.push(options.sessionId);
  }
  if (options?.eventType) {
    conditions.push("event_type = ?");
    params.push(options.eventType);
  }
  if (conditions.length > 0) sql += " WHERE " + conditions.join(" AND ");
  sql += " ORDER BY timestamp DESC";
  if (options?.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }
  if (options?.offset) {
    sql += " OFFSET ?";
    params.push(options.offset);
  }
  const rows = database.prepare(sql).all(...params) as Array<Record<string, unknown>>;
  return rows.map(rowToAuditEvent);
}

// =============================================================================
// Session Management
// =============================================================================

export function createSession(options: CreateSessionOptions): CreateSessionResult {
  const database = getDb();
  const sessionId = generateId();
  const now = new Date().toISOString();

  // Check concurrent session limit
  const activeSessionCount = (
    database
      .prepare("SELECT COUNT(*) as count FROM sessions WHERE user_id = ? AND is_active = 1")
      .get(options.userId) as { count: number }
  ).count;

  if (activeSessionCount >= config.maxConcurrentSessions) {
    // Revoke oldest session
    const oldestSession = database
      .prepare(
        "SELECT id FROM sessions WHERE user_id = ? AND is_active = 1 ORDER BY created_at ASC LIMIT 1"
      )
      .get(options.userId) as { id: string } | undefined;
    if (oldestSession) {
      revokeSession(oldestSession.id, "Concurrent session limit exceeded");
      logSessionAudit({
        eventType: "CONCURRENT_LIMIT_EXCEEDED",
        sessionId: oldestSession.id,
        userId: options.userId,
        ipAddress: options.ipAddress,
        status: "SUCCESS",
        details: { revokedSessionId: oldestSession.id, limit: config.maxConcurrentSessions },
      });
    }
  }

  const { tokens, accessJti, refreshToken } = generateTokenPair(sessionId, options.userId, {
    email: options.email,
    roles: options.roles,
    teams: options.teams,
    permissions: options.permissions,
    accessExpirySeconds: options.accessExpirySeconds,
    refreshExpirySeconds: options.refreshExpirySeconds,
  });

  const refreshTokenHash = hashToken(refreshToken);
  const expiresAt = tokens.refreshExpiresAt;

  database
    .prepare(
      `INSERT INTO sessions (id, user_id, refresh_token_hash, access_token_jti, device_json, ip_address, created_at, last_activity, expires_at, is_active)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`
    )
    .run(
      sessionId,
      options.userId,
      refreshTokenHash,
      accessJti,
      options.device ? JSON.stringify(options.device) : null,
      options.ipAddress || null,
      now,
      now,
      expiresAt
    );

  const session: Session = {
    id: sessionId,
    userId: options.userId,
    refreshTokenHash,
    accessTokenJti: accessJti,
    device: options.device,
    ipAddress: options.ipAddress,
    createdAt: now,
    lastActivity: now,
    expiresAt,
    isActive: true,
  };

  logSessionAudit({
    eventType: "SESSION_CREATED",
    sessionId,
    userId: options.userId,
    ipAddress: options.ipAddress,
    status: "SUCCESS",
  });
  return { session, tokens };
}

export function getSession(sessionId: string): Session | null {
  const database = getDb();
  const row = database.prepare("SELECT * FROM sessions WHERE id = ?").get(sessionId) as
    | Record<string, unknown>
    | undefined;
  return row ? rowToSession(row) : null;
}

export function listSessions(options?: SessionListOptions): Session[] {
  const database = getDb();
  let sql = "SELECT * FROM sessions";
  const params: (string | number)[] = [];
  const conditions: string[] = [];
  if (options?.userId) {
    conditions.push("user_id = ?");
    params.push(options.userId);
  }
  if (options?.activeOnly) {
    conditions.push("is_active = 1");
  }
  if (!options?.includeExpired) {
    conditions.push("expires_at > datetime('now')");
  }
  if (conditions.length > 0) sql += " WHERE " + conditions.join(" AND ");
  sql += " ORDER BY last_activity DESC";
  if (options?.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }
  if (options?.offset) {
    sql += " OFFSET ?";
    params.push(options.offset);
  }
  const rows = database.prepare(sql).all(...params) as Array<Record<string, unknown>>;
  return rows.map(rowToSession);
}

export function revokeSession(sessionId: string, reason?: string): boolean {
  const database = getDb();
  const session = getSession(sessionId);
  if (!session) return false;

  const result = database
    .prepare("UPDATE sessions SET is_active = 0 WHERE id = ? AND is_active = 1")
    .run(sessionId);
  if (result.changes === 0) return false;

  blacklistToken(session.accessTokenJti, reason || "Session revoked", session.expiresAt);
  logSessionAudit({
    eventType: "SESSION_REVOKED",
    sessionId,
    userId: session.userId,
    ipAddress: session.ipAddress,
    status: "SUCCESS",
    details: { reason },
  });
  return true;
}

export function revokeAllUserSessions(userId: string, reason?: string): number {
  const sessions = listSessions({ userId, activeOnly: true });
  let revokedCount = 0;
  for (const session of sessions) {
    if (revokeSession(session.id, reason)) revokedCount++;
  }
  return revokedCount;
}

// =============================================================================
// Token Validation
// =============================================================================

export function validateAccessToken(token: string): TokenValidationResult {
  try {
    const decoded = jwt.verify(token, config.jwtSecret) as TokenClaims;

    if (decoded.type !== "access") {
      return { valid: false, error: "Invalid token type", errorCode: "INVALID_TYPE" };
    }

    // Check if token is blacklisted
    if (isTokenBlacklisted(decoded.jti)) {
      logSessionAudit({
        eventType: "SUSPICIOUS_ACTIVITY",
        sessionId: decoded.sid,
        userId: decoded.sub,
        status: "FAILURE",
        details: { reason: "Attempted use of blacklisted token", jti: decoded.jti },
      });
      return { valid: false, error: "Token has been revoked", errorCode: "TOKEN_REVOKED" };
    }

    // Check if session is still active
    const session = getSession(decoded.sid);
    if (!session || !session.isActive) {
      return { valid: false, error: "Session no longer active", errorCode: "SESSION_INACTIVE" };
    }

    // Update last activity
    const database = getDb();
    database
      .prepare("UPDATE sessions SET last_activity = ? WHERE id = ?")
      .run(new Date().toISOString(), decoded.sid);

    return {
      valid: true,
      claims: decoded,
      session,
    };
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return { valid: false, error: "Token has expired", errorCode: "TOKEN_EXPIRED" };
    }
    if (error instanceof jwt.JsonWebTokenError) {
      return { valid: false, error: "Invalid token", errorCode: "INVALID_TOKEN" };
    }
    return {
      valid: false,
      error: error instanceof Error ? error.message : String(error),
      errorCode: "UNKNOWN_ERROR",
    };
  }
}

export function refreshTokens(
  refreshToken: string,
  options?: {
    ipAddress?: string;
    device?: SessionDevice;
  }
): RefreshTokenResult {
  try {
    const decoded = jwt.verify(refreshToken, config.jwtSecret) as TokenClaims;

    if (decoded.type !== "refresh") {
      logSessionAudit({
        eventType: "SUSPICIOUS_ACTIVITY",
        userId: decoded.sub,
        ipAddress: options?.ipAddress,
        status: "FAILURE",
        details: { reason: "Invalid token type for refresh", providedType: decoded.type },
      });
      return { success: false, error: "Invalid token type" };
    }

    const session = getSession(decoded.sid);
    if (!session) {
      return { success: false, error: "Session not found" };
    }

    if (!session.isActive) {
      logSessionAudit({
        eventType: "SUSPICIOUS_ACTIVITY",
        sessionId: session.id,
        userId: session.userId,
        ipAddress: options?.ipAddress,
        status: "FAILURE",
        details: { reason: "Attempted refresh on inactive session" },
      });
      return { success: false, error: "Session is no longer active" };
    }

    // Verify refresh token hash
    const tokenHash = hashToken(refreshToken);
    if (tokenHash !== session.refreshTokenHash) {
      logSessionAudit({
        eventType: "SUSPICIOUS_ACTIVITY",
        sessionId: session.id,
        userId: session.userId,
        ipAddress: options?.ipAddress,
        status: "FAILURE",
        details: { reason: "Refresh token hash mismatch - possible token reuse" },
      });
      // Revoke session on token mismatch (potential replay attack)
      revokeSession(session.id, "Refresh token mismatch detected");
      return { success: false, error: "Invalid refresh token" };
    }

    // Blacklist old access token
    blacklistToken(session.accessTokenJti, "Token refreshed", session.expiresAt);

    // Generate new token pair
    const {
      tokens,
      accessJti,
      refreshToken: newRefreshToken,
    } = generateTokenPair(session.id, session.userId, {});

    const database = getDb();
    const now = new Date().toISOString();

    if (config.rotateRefreshTokens) {
      // Rotate refresh token
      const newRefreshHash = hashToken(newRefreshToken);
      database
        .prepare(
          "UPDATE sessions SET refresh_token_hash = ?, access_token_jti = ?, last_activity = ?, expires_at = ? WHERE id = ?"
        )
        .run(newRefreshHash, accessJti, now, tokens.refreshExpiresAt, session.id);
    } else {
      // Keep same refresh token, just update access token
      database
        .prepare("UPDATE sessions SET access_token_jti = ?, last_activity = ? WHERE id = ?")
        .run(accessJti, now, session.id);
      tokens.refreshToken = refreshToken; // Return original refresh token
      tokens.refreshExpiresAt = session.expiresAt;
    }

    logSessionAudit({
      eventType: "SESSION_REFRESHED",
      sessionId: session.id,
      userId: session.userId,
      ipAddress: options?.ipAddress,
      status: "SUCCESS",
      details: { rotated: config.rotateRefreshTokens },
    });

    return { success: true, tokens };
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return { success: false, error: "Refresh token has expired" };
    }
    if (error instanceof jwt.JsonWebTokenError) {
      return { success: false, error: "Invalid refresh token" };
    }
    return { success: false, error: error instanceof Error ? error.message : String(error) };
  }
}

// =============================================================================
// Token Blacklist
// =============================================================================

export function blacklistToken(jti: string, reason: string, expiresAt: string): void {
  const database = getDb();
  const blacklistedAt = new Date().toISOString();
  database
    .prepare(
      "INSERT OR IGNORE INTO token_blacklist (jti, reason, blacklisted_at, expires_at) VALUES (?, ?, ?, ?)"
    )
    .run(jti, reason, blacklistedAt, expiresAt);
  logSessionAudit({ eventType: "TOKEN_BLACKLISTED", status: "SUCCESS", details: { jti, reason } });
}

export function isTokenBlacklisted(jti: string): boolean {
  const database = getDb();
  const row = database.prepare("SELECT 1 FROM token_blacklist WHERE jti = ?").get(jti);
  return row !== undefined;
}

export function getBlacklistedTokens(options?: {
  limit?: number;
  offset?: number;
}): BlacklistedToken[] {
  const database = getDb();
  let sql =
    "SELECT * FROM token_blacklist WHERE expires_at > datetime('now') ORDER BY blacklisted_at DESC";
  const params: number[] = [];
  if (options?.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }
  if (options?.offset) {
    sql += " OFFSET ?";
    params.push(options.offset);
  }
  const rows = database.prepare(sql).all(...params) as Array<Record<string, unknown>>;
  return rows.map((row) => ({
    jti: row.jti as string,
    reason: row.reason as string,
    blacklistedAt: row.blacklisted_at as string,
    expiresAt: row.expires_at as string,
  }));
}

// =============================================================================
// Maintenance Functions
// =============================================================================

export function cleanupExpiredSessions(): number {
  const database = getDb();
  const result = database.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();
  return result.changes;
}

export function cleanupExpiredBlacklistEntries(): number {
  const database = getDb();
  const result = database
    .prepare("DELETE FROM token_blacklist WHERE expires_at < datetime('now')")
    .run();
  return result.changes;
}

export function cleanupSessionAuditEvents(olderThanDays: number = 90): number {
  const database = getDb();
  const cutoff = new Date(Date.now() - olderThanDays * 24 * 60 * 60 * 1000).toISOString();
  const result = database.prepare("DELETE FROM session_audit WHERE timestamp < ?").run(cutoff);
  return result.changes;
}

export function getSessionStats(userId?: string): SessionStats {
  const database = getDb();

  let totalSessions: number;
  let activeSessions: number;
  let expiredSessions: number;

  if (userId) {
    totalSessions = (
      database.prepare("SELECT COUNT(*) as count FROM sessions WHERE user_id = ?").get(userId) as {
        count: number;
      }
    ).count;
    activeSessions = (
      database
        .prepare(
          "SELECT COUNT(*) as count FROM sessions WHERE user_id = ? AND is_active = 1 AND expires_at > datetime('now')"
        )
        .get(userId) as { count: number }
    ).count;
    expiredSessions = (
      database
        .prepare(
          "SELECT COUNT(*) as count FROM sessions WHERE user_id = ? AND expires_at < datetime('now')"
        )
        .get(userId) as { count: number }
    ).count;
  } else {
    totalSessions = (
      database.prepare("SELECT COUNT(*) as count FROM sessions").get() as { count: number }
    ).count;
    activeSessions = (
      database
        .prepare(
          "SELECT COUNT(*) as count FROM sessions WHERE is_active = 1 AND expires_at > datetime('now')"
        )
        .get() as { count: number }
    ).count;
    expiredSessions = (
      database
        .prepare("SELECT COUNT(*) as count FROM sessions WHERE expires_at < datetime('now')")
        .get() as { count: number }
    ).count;
  }

  const blacklistedTokens = (
    database
      .prepare("SELECT COUNT(*) as count FROM token_blacklist WHERE expires_at > datetime('now')")
      .get() as { count: number }
  ).count;
  const auditEvents = (
    database.prepare("SELECT COUNT(*) as count FROM session_audit").get() as { count: number }
  ).count;

  return {
    totalSessions,
    activeSessions,
    expiredSessions,
    revokedSessions: totalSessions - activeSessions - expiredSessions,
    blacklistedTokens,
    auditEvents,
  };
}
