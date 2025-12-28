/**
 * Session Management Tests
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  initSessionDatabase,
  closeSessionDatabase,
  isSessionDbInitialized,
  getSessionConfig,
  updateSessionConfig,
  createSession,
  getSession,
  listSessions,
  revokeSession,
  revokeAllUserSessions,
  validateAccessToken,
  refreshTokens,
  blacklistToken,
  isTokenBlacklisted,
  getBlacklistedTokens,
  logSessionAudit,
  getSessionAuditEvents,
  cleanupExpiredSessions,
  cleanupExpiredBlacklistEntries,
  cleanupSessionAuditEvents,
  getSessionStats,
} from "./session-manager.js";

describe("Session Management", () => {
  let testDbPath: string;

  beforeEach(() => {
    // Create a unique temp database for each test
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "session-test-"));
    testDbPath = path.join(tempDir, "sessions.db");
  });

  afterEach(() => {
    closeSessionDatabase();
    // Clean up test database
    try {
      if (fs.existsSync(testDbPath)) {
        fs.unlinkSync(testDbPath);
      }
      const dir = path.dirname(testDbPath);
      if (fs.existsSync(dir)) {
        fs.rmdirSync(dir);
      }
    } catch {
      // Ignore cleanup errors
    }
  });

  describe("Database Lifecycle", () => {
    it("should initialize database successfully", () => {
      const result = initSessionDatabase(testDbPath);
      expect(result.success).toBe(true);
      expect(result.created).toBe(true);
      expect(result.path).toBe(testDbPath);
      expect(isSessionDbInitialized()).toBe(true);
    });

    it("should return existing database on re-initialization", () => {
      const first = initSessionDatabase(testDbPath);
      expect(first.created).toBe(true);

      const second = initSessionDatabase(testDbPath);
      expect(second.success).toBe(true);
      expect(second.created).toBe(false);
    });

    it("should close database", () => {
      initSessionDatabase(testDbPath);
      expect(isSessionDbInitialized()).toBe(true);

      closeSessionDatabase();
      expect(isSessionDbInitialized()).toBe(false);
    });
  });

  describe("Configuration", () => {
    it("should return default config", () => {
      initSessionDatabase(testDbPath);
      const config = getSessionConfig();
      expect(config.accessExpirySeconds).toBe(900);
      expect(config.refreshExpirySeconds).toBe(604800);
      expect(config.maxConcurrentSessions).toBe(5);
      expect(config.rotateRefreshTokens).toBe(true);
    });

    it("should update config", () => {
      initSessionDatabase(testDbPath);
      const updated = updateSessionConfig({ maxConcurrentSessions: 10 });
      expect(updated.maxConcurrentSessions).toBe(10);
    });

    it("should apply custom config on init", () => {
      initSessionDatabase(testDbPath, { maxConcurrentSessions: 3 });
      const config = getSessionConfig();
      expect(config.maxConcurrentSessions).toBe(3);
    });
  });

  describe("Session CRUD", () => {
    beforeEach(() => {
      initSessionDatabase(testDbPath, { jwtSecret: "test-secret-key-for-testing-12345" });
    });

    it("should create a session", () => {
      const result = createSession({
        userId: "user-1",
        email: "user@example.com",
        roles: ["user"],
        ipAddress: "192.168.1.1",
      });

      expect(result.session).toBeDefined();
      expect(result.session.userId).toBe("user-1");
      expect(result.session.isActive).toBe(true);
      expect(result.tokens.accessToken).toBeDefined();
      expect(result.tokens.refreshToken).toBeDefined();
      expect(result.tokens.tokenType).toBe("Bearer");
    });

    it("should get session by ID", () => {
      const created = createSession({ userId: "user-1" });
      const session = getSession(created.session.id);

      expect(session).toBeDefined();
      expect(session?.id).toBe(created.session.id);
      expect(session?.userId).toBe("user-1");
    });

    it("should return null for non-existent session", () => {
      const session = getSession("non-existent-id");
      expect(session).toBeNull();
    });

    it("should list sessions for user", () => {
      createSession({ userId: "user-1" });
      createSession({ userId: "user-1" });
      createSession({ userId: "user-2" });

      const user1Sessions = listSessions({ userId: "user-1" });
      expect(user1Sessions).toHaveLength(2);

      const allSessions = listSessions({});
      expect(allSessions).toHaveLength(3);
    });

    it("should filter active sessions only", () => {
      const created = createSession({ userId: "user-1" });
      createSession({ userId: "user-1" });
      revokeSession(created.session.id);

      const activeSessions = listSessions({ userId: "user-1", activeOnly: true });
      expect(activeSessions).toHaveLength(1);
    });

    it("should revoke session", () => {
      const created = createSession({ userId: "user-1" });
      const revoked = revokeSession(created.session.id, "Testing revocation");

      expect(revoked).toBe(true);

      const session = getSession(created.session.id);
      expect(session?.isActive).toBe(false);
    });

    it("should revoke all user sessions", () => {
      createSession({ userId: "user-1" });
      createSession({ userId: "user-1" });
      createSession({ userId: "user-2" });

      const revokedCount = revokeAllUserSessions("user-1", "Account compromised");
      expect(revokedCount).toBe(2);

      const user1Sessions = listSessions({ userId: "user-1", activeOnly: true });
      expect(user1Sessions).toHaveLength(0);

      const user2Sessions = listSessions({ userId: "user-2", activeOnly: true });
      expect(user2Sessions).toHaveLength(1);
    });

    it("should enforce concurrent session limit", () => {
      initSessionDatabase(testDbPath, {
        jwtSecret: "test-secret-key-for-testing-12345",
        maxConcurrentSessions: 2,
      });

      createSession({ userId: "user-1" });
      createSession({ userId: "user-1" });
      createSession({ userId: "user-1" }); // Should revoke the oldest

      const sessions = listSessions({ userId: "user-1", activeOnly: true });
      expect(sessions).toHaveLength(2);
    });
  });

  describe("Token Validation", () => {
    beforeEach(() => {
      initSessionDatabase(testDbPath, { jwtSecret: "test-secret-key-for-testing-12345" });
    });

    it("should validate a valid access token", () => {
      const created = createSession({ userId: "user-1", roles: ["admin"] });
      const result = validateAccessToken(created.tokens.accessToken);

      expect(result.valid).toBe(true);
      expect(result.claims?.sub).toBe("user-1");
      expect(result.claims?.roles).toContain("admin");
    });

    it("should reject an invalid token", () => {
      const result = validateAccessToken("invalid-token");
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe("INVALID_TOKEN");
    });

    it("should reject token from revoked session", () => {
      const created = createSession({ userId: "user-1" });
      revokeSession(created.session.id);

      const result = validateAccessToken(created.tokens.accessToken);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe("TOKEN_REVOKED");
    });
  });

  describe("Token Refresh", () => {
    beforeEach(() => {
      initSessionDatabase(testDbPath, {
        jwtSecret: "test-secret-key-for-testing-12345",
        rotateRefreshTokens: true,
      });
    });

    it("should refresh tokens", () => {
      const created = createSession({ userId: "user-1" });
      const result = refreshTokens(created.tokens.refreshToken);

      expect(result.success).toBe(true);
      expect(result.tokens).toBeDefined();
      expect(result.tokens?.accessToken).toBeDefined();
      expect(result.tokens?.accessToken).not.toBe(created.tokens.accessToken);
    });

    it("should blacklist old access token on refresh", () => {
      const created = createSession({ userId: "user-1" });
      refreshTokens(created.tokens.refreshToken);

      // The old access token should now be blacklisted
      const validation = validateAccessToken(created.tokens.accessToken);
      expect(validation.valid).toBe(false);
      expect(validation.errorCode).toBe("TOKEN_REVOKED");
    });

    it("should reject refresh with wrong token", () => {
      createSession({ userId: "user-1" });
      const result = refreshTokens("invalid-refresh-token");

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it("should reject refresh after session revocation", () => {
      const created = createSession({ userId: "user-1" });
      revokeSession(created.session.id);

      const result = refreshTokens(created.tokens.refreshToken);
      expect(result.success).toBe(false);
    });
  });

  describe("Token Blacklist", () => {
    beforeEach(() => {
      initSessionDatabase(testDbPath, { jwtSecret: "test-secret-key-for-testing-12345" });
    });

    it("should blacklist a token", () => {
      const jti = "test-jti-12345";
      blacklistToken(jti, "Test blacklist", new Date(Date.now() + 3600000).toISOString());

      expect(isTokenBlacklisted(jti)).toBe(true);
    });

    it("should not find non-blacklisted token", () => {
      expect(isTokenBlacklisted("non-existent-jti")).toBe(false);
    });

    it("should list blacklisted tokens", () => {
      const future = new Date(Date.now() + 3600000).toISOString();
      blacklistToken("jti-1", "Reason 1", future);
      blacklistToken("jti-2", "Reason 2", future);

      const blacklisted = getBlacklistedTokens();
      expect(blacklisted.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("Audit Logging", () => {
    beforeEach(() => {
      initSessionDatabase(testDbPath, { jwtSecret: "test-secret-key-for-testing-12345" });
    });

    it("should log session audit events", () => {
      logSessionAudit({
        eventType: "SESSION_CREATED",
        userId: "user-1",
        status: "SUCCESS",
      });

      const events = getSessionAuditEvents({ userId: "user-1" });
      expect(events).toHaveLength(1);
      expect(events[0].eventType).toBe("SESSION_CREATED");
      expect(events[0].status).toBe("SUCCESS");
    });

    it("should filter events by type", () => {
      createSession({ userId: "user-1" });
      createSession({ userId: "user-1" });

      const events = getSessionAuditEvents({ eventType: "SESSION_CREATED" });
      expect(events.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("Statistics", () => {
    beforeEach(() => {
      initSessionDatabase(testDbPath, { jwtSecret: "test-secret-key-for-testing-12345" });
    });

    it("should get session stats", () => {
      createSession({ userId: "user-1" });
      createSession({ userId: "user-1" });
      const created = createSession({ userId: "user-2" });
      revokeSession(created.session.id);

      const stats = getSessionStats();
      expect(stats.totalSessions).toBe(3);
      expect(stats.activeSessions).toBe(2);
      expect(stats.revokedSessions).toBe(1);
    });

    it("should get user-specific stats", () => {
      createSession({ userId: "user-1" });
      createSession({ userId: "user-1" });
      createSession({ userId: "user-2" });

      const stats = getSessionStats("user-1");
      expect(stats.totalSessions).toBe(2);
      expect(stats.activeSessions).toBe(2);
    });
  });

  describe("Maintenance Functions", () => {
    beforeEach(() => {
      initSessionDatabase(testDbPath, { jwtSecret: "test-secret-key-for-testing-12345" });
    });

    it("should cleanup expired sessions", () => {
      // Create a session (will be active, not expired)
      createSession({ userId: "user-1" });

      // This won't delete any because we just created them
      const cleaned = cleanupExpiredSessions();
      expect(cleaned).toBe(0);
    });

    it("should cleanup expired blacklist entries", () => {
      const cleaned = cleanupExpiredBlacklistEntries();
      expect(cleaned).toBe(0);
    });

    it("should cleanup old audit events", () => {
      logSessionAudit({
        eventType: "SESSION_CREATED",
        userId: "user-1",
        status: "SUCCESS",
      });

      // Won't delete recent events
      const cleaned = cleanupSessionAuditEvents(90);
      expect(cleaned).toBe(0);
    });
  });
});
