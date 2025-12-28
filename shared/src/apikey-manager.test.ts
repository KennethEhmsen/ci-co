/**
 * API Key Management Tests
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  initApiKeyDatabase,
  closeApiKeyDatabase,
  isApiKeyDbInitialized,
  createApiKey,
  getApiKey,
  listApiKeys,
  revokeApiKey,
  rotateApiKey,
  validateApiKey,
  getApiKeyAuditEvents,
  markExpiredApiKeys,
  getApiKeyStats,
  cleanupApiKeyAuditLogs,
  VALID_SCOPES,
} from "./apikey-manager.js";

describe("API Key Management", () => {
  let testDbPath: string;

  beforeEach(() => {
    // Create a unique temp database for each test
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "apikey-test-"));
    testDbPath = path.join(tempDir, "apikeys.db");
  });

  afterEach(() => {
    closeApiKeyDatabase();
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
      const result = initApiKeyDatabase(testDbPath);
      expect(result.success).toBe(true);
      expect(result.created).toBe(true);
      expect(result.path).toBe(testDbPath);
      expect(isApiKeyDbInitialized()).toBe(true);
    });

    it("should return existing database on re-initialization", () => {
      const first = initApiKeyDatabase(testDbPath);
      expect(first.created).toBe(true);

      const second = initApiKeyDatabase(testDbPath);
      expect(second.success).toBe(true);
      expect(second.created).toBe(false);
    });

    it("should close database", () => {
      initApiKeyDatabase(testDbPath);
      expect(isApiKeyDbInitialized()).toBe(true);

      closeApiKeyDatabase();
      expect(isApiKeyDbInitialized()).toBe(false);
    });
  });

  describe("API Key Creation", () => {
    beforeEach(() => {
      initApiKeyDatabase(testDbPath);
    });

    it("should create an API key with valid scopes", () => {
      const result = createApiKey({
        name: "Test Key",
        scopes: ["scan:read", "report:read"],
        createdBy: "testUser",
      });

      expect(result.key.name).toBe("Test Key");
      expect(result.key.scopes).toContain("scan:read");
      expect(result.key.scopes).toContain("report:read");
      expect(result.key.status).toBe("active");
      expect(result.fullKey).toMatch(/^ci-co_/);
    });

    it("should create an API key with custom expiration", () => {
      const result = createApiKey({
        name: "Short-lived Key",
        scopes: ["scan:read"],
        createdBy: "testUser",
        expiresInDays: 30,
      });

      expect(result.key.expiresAt).toBeDefined();
      const expiresAt = new Date(result.key.expiresAt!);
      const now = new Date();
      const daysDiff = Math.ceil((expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
      expect(daysDiff).toBeGreaterThanOrEqual(29);
      expect(daysDiff).toBeLessThanOrEqual(31);
    });

    it("should create an API key with IP allowlist", () => {
      const result = createApiKey({
        name: "IP Restricted Key",
        scopes: ["scan:read"],
        createdBy: "testUser",
        ipAllowlist: ["192.168.1.1", "10.0.0.1"],
      });

      expect(result.key.ipAllowlist).toContain("192.168.1.1");
      expect(result.key.ipAllowlist).toContain("10.0.0.1");
    });

    it("should create an API key with custom rate limit", () => {
      const result = createApiKey({
        name: "Rate Limited Key",
        scopes: ["scan:read"],
        createdBy: "testUser",
        rateLimit: 50,
      });

      expect(result.key.rateLimit).toBe(50);
    });

    it("should reject invalid scopes", () => {
      expect(() =>
        createApiKey({
          name: "Bad Key",
          scopes: ["invalid:scope" as any],
          createdBy: "testUser",
        })
      ).toThrow("Invalid scope");
    });
  });

  describe("API Key Retrieval", () => {
    beforeEach(() => {
      initApiKeyDatabase(testDbPath);
    });

    it("should get an API key by ID", () => {
      const created = createApiKey({
        name: "Get Test",
        scopes: ["scan:read"],
        createdBy: "testUser",
      });

      const retrieved = getApiKey(created.key.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.name).toBe("Get Test");
    });

    it("should return null for non-existent key", () => {
      const retrieved = getApiKey("non-existent-id");
      expect(retrieved).toBeNull();
    });

    it("should list API keys", () => {
      createApiKey({ name: "Key 1", scopes: ["scan:read"], createdBy: "user1" });
      createApiKey({ name: "Key 2", scopes: ["report:read"], createdBy: "user2" });
      createApiKey({ name: "Key 3", scopes: ["admin:*"], createdBy: "user1" });

      const allKeys = listApiKeys();
      expect(allKeys.length).toBe(3);
    });

    it("should filter keys by creator", () => {
      createApiKey({ name: "Key 1", scopes: ["scan:read"], createdBy: "user1" });
      createApiKey({ name: "Key 2", scopes: ["report:read"], createdBy: "user2" });
      createApiKey({ name: "Key 3", scopes: ["admin:*"], createdBy: "user1" });

      const user1Keys = listApiKeys({ createdBy: "user1" });
      expect(user1Keys.length).toBe(2);
    });

    it("should filter keys by status", () => {
      const key1 = createApiKey({ name: "Key 1", scopes: ["scan:read"], createdBy: "user1" });
      createApiKey({ name: "Key 2", scopes: ["report:read"], createdBy: "user2" });

      revokeApiKey(key1.key.id);

      const activeKeys = listApiKeys({ status: "active" });
      expect(activeKeys.length).toBe(1);

      const revokedKeys = listApiKeys({ status: "revoked", includeExpired: true });
      expect(revokedKeys.length).toBe(1);
    });
  });

  describe("API Key Revocation", () => {
    beforeEach(() => {
      initApiKeyDatabase(testDbPath);
    });

    it("should revoke an API key", () => {
      const created = createApiKey({
        name: "Revoke Test",
        scopes: ["scan:read"],
        createdBy: "testUser",
      });

      const revoked = revokeApiKey(created.key.id);
      expect(revoked).toBe(true);

      const retrieved = getApiKey(created.key.id);
      expect(retrieved?.status).toBe("revoked");
    });

    it("should return false when revoking non-existent key", () => {
      const revoked = revokeApiKey("non-existent-id");
      expect(revoked).toBe(false);
    });

    it("should return false when revoking already revoked key", () => {
      const created = createApiKey({
        name: "Double Revoke",
        scopes: ["scan:read"],
        createdBy: "testUser",
      });

      revokeApiKey(created.key.id);
      const secondRevoke = revokeApiKey(created.key.id);
      expect(secondRevoke).toBe(false);
    });
  });

  describe("API Key Rotation", () => {
    beforeEach(() => {
      initApiKeyDatabase(testDbPath);
    });

    it("should rotate an API key", () => {
      const created = createApiKey({
        name: "Rotate Test",
        scopes: ["scan:read"],
        createdBy: "testUser",
      });

      const rotated = rotateApiKey(created.key.id);
      expect(rotated).not.toBeNull();
      expect(rotated?.key.id).toBe(created.key.id); // ID preserved
      expect(rotated?.newFullKey).toMatch(/^ci-co_/);
      expect(rotated?.previousKeyPrefix).toBe(created.key.keyPrefix);
      expect(rotated?.key.keyPrefix).not.toBe(created.key.keyPrefix); // New prefix
    });

    it("should return null when rotating non-existent key", () => {
      const rotated = rotateApiKey("non-existent-id");
      expect(rotated).toBeNull();
    });

    it("should throw when rotating revoked key", () => {
      const created = createApiKey({
        name: "Revoked Rotate",
        scopes: ["scan:read"],
        createdBy: "testUser",
      });

      revokeApiKey(created.key.id);
      expect(() => rotateApiKey(created.key.id)).toThrow("Cannot rotate a revoked or expired key");
    });
  });

  describe("API Key Validation", () => {
    beforeEach(() => {
      initApiKeyDatabase(testDbPath);
    });

    it("should validate a valid API key", () => {
      const created = createApiKey({
        name: "Validate Test",
        scopes: ["scan:read"],
        createdBy: "testUser",
      });

      const result = validateApiKey(created.fullKey);
      expect(result.valid).toBe(true);
      expect(result.key?.name).toBe("Validate Test");
    });

    it("should reject an invalid API key", () => {
      const result = validateApiKey("ci-co_invalidkey12345");
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("Invalid API key");
    });

    it("should reject a revoked API key", () => {
      const created = createApiKey({
        name: "Revoked Validate",
        scopes: ["scan:read"],
        createdBy: "testUser",
      });

      revokeApiKey(created.key.id);

      const result = validateApiKey(created.fullKey);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("revoked");
    });

    it("should validate scope requirements", () => {
      const created = createApiKey({
        name: "Scope Test",
        scopes: ["scan:read"],
        createdBy: "testUser",
      });

      const validScope = validateApiKey(created.fullKey, "scan:read");
      expect(validScope.valid).toBe(true);

      const invalidScope = validateApiKey(created.fullKey, "report:write");
      expect(invalidScope.valid).toBe(false);
      expect(invalidScope.reason).toContain("Missing required scope");
    });

    it("should validate admin:* scope grants all permissions", () => {
      const created = createApiKey({
        name: "Admin Test",
        scopes: ["admin:*"],
        createdBy: "testUser",
      });

      expect(validateApiKey(created.fullKey, "scan:read").valid).toBe(true);
      expect(validateApiKey(created.fullKey, "report:write").valid).toBe(true);
      expect(validateApiKey(created.fullKey, "policy:read").valid).toBe(true);
    });

    it("should validate IP allowlist", () => {
      const created = createApiKey({
        name: "IP Test",
        scopes: ["scan:read"],
        createdBy: "testUser",
        ipAllowlist: ["192.168.1.1"],
      });

      const validIp = validateApiKey(created.fullKey, undefined, "192.168.1.1");
      expect(validIp.valid).toBe(true);

      const invalidIp = validateApiKey(created.fullKey, undefined, "10.0.0.1");
      expect(invalidIp.valid).toBe(false);
      expect(invalidIp.reason).toContain("IP address not allowed");
    });

    it("should mark expired keys during validation", () => {
      const pastDate = new Date(Date.now() - 1000).toISOString();
      const created = createApiKey({
        name: "Expired Test",
        scopes: ["scan:read"],
        createdBy: "testUser",
        expiresAt: pastDate,
      });

      const result = validateApiKey(created.fullKey);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("expired");
      expect(result.key?.status).toBe("expired");
    });
  });

  describe("Audit Events", () => {
    beforeEach(() => {
      initApiKeyDatabase(testDbPath);
    });

    it("should log key creation", () => {
      createApiKey({
        name: "Audit Test",
        scopes: ["scan:read"],
        createdBy: "auditUser",
      });

      const events = getApiKeyAuditEvents({ eventType: "KEY_CREATED" });
      expect(events.length).toBeGreaterThan(0);

      const createEvent = events.find((e) => e.keyName === "Audit Test");
      expect(createEvent).toBeDefined();
      expect(createEvent?.status).toBe("SUCCESS");
    });

    it("should log key revocation", () => {
      const created = createApiKey({
        name: "Revoke Audit",
        scopes: ["scan:read"],
        createdBy: "testUser",
      });

      revokeApiKey(created.key.id, "adminActor");

      const events = getApiKeyAuditEvents({ eventType: "KEY_REVOKED" });
      expect(events.length).toBeGreaterThan(0);
    });

    it("should log key rotation", () => {
      const created = createApiKey({
        name: "Rotate Audit",
        scopes: ["scan:read"],
        createdBy: "testUser",
      });

      rotateApiKey(created.key.id);

      const events = getApiKeyAuditEvents({ eventType: "KEY_ROTATED" });
      expect(events.length).toBeGreaterThan(0);
    });

    it("should log key usage", () => {
      const created = createApiKey({
        name: "Usage Audit",
        scopes: ["scan:read"],
        createdBy: "testUser",
      });

      validateApiKey(created.fullKey);

      const events = getApiKeyAuditEvents({ eventType: "KEY_USED" });
      expect(events.length).toBeGreaterThan(0);
    });
  });

  describe("Maintenance", () => {
    beforeEach(() => {
      initApiKeyDatabase(testDbPath);
    });

    it("should mark expired keys", () => {
      const pastDate = new Date(Date.now() - 1000).toISOString();
      createApiKey({
        name: "Expired Key",
        scopes: ["scan:read"],
        createdBy: "testUser",
        expiresAt: pastDate,
      });

      const marked = markExpiredApiKeys();
      expect(marked).toBeGreaterThanOrEqual(1);
    });

    it("should get API key stats", () => {
      createApiKey({ name: "Key 1", scopes: ["scan:read"], createdBy: "user1" });
      createApiKey({ name: "Key 2", scopes: ["report:read"], createdBy: "user2" });
      const key3 = createApiKey({ name: "Key 3", scopes: ["admin:*"], createdBy: "user1" });

      revokeApiKey(key3.key.id);

      const stats = getApiKeyStats();
      expect(stats.total).toBe(3);
      expect(stats.active).toBe(2);
      expect(stats.revoked).toBe(1);
    });

    it("should cleanup old audit logs", () => {
      createApiKey({
        name: "Cleanup Test",
        scopes: ["scan:read"],
        createdBy: "testUser",
      });

      // Cleanup with -1 days (future date) to remove all logs including current ones
      const cleaned = cleanupApiKeyAuditLogs(-1);
      expect(cleaned).toBeGreaterThan(0);
    });
  });

  describe("Valid Scopes", () => {
    it("should export valid scopes", () => {
      expect(VALID_SCOPES).toContain("scan:read");
      expect(VALID_SCOPES).toContain("scan:write");
      expect(VALID_SCOPES).toContain("policy:read");
      expect(VALID_SCOPES).toContain("policy:write");
      expect(VALID_SCOPES).toContain("suppression:read");
      expect(VALID_SCOPES).toContain("suppression:write");
      expect(VALID_SCOPES).toContain("report:read");
      expect(VALID_SCOPES).toContain("report:write");
      expect(VALID_SCOPES).toContain("admin:*");
    });
  });
});
