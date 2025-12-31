/**
 * Tests for Audit/SIEM Integration Module
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import {
  initAuditSiemDb,
  createSiemConfig,
  getSiemConfig,
  listSiemConfigs,
  updateSiemConfig,
  deleteSiemConfig,
  logSecurityEvent,
  queryAuditLogs,
  getAuditLogStats,
  getForwardQueue,
  retryFailedEvents,
  clearForwardQueue,
} from "./audit-siem.js";

// Use unique DB path per test run to avoid locking issues
const getTestDbPath = () =>
  path.join(
    process.cwd(),
    `.test-audit-siem-${Date.now()}-${Math.random().toString(36).slice(2)}.db`
  );
let testDbPath: string;

describe("Audit/SIEM Integration", () => {
  beforeEach(() => {
    testDbPath = getTestDbPath();
  });

  afterEach(() => {
    try {
      if (fs.existsSync(testDbPath)) {
        fs.unlinkSync(testDbPath);
      }
    } catch {
      // Ignore cleanup errors on Windows
    }
  });

  describe("initAuditSiemDb", () => {
    it("should initialize database with required tables", () => {
      const result = initAuditSiemDb(testDbPath);
      expect(result.path).toBe(testDbPath);
      expect(result.tables).toContain("siem_configs");
      expect(result.tables).toContain("audit_events");
      expect(result.tables).toContain("forward_queue");
    });
  });

  describe("SIEM Configuration", () => {
    it("should create SIEM config", () => {
      initAuditSiemDb(testDbPath);
      const config = createSiemConfig({
        name: "Splunk Production",
        provider: "splunk",
        endpoint: "https://splunk.example.com:8088",
        apiKey: "test-token",
        enabled: true,
        retryCount: 3,
        batchSize: 100,
        flushIntervalMs: 30000,
      });

      expect(config.id).toMatch(/^siem-\d+-[a-z0-9]+$/);
      expect(config.name).toBe("Splunk Production");
      expect(config.provider).toBe("splunk");
      expect(config.enabled).toBe(true);
    });

    it("should get SIEM config by ID", () => {
      initAuditSiemDb(testDbPath);
      const created = createSiemConfig({
        name: "ES Config",
        provider: "elasticsearch",
        endpoint: "https://es.example.com:9200",
        index: "security-logs",
        enabled: true,
        retryCount: 3,
        batchSize: 50,
        flushIntervalMs: 60000,
      });

      const config = getSiemConfig(created.id);
      expect(config).not.toBeNull();
      expect(config?.name).toBe("ES Config");
      expect(config?.index).toBe("security-logs");
    });

    it("should list SIEM configs", () => {
      initAuditSiemDb(testDbPath);
      createSiemConfig({
        name: "Splunk",
        provider: "splunk",
        endpoint: "https://splunk.example.com",
        enabled: true,
        retryCount: 3,
        batchSize: 100,
        flushIntervalMs: 30000,
      });
      createSiemConfig({
        name: "ES",
        provider: "elasticsearch",
        endpoint: "https://es.example.com",
        enabled: true,
        retryCount: 3,
        batchSize: 100,
        flushIntervalMs: 30000,
      });

      const allConfigs = listSiemConfigs();
      expect(allConfigs.length).toBe(2);

      const splunkConfigs = listSiemConfigs("splunk");
      expect(splunkConfigs.length).toBe(1);
    });

    it("should update SIEM config", () => {
      initAuditSiemDb(testDbPath);
      const created = createSiemConfig({
        name: "Original",
        provider: "syslog",
        endpoint: "syslog.example.com:514",
        enabled: true,
        retryCount: 3,
        batchSize: 100,
        flushIntervalMs: 30000,
      });

      const updated = updateSiemConfig(created.id, {
        name: "Updated",
        enabled: false,
      });

      expect(updated?.name).toBe("Updated");
      expect(updated?.enabled).toBe(false);
    });

    it("should delete SIEM config", () => {
      initAuditSiemDb(testDbPath);
      const created = createSiemConfig({
        name: "ToDelete",
        provider: "file",
        endpoint: "/var/log/audit.log",
        enabled: true,
        retryCount: 3,
        batchSize: 100,
        flushIntervalMs: 30000,
      });

      const deleted = deleteSiemConfig(created.id);
      expect(deleted).toBe(true);

      const config = getSiemConfig(created.id);
      expect(config).toBeNull();
    });
  });

  describe("Security Event Logging", () => {
    it("should log security event", () => {
      initAuditSiemDb(testDbPath);
      const event = logSecurityEvent({
        severity: "high",
        category: "authentication",
        action: "login_failed",
        actor: "user@example.com",
        actorType: "user",
        resource: "/api/login",
        resourceType: "endpoint",
        outcome: "failure",
        details: { attempts: 5, ip: "192.168.1.100" },
      });

      expect(event.id).toMatch(/^evt-\d+-[a-z0-9]+$/);
      expect(event.severity).toBe("high");
      expect(event.category).toBe("authentication");
      expect(event.outcome).toBe("failure");
    });

    it("should query audit logs with filters", () => {
      initAuditSiemDb(testDbPath);
      logSecurityEvent({
        severity: "high",
        category: "authentication",
        action: "login_failed",
        actor: "user1@example.com",
        actorType: "user",
        resource: "/api/login",
        resourceType: "endpoint",
        outcome: "failure",
        details: {},
      });
      logSecurityEvent({
        severity: "info",
        category: "data_access",
        action: "read_file",
        actor: "user2@example.com",
        actorType: "user",
        resource: "/files/report.pdf",
        resourceType: "file",
        outcome: "success",
        details: {},
      });

      const highEvents = queryAuditLogs({ severity: ["high"] });
      expect(highEvents.length).toBe(1);

      const authEvents = queryAuditLogs({ category: ["authentication"] });
      expect(authEvents.length).toBe(1);

      const failedEvents = queryAuditLogs({ outcome: "failure" });
      expect(failedEvents.length).toBe(1);
    });

    it("should get audit log statistics", () => {
      initAuditSiemDb(testDbPath);
      logSecurityEvent({
        severity: "high",
        category: "authentication",
        action: "login_failed",
        actor: "user@example.com",
        actorType: "user",
        resource: "/api/login",
        resourceType: "endpoint",
        outcome: "failure",
        details: {},
      });
      logSecurityEvent({
        severity: "info",
        category: "system",
        action: "startup",
        actor: "system",
        actorType: "system",
        resource: "mcp-server",
        resourceType: "service",
        outcome: "success",
        details: {},
      });

      const stats = getAuditLogStats();
      expect(stats.totalEvents).toBe(2);
      expect(stats.eventsByCategory["authentication"]).toBe(1);
      expect(stats.eventsByCategory["system"]).toBe(1);
      expect(stats.eventsBySeverity["high"]).toBe(1);
      expect(stats.eventsBySeverity["info"]).toBe(1);
    });
  });

  describe("Forward Queue Management", () => {
    it("should get forward queue status", () => {
      initAuditSiemDb(testDbPath);
      createSiemConfig({
        name: "Test",
        provider: "file",
        endpoint: "/tmp/test.log",
        enabled: true,
        retryCount: 3,
        batchSize: 100,
        flushIntervalMs: 30000,
      });

      logSecurityEvent({
        severity: "info",
        category: "system",
        action: "test",
        actor: "system",
        actorType: "system",
        resource: "test",
        resourceType: "test",
        outcome: "success",
        details: {},
      });

      const queue = getForwardQueue();
      expect(queue.pending).toBeGreaterThanOrEqual(0);
    });

    it("should retry failed events", () => {
      initAuditSiemDb(testDbPath);
      const config = createSiemConfig({
        name: "Test",
        provider: "file",
        endpoint: "/tmp/test.log",
        enabled: true,
        retryCount: 3,
        batchSize: 100,
        flushIntervalMs: 30000,
      });

      const retried = retryFailedEvents(config.id);
      expect(retried).toBeGreaterThanOrEqual(0);
    });

    it("should clear forward queue", () => {
      initAuditSiemDb(testDbPath);
      const config = createSiemConfig({
        name: "Test",
        provider: "file",
        endpoint: "/tmp/test.log",
        enabled: true,
        retryCount: 3,
        batchSize: 100,
        flushIntervalMs: 30000,
      });

      const cleared = clearForwardQueue(config.id);
      expect(cleared).toBeGreaterThanOrEqual(0);
    });
  });
});
