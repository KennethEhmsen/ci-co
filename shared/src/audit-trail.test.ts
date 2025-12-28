/**
 * Audit Trail Tests
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  initAuditDatabase,
  closeAuditDatabase,
  isAuditDbInitialized,
  getAuditConfig,
  updateAuditConfig,
  logAuditEvent,
  getAuditEvent,
  searchAuditEvents,
  getActionCategory,
  exportAuditLogs,
  verifyEventChecksum,
  verifyAuditIntegrity,
  addAuditEventListener,
  removeAuditEventListener,
  configureSiem,
  getSiemQueueStatus,
  getAuditStats,
  aggregateAuditEvents,
  cleanupExpiredAuditEvents,
  cleanupFailedSiemQueue,
} from "./audit-trail.js";
import type { AuditEvent, CreateAuditEventOptions } from "./types.js";

describe("Audit Trail", () => {
  let testDbPath: string;

  beforeEach(() => {
    // Create a unique temp database for each test
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-test-"));
    testDbPath = path.join(tempDir, "audit.db");
  });

  afterEach(() => {
    closeAuditDatabase();
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
      const result = initAuditDatabase(testDbPath);
      expect(result.success).toBe(true);
      expect(result.created).toBe(true);
      expect(result.path).toBe(testDbPath);
      expect(isAuditDbInitialized()).toBe(true);
    });

    it("should return existing database on re-initialization", () => {
      const first = initAuditDatabase(testDbPath);
      expect(first.created).toBe(true);

      const second = initAuditDatabase(testDbPath);
      expect(second.success).toBe(true);
      expect(second.created).toBe(false);
    });

    it("should close database", () => {
      initAuditDatabase(testDbPath);
      expect(isAuditDbInitialized()).toBe(true);

      closeAuditDatabase();
      expect(isAuditDbInitialized()).toBe(false);
    });
  });

  describe("Configuration", () => {
    it("should return default config", () => {
      initAuditDatabase(testDbPath);
      const config = getAuditConfig();
      expect(config.retentionDays).toBe(90);
      expect(config.tamperProof).toBe(true);
      expect(config.realTimeStreaming).toBe(false);
    });

    it("should update config", () => {
      initAuditDatabase(testDbPath);
      const updated = updateAuditConfig({ retentionDays: 30 });
      expect(updated.retentionDays).toBe(30);
    });

    it("should apply custom config on init", () => {
      initAuditDatabase(testDbPath, { retentionDays: 180, tamperProof: false });
      const config = getAuditConfig();
      expect(config.retentionDays).toBe(180);
      expect(config.tamperProof).toBe(false);
    });
  });

  describe("Event Logging", () => {
    beforeEach(() => {
      initAuditDatabase(testDbPath);
    });

    it("should log an audit event", () => {
      const options: CreateAuditEventOptions = {
        actor: { type: "user", id: "user-1", email: "user@example.com" },
        action: "auth.login",
        resource: { type: "session", id: "session-123" },
        outcome: "success",
      };

      const event = logAuditEvent(options);

      expect(event.id).toBeDefined();
      expect(event.timestamp).toBeDefined();
      expect(event.actor.id).toBe("user-1");
      expect(event.action).toBe("auth.login");
      expect(event.outcome).toBe("success");
      expect(event.checksum).toBeDefined(); // tamperProof is true by default
    });

    it("should log event with details", () => {
      const event = logAuditEvent({
        actor: { type: "system", id: "system" },
        action: "scan.triggered",
        resource: { type: "image", id: "nginx:latest" },
        outcome: "success",
        details: { severity: "HIGH", vulnerabilities: 5 },
      });

      expect(event.details).toEqual({ severity: "HIGH", vulnerabilities: 5 });
    });

    it("should log event with context", () => {
      const event = logAuditEvent({
        actor: { type: "apikey", id: "key-1" },
        action: "data.export",
        resource: { type: "report", id: "report-1" },
        outcome: "success",
        context: { ipAddress: "192.168.1.1", userAgent: "curl/7.68.0" },
      });

      expect(event.context.ipAddress).toBe("192.168.1.1");
      expect(event.context.userAgent).toBe("curl/7.68.0");
    });

    it("should get event by ID", () => {
      const created = logAuditEvent({
        actor: { type: "user", id: "user-1" },
        action: "auth.logout",
        resource: { type: "session", id: "session-1" },
        outcome: "success",
      });

      const retrieved = getAuditEvent(created.id);
      expect(retrieved).toBeDefined();
      expect(retrieved?.id).toBe(created.id);
      expect(retrieved?.action).toBe("auth.logout");
    });

    it("should return null for non-existent event", () => {
      const event = getAuditEvent("non-existent-id");
      expect(event).toBeNull();
    });
  });

  describe("Event Search", () => {
    beforeEach(() => {
      initAuditDatabase(testDbPath);

      // Create test events
      logAuditEvent({
        actor: { type: "user", id: "user-1" },
        action: "auth.login",
        resource: { type: "session", id: "s1" },
        outcome: "success",
      });
      logAuditEvent({
        actor: { type: "user", id: "user-1" },
        action: "auth.login_failed",
        resource: { type: "session", id: "s2" },
        outcome: "failure",
      });
      logAuditEvent({
        actor: { type: "apikey", id: "key-1" },
        action: "scan.triggered",
        resource: { type: "image", id: "nginx:latest" },
        outcome: "success",
      });
      logAuditEvent({
        actor: { type: "system", id: "system" },
        action: "admin.settings_changed",
        resource: { type: "config", id: "retention" },
        outcome: "success",
      });
    });

    it("should search all events", () => {
      const events = searchAuditEvents({});
      expect(events.length).toBe(4);
    });

    it("should filter by actor ID", () => {
      const events = searchAuditEvents({ actorId: "user-1" });
      expect(events.length).toBe(2);
    });

    it("should filter by actor type", () => {
      const events = searchAuditEvents({ actorType: "apikey" });
      expect(events.length).toBe(1);
      expect(events[0].action).toBe("scan.triggered");
    });

    it("should filter by action", () => {
      const events = searchAuditEvents({ action: "auth.login" });
      expect(events.length).toBe(1);
    });

    it("should filter by action category", () => {
      const events = searchAuditEvents({ actionCategory: "authentication" });
      expect(events.length).toBe(2);
    });

    it("should filter by outcome", () => {
      const events = searchAuditEvents({ outcome: "failure" });
      expect(events.length).toBe(1);
      expect(events[0].action).toBe("auth.login_failed");
    });

    it("should filter by resource type", () => {
      const events = searchAuditEvents({ resourceType: "image" });
      expect(events.length).toBe(1);
    });

    it("should support pagination", () => {
      const page1 = searchAuditEvents({ limit: 2, offset: 0 });
      const page2 = searchAuditEvents({ limit: 2, offset: 2 });

      expect(page1.length).toBe(2);
      expect(page2.length).toBe(2);
    });

    it("should support text search", () => {
      const events = searchAuditEvents({ query: "nginx" });
      expect(events.length).toBe(1);
      expect(events[0].resource.id).toBe("nginx:latest");
    });
  });

  describe("Action Category", () => {
    it("should identify authentication actions", () => {
      expect(getActionCategory("auth.login")).toBe("authentication");
      expect(getActionCategory("auth.logout")).toBe("authentication");
    });

    it("should identify authorization actions", () => {
      expect(getActionCategory("authz.permission_denied")).toBe("authorization");
      expect(getActionCategory("authz.role_assigned")).toBe("authorization");
    });

    it("should identify scan actions", () => {
      expect(getActionCategory("scan.triggered")).toBe("scan");
      expect(getActionCategory("scan.completed")).toBe("scan");
    });

    it("should identify policy actions", () => {
      expect(getActionCategory("policy.created")).toBe("policy");
      expect(getActionCategory("policy.evaluated")).toBe("policy");
    });

    it("should identify admin actions", () => {
      expect(getActionCategory("admin.user_created")).toBe("admin");
      expect(getActionCategory("admin.settings_changed")).toBe("admin");
    });

    it("should identify data actions", () => {
      expect(getActionCategory("data.export")).toBe("data");
      expect(getActionCategory("data.download")).toBe("data");
    });
  });

  describe("Export", () => {
    beforeEach(() => {
      initAuditDatabase(testDbPath);

      logAuditEvent({
        actor: { type: "user", id: "user-1" },
        action: "auth.login",
        resource: { type: "session", id: "s1" },
        outcome: "success",
      });
      logAuditEvent({
        actor: { type: "user", id: "user-2" },
        action: "scan.triggered",
        resource: { type: "image", id: "nginx:latest" },
        outcome: "success",
      });
    });

    it("should export to JSON", () => {
      const result = exportAuditLogs({ format: "json" });

      expect(result.success).toBe(true);
      expect(result.count).toBe(2);
      expect(result.format).toBe("json");
      expect(result.data).toBeDefined();

      const parsed = JSON.parse(result.data!);
      expect(Array.isArray(parsed)).toBe(true);
      expect(parsed.length).toBe(2);
    });

    it("should export to CSV", () => {
      const result = exportAuditLogs({ format: "csv" });

      expect(result.success).toBe(true);
      expect(result.format).toBe("csv");
      expect(result.data).toContain("id,timestamp");
      expect(result.data).toContain("auth.login");
    });

    it("should export to NDJSON", () => {
      const result = exportAuditLogs({ format: "ndjson" });

      expect(result.success).toBe(true);
      expect(result.format).toBe("ndjson");

      const lines = result.data!.split("\n");
      expect(lines.length).toBe(2);
      expect(JSON.parse(lines[0]).action).toBeDefined();
    });

    it("should export with filters", () => {
      const result = exportAuditLogs({
        filters: { actorId: "user-1" },
      });

      expect(result.count).toBe(1);
    });

    it("should include checksum when requested", () => {
      const result = exportAuditLogs({
        format: "json",
        includeChecksum: true,
      });

      const parsed = JSON.parse(result.data!);
      expect(parsed[0].checksum).toBeDefined();
    });

    it("should exclude checksum by default", () => {
      const result = exportAuditLogs({
        format: "json",
        includeChecksum: false,
      });

      const parsed = JSON.parse(result.data!);
      expect(parsed[0].checksum).toBeUndefined();
    });

    it("should write to file when path provided", () => {
      const outputPath = path.join(os.tmpdir(), "audit-export-test.json");

      try {
        const result = exportAuditLogs({
          format: "json",
          outputPath,
        });

        expect(result.success).toBe(true);
        expect(result.path).toBe(outputPath);
        expect(fs.existsSync(outputPath)).toBe(true);
      } finally {
        if (fs.existsSync(outputPath)) {
          fs.unlinkSync(outputPath);
        }
      }
    });
  });

  describe("Tamper Detection", () => {
    beforeEach(() => {
      initAuditDatabase(testDbPath, { tamperProof: true });
    });

    it("should generate checksum for events", () => {
      const event = logAuditEvent({
        actor: { type: "user", id: "user-1" },
        action: "auth.login",
        resource: { type: "session", id: "s1" },
        outcome: "success",
      });

      expect(event.checksum).toBeDefined();
      expect(event.checksum!.length).toBe(64); // SHA-256 hex
    });

    it("should verify valid checksum", () => {
      const event = logAuditEvent({
        actor: { type: "user", id: "user-1" },
        action: "auth.login",
        resource: { type: "session", id: "s1" },
        outcome: "success",
      });

      expect(verifyEventChecksum(event)).toBe(true);
    });

    it("should detect tampered event", () => {
      const event = logAuditEvent({
        actor: { type: "user", id: "user-1" },
        action: "auth.login",
        resource: { type: "session", id: "s1" },
        outcome: "success",
      });

      // Tamper with the event
      const tampered: AuditEvent = {
        ...event,
        outcome: "failure", // Changed from success to failure
      };

      expect(verifyEventChecksum(tampered)).toBe(false);
    });

    it("should verify all events integrity", () => {
      logAuditEvent({
        actor: { type: "user", id: "user-1" },
        action: "auth.login",
        resource: { type: "session", id: "s1" },
        outcome: "success",
      });
      logAuditEvent({
        actor: { type: "user", id: "user-2" },
        action: "auth.logout",
        resource: { type: "session", id: "s2" },
        outcome: "success",
      });

      const result = verifyAuditIntegrity();
      expect(result.total).toBe(2);
      expect(result.verified).toBe(2);
      expect(result.tampered).toBe(0);
    });
  });

  describe("Real-time Streaming", () => {
    beforeEach(() => {
      initAuditDatabase(testDbPath, { realTimeStreaming: true });
    });

    it("should notify listeners of new events", () => {
      const receivedEvents: AuditEvent[] = [];
      const listener = (event: AuditEvent) => {
        receivedEvents.push(event);
      };

      addAuditEventListener(listener);

      logAuditEvent({
        actor: { type: "user", id: "user-1" },
        action: "auth.login",
        resource: { type: "session", id: "s1" },
        outcome: "success",
      });

      expect(receivedEvents.length).toBe(1);
      expect(receivedEvents[0].action).toBe("auth.login");

      removeAuditEventListener(listener);
    });

    it("should stop notifying after listener removed", () => {
      const receivedEvents: AuditEvent[] = [];
      const listener = (event: AuditEvent) => {
        receivedEvents.push(event);
      };

      addAuditEventListener(listener);
      removeAuditEventListener(listener);

      logAuditEvent({
        actor: { type: "user", id: "user-1" },
        action: "auth.login",
        resource: { type: "session", id: "s1" },
        outcome: "success",
      });

      expect(receivedEvents.length).toBe(0);
    });
  });

  describe("SIEM Integration", () => {
    beforeEach(() => {
      initAuditDatabase(testDbPath);
    });

    it("should configure SIEM", () => {
      configureSiem({
        endpoint: "https://siem.example.com/ingest",
        authToken: "token-123",
        enabled: true,
      });

      const config = getAuditConfig();
      expect(config.siem?.endpoint).toBe("https://siem.example.com/ingest");
      expect(config.siem?.enabled).toBe(true);
    });

    it("should get SIEM queue status", () => {
      const status = getSiemQueueStatus();
      expect(status.pending).toBe(0);
      expect(status.failed).toBe(0);
    });

    it("should queue events for SIEM when enabled", () => {
      configureSiem({
        endpoint: "https://siem.example.com/ingest",
        enabled: true,
      });

      logAuditEvent({
        actor: { type: "user", id: "user-1" },
        action: "auth.login",
        resource: { type: "session", id: "s1" },
        outcome: "success",
      });

      const status = getSiemQueueStatus();
      expect(status.pending).toBe(1);
    });
  });

  describe("Statistics", () => {
    beforeEach(() => {
      initAuditDatabase(testDbPath);

      // Create diverse events
      logAuditEvent({
        actor: { type: "user", id: "user-1" },
        action: "auth.login",
        resource: { type: "session", id: "s1" },
        outcome: "success",
      });
      logAuditEvent({
        actor: { type: "user", id: "user-2" },
        action: "auth.login_failed",
        resource: { type: "session", id: "s2" },
        outcome: "failure",
      });
      logAuditEvent({
        actor: { type: "apikey", id: "key-1" },
        action: "scan.triggered",
        resource: { type: "image", id: "nginx" },
        outcome: "success",
      });
      logAuditEvent({
        actor: { type: "system", id: "system" },
        action: "admin.settings_changed",
        resource: { type: "config", id: "retention" },
        outcome: "success",
      });
    });

    it("should get total event count", () => {
      const stats = getAuditStats();
      expect(stats.totalEvents).toBe(4);
    });

    it("should count by outcome", () => {
      const stats = getAuditStats();
      expect(stats.byOutcome.success).toBe(3);
      expect(stats.byOutcome.failure).toBe(1);
    });

    it("should count by category", () => {
      const stats = getAuditStats();
      expect(stats.byCategory.authentication).toBe(2);
      expect(stats.byCategory.scan).toBe(1);
      expect(stats.byCategory.admin).toBe(1);
    });

    it("should count by actor type", () => {
      const stats = getAuditStats();
      expect(stats.byActorType.user).toBe(2);
      expect(stats.byActorType.apikey).toBe(1);
      expect(stats.byActorType.system).toBe(1);
    });

    it("should report tamper status", () => {
      const stats = getAuditStats();
      expect(stats.tamperDetected).toBe(false);
      expect(stats.tamperedCount).toBe(0);
    });

    it("should have time-based counts", () => {
      const stats = getAuditStats();
      expect(stats.last24Hours).toBe(4);
      expect(stats.last7Days).toBe(4);
      expect(stats.last30Days).toBe(4);
    });
  });

  describe("Aggregation", () => {
    beforeEach(() => {
      initAuditDatabase(testDbPath);

      // Create events for aggregation
      logAuditEvent({
        actor: { type: "user", id: "user-1" },
        action: "auth.login",
        resource: { type: "session", id: "s1" },
        outcome: "success",
      });
      logAuditEvent({
        actor: { type: "user", id: "user-1" },
        action: "auth.login",
        resource: { type: "session", id: "s2" },
        outcome: "success",
      });
      logAuditEvent({
        actor: { type: "user", id: "user-2" },
        action: "auth.login",
        resource: { type: "session", id: "s3" },
        outcome: "failure",
      });
    });

    it("should aggregate by action", () => {
      const results = aggregateAuditEvents({ groupBy: "action" });
      expect(results.length).toBe(1);
      expect(results[0].key).toBe("auth.login");
      expect(results[0].count).toBe(3);
    });

    it("should aggregate by actor ID", () => {
      const results = aggregateAuditEvents({ groupBy: "actorId" });
      expect(results.length).toBe(2);
    });

    it("should aggregate by outcome", () => {
      const results = aggregateAuditEvents({ groupBy: "outcome" });
      const success = results.find((r) => r.key === "success");
      const failure = results.find((r) => r.key === "failure");
      expect(success?.count).toBe(2);
      expect(failure?.count).toBe(1);
    });

    it("should aggregate by day", () => {
      const results = aggregateAuditEvents({ groupBy: "day" });
      expect(results.length).toBe(1); // All same day
      expect(results[0].count).toBe(3);
    });
  });

  describe("Maintenance", () => {
    beforeEach(() => {
      initAuditDatabase(testDbPath, { retentionDays: 90 });
    });

    it("should cleanup old events", () => {
      // Create an event (will not be deleted as it's recent)
      logAuditEvent({
        actor: { type: "user", id: "user-1" },
        action: "auth.login",
        resource: { type: "session", id: "s1" },
        outcome: "success",
      });

      const deleted = cleanupExpiredAuditEvents();
      expect(deleted).toBe(0); // Recent events should not be deleted
    });

    it("should cleanup failed SIEM queue", () => {
      const cleaned = cleanupFailedSiemQueue();
      expect(cleaned).toBe(0); // No failed entries
    });
  });
});
