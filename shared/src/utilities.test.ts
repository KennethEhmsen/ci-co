import { describe, it, expect, beforeEach, vi } from "vitest";

// Cache tests
import { ScanCache, withCache } from "./cache.js";

describe("ScanCache", () => {
  let cache: ScanCache<string>;

  beforeEach(() => {
    cache = new ScanCache<string>(1000); // 1 second TTL for testing
  });

  describe("basic operations", () => {
    it("should store and retrieve values", () => {
      cache.set("key1", "value1");
      expect(cache.get("key1")).toBe("value1");
    });

    it("should return undefined for missing keys", () => {
      expect(cache.get("nonexistent")).toBeUndefined();
    });

    it("should check if key exists", () => {
      cache.set("key1", "value1");
      expect(cache.has("key1")).toBe(true);
      expect(cache.has("nonexistent")).toBe(false);
    });

    it("should delete entries", () => {
      cache.set("key1", "value1");
      expect(cache.delete("key1")).toBe(true);
      expect(cache.get("key1")).toBeUndefined();
    });

    it("should clear all entries", () => {
      cache.set("key1", "value1");
      cache.set("key2", "value2");
      cache.clear();
      expect(cache.size).toBe(0);
    });

    it("should report size", () => {
      expect(cache.size).toBe(0);
      cache.set("key1", "value1");
      expect(cache.size).toBe(1);
    });
  });

  describe("TTL expiration", () => {
    it("should expire entries after TTL", async () => {
      const shortCache = new ScanCache<string>(50); // 50ms TTL
      shortCache.set("key1", "value1");
      expect(shortCache.get("key1")).toBe("value1");

      await new Promise((r) => setTimeout(r, 60));
      expect(shortCache.get("key1")).toBeUndefined();
    });

    it("should allow custom TTL per entry", async () => {
      cache.set("key1", "value1", 50); // 50ms TTL
      expect(cache.get("key1")).toBe("value1");

      await new Promise((r) => setTimeout(r, 60));
      expect(cache.get("key1")).toBeUndefined();
    });

    it("should prune expired entries", async () => {
      const shortCache = new ScanCache<string>(50);
      shortCache.set("key1", "value1");
      shortCache.set("key2", "value2");

      await new Promise((r) => setTimeout(r, 60));
      const pruned = shortCache.prune();
      expect(pruned).toBe(2);
    });
  });

  describe("generateKey", () => {
    it("should generate cache key from params", () => {
      const key = ScanCache.generateKey("scan", "path", "HIGH");
      expect(key).toBe("scan:path:HIGH");
    });

    it("should filter undefined params", () => {
      const key = ScanCache.generateKey("scan", "path", undefined, "CRITICAL");
      expect(key).toBe("scan:path:CRITICAL");
    });
  });
});

describe("withCache", () => {
  it("should cache function results", async () => {
    const cache = new ScanCache<number>();
    const fn = vi.fn().mockResolvedValue(42);
    const cachedFn = withCache(cache, (x: number) => `key:${x}`)(fn);

    const result1 = await cachedFn(1);
    const result2 = await cachedFn(1);

    expect(result1).toBe(42);
    expect(result2).toBe(42);
    expect(fn).toHaveBeenCalledTimes(1);
  });
});

// Circuit Breaker tests
import { CircuitBreaker, CircuitOpenError } from "./circuit-breaker.js";

describe("CircuitBreaker", () => {
  let breaker: CircuitBreaker;

  beforeEach(() => {
    breaker = new CircuitBreaker("test", {
      failureThreshold: 3,
      recoveryTimeout: 100,
      successThreshold: 2,
    });
  });

  describe("state transitions", () => {
    it("should start in CLOSED state", () => {
      expect(breaker.getState()).toBe("CLOSED");
    });

    it("should open after failure threshold", () => {
      breaker.recordFailure();
      breaker.recordFailure();
      expect(breaker.getState()).toBe("CLOSED");
      breaker.recordFailure();
      expect(breaker.getState()).toBe("OPEN");
    });

    it("should transition to HALF_OPEN after recovery timeout", async () => {
      breaker.recordFailure();
      breaker.recordFailure();
      breaker.recordFailure();
      expect(breaker.getState()).toBe("OPEN");

      await new Promise((r) => setTimeout(r, 110));
      expect(breaker.getState()).toBe("HALF_OPEN");
    });

    it("should close after success threshold in HALF_OPEN", async () => {
      breaker.recordFailure();
      breaker.recordFailure();
      breaker.recordFailure();

      await new Promise((r) => setTimeout(r, 110));
      expect(breaker.getState()).toBe("HALF_OPEN");

      breaker.recordSuccess();
      breaker.recordSuccess();
      expect(breaker.getState()).toBe("CLOSED");
    });

    it("should reopen on failure in HALF_OPEN", async () => {
      breaker.recordFailure();
      breaker.recordFailure();
      breaker.recordFailure();

      await new Promise((r) => setTimeout(r, 110));
      expect(breaker.getState()).toBe("HALF_OPEN");

      breaker.recordFailure();
      expect(breaker.getState()).toBe("OPEN");
    });
  });

  describe("execute", () => {
    it("should execute function when closed", async () => {
      const result = await breaker.execute(async () => 42);
      expect(result).toBe(42);
    });

    it("should throw CircuitOpenError when open", async () => {
      breaker.recordFailure();
      breaker.recordFailure();
      breaker.recordFailure();

      await expect(breaker.execute(async () => 42)).rejects.toThrow(CircuitOpenError);
    });

    it("should record success on successful execution", async () => {
      await breaker.execute(async () => 42);
      expect(breaker.getStats().failureCount).toBe(0);
    });

    it("should record failure on failed execution", async () => {
      try {
        await breaker.execute(async () => {
          throw new Error("test");
        });
      } catch {
        // Expected
      }
      expect(breaker.getStats().failureCount).toBe(1);
    });
  });

  describe("reset", () => {
    it("should reset to closed state", () => {
      breaker.recordFailure();
      breaker.recordFailure();
      breaker.recordFailure();
      expect(breaker.getState()).toBe("OPEN");

      breaker.reset();
      expect(breaker.getState()).toBe("CLOSED");
      expect(breaker.getStats().failureCount).toBe(0);
    });
  });

  describe("isOpen", () => {
    it("should return true when open", () => {
      breaker.recordFailure();
      breaker.recordFailure();
      breaker.recordFailure();
      expect(breaker.isOpen()).toBe(true);
    });

    it("should return false when closed", () => {
      expect(breaker.isOpen()).toBe(false);
    });
  });

  describe("onStateChange callback", () => {
    it("should call callback on state change", () => {
      const callback = vi.fn();
      const breakerWithCallback = new CircuitBreaker("test", {
        failureThreshold: 1,
        onStateChange: callback,
      });

      breakerWithCallback.recordFailure();
      expect(callback).toHaveBeenCalledWith("CLOSED", "OPEN", "test");
    });
  });
});

// Rate Limiter tests
import { RateLimiter, QueuedRateLimiter } from "./rate-limiter.js";

describe("RateLimiter", () => {
  describe("tryAcquire", () => {
    it("should allow requests within limit", () => {
      const limiter = new RateLimiter({
        maxTokens: 3,
        refillRate: 1,
        refillInterval: 1000,
      });

      expect(limiter.tryAcquire()).toBe(true);
      expect(limiter.tryAcquire()).toBe(true);
      expect(limiter.tryAcquire()).toBe(true);
      expect(limiter.tryAcquire()).toBe(false);
    });

    it("should refill tokens over time", async () => {
      const limiter = new RateLimiter({
        maxTokens: 1,
        refillRate: 1,
        refillInterval: 50,
      });

      expect(limiter.tryAcquire()).toBe(true);
      expect(limiter.tryAcquire()).toBe(false);

      await new Promise((r) => setTimeout(r, 60));
      expect(limiter.tryAcquire()).toBe(true);
    });
  });

  describe("getAvailableTokens", () => {
    it("should return available tokens", () => {
      const limiter = new RateLimiter({
        maxTokens: 5,
        refillRate: 1,
        refillInterval: 1000,
      });

      expect(limiter.getAvailableTokens()).toBe(5);
      limiter.tryAcquire();
      expect(limiter.getAvailableTokens()).toBe(4);
    });
  });

  describe("getWaitTime", () => {
    it("should return 0 when tokens available", () => {
      const limiter = new RateLimiter({
        maxTokens: 5,
        refillRate: 1,
        refillInterval: 1000,
      });

      expect(limiter.getWaitTime()).toBe(0);
    });

    it("should return wait time when no tokens", () => {
      const limiter = new RateLimiter({
        maxTokens: 1,
        refillRate: 1,
        refillInterval: 1000,
      });

      limiter.tryAcquire();
      const waitTime = limiter.getWaitTime();
      expect(waitTime).toBeGreaterThan(0);
      expect(waitTime).toBeLessThanOrEqual(1000);
    });
  });

  describe("acquire", () => {
    it("should wait for token when none available", async () => {
      const limiter = new RateLimiter({
        maxTokens: 1,
        refillRate: 1,
        refillInterval: 50,
      });

      limiter.tryAcquire();
      const start = Date.now();
      await limiter.acquire();
      const elapsed = Date.now() - start;
      expect(elapsed).toBeGreaterThanOrEqual(40);
    });
  });
});

describe("QueuedRateLimiter", () => {
  it("should queue requests", async () => {
    const limiter = new QueuedRateLimiter({
      maxTokens: 1,
      refillRate: 1,
      refillInterval: 50,
    });

    expect(limiter.getQueueLength()).toBe(0);

    const p1 = limiter.enqueue();
    const p2 = limiter.enqueue();

    // First should complete immediately
    await p1;

    // Second should be in queue initially
    await p2;
  });
});

// Policy tests
import {
  evaluatePolicy,
  getPolicy,
  strictPolicy,
  standardPolicy,
  permissivePolicy,
} from "./policy.js";

describe("Policy", () => {
  describe("evaluatePolicy", () => {
    it("should pass when no violations", () => {
      const result = evaluatePolicy(permissivePolicy, {
        vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
      });
      expect(result.passed).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it("should fail on critical vulnerability threshold", () => {
      const result = evaluatePolicy(strictPolicy, {
        vulnerabilities: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 },
      });
      expect(result.passed).toBe(false);
      expect(result.violations.some((v) => v.reason.includes("Critical"))).toBe(true);
    });

    it("should fail on high vulnerability threshold", () => {
      const result = evaluatePolicy(strictPolicy, {
        vulnerabilities: { critical: 0, high: 10, medium: 0, low: 0, unknown: 0 },
      });
      expect(result.passed).toBe(false);
    });

    it("should fail on secrets found", () => {
      const result = evaluatePolicy(strictPolicy, {
        secretsFound: true,
      });
      expect(result.passed).toBe(false);
      expect(result.violations.some((v) => v.reason.includes("Secrets"))).toBe(true);
    });

    it("should fail on blocked licenses", () => {
      const policy = {
        name: "test",
        version: "1.0",
        mode: "all" as const,
        rules: [
          {
            name: "license-check",
            blockedLicenses: ["GPL-3.0"],
          },
        ],
      };
      const result = evaluatePolicy(policy, {
        licenses: ["MIT", "GPL-3.0"],
      });
      expect(result.passed).toBe(false);
      expect(result.violations.some((v) => v.reason.includes("Blocked licenses"))).toBe(true);
    });

    it("should fail on quality gate", () => {
      const result = evaluatePolicy(strictPolicy, {
        qualityGatePassed: false,
      });
      expect(result.passed).toBe(false);
    });

    it("should fail on code coverage", () => {
      const policy = {
        name: "coverage-test",
        version: "1.0",
        mode: "all" as const,
        rules: [{ name: "coverage", minCodeCoverage: 80 }],
      };
      const result = evaluatePolicy(policy, {
        codeCoverage: 50,
      });
      expect(result.passed).toBe(false);
      expect(result.violations.some((v) => v.reason.includes("coverage"))).toBe(true);
    });

    it("should handle 'any' mode", () => {
      const policy = {
        name: "any-test",
        version: "1.0",
        mode: "any" as const,
        rules: [
          { name: "rule1", maxVulnerabilities: { critical: 0 } },
          { name: "rule2", maxVulnerabilities: { critical: 10 } },
        ],
      };
      const result = evaluatePolicy(policy, {
        vulnerabilities: { critical: 5, high: 0, medium: 0, low: 0, unknown: 0 },
      });
      // Should pass because rule2 passes (any mode)
      expect(result.passed).toBe(true);
    });
  });

  describe("getPolicy", () => {
    it("should return strict policy", () => {
      expect(getPolicy("strict")).toBe(strictPolicy);
    });

    it("should return standard policy", () => {
      expect(getPolicy("standard")).toBe(standardPolicy);
    });

    it("should return permissive policy", () => {
      expect(getPolicy("permissive")).toBe(permissivePolicy);
    });

    it("should return undefined for unknown policy", () => {
      expect(getPolicy("unknown")).toBeUndefined();
    });

    it("should be case insensitive", () => {
      expect(getPolicy("STRICT")).toBe(strictPolicy);
    });
  });
});

// Audit tests
import {
  auditLogger,
  auditOperation,
  auditSecurityEvent,
  getSecurityEvents,
  getFailedOperations,
} from "./audit.js";

describe("Audit", () => {
  beforeEach(() => {
    auditLogger.clear();
  });

  describe("auditLogger", () => {
    it("should log entries", () => {
      auditLogger.log({
        level: "INFO",
        operation: "test",
        service: "test-service",
        status: "completed",
      });
      expect(auditLogger.getEntries()).toHaveLength(1);
    });

    it("should filter by level", () => {
      auditLogger.log({
        level: "INFO",
        operation: "test1",
        service: "test",
        status: "completed",
      });
      auditLogger.log({
        level: "ERROR",
        operation: "test2",
        service: "test",
        status: "failed",
      });

      const errors = auditLogger.getEntries({ level: "ERROR" });
      expect(errors).toHaveLength(1);
      expect(errors[0].operation).toBe("test2");
    });

    it("should limit entries", () => {
      for (let i = 0; i < 5; i++) {
        auditLogger.log({
          level: "INFO",
          operation: `test${i}`,
          service: "test",
          status: "completed",
        });
      }

      const entries = auditLogger.getEntries({ limit: 2 });
      expect(entries).toHaveLength(2);
    });

    it("should clear entries", () => {
      auditLogger.log({
        level: "INFO",
        operation: "test",
        service: "test",
        status: "completed",
      });
      auditLogger.clear();
      expect(auditLogger.getEntries()).toHaveLength(0);
    });
  });

  describe("auditOperation", () => {
    it("should track operation lifecycle", () => {
      const op = auditOperation("scan", "trivy", "/path/to/scan");
      op.start();
      op.complete({ findings: 5 });

      const entries = auditLogger.getEntries();
      expect(entries).toHaveLength(2);
      expect(entries[0].status).toBe("started");
      expect(entries[1].status).toBe("completed");
    });

    it("should track failed operations", () => {
      const op = auditOperation("scan", "trivy");
      op.start();
      op.fail("Connection timeout");

      const entries = auditLogger.getEntries();
      expect(entries[1].status).toBe("failed");
      expect(entries[1].error).toBe("Connection timeout");
    });
  });

  describe("auditSecurityEvent", () => {
    it("should log security events", () => {
      auditSecurityEvent("policy_violation", "scanner", {
        reason: "Critical vulnerability found",
        target: "image:latest",
      });

      const events = getSecurityEvents();
      expect(events).toHaveLength(1);
      expect(events[0].level).toBe("SECURITY");
    });
  });

  describe("getFailedOperations", () => {
    it("should return only failed operations", () => {
      auditLogger.log({
        level: "INFO",
        operation: "success",
        service: "test",
        status: "completed",
      });
      auditLogger.log({
        level: "ERROR",
        operation: "failure",
        service: "test",
        status: "failed",
      });

      const failed = getFailedOperations();
      expect(failed).toHaveLength(1);
      expect(failed[0].operation).toBe("failure");
    });
  });
});

// Config Validation tests
import { validateConfig } from "./config-validation.js";

describe("ConfigValidation", () => {
  describe("validateConfig", () => {
    it("should validate correct config", () => {
      const result = validateConfig({
        gitea: { url: "http://localhost:3000", user: "admin", password: "admin" },
        drone: { url: "http://localhost:8085", token: "token" },
        sonarqube: { url: "http://localhost:9000", user: "admin", password: "admin" },
        dependencyTrack: { url: "http://localhost:8081", apiKey: "key" },
        trivy: { url: "http://localhost:4954" },
        registry: { url: "http://localhost:5000" },
      });
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it("should detect invalid URLs", () => {
      const result = validateConfig({
        gitea: { url: "not-a-url", user: "admin", password: "admin" },
        drone: { url: "http://localhost:8085", token: "token" },
        sonarqube: { url: "http://localhost:9000", user: "admin", password: "admin" },
        dependencyTrack: { url: "http://localhost:8081", apiKey: "key" },
        trivy: { url: "http://localhost:4954" },
        registry: { url: "http://localhost:5000" },
      });
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("Invalid Gitea URL"))).toBe(true);
    });

    it("should warn about missing credentials", () => {
      const result = validateConfig({
        gitea: { url: "http://localhost:3000", user: "", password: "" },
        drone: { url: "http://localhost:8085", token: "" },
        sonarqube: { url: "http://localhost:9000", user: "", password: "" },
        dependencyTrack: { url: "http://localhost:8081", apiKey: "" },
        trivy: { url: "http://localhost:4954" },
        registry: { url: "http://localhost:5000" },
      });
      expect(result.warnings.length).toBeGreaterThan(0);
    });
  });
});
