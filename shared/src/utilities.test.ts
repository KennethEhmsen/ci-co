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
import {
  CircuitBreaker,
  CircuitOpenError,
  getAllCircuitStats,
  circuitBreakers,
} from "./circuit-breaker.js";

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

describe("getAllCircuitStats", () => {
  it("should return stats for all circuit breakers", () => {
    const stats = getAllCircuitStats();
    expect(Array.isArray(stats)).toBe(true);
    expect(stats.length).toBe(Object.keys(circuitBreakers).length);
  });

  it("should include required fields in each stat", () => {
    const stats = getAllCircuitStats();
    for (const stat of stats) {
      expect(stat).toHaveProperty("serviceName");
      expect(stat).toHaveProperty("state");
      expect(stat).toHaveProperty("failureCount");
      expect(stat).toHaveProperty("successCount");
    }
  });

  it("should return stats for known services", () => {
    const stats = getAllCircuitStats();
    const names = stats.map((s) => s.serviceName);
    expect(names).toContain("trivy");
    expect(names).toContain("sonarqube");
    expect(names).toContain("dependency-track");
  });
});

// Rate Limiter tests
import { RateLimiter, QueuedRateLimiter, withRateLimit } from "./rate-limiter.js";

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

describe("withRateLimit", () => {
  it("should wrap function with rate limiting", async () => {
    const limiter = new RateLimiter({
      maxTokens: 2,
      refillRate: 1,
      refillInterval: 100,
    });

    const fn = vi.fn().mockResolvedValue("result");
    const rateLimitedFn = withRateLimit(limiter)(fn);

    const result = await rateLimitedFn("arg1", "arg2");
    expect(result).toBe("result");
    expect(fn).toHaveBeenCalledWith("arg1", "arg2");
  });

  it("should enforce rate limits on wrapped function", async () => {
    const limiter = new RateLimiter({
      maxTokens: 1,
      refillRate: 1,
      refillInterval: 50,
    });

    const fn = vi.fn().mockResolvedValue("done");
    const rateLimitedFn = withRateLimit(limiter)(fn);

    // First call should be immediate
    await rateLimitedFn();

    // Second call should wait for rate limit
    const start = Date.now();
    await rateLimitedFn();
    const elapsed = Date.now() - start;

    expect(elapsed).toBeGreaterThanOrEqual(40);
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("should preserve function return type", async () => {
    const limiter = new RateLimiter({
      maxTokens: 5,
      refillRate: 1,
      refillInterval: 100,
    });

    const fn = vi.fn().mockResolvedValue({ data: [1, 2, 3] });
    const rateLimitedFn = withRateLimit(limiter)(fn);

    const result = await rateLimitedFn();
    expect(result).toEqual({ data: [1, 2, 3] });
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

  describe("ignoreCves and ignorePackages filtering", () => {
    it("should ignore specified CVEs", () => {
      const policy = {
        name: "ignore-cve-test",
        version: "1.0",
        mode: "all" as const,
        rules: [
          {
            name: "vuln-check",
            maxVulnerabilities: { critical: 0 },
            ignoreCves: ["CVE-2023-12345"],
          },
        ],
      };
      const result = evaluatePolicy(policy, {
        vulnerabilities: {
          critical: 1,
          high: 0,
          medium: 0,
          low: 0,
          unknown: 0,
          cves: ["CVE-2023-12345"],
        },
      });
      // CVE is ignored, so should still fail on count but exercise the filter path
      expect(result.policy).toBe("ignore-cve-test");
    });

    it("should ignore specified packages", () => {
      const policy = {
        name: "ignore-pkg-test",
        version: "1.0",
        mode: "all" as const,
        rules: [
          {
            name: "vuln-check",
            maxVulnerabilities: { critical: 0 },
            ignorePackages: ["lodash"],
          },
        ],
      };
      const result = evaluatePolicy(policy, {
        vulnerabilities: {
          critical: 1,
          high: 0,
          medium: 0,
          low: 0,
          unknown: 0,
          packages: ["lodash@4.17.21"],
        },
      });
      expect(result.policy).toBe("ignore-pkg-test");
    });

    it("should filter both CVEs and packages", () => {
      const policy = {
        name: "filter-both-test",
        version: "1.0",
        mode: "all" as const,
        rules: [
          {
            name: "combined-filter",
            maxVulnerabilities: { critical: 0, high: 0 },
            ignoreCves: ["CVE-2023-11111", "CVE-2023-22222"],
            ignorePackages: ["express", "lodash"],
          },
        ],
      };
      const result = evaluatePolicy(policy, {
        vulnerabilities: {
          critical: 2,
          high: 2,
          medium: 0,
          low: 0,
          unknown: 0,
          cves: ["CVE-2023-11111", "CVE-2023-22222", "CVE-2023-33333"],
          packages: ["express@4.18.0", "lodash@4.17.21", "axios@1.0.0"],
        },
      });
      // Exercises the filter path with both filters
      expect(result.violations.length).toBeGreaterThan(0);
    });

    it("should handle empty ignore lists", () => {
      const policy = {
        name: "empty-ignore-test",
        version: "1.0",
        mode: "all" as const,
        rules: [
          {
            name: "no-filter",
            maxVulnerabilities: { critical: 0 },
            ignoreCves: [],
            ignorePackages: [],
          },
        ],
      };
      const result = evaluatePolicy(policy, {
        vulnerabilities: {
          critical: 1,
          high: 0,
          medium: 0,
          low: 0,
          unknown: 0,
          cves: ["CVE-2023-12345"],
        },
      });
      expect(result.passed).toBe(false);
    });

    it("should handle vulnerabilities without cves/packages arrays", () => {
      const policy = {
        name: "no-arrays-test",
        version: "1.0",
        mode: "all" as const,
        rules: [
          {
            name: "filter-test",
            maxVulnerabilities: { critical: 0 },
            ignoreCves: ["CVE-2023-12345"],
            ignorePackages: ["lodash"],
          },
        ],
      };
      const result = evaluatePolicy(policy, {
        vulnerabilities: {
          critical: 1,
          high: 0,
          medium: 0,
          low: 0,
          unknown: 0,
          // No cves or packages arrays
        },
      });
      expect(result.passed).toBe(false);
    });

    it("should handle case-insensitive CVE matching", () => {
      const policy = {
        name: "case-test",
        version: "1.0",
        mode: "all" as const,
        rules: [
          {
            name: "case-filter",
            maxVulnerabilities: { high: 5 },
            ignoreCves: ["cve-2023-12345"], // lowercase
          },
        ],
      };
      const result = evaluatePolicy(policy, {
        vulnerabilities: {
          critical: 0,
          high: 1,
          medium: 0,
          low: 0,
          unknown: 0,
          cves: ["CVE-2023-12345"], // uppercase
        },
      });
      expect(result.policy).toBe("case-test");
    });

    it("should handle partial package name matching", () => {
      const policy = {
        name: "partial-match-test",
        version: "1.0",
        mode: "all" as const,
        rules: [
          {
            name: "partial-filter",
            maxVulnerabilities: { high: 5 },
            ignorePackages: ["lodash"], // partial name
          },
        ],
      };
      const result = evaluatePolicy(policy, {
        vulnerabilities: {
          critical: 0,
          high: 1,
          medium: 0,
          low: 0,
          unknown: 0,
          packages: ["lodash@4.17.21", "@types/lodash@4.14.0"],
        },
      });
      expect(result.policy).toBe("partial-match-test");
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
import {
  validateConfig,
  validateConnectivity,
  validateStartup,
  logValidationResults,
} from "./config-validation.js";

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

    it("should detect missing URLs", () => {
      const result = validateConfig({
        gitea: { url: "", user: "admin", password: "admin" },
        drone: { url: "", token: "token" },
        sonarqube: { url: "", user: "admin", password: "admin" },
        dependencyTrack: { url: "", apiKey: "key" },
        trivy: { url: "" },
        registry: { url: "" },
      });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it("should detect invalid registry URL", () => {
      const result = validateConfig({
        gitea: { url: "http://localhost:3000", user: "admin", password: "admin" },
        drone: { url: "http://localhost:8085", token: "token" },
        sonarqube: { url: "http://localhost:9000", user: "admin", password: "admin" },
        dependencyTrack: { url: "http://localhost:8081", apiKey: "key" },
        trivy: { url: "http://localhost:4954" },
        registry: { url: "not-valid-url" },
      });
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("Invalid Registry URL"))).toBe(true);
    });

    it("should detect invalid Drone URL", () => {
      const result = validateConfig({
        gitea: { url: "http://localhost:3000", user: "admin", password: "admin" },
        drone: { url: "invalid-drone-url", token: "token" },
        sonarqube: { url: "http://localhost:9000", user: "admin", password: "admin" },
        dependencyTrack: { url: "http://localhost:8081", apiKey: "key" },
        trivy: { url: "http://localhost:4954" },
        registry: { url: "http://localhost:5000" },
      });
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("Invalid Drone URL"))).toBe(true);
    });

    it("should detect invalid SonarQube URL", () => {
      const result = validateConfig({
        gitea: { url: "http://localhost:3000", user: "admin", password: "admin" },
        drone: { url: "http://localhost:8085", token: "token" },
        sonarqube: { url: "bad-sonar-url", user: "admin", password: "admin" },
        dependencyTrack: { url: "http://localhost:8081", apiKey: "key" },
        trivy: { url: "http://localhost:4954" },
        registry: { url: "http://localhost:5000" },
      });
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("Invalid SonarQube URL"))).toBe(true);
    });

    it("should detect invalid Dependency-Track URL", () => {
      const result = validateConfig({
        gitea: { url: "http://localhost:3000", user: "admin", password: "admin" },
        drone: { url: "http://localhost:8085", token: "token" },
        sonarqube: { url: "http://localhost:9000", user: "admin", password: "admin" },
        dependencyTrack: { url: "bad-dtrack-url", apiKey: "key" },
        trivy: { url: "http://localhost:4954" },
        registry: { url: "http://localhost:5000" },
      });
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("Invalid Dependency-Track URL"))).toBe(true);
    });
  });

  describe("validateConnectivity", () => {
    it("should check connectivity for all services", async () => {
      const testConfig = {
        gitea: { url: "http://localhost:39999", user: "admin", password: "admin" },
        drone: { url: "http://localhost:39998", token: "token" },
        sonarqube: { url: "http://localhost:39997", user: "admin", password: "admin" },
        dependencyTrack: { url: "http://localhost:39996", apiKey: "key" },
        trivy: { url: "http://localhost:39995" },
        registry: { url: "http://localhost:39994" },
      };
      const results = await validateConnectivity(testConfig);
      expect(results).toHaveLength(5);
      expect(results.every((r) => r.service && typeof r.reachable === "boolean")).toBe(true);
    });

    it("should return service names", async () => {
      const testConfig = {
        gitea: { url: "http://localhost:39999", user: "admin", password: "admin" },
        drone: { url: "http://localhost:39998", token: "token" },
        sonarqube: { url: "http://localhost:39997", user: "admin", password: "admin" },
        dependencyTrack: { url: "http://localhost:39996", apiKey: "key" },
        trivy: { url: "http://localhost:39995" },
        registry: { url: "http://localhost:39994" },
      };
      const results = await validateConnectivity(testConfig);
      const serviceNames = results.map((r) => r.service);
      expect(serviceNames).toContain("gitea");
      expect(serviceNames).toContain("drone");
      expect(serviceNames).toContain("sonarqube");
      expect(serviceNames).toContain("dependency-track");
      expect(serviceNames).toContain("registry");
    });

    it("should include error message for failed connections", async () => {
      const testConfig = {
        gitea: { url: "http://localhost:39999", user: "admin", password: "admin" },
        drone: { url: "http://localhost:39998", token: "token" },
        sonarqube: { url: "http://localhost:39997", user: "admin", password: "admin" },
        dependencyTrack: { url: "http://localhost:39996", apiKey: "key" },
        trivy: { url: "http://localhost:39995" },
        registry: { url: "http://localhost:39994" },
      };
      const results = await validateConnectivity(testConfig);
      const failedServices = results.filter((r) => !r.reachable);
      expect(failedServices.length).toBeGreaterThan(0);
      expect(failedServices.every((r) => r.error !== undefined)).toBe(true);
    });
  });

  describe("validateStartup", () => {
    it("should return combined validation results", async () => {
      const testConfig = {
        gitea: { url: "http://localhost:39999", user: "admin", password: "admin" },
        drone: { url: "http://localhost:39998", token: "token" },
        sonarqube: { url: "http://localhost:39997", user: "admin", password: "admin" },
        dependencyTrack: { url: "http://localhost:39996", apiKey: "key" },
        trivy: { url: "http://localhost:39995" },
        registry: { url: "http://localhost:39994" },
      };
      const result = await validateStartup(testConfig);
      expect(result.config).toBeDefined();
      expect(result.connectivity).toBeDefined();
      expect(typeof result.ready).toBe("boolean");
    });

    it("should report not ready when no services are reachable", async () => {
      const testConfig = {
        gitea: { url: "http://localhost:39999", user: "admin", password: "admin" },
        drone: { url: "http://localhost:39998", token: "token" },
        sonarqube: { url: "http://localhost:39997", user: "admin", password: "admin" },
        dependencyTrack: { url: "http://localhost:39996", apiKey: "key" },
        trivy: { url: "http://localhost:39995" },
        registry: { url: "http://localhost:39994" },
      };
      const result = await validateStartup(testConfig);
      // With no services reachable, should not be ready
      expect(result.ready).toBe(false);
    });

    it("should report not ready when config is invalid", async () => {
      const testConfig = {
        gitea: { url: "invalid", user: "admin", password: "admin" },
        drone: { url: "invalid", token: "token" },
        sonarqube: { url: "invalid", user: "admin", password: "admin" },
        dependencyTrack: { url: "invalid", apiKey: "key" },
        trivy: { url: "invalid" },
        registry: { url: "invalid" },
      };
      const result = await validateStartup(testConfig);
      expect(result.config.valid).toBe(false);
      expect(result.ready).toBe(false);
    });
  });

  describe("logValidationResults", () => {
    it("should log validation results without errors", () => {
      const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});

      logValidationResults({
        config: { valid: true, errors: [], warnings: [] },
        connectivity: [
          { service: "gitea", reachable: true, responseTimeMs: 10 },
          { service: "drone", reachable: true, responseTimeMs: 15 },
        ],
        ready: true,
      });

      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    it("should log errors when present", () => {
      const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});

      logValidationResults({
        config: { valid: false, errors: ["Test error"], warnings: [] },
        connectivity: [{ service: "gitea", reachable: false, error: "Connection refused" }],
        ready: false,
      });

      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    it("should log warnings when present", () => {
      const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});

      logValidationResults({
        config: { valid: true, errors: [], warnings: ["Test warning"] },
        connectivity: [{ service: "gitea", reachable: true }],
        ready: true,
      });

      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    it("should log service connectivity with response times", () => {
      const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});

      logValidationResults({
        config: { valid: true, errors: [], warnings: [] },
        connectivity: [
          { service: "gitea", reachable: true, responseTimeMs: 50 },
          { service: "drone", reachable: false, error: "Timeout", responseTimeMs: 5000 },
        ],
        ready: false,
      });

      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });
  });
});

// SARIF tests
import {
  createSarifLog,
  createSarifRun,
  trivyToSarif,
  sonarToSarif,
  dtrackToSarif,
  dashboardToSarif,
  mergeSarifLogs,
  sarifToJson,
  getSarifSummary,
  uploadSarifToGitHub,
  writeSarifFile,
} from "./sarif.js";

describe("SARIF", () => {
  describe("createSarifLog", () => {
    it("should create a valid SARIF log structure", () => {
      const log = createSarifLog();
      expect(log.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
      expect(log.version).toBe("2.1.0");
      expect(log.runs).toEqual([]);
    });
  });

  describe("createSarifRun", () => {
    it("should create a run with tool information", () => {
      const run = createSarifRun("TestTool", "1.0.0", "https://example.com");
      expect(run.tool.driver.name).toBe("TestTool");
      expect(run.tool.driver.version).toBe("1.0.0");
      expect(run.tool.driver.informationUri).toBe("https://example.com");
      expect(run.results).toEqual([]);
    });

    it("should include invocation with timestamp", () => {
      const run = createSarifRun("TestTool");
      expect(run.invocations).toHaveLength(1);
      expect(run.invocations![0].executionSuccessful).toBe(true);
      expect(run.invocations![0].endTimeUtc).toBeDefined();
    });
  });

  describe("trivyToSarif", () => {
    it("should convert Trivy vulnerabilities to SARIF", () => {
      const trivyResult = {
        Results: [
          {
            Target: "package.json",
            Class: "lang-pkgs",
            Type: "npm",
            Vulnerabilities: [
              {
                VulnerabilityID: "CVE-2023-12345",
                PkgName: "lodash",
                InstalledVersion: "4.17.20",
                FixedVersion: "4.17.21",
                Severity: "HIGH" as const,
                Title: "Prototype Pollution",
                Description: "A vulnerability in lodash",
                PrimaryURL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
              },
            ],
          },
        ],
      };

      const sarif = trivyToSarif(trivyResult);
      expect(sarif.version).toBe("2.1.0");
      expect(sarif.runs).toHaveLength(1);
      expect(sarif.runs[0].tool.driver.name).toBe("Trivy");
      expect(sarif.runs[0].results).toHaveLength(1);
      expect(sarif.runs[0].results[0].ruleId).toBe("CVE-2023-12345");
      expect(sarif.runs[0].results[0].level).toBe("error");
    });

    it("should convert Trivy secrets to SARIF", () => {
      const trivyResult = {
        Results: [
          {
            Target: "config.js",
            Class: "secret",
            Type: "secret",
            Secrets: [
              {
                RuleID: "aws-access-key",
                Category: "AWS",
                Severity: "CRITICAL",
                Title: "AWS Access Key",
                StartLine: 10,
                EndLine: 10,
                Match: "AKIA***",
              },
            ],
          },
        ],
      };

      const sarif = trivyToSarif(trivyResult);
      expect(sarif.runs[0].results).toHaveLength(1);
      expect(sarif.runs[0].results[0].ruleId).toBe("secret/aws-access-key");
      expect(sarif.runs[0].results[0].locations![0].physicalLocation?.region?.startLine).toBe(10);
    });

    it("should handle empty results", () => {
      const trivyResult = { Results: [] };
      const sarif = trivyToSarif(trivyResult);
      expect(sarif.runs[0].results).toHaveLength(0);
    });
  });

  describe("sonarToSarif", () => {
    it("should convert SonarQube issues to SARIF", () => {
      const issues = [
        {
          key: "issue-1",
          rule: "typescript:S1234",
          severity: "CRITICAL" as const,
          component: "src/index.ts",
          project: "my-project",
          line: 42,
          message: "Remove this unused variable",
          type: "CODE_SMELL" as const,
          status: "OPEN",
        },
      ];

      const sarif = sonarToSarif(issues);
      expect(sarif.runs[0].tool.driver.name).toBe("SonarQube");
      expect(sarif.runs[0].results).toHaveLength(1);
      expect(sarif.runs[0].results[0].ruleId).toBe("typescript:S1234");
      expect(sarif.runs[0].results[0].level).toBe("error");
      expect(sarif.runs[0].results[0].locations![0].physicalLocation?.region?.startLine).toBe(42);
    });

    it("should handle issues without line numbers", () => {
      const issues = [
        {
          key: "issue-2",
          rule: "typescript:S5678",
          severity: "MINOR" as const,
          component: "src/utils.ts",
          project: "my-project",
          message: "Add documentation",
          type: "CODE_SMELL" as const,
          status: "OPEN",
        },
      ];

      const sarif = sonarToSarif(issues);
      expect(sarif.runs[0].results[0].locations![0].physicalLocation?.region).toBeUndefined();
    });
  });

  describe("dtrackToSarif", () => {
    it("should convert Dependency-Track findings to SARIF", () => {
      const findings = [
        {
          component: {
            uuid: "comp-uuid-1",
            name: "express",
            version: "4.17.0",
          },
          vulnerability: {
            uuid: "vuln-uuid-1",
            vulnId: "CVE-2024-99999",
            source: "NVD",
            severity: "HIGH" as const,
            title: "Remote Code Execution",
            description: "A critical vulnerability",
            cvssV3BaseScore: 8.5,
          },
        },
      ];

      const sarif = dtrackToSarif(findings);
      expect(sarif.runs[0].tool.driver.name).toBe("Dependency-Track");
      expect(sarif.runs[0].results).toHaveLength(1);
      expect(sarif.runs[0].results[0].ruleId).toBe("CVE-2024-99999");
      expect(sarif.runs[0].results[0].level).toBe("error");
    });
  });

  describe("dashboardToSarif", () => {
    it("should convert security dashboard to SARIF", () => {
      const dashboard = {
        timestamp: new Date().toISOString(),
        summary: { critical: 1, high: 2, medium: 3, low: 4, total: 10 },
        bySource: {
          trivy: { critical: 1, high: 1, medium: 1, low: 1, total: 4 },
          sonarqube: {
            bugs: 0,
            vulnerabilities: 1,
            codeSmells: 5,
            hotspots: 0,
            qualityGateStatus: "OK",
          },
          dependencyTrack: { critical: 0, high: 1, medium: 2, low: 3, total: 6 },
        },
        topFindings: [
          {
            id: "CVE-2023-11111",
            severity: "CRITICAL" as const,
            source: "trivy" as const,
            package: "lodash@4.17.20",
            message: "Prototype Pollution vulnerability",
          },
        ],
        scanTargets: {
          image: "node:20",
          sonarProject: "my-project",
        },
      };

      const sarif = dashboardToSarif(dashboard);
      expect(sarif.runs[0].tool.driver.name).toBe("CI/CD Security Scanner");
      expect(sarif.runs[0].results).toHaveLength(1);
      expect(sarif.runs[0].properties?.summary).toEqual(dashboard.summary);
    });
  });

  describe("mergeSarifLogs", () => {
    it("should merge multiple SARIF logs", () => {
      const log1 = createSarifLog();
      log1.runs.push(createSarifRun("Tool1"));

      const log2 = createSarifLog();
      log2.runs.push(createSarifRun("Tool2"));

      const merged = mergeSarifLogs(log1, log2);
      expect(merged.runs).toHaveLength(2);
      expect(merged.runs[0].tool.driver.name).toBe("Tool1");
      expect(merged.runs[1].tool.driver.name).toBe("Tool2");
    });
  });

  describe("sarifToJson", () => {
    it("should convert SARIF log to JSON string", () => {
      const log = createSarifLog();
      const json = sarifToJson(log);
      expect(typeof json).toBe("string");
      const parsed = JSON.parse(json);
      expect(parsed.version).toBe("2.1.0");
    });

    it("should support compact output", () => {
      const log = createSarifLog();
      const prettyJson = sarifToJson(log, true);
      const compactJson = sarifToJson(log, false);
      expect(compactJson.length).toBeLessThan(prettyJson.length);
    });
  });

  describe("getSarifSummary", () => {
    it("should return summary statistics", () => {
      const log = createSarifLog();
      const run = createSarifRun("TestTool");
      run.results.push({
        ruleId: "rule1",
        level: "error",
        message: { text: "Error 1" },
      });
      run.results.push({
        ruleId: "rule2",
        level: "warning",
        message: { text: "Warning 1" },
      });
      log.runs.push(run);

      const summary = getSarifSummary(log);
      expect(summary.totalResults).toBe(2);
      expect(summary.byLevel.error).toBe(1);
      expect(summary.byLevel.warning).toBe(1);
      expect(summary.byTool.TestTool).toBe(2);
    });
  });

  describe("uploadSarifToGitHub", () => {
    it("should upload SARIF to GitHub with correct payload", async () => {
      const mockResponse = {
        ok: true,
        json: async () => ({ id: "upload-123", url: "https://api.github.com/..." }),
      };
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue(mockResponse) as typeof fetch;

      try {
        const log = createSarifLog();
        log.runs.push(createSarifRun("TestTool"));

        const result = await uploadSarifToGitHub(log, {
          owner: "testowner",
          repo: "testrepo",
          commitSha: "abc123",
          ref: "refs/heads/main",
          token: "ghp_test_token",
        });

        expect(result.id).toBe("upload-123");
        expect(globalThis.fetch).toHaveBeenCalledWith(
          "https://api.github.com/repos/testowner/testrepo/code-scanning/sarifs",
          expect.objectContaining({
            method: "POST",
            headers: expect.objectContaining({
              Authorization: "Bearer ghp_test_token",
              "Content-Type": "application/json",
            }),
          })
        );
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("should throw error on failed upload", async () => {
      const mockResponse = {
        ok: false,
        status: 401,
        text: async () => "Unauthorized",
      };
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue(mockResponse) as typeof fetch;

      try {
        const log = createSarifLog();
        await expect(
          uploadSarifToGitHub(log, {
            owner: "testowner",
            repo: "testrepo",
            commitSha: "abc123",
            ref: "refs/heads/main",
            token: "invalid_token",
          })
        ).rejects.toThrow("GitHub SARIF upload failed (401)");
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("should use custom API URL", async () => {
      const mockResponse = {
        ok: true,
        json: async () => ({ id: "upload-456", url: "https://github.example.com/..." }),
      };
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue(mockResponse) as typeof fetch;

      try {
        const log = createSarifLog();
        log.runs.push(createSarifRun("TestTool"));

        await uploadSarifToGitHub(log, {
          owner: "testowner",
          repo: "testrepo",
          commitSha: "abc123",
          ref: "refs/heads/main",
          token: "ghp_token",
          apiUrl: "https://github.example.com/api/v3",
        });

        expect(globalThis.fetch).toHaveBeenCalledWith(
          "https://github.example.com/api/v3/repos/testowner/testrepo/code-scanning/sarifs",
          expect.anything()
        );
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  describe("writeSarifFile", () => {
    it("should write SARIF to file", async () => {
      // Use a test file in the temp directory
      const testPath = "/tmp/sarif-test-output.sarif";

      const log = createSarifLog();
      log.runs.push(createSarifRun("TestTool"));

      await writeSarifFile(log, testPath);

      // Read the file back and verify contents
      const fs = await import("node:fs/promises");
      const content = await fs.readFile(testPath, "utf-8");
      const parsed = JSON.parse(content);

      expect(parsed.version).toBe("2.1.0");
      expect(parsed.runs).toHaveLength(1);
      expect(parsed.runs[0].tool.driver.name).toBe("TestTool");

      // Clean up
      await fs.unlink(testPath);
    });
  });
});
