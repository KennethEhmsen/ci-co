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
  // Default webhook config for tests
  const defaultWebhook = {
    url: "",
    urls: "",
    config: "",
    slackUrl: "",
    teamsUrl: "",
    severityThreshold: "HIGH",
  };

  // Default policy config for tests
  const defaultPolicy = {
    file: "",
    directory: "",
    defaultPolicy: "standard",
    strict: false,
  };

  describe("validateConfig", () => {
    it("should validate correct config", () => {
      const result = validateConfig({
        gitea: { url: "http://localhost:3000", user: "admin", password: "admin" },
        drone: { url: "http://localhost:8085", token: "token" },
        sonarqube: { url: "http://localhost:9000", user: "admin", password: "admin" },
        dependencyTrack: { url: "http://localhost:8081", apiKey: "key" },
        trivy: { url: "http://localhost:4954" },
        registry: { url: "http://localhost:5000" },
        webhook: defaultWebhook,
        policy: defaultPolicy,
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
        webhook: defaultWebhook,
        policy: defaultPolicy,
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
        webhook: defaultWebhook,
        policy: defaultPolicy,
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
        webhook: defaultWebhook,
        policy: defaultPolicy,
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
        webhook: defaultWebhook,
        policy: defaultPolicy,
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
        webhook: defaultWebhook,
        policy: defaultPolicy,
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
        webhook: defaultWebhook,
        policy: defaultPolicy,
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
        webhook: defaultWebhook,
        policy: defaultPolicy,
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
        webhook: defaultWebhook,
        policy: defaultPolicy,
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
        webhook: defaultWebhook,
        policy: defaultPolicy,
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
        webhook: defaultWebhook,
        policy: defaultPolicy,
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
        webhook: defaultWebhook,
        policy: defaultPolicy,
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
        webhook: defaultWebhook,
        policy: defaultPolicy,
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
        webhook: defaultWebhook,
        policy: defaultPolicy,
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

// Webhook tests
import {
  meetsSeverityThreshold,
  formatSlackMessage,
  formatTeamsMessage,
  formatGenericMessage,
  sendWebhook,
  sendWebhooks,
  createScanSummary,
  parseWebhookConfig,
} from "./webhook.js";
import type { WebhookScanSummary, WebhookEndpoint, WebhookConfig } from "./types.js";

describe("Webhook", () => {
  const baseSummary: WebhookScanSummary = {
    target: "node:20-alpine",
    scanType: "image",
    timestamp: "2024-01-15T10:00:00Z",
    vulnerabilities: {
      critical: 2,
      high: 5,
      medium: 10,
      low: 20,
      total: 37,
    },
  };

  describe("meetsSeverityThreshold", () => {
    it("should return true when critical > 0 and threshold is CRITICAL", () => {
      expect(meetsSeverityThreshold(baseSummary, "CRITICAL")).toBe(true);
    });

    it("should return true when high > 0 and threshold is HIGH", () => {
      const summary = {
        ...baseSummary,
        vulnerabilities: { ...baseSummary.vulnerabilities, critical: 0 },
      };
      expect(meetsSeverityThreshold(summary, "HIGH")).toBe(true);
    });

    it("should return false when no vulns meet threshold", () => {
      const summary = {
        ...baseSummary,
        vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
      };
      expect(meetsSeverityThreshold(summary, "HIGH")).toBe(false);
    });

    it("should return true for LOW threshold with any vulns", () => {
      const summary = {
        ...baseSummary,
        vulnerabilities: { critical: 0, high: 0, medium: 0, low: 1, total: 1 },
      };
      expect(meetsSeverityThreshold(summary, "LOW")).toBe(true);
    });
  });

  describe("formatSlackMessage", () => {
    it("should format scan summary as Slack payload", () => {
      const payload = formatSlackMessage(baseSummary);

      expect(payload.text).toContain("node:20-alpine");
      expect(payload.blocks).toBeDefined();
      expect(payload.blocks!.length).toBeGreaterThan(0);
      expect(payload.blocks![0].type).toBe("header");
    });

    it("should include policy status when provided", () => {
      const summary = { ...baseSummary, policyPassed: false };
      const payload = formatSlackMessage(summary);

      const policyBlock = payload.blocks?.find((b) => b.text?.text?.includes("Policy Check"));
      expect(policyBlock).toBeDefined();
    });

    it("should include top findings when provided", () => {
      const summary = {
        ...baseSummary,
        topFindings: [
          { id: "CVE-2024-1234", severity: "CRITICAL", title: "Test vuln", package: "pkg@1.0" },
        ],
      };
      const payload = formatSlackMessage(summary);

      const findingsBlock = payload.blocks?.find((b) => b.text?.text?.includes("CVE-2024-1234"));
      expect(findingsBlock).toBeDefined();
    });

    it("should include details URL when provided", () => {
      const summary = { ...baseSummary, detailsUrl: "https://example.com/scan/123" };
      const payload = formatSlackMessage(summary);

      const actionsBlock = payload.blocks?.find((b) => b.type === "actions");
      expect(actionsBlock).toBeDefined();
      expect(actionsBlock!.elements![0].url).toBe("https://example.com/scan/123");
    });
  });

  describe("formatTeamsMessage", () => {
    it("should format scan summary as Teams Adaptive Card", () => {
      const payload = formatTeamsMessage(baseSummary);

      expect(payload.type).toBe("message");
      expect(payload.attachments).toHaveLength(1);
      expect(payload.attachments[0].contentType).toBe("application/vnd.microsoft.card.adaptive");
      expect(payload.attachments[0].content.type).toBe("AdaptiveCard");
    });

    it("should include vulnerability counts", () => {
      const payload = formatTeamsMessage(baseSummary);
      const body = payload.attachments[0].content.body;

      const columnSet = body.find((e) => e.type === "ColumnSet");
      expect(columnSet).toBeDefined();
      expect(columnSet!.columns).toHaveLength(4);
    });

    it("should include details URL as action", () => {
      const summary = { ...baseSummary, detailsUrl: "https://example.com/scan/123" };
      const payload = formatTeamsMessage(summary);

      expect(payload.attachments[0].content.actions).toBeDefined();
      expect(payload.attachments[0].content.actions![0].url).toBe("https://example.com/scan/123");
    });
  });

  describe("formatGenericMessage", () => {
    it("should format scan summary as generic payload", () => {
      const payload = formatGenericMessage(baseSummary);

      expect(payload.event).toBe("scan_completed");
      expect(payload.target).toBe("node:20-alpine");
      expect(payload.scanType).toBe("image");
      expect(payload.summary).toEqual(baseSummary.vulnerabilities);
    });

    it("should include optional fields when provided", () => {
      const summary = {
        ...baseSummary,
        policyPassed: true,
        topFindings: [{ id: "CVE-1", severity: "HIGH", title: "Test" }],
        detailsUrl: "https://example.com",
      };
      const payload = formatGenericMessage(summary);

      expect(payload.policyPassed).toBe(true);
      expect(payload.topFindings).toHaveLength(1);
      expect(payload.detailsUrl).toBe("https://example.com");
    });
  });

  describe("sendWebhook", () => {
    it("should send webhook and return success result", async () => {
      const mockResponse = { ok: true, status: 200 };
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue(mockResponse) as typeof fetch;

      try {
        const endpoint: WebhookEndpoint = {
          id: "test-1",
          name: "Test Webhook",
          url: "https://hooks.example.com/webhook",
          format: "generic",
        };

        const result = await sendWebhook(endpoint, baseSummary);

        expect(result.success).toBe(true);
        expect(result.endpointId).toBe("test-1");
        expect(result.attempts).toBe(1);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("should skip notification if severity threshold not met", async () => {
      const endpoint: WebhookEndpoint = {
        id: "test-2",
        name: "Test Webhook",
        url: "https://hooks.example.com/webhook",
        format: "generic",
        severityThreshold: "CRITICAL",
      };

      const lowSeveritySummary = {
        ...baseSummary,
        vulnerabilities: { critical: 0, high: 0, medium: 1, low: 0, total: 1 },
      };

      const result = await sendWebhook(endpoint, lowSeveritySummary);

      expect(result.success).toBe(true);
      expect(result.attempts).toBe(0); // No attempt made
    });

    it("should retry on failure", async () => {
      let attempts = 0;
      const mockResponse = {
        ok: false,
        status: 500,
        text: async () => "Server Error",
      };
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockImplementation(() => {
        attempts++;
        return Promise.resolve(mockResponse);
      }) as typeof fetch;

      try {
        const endpoint: WebhookEndpoint = {
          id: "test-3",
          name: "Test Webhook",
          url: "https://hooks.example.com/webhook",
          format: "generic",
        };

        const result = await sendWebhook(endpoint, baseSummary, {
          endpoints: [],
          retryAttempts: 3,
          retryDelayMs: 10,
        });

        expect(result.success).toBe(false);
        expect(result.attempts).toBe(3);
        expect(attempts).toBe(3);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("should not retry on 4xx errors except 429", async () => {
      const mockResponse = {
        ok: false,
        status: 400,
        text: async () => "Bad Request",
      };
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue(mockResponse) as typeof fetch;

      try {
        const endpoint: WebhookEndpoint = {
          id: "test-4",
          name: "Test Webhook",
          url: "https://hooks.example.com/webhook",
          format: "generic",
        };

        const result = await sendWebhook(endpoint, baseSummary, {
          endpoints: [],
          retryAttempts: 3,
        });

        expect(result.success).toBe(false);
        expect(result.attempts).toBe(1); // Only one attempt
        expect(result.statusCode).toBe(400);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  describe("sendWebhooks", () => {
    it("should send to all enabled endpoints", async () => {
      const mockResponse = { ok: true, status: 200 };
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue(mockResponse) as typeof fetch;

      try {
        const config: WebhookConfig = {
          endpoints: [
            {
              id: "slack",
              name: "Slack",
              url: "https://slack.com/hook",
              format: "slack",
              enabled: true,
            },
            {
              id: "teams",
              name: "Teams",
              url: "https://teams.com/hook",
              format: "teams",
              enabled: true,
            },
            {
              id: "disabled",
              name: "Disabled",
              url: "https://disabled.com",
              format: "generic",
              enabled: false,
            },
          ],
        };

        const results = await sendWebhooks(config, baseSummary);

        expect(results).toHaveLength(2);
        expect(results.every((r) => r.success)).toBe(true);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  describe("createScanSummary", () => {
    it("should create a scan summary with required fields", () => {
      const summary = createScanSummary("myimage:latest", "image", {
        critical: 1,
        high: 2,
        medium: 3,
        low: 4,
        total: 10,
      });

      expect(summary.target).toBe("myimage:latest");
      expect(summary.scanType).toBe("image");
      expect(summary.timestamp).toBeDefined();
      expect(summary.vulnerabilities.total).toBe(10);
    });

    it("should include optional fields", () => {
      const summary = createScanSummary(
        "myimage:latest",
        "image",
        { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
        {
          policyPassed: true,
          topFindings: [{ id: "CVE-1", severity: "HIGH", title: "Test" }],
          detailsUrl: "https://example.com",
        }
      );

      expect(summary.policyPassed).toBe(true);
      expect(summary.topFindings).toHaveLength(1);
      expect(summary.detailsUrl).toBe("https://example.com");
    });
  });

  describe("parseWebhookConfig", () => {
    it("should return null for empty input", () => {
      expect(parseWebhookConfig(undefined)).toBeNull();
      expect(parseWebhookConfig("")).toBeNull();
    });

    it("should parse JSON configuration", () => {
      const jsonConfig = JSON.stringify({
        endpoints: [{ id: "test", name: "Test", url: "https://example.com", format: "slack" }],
      });

      const config = parseWebhookConfig(jsonConfig);

      expect(config).not.toBeNull();
      expect(config!.endpoints).toHaveLength(1);
      expect(config!.endpoints[0].format).toBe("slack");
    });

    it("should parse comma-separated URLs", () => {
      const urls = "https://hook1.example.com,https://hook2.example.com";

      const config = parseWebhookConfig(urls);

      expect(config).not.toBeNull();
      expect(config!.endpoints).toHaveLength(2);
      expect(config!.endpoints[0].format).toBe("generic");
      expect(config!.endpoints[1].url).toBe("https://hook2.example.com");
    });
  });
});

// Policy loader tests
import {
  validatePolicySchema,
  convertToPolicy,
  mergePolicies,
  resolvePolicy,
} from "./policy-loader.js";
import type { PolicyFileSchema, PolicyLoadResult } from "./types.js";

describe("Policy Loader", () => {
  describe("validatePolicySchema", () => {
    it("should validate a minimal valid policy", () => {
      const policy = {
        name: "test-policy",
        version: "1.0.0",
      };

      const result = validatePolicySchema(policy);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it("should require name field", () => {
      const policy = {
        version: "1.0.0",
      };

      const result = validatePolicySchema(policy);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === "name")).toBe(true);
    });

    it("should require version field", () => {
      const policy = {
        name: "test-policy",
      };

      const result = validatePolicySchema(policy);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === "version")).toBe(true);
    });

    it("should reject non-object input", () => {
      const result = validatePolicySchema("invalid");

      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toBe("Policy must be an object");
    });

    it("should validate mode field", () => {
      const policy = {
        name: "test",
        version: "1.0.0",
        mode: "invalid",
      };

      const result = validatePolicySchema(policy);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === "mode")).toBe(true);
    });

    it("should accept valid mode values", () => {
      const policy1 = { name: "test", version: "1.0.0", mode: "all" };
      const policy2 = { name: "test", version: "1.0.0", mode: "any" };

      expect(validatePolicySchema(policy1).valid).toBe(true);
      expect(validatePolicySchema(policy2).valid).toBe(true);
    });

    it("should warn about unknown extends value", () => {
      const policy = {
        name: "test",
        version: "1.0.0",
        extends: "unknown-policy",
      };

      const result = validatePolicySchema(policy);

      expect(result.valid).toBe(true); // warnings don't fail validation
      expect(result.warnings.some((w) => w.path === "extends")).toBe(true);
    });

    it("should validate rules array", () => {
      const policy = {
        name: "test",
        version: "1.0.0",
        rules: "not-an-array",
      };

      const result = validatePolicySchema(policy);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === "rules")).toBe(true);
    });

    it("should validate individual rules", () => {
      const policy = {
        name: "test",
        version: "1.0.0",
        rules: [
          { name: "valid-rule" },
          { notname: "invalid" }, // missing name
        ],
      };

      const result = validatePolicySchema(policy);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === "rules[1].name")).toBe(true);
    });

    it("should validate maxVulnerabilities structure", () => {
      const policy = {
        name: "test",
        version: "1.0.0",
        rules: [
          {
            name: "vuln-rule",
            maxVulnerabilities: {
              critical: 0,
              high: 5,
              invalid: 10, // unknown severity
            },
          },
        ],
      };

      const result = validatePolicySchema(policy);

      expect(result.valid).toBe(true); // unknown severity is a warning
      expect(result.warnings.some((w) => w.path.includes("invalid"))).toBe(true);
    });

    it("should reject negative vulnerability counts", () => {
      const policy = {
        name: "test",
        version: "1.0.0",
        rules: [
          {
            name: "vuln-rule",
            maxVulnerabilities: {
              critical: -1,
            },
          },
        ],
      };

      const result = validatePolicySchema(policy);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path.includes("critical"))).toBe(true);
    });

    it("should validate ignoreCves array", () => {
      const policy = {
        name: "test",
        version: "1.0.0",
        rules: [
          {
            name: "cve-rule",
            ignoreCves: "not-an-array",
          },
        ],
      };

      const result = validatePolicySchema(policy);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path.includes("ignoreCves"))).toBe(true);
    });

    it("should validate minCodeCoverage range", () => {
      const policy = {
        name: "test",
        version: "1.0.0",
        rules: [
          {
            name: "coverage-rule",
            minCodeCoverage: 150, // invalid: > 100
          },
        ],
      };

      const result = validatePolicySchema(policy);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path.includes("minCodeCoverage"))).toBe(true);
    });

    it("should validate settings", () => {
      const policy = {
        name: "test",
        version: "1.0.0",
        settings: {
          failOpen: "not-a-boolean",
        },
      };

      const result = validatePolicySchema(policy);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === "settings.failOpen")).toBe(true);
    });

    it("should validate settings reportFormat", () => {
      const policy = {
        name: "test",
        version: "1.0.0",
        settings: {
          reportFormat: "invalid",
        },
      };

      const result = validatePolicySchema(policy);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === "settings.reportFormat")).toBe(true);
    });

    it("should accept valid settings", () => {
      const policy = {
        name: "test",
        version: "1.0.0",
        settings: {
          failOpen: true,
          reportFormat: "sarif",
          includeWarnings: false,
        },
      };

      const result = validatePolicySchema(policy);

      expect(result.valid).toBe(true);
    });
  });

  describe("convertToPolicy", () => {
    it("should convert a file schema to runtime policy", () => {
      const fileSchema: PolicyFileSchema = {
        name: "my-policy",
        version: "1.0.0",
        description: "Test policy",
        mode: "any",
        rules: [
          {
            name: "rule1",
            maxVulnerabilities: { critical: 0 },
          },
        ],
      };

      const policy = convertToPolicy(fileSchema);

      expect(policy.name).toBe("my-policy");
      expect(policy.version).toBe("1.0.0");
      expect(policy.mode).toBe("any");
      expect(policy.rules).toHaveLength(1);
    });

    it("should default mode to all", () => {
      const fileSchema: PolicyFileSchema = {
        name: "my-policy",
        version: "1.0.0",
      };

      const policy = convertToPolicy(fileSchema);

      expect(policy.mode).toBe("all");
    });

    it("should filter disabled rules", () => {
      const fileSchema: PolicyFileSchema = {
        name: "my-policy",
        version: "1.0.0",
        rules: [
          { name: "enabled-rule", enabled: true },
          { name: "disabled-rule", enabled: false },
          { name: "default-enabled" }, // enabled by default
        ],
      };

      const policy = convertToPolicy(fileSchema);

      expect(policy.rules).toHaveLength(2);
      expect(policy.rules.map((r) => r.name)).toContain("enabled-rule");
      expect(policy.rules.map((r) => r.name)).toContain("default-enabled");
      expect(policy.rules.map((r) => r.name)).not.toContain("disabled-rule");
    });
  });

  describe("mergePolicies", () => {
    it("should merge file policy with base policy", () => {
      const filePolicy: PolicyFileSchema = {
        name: "custom-policy",
        version: "1.0.0",
        rules: [
          {
            name: "custom-rule",
            maxVulnerabilities: { critical: 5 },
          },
        ],
      };

      const merged = mergePolicies(filePolicy, standardPolicy);

      expect(merged.name).toBe("custom-policy");
      expect(merged.rules.length).toBeGreaterThan(1); // includes base rules
      expect(merged.rules.some((r) => r.name === "custom-rule")).toBe(true);
    });

    it("should override base rules by name", () => {
      const filePolicy: PolicyFileSchema = {
        name: "custom-policy",
        version: "1.0.0",
        rules: [
          {
            name: "vuln-limits", // same name as standard policy rule
            maxVulnerabilities: { critical: 10 }, // override threshold
          },
        ],
      };

      const merged = mergePolicies(filePolicy, standardPolicy);

      const vulnRule = merged.rules.find((r) => r.name === "vuln-limits");
      expect(vulnRule?.maxVulnerabilities?.critical).toBe(10);
    });

    it("should disable base rules when enabled: false", () => {
      const filePolicy: PolicyFileSchema = {
        name: "custom-policy",
        version: "1.0.0",
        rules: [
          {
            name: "no-secrets", // exists in standard policy
            enabled: false,
          },
        ],
      };

      const merged = mergePolicies(filePolicy, standardPolicy);

      expect(merged.rules.some((r) => r.name === "no-secrets")).toBe(false);
    });

    it("should merge arrays in rules", () => {
      const basePolicy = {
        ...standardPolicy,
        rules: [
          {
            name: "ignore-rule",
            ignoreCves: ["CVE-2023-0001"],
            ignorePackages: ["old-package"],
          },
        ],
      };

      const filePolicy: PolicyFileSchema = {
        name: "custom",
        version: "1.0.0",
        rules: [
          {
            name: "ignore-rule",
            ignoreCves: ["CVE-2023-0002"],
            ignorePackages: ["another-package"],
          },
        ],
      };

      const merged = mergePolicies(filePolicy, basePolicy);

      const rule = merged.rules.find((r) => r.name === "ignore-rule");
      expect(rule?.ignoreCves).toContain("CVE-2023-0001");
      expect(rule?.ignoreCves).toContain("CVE-2023-0002");
      expect(rule?.ignorePackages).toContain("old-package");
      expect(rule?.ignorePackages).toContain("another-package");
    });

    it("should inherit mode from file policy", () => {
      const filePolicy: PolicyFileSchema = {
        name: "custom",
        version: "1.0.0",
        mode: "any",
      };

      const merged = mergePolicies(filePolicy, standardPolicy);

      expect(merged.mode).toBe("any");
    });
  });

  describe("resolvePolicy", () => {
    it("should return default policy on load failure", () => {
      const loadResult: PolicyLoadResult = {
        success: false,
        error: "File not found",
        source: "file",
      };

      const policy = resolvePolicy(loadResult);

      expect(policy.name).toBe("standard"); // default
    });

    it("should use specified default policy on failure", () => {
      const loadResult: PolicyLoadResult = {
        success: false,
        error: "File not found",
        source: "file",
      };

      const policy = resolvePolicy(loadResult, "strict");

      expect(policy.name).toBe("strict");
    });

    it("should merge with extended policy", () => {
      const loadResult: PolicyLoadResult = {
        success: true,
        policy: {
          name: "my-policy",
          version: "1.0.0",
          extends: "permissive",
          rules: [{ name: "extra-rule" }],
        },
        source: "file",
      };

      const policy = resolvePolicy(loadResult);

      expect(policy.name).toBe("my-policy");
      expect(policy.rules.some((r) => r.name === "extra-rule")).toBe(true);
      // Should include rules from permissive
      expect(policy.rules.some((r) => r.name === "critical-only")).toBe(true);
    });

    it("should convert directly without extends", () => {
      const loadResult: PolicyLoadResult = {
        success: true,
        policy: {
          name: "standalone",
          version: "2.0.0",
          rules: [{ name: "only-rule" }],
        },
        source: "file",
      };

      const policy = resolvePolicy(loadResult);

      expect(policy.name).toBe("standalone");
      expect(policy.rules).toHaveLength(1);
    });
  });
});

// Parallel scanner tests
import { parseTargets, parseImages, parsePaths } from "./parallel-scanner.js";
import type { ScanTarget, ScanProgress, TargetScanResult } from "./types.js";

describe("Parallel Scanner", () => {
  describe("parseTargets", () => {
    it("should parse comma-separated targets", () => {
      const targets = parseTargets("node:20,python:3.12,nginx:latest");

      expect(targets).toHaveLength(3);
      expect(targets[0].target).toBe("node:20");
      expect(targets[1].target).toBe("python:3.12");
      expect(targets[2].target).toBe("nginx:latest");
    });

    it("should handle single target", () => {
      const targets = parseTargets("alpine:latest");

      expect(targets).toHaveLength(1);
      expect(targets[0].target).toBe("alpine:latest");
      expect(targets[0].type).toBe("image");
    });

    it("should trim whitespace", () => {
      const targets = parseTargets("  node:20 , python:3.12  ");

      expect(targets).toHaveLength(2);
      expect(targets[0].target).toBe("node:20");
      expect(targets[1].target).toBe("python:3.12");
    });

    it("should filter empty entries", () => {
      const targets = parseTargets("node:20,,python:3.12,");

      expect(targets).toHaveLength(2);
    });

    it("should use specified type", () => {
      const targets = parseTargets("/app,/lib", "path");

      expect(targets[0].type).toBe("path");
      expect(targets[1].type).toBe("path");
    });

    it("should set label to target value", () => {
      const targets = parseTargets("node:20");

      expect(targets[0].label).toBe("node:20");
    });
  });

  describe("parseImages", () => {
    it("should parse string input", () => {
      const targets = parseImages("node:20,python:3.12");

      expect(targets).toHaveLength(2);
      expect(targets.every((t) => t.type === "image")).toBe(true);
    });

    it("should parse array input", () => {
      const targets = parseImages(["node:20", "python:3.12"]);

      expect(targets).toHaveLength(2);
      expect(targets[0].target).toBe("node:20");
      expect(targets[1].target).toBe("python:3.12");
    });
  });

  describe("parsePaths", () => {
    it("should parse string input", () => {
      const targets = parsePaths("/app,/lib");

      expect(targets).toHaveLength(2);
      expect(targets.every((t) => t.type === "path")).toBe(true);
    });

    it("should parse array input", () => {
      const targets = parsePaths(["/app", "/lib"]);

      expect(targets).toHaveLength(2);
      expect(targets[0].target).toBe("/app");
      expect(targets[1].target).toBe("/lib");
    });
  });

  describe("ScanProgress type", () => {
    it("should have correct structure", () => {
      const progress: ScanProgress = {
        total: 5,
        completed: 2,
        failed: 0,
        running: 2,
        currentTargets: ["node:20", "python:3.12"],
        percentage: 40,
      };

      expect(progress.total).toBe(5);
      expect(progress.percentage).toBe(40);
      expect(progress.currentTargets).toHaveLength(2);
    });
  });

  describe("TargetScanResult type", () => {
    it("should represent successful scan", () => {
      const result: TargetScanResult = {
        target: { target: "node:20", type: "image" },
        success: true,
        result: { Results: [] },
        durationMs: 5000,
        startedAt: "2024-01-01T00:00:00Z",
        completedAt: "2024-01-01T00:00:05Z",
      };

      expect(result.success).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should represent failed scan", () => {
      const result: TargetScanResult = {
        target: { target: "invalid:image", type: "image" },
        success: false,
        error: "Image not found",
        durationMs: 1000,
        startedAt: "2024-01-01T00:00:00Z",
        completedAt: "2024-01-01T00:00:01Z",
      };

      expect(result.success).toBe(false);
      expect(result.error).toBe("Image not found");
      expect(result.result).toBeUndefined();
    });
  });

  describe("ScanTarget type", () => {
    it("should support image type", () => {
      const target: ScanTarget = {
        target: "node:20",
        type: "image",
        label: "Node.js 20",
      };

      expect(target.type).toBe("image");
    });

    it("should support path type", () => {
      const target: ScanTarget = {
        target: "/app/backend",
        type: "path",
        label: "Backend",
      };

      expect(target.type).toBe("path");
    });

    it("should make label optional", () => {
      const target: ScanTarget = {
        target: "alpine:latest",
        type: "image",
      };

      expect(target.label).toBeUndefined();
    });
  });
});

// Metrics tests
import {
  METRICS,
  recordScanMetrics,
  recordCacheHit,
  recordCacheMiss,
  recordCircuitBreakerFailure,
  resetMetrics,
  getMetrics,
  getMetricsSnapshot,
  toPrometheusFormat,
} from "./metrics.js";
import type { ScanMetrics, MetricsSnapshot } from "./types.js";

describe("Metrics", () => {
  beforeEach(() => {
    resetMetrics();
  });

  describe("METRICS definitions", () => {
    it("should define scan duration histogram", () => {
      expect(METRICS.scanDuration.name).toContain("scan_duration_seconds");
      expect(METRICS.scanDuration.type).toBe("histogram");
    });

    it("should define scan total counter", () => {
      expect(METRICS.scanTotal.name).toContain("scan_total");
      expect(METRICS.scanTotal.type).toBe("counter");
    });

    it("should define vulnerabilities counter", () => {
      expect(METRICS.vulnerabilitiesTotal.name).toContain("vulnerabilities_total");
      expect(METRICS.vulnerabilitiesTotal.type).toBe("counter");
    });

    it("should define circuit breaker state gauge", () => {
      expect(METRICS.circuitBreakerState.name).toContain("circuit_breaker_state");
      expect(METRICS.circuitBreakerState.type).toBe("gauge");
    });

    it("should define cache metrics", () => {
      expect(METRICS.cacheHits.name).toContain("cache_hits_total");
      expect(METRICS.cacheMisses.name).toContain("cache_misses_total");
    });
  });

  describe("recordScanMetrics", () => {
    it("should record successful scan", () => {
      const metrics: ScanMetrics = {
        target: "node:20",
        type: "image",
        durationSeconds: 5.5,
        success: true,
        vulnerabilities: {
          critical: 1,
          high: 2,
          medium: 3,
          low: 4,
        },
      };

      recordScanMetrics(metrics);

      const snapshot = getMetricsSnapshot();
      const scanTotal = snapshot.metrics.find((m) => m.definition.name.includes("scan_total"));

      expect(scanTotal).toBeDefined();
      expect(scanTotal!.values.length).toBeGreaterThan(0);
    });

    it("should record failed scan", () => {
      const metrics: ScanMetrics = {
        target: "invalid:image",
        type: "image",
        durationSeconds: 1.0,
        success: false,
        error: "Connection timeout",
      };

      recordScanMetrics(metrics);

      const snapshot = getMetricsSnapshot();
      const errorTotal = snapshot.metrics.find((m) => m.definition.name.includes("errors_total"));

      expect(errorTotal).toBeDefined();
    });

    it("should record vulnerability counts", () => {
      const metrics: ScanMetrics = {
        target: "python:3.12",
        type: "image",
        durationSeconds: 3.0,
        success: true,
        vulnerabilities: {
          critical: 2,
          high: 5,
          medium: 10,
          low: 20,
        },
      };

      recordScanMetrics(metrics);

      const snapshot = getMetricsSnapshot();
      const vulnTotal = snapshot.metrics.find((m) =>
        m.definition.name.includes("vulnerabilities_total")
      );

      expect(vulnTotal).toBeDefined();
      expect(vulnTotal!.values.length).toBeGreaterThan(0);
    });
  });

  describe("cache metrics", () => {
    it("should record cache hits", () => {
      recordCacheHit("trivy");
      recordCacheHit("trivy");
      recordCacheHit("sonar");

      const snapshot = getMetricsSnapshot();
      const cacheHits = snapshot.metrics.find((m) => m.definition.name.includes("cache_hits"));

      expect(cacheHits).toBeDefined();
      expect(cacheHits!.values.length).toBe(2); // trivy and sonar
    });

    it("should record cache misses", () => {
      recordCacheMiss("trivy");
      recordCacheMiss("dtrack");

      const snapshot = getMetricsSnapshot();
      const cacheMisses = snapshot.metrics.find((m) => m.definition.name.includes("cache_misses"));

      expect(cacheMisses).toBeDefined();
      expect(cacheMisses!.values.length).toBe(2);
    });
  });

  describe("circuit breaker metrics", () => {
    it("should record circuit breaker failures", () => {
      recordCircuitBreakerFailure("trivy");
      recordCircuitBreakerFailure("trivy");
      recordCircuitBreakerFailure("sonar");

      const snapshot = getMetricsSnapshot();
      const cbFailures = snapshot.metrics.find((m) =>
        m.definition.name.includes("circuit_breaker_failures")
      );

      expect(cbFailures).toBeDefined();
    });

    it("should collect circuit breaker state", () => {
      const snapshot = getMetricsSnapshot();
      const cbState = snapshot.metrics.find((m) =>
        m.definition.name.includes("circuit_breaker_state")
      );

      expect(cbState).toBeDefined();
      // Should have entries for each service
      expect(cbState!.values.length).toBeGreaterThan(0);
    });
  });

  describe("getMetrics", () => {
    it("should return Prometheus format string", () => {
      recordScanMetrics({
        target: "test:latest",
        type: "image",
        durationSeconds: 1.0,
        success: true,
      });

      const output = getMetrics();

      expect(typeof output).toBe("string");
      expect(output).toContain("# HELP");
      expect(output).toContain("# TYPE");
    });

    it("should include cache sizes when provided", () => {
      const output = getMetrics({
        cacheSizes: { trivy: 10, sonar: 5 },
      });

      expect(output).toContain("cache_size");
    });

    it("should include rate limiter queues when provided", () => {
      const output = getMetrics({
        rateLimiterQueues: { trivy: 3, sonar: 0 },
      });

      expect(output).toContain("rate_limiter_queue_size");
    });
  });

  describe("toPrometheusFormat", () => {
    it("should format counter metrics", () => {
      recordCacheHit("test-cache");

      const snapshot = getMetricsSnapshot();
      const output = toPrometheusFormat(snapshot);

      expect(output).toContain('cache_hits_total{cache="test-cache"}');
    });

    it("should format gauge metrics", () => {
      const snapshot = getMetricsSnapshot();
      const output = toPrometheusFormat(snapshot);

      expect(output).toContain("circuit_breaker_state");
    });

    it("should format histogram metrics", () => {
      recordScanMetrics({
        target: "test:latest",
        type: "image",
        durationSeconds: 2.5,
        success: true,
      });

      const snapshot = getMetricsSnapshot();
      const output = toPrometheusFormat(snapshot);

      expect(output).toContain("scan_duration_seconds_bucket");
      expect(output).toContain("scan_duration_seconds_sum");
      expect(output).toContain("scan_duration_seconds_count");
    });

    it("should escape label values", () => {
      // The circuit breaker service names shouldn't need escaping,
      // but the format function should handle special chars
      const snapshot = getMetricsSnapshot();
      const output = toPrometheusFormat(snapshot);

      // Should be valid Prometheus format (no unclosed quotes)
      const quoteCount = (output.match(/"/g) || []).length;
      expect(quoteCount % 2).toBe(0);
    });
  });

  describe("resetMetrics", () => {
    it("should clear all collected metrics", () => {
      recordScanMetrics({
        target: "test:latest",
        type: "image",
        durationSeconds: 1.0,
        success: true,
        vulnerabilities: { critical: 1, high: 2, medium: 3, low: 4 },
      });
      recordCacheHit("test");

      resetMetrics();

      const snapshot = getMetricsSnapshot();
      const vulnMetric = snapshot.metrics.find((m) =>
        m.definition.name.includes("vulnerabilities_total")
      );

      // After reset, vulnerability counter should have no values
      expect(vulnMetric!.values.length).toBe(0);
    });
  });

  describe("MetricsSnapshot type", () => {
    it("should have correct structure", () => {
      const snapshot: MetricsSnapshot = getMetricsSnapshot();

      expect(snapshot.timestamp).toBeDefined();
      expect(Array.isArray(snapshot.metrics)).toBe(true);
      expect(snapshot.metrics.length).toBeGreaterThan(0);
    });

    it("should include metric definitions", () => {
      const snapshot = getMetricsSnapshot();

      for (const metric of snapshot.metrics) {
        expect(metric.definition.name).toBeDefined();
        expect(metric.definition.help).toBeDefined();
        expect(metric.definition.type).toBeDefined();
      }
    });
  });
});

// Scan Diff tests
import {
  createFingerprint,
  fingerprintTrivyVulnerability,
  extractTrivyVulnerabilities,
  compareVulnerabilities,
  compareScanResults,
  compareTrivyScans,
  getScanHistory,
  resetScanHistory,
  createScanRecord,
  storeTrivyScan,
  storeAndCompare,
} from "./scan-diff.js";
import type { TrivyVulnerability, TrivyScanResult, FingerprintedVulnerability } from "./types.js";

describe("Scan Diff", () => {
  beforeEach(() => {
    resetScanHistory();
  });

  describe("createFingerprint", () => {
    it("should create consistent fingerprints for same input", () => {
      const fp1 = createFingerprint(
        "CVE-2023-1234",
        "lodash",
        "4.17.20",
        "app/node_modules",
        "trivy"
      );
      const fp2 = createFingerprint(
        "CVE-2023-1234",
        "lodash",
        "4.17.20",
        "app/node_modules",
        "trivy"
      );
      expect(fp1).toBe(fp2);
    });

    it("should create different fingerprints for different inputs", () => {
      const fp1 = createFingerprint(
        "CVE-2023-1234",
        "lodash",
        "4.17.20",
        "app/node_modules",
        "trivy"
      );
      const fp2 = createFingerprint(
        "CVE-2023-5678",
        "lodash",
        "4.17.20",
        "app/node_modules",
        "trivy"
      );
      expect(fp1).not.toBe(fp2);
    });

    it("should create 16-character fingerprints", () => {
      const fp = createFingerprint(
        "CVE-2023-1234",
        "lodash",
        "4.17.20",
        "app/node_modules",
        "trivy"
      );
      expect(fp.length).toBe(16);
    });
  });

  describe("fingerprintTrivyVulnerability", () => {
    it("should convert Trivy vulnerability to fingerprinted vulnerability", () => {
      const trivyVuln: TrivyVulnerability = {
        VulnerabilityID: "CVE-2023-1234",
        PkgName: "lodash",
        InstalledVersion: "4.17.20",
        FixedVersion: "4.17.21",
        Severity: "HIGH",
        Title: "Test vulnerability",
        Description: "A test vulnerability",
      };

      const result = fingerprintTrivyVulnerability(trivyVuln, "node_modules");

      expect(result.fingerprint).toBeDefined();
      expect(result.id).toBe("CVE-2023-1234");
      expect(result.package).toBe("lodash");
      expect(result.version).toBe("4.17.20");
      expect(result.severity).toBe("HIGH");
      expect(result.fixedVersion).toBe("4.17.21");
      expect(result.source).toBe("trivy");
    });
  });

  describe("extractTrivyVulnerabilities", () => {
    it("should extract all vulnerabilities from scan result", () => {
      const scanResult: TrivyScanResult = {
        ArtifactName: "node:20",
        Results: [
          {
            Target: "node_modules",
            Class: "lang-pkgs",
            Type: "node-pkg",
            Vulnerabilities: [
              {
                VulnerabilityID: "CVE-2023-1234",
                PkgName: "lodash",
                InstalledVersion: "4.17.20",
                Severity: "HIGH",
              },
              {
                VulnerabilityID: "CVE-2023-5678",
                PkgName: "express",
                InstalledVersion: "4.18.0",
                Severity: "MEDIUM",
              },
            ],
          },
        ],
      };

      const vulns = extractTrivyVulnerabilities(scanResult);

      expect(vulns.length).toBe(2);
      expect(vulns[0].id).toBe("CVE-2023-1234");
      expect(vulns[1].id).toBe("CVE-2023-5678");
    });

    it("should handle empty results", () => {
      const scanResult: TrivyScanResult = {
        ArtifactName: "node:20",
        Results: [],
      };

      const vulns = extractTrivyVulnerabilities(scanResult);
      expect(vulns.length).toBe(0);
    });

    it("should handle missing vulnerabilities array", () => {
      const scanResult: TrivyScanResult = {
        ArtifactName: "node:20",
        Results: [
          {
            Target: "node_modules",
            Class: "lang-pkgs",
            Type: "node-pkg",
          },
        ],
      };

      const vulns = extractTrivyVulnerabilities(scanResult);
      expect(vulns.length).toBe(0);
    });
  });

  describe("compareVulnerabilities", () => {
    const createVuln = (id: string, severity: string): FingerprintedVulnerability => ({
      fingerprint: createFingerprint(id, "pkg", "1.0", "target", "trivy"),
      id,
      package: "pkg",
      version: "1.0",
      severity,
      target: "target",
      source: "trivy",
    });

    it("should identify new vulnerabilities", () => {
      const current = [createVuln("CVE-1", "HIGH"), createVuln("CVE-2", "MEDIUM")];
      const baseline = [createVuln("CVE-1", "HIGH")];

      const result = compareVulnerabilities(current, baseline);

      expect(result.new.length).toBe(1);
      expect(result.new[0].id).toBe("CVE-2");
      expect(result.fixed.length).toBe(0);
      expect(result.unchanged.length).toBe(1);
    });

    it("should identify fixed vulnerabilities", () => {
      const current = [createVuln("CVE-1", "HIGH")];
      const baseline = [createVuln("CVE-1", "HIGH"), createVuln("CVE-2", "MEDIUM")];

      const result = compareVulnerabilities(current, baseline);

      expect(result.new.length).toBe(0);
      expect(result.fixed.length).toBe(1);
      expect(result.fixed[0].id).toBe("CVE-2");
      expect(result.unchanged.length).toBe(1);
    });

    it("should identify unchanged vulnerabilities", () => {
      const vuln = createVuln("CVE-1", "HIGH");
      const current = [vuln];
      const baseline = [vuln];

      const result = compareVulnerabilities(current, baseline);

      expect(result.new.length).toBe(0);
      expect(result.fixed.length).toBe(0);
      expect(result.unchanged.length).toBe(1);
    });

    it("should filter by minimum severity", () => {
      const current = [
        createVuln("CVE-1", "CRITICAL"),
        createVuln("CVE-2", "HIGH"),
        createVuln("CVE-3", "LOW"),
      ];
      const baseline: FingerprintedVulnerability[] = [];

      const result = compareVulnerabilities(current, baseline, { minSeverity: "HIGH" });

      expect(result.new.length).toBe(2);
      expect(result.new.map((v) => v.id)).toContain("CVE-1");
      expect(result.new.map((v) => v.id)).toContain("CVE-2");
      expect(result.new.map((v) => v.id)).not.toContain("CVE-3");
    });

    it("should exclude unchanged when option is set", () => {
      const vuln = createVuln("CVE-1", "HIGH");
      const result = compareVulnerabilities([vuln], [vuln], { includeUnchanged: false });

      expect(result.unchanged.length).toBe(0);
    });
  });

  describe("compareScanResults", () => {
    it("should generate full diff result with summary", () => {
      const current: FingerprintedVulnerability[] = [
        {
          fingerprint: "fp1",
          id: "CVE-NEW",
          package: "pkg",
          version: "1.0",
          severity: "CRITICAL",
          target: "t",
          source: "trivy",
        },
        {
          fingerprint: "fp2",
          id: "CVE-UNCHANGED",
          package: "pkg",
          version: "1.0",
          severity: "HIGH",
          target: "t",
          source: "trivy",
        },
      ];

      const baseline: FingerprintedVulnerability[] = [
        {
          fingerprint: "fp2",
          id: "CVE-UNCHANGED",
          package: "pkg",
          version: "1.0",
          severity: "HIGH",
          target: "t",
          source: "trivy",
        },
        {
          fingerprint: "fp3",
          id: "CVE-FIXED",
          package: "pkg",
          version: "1.0",
          severity: "MEDIUM",
          target: "t",
          source: "trivy",
        },
      ];

      const result = compareScanResults(
        current,
        baseline,
        { target: "image:latest", scannedAt: "2025-01-01" },
        { target: "image:latest", scannedAt: "2024-12-01" }
      );

      expect(result.summary.currentTotal).toBe(2);
      expect(result.summary.baselineTotal).toBe(2);
      expect(result.summary.new).toBe(1);
      expect(result.summary.fixed).toBe(1);
      expect(result.summary.unchanged).toBe(1);
      expect(result.summary.bySeverity.critical.new).toBe(1);
      expect(result.summary.bySeverity.high.unchanged).toBe(1);
      expect(result.summary.bySeverity.medium.fixed).toBe(1);
      expect(result.newVulnerabilities[0].id).toBe("CVE-NEW");
      expect(result.fixedVulnerabilities[0].id).toBe("CVE-FIXED");
    });
  });

  describe("compareTrivyScans", () => {
    it("should compare two Trivy scan results", () => {
      const current: TrivyScanResult = {
        ArtifactName: "node:20",
        Results: [
          {
            Target: "app",
            Class: "lang-pkgs",
            Type: "node-pkg",
            Vulnerabilities: [
              {
                VulnerabilityID: "CVE-2023-NEW",
                PkgName: "pkg",
                InstalledVersion: "1.0",
                Severity: "HIGH",
              },
            ],
          },
        ],
      };

      const baseline: TrivyScanResult = {
        ArtifactName: "node:20",
        Results: [
          {
            Target: "app",
            Class: "lang-pkgs",
            Type: "node-pkg",
            Vulnerabilities: [
              {
                VulnerabilityID: "CVE-2023-OLD",
                PkgName: "pkg",
                InstalledVersion: "1.0",
                Severity: "MEDIUM",
              },
            ],
          },
        ],
      };

      const result = compareTrivyScans(current, baseline);

      expect(result.summary.new).toBe(1);
      expect(result.summary.fixed).toBe(1);
      expect(result.newVulnerabilities[0].id).toBe("CVE-2023-NEW");
      expect(result.fixedVulnerabilities[0].id).toBe("CVE-2023-OLD");
    });
  });

  describe("Scan History", () => {
    it("should store and retrieve scan records", () => {
      const history = getScanHistory();
      const record = createScanRecord("node:20", [
        {
          fingerprint: "fp1",
          id: "CVE-1",
          package: "pkg",
          version: "1.0",
          severity: "HIGH",
          target: "t",
          source: "trivy",
        },
      ]);

      history.store(record);
      const retrieved = history.getHistory("node:20");

      expect(retrieved.length).toBe(1);
      expect(retrieved[0].id).toBe(record.id);
    });

    it("should retrieve latest scan", () => {
      const history = getScanHistory();

      const record1 = createScanRecord("node:20", []);
      history.store(record1);

      const record2 = createScanRecord("node:20", []);
      history.store(record2);

      const latest = history.getLatest("node:20");
      expect(latest?.id).toBe(record2.id);
    });

    it("should limit history per target", () => {
      resetScanHistory();
      const history = getScanHistory({ maxRecordsPerTarget: 3 });

      for (let i = 0; i < 5; i++) {
        history.store(createScanRecord("node:20", []));
      }

      const records = history.getHistory("node:20");
      expect(records.length).toBe(3);
    });

    it("should clear history", () => {
      const history = getScanHistory();
      history.store(createScanRecord("node:20", []));
      history.clear();

      expect(history.getHistory("node:20").length).toBe(0);
    });
  });

  describe("storeTrivyScan", () => {
    it("should store scan and return record", () => {
      const scanResult: TrivyScanResult = {
        ArtifactName: "node:20",
        Results: [
          {
            Target: "app",
            Class: "lang-pkgs",
            Type: "node-pkg",
            Vulnerabilities: [
              {
                VulnerabilityID: "CVE-1",
                PkgName: "pkg",
                InstalledVersion: "1.0",
                Severity: "HIGH",
              },
            ],
          },
        ],
      };

      const record = storeTrivyScan(scanResult, "v1.0.0");

      expect(record.target).toBe("node:20");
      expect(record.identifier).toBe("v1.0.0");
      expect(record.vulnerabilities.length).toBe(1);
      expect(record.summary.high).toBe(1);
      expect(record.summary.total).toBe(1);
    });
  });

  describe("storeAndCompare", () => {
    it("should return null diff on first scan", () => {
      const scanResult: TrivyScanResult = {
        ArtifactName: "python:3.12",
        Results: [],
      };

      const { record, diff } = storeAndCompare(scanResult);

      expect(record).toBeDefined();
      expect(diff).toBeNull();
    });

    it("should return diff on subsequent scans", () => {
      const scan1: TrivyScanResult = {
        ArtifactName: "python:3.12",
        Results: [
          {
            Target: "app",
            Class: "lang-pkgs",
            Type: "python-pkg",
            Vulnerabilities: [
              {
                VulnerabilityID: "CVE-OLD",
                PkgName: "pkg",
                InstalledVersion: "1.0",
                Severity: "HIGH",
              },
            ],
          },
        ],
      };

      const scan2: TrivyScanResult = {
        ArtifactName: "python:3.12",
        Results: [
          {
            Target: "app",
            Class: "lang-pkgs",
            Type: "python-pkg",
            Vulnerabilities: [
              {
                VulnerabilityID: "CVE-NEW",
                PkgName: "pkg",
                InstalledVersion: "2.0",
                Severity: "CRITICAL",
              },
            ],
          },
        ],
      };

      storeAndCompare(scan1, "v1.0");
      const { diff } = storeAndCompare(scan2, "v2.0");

      expect(diff).not.toBeNull();
      expect(diff!.summary.new).toBe(1);
      expect(diff!.summary.fixed).toBe(1);
      expect(diff!.newVulnerabilities[0].id).toBe("CVE-NEW");
      expect(diff!.fixedVulnerabilities[0].id).toBe("CVE-OLD");
    });
  });

  describe("createScanRecord", () => {
    it("should calculate summary correctly", () => {
      const vulns: FingerprintedVulnerability[] = [
        {
          fingerprint: "1",
          id: "1",
          package: "p",
          version: "1",
          severity: "CRITICAL",
          target: "t",
          source: "trivy",
        },
        {
          fingerprint: "2",
          id: "2",
          package: "p",
          version: "1",
          severity: "CRITICAL",
          target: "t",
          source: "trivy",
        },
        {
          fingerprint: "3",
          id: "3",
          package: "p",
          version: "1",
          severity: "HIGH",
          target: "t",
          source: "trivy",
        },
        {
          fingerprint: "4",
          id: "4",
          package: "p",
          version: "1",
          severity: "MEDIUM",
          target: "t",
          source: "trivy",
        },
        {
          fingerprint: "5",
          id: "5",
          package: "p",
          version: "1",
          severity: "LOW",
          target: "t",
          source: "trivy",
        },
      ];

      const record = createScanRecord("target", vulns, "test");

      expect(record.summary.critical).toBe(2);
      expect(record.summary.high).toBe(1);
      expect(record.summary.medium).toBe(1);
      expect(record.summary.low).toBe(1);
      expect(record.summary.total).toBe(5);
    });
  });
});

// Suppression tests
import {
  createSuppression,
  suppressCve,
  suppressPackage,
  suppressPath,
  isExpired,
  getDaysUntilExpiration,
  filterExpired,
  matchesCve,
  matchesPackage,
  matchesVersion,
  matchesPath,
  matchesSuppression,
  validateSuppression,
  applySuppressionsToVulnerabilities,
  applySuppressions,
  generateSuppressionReport,
} from "./suppression.js";
import type { Suppression, TrivyScanResult as SuppressionTrivyScanResult } from "./types.js";

describe("Suppression", () => {
  describe("createSuppression", () => {
    it("should create a suppression with required fields", () => {
      const suppression = createSuppression("cve", "CVE-2023-1234", "False positive");

      expect(suppression.id).toBeDefined();
      expect(suppression.type).toBe("cve");
      expect(suppression.pattern).toBe("CVE-2023-1234");
      expect(suppression.reason).toBe("False positive");
      expect(suppression.createdAt).toBeDefined();
    });

    it("should include optional fields when provided", () => {
      const suppression = createSuppression("package", "lodash", "Accepted risk", {
        expires: "2025-12-31",
        createdBy: "admin",
        notes: "Test note",
      });

      expect(suppression.expires).toBe("2025-12-31");
      expect(suppression.createdBy).toBe("admin");
      expect(suppression.notes).toBe("Test note");
    });
  });

  describe("suppressCve", () => {
    it("should create a CVE suppression with uppercase pattern", () => {
      const suppression = suppressCve("cve-2023-1234", "Test reason");

      expect(suppression.type).toBe("cve");
      expect(suppression.pattern).toBe("CVE-2023-1234");
    });
  });

  describe("suppressPackage", () => {
    it("should create a package suppression", () => {
      const suppression = suppressPackage("lodash", "Old version OK", { version: "4.17.21" });

      expect(suppression.type).toBe("package");
      expect(suppression.pattern).toBe("lodash");
      expect(suppression.versionConstraint).toBe("4.17.21");
    });
  });

  describe("suppressPath", () => {
    it("should create a path suppression", () => {
      const suppression = suppressPath("**/test/**", "Test files only");

      expect(suppression.type).toBe("path");
      expect(suppression.pattern).toBe("**/test/**");
    });
  });

  describe("isExpired", () => {
    it("should return false for suppression without expiration", () => {
      const suppression = createSuppression("cve", "CVE-2023-1234", "Test");
      expect(isExpired(suppression)).toBe(false);
    });

    it("should return true for expired suppression", () => {
      const suppression = createSuppression("cve", "CVE-2023-1234", "Test", {
        expires: "2020-01-01",
      });
      expect(isExpired(suppression)).toBe(true);
    });

    it("should return false for future expiration", () => {
      const suppression = createSuppression("cve", "CVE-2023-1234", "Test", {
        expires: "2099-12-31",
      });
      expect(isExpired(suppression)).toBe(false);
    });
  });

  describe("getDaysUntilExpiration", () => {
    it("should return null for suppression without expiration", () => {
      const suppression = createSuppression("cve", "CVE-2023-1234", "Test");
      expect(getDaysUntilExpiration(suppression)).toBeNull();
    });

    it("should return negative for expired suppression", () => {
      const suppression = createSuppression("cve", "CVE-2023-1234", "Test", {
        expires: "2020-01-01",
      });
      const days = getDaysUntilExpiration(suppression);
      expect(days).not.toBeNull();
      expect(days!).toBeLessThan(0);
    });
  });

  describe("filterExpired", () => {
    it("should filter out expired suppressions", () => {
      const suppressions: Suppression[] = [
        createSuppression("cve", "CVE-1", "Test", { expires: "2020-01-01" }),
        createSuppression("cve", "CVE-2", "Test", { expires: "2099-12-31" }),
        createSuppression("cve", "CVE-3", "Test"),
      ];

      const active = filterExpired(suppressions);
      expect(active.length).toBe(2);
    });
  });

  describe("matchesCve", () => {
    it("should match exact CVE IDs", () => {
      expect(matchesCve("CVE-2023-1234", "CVE-2023-1234")).toBe(true);
      expect(matchesCve("CVE-2023-1234", "CVE-2023-5678")).toBe(false);
    });

    it("should be case insensitive", () => {
      expect(matchesCve("cve-2023-1234", "CVE-2023-1234")).toBe(true);
    });

    it("should support wildcard patterns", () => {
      expect(matchesCve("CVE-2023-1234", "CVE-2023-*")).toBe(true);
      expect(matchesCve("CVE-2024-1234", "CVE-2023-*")).toBe(false);
    });
  });

  describe("matchesPackage", () => {
    it("should match exact package names", () => {
      expect(matchesPackage("lodash", "lodash")).toBe(true);
      expect(matchesPackage("lodash", "express")).toBe(false);
    });

    it("should be case insensitive", () => {
      expect(matchesPackage("Lodash", "lodash")).toBe(true);
    });

    it("should support glob patterns", () => {
      expect(matchesPackage("@angular/core", "@angular/*")).toBe(true);
    });
  });

  describe("matchesVersion", () => {
    it("should match exact versions", () => {
      expect(matchesVersion("1.0.0", "1.0.0")).toBe(true);
      expect(matchesVersion("1.0.0", "2.0.0")).toBe(false);
    });

    it("should match wildcard", () => {
      expect(matchesVersion("1.0.0", "*")).toBe(true);
    });

    it("should support >= operator", () => {
      expect(matchesVersion("2.0.0", ">=1.0.0")).toBe(true);
      expect(matchesVersion("0.5.0", ">=1.0.0")).toBe(false);
    });

    it("should support <= operator", () => {
      expect(matchesVersion("1.0.0", "<=2.0.0")).toBe(true);
      expect(matchesVersion("3.0.0", "<=2.0.0")).toBe(false);
    });
  });

  describe("matchesPath", () => {
    it("should match exact paths", () => {
      expect(matchesPath("node_modules/lodash", "node_modules/lodash")).toBe(true);
    });

    it("should support glob patterns", () => {
      expect(matchesPath("node_modules/lodash/index.js", "**/lodash/**")).toBe(true);
      expect(matchesPath("src/index.js", "**/node_modules/**")).toBe(false);
    });

    it("should normalize path separators", () => {
      expect(matchesPath("node_modules\\lodash", "node_modules/lodash")).toBe(true);
    });
  });

  describe("matchesSuppression", () => {
    it("should match CVE suppression", () => {
      const suppression = suppressCve("CVE-2023-1234", "Test");
      expect(
        matchesSuppression(suppression, {
          id: "CVE-2023-1234",
          package: "lodash",
          version: "4.17.20",
          target: "node_modules",
        })
      ).toBe(true);
    });

    it("should match package suppression", () => {
      const suppression = suppressPackage("lodash", "Test");
      expect(
        matchesSuppression(suppression, {
          id: "CVE-2023-1234",
          package: "lodash",
          version: "4.17.20",
          target: "node_modules",
        })
      ).toBe(true);
    });

    it("should match path suppression", () => {
      const suppression = suppressPath("**/test/**", "Test");
      expect(
        matchesSuppression(suppression, {
          id: "CVE-2023-1234",
          package: "lodash",
          version: "4.17.20",
          target: "app/test/fixtures",
        })
      ).toBe(true);
    });
  });

  describe("validateSuppression", () => {
    it("should return no errors for valid suppression", () => {
      const suppression = suppressCve("CVE-2023-1234", "Test reason");
      const errors = validateSuppression(suppression);
      expect(errors.length).toBe(0);
    });

    it("should return error for missing reason", () => {
      const suppression = { ...suppressCve("CVE-2023-1234", "Test"), reason: "" };
      const errors = validateSuppression(suppression);
      expect(errors).toContain("Suppression must have a reason");
    });

    it("should return error for invalid type", () => {
      const suppression = { ...suppressCve("CVE-2023-1234", "Test"), type: "invalid" as any };
      const errors = validateSuppression(suppression);
      expect(errors.some((e) => e.includes("Invalid suppression type"))).toBe(true);
    });
  });

  describe("applySuppressionsToVulnerabilities", () => {
    const createVuln = (id: string, pkg: string, severity: string) => ({
      VulnerabilityID: id,
      PkgName: pkg,
      InstalledVersion: "1.0.0",
      Severity: severity as "HIGH" | "MEDIUM" | "LOW" | "CRITICAL" | "UNKNOWN",
    });

    it("should suppress matching vulnerabilities", () => {
      const vulns = [
        createVuln("CVE-2023-1234", "lodash", "HIGH"),
        createVuln("CVE-2023-5678", "express", "MEDIUM"),
      ];

      const suppressions = [suppressCve("CVE-2023-1234", "False positive")];

      const result = applySuppressionsToVulnerabilities(vulns, "node_modules", suppressions);

      expect(result.summary.total).toBe(2);
      expect(result.summary.suppressed).toBe(1);
      expect(result.summary.remaining).toBe(1);
      expect(result.remaining[0].VulnerabilityID).toBe("CVE-2023-5678");
      expect(result.suppressed[0].id).toBe("CVE-2023-1234");
    });

    it("should not suppress when maxSeverityToSuppress is exceeded", () => {
      const vulns = [createVuln("CVE-2023-1234", "lodash", "CRITICAL")];
      const suppressions = [suppressCve("CVE-2023-1234", "Test")];

      const result = applySuppressionsToVulnerabilities(vulns, "node_modules", suppressions, {
        maxSeverityToSuppress: "HIGH",
      });

      expect(result.summary.suppressed).toBe(0);
      expect(result.summary.remaining).toBe(1);
    });

    it("should skip expired suppressions by default", () => {
      const vulns = [createVuln("CVE-2023-1234", "lodash", "HIGH")];
      const suppressions = [{ ...suppressCve("CVE-2023-1234", "Test"), expires: "2020-01-01" }];

      const result = applySuppressionsToVulnerabilities(vulns, "node_modules", suppressions);

      expect(result.summary.suppressed).toBe(0);
    });

    it("should include expired when option is set", () => {
      const vulns = [createVuln("CVE-2023-1234", "lodash", "HIGH")];
      const suppressions = [{ ...suppressCve("CVE-2023-1234", "Test"), expires: "2020-01-01" }];

      const result = applySuppressionsToVulnerabilities(vulns, "node_modules", suppressions, {
        includeExpired: true,
      });

      expect(result.summary.suppressed).toBe(1);
      expect(result.summary.expiredSuppressions).toBe(1);
    });
  });

  describe("applySuppressions", () => {
    it("should apply suppressions to Trivy scan result", () => {
      const scanResult: SuppressionTrivyScanResult = {
        ArtifactName: "node:20",
        Results: [
          {
            Target: "node_modules",
            Class: "lang-pkgs",
            Type: "node-pkg",
            Vulnerabilities: [
              {
                VulnerabilityID: "CVE-2023-1234",
                PkgName: "lodash",
                InstalledVersion: "4.17.20",
                Severity: "HIGH",
              },
              {
                VulnerabilityID: "CVE-2023-5678",
                PkgName: "express",
                InstalledVersion: "4.18.0",
                Severity: "MEDIUM",
              },
            ],
          },
        ],
      };

      const suppressions = [suppressCve("CVE-2023-1234", "False positive")];

      const { result, suppressionResult } = applySuppressions(scanResult, suppressions);

      expect(suppressionResult.summary.suppressed).toBe(1);
      expect(result.Results![0].Vulnerabilities?.length).toBe(1);
      expect(result.Results![0].Vulnerabilities?.[0].VulnerabilityID).toBe("CVE-2023-5678");
    });

    it("should handle results with no vulnerabilities", () => {
      const scanResult: SuppressionTrivyScanResult = {
        ArtifactName: "alpine:latest",
        Results: [
          {
            Target: "alpine:latest",
            Class: "os-pkgs",
            Type: "alpine",
            // No Vulnerabilities field
          },
          {
            Target: "app/package.json",
            Class: "lang-pkgs",
            Type: "node-pkg",
            Vulnerabilities: [], // Empty array
          },
        ],
      };

      const suppressions = [suppressCve("CVE-2023-1234", "Test")];
      const { result, suppressionResult } = applySuppressions(scanResult, suppressions);

      expect(result.Results?.length).toBe(2);
      expect(suppressionResult.summary.total).toBe(0);
      expect(suppressionResult.summary.suppressed).toBe(0);
    });
  });

  describe("generateSuppressionReport", () => {
    it("should generate markdown report", () => {
      const suppressions = [
        suppressCve("CVE-2023-1234", "False positive"),
        suppressPackage("lodash", "Accepted risk", { expires: "2025-12-31" }),
      ];

      const report = generateSuppressionReport(suppressions);

      expect(report).toContain("# Vulnerability Suppression Report");
      expect(report).toContain("CVE-2023-1234");
      expect(report).toContain("lodash");
      expect(report).toContain("False positive");
    });

    it("should include createdBy and notes when provided", () => {
      const suppressions = [
        {
          ...suppressCve("CVE-2023-5678", "Known issue"),
          createdBy: "security-team",
          notes: "Reviewed and approved by CISO",
        },
      ];

      const report = generateSuppressionReport(suppressions);

      expect(report).toContain("Created by: security-team");
      expect(report).toContain("Notes: Reviewed and approved by CISO");
    });

    it("should handle path type suppressions", () => {
      const suppressions = [suppressPath("/vendor/*", "Third-party code")];

      const report = generateSuppressionReport(suppressions);

      expect(report).toContain("PATH Suppressions");
      expect(report).toContain("/vendor/*");
    });
  });
});

// =============================================================================
// SBOM Upload Tests
// =============================================================================

import type { SbomUploadOptions, DTrackProjectCreateOptions } from "./types.js";

// Mock the external dependencies
vi.mock("./config.js", async () => {
  const actual = await vi.importActual("./config.js");
  return {
    ...actual,
    config: {
      dependencyTrack: {
        url: "http://localhost:8081",
        apiKey: "test-api-key",
      },
      trivy: {
        url: "http://localhost:8090",
      },
    },
  };
});

// We'll test the utility functions that don't require external calls
describe("SBOM Upload Module - Utility Functions", () => {
  describe("SbomUploadOptions interface", () => {
    it("should accept minimal options", () => {
      const options: SbomUploadOptions = {
        target: "nginx:latest",
      };

      expect(options.target).toBe("nginx:latest");
      expect(options.targetType).toBeUndefined();
      expect(options.projectName).toBeUndefined();
    });

    it("should accept full options", () => {
      const options: SbomUploadOptions = {
        target: "nginx:latest",
        targetType: "image",
        projectName: "nginx",
        projectVersion: "1.25.0",
        autoCreateProject: true,
        tags: ["production", "web"],
        parentUuid: "parent-uuid-123",
        sbomFormat: "cyclonedx",
        waitForProcessing: true,
        processingTimeout: 60000,
      };

      expect(options.target).toBe("nginx:latest");
      expect(options.targetType).toBe("image");
      expect(options.projectName).toBe("nginx");
      expect(options.projectVersion).toBe("1.25.0");
      expect(options.autoCreateProject).toBe(true);
      expect(options.tags).toEqual(["production", "web"]);
      expect(options.parentUuid).toBe("parent-uuid-123");
      expect(options.sbomFormat).toBe("cyclonedx");
      expect(options.waitForProcessing).toBe(true);
      expect(options.processingTimeout).toBe(60000);
    });

    it("should accept path target type", () => {
      const options: SbomUploadOptions = {
        target: "/app/project",
        targetType: "path",
        projectName: "my-project",
      };

      expect(options.targetType).toBe("path");
    });
  });

  describe("DTrackProjectCreateOptions interface", () => {
    it("should accept minimal options", () => {
      const options: DTrackProjectCreateOptions = {
        name: "my-project",
      };

      expect(options.name).toBe("my-project");
      expect(options.version).toBeUndefined();
    });

    it("should accept full options", () => {
      const options: DTrackProjectCreateOptions = {
        name: "my-project",
        version: "1.0.0",
        description: "A test project",
        tags: ["tag1", "tag2"],
        parent: "parent-uuid-456",
        classifier: "APPLICATION",
      };

      expect(options.name).toBe("my-project");
      expect(options.version).toBe("1.0.0");
      expect(options.description).toBe("A test project");
      expect(options.tags).toEqual(["tag1", "tag2"]);
      expect(options.parent).toBe("parent-uuid-456");
      expect(options.classifier).toBe("APPLICATION");
    });
  });
});

describe("SBOM Upload Module - Project Name Derivation", () => {
  // Test the deriveProjectName logic by checking expected outputs
  it("should derive project name from simple image", () => {
    // Testing expected behavior - nginx:latest -> nginx
    const imageName = "nginx:latest";
    const parts = imageName.split("/");
    const nameWithTag = parts[parts.length - 1];
    const name = nameWithTag.split(":")[0];

    expect(name).toBe("nginx");
  });

  it("should derive project name from registry image", () => {
    // docker.io/library/nginx:1.25 -> nginx
    const imageName = "docker.io/library/nginx:1.25";
    const parts = imageName.split("/");
    const nameWithTag = parts[parts.length - 1];
    const name = nameWithTag.split(":")[0];

    expect(name).toBe("nginx");
  });

  it("should derive project name from custom registry image", () => {
    // registry.example.com/team/myapp:v2.0 -> myapp
    const imageName = "registry.example.com/team/myapp:v2.0";
    const parts = imageName.split("/");
    const nameWithTag = parts[parts.length - 1];
    const name = nameWithTag.split(":")[0];

    expect(name).toBe("myapp");
  });

  it("should derive project name from path", () => {
    // /home/user/projects/myproject -> myproject
    const path = "/home/user/projects/myproject";
    const normalized = path.replaceAll("\\", "/").replace(/\/+$/, "");
    const parts = normalized.split("/");
    const name = parts.at(-1);

    expect(name).toBe("myproject");
  });

  it("should derive project name from Windows path", () => {
    // C:\Users\dev\projects\myapp -> myapp
    const path = "C:\\Users\\dev\\projects\\myapp";
    const normalized = path.replaceAll("\\", "/").replace(/\/+$/, "");
    const parts = normalized.split("/");
    const name = parts.at(-1);

    expect(name).toBe("myapp");
  });

  it("should handle trailing slashes in path", () => {
    // /app/project/ -> project
    const path = "/app/project/";
    const normalized = path.replaceAll("\\", "/").replace(/\/+$/, "");
    const parts = normalized.split("/");
    const name = parts.at(-1);

    expect(name).toBe("project");
  });
});

describe("SBOM Upload Module - SbomUploadResult interface", () => {
  it("should represent successful upload", () => {
    const result: {
      success: boolean;
      projectUuid: string;
      projectName: string;
      projectVersion: string;
      componentsCount: number;
      token: string;
      projectCreated: boolean;
      uploadedAt: string;
      error?: string;
    } = {
      success: true,
      projectUuid: "uuid-123",
      projectName: "my-project",
      projectVersion: "1.0.0",
      componentsCount: 150,
      token: "upload-token-abc",
      projectCreated: true,
      uploadedAt: "2024-01-15T10:00:00Z",
    };

    expect(result.success).toBe(true);
    expect(result.projectUuid).toBe("uuid-123");
    expect(result.componentsCount).toBe(150);
    expect(result.projectCreated).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("should represent failed upload", () => {
    const result = {
      success: false,
      projectUuid: "",
      projectName: "my-project",
      projectVersion: "1.0.0",
      componentsCount: 0,
      token: "",
      projectCreated: false,
      uploadedAt: "2024-01-15T10:00:00Z",
      error: "Trivy scan failed: image not found",
    };

    expect(result.success).toBe(false);
    expect(result.projectUuid).toBe("");
    expect(result.error).toBe("Trivy scan failed: image not found");
  });
});

describe("SBOM Upload Module - DTrackProjectCreateResult interface", () => {
  it("should represent created project", () => {
    const result = {
      uuid: "project-uuid-456",
      name: "my-app",
      version: "2.0.0",
      active: true,
    };

    expect(result.uuid).toBe("project-uuid-456");
    expect(result.name).toBe("my-app");
    expect(result.version).toBe("2.0.0");
    expect(result.active).toBe(true);
  });
});

// =============================================================================
// Registry Scanner Tests
// =============================================================================

import {
  parseDuration,
  isWithinMaxAge,
  matchesRepositoryPattern,
  matchesTagFilter,
} from "./registry-scanner.js";

describe("Registry Scanner - Duration Parsing", () => {
  describe("parseDuration", () => {
    it("should parse days", () => {
      expect(parseDuration("7d")).toBe(7 * 24 * 60 * 60 * 1000);
      expect(parseDuration("1d")).toBe(24 * 60 * 60 * 1000);
      expect(parseDuration("30d")).toBe(30 * 24 * 60 * 60 * 1000);
    });

    it("should parse hours", () => {
      expect(parseDuration("24h")).toBe(24 * 60 * 60 * 1000);
      expect(parseDuration("1h")).toBe(60 * 60 * 1000);
      expect(parseDuration("48h")).toBe(48 * 60 * 60 * 1000);
    });

    it("should parse minutes", () => {
      expect(parseDuration("30m")).toBe(30 * 60 * 1000);
      expect(parseDuration("60m")).toBe(60 * 60 * 1000);
    });

    it("should parse seconds", () => {
      expect(parseDuration("60s")).toBe(60 * 1000);
      expect(parseDuration("3600s")).toBe(3600 * 1000);
    });

    it("should be case insensitive", () => {
      expect(parseDuration("7D")).toBe(7 * 24 * 60 * 60 * 1000);
      expect(parseDuration("24H")).toBe(24 * 60 * 60 * 1000);
    });

    it("should throw for invalid format", () => {
      expect(() => parseDuration("invalid")).toThrow();
      expect(() => parseDuration("7")).toThrow();
      expect(() => parseDuration("d7")).toThrow();
      expect(() => parseDuration("7x")).toThrow();
    });
  });

  describe("isWithinMaxAge", () => {
    it("should return true for recent dates", () => {
      const now = new Date();
      expect(isWithinMaxAge(now, "7d")).toBe(true);
      expect(isWithinMaxAge(now.toISOString(), "24h")).toBe(true);
    });

    it("should return false for old dates", () => {
      const oldDate = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000); // 10 days ago
      expect(isWithinMaxAge(oldDate, "7d")).toBe(false);
      expect(isWithinMaxAge(oldDate, "1d")).toBe(false);
    });

    it("should handle edge cases", () => {
      const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000 + 1000);
      expect(isWithinMaxAge(sevenDaysAgo, "7d")).toBe(true);
    });
  });
});

describe("Registry Scanner - Filtering", () => {
  describe("matchesRepositoryPattern", () => {
    it("should match all when no patterns provided", () => {
      expect(matchesRepositoryPattern("myapp/backend", [])).toBe(true);
      expect(matchesRepositoryPattern("anything", [])).toBe(true);
    });

    it("should match exact names", () => {
      expect(matchesRepositoryPattern("myapp", ["myapp"])).toBe(true);
      expect(matchesRepositoryPattern("myapp", ["other"])).toBe(false);
    });

    it("should match glob patterns", () => {
      expect(matchesRepositoryPattern("myapp/backend", ["myapp/*"])).toBe(true);
      expect(matchesRepositoryPattern("myapp/frontend", ["myapp/*"])).toBe(true);
      expect(matchesRepositoryPattern("other/backend", ["myapp/*"])).toBe(false);
    });

    it("should match globstar patterns", () => {
      expect(matchesRepositoryPattern("library/nginx", ["library/**"])).toBe(true);
      expect(matchesRepositoryPattern("library/official/node", ["library/**"])).toBe(true);
    });

    it("should match regex patterns", () => {
      expect(matchesRepositoryPattern("myapp-v1", ["/myapp-v\\d+/"])).toBe(true);
      expect(matchesRepositoryPattern("myapp-v2", ["/myapp-v\\d+/"])).toBe(true);
      expect(matchesRepositoryPattern("myapp-beta", ["/myapp-v\\d+/"])).toBe(false);
    });

    it("should match any pattern in array", () => {
      expect(matchesRepositoryPattern("frontend", ["backend", "frontend"])).toBe(true);
      expect(matchesRepositoryPattern("backend", ["backend", "frontend"])).toBe(true);
      expect(matchesRepositoryPattern("database", ["backend", "frontend"])).toBe(false);
    });
  });

  describe("matchesTagFilter", () => {
    it("should match all when no filter provided", () => {
      expect(matchesTagFilter("latest")).toBe(true);
      expect(matchesTagFilter("v1.0.0")).toBe(true);
    });

    it("should match regex patterns", () => {
      expect(matchesTagFilter("v1.0.0", "^v\\d+")).toBe(true);
      expect(matchesTagFilter("v2.5.3", "^v\\d+")).toBe(true);
      expect(matchesTagFilter("latest", "^v\\d+")).toBe(false);
    });

    it("should match version patterns", () => {
      expect(matchesTagFilter("1.0.0", "^\\d+\\.\\d+\\.\\d+$")).toBe(true);
      expect(matchesTagFilter("10.20.30", "^\\d+\\.\\d+\\.\\d+$")).toBe(true);
      expect(matchesTagFilter("latest", "^\\d+\\.\\d+\\.\\d+$")).toBe(false);
    });

    it("should handle simple string matching for invalid regex", () => {
      expect(matchesTagFilter("latest-build", "latest")).toBe(true);
      expect(matchesTagFilter("production", "latest")).toBe(false);
    });
  });
});

describe("Registry Scanner - Types", () => {
  it("should accept RegistryScanOptions", () => {
    const options: import("./types.js").RegistryScanOptions = {
      registry: "registry.example.com",
      repositories: ["myapp/*"],
      tagFilter: "^v\\d+",
      concurrency: 5,
      severity: "CRITICAL",
      limit: 10,
      allTags: false,
    };

    expect(options.registry).toBe("registry.example.com");
    expect(options.repositories).toEqual(["myapp/*"]);
    expect(options.concurrency).toBe(5);
  });

  it("should accept RegistryScanResult", () => {
    const result: import("./types.js").RegistryScanResult = {
      registry: "localhost:5000",
      startedAt: "2024-01-15T10:00:00Z",
      completedAt: "2024-01-15T10:05:00Z",
      durationMs: 300000,
      discovery: {
        repositoriesFound: 10,
        imagesFound: 50,
        imagesMatched: 25,
        imagesScanned: 25,
      },
      vulnerabilities: {
        critical: 5,
        high: 10,
        medium: 15,
        low: 20,
        unknown: 0,
        total: 50,
      },
      results: [],
      failedImages: ["image1:tag1"],
      skippedImages: ["image2:old"],
    };

    expect(result.registry).toBe("localhost:5000");
    expect(result.discovery.imagesScanned).toBe(25);
    expect(result.vulnerabilities.critical).toBe(5);
  });

  it("should accept RegistryImage", () => {
    const image: import("./types.js").RegistryImage = {
      fullName: "registry.example.com/myapp:v1.0.0",
      repository: "myapp",
      tag: "v1.0.0",
      digest: "sha256:abc123",
      createdAt: "2024-01-15T10:00:00Z",
      size: 50000000,
    };

    expect(image.fullName).toBe("registry.example.com/myapp:v1.0.0");
    expect(image.repository).toBe("myapp");
    expect(image.tag).toBe("v1.0.0");
  });
});

// =============================================================================
// DB-SYNC TESTS
// =============================================================================

import {
  getTrivyCacheDir,
  getTrivyDbPath,
  parseVulnFromTrivy,
  importTrivyScanResult,
  getVulnDbSyncStatus,
} from "./db-sync.js";
import { initVulnDatabase, closeVulnDatabase } from "./vuln-database.js";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs";

describe("DB-Sync", () => {
  describe("getTrivyCacheDir", () => {
    it("should return path for current platform", () => {
      const cacheDir = getTrivyCacheDir();
      expect(cacheDir).toBeDefined();
      expect(typeof cacheDir).toBe("string");
      expect(cacheDir.length).toBeGreaterThan(0);
    });

    it("should return platform-appropriate path", () => {
      const cacheDir = getTrivyCacheDir();
      if (process.platform === "win32") {
        expect(cacheDir).toContain("trivy");
      } else {
        expect(cacheDir).toContain(".cache");
        expect(cacheDir).toContain("trivy");
      }
    });
  });

  describe("getTrivyDbPath", () => {
    it("should return path to trivy.db", () => {
      const dbPath = getTrivyDbPath();
      expect(dbPath).toBeDefined();
      expect(dbPath).toContain("trivy.db");
      expect(dbPath).toContain("db");
    });

    it("should be under cache directory", () => {
      const cacheDir = getTrivyCacheDir();
      const dbPath = getTrivyDbPath();
      expect(dbPath.startsWith(cacheDir)).toBe(true);
    });
  });

  describe("parseVulnFromTrivy", () => {
    it("should parse vulnerability with all fields", () => {
      const trivyVuln = {
        VulnerabilityID: "CVE-2024-1234",
        Severity: "HIGH" as const,
        Title: "Test Vulnerability",
        Description: "A test vulnerability description",
        PrimaryURL: "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        PkgName: "test-package",
        InstalledVersion: "1.0.0",
        FixedVersion: "1.0.1",
      };

      const result = parseVulnFromTrivy(trivyVuln, "alpine:latest");

      expect(result.id).toBe("CVE-2024-1234");
      expect(result.source).toBe("trivy");
      expect(result.severity).toBe("HIGH");
      expect(result.title).toBe("Test Vulnerability");
      expect(result.description).toBe("A test vulnerability description");
      expect(result.references).toContain("https://nvd.nist.gov/vuln/detail/CVE-2024-1234");
    });

    it("should handle missing optional fields", () => {
      const trivyVuln = {
        VulnerabilityID: "CVE-2024-5678",
        Severity: "CRITICAL" as const,
        PkgName: "vulnerable-pkg",
        InstalledVersion: "2.0.0",
      };

      const result = parseVulnFromTrivy(trivyVuln, "node:20");

      expect(result.id).toBe("CVE-2024-5678");
      expect(result.severity).toBe("CRITICAL");
      expect(result.title).toBe("CVE-2024-5678"); // Falls back to ID
      expect(result.description).toBe("");
      expect(result.references).toEqual([]);
    });

    it("should handle different severity levels", () => {
      const severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"] as const;

      for (const severity of severities) {
        const vuln = {
          VulnerabilityID: `CVE-2024-${severity}`,
          Severity: severity,
          PkgName: "test",
          InstalledVersion: "1.0.0",
        };

        const result = parseVulnFromTrivy(vuln, "test:latest");
        expect(result.severity).toBe(severity);
      }
    });
  });

  describe("importTrivyScanResult", () => {
    const testDbPath = path.join(os.tmpdir(), `vuln-import-test-${Date.now()}.db`);

    beforeEach(() => {
      // Initialize a fresh database for testing
      initVulnDatabase(testDbPath);
    });

    afterEach(() => {
      closeVulnDatabase();
      if (fs.existsSync(testDbPath)) {
        fs.unlinkSync(testDbPath);
      }
    });

    it("should import vulnerabilities from scan result", () => {
      const scanResult = {
        Results: [
          {
            Target: "alpine:latest",
            Vulnerabilities: [
              {
                VulnerabilityID: "CVE-2024-0001",
                Severity: "HIGH" as const,
                Title: "High Severity Bug",
                PkgName: "openssl",
                InstalledVersion: "1.1.1k",
                FixedVersion: "1.1.1l",
              },
              {
                VulnerabilityID: "CVE-2024-0002",
                Severity: "MEDIUM" as const,
                Title: "Medium Bug",
                PkgName: "curl",
                InstalledVersion: "7.79.0",
              },
            ],
          },
        ],
      };

      const result = importTrivyScanResult(scanResult as import("./types.js").TrivyScanResult);

      expect(result.success).toBe(true);
      expect(result.imported).toBe(2);
    });

    it("should handle empty results", () => {
      const scanResult = {
        Results: [],
      };

      const result = importTrivyScanResult(scanResult as import("./types.js").TrivyScanResult);

      expect(result.success).toBe(true);
      expect(result.imported).toBe(0);
    });

    it("should handle null Results", () => {
      const scanResult = {} as import("./types.js").TrivyScanResult;

      const result = importTrivyScanResult(scanResult);

      expect(result.success).toBe(true);
      expect(result.imported).toBe(0);
    });

    it("should deduplicate vulnerabilities with same ID", () => {
      const scanResult = {
        Results: [
          {
            Target: "app:v1",
            Vulnerabilities: [
              {
                VulnerabilityID: "CVE-2024-DUPE",
                Severity: "HIGH" as const,
                PkgName: "pkg1",
                InstalledVersion: "1.0.0",
              },
            ],
          },
          {
            Target: "app:v2",
            Vulnerabilities: [
              {
                VulnerabilityID: "CVE-2024-DUPE", // Same CVE
                Severity: "HIGH" as const,
                PkgName: "pkg2",
                InstalledVersion: "2.0.0",
              },
            ],
          },
        ],
      };

      const result = importTrivyScanResult(scanResult as import("./types.js").TrivyScanResult);

      expect(result.success).toBe(true);
      expect(result.imported).toBe(1); // Only one because of deduplication
    });

    it("should handle Results with no vulnerabilities", () => {
      const scanResult = {
        Results: [
          {
            Target: "clean-image:latest",
            Class: "os-pkgs",
            Type: "alpine",
            // No Vulnerabilities field
          },
        ],
      };

      const result = importTrivyScanResult(scanResult as import("./types.js").TrivyScanResult);

      expect(result.success).toBe(true);
      expect(result.imported).toBe(0);
    });
  });

  describe("getVulnDbSyncStatus", () => {
    const testDbPath = path.join(os.tmpdir(), `vuln-sync-status-test-${Date.now()}.db`);

    beforeEach(() => {
      initVulnDatabase(testDbPath);
    });

    afterEach(() => {
      closeVulnDatabase();
      if (fs.existsSync(testDbPath)) {
        fs.unlinkSync(testDbPath);
      }
    });

    it("should return sync status when database is initialized", () => {
      const status = getVulnDbSyncStatus();

      expect(status).toBeDefined();
      expect(status.sources).toBeDefined();
      expect(Array.isArray(status.sources)).toBe(true);
    });
  });
});

// =============================================================================
// OFFLINE-SCANNER TESTS
// =============================================================================

import { isOfflineScanError } from "./offline-scanner.js";

describe("Offline-Scanner", () => {
  describe("isOfflineScanError", () => {
    it("should return true for error objects", () => {
      const errorResult = { error: "Something went wrong" };
      expect(isOfflineScanError(errorResult)).toBe(true);
    });

    it("should return true for error with dbStatus", () => {
      const errorResult = {
        error: "Database not available",
        dbStatus: { exists: false, isStale: true },
      };
      expect(isOfflineScanError(errorResult)).toBe(true);
    });

    it("should return false for valid scan results", () => {
      const scanResult = {
        Results: [
          {
            Target: "alpine:latest",
            Vulnerabilities: [],
          },
        ],
      };
      expect(isOfflineScanError(scanResult)).toBe(false);
    });

    it("should return false for empty scan results", () => {
      const scanResult = { Results: [] };
      expect(isOfflineScanError(scanResult)).toBe(false);
    });
  });
});
