import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  getRedisConfig,
  getTTLConfig,
  DistributedCache,
  createCacheKey,
  isRedisConnected,
} from "./redis-cache.js";

describe("Redis Cache", () => {
  describe("getRedisConfig", () => {
    const originalEnv = process.env;

    beforeEach(() => {
      vi.resetModules();
      process.env = { ...originalEnv };
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it("should return default config when no env vars set", () => {
      delete process.env.REDIS_HOST;
      delete process.env.REDIS_PORT;
      delete process.env.REDIS_PASSWORD;
      delete process.env.REDIS_DB;
      delete process.env.REDIS_KEY_PREFIX;

      const config = getRedisConfig();

      expect(config.host).toBe("localhost");
      expect(config.port).toBe(6379);
      expect(config.password).toBeUndefined();
      expect(config.db).toBe(0);
      expect(config.keyPrefix).toBe("cicd:");
    });

    it("should use environment variables when set", () => {
      process.env.REDIS_HOST = "redis.example.com";
      process.env.REDIS_PORT = "6380";
      process.env.REDIS_PASSWORD = "secret123";
      process.env.REDIS_DB = "5";
      process.env.REDIS_KEY_PREFIX = "myapp:";

      const config = getRedisConfig();

      expect(config.host).toBe("redis.example.com");
      expect(config.port).toBe(6380);
      expect(config.password).toBe("secret123");
      expect(config.db).toBe(5);
      expect(config.keyPrefix).toBe("myapp:");
    });

    it("should handle connection timeout and retry settings", () => {
      process.env.REDIS_CONNECT_TIMEOUT = "10000";
      process.env.REDIS_MAX_RETRIES = "5";
      process.env.REDIS_OFFLINE_QUEUE = "true";

      const config = getRedisConfig();

      expect(config.connectTimeout).toBe(10000);
      expect(config.maxRetriesPerRequest).toBe(5);
      expect(config.enableOfflineQueue).toBe(true);
    });
  });

  describe("getTTLConfig", () => {
    const originalEnv = process.env;

    beforeEach(() => {
      vi.resetModules();
      process.env = { ...originalEnv };
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it("should return default TTL config when no env vars set", () => {
      delete process.env.CACHE_TTL_TRIVY;
      delete process.env.CACHE_TTL_SONARQUBE;
      delete process.env.CACHE_TTL_DTRACK;
      delete process.env.CACHE_TTL_REGISTRY;
      delete process.env.CACHE_TTL_DEFAULT;

      const config = getTTLConfig();

      expect(config.trivy).toBe(300);
      expect(config.sonarqube).toBe(600);
      expect(config.dtrack).toBe(600);
      expect(config.registry).toBe(1800);
      expect(config.default).toBe(300);
    });

    it("should use environment variables when set", () => {
      process.env.CACHE_TTL_TRIVY = "120";
      process.env.CACHE_TTL_SONARQUBE = "240";
      process.env.CACHE_TTL_DTRACK = "360";
      process.env.CACHE_TTL_REGISTRY = "900";
      process.env.CACHE_TTL_DEFAULT = "180";

      const config = getTTLConfig();

      expect(config.trivy).toBe(120);
      expect(config.sonarqube).toBe(240);
      expect(config.dtrack).toBe(360);
      expect(config.registry).toBe(900);
      expect(config.default).toBe(180);
    });
  });

  describe("createCacheKey", () => {
    it("should create key from scan type and target", () => {
      const key = createCacheKey("trivy", "alpine:latest");

      expect(key).toMatch(/^trivy:[a-f0-9]+$/);
    });

    it("should create consistent keys for same inputs", () => {
      const key1 = createCacheKey("trivy", "alpine:latest");
      const key2 = createCacheKey("trivy", "alpine:latest");

      expect(key1).toBe(key2);
    });

    it("should create different keys for different inputs", () => {
      const key1 = createCacheKey("trivy", "alpine:latest");
      const key2 = createCacheKey("trivy", "node:20");

      expect(key1).not.toBe(key2);
    });

    it("should include options in key generation", () => {
      const key1 = createCacheKey("trivy", "alpine:latest", { severity: "HIGH" });
      const key2 = createCacheKey("trivy", "alpine:latest", { severity: "CRITICAL" });

      expect(key1).not.toBe(key2);
    });

    it("should generate same key regardless of option order", () => {
      const key1 = createCacheKey("trivy", "alpine:latest", {
        severity: "HIGH",
        format: "json",
      });
      const key2 = createCacheKey("trivy", "alpine:latest", {
        format: "json",
        severity: "HIGH",
      });

      expect(key1).toBe(key2);
    });
  });

  describe("DistributedCache (memory fallback)", () => {
    let cache: DistributedCache<{ value: number }>;

    beforeEach(() => {
      // Create cache with short TTL for testing
      cache = new DistributedCache<{ value: number }>("test", 60);
    });

    it("should store and retrieve values", async () => {
      await cache.set("key1", { value: 42 });
      const result = await cache.get("key1");

      expect(result).toEqual({ value: 42 });
    });

    it("should return undefined for missing keys", async () => {
      const result = await cache.get("nonexistent");

      expect(result).toBeUndefined();
    });

    it("should delete values", async () => {
      await cache.set("key1", { value: 42 });
      await cache.delete("key1");
      const result = await cache.get("key1");

      expect(result).toBeUndefined();
    });

    it("should check if key exists", async () => {
      await cache.set("key1", { value: 42 });

      expect(await cache.has("key1")).toBe(true);
      expect(await cache.has("nonexistent")).toBe(false);
    });

    it("should clear all values", async () => {
      await cache.set("key1", { value: 1 });
      await cache.set("key2", { value: 2 });
      await cache.clear();

      expect(await cache.get("key1")).toBeUndefined();
      expect(await cache.get("key2")).toBeUndefined();
    });

    it("should track hit/miss statistics", async () => {
      cache.resetStats();
      await cache.set("key1", { value: 42 });

      // Miss
      await cache.get("nonexistent");

      // Hits
      await cache.get("key1");
      await cache.get("key1");

      const stats = cache.getStats();

      expect(stats.hits).toBe(2);
      expect(stats.misses).toBe(1);
      expect(stats.hitRate).toBeCloseTo(2 / 3, 2);
    });

    it("should reset statistics", async () => {
      await cache.set("key1", { value: 42 });
      await cache.get("key1");
      await cache.get("nonexistent");

      cache.resetStats();
      const stats = cache.getStats();

      expect(stats.hits).toBe(0);
      expect(stats.misses).toBe(0);
      expect(stats.hitRate).toBe(0);
    });
  });

  describe("isRedisConnected", () => {
    it("should return false when Redis is not initialized", () => {
      expect(isRedisConnected()).toBe(false);
    });
  });
});
