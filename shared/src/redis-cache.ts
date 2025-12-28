/**
 * Redis-based distributed cache with in-memory fallback
 * Issue #19: Redis Caching Backend
 */

import { ScanCache } from "./cache.js";

// Redis client type (using ioredis)
type RedisClient = {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, expiryMode?: string, time?: number): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
  keys(pattern: string): Promise<string[]>;
  ping(): Promise<string>;
  quit(): Promise<string>;
  info(section?: string): Promise<string>;
  dbsize(): Promise<number>;
  flushdb(): Promise<string>;
};

export interface RedisConfig {
  host: string;
  port: number;
  password?: string;
  db?: number;
  keyPrefix?: string;
  connectTimeout?: number;
  maxRetriesPerRequest?: number;
  enableOfflineQueue?: boolean;
}

export interface CacheStats {
  type: "redis" | "memory";
  connected: boolean;
  keys?: number;
  memoryUsage?: string;
  uptime?: number;
  hits?: number;
  misses?: number;
}

export interface CacheTTLConfig {
  trivy: number;
  sonarqube: number;
  dtrack: number;
  registry: number;
  default: number;
}

export interface CacheHealthStatus {
  redis: {
    connected: boolean;
    latencyMs?: number;
    error?: string;
  };
  memory: {
    available: boolean;
    cacheCount: number;
  };
  mode: "redis" | "memory" | "hybrid";
}

// Default configuration
const DEFAULT_REDIS_CONFIG: RedisConfig = {
  host: "localhost",
  port: 6379,
  db: 0,
  keyPrefix: "cicd:",
  connectTimeout: 5000,
  maxRetriesPerRequest: 3,
  enableOfflineQueue: false,
};

const DEFAULT_TTL_CONFIG: CacheTTLConfig = {
  trivy: 300, // 5 minutes
  sonarqube: 600, // 10 minutes
  dtrack: 600, // 10 minutes
  registry: 1800, // 30 minutes
  default: 300, // 5 minutes
};

/**
 * Get Redis configuration from environment variables
 */
export function getRedisConfig(): RedisConfig {
  return {
    host: process.env.REDIS_HOST || DEFAULT_REDIS_CONFIG.host,
    port: Number.parseInt(process.env.REDIS_PORT || String(DEFAULT_REDIS_CONFIG.port), 10),
    password: process.env.REDIS_PASSWORD || undefined,
    db: Number.parseInt(process.env.REDIS_DB || String(DEFAULT_REDIS_CONFIG.db), 10),
    keyPrefix: process.env.REDIS_KEY_PREFIX || DEFAULT_REDIS_CONFIG.keyPrefix,
    connectTimeout: Number.parseInt(
      process.env.REDIS_CONNECT_TIMEOUT || String(DEFAULT_REDIS_CONFIG.connectTimeout),
      10
    ),
    maxRetriesPerRequest: Number.parseInt(
      process.env.REDIS_MAX_RETRIES || String(DEFAULT_REDIS_CONFIG.maxRetriesPerRequest),
      10
    ),
    enableOfflineQueue:
      process.env.REDIS_OFFLINE_QUEUE === "true" || DEFAULT_REDIS_CONFIG.enableOfflineQueue,
  };
}

/**
 * Get TTL configuration from environment variables
 */
export function getTTLConfig(): CacheTTLConfig {
  return {
    trivy: Number.parseInt(process.env.CACHE_TTL_TRIVY || String(DEFAULT_TTL_CONFIG.trivy), 10),
    sonarqube: Number.parseInt(
      process.env.CACHE_TTL_SONARQUBE || String(DEFAULT_TTL_CONFIG.sonarqube),
      10
    ),
    dtrack: Number.parseInt(process.env.CACHE_TTL_DTRACK || String(DEFAULT_TTL_CONFIG.dtrack), 10),
    registry: Number.parseInt(
      process.env.CACHE_TTL_REGISTRY || String(DEFAULT_TTL_CONFIG.registry),
      10
    ),
    default: Number.parseInt(
      process.env.CACHE_TTL_DEFAULT || String(DEFAULT_TTL_CONFIG.default),
      10
    ),
  };
}

// Global Redis client instance
let redisClient: RedisClient | null = null;
let redisConnected = false;

// Extended interface for ioredis client with connect method
interface IoRedisClient extends RedisClient {
  connect(): Promise<void>;
}

// Type for Redis constructor
type RedisConstructor = new (options: {
  host: string;
  port: number;
  password?: string;
  db?: number;
  keyPrefix?: string;
  connectTimeout?: number;
  maxRetriesPerRequest?: number;
  enableOfflineQueue?: boolean;
  lazyConnect?: boolean;
}) => IoRedisClient;

/**
 * Initialize Redis connection
 */
export async function initRedisConnection(config?: RedisConfig): Promise<boolean> {
  if (redisClient && redisConnected) {
    return true;
  }

  const cfg = config || getRedisConfig();

  try {
    // Dynamic import to avoid requiring ioredis if not used
    // Use type assertion since ioredis has complex export patterns
    const ioredisModule = await import("ioredis");
    const Redis = (ioredisModule.default ?? ioredisModule) as unknown as RedisConstructor;

    const client = new Redis({
      host: cfg.host,
      port: cfg.port,
      password: cfg.password,
      db: cfg.db,
      keyPrefix: cfg.keyPrefix,
      connectTimeout: cfg.connectTimeout,
      maxRetriesPerRequest: cfg.maxRetriesPerRequest,
      enableOfflineQueue: cfg.enableOfflineQueue,
      lazyConnect: true,
    });

    // Test connection
    await client.connect();
    await client.ping();

    redisClient = client;
    redisConnected = true;

    return true;
  } catch (error) {
    redisConnected = false;
    redisClient = null;
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`Redis connection failed, falling back to memory cache: ${message}`);
    return false;
  }
}

/**
 * Close Redis connection
 */
export async function closeRedisConnection(): Promise<void> {
  if (redisClient) {
    try {
      await redisClient.quit();
    } catch {
      // Ignore errors on close
    }
    redisClient = null;
    redisConnected = false;
  }
}

/**
 * Check if Redis is connected
 */
export function isRedisConnected(): boolean {
  return redisConnected && redisClient !== null;
}

/**
 * Get the Redis client (for advanced operations)
 */
export function getRedisClient(): RedisClient | null {
  return redisClient;
}

/**
 * Distributed cache with Redis backend and in-memory fallback
 */
export class DistributedCache<T> {
  private readonly memoryCache: ScanCache<T>;
  private readonly keyPrefix: string;
  private readonly ttlSeconds: number;
  private stats = { hits: 0, misses: 0 };

  constructor(name: string, ttlSeconds: number = DEFAULT_TTL_CONFIG.default) {
    this.keyPrefix = name;
    this.ttlSeconds = ttlSeconds;
    // Memory cache TTL in milliseconds
    this.memoryCache = new ScanCache<T>(ttlSeconds * 1000);
  }

  /**
   * Generate cache key
   */
  private getCacheKey(key: string): string {
    return `${this.keyPrefix}:${key}`;
  }

  /**
   * Get value from cache
   */
  async get(key: string): Promise<T | undefined> {
    const cacheKey = this.getCacheKey(key);

    // Try Redis first if connected
    if (isRedisConnected() && redisClient) {
      try {
        const value = await redisClient.get(cacheKey);
        if (value) {
          this.stats.hits++;
          return JSON.parse(value) as T;
        }
      } catch (error) {
        console.warn(`Redis get error for ${cacheKey}:`, error);
      }
    }

    // Fall back to memory cache
    const memValue = this.memoryCache.get(key);
    if (memValue !== undefined) {
      this.stats.hits++;
      return memValue;
    }

    this.stats.misses++;
    return undefined;
  }

  /**
   * Set value in cache
   */
  async set(key: string, value: T, ttlSeconds?: number): Promise<void> {
    const cacheKey = this.getCacheKey(key);
    const ttl = ttlSeconds ?? this.ttlSeconds;

    // Try Redis if connected
    if (isRedisConnected() && redisClient) {
      try {
        await redisClient.set(cacheKey, JSON.stringify(value), "EX", ttl);
      } catch (error) {
        console.warn(`Redis set error for ${cacheKey}:`, error);
      }
    }

    // Always set in memory cache as fallback
    this.memoryCache.set(key, value);
  }

  /**
   * Delete value from cache
   */
  async delete(key: string): Promise<boolean> {
    const cacheKey = this.getCacheKey(key);
    let deleted = false;

    // Try Redis if connected
    if (isRedisConnected() && redisClient) {
      try {
        const count = await redisClient.del(cacheKey);
        deleted = count > 0;
      } catch (error) {
        console.warn(`Redis delete error for ${cacheKey}:`, error);
      }
    }

    // Also delete from memory cache
    this.memoryCache.delete(key);

    return deleted;
  }

  /**
   * Clear all entries in this cache namespace
   */
  async clear(): Promise<void> {
    // Clear Redis keys with this prefix
    if (isRedisConnected() && redisClient) {
      try {
        const config = getRedisConfig();
        const pattern = `${config.keyPrefix}${this.keyPrefix}:*`;
        const keys = await redisClient.keys(pattern);
        if (keys.length > 0) {
          // Remove the global prefix from keys before deleting
          // since the client adds it automatically
          const keysWithoutGlobalPrefix = keys.map((k) =>
            k.startsWith(config.keyPrefix || "") ? k.slice((config.keyPrefix || "").length) : k
          );
          await redisClient.del(...keysWithoutGlobalPrefix);
        }
      } catch (error) {
        console.warn(`Redis clear error for ${this.keyPrefix}:`, error);
      }
    }

    // Clear memory cache
    this.memoryCache.clear();
  }

  /**
   * Check if key exists in cache
   */
  async has(key: string): Promise<boolean> {
    const value = await this.get(key);
    return value !== undefined;
  }

  /**
   * Get cache statistics
   */
  getStats(): { hits: number; misses: number; hitRate: number } {
    const total = this.stats.hits + this.stats.misses;
    return {
      hits: this.stats.hits,
      misses: this.stats.misses,
      hitRate: total > 0 ? this.stats.hits / total : 0,
    };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.stats = { hits: 0, misses: 0 };
  }
}

// Global cache instances for different scan types
let trivyCache: DistributedCache<unknown> | null = null;
let sonarqubeCache: DistributedCache<unknown> | null = null;
let dtrackCache: DistributedCache<unknown> | null = null;
let registryCache: DistributedCache<unknown> | null = null;

/**
 * Initialize all distributed caches
 */
export async function initDistributedCaches(
  tryRedis: boolean = true
): Promise<{ redis: boolean; memory: boolean }> {
  const ttlConfig = getTTLConfig();

  // Try to connect to Redis
  let redisOk = false;
  if (tryRedis) {
    redisOk = await initRedisConnection();
  }

  // Create cache instances
  trivyCache = new DistributedCache<unknown>("trivy", ttlConfig.trivy);
  sonarqubeCache = new DistributedCache<unknown>("sonarqube", ttlConfig.sonarqube);
  dtrackCache = new DistributedCache<unknown>("dtrack", ttlConfig.dtrack);
  registryCache = new DistributedCache<unknown>("registry", ttlConfig.registry);

  return { redis: redisOk, memory: true };
}

/**
 * Get Trivy cache instance
 */
export function getTrivyCache(): DistributedCache<unknown> {
  if (!trivyCache) {
    const ttlConfig = getTTLConfig();
    trivyCache = new DistributedCache<unknown>("trivy", ttlConfig.trivy);
  }
  return trivyCache;
}

/**
 * Get SonarQube cache instance
 */
export function getSonarqubeCache(): DistributedCache<unknown> {
  if (!sonarqubeCache) {
    const ttlConfig = getTTLConfig();
    sonarqubeCache = new DistributedCache<unknown>("sonarqube", ttlConfig.sonarqube);
  }
  return sonarqubeCache;
}

/**
 * Get Dependency-Track cache instance
 */
export function getDtrackCache(): DistributedCache<unknown> {
  if (!dtrackCache) {
    const ttlConfig = getTTLConfig();
    dtrackCache = new DistributedCache<unknown>("dtrack", ttlConfig.dtrack);
  }
  return dtrackCache;
}

/**
 * Get Registry cache instance
 */
export function getRegistryCache(): DistributedCache<unknown> {
  if (!registryCache) {
    const ttlConfig = getTTLConfig();
    registryCache = new DistributedCache<unknown>("registry", ttlConfig.registry);
  }
  return registryCache;
}

/**
 * Get all cache statistics
 */
export async function getAllCacheStats(): Promise<{
  trivy: ReturnType<DistributedCache<unknown>["getStats"]>;
  sonarqube: ReturnType<DistributedCache<unknown>["getStats"]>;
  dtrack: ReturnType<DistributedCache<unknown>["getStats"]>;
  registry: ReturnType<DistributedCache<unknown>["getStats"]>;
  redis: CacheStats | null;
}> {
  const stats = {
    trivy: getTrivyCache().getStats(),
    sonarqube: getSonarqubeCache().getStats(),
    dtrack: getDtrackCache().getStats(),
    registry: getRegistryCache().getStats(),
    redis: null as CacheStats | null,
  };

  // Get Redis stats if connected
  if (isRedisConnected() && redisClient) {
    try {
      const info = await redisClient.info("memory");
      const dbsize = await redisClient.dbsize();

      // Parse memory info
      const memoryMatch = /used_memory_human:(\S+)/.exec(info);
      const uptimeMatch = /uptime_in_seconds:(\d+)/.exec(info);

      stats.redis = {
        type: "redis",
        connected: true,
        keys: dbsize,
        memoryUsage: memoryMatch?.[1] || "unknown",
        uptime: uptimeMatch ? Number.parseInt(uptimeMatch[1], 10) : undefined,
      };
    } catch {
      // Redis stats unavailable - mark as disconnected
      stats.redis = {
        type: "redis",
        connected: false,
      };
    }
  }

  return stats;
}

/**
 * Clear all caches
 */
export async function clearAllCaches(): Promise<void> {
  await Promise.all([
    getTrivyCache().clear(),
    getSonarqubeCache().clear(),
    getDtrackCache().clear(),
    getRegistryCache().clear(),
  ]);
}

/**
 * Invalidate cache entries by pattern
 */
export async function invalidateCacheByPattern(pattern: string): Promise<number> {
  let deletedCount = 0;

  if (isRedisConnected() && redisClient) {
    try {
      const config = getRedisConfig();
      const fullPattern = `${config.keyPrefix}${pattern}`;
      const keys = await redisClient.keys(fullPattern);

      if (keys.length > 0) {
        const keysWithoutGlobalPrefix = keys.map((k) =>
          k.startsWith(config.keyPrefix || "") ? k.slice((config.keyPrefix || "").length) : k
        );
        deletedCount = await redisClient.del(...keysWithoutGlobalPrefix);
      }
    } catch (error) {
      console.warn(`Redis pattern invalidation error for ${pattern}:`, error);
    }
  }

  return deletedCount;
}

/**
 * Get cache health status
 */
export async function getCacheHealth(): Promise<CacheHealthStatus> {
  const health: CacheHealthStatus = {
    redis: {
      connected: false,
    },
    memory: {
      available: true,
      cacheCount: 4, // trivy, sonarqube, dtrack, registry
    },
    mode: "memory",
  };

  if (isRedisConnected() && redisClient) {
    try {
      const start = Date.now();
      await redisClient.ping();
      const latency = Date.now() - start;

      health.redis = {
        connected: true,
        latencyMs: latency,
      };
      health.mode = "hybrid";
    } catch (error) {
      health.redis = {
        connected: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  return health;
}

/**
 * Create a cache key from scan parameters
 */
export function createCacheKey(
  scanType: string,
  target: string,
  options?: Record<string, unknown>
): string {
  const parts = [scanType, target];

  if (options) {
    // Sort options for consistent key generation using localeCompare for reliable sorting
    const sortedOptions = Object.keys(options)
      .sort((a, b) => a.localeCompare(b))
      .map((k) => `${k}=${JSON.stringify(options[k])}`)
      .join(",");
    if (sortedOptions) {
      parts.push(sortedOptions);
    }
  }

  // Create a hash-like string (simple for now, could use crypto)
  const keyString = parts.join(":");

  // Simple hash function for cache keys
  let hash = 0;
  for (let i = 0; i < keyString.length; i++) {
    const char = keyString.codePointAt(i) ?? 0;
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32-bit integer
  }

  return `${scanType}:${Math.abs(hash).toString(16)}`;
}
