/**
 * Simple in-memory cache with TTL support for scan results
 */

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

export class ScanCache<T = unknown> {
  private readonly cache: Map<string, CacheEntry<T>> = new Map();
  private readonly defaultTtlMs: number;

  /**
   * Create a new cache instance
   * @param defaultTtlMs Default time-to-live in milliseconds (default: 5 minutes)
   */
  constructor(defaultTtlMs: number = 5 * 60 * 1000) {
    this.defaultTtlMs = defaultTtlMs;
  }

  /**
   * Generate a cache key from scan parameters
   */
  static generateKey(operation: string, ...params: (string | undefined)[]): string {
    return [operation, ...params.filter(Boolean)].join(":");
  }

  /**
   * Get a cached value
   * @returns The cached value or undefined if not found or expired
   */
  get(key: string): T | undefined {
    const entry = this.cache.get(key);
    if (!entry) {
      return undefined;
    }

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return undefined;
    }

    return entry.value;
  }

  /**
   * Set a cached value
   * @param key Cache key
   * @param value Value to cache
   * @param ttlMs Optional TTL override in milliseconds
   */
  set(key: string, value: T, ttlMs?: number): void {
    const ttl = ttlMs ?? this.defaultTtlMs;
    this.cache.set(key, {
      value,
      expiresAt: Date.now() + ttl,
    });
  }

  /**
   * Check if a key exists and is not expired
   */
  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  /**
   * Delete a cached entry
   */
  delete(key: string): boolean {
    return this.cache.delete(key);
  }

  /**
   * Clear all cached entries
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get the number of cached entries (including expired)
   */
  get size(): number {
    return this.cache.size;
  }

  /**
   * Remove all expired entries
   */
  prune(): number {
    const now = Date.now();
    let pruned = 0;
    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
        pruned++;
      }
    }
    return pruned;
  }
}

/**
 * Decorator function for caching async function results
 * @param cache The cache instance to use
 * @param keyGenerator Function to generate cache key from arguments
 * @param ttlMs Optional TTL override
 */
export function withCache<TArgs extends unknown[], TResult>(
  cache: ScanCache<TResult>,
  keyGenerator: (...args: TArgs) => string,
  ttlMs?: number
): (fn: (...args: TArgs) => Promise<TResult>) => (...args: TArgs) => Promise<TResult> {
  return (fn) => {
    return async (...args) => {
      const key = keyGenerator(...args);
      const cached = cache.get(key);
      if (cached !== undefined) {
        return cached;
      }

      const result = await fn(...args);
      cache.set(key, result, ttlMs);
      return result;
    };
  };
}

// Global cache instances for different scan types
export const trivyScanCache = new ScanCache(5 * 60 * 1000); // 5 minute TTL
export const sonarCache = new ScanCache(2 * 60 * 1000); // 2 minute TTL
export const dtrackCache = new ScanCache(2 * 60 * 1000); // 2 minute TTL
