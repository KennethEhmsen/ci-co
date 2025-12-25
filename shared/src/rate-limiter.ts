/**
 * Rate Limiter for HTTP Requests
 *
 * Token bucket algorithm implementation to prevent overwhelming external services.
 */

export interface RateLimiterOptions {
  /** Maximum tokens in the bucket */
  maxTokens: number;
  /** Tokens added per interval */
  refillRate: number;
  /** Refill interval in milliseconds */
  refillInterval: number;
}

export class RateLimiter {
  private tokens: number;
  private readonly maxTokens: number;
  private readonly refillRate: number;
  private readonly refillInterval: number;
  private lastRefill: number;

  constructor(options: RateLimiterOptions) {
    this.maxTokens = options.maxTokens;
    this.refillRate = options.refillRate;
    this.refillInterval = options.refillInterval;
    this.tokens = this.maxTokens;
    this.lastRefill = Date.now();
  }

  /**
   * Refill tokens based on elapsed time
   */
  private refill(): void {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    const intervals = Math.floor(elapsed / this.refillInterval);

    if (intervals > 0) {
      this.tokens = Math.min(this.maxTokens, this.tokens + intervals * this.refillRate);
      this.lastRefill = now;
    }
  }

  /**
   * Try to acquire a token. Returns true if successful.
   */
  tryAcquire(): boolean {
    this.refill();

    if (this.tokens > 0) {
      this.tokens--;
      return true;
    }

    return false;
  }

  /**
   * Wait until a token is available, then acquire it.
   */
  async acquire(): Promise<void> {
    while (!this.tryAcquire()) {
      // Wait for next refill interval
      await this.sleep(this.refillInterval);
    }
  }

  /**
   * Get time in ms until next token is available
   */
  getWaitTime(): number {
    this.refill();

    if (this.tokens > 0) {
      return 0;
    }

    const elapsed = Date.now() - this.lastRefill;
    return this.refillInterval - elapsed;
  }

  /**
   * Get current token count
   */
  getAvailableTokens(): number {
    this.refill();
    return this.tokens;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

/**
 * Rate limiter that queues requests instead of rejecting
 */
export class QueuedRateLimiter {
  private queue: Array<{ resolve: () => void }> = [];
  private readonly limiter: RateLimiter;
  private processing = false;

  constructor(options: RateLimiterOptions) {
    this.limiter = new RateLimiter(options);
  }

  /**
   * Queue a request and wait for rate limit clearance
   */
  async enqueue(): Promise<void> {
    return new Promise((resolve) => {
      this.queue.push({ resolve });
      this.processQueue();
    });
  }

  private async processQueue(): Promise<void> {
    if (this.processing || this.queue.length === 0) {
      return;
    }

    this.processing = true;

    while (this.queue.length > 0) {
      await this.limiter.acquire();
      const request = this.queue.shift();
      request?.resolve();
    }

    this.processing = false;
  }

  /**
   * Get queue length
   */
  getQueueLength(): number {
    return this.queue.length;
  }
}

// Pre-configured rate limiters for different services
export const rateLimiters = {
  // Trivy: Allow 10 scans per minute
  trivy: new RateLimiter({
    maxTokens: 10,
    refillRate: 1,
    refillInterval: 6000, // 1 token every 6 seconds
  }),

  // SonarQube: Allow 30 requests per minute
  sonarqube: new RateLimiter({
    maxTokens: 30,
    refillRate: 1,
    refillInterval: 2000,
  }),

  // Dependency-Track: Allow 20 requests per minute
  dtrack: new RateLimiter({
    maxTokens: 20,
    refillRate: 1,
    refillInterval: 3000,
  }),

  // Gitea: Allow 60 requests per minute
  gitea: new RateLimiter({
    maxTokens: 60,
    refillRate: 1,
    refillInterval: 1000,
  }),

  // Drone: Allow 60 requests per minute
  drone: new RateLimiter({
    maxTokens: 60,
    refillRate: 1,
    refillInterval: 1000,
  }),

  // Registry: Allow 30 requests per minute
  registry: new RateLimiter({
    maxTokens: 30,
    refillRate: 1,
    refillInterval: 2000,
  }),
};

/**
 * Decorator for rate-limited functions
 */
export function withRateLimit<TArgs extends unknown[], TResult>(
  limiter: RateLimiter
): (fn: (...args: TArgs) => Promise<TResult>) => (...args: TArgs) => Promise<TResult> {
  return (fn) => {
    return async (...args) => {
      await limiter.acquire();
      return fn(...args);
    };
  };
}
