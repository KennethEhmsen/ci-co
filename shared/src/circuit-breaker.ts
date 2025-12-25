/**
 * Circuit Breaker Pattern Implementation
 *
 * Protects against cascading failures when external services are down.
 * States: CLOSED (normal) -> OPEN (failing) -> HALF_OPEN (testing recovery)
 */

export type CircuitState = "CLOSED" | "OPEN" | "HALF_OPEN";

export interface CircuitBreakerOptions {
  /** Number of failures before opening circuit (default: 5) */
  failureThreshold?: number;
  /** Time in ms before attempting recovery (default: 30000) */
  recoveryTimeout?: number;
  /** Number of successful calls needed to close circuit (default: 2) */
  successThreshold?: number;
  /** Optional callback when state changes */
  onStateChange?: (from: CircuitState, to: CircuitState, service: string) => void;
}

export class CircuitBreaker {
  private state: CircuitState = "CLOSED";
  private failureCount = 0;
  private successCount = 0;
  private lastFailureTime = 0;
  private readonly options: Required<Omit<CircuitBreakerOptions, "onStateChange">> & {
    onStateChange?: CircuitBreakerOptions["onStateChange"];
  };

  constructor(
    private readonly serviceName: string,
    options: CircuitBreakerOptions = {}
  ) {
    this.options = {
      failureThreshold: options.failureThreshold ?? 5,
      recoveryTimeout: options.recoveryTimeout ?? 30000,
      successThreshold: options.successThreshold ?? 2,
      onStateChange: options.onStateChange,
    };
  }

  /**
   * Get current circuit state
   */
  getState(): CircuitState {
    if (this.state === "OPEN" && this.shouldAttemptRecovery()) {
      this.transitionTo("HALF_OPEN");
    }
    return this.state;
  }

  /**
   * Check if circuit allows requests
   */
  isOpen(): boolean {
    return this.getState() === "OPEN";
  }

  /**
   * Check if we should attempt recovery
   */
  private shouldAttemptRecovery(): boolean {
    return Date.now() - this.lastFailureTime >= this.options.recoveryTimeout;
  }

  /**
   * Transition to a new state
   */
  private transitionTo(newState: CircuitState): void {
    if (this.state !== newState) {
      const oldState = this.state;
      this.state = newState;
      this.options.onStateChange?.(oldState, newState, this.serviceName);
    }
  }

  /**
   * Record a successful call
   */
  recordSuccess(): void {
    if (this.state === "HALF_OPEN") {
      this.successCount++;
      if (this.successCount >= this.options.successThreshold) {
        this.reset();
      }
    } else if (this.state === "CLOSED") {
      // Reset failure count on success
      this.failureCount = 0;
    }
  }

  /**
   * Record a failed call
   */
  recordFailure(): void {
    this.lastFailureTime = Date.now();

    if (this.state === "HALF_OPEN") {
      // Any failure in half-open reopens the circuit
      this.transitionTo("OPEN");
      this.successCount = 0;
    } else if (this.state === "CLOSED") {
      this.failureCount++;
      if (this.failureCount >= this.options.failureThreshold) {
        this.transitionTo("OPEN");
      }
    }
  }

  /**
   * Reset the circuit breaker to closed state
   */
  reset(): void {
    this.transitionTo("CLOSED");
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureTime = 0;
  }

  /**
   * Execute a function with circuit breaker protection
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.isOpen()) {
      throw new CircuitOpenError(
        `Circuit breaker is OPEN for ${this.serviceName}. Service is temporarily unavailable.`
      );
    }

    try {
      const result = await fn();
      this.recordSuccess();
      return result;
    } catch (error) {
      this.recordFailure();
      throw error;
    }
  }

  /**
   * Get circuit breaker statistics
   */
  getStats(): {
    state: CircuitState;
    failureCount: number;
    successCount: number;
    lastFailureTime: number;
    serviceName: string;
  } {
    return {
      state: this.getState(),
      failureCount: this.failureCount,
      successCount: this.successCount,
      lastFailureTime: this.lastFailureTime,
      serviceName: this.serviceName,
    };
  }
}

/**
 * Error thrown when circuit is open
 */
export class CircuitOpenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CircuitOpenError";
  }
}

// Pre-configured circuit breakers for each service
export const circuitBreakers = {
  trivy: new CircuitBreaker("trivy", { failureThreshold: 3, recoveryTimeout: 60000 }),
  sonarqube: new CircuitBreaker("sonarqube", { failureThreshold: 5, recoveryTimeout: 30000 }),
  dtrack: new CircuitBreaker("dependency-track", { failureThreshold: 5, recoveryTimeout: 30000 }),
  gitea: new CircuitBreaker("gitea", { failureThreshold: 5, recoveryTimeout: 30000 }),
  drone: new CircuitBreaker("drone", { failureThreshold: 5, recoveryTimeout: 30000 }),
  registry: new CircuitBreaker("registry", { failureThreshold: 3, recoveryTimeout: 30000 }),
};

/**
 * Get all circuit breaker stats
 */
export function getAllCircuitStats(): ReturnType<CircuitBreaker["getStats"]>[] {
  return Object.values(circuitBreakers).map((cb) => cb.getStats());
}
