/**
 * Audit Logging for Security Operations
 *
 * Provides structured logging for security-relevant operations
 * with support for multiple output formats and destinations.
 */

export type AuditLevel = "INFO" | "WARN" | "ERROR" | "SECURITY";

export interface AuditEntry {
  /** Unique log ID */
  id: string;
  /** Timestamp in ISO format */
  timestamp: string;
  /** Log level */
  level: AuditLevel;
  /** Operation being performed */
  operation: string;
  /** Service involved */
  service: string;
  /** Operation status */
  status: "started" | "completed" | "failed";
  /** User or system initiating the operation */
  actor?: string;
  /** Target resource (path, image, project, etc.) */
  target?: string;
  /** Additional context */
  metadata?: Record<string, unknown>;
  /** Duration in milliseconds (for completed operations) */
  durationMs?: number;
  /** Error message if failed */
  error?: string;
}

export interface AuditLogger {
  log(entry: Omit<AuditEntry, "id" | "timestamp">): void;
  getEntries(options?: { limit?: number; level?: AuditLevel }): AuditEntry[];
  clear(): void;
}

/**
 * Generate a unique ID for audit entries
 */
function generateId(): string {
  return `audit-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
}

/**
 * In-memory audit logger implementation
 */
class InMemoryAuditLogger implements AuditLogger {
  private entries: AuditEntry[] = [];
  private readonly maxEntries: number;

  constructor(maxEntries: number = 1000) {
    this.maxEntries = maxEntries;
  }

  log(entry: Omit<AuditEntry, "id" | "timestamp">): void {
    const fullEntry: AuditEntry = {
      ...entry,
      id: generateId(),
      timestamp: new Date().toISOString(),
    };

    this.entries.push(fullEntry);

    // Trim old entries if exceeding max
    if (this.entries.length > this.maxEntries) {
      this.entries = this.entries.slice(-this.maxEntries);
    }

    // Also log to console in development
    this.consoleLog(fullEntry);
  }

  private consoleLog(entry: AuditEntry): void {
    const prefix = `[${entry.level}] [${entry.service}]`;
    const message = `${entry.operation} - ${entry.status}`;
    const target = entry.target ? ` (${entry.target})` : "";
    const duration = entry.durationMs ? ` [${entry.durationMs}ms]` : "";
    const error = entry.error ? ` - Error: ${entry.error}` : "";

    const logLine = `${prefix} ${message}${target}${duration}${error}`;

    switch (entry.level) {
      case "ERROR":
      case "SECURITY":
        console.error(logLine);
        break;
      case "WARN":
        console.warn(logLine);
        break;
      default:
        // Only log INFO in verbose mode
        if (process.env.VERBOSE === "true" || process.env.DEBUG === "true") {
          console.log(logLine);
        }
    }
  }

  getEntries(options?: { limit?: number; level?: AuditLevel }): AuditEntry[] {
    let filtered = [...this.entries];

    if (options?.level) {
      filtered = filtered.filter((e) => e.level === options.level);
    }

    if (options?.limit) {
      filtered = filtered.slice(-options.limit);
    }

    return filtered;
  }

  clear(): void {
    this.entries = [];
  }
}

// Global audit logger instance
export const auditLogger = new InMemoryAuditLogger();

/**
 * Helper to create audit entries for operations
 */
export function auditOperation(
  operation: string,
  service: string,
  target?: string,
  actor?: string
): {
  start: () => void;
  complete: (metadata?: Record<string, unknown>) => void;
  fail: (error: string, metadata?: Record<string, unknown>) => void;
} {
  let startTime: number;

  return {
    start: () => {
      startTime = Date.now();
      auditLogger.log({
        level: "INFO",
        operation,
        service,
        status: "started",
        target,
        actor,
      });
    },
    complete: (metadata?: Record<string, unknown>) => {
      auditLogger.log({
        level: "INFO",
        operation,
        service,
        status: "completed",
        target,
        actor,
        durationMs: Date.now() - startTime,
        metadata,
      });
    },
    fail: (error: string, metadata?: Record<string, unknown>) => {
      auditLogger.log({
        level: "ERROR",
        operation,
        service,
        status: "failed",
        target,
        actor,
        durationMs: Date.now() - startTime,
        error,
        metadata,
      });
    },
  };
}

/**
 * Log a security-relevant event
 */
export function auditSecurityEvent(
  operation: string,
  service: string,
  details: {
    target?: string;
    actor?: string;
    reason: string;
    metadata?: Record<string, unknown>;
  }
): void {
  auditLogger.log({
    level: "SECURITY",
    operation,
    service,
    status: "completed",
    target: details.target,
    actor: details.actor,
    metadata: {
      ...details.metadata,
      reason: details.reason,
    },
  });
}

/**
 * Get security events from the audit log
 */
export function getSecurityEvents(limit?: number): AuditEntry[] {
  return auditLogger.getEntries({ level: "SECURITY", limit });
}

/**
 * Get all failed operations
 */
export function getFailedOperations(limit?: number): AuditEntry[] {
  return auditLogger.getEntries({ limit }).filter((e) => e.status === "failed");
}
