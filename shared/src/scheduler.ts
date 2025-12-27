/**
 * Scan Scheduler Module
 *
 * Enables scheduled scanning of targets using cron expressions
 * for continuous security monitoring.
 */

import { randomUUID } from "node:crypto";
import { trivyScanImage, trivyScanPath } from "./handlers.js";
import { scanRegistry } from "./registry-scanner.js";
import { sendWebhooks, createScanSummary } from "./webhook.js";
import type {
  ScanSchedule,
  CreateScheduleInput,
  UpdateScheduleInput,
  ScheduleExecutionResult,
  ScheduleHistoryEntry,
  ListSchedulesOptions,
  CronValidationResult,
  ParsedCronExpression,
  CronField,
  TrivyScanResult,
  VulnerabilityCounts,
  TargetScanResult,
  ScanTarget,
  WebhookConfig,
} from "./types.js";

// =============================================================================
// Constants
// =============================================================================

const CRON_FIELD_RANGES: Record<string, { min: number; max: number }> = {
  minute: { min: 0, max: 59 },
  hour: { min: 0, max: 23 },
  dayOfMonth: { min: 1, max: 31 },
  month: { min: 1, max: 12 },
  dayOfWeek: { min: 0, max: 6 },
};

const MONTH_NAMES: Record<string, number> = {
  jan: 1,
  feb: 2,
  mar: 3,
  apr: 4,
  may: 5,
  jun: 6,
  jul: 7,
  aug: 8,
  sep: 9,
  oct: 10,
  nov: 11,
  dec: 12,
};

const DAY_NAMES: Record<string, number> = {
  sun: 0,
  mon: 1,
  tue: 2,
  wed: 3,
  thu: 4,
  fri: 5,
  sat: 6,
};

const CRON_ALIASES: Record<string, string> = {
  "@yearly": "0 0 1 1 *",
  "@annually": "0 0 1 1 *",
  "@monthly": "0 0 1 * *",
  "@weekly": "0 0 * * 0",
  "@daily": "0 0 * * *",
  "@midnight": "0 0 * * *",
  "@hourly": "0 * * * *",
};

// =============================================================================
// In-Memory Storage
// =============================================================================

const scheduleStore = new Map<string, ScanSchedule>();
const historyStore = new Map<string, ScheduleHistoryEntry[]>();
const timers = new Map<string, NodeJS.Timeout>();

// =============================================================================
// Cron Parsing
// =============================================================================

/**
 * Parse a single cron field value
 */
function parseCronFieldValue(
  value: string,
  fieldName: string,
  range: { min: number; max: number }
): number[] {
  const { min, max } = range;

  // Handle wildcard
  if (value === "*") {
    return Array.from({ length: max - min + 1 }, (_, i) => min + i);
  }

  // Handle step values (e.g., */5, 1-10/2)
  if (value.includes("/")) {
    const [rangeStr, stepStr] = value.split("/");
    const step = Number.parseInt(stepStr, 10);
    if (Number.isNaN(step) || step <= 0) {
      throw new Error("Invalid step value in " + fieldName + ": " + value);
    }

    let rangeValues: number[];
    if (rangeStr === "*") {
      rangeValues = Array.from({ length: max - min + 1 }, (_, i) => min + i);
    } else {
      rangeValues = parseCronFieldValue(rangeStr, fieldName, range);
    }

    return rangeValues.filter((v) => (v - min) % step === 0);
  }

  // Handle ranges (e.g., 1-5)
  if (value.includes("-")) {
    const [startStr, endStr] = value.split("-");
    const start = parseFieldValue(startStr, fieldName);
    const end = parseFieldValue(endStr, fieldName);
    if (start > end) {
      throw new Error("Invalid range in " + fieldName + ": " + value);
    }
    return Array.from({ length: end - start + 1 }, (_, i) => start + i);
  }

  // Handle lists (e.g., 1,3,5)
  if (value.includes(",")) {
    const values = value.split(",").flatMap((v) => parseCronFieldValue(v.trim(), fieldName, range));
    return [...new Set(values)].sort((a, b) => a - b);
  }

  // Handle single value
  const numValue = parseFieldValue(value, fieldName);
  if (numValue < min || numValue > max) {
    throw new Error("Value out of range in " + fieldName + ": " + value);
  }
  return [numValue];
}

/**
 * Parse a field value (number or name)
 */
function parseFieldValue(value: string, fieldName: string): number {
  // Try as number first
  const num = Number.parseInt(value, 10);
  if (!Number.isNaN(num)) return num;

  // Try as name
  const lower = value.toLowerCase();
  if (fieldName === "month" && MONTH_NAMES[lower] !== undefined) {
    return MONTH_NAMES[lower];
  }
  if (fieldName === "dayOfWeek" && DAY_NAMES[lower] !== undefined) {
    return DAY_NAMES[lower];
  }

  throw new Error("Invalid value in " + fieldName + ": " + value);
}

/**
 * Parse a cron field
 */
function parseCronField(value: string, fieldName: string): CronField {
  const range = CRON_FIELD_RANGES[fieldName];
  const values = parseCronFieldValue(value, fieldName, range);
  return {
    expression: value,
    values,
  };
}

/**
 * Parse a cron expression
 */
export function parseCronExpression(expression: string): ParsedCronExpression {
  // Handle aliases
  let normalizedExpr = expression.trim();
  if (CRON_ALIASES[normalizedExpr.toLowerCase()]) {
    normalizedExpr = CRON_ALIASES[normalizedExpr.toLowerCase()];
  }

  const parts = normalizedExpr.split(/\s+/);
  if (parts.length !== 5) {
    throw new Error("Invalid cron expression: expected 5 fields, got " + parts.length);
  }

  return {
    minute: parseCronField(parts[0], "minute"),
    hour: parseCronField(parts[1], "hour"),
    dayOfMonth: parseCronField(parts[2], "dayOfMonth"),
    month: parseCronField(parts[3], "month"),
    dayOfWeek: parseCronField(parts[4], "dayOfWeek"),
    original: expression,
  };
}

/**
 * Validate a cron expression
 */
export function validateCronExpression(
  expression: string,
  _options?: { allowSeconds?: boolean; allowHash?: boolean }
): CronValidationResult {
  try {
    const parsed = parseCronExpression(expression);
    const nextRuns = getNextRunTimes(expression, 3);
    return {
      valid: true,
      parsed,
      nextRuns: nextRuns.map((d) => d.toISOString()),
    };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Generate human-readable description of cron expression
 */
export function describeCronExpression(parsed: ParsedCronExpression): string {
  const { minute, hour, dayOfMonth, month, dayOfWeek } = parsed;
  const parts: string[] = [];

  // Time
  if (minute.values.length === 60 && hour.values.length === 24) {
    parts.push("Every minute");
  } else if (minute.values.length === 60) {
    parts.push(
      "Every minute during hour" +
        (hour.values.length > 1 ? "s" : "") +
        " " +
        hour.values.join(", ")
    );
  } else if (hour.values.length === 24) {
    parts.push(
      "At minute" +
        (minute.values.length > 1 ? "s" : "") +
        " " +
        minute.values.join(", ") +
        " of every hour"
    );
  } else {
    const times = hour.values.flatMap((h) =>
      minute.values.map((m) => h.toString().padStart(2, "0") + ":" + m.toString().padStart(2, "0"))
    );
    parts.push("At " + times.slice(0, 3).join(", ") + (times.length > 3 ? "..." : ""));
  }

  // Day restrictions
  const hasDayOfMonthRestriction = dayOfMonth.values.length < 31;
  const hasDayOfWeekRestriction = dayOfWeek.values.length < 7;
  const hasMonthRestriction = month.values.length < 12;

  if (hasDayOfWeekRestriction) {
    const dayNames = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
    const days = dayOfWeek.values.map((d) => dayNames[d]);
    parts.push("on " + days.join(", "));
  }

  if (hasDayOfMonthRestriction) {
    parts.push(
      "on day" + (dayOfMonth.values.length > 1 ? "s" : "") + " " + dayOfMonth.values.join(", ")
    );
  }

  if (hasMonthRestriction) {
    const monthNames = [
      "",
      "January",
      "February",
      "March",
      "April",
      "May",
      "June",
      "July",
      "August",
      "September",
      "October",
      "November",
      "December",
    ];
    const months = month.values.map((m) => monthNames[m]);
    parts.push("in " + months.join(", "));
  }

  return parts.join(" ");
}

// =============================================================================
// Next Run Calculation
// =============================================================================

/**
 * Get the next run time for a cron expression
 */
export function getNextRunTime(
  expression: string,
  after: Date = new Date(),
  _timezone?: string
): Date {
  const parsed = parseCronExpression(expression);
  const { minute, hour, dayOfMonth, month, dayOfWeek } = parsed;

  // Start from the next minute
  const current = new Date(after);
  current.setSeconds(0, 0);
  current.setMinutes(current.getMinutes() + 1);

  // Max iterations to prevent infinite loop
  const maxIterations = 366 * 24 * 60;

  for (let i = 0; i < maxIterations; i++) {
    const m = current.getMinutes();
    const h = current.getHours();
    const dom = current.getDate();
    const mon = current.getMonth() + 1;
    const dow = current.getDay();

    if (
      minute.values.includes(m) &&
      hour.values.includes(h) &&
      month.values.includes(mon) &&
      (dayOfMonth.values.includes(dom) || dayOfWeek.values.includes(dow))
    ) {
      return current;
    }

    current.setMinutes(current.getMinutes() + 1);
  }

  throw new Error("Could not find next run time within one year");
}

/**
 * Get multiple next run times
 */
export function getNextRunTimes(expression: string, count: number, _timezone?: string): Date[] {
  const times: Date[] = [];
  let after = new Date();

  for (let i = 0; i < count; i++) {
    const next = getNextRunTime(expression, after, _timezone);
    times.push(next);
    after = next;
  }

  return times;
}

// =============================================================================
// Schedule CRUD Operations
// =============================================================================

/**
 * Create a new schedule
 */
export function createSchedule(input: CreateScheduleInput): ScanSchedule {
  // Validate cron expression
  const validation = validateCronExpression(input.cron);
  if (!validation.valid) {
    throw new Error("Invalid cron expression: " + validation.error);
  }

  // Validate targets
  if (!input.targets || input.targets.length === 0) {
    throw new Error("At least one target is required");
  }

  const now = new Date().toISOString();
  const id = randomUUID();

  const schedule: ScanSchedule = {
    id,
    name: input.name,
    cron: input.cron,
    timezone: input.timezone || "UTC",
    targets: input.targets,
    options: input.options,
    notifications: input.notifications,
    enabled: input.enabled ?? true,
    nextRun: validation.nextRuns?.[0],
    createdAt: now,
    updatedAt: now,
  };

  scheduleStore.set(id, schedule);

  // Start timer if enabled
  if (schedule.enabled) {
    scheduleNextRun(schedule);
  }

  return schedule;
}

/**
 * Get a schedule by ID
 */
export function getSchedule(id: string): ScanSchedule | undefined {
  return scheduleStore.get(id);
}

/**
 * List all schedules
 */
export function listSchedules(options?: ListSchedulesOptions): ScanSchedule[] {
  let schedules = Array.from(scheduleStore.values());

  if (options?.enabled !== undefined) {
    schedules = schedules.filter((s) => s.enabled === options.enabled);
  }

  if (options?.targetType) {
    schedules = schedules.filter((s) => s.targets.some((t) => t.type === options.targetType));
  }

  return schedules;
}

/**
 * Update a schedule
 */
export function updateSchedule(id: string, updates: UpdateScheduleInput): ScanSchedule {
  const schedule = scheduleStore.get(id);
  if (!schedule) {
    throw new Error("Schedule not found: " + id);
  }

  // Validate cron if updating
  if (updates.cron) {
    const validation = validateCronExpression(updates.cron);
    if (!validation.valid) {
      throw new Error("Invalid cron expression: " + validation.error);
    }
  }

  const wasEnabled = schedule.enabled;
  const updatedSchedule: ScanSchedule = {
    ...schedule,
    ...updates,
    updatedAt: new Date().toISOString(),
  };

  // Update next run time if cron changed
  if (updates.cron) {
    const validation = validateCronExpression(updates.cron);
    updatedSchedule.nextRun = validation.nextRuns?.[0];
  }

  scheduleStore.set(id, updatedSchedule);

  // Handle timer updates
  if (wasEnabled && !updatedSchedule.enabled) {
    cancelScheduleTimer(id);
  } else if (!wasEnabled && updatedSchedule.enabled) {
    scheduleNextRun(updatedSchedule);
  } else if (updatedSchedule.enabled && updates.cron) {
    cancelScheduleTimer(id);
    scheduleNextRun(updatedSchedule);
  }

  return updatedSchedule;
}

/**
 * Delete a schedule
 */
export function deleteSchedule(id: string): void {
  if (!scheduleStore.has(id)) {
    throw new Error("Schedule not found: " + id);
  }

  cancelScheduleTimer(id);
  scheduleStore.delete(id);
  historyStore.delete(id);
}

// =============================================================================
// Schedule Execution
// =============================================================================

/**
 * Execute a schedule's scans
 */
async function executeSchedule(schedule: ScanSchedule): Promise<ScheduleExecutionResult> {
  const startTime = Date.now();
  const executedAt = new Date().toISOString();
  const results: TargetScanResult[] = [];

  const totalVulns: VulnerabilityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
    total: 0,
  };

  let targetsFailed = 0;

  for (const scanTarget of schedule.targets) {
    const targetStartTime = Date.now();
    const targetStartedAt = new Date().toISOString();

    // Convert ScheduledScanTarget to ScanTarget for results
    // Only "image" and "path" are valid ScanTarget types
    const target: ScanTarget = {
      target: scanTarget.target,
      type: scanTarget.type === "registry" ? "image" : scanTarget.type,
      label: scanTarget.label,
    };

    try {
      const severity = schedule.options?.severity || "HIGH,CRITICAL";
      let scanResult: TrivyScanResult | undefined;
      let vulnCounts: VulnerabilityCounts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0,
        total: 0,
      };

      switch (scanTarget.type) {
        case "image": {
          const result = (await trivyScanImage(scanTarget.target, severity)) as TrivyScanResult;
          if (result && !("error" in result)) {
            scanResult = result;
            vulnCounts = countVulnerabilities(result);
          }
          break;
        }
        case "path": {
          const result = (await trivyScanPath(scanTarget.target, severity)) as TrivyScanResult;
          if (result && !("error" in result)) {
            scanResult = result;
            vulnCounts = countVulnerabilities(result);
          }
          break;
        }
        case "registry": {
          // Registry scans are handled specially - scan all images in registry
          const registryResult = await scanRegistry({
            severity,
            concurrency: schedule.options?.concurrency,
          });
          // Aggregate vulnerabilities from all registry scan results
          for (const imgResult of registryResult.results) {
            if (imgResult.success && imgResult.result) {
              const counts = countVulnerabilities(imgResult.result);
              vulnCounts.critical += counts.critical;
              vulnCounts.high += counts.high;
              vulnCounts.medium += counts.medium;
              vulnCounts.low += counts.low;
              vulnCounts.unknown += counts.unknown;
              vulnCounts.total += counts.total;
            }
          }
          break;
        }
      }

      // Add to totals
      totalVulns.critical += vulnCounts.critical;
      totalVulns.high += vulnCounts.high;
      totalVulns.medium += vulnCounts.medium;
      totalVulns.low += vulnCounts.low;
      totalVulns.unknown += vulnCounts.unknown;
      totalVulns.total += vulnCounts.total;

      results.push({
        target,
        success: true,
        result: scanResult,
        durationMs: Date.now() - targetStartTime,
        startedAt: targetStartedAt,
        completedAt: new Date().toISOString(),
      });
    } catch (error) {
      targetsFailed++;
      results.push({
        target,
        success: false,
        error: error instanceof Error ? error.message : String(error),
        durationMs: Date.now() - targetStartTime,
        startedAt: targetStartedAt,
        completedAt: new Date().toISOString(),
      });
    }
  }

  const success = targetsFailed === 0;
  const durationMs = Date.now() - startTime;

  // Record history
  const historyEntry: ScheduleHistoryEntry = {
    executionId: randomUUID(),
    scheduleId: schedule.id,
    executedAt,
    durationMs,
    success,
    summary: {
      targetsScanned: schedule.targets.length,
      targetsFailed,
      vulnerabilities: totalVulns,
    },
  };

  const history = historyStore.get(schedule.id) || [];
  history.unshift(historyEntry);
  if (history.length > 100) history.pop();
  historyStore.set(schedule.id, history);

  // Update schedule
  const updatedSchedule: ScanSchedule = {
    ...schedule,
    lastRun: executedAt,
    nextRun: getNextRunTime(schedule.cron).toISOString(),
    updatedAt: new Date().toISOString(),
  };
  scheduleStore.set(schedule.id, updatedSchedule);

  // Send notifications
  const webhookResults: Array<{ url: string; success: boolean; error?: string }> = [];
  if (schedule.notifications && schedule.notifications.length > 0) {
    const hasVulnerabilities = totalVulns.total > 0;

    for (const notification of schedule.notifications) {
      const shouldNotify =
        (success && notification.notifyOn?.includes("success")) ||
        (!success && notification.notifyOn?.includes("failure")) ||
        (hasVulnerabilities && notification.notifyOn?.includes("vulnerabilities")) ||
        !notification.notifyOn ||
        notification.notifyOn.length === 0;

      if (shouldNotify) {
        try {
          const summary = createScanSummary(
            schedule.targets[0]?.target || "scheduled-scan",
            "image",
            totalVulns
          );
          const config: WebhookConfig = {
            endpoints: [
              {
                id: randomUUID(),
                name: "notification",
                url: notification.url,
                format: notification.format || "slack",
                enabled: true,
              },
            ],
          };

          await sendWebhooks(config, summary);
          webhookResults.push({ url: notification.url, success: true });
        } catch (error) {
          webhookResults.push({
            url: notification.url,
            success: false,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }
    }
  }

  // Schedule next run
  scheduleNextRun(updatedSchedule);

  return {
    scheduleId: schedule.id,
    scheduleName: schedule.name,
    executedAt,
    durationMs,
    success,
    targetsScanned: schedule.targets.length,
    targetsFailed,
    vulnerabilities: totalVulns,
    results,
    webhookResults: webhookResults.length > 0 ? webhookResults : undefined,
  };
}

/**
 * Count vulnerabilities from a Trivy scan result
 */
function countVulnerabilities(result: TrivyScanResult): VulnerabilityCounts {
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  let unknown = 0;
  let total = 0;

  if (result.Results) {
    for (const r of result.Results) {
      if (!r.Vulnerabilities) continue;
      for (const v of r.Vulnerabilities) {
        switch (v.Severity?.toUpperCase()) {
          case "CRITICAL":
            critical++;
            break;
          case "HIGH":
            high++;
            break;
          case "MEDIUM":
            medium++;
            break;
          case "LOW":
            low++;
            break;
          default:
            unknown++;
        }
        total++;
      }
    }
  }

  return { critical, high, medium, low, unknown, total };
}

/**
 * Manually trigger a schedule
 */
export async function triggerSchedule(id: string): Promise<ScheduleExecutionResult> {
  const schedule = scheduleStore.get(id);
  if (!schedule) {
    throw new Error("Schedule not found: " + id);
  }

  return executeSchedule(schedule);
}

/**
 * Get schedule history
 */
export function getScheduleHistory(scheduleId: string, limit: number = 10): ScheduleHistoryEntry[] {
  const history = historyStore.get(scheduleId) || [];
  return history.slice(0, limit);
}

// =============================================================================
// Timer Management
// =============================================================================

/**
 * Schedule the next run for a schedule
 */
function scheduleNextRun(schedule: ScanSchedule): void {
  try {
    const nextRun = getNextRunTime(schedule.cron);
    const now = Date.now();
    const delay = nextRun.getTime() - now;

    if (delay > 0) {
      // setTimeout max is ~24.8 days, use a shorter interval for longer delays
      const maxDelay = 24 * 60 * 60 * 1000; // 24 hours
      const actualDelay = Math.min(delay, maxDelay);

      const timer = setTimeout(() => {
        if (delay > maxDelay) {
          // Reschedule if we couldn't wait the full time
          scheduleNextRun(schedule);
        } else {
          // Execute and reschedule
          executeSchedule(schedule).catch(console.error);
        }
      }, actualDelay);

      timers.set(schedule.id, timer);
    }
  } catch (error) {
    console.error("Failed to schedule " + schedule.id + ":", error);
  }
}

/**
 * Cancel a schedule's timer
 */
function cancelScheduleTimer(id: string): void {
  const timer = timers.get(id);
  if (timer) {
    clearTimeout(timer);
    timers.delete(id);
  }
}

/**
 * Start the scheduler - start all enabled schedules
 */
export function startScheduler(): void {
  for (const schedule of scheduleStore.values()) {
    if (schedule.enabled) {
      scheduleNextRun(schedule);
    }
  }
}

/**
 * Stop the scheduler - stop all schedules
 */
export function stopScheduler(): void {
  for (const id of timers.keys()) {
    cancelScheduleTimer(id);
  }
}

// =============================================================================
// Persistence (File-based)
// =============================================================================

/**
 * Save schedules to a file
 */
export async function saveSchedulesToFile(filePath: string): Promise<void> {
  const { writeFile } = await import("node:fs/promises");
  const schedules = Array.from(scheduleStore.values());
  await writeFile(filePath, JSON.stringify(schedules, null, 2), "utf-8");
}

/**
 * Load schedules from a file
 */
export async function loadSchedulesFromFile(filePath: string): Promise<void> {
  const { readFile } = await import("node:fs/promises");

  try {
    const content = await readFile(filePath, "utf-8");
    const schedules = JSON.parse(content) as ScanSchedule[];

    for (const schedule of schedules) {
      scheduleStore.set(schedule.id, schedule);
      if (schedule.enabled) {
        scheduleNextRun(schedule);
      }
    }
  } catch (error) {
    // File doesn't exist or is invalid, start fresh
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  }
}

/**
 * Clear all schedules (for testing)
 */
export function clearAllSchedules(): void {
  stopScheduler();
  scheduleStore.clear();
  historyStore.clear();
}
