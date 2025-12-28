/**
 * Scheduler Module Tests
 *
 * Comprehensive tests for cron parsing, schedule management,
 * and scheduled scan execution.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  parseCronExpression,
  validateCronExpression,
  describeCronExpression,
  getNextRunTime,
  getNextRunTimes,
  createSchedule,
  getSchedule,
  listSchedules,
  updateSchedule,
  deleteSchedule,
  triggerSchedule,
  getScheduleHistory,
  startScheduler,
  stopScheduler,
  clearAllSchedules,
} from "./scheduler.js";

// =============================================================================
// Cron Parsing Tests
// =============================================================================

describe("Cron Parsing", () => {
  describe("parseCronExpression", () => {
    it("should parse standard 5-field expression", () => {
      const result = parseCronExpression("0 2 * * *");
      expect(result.minute.values).toEqual([0]);
      expect(result.hour.values).toEqual([2]);
      expect(result.dayOfMonth.values).toHaveLength(31);
      expect(result.month.values).toHaveLength(12);
      expect(result.dayOfWeek.values).toHaveLength(7);
    });

    it("should parse specific values", () => {
      const result = parseCronExpression("30 14 15 6 3");
      expect(result.minute.values).toEqual([30]);
      expect(result.hour.values).toEqual([14]);
      expect(result.dayOfMonth.values).toEqual([15]);
      expect(result.month.values).toEqual([6]);
      expect(result.dayOfWeek.values).toEqual([3]);
    });

    it("should parse ranges", () => {
      const result = parseCronExpression("0-30 9-17 * * *");
      expect(result.minute.values).toHaveLength(31);
      expect(result.minute.values).toContain(0);
      expect(result.minute.values).toContain(30);
      expect(result.hour.values).toHaveLength(9);
      expect(result.hour.values).toContain(9);
      expect(result.hour.values).toContain(17);
    });

    it("should parse lists", () => {
      const result = parseCronExpression("0,15,30,45 * * * *");
      expect(result.minute.values).toEqual([0, 15, 30, 45]);
    });

    it("should parse step values", () => {
      const result = parseCronExpression("*/15 */2 * * *");
      expect(result.minute.values).toEqual([0, 15, 30, 45]);
      expect(result.hour.values).toEqual([0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22]);
    });

    it("should parse step values with ranges", () => {
      const result = parseCronExpression("0-30/10 * * * *");
      expect(result.minute.values).toEqual([0, 10, 20, 30]);
    });

    it("should parse named months", () => {
      const result = parseCronExpression("0 0 1 jan,jul *");
      expect(result.month.values).toEqual([1, 7]);
    });

    it("should parse named days of week", () => {
      const result = parseCronExpression("0 0 * * mon-fri");
      expect(result.dayOfWeek.values).toEqual([1, 2, 3, 4, 5]);
    });

    it("should parse @daily alias", () => {
      const result = parseCronExpression("@daily");
      expect(result.minute.values).toEqual([0]);
      expect(result.hour.values).toEqual([0]);
      expect(result.dayOfMonth.values).toHaveLength(31);
      expect(result.month.values).toHaveLength(12);
      expect(result.dayOfWeek.values).toHaveLength(7);
    });

    it("should parse @weekly alias", () => {
      const result = parseCronExpression("@weekly");
      expect(result.minute.values).toEqual([0]);
      expect(result.hour.values).toEqual([0]);
      expect(result.dayOfWeek.values).toEqual([0]); // Sunday
    });

    it("should parse @hourly alias", () => {
      const result = parseCronExpression("@hourly");
      expect(result.minute.values).toEqual([0]);
      expect(result.hour.values).toHaveLength(24);
    });

    it("should parse @monthly alias", () => {
      const result = parseCronExpression("@monthly");
      expect(result.minute.values).toEqual([0]);
      expect(result.hour.values).toEqual([0]);
      expect(result.dayOfMonth.values).toEqual([1]);
    });

    it("should throw on invalid expression with wrong field count", () => {
      expect(() => parseCronExpression("0 0 0")).toThrow();
    });

    it("should throw on out-of-range values", () => {
      expect(() => parseCronExpression("60 * * * *")).toThrow();
      expect(() => parseCronExpression("* 25 * * *")).toThrow();
      expect(() => parseCronExpression("* * 32 * *")).toThrow();
      expect(() => parseCronExpression("* * * 13 *")).toThrow();
      expect(() => parseCronExpression("* * * * 8")).toThrow();
    });
  });

  describe("validateCronExpression", () => {
    it("should validate correct expression", () => {
      const result = validateCronExpression("0 2 * * *");
      expect(result.valid).toBe(true);
      expect(result.parsed).toBeDefined();
    });

    it("should validate aliases", () => {
      const result = validateCronExpression("@daily");
      expect(result.valid).toBe(true);
      expect(result.parsed).toBeDefined();
    });

    it("should reject invalid expression", () => {
      const result = validateCronExpression("invalid");
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it("should reject empty expression", () => {
      const result = validateCronExpression("");
      expect(result.valid).toBe(false);
    });
  });

  describe("describeCronExpression", () => {
    it("should describe daily at midnight", () => {
      const parsed = parseCronExpression("0 0 * * *");
      const desc = describeCronExpression(parsed);
      expect(desc).toBeDefined();
      expect(typeof desc).toBe("string");
    });

    it("should describe specific time", () => {
      const parsed = parseCronExpression("30 14 * * *");
      const desc = describeCronExpression(parsed);
      expect(desc).toContain("30");
      expect(desc).toContain("14");
    });

    it("should describe every hour", () => {
      const parsed = parseCronExpression("0 * * * *");
      const desc = describeCronExpression(parsed);
      expect(desc.toLowerCase()).toContain("every hour");
    });

    it("should describe multiple minutes", () => {
      const parsed = parseCronExpression("0,30 * * * *");
      const desc = describeCronExpression(parsed);
      expect(desc).toContain("0");
      expect(desc).toContain("30");
    });
  });
});

// =============================================================================
// Next Run Calculation Tests
// =============================================================================

describe("Next Run Calculation", () => {
  describe("getNextRunTime", () => {
    it("should calculate next run for daily expression", () => {
      const now = new Date();
      const next = getNextRunTime("0 2 * * *", now);

      // The next run should be at 2:00 AM
      expect(next.getHours()).toBe(2);
      expect(next.getMinutes()).toBe(0);
      // Next run should be in the future
      expect(next.getTime()).toBeGreaterThan(now.getTime());
    });

    it("should calculate next run for hourly expression", () => {
      const now = new Date();
      now.setMinutes(15); // Set to :15 past the hour
      const next = getNextRunTime("30 * * * *", now);

      // Should be at :30 of the current hour
      expect(next.getMinutes()).toBe(30);
    });

    it("should handle monthly expression", () => {
      const times = getNextRunTimes("0 0 15 * *", 3);
      // Should return 3 times in chronological order
      expect(times).toHaveLength(3);
      for (let i = 1; i < times.length; i++) {
        expect(times[i].getTime()).toBeGreaterThan(times[i - 1].getTime());
      }
    });

    it("should handle day of week expression", () => {
      const times = getNextRunTimes("0 0 * * 1", 3); // Monday
      // Should return 3 times in chronological order
      expect(times).toHaveLength(3);
      for (let i = 1; i < times.length; i++) {
        expect(times[i].getTime()).toBeGreaterThan(times[i - 1].getTime());
      }
    });
  });

  describe("getNextRunTimes", () => {
    it("should return multiple next run times", () => {
      const times = getNextRunTimes("0 * * * *", 5);
      expect(times).toHaveLength(5);

      // Each time should be an hour apart
      for (let i = 1; i < times.length; i++) {
        const diff = times[i].getTime() - times[i - 1].getTime();
        expect(diff).toBe(60 * 60 * 1000); // 1 hour in ms
      }
    });

    it("should return times in chronological order", () => {
      const times = getNextRunTimes("*/15 * * * *", 10);
      for (let i = 1; i < times.length; i++) {
        expect(times[i].getTime()).toBeGreaterThan(times[i - 1].getTime());
      }
    });

    it("should handle daily expression", () => {
      const times = getNextRunTimes("0 0 * * *", 7);
      expect(times).toHaveLength(7);

      // Each time should be a day apart
      for (let i = 1; i < times.length; i++) {
        const diff = times[i].getTime() - times[i - 1].getTime();
        expect(diff).toBe(24 * 60 * 60 * 1000); // 1 day in ms
      }
    });
  });
});

// =============================================================================
// Schedule CRUD Tests
// =============================================================================

describe("Schedule CRUD", () => {
  beforeEach(() => {
    clearAllSchedules();
  });

  afterEach(() => {
    stopScheduler();
    clearAllSchedules();
  });

  describe("createSchedule", () => {
    it("should create schedule with minimal options", () => {
      const schedule = createSchedule({
        name: "Test Schedule",
        cron: "0 2 * * *",
        targets: [{ type: "image", target: "nginx:latest" }],
      });

      expect(schedule.id).toBeDefined();
      expect(schedule.name).toBe("Test Schedule");
      expect(schedule.cron).toBe("0 2 * * *");
      expect(schedule.targets[0].type).toBe("image");
      expect(schedule.targets[0].target).toBe("nginx:latest");
      expect(schedule.enabled).toBe(true);
      expect(schedule.createdAt).toBeDefined();
      expect(schedule.nextRun).toBeDefined();
    });

    it("should create schedule with all options", () => {
      const schedule = createSchedule({
        name: "Full Schedule",
        cron: "@daily",
        targets: [
          {
            type: "path",
            target: "/app",
            label: "App Directory",
          },
        ],
        enabled: false,
        options: {
          severity: "CRITICAL",
        },
        notifications: [
          {
            url: "https://hooks.slack.com/test",
            format: "slack",
            notifyOn: ["success", "failure"],
          },
        ],
      });

      expect(schedule.enabled).toBe(false);
      expect(schedule.options?.severity).toBe("CRITICAL");
      expect(schedule.notifications).toHaveLength(1);
      expect(schedule.notifications?.[0].format).toBe("slack");
    });

    it("should create schedule with registry target", () => {
      const schedule = createSchedule({
        name: "Registry Scan",
        cron: "0 0 * * 0",
        targets: [{ type: "registry", target: "localhost:5000" }],
      });

      expect(schedule.targets[0].type).toBe("registry");
    });

    it("should create schedule with multiple targets", () => {
      const schedule = createSchedule({
        name: "Multi-target Scan",
        cron: "@daily",
        targets: [
          { type: "image", target: "nginx:latest" },
          { type: "image", target: "redis:latest" },
          { type: "path", target: "/app" },
        ],
      });

      expect(schedule.targets).toHaveLength(3);
    });

    it("should generate unique IDs", () => {
      const schedule1 = createSchedule({
        name: "Schedule 1",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
      });

      const schedule2 = createSchedule({
        name: "Schedule 2",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
      });

      expect(schedule1.id).not.toBe(schedule2.id);
    });
  });

  describe("getSchedule", () => {
    it("should get schedule by ID", () => {
      const created = createSchedule({
        name: "Test",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
      });

      const retrieved = getSchedule(created.id);
      expect(retrieved).toBeDefined();
      expect(retrieved?.id).toBe(created.id);
      expect(retrieved?.name).toBe("Test");
    });

    it("should return undefined for non-existent ID", () => {
      const result = getSchedule("non-existent-id");
      expect(result).toBeUndefined();
    });
  });

  describe("listSchedules", () => {
    it("should list all schedules", () => {
      createSchedule({
        name: "Schedule 1",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
      });

      createSchedule({
        name: "Schedule 2",
        cron: "@weekly",
        targets: [{ type: "path", target: "/app" }],
      });

      const schedules = listSchedules();
      expect(schedules).toHaveLength(2);
    });

    it("should filter by enabled status", () => {
      createSchedule({
        name: "Enabled",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
        enabled: true,
      });

      createSchedule({
        name: "Disabled",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
        enabled: false,
      });

      const enabled = listSchedules({ enabled: true });
      expect(enabled).toHaveLength(1);
      expect(enabled[0].name).toBe("Enabled");

      const disabled = listSchedules({ enabled: false });
      expect(disabled).toHaveLength(1);
      expect(disabled[0].name).toBe("Disabled");
    });

    it("should filter by target type", () => {
      createSchedule({
        name: "Image Scan",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
      });

      createSchedule({
        name: "Path Scan",
        cron: "@daily",
        targets: [{ type: "path", target: "/app" }],
      });

      const images = listSchedules({ targetType: "image" });
      expect(images).toHaveLength(1);
      expect(images[0].name).toBe("Image Scan");

      const paths = listSchedules({ targetType: "path" });
      expect(paths).toHaveLength(1);
      expect(paths[0].name).toBe("Path Scan");
    });

    it("should return empty array when no schedules exist", () => {
      const schedules = listSchedules();
      expect(schedules).toEqual([]);
    });
  });

  describe("updateSchedule", () => {
    it("should update schedule name", () => {
      const schedule = createSchedule({
        name: "Original",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
      });

      const updated = updateSchedule(schedule.id, { name: "Updated" });
      expect(updated.name).toBe("Updated");
      expect(updated.cron).toBe("@daily"); // Unchanged
    });

    it("should update cron expression", () => {
      const schedule = createSchedule({
        name: "Test",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
      });

      const updated = updateSchedule(schedule.id, { cron: "@weekly" });
      expect(updated.cron).toBe("@weekly");
      expect(updated.nextRun).toBeDefined();
    });

    it("should update enabled status", () => {
      const schedule = createSchedule({
        name: "Test",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
        enabled: true,
      });

      const updated = updateSchedule(schedule.id, { enabled: false });
      expect(updated.enabled).toBe(false);
    });

    it("should update targets", () => {
      const schedule = createSchedule({
        name: "Test",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
      });

      const updated = updateSchedule(schedule.id, {
        targets: [{ type: "path", target: "/new/path" }],
      });
      expect(updated.targets[0].type).toBe("path");
      expect(updated.targets[0].target).toBe("/new/path");
    });

    it("should throw for non-existent schedule", () => {
      expect(() => updateSchedule("non-existent", { name: "New" })).toThrow();
    });
  });

  describe("deleteSchedule", () => {
    it("should delete schedule", () => {
      const schedule = createSchedule({
        name: "To Delete",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
      });

      deleteSchedule(schedule.id);
      expect(getSchedule(schedule.id)).toBeUndefined();
    });

    it("should throw for non-existent ID", () => {
      expect(() => deleteSchedule("non-existent")).toThrow("not found");
    });

    it("should remove schedule from list", () => {
      const schedule = createSchedule({
        name: "Test",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
      });

      expect(listSchedules()).toHaveLength(1);
      deleteSchedule(schedule.id);
      expect(listSchedules()).toHaveLength(0);
    });
  });
});

// =============================================================================
// Schedule History Tests
// =============================================================================

describe("Schedule History", () => {
  beforeEach(() => {
    clearAllSchedules();
  });

  afterEach(() => {
    stopScheduler();
    clearAllSchedules();
  });

  describe("getScheduleHistory", () => {
    it("should return empty array for new schedule", () => {
      const schedule = createSchedule({
        name: "Test",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
      });

      const history = getScheduleHistory(schedule.id);
      expect(history).toEqual([]);
    });

    it("should return empty array for non-existent schedule", () => {
      const history = getScheduleHistory("non-existent");
      expect(history).toEqual([]);
    });

    it("should respect limit parameter", () => {
      const schedule = createSchedule({
        name: "Test",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
      });

      const history = getScheduleHistory(schedule.id, 5);
      expect(history.length).toBeLessThanOrEqual(5);
    });
  });
});

// =============================================================================
// Scheduler Control Tests
// =============================================================================

describe("Scheduler Control", () => {
  beforeEach(() => {
    clearAllSchedules();
  });

  afterEach(() => {
    stopScheduler();
    clearAllSchedules();
  });

  describe("startScheduler / stopScheduler", () => {
    it("should start scheduler without error", () => {
      expect(() => startScheduler()).not.toThrow();
    });

    it("should stop scheduler without error", () => {
      startScheduler();
      expect(() => stopScheduler()).not.toThrow();
    });

    it("should handle multiple start calls", () => {
      expect(() => {
        startScheduler();
        startScheduler();
      }).not.toThrow();
    });

    it("should handle stop without start", () => {
      expect(() => stopScheduler()).not.toThrow();
    });
  });

  describe("clearAllSchedules", () => {
    it("should clear all schedules", () => {
      createSchedule({
        name: "Schedule 1",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
      });

      createSchedule({
        name: "Schedule 2",
        cron: "@weekly",
        targets: [{ type: "path", target: "/app" }],
      });

      expect(listSchedules()).toHaveLength(2);
      clearAllSchedules();
      expect(listSchedules()).toHaveLength(0);
    });

    it("should be idempotent", () => {
      expect(() => {
        clearAllSchedules();
        clearAllSchedules();
      }).not.toThrow();
    });
  });
});

// =============================================================================
// Trigger Execution Tests
// =============================================================================

describe("triggerSchedule", () => {
  beforeEach(() => {
    clearAllSchedules();
  });

  afterEach(() => {
    stopScheduler();
    clearAllSchedules();
  });

  it("should throw for non-existent schedule", async () => {
    await expect(triggerSchedule("non-existent")).rejects.toThrow("not found");
  });

  it("should return execution result structure", async () => {
    const schedule = createSchedule({
      name: "Test",
      cron: "@daily",
      targets: [{ type: "image", target: "nginx:latest" }],
    });

    // This will attempt to scan - may fail if Trivy not available
    const result = await triggerSchedule(schedule.id);
    expect(result).toHaveProperty("success");
    expect(result).toHaveProperty("scheduleId");
    expect(result.scheduleId).toBe(schedule.id);
  });
});

// =============================================================================
// Edge Cases and Error Handling
// =============================================================================

describe("Edge Cases", () => {
  beforeEach(() => {
    clearAllSchedules();
  });

  afterEach(() => {
    stopScheduler();
    clearAllSchedules();
  });

  describe("Cron Expression Edge Cases", () => {
    it("should handle first day of month expression", () => {
      const parsed = parseCronExpression("0 0 1 * *");
      expect(parsed.dayOfMonth.values).toEqual([1]);
    });

    it("should handle last weekday (Saturday)", () => {
      const parsed = parseCronExpression("0 0 * * 6");
      expect(parsed.dayOfWeek.values).toEqual([6]);
    });

    it("should handle complex expression", () => {
      const parsed = parseCronExpression("0,30 9-17 1-15 1,6 mon-fri");
      expect(parsed.minute.values).toEqual([0, 30]);
      expect(parsed.hour.values).toEqual([9, 10, 11, 12, 13, 14, 15, 16, 17]);
      expect(parsed.dayOfMonth.values).toHaveLength(15);
      expect(parsed.month.values).toEqual([1, 6]);
      expect(parsed.dayOfWeek.values).toEqual([1, 2, 3, 4, 5]);
    });
  });

  describe("Schedule with Notifications", () => {
    it("should create schedule with multiple notifications", () => {
      const schedule = createSchedule({
        name: "Multi-notification",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
        notifications: [
          { url: "https://slack.com/webhook1", format: "slack", notifyOn: ["failure"] },
          { url: "https://teams.com/webhook2", format: "teams", notifyOn: ["success"] },
          {
            url: "https://generic.com/webhook3",
            format: "generic",
            notifyOn: ["success", "failure"],
          },
        ],
      });

      expect(schedule.notifications).toHaveLength(3);
    });
  });

  describe("Timezone handling", () => {
    it("should accept timezone in schedule", () => {
      const schedule = createSchedule({
        name: "TZ Schedule",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
        timezone: "America/New_York",
      });

      expect(schedule.timezone).toBe("America/New_York");
    });
  });

  describe("Schedule Options", () => {
    it("should handle schedule with severity option", () => {
      const schedule = createSchedule({
        name: "High Severity Only",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
        options: { severity: "HIGH,CRITICAL" },
      });

      expect(schedule.options?.severity).toBe("HIGH,CRITICAL");
    });

    it("should handle schedule with concurrency option", () => {
      const schedule = createSchedule({
        name: "High Concurrency",
        cron: "@daily",
        targets: [{ type: "image", target: "nginx:latest" }],
        options: { concurrency: 10 },
      });

      expect(schedule.options?.concurrency).toBe(10);
    });
  });

  describe("startScheduler and stopScheduler", () => {
    it("should start and stop scheduler without error", () => {
      // Create an enabled schedule
      createSchedule({
        name: "StartStop Test",
        cron: "0 0 * * *",
        targets: [{ type: "image", target: "nginx:latest" }],
        enabled: true,
      });

      expect(() => startScheduler()).not.toThrow();
      expect(() => stopScheduler()).not.toThrow();
    });

    it("should handle starting scheduler with disabled schedules", () => {
      createSchedule({
        name: "Disabled Schedule",
        cron: "0 0 * * *",
        targets: [{ type: "image", target: "nginx:latest" }],
        enabled: false,
      });

      expect(() => startScheduler()).not.toThrow();
      stopScheduler();
    });
  });
});
