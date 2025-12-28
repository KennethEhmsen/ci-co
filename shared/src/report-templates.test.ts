/**
 * Tests for Report Templates Module
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import {
  initReportDatabase,
  closeReportDatabase,
  isReportDbInitialized,
  createTemplate,
  getTemplate,
  getTemplateByName,
  listTemplates,
  updateTemplate,
  deleteTemplate,
  generateReport,
  createReportSchedule,
  getReportSchedule,
  listReportSchedules,
  updateReportSchedule,
  deleteReportSchedule,
  getReportHistory,
  cleanupReportHistory,
} from "./report-templates.js";

describe("Report Templates", () => {
  const testDbPath = path.join(process.cwd(), ".test-data", "report-test.db");

  beforeEach(() => {
    // Clean up before each test
    closeReportDatabase();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
  });

  afterEach(() => {
    closeReportDatabase();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
  });

  describe("Database Lifecycle", () => {
    it("should initialize database successfully", () => {
      const result = initReportDatabase(testDbPath);
      expect(result.success).toBe(true);
      expect(result.path).toBe(testDbPath);
      expect(result.builtinTemplates).toBe(5);
      expect(isReportDbInitialized()).toBe(true);
    });

    it("should close database successfully", () => {
      initReportDatabase(testDbPath);
      closeReportDatabase();
      expect(isReportDbInitialized()).toBe(false);
    });

    it("should seed built-in templates", () => {
      initReportDatabase(testDbPath);
      const templates = listTemplates();
      expect(templates.length).toBeGreaterThanOrEqual(5);

      const builtinNames = templates.filter((t) => t.isBuiltin).map((t) => t.name);
      expect(builtinNames).toContain("Executive Summary");
      expect(builtinNames).toContain("Technical Detail Report");
      expect(builtinNames).toContain("Compliance Audit Report");
      expect(builtinNames).toContain("Trend Analysis Report");
      expect(builtinNames).toContain("Vulnerability List");
    });
  });

  describe("Template Management", () => {
    beforeEach(() => {
      initReportDatabase(testDbPath);
    });

    it("should create a custom template", () => {
      const template = createTemplate({
        name: "My Custom Report",
        description: "A custom security report",
        format: "html",
        sections: [
          { type: "health-score", enabled: true },
          { type: "vulnerability-summary", enabled: true },
        ],
      });

      expect(template.id).toBeDefined();
      expect(template.name).toBe("My Custom Report");
      expect(template.description).toBe("A custom security report");
      expect(template.format).toBe("html");
      expect(template.isBuiltin).toBe(false);
      expect(template.sections).toHaveLength(2);
    });

    it("should get a template by ID", () => {
      const created = createTemplate({
        name: "Test Template",
        sections: [{ type: "health-score", enabled: true }],
      });

      const retrieved = getTemplate(created.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.id).toBe(created.id);
      expect(retrieved?.name).toBe("Test Template");
    });

    it("should get a template by name", () => {
      const template = getTemplateByName("Executive Summary");
      expect(template).not.toBeNull();
      expect(template?.isBuiltin).toBe(true);
    });

    it("should return null for non-existent template", () => {
      const template = getTemplate("non-existent-id");
      expect(template).toBeNull();
    });

    it("should list all templates", () => {
      createTemplate({
        name: "Custom Template 1",
        sections: [{ type: "health-score", enabled: true }],
      });
      createTemplate({
        name: "Custom Template 2",
        sections: [{ type: "vulnerability-summary", enabled: true }],
      });

      const templates = listTemplates();
      expect(templates.length).toBeGreaterThanOrEqual(7); // 5 builtin + 2 custom
    });

    it("should filter templates by format", () => {
      createTemplate({
        name: "Markdown Template",
        format: "markdown",
        sections: [{ type: "health-score", enabled: true }],
      });

      const markdownTemplates = listTemplates({ format: "markdown" });
      expect(markdownTemplates.every((t) => t.format === "markdown")).toBe(true);
    });

    it("should exclude built-in templates when requested", () => {
      createTemplate({
        name: "Custom Only",
        sections: [{ type: "health-score", enabled: true }],
      });

      const customTemplates = listTemplates({ includeBuiltin: false });
      expect(customTemplates.every((t) => !t.isBuiltin)).toBe(true);
    });

    it("should update a custom template", () => {
      const created = createTemplate({
        name: "Original Name",
        sections: [{ type: "health-score", enabled: true }],
      });

      const updated = updateTemplate(created.id, {
        name: "Updated Name",
        description: "New description",
      });

      expect(updated).not.toBeNull();
      expect(updated?.name).toBe("Updated Name");
      expect(updated?.description).toBe("New description");
    });

    it("should not allow updating built-in templates", () => {
      const builtin = getTemplateByName("Executive Summary");
      expect(() => {
        updateTemplate(builtin!.id, { name: "Modified" });
      }).toThrow("Cannot modify built-in templates");
    });

    it("should delete a custom template", () => {
      const created = createTemplate({
        name: "To Delete",
        sections: [{ type: "health-score", enabled: true }],
      });

      const deleted = deleteTemplate(created.id);
      expect(deleted).toBe(true);

      const retrieved = getTemplate(created.id);
      expect(retrieved).toBeNull();
    });

    it("should not allow deleting built-in templates", () => {
      const builtin = getTemplateByName("Executive Summary");
      expect(() => {
        deleteTemplate(builtin!.id);
      }).toThrow("Cannot delete built-in templates");
    });
  });

  describe("Report Generation", () => {
    beforeEach(() => {
      initReportDatabase(testDbPath);
    });

    it("should generate a report from built-in template", () => {
      const report = generateReport({
        templateId: "builtin-executive-summary",
      });

      expect(report.id).toBeDefined();
      expect(report.templateId).toBe("builtin-executive-summary");
      expect(report.templateName).toBe("Executive Summary");
      expect(report.format).toBe("html");
      expect(report.content).toBeDefined();
      expect(report.content.length).toBeGreaterThan(0);
      expect(report.generatedAt).toBeDefined();
      expect(report.durationMs).toBeGreaterThanOrEqual(0);
    });

    it("should generate HTML report with all sections", () => {
      const report = generateReport({
        templateId: "builtin-executive-summary",
        includeToc: true,
      });

      expect(report.content).toContain("<!DOCTYPE html>");
      expect(report.content).toContain("Security Health Score");
      expect(report.content).toContain("Vulnerability Summary");
      expect(report.content).toContain("Table of Contents");
    });

    it("should generate Markdown report", () => {
      const report = generateReport({
        templateId: "builtin-vulnerability-list",
      });

      expect(report.format).toBe("markdown");
      expect(report.content).toContain("# Vulnerability List");
      expect(report.content).toContain("CVE ID");
    });

    it("should apply custom title", () => {
      const report = generateReport({
        templateId: "builtin-executive-summary",
        title: "Custom Report Title",
      });

      expect(report.title).toBe("Custom Report Title");
      expect(report.content).toContain("Custom Report Title");
    });

    it("should apply time range filter", () => {
      const report = generateReport({
        templateId: "builtin-executive-summary",
        filters: { timeRange: "7d" },
      });

      expect(report.filters.timeRange).toBe("7d");
    });

    it("should include summary statistics", () => {
      const report = generateReport({
        templateId: "builtin-executive-summary",
      });

      expect(report.summary).toBeDefined();
      expect(typeof report.summary.totalVulnerabilities).toBe("number");
      expect(typeof report.summary.criticalCount).toBe("number");
      expect(typeof report.summary.highCount).toBe("number");
    });

    it("should throw error for non-existent template", () => {
      expect(() => {
        generateReport({ templateId: "non-existent" });
      }).toThrow("Template not found");
    });

    it("should generate JSON format report", () => {
      const customTemplate = createTemplate({
        name: "JSON Report",
        format: "json",
        sections: [
          { type: "health-score", enabled: true },
          { type: "vulnerability-summary", enabled: true },
        ],
      });

      const report = generateReport({ templateId: customTemplate.id });
      expect(report.format).toBe("json");

      const parsed = JSON.parse(report.content);
      expect(parsed.title).toBe("JSON Report");
      expect(parsed.sections).toBeDefined();
    });
  });

  describe("Report History", () => {
    beforeEach(() => {
      initReportDatabase(testDbPath);
    });

    it("should record report generation in history", () => {
      generateReport({ templateId: "builtin-executive-summary" });
      generateReport({ templateId: "builtin-technical-detail" });

      const history = getReportHistory({ limit: 10 });
      expect(history.length).toBe(2);
    });

    it("should filter history by template", () => {
      generateReport({ templateId: "builtin-executive-summary" });
      generateReport({ templateId: "builtin-executive-summary" });
      generateReport({ templateId: "builtin-technical-detail" });

      const history = getReportHistory({
        templateId: "builtin-executive-summary",
      });
      expect(history.length).toBe(2);
    });

    it("should cleanup old history entries", () => {
      generateReport({ templateId: "builtin-executive-summary" });

      // Cleanup with 0 days retention should delete everything
      const deleted = cleanupReportHistory(0);
      expect(deleted).toBe(1);

      const history = getReportHistory();
      expect(history.length).toBe(0);
    });
  });

  describe("Schedule Management", () => {
    beforeEach(() => {
      initReportDatabase(testDbPath);
    });

    it("should create a schedule", () => {
      const schedule = createReportSchedule({
        name: "Daily Security Report",
        templateId: "builtin-executive-summary",
        frequency: "daily",
        hour: 8,
        minute: 0,
      });

      expect(schedule.id).toBeDefined();
      expect(schedule.name).toBe("Daily Security Report");
      expect(schedule.templateId).toBe("builtin-executive-summary");
      expect(schedule.frequency).toBe("daily");
      expect(schedule.enabled).toBe(true);
      expect(schedule.nextRunAt).toBeDefined();
    });

    it("should get a schedule by ID", () => {
      const created = createReportSchedule({
        name: "Test Schedule",
        templateId: "builtin-executive-summary",
        frequency: "weekly",
        dayOfWeek: 1,
      });

      const retrieved = getReportSchedule(created.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.id).toBe(created.id);
    });

    it("should list all schedules", () => {
      createReportSchedule({
        name: "Schedule 1",
        templateId: "builtin-executive-summary",
        frequency: "daily",
      });
      createReportSchedule({
        name: "Schedule 2",
        templateId: "builtin-technical-detail",
        frequency: "weekly",
      });

      const schedules = listReportSchedules();
      expect(schedules.length).toBe(2);
    });

    it("should filter schedules by template", () => {
      createReportSchedule({
        name: "Schedule 1",
        templateId: "builtin-executive-summary",
        frequency: "daily",
      });
      createReportSchedule({
        name: "Schedule 2",
        templateId: "builtin-technical-detail",
        frequency: "daily",
      });

      const filtered = listReportSchedules({
        templateId: "builtin-executive-summary",
      });
      expect(filtered.length).toBe(1);
    });

    it("should filter schedules by enabled status", () => {
      createReportSchedule({
        name: "Enabled",
        templateId: "builtin-executive-summary",
        frequency: "daily",
        enabled: true,
      });
      createReportSchedule({
        name: "Disabled",
        templateId: "builtin-executive-summary",
        frequency: "daily",
        enabled: false,
      });

      const enabled = listReportSchedules({ enabled: true });
      expect(enabled.length).toBe(1);
      expect(enabled[0].name).toBe("Enabled");
    });

    it("should update a schedule", () => {
      const created = createReportSchedule({
        name: "Original",
        templateId: "builtin-executive-summary",
        frequency: "daily",
      });

      const updated = updateReportSchedule(created.id, {
        name: "Updated",
        hour: 9,
        enabled: false,
      });

      expect(updated).not.toBeNull();
      expect(updated?.name).toBe("Updated");
      expect(updated?.hour).toBe(9);
      expect(updated?.enabled).toBe(false);
    });

    it("should delete a schedule", () => {
      const created = createReportSchedule({
        name: "To Delete",
        templateId: "builtin-executive-summary",
        frequency: "daily",
      });

      const deleted = deleteReportSchedule(created.id);
      expect(deleted).toBe(true);

      const retrieved = getReportSchedule(created.id);
      expect(retrieved).toBeNull();
    });

    it("should throw error for non-existent template", () => {
      expect(() => {
        createReportSchedule({
          name: "Invalid",
          templateId: "non-existent",
          frequency: "daily",
        });
      }).toThrow("Template not found");
    });

    it("should calculate next run time correctly for daily", () => {
      const schedule = createReportSchedule({
        name: "Daily",
        templateId: "builtin-executive-summary",
        frequency: "daily",
        hour: 23,
        minute: 59,
      });

      expect(schedule.nextRunAt).toBeDefined();
      const nextRun = new Date(schedule.nextRunAt!);
      expect(nextRun.getHours()).toBe(23);
      expect(nextRun.getMinutes()).toBe(59);
    });

    it("should support webhook configuration", () => {
      const schedule = createReportSchedule({
        name: "With Webhook",
        templateId: "builtin-executive-summary",
        frequency: "daily",
        webhook: {
          url: "https://example.com/webhook",
          method: "POST",
          headers: { Authorization: "Bearer token" },
        },
      });

      expect(schedule.webhook).toBeDefined();
      expect(schedule.webhook?.url).toBe("https://example.com/webhook");
    });
  });

  describe("Error Handling", () => {
    it("should throw when database not initialized", () => {
      expect(() => {
        createTemplate({
          name: "Test",
          sections: [{ type: "health-score", enabled: true }],
        });
      }).toThrow("Report database not initialized");
    });

    it("should return null for update of non-existent template", () => {
      initReportDatabase(testDbPath);
      const result = updateTemplate("non-existent", { name: "Test" });
      expect(result).toBeNull();
    });

    it("should return false for delete of non-existent template", () => {
      initReportDatabase(testDbPath);
      const result = deleteTemplate("non-existent");
      expect(result).toBe(false);
    });

    it("should return null for update of non-existent schedule", () => {
      initReportDatabase(testDbPath);
      const result = updateReportSchedule("non-existent", { name: "Test" });
      expect(result).toBeNull();
    });

    it("should return false for delete of non-existent schedule", () => {
      initReportDatabase(testDbPath);
      const result = deleteReportSchedule("non-existent");
      expect(result).toBe(false);
    });
  });

  describe("Built-in Templates Content", () => {
    beforeEach(() => {
      initReportDatabase(testDbPath);
    });

    it("should have correct sections in Executive Summary", () => {
      const template = getTemplateByName("Executive Summary");
      expect(template).not.toBeNull();

      const enabledSections = template!.sections.filter((s) => s.enabled);
      expect(enabledSections.map((s) => s.type)).toEqual(
        expect.arrayContaining([
          "health-score",
          "vulnerability-summary",
          "compliance-status",
          "top-risks",
          "mttr-metrics",
        ])
      );
    });

    it("should have correct sections in Technical Detail", () => {
      const template = getTemplateByName("Technical Detail Report");
      expect(template).not.toBeNull();

      const enabledSections = template!.sections.filter((s) => s.enabled);
      expect(enabledSections.map((s) => s.type)).toEqual(
        expect.arrayContaining([
          "vulnerability-summary",
          "vulnerability-list",
          "remediation-status",
          "scan-coverage",
        ])
      );
    });

    it("should have correct sections in Compliance Audit", () => {
      const template = getTemplateByName("Compliance Audit Report");
      expect(template).not.toBeNull();

      const enabledSections = template!.sections.filter((s) => s.enabled);
      expect(enabledSections.map((s) => s.type)).toContain("compliance-status");
    });
  });
});
