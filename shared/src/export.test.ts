/**
 * Export Module Tests
 *
 * Tests for PDF, Excel, and CSV export functionality.
 * Note: PDF tests require puppeteer which may not be available in all environments.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import {
  exportToCsv,
  exportToExcel,
  createVulnerabilityWorksheet,
  createSummaryWorksheet,
  createComplianceWorksheet,
  checkExportDependencies,
} from "./export.js";
import type { ReportData, CsvExportOptions } from "./types.js";

describe("Export Module", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "export-test-"));
  });

  afterEach(() => {
    // Clean up temp files
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  const sampleReportData: ReportData = {
    title: "Security Scan Report",
    generatedAt: new Date().toISOString(),
    target: "myapp:latest",
    summary: {
      totalVulnerabilities: 10,
      criticalCount: 2,
      highCount: 3,
      mediumCount: 4,
      lowCount: 1,
      healthScore: 75,
    },
    vulnerabilities: [
      {
        id: "CVE-2024-1234",
        severity: "CRITICAL",
        package: "lodash",
        version: "4.17.20",
        fixedVersion: "4.17.21",
        title: "Prototype Pollution",
        cvss: 9.8,
        riskScore: 95,
      },
      {
        id: "CVE-2024-5678",
        severity: "HIGH",
        package: "express",
        version: "4.18.0",
        fixedVersion: "4.18.2",
        title: "Path Traversal",
        cvss: 7.5,
        riskScore: 72,
      },
      {
        id: "CVE-2024-9012",
        severity: "MEDIUM",
        package: "axios",
        version: "1.0.0",
        fixedVersion: "1.0.1",
        title: "SSRF Vulnerability",
        cvss: 5.3,
        riskScore: 45,
      },
    ],
    compliance: [
      { framework: "SOC2", control: "CC6.1", status: "PASS", findings: 0 },
      { framework: "HIPAA", control: "164.312(a)(1)", status: "FAIL", findings: 2 },
    ],
    trends: [
      { date: "2024-12-01", critical: 5, high: 10, medium: 15, low: 20 },
      { date: "2024-12-15", critical: 3, high: 8, medium: 12, low: 18 },
      { date: "2024-12-29", critical: 2, high: 3, medium: 4, low: 1 },
    ],
  };

  describe("CSV Export", () => {
    it("should export data to CSV format", async () => {
      const outputPath = path.join(tempDir, "test-export.csv");
      const data = [
        { id: "1", name: "Test Item", value: 100 },
        { id: "2", name: "Another Item", value: 200 },
      ];

      const result = await exportToCsv({
        outputPath,
        data,
      });

      expect(result.success).toBe(true);
      expect(result.path).toBe(outputPath);
      expect(result.format).toBe("csv");
      expect(result.rowCount).toBe(2);
      expect(fs.existsSync(outputPath)).toBe(true);

      const content = fs.readFileSync(outputPath, "utf8");
      expect(content).toContain("id,name,value");
      expect(content).toContain("1,Test Item,100");
    });

    it("should include UTF-8 BOM when requested", async () => {
      const outputPath = path.join(tempDir, "test-bom.csv");

      await exportToCsv({
        outputPath,
        data: [{ a: "1" }],
        includeBom: true,
      });

      const buffer = fs.readFileSync(outputPath);
      // UTF-8 BOM is EF BB BF
      expect(buffer[0]).toBe(0xef);
      expect(buffer[1]).toBe(0xbb);
      expect(buffer[2]).toBe(0xbf);
    });

    it("should use custom delimiter", async () => {
      const outputPath = path.join(tempDir, "test-semicolon.csv");

      await exportToCsv({
        outputPath,
        data: [{ a: "1", b: "2" }],
        delimiter: ";",
      });

      const content = fs.readFileSync(outputPath, "utf8");
      expect(content).toContain("a;b");
      expect(content).toContain("1;2");
    });

    it("should quote fields containing delimiter", async () => {
      const outputPath = path.join(tempDir, "test-quotes.csv");

      await exportToCsv({
        outputPath,
        data: [{ text: "Hello, World" }],
      });

      const content = fs.readFileSync(outputPath, "utf8");
      expect(content).toContain('"Hello, World"');
    });

    it("should escape quotes in values", async () => {
      const outputPath = path.join(tempDir, "test-escape.csv");

      await exportToCsv({
        outputPath,
        data: [{ text: 'Say "Hello"' }],
      });

      const content = fs.readFileSync(outputPath, "utf8");
      expect(content).toContain('"Say ""Hello"""');
    });

    it("should use custom headers", async () => {
      const outputPath = path.join(tempDir, "test-headers.csv");

      await exportToCsv({
        outputPath,
        data: [{ id: "1", name: "Test" }],
        headers: {
          id: "Identifier",
          name: "Full Name",
        },
      });

      const content = fs.readFileSync(outputPath, "utf8");
      expect(content).toContain("Identifier,Full Name");
    });

    it("should use specified column order", async () => {
      const outputPath = path.join(tempDir, "test-order.csv");

      await exportToCsv({
        outputPath,
        data: [{ a: "1", b: "2", c: "3" }],
        columns: ["c", "a", "b"],
      });

      const content = fs.readFileSync(outputPath, "utf8");
      const lines = content.split("\n");
      expect(lines[0]).toBe("c,a,b");
      expect(lines[1]).toBe("3,1,2");
    });

    it("should quote all fields when requested", async () => {
      const outputPath = path.join(tempDir, "test-quote-all.csv");

      await exportToCsv({
        outputPath,
        data: [{ a: "simple", b: "text" }],
        quoteAll: true,
      });

      const content = fs.readFileSync(outputPath, "utf8");
      expect(content).toContain('"a","b"');
      expect(content).toContain('"simple","text"');
    });

    it("should handle empty data array", async () => {
      const outputPath = path.join(tempDir, "test-empty.csv");

      const result = await exportToCsv({
        outputPath,
        data: [],
      });

      expect(result.success).toBe(true);
      expect(result.rowCount).toBe(0);
    });

    it("should use tab delimiter", async () => {
      const outputPath = path.join(tempDir, "test-tsv.csv");

      await exportToCsv({
        outputPath,
        data: [{ col1: "a", col2: "b" }],
        delimiter: "\t",
      });

      const content = fs.readFileSync(outputPath, "utf8");
      expect(content).toContain("col1\tcol2");
    });

    it("should handle null and undefined values", async () => {
      const outputPath = path.join(tempDir, "test-nulls.csv");

      await exportToCsv({
        outputPath,
        data: [{ a: null, b: undefined, c: "" }] as unknown as CsvExportOptions["data"],
      });

      const content = fs.readFileSync(outputPath, "utf8");
      expect(content).toContain(",,");
    });

    it("should use Windows line endings when specified", async () => {
      const outputPath = path.join(tempDir, "test-crlf.csv");

      await exportToCsv({
        outputPath,
        data: [{ a: "1" }, { a: "2" }],
        lineEnding: "\r\n",
      });

      const content = fs.readFileSync(outputPath, "utf8");
      expect(content).toContain("\r\n");
    });

    it("should record duration", async () => {
      const outputPath = path.join(tempDir, "test-duration.csv");

      const result = await exportToCsv({
        outputPath,
        data: [{ a: "1" }],
      });

      expect(result.duration).toBeGreaterThanOrEqual(0);
      expect(result.duration).toBeLessThan(1000);
    });

    it("should create output directory if it doesn't exist", async () => {
      const outputPath = path.join(tempDir, "subdir", "nested", "test.csv");

      const result = await exportToCsv({
        outputPath,
        data: [{ a: "1" }],
      });

      expect(result.success).toBe(true);
      expect(fs.existsSync(outputPath)).toBe(true);
    });
  });

  describe("Worksheet Helpers", () => {
    it("should create vulnerability worksheet from report data", () => {
      const worksheet = createVulnerabilityWorksheet(sampleReportData);

      expect(worksheet.name).toBe("Vulnerabilities");
      expect(worksheet.data.length).toBe(3);
      expect(worksheet.columns).toBeDefined();
      expect(worksheet.columns?.length).toBe(8);
      expect(worksheet.includeFilters).toBe(true);
      expect(worksheet.freezeHeader).toBe(true);
    });

    it("should create summary worksheet from report data", () => {
      const worksheet = createSummaryWorksheet(sampleReportData);

      expect(worksheet.name).toBe("Summary");
      expect(worksheet.data.length).toBeGreaterThan(0);
      expect(worksheet.freezeHeader).toBe(true);
    });

    it("should create compliance worksheet from report data", () => {
      const worksheet = createComplianceWorksheet(sampleReportData);

      expect(worksheet.name).toBe("Compliance");
      expect(worksheet.data.length).toBe(2);
      expect(worksheet.includeFilters).toBe(true);
    });

    it("should handle empty vulnerabilities", () => {
      const emptyData: ReportData = {
        title: "Empty Report",
        generatedAt: new Date().toISOString(),
      };

      const worksheet = createVulnerabilityWorksheet(emptyData);
      expect(worksheet.data.length).toBe(0);
    });

    it("should handle empty compliance data", () => {
      const emptyData: ReportData = {
        title: "Empty Report",
        generatedAt: new Date().toISOString(),
      };

      const worksheet = createComplianceWorksheet(emptyData);
      expect(worksheet.data.length).toBe(0);
    });

    it("should include health score in summary when present", () => {
      const worksheet = createSummaryWorksheet(sampleReportData);
      const data = worksheet.data as Array<{ metric: string; value: unknown }>;

      const healthScoreRow = data.find((row) => row.metric === "Health Score");
      expect(healthScoreRow).toBeDefined();
      expect(healthScoreRow?.value).toBe(75);
    });
  });

  describe("Excel Export", () => {
    it("should export report data to Excel format", async () => {
      const outputPath = path.join(tempDir, "test-report.xlsx");

      const result = await exportToExcel(sampleReportData, {
        outputPath,
        worksheets: [
          createSummaryWorksheet(sampleReportData),
          createVulnerabilityWorksheet(sampleReportData),
        ],
        title: "Security Report",
        author: "Test User",
      });

      expect(result.success).toBe(true);
      expect(result.path).toBe(outputPath);
      expect(result.format).toBe("excel");
      expect(result.worksheetCount).toBe(2);
      expect(fs.existsSync(outputPath)).toBe(true);
    });

    it("should handle single worksheet", async () => {
      const outputPath = path.join(tempDir, "single-sheet.xlsx");

      const result = await exportToExcel(sampleReportData, {
        outputPath,
        worksheets: [createSummaryWorksheet(sampleReportData)],
      });

      expect(result.success).toBe(true);
      expect(result.worksheetCount).toBe(1);
    });

    it("should set document properties", async () => {
      const outputPath = path.join(tempDir, "with-props.xlsx");

      const result = await exportToExcel(sampleReportData, {
        outputPath,
        worksheets: [createSummaryWorksheet(sampleReportData)],
        title: "Test Title",
        author: "Test Author",
        company: "Test Company",
      });

      expect(result.success).toBe(true);
    });

    it("should include trend chart data when available", async () => {
      const outputPath = path.join(tempDir, "with-trends.xlsx");

      const result = await exportToExcel(sampleReportData, {
        outputPath,
        worksheets: [createSummaryWorksheet(sampleReportData)],
        includeCharts: true,
      });

      expect(result.success).toBe(true);
      expect(result.hasCharts).toBe(true);
    });

    it("should not include charts when no trend data", async () => {
      const noTrendData: ReportData = {
        title: "No Trends",
        generatedAt: new Date().toISOString(),
      };

      const outputPath = path.join(tempDir, "no-trends.xlsx");

      const result = await exportToExcel(noTrendData, {
        outputPath,
        worksheets: [createSummaryWorksheet(noTrendData)],
        includeCharts: true,
      });

      expect(result.success).toBe(true);
      expect(result.hasCharts).toBe(false);
    });

    it("should create output directory if needed", async () => {
      const outputPath = path.join(tempDir, "new-dir", "report.xlsx");

      const result = await exportToExcel(sampleReportData, {
        outputPath,
        worksheets: [createSummaryWorksheet(sampleReportData)],
      });

      expect(result.success).toBe(true);
      expect(fs.existsSync(outputPath)).toBe(true);
    });

    it("should handle 2D array data", async () => {
      const outputPath = path.join(tempDir, "array-data.xlsx");

      const result = await exportToExcel(sampleReportData, {
        outputPath,
        worksheets: [
          {
            name: "Array Data",
            data: [
              ["Header 1", "Header 2"],
              ["Value 1", "Value 2"],
            ],
          },
        ],
      });

      expect(result.success).toBe(true);
    });
  });

  describe("Dependency Check", () => {
    it("should report CSV as always available", async () => {
      const deps = await checkExportDependencies();

      expect(deps.csv).toBe(true);
    });

    it("should check PDF and Excel availability", async () => {
      const deps = await checkExportDependencies();

      // These may or may not be available depending on environment
      expect(typeof deps.pdf).toBe("boolean");
      expect(typeof deps.excel).toBe("boolean");
    });
  });

  describe("Error Handling", () => {
    it("should handle invalid output path", async () => {
      // Try to write to a path with invalid characters (Windows)
      const invalidPath =
        process.platform === "win32"
          ? "Z:\\nonexistent\\path\\file.csv"
          : "/root/no-permission.csv";

      const result = await exportToCsv({
        outputPath: invalidPath,
        data: [{ a: "1" }],
      });

      // Either succeeds (if dir is creatable) or returns error
      if (!result.success) {
        expect(result.error).toBeDefined();
      }
    });
  });
});
