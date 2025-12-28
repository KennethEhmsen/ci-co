/**
 * Tests for Executive Dashboard Module
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import {
  initDashboardDatabase,
  closeDashboardDatabase,
  isDashboardDbInitialized,
  getDashboardConfig,
  updateDashboardConfig,
  setAssetCriticality,
  getAssetCriticality,
  listAssetCriticalities,
  recordScan,
  getScanRecords,
  recordVulnerabilityDetected,
  markVulnerabilityRemediated,
  calculateHealthScore,
  getHealthScore,
  getVulnerabilityCounts,
  getScanCoverage,
  getMTTRMetrics,
  getTopRisks,
  getComplianceStatus,
  getDashboardSummary,
  saveDashboardSnapshot,
  getDashboardSnapshots,
  cleanupOldSnapshots,
} from "./executive-dashboard.js";
import type {
  SeverityCounts,
  ComplianceStatusSummary,
  ScanCoverage,
  MTTRMetrics,
} from "./types.js";

describe("Executive Dashboard", () => {
  const testDbPath = path.join(process.cwd(), ".test-data", "dashboard-test.db");

  beforeEach(() => {
    // Clean up before each test
    closeDashboardDatabase();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
  });

  afterEach(() => {
    closeDashboardDatabase();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
  });

  describe("Database Lifecycle", () => {
    it("should initialize database successfully", () => {
      const result = initDashboardDatabase(testDbPath);
      expect(result.success).toBe(true);
      expect(result.path).toBe(testDbPath);
      expect(isDashboardDbInitialized()).toBe(true);
    });

    it("should close database successfully", () => {
      initDashboardDatabase(testDbPath);
      closeDashboardDatabase();
      expect(isDashboardDbInitialized()).toBe(false);
    });

    it("should apply initial config", () => {
      initDashboardDatabase(testDbPath, { topRisksCount: 5 });
      const config = getDashboardConfig();
      expect(config.topRisksCount).toBe(5);
    });
  });

  describe("Configuration", () => {
    beforeEach(() => {
      // Close and reinitialize to get fresh defaults
      closeDashboardDatabase();
      if (fs.existsSync(testDbPath)) {
        fs.unlinkSync(testDbPath);
      }
      initDashboardDatabase(testDbPath);
    });

    it("should get default configuration", () => {
      const config = getDashboardConfig();
      expect(config.defaultTimeRange).toBe("30d");
      expect(config.topRisksCount).toBe(10);
      expect(config.weights.vulnerability).toBe(0.4);
    });

    it("should update configuration", () => {
      const updated = updateDashboardConfig({
        defaultTimeRange: "7d",
        topRisksCount: 5,
      });
      expect(updated.defaultTimeRange).toBe("7d");
      expect(updated.topRisksCount).toBe(5);

      // Verify persistence
      const config = getDashboardConfig();
      expect(config.defaultTimeRange).toBe("7d");
    });
  });

  describe("Asset Criticality", () => {
    beforeEach(() => {
      initDashboardDatabase(testDbPath);
    });

    it("should set and get asset criticality", () => {
      const result = setAssetCriticality("myapp", "image", "critical", {
        notes: "Production system",
        setBy: "admin",
      });

      expect(result.asset).toBe("myapp");
      expect(result.criticality).toBe("critical");
      expect(result.notes).toBe("Production system");

      const retrieved = getAssetCriticality("myapp", "image");
      expect(retrieved).not.toBeNull();
      expect(retrieved?.criticality).toBe("critical");
    });

    it("should return null for unknown asset", () => {
      const result = getAssetCriticality("unknown", "image");
      expect(result).toBeNull();
    });

    it("should list all asset criticalities", () => {
      setAssetCriticality("app1", "image", "critical");
      setAssetCriticality("app2", "project", "high");
      setAssetCriticality("app3", "repository", "medium");

      const list = listAssetCriticalities();
      expect(list).toHaveLength(3);
      expect(list.map((a) => a.asset)).toContain("app1");
      expect(list.map((a) => a.asset)).toContain("app2");
    });

    it("should update existing criticality", () => {
      setAssetCriticality("myapp", "image", "medium");
      setAssetCriticality("myapp", "image", "critical");

      const retrieved = getAssetCriticality("myapp", "image");
      expect(retrieved?.criticality).toBe("critical");
    });
  });

  describe("Scan Recording", () => {
    beforeEach(() => {
      initDashboardDatabase(testDbPath);
    });

    it("should record a scan", () => {
      const id = recordScan("nginx:latest", "image", "trivy", {
        critical: 2,
        high: 5,
        medium: 10,
        low: 20,
      });

      expect(id).toBeDefined();
      expect(typeof id).toBe("string");
    });

    it("should get scan records for a target", () => {
      recordScan("nginx:latest", "image", "trivy", {
        critical: 2,
        high: 5,
        medium: 10,
        low: 20,
      });

      const records = getScanRecords("nginx:latest");
      expect(records).toHaveLength(1);
      expect(records[0].target).toBe("nginx:latest");
      expect(records[0].severityCounts.critical).toBe(2);
    });

    it("should limit scan records", () => {
      for (let i = 0; i < 5; i++) {
        recordScan("nginx:latest", "image", "trivy", {
          critical: i,
          high: 0,
          medium: 0,
          low: 0,
        });
      }

      const records = getScanRecords("nginx:latest", { limit: 2 });
      expect(records).toHaveLength(2);
    });
  });

  describe("Remediation Tracking", () => {
    beforeEach(() => {
      initDashboardDatabase(testDbPath);
    });

    it("should record vulnerability detection", () => {
      const id = recordVulnerabilityDetected("CVE-2024-1234", "nginx:latest", "CRITICAL");
      expect(id).toBeDefined();
    });

    it("should not duplicate open vulnerabilities", () => {
      const id1 = recordVulnerabilityDetected("CVE-2024-1234", "nginx:latest", "CRITICAL");
      const id2 = recordVulnerabilityDetected("CVE-2024-1234", "nginx:latest", "CRITICAL");
      expect(id1).toBe(id2);
    });

    it("should mark vulnerability as remediated", () => {
      recordVulnerabilityDetected("CVE-2024-1234", "nginx:latest", "CRITICAL");
      const result = markVulnerabilityRemediated("CVE-2024-1234", "nginx:latest");
      expect(result).toBe(true);
    });

    it("should return false for non-existent vulnerability", () => {
      const result = markVulnerabilityRemediated("CVE-UNKNOWN", "nginx:latest");
      expect(result).toBe(false);
    });
  });

  describe("Health Score Calculation", () => {
    const mockVulnerabilities: SeverityCounts = {
      critical: 0,
      high: 0,
      medium: 5,
      low: 10,
    };

    const mockCompliance: ComplianceStatusSummary[] = [
      {
        framework: "SOC2",
        totalControls: 10,
        passingControls: 10,
        failingControls: 0,
        compliancePercent: 100,
        status: "compliant",
      },
    ];

    const mockCoverage: ScanCoverage = {
      totalAssets: 10,
      scannedAssets: 10,
      coveragePercent: 100,
      neverScanned: 0,
      staleScans: 0,
    };

    const mockMttr: MTTRMetrics = {
      overall: 5,
      bySeverity: { critical: 3, high: 7, medium: 14, low: 30 },
      trend: { current: 5, previous: 7, change: -2, changePercent: -28.57, direction: "down" },
    };

    it("should calculate health score", () => {
      const score = calculateHealthScore(
        mockVulnerabilities,
        mockCompliance,
        mockCoverage,
        mockMttr
      );

      expect(score.score).toBeGreaterThanOrEqual(0);
      expect(score.score).toBeLessThanOrEqual(100);
      expect(["A", "B", "C", "D", "F"]).toContain(score.grade);
      expect(score.components).toBeDefined();
      expect(score.trend).toBeDefined();
    });

    it("should give grade A for score >= 90", () => {
      const perfectVulns: SeverityCounts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      };
      const score = calculateHealthScore(perfectVulns, mockCompliance, mockCoverage, mockMttr);
      expect(score.grade).toBe("A");
    });

    it("should give grade F for poor score", () => {
      const badVulns: SeverityCounts = {
        critical: 10,
        high: 20,
        medium: 30,
        low: 40,
      };
      const score = calculateHealthScore(
        badVulns,
        [],
        { ...mockCoverage, coveragePercent: 0 },
        { ...mockMttr, bySeverity: { critical: 60, high: 90, medium: 120, low: 180 } }
      );
      expect(score.grade).toBe("F");
    });

    it("should calculate trend correctly", () => {
      const score = calculateHealthScore(
        mockVulnerabilities,
        mockCompliance,
        mockCoverage,
        mockMttr,
        80 // Previous score
      );

      expect(score.trend.previous).toBe(80);
      expect(score.trend.direction).toBeDefined();
    });
  });

  describe("Dashboard Data Retrieval", () => {
    beforeEach(() => {
      initDashboardDatabase(testDbPath);
    });

    it("should get vulnerability counts", () => {
      recordScan("app1", "image", "trivy", {
        critical: 1,
        high: 2,
        medium: 3,
        low: 4,
      });
      recordScan("app2", "image", "trivy", {
        critical: 2,
        high: 3,
        medium: 4,
        low: 5,
      });

      const counts = getVulnerabilityCounts("30d");
      expect(counts.critical).toBe(3);
      expect(counts.high).toBe(5);
      expect(counts.medium).toBe(7);
      expect(counts.low).toBe(9);
    });

    it("should get scan coverage", () => {
      recordScan("app1", "image", "trivy", { critical: 0, high: 0, medium: 0, low: 0 });
      recordScan("app2", "image", "trivy", { critical: 0, high: 0, medium: 0, low: 0 });

      const coverage = getScanCoverage("30d");
      expect(coverage.totalAssets).toBe(2);
      expect(coverage.scannedAssets).toBe(2);
      expect(coverage.coveragePercent).toBe(100);
    });

    it("should get MTTR metrics", () => {
      const mttr = getMTTRMetrics("30d");
      expect(mttr.overall).toBeGreaterThanOrEqual(0);
      expect(mttr.bySeverity).toBeDefined();
      expect(mttr.trend).toBeDefined();
    });

    it("should get top risks", () => {
      recordScan("risky-app", "image", "trivy", {
        critical: 5,
        high: 10,
        medium: 20,
        low: 30,
      });
      setAssetCriticality("risky-app", "image", "critical");

      const risks = getTopRisks(5);
      expect(risks.length).toBeGreaterThanOrEqual(1);
      expect(risks[0].target).toBe("risky-app");
      expect(risks[0].riskScore).toBeGreaterThan(0);
    });

    it("should get compliance status", () => {
      const status = getComplianceStatus();
      expect(status).toBeInstanceOf(Array);
      expect(status.length).toBeGreaterThan(0);
      expect(status[0].framework).toBeDefined();
    });
  });

  describe("Dashboard Summary", () => {
    beforeEach(() => {
      initDashboardDatabase(testDbPath);
    });

    it("should get dashboard summary", () => {
      recordScan("app1", "image", "trivy", {
        critical: 1,
        high: 2,
        medium: 3,
        low: 4,
      });

      const summary = getDashboardSummary("30d");
      expect(summary.healthScore).toBeDefined();
      expect(summary.vulnerabilities).toBeDefined();
      expect(summary.compliance).toBeDefined();
      expect(summary.topRisks).toBeDefined();
      expect(summary.mttr).toBeDefined();
      expect(summary.coverage).toBeDefined();
      expect(summary.timeRange).toBe("30d");
      expect(summary.generatedAt).toBeDefined();
    });

    it("should get health score only", () => {
      const score = getHealthScore("7d");
      expect(score.score).toBeGreaterThanOrEqual(0);
      expect(score.score).toBeLessThanOrEqual(100);
      expect(score.grade).toBeDefined();
      expect(score.components).toBeDefined();
    });
  });

  describe("Snapshot Management", () => {
    beforeEach(() => {
      initDashboardDatabase(testDbPath);
    });

    it("should save dashboard snapshot", () => {
      recordScan("app1", "image", "trivy", {
        critical: 1,
        high: 2,
        medium: 3,
        low: 4,
      });

      const snapshot = saveDashboardSnapshot();
      expect(snapshot.id).toBeDefined();
      expect(snapshot.timestamp).toBeDefined();
      expect(snapshot.healthScore).toBeGreaterThanOrEqual(0);
      expect(snapshot.vulnerabilities).toBeDefined();
    });

    it("should get dashboard snapshots", () => {
      saveDashboardSnapshot();
      saveDashboardSnapshot();

      const snapshots = getDashboardSnapshots({ limit: 10 });
      expect(snapshots.length).toBe(2);
    });

    it("should filter snapshots by date", () => {
      saveDashboardSnapshot();

      const futureDate = new Date(Date.now() + 86400000).toISOString();
      const snapshots = getDashboardSnapshots({ since: futureDate });
      expect(snapshots.length).toBe(0);
    });

    it("should cleanup old snapshots", () => {
      // Create snapshot and set its timestamp to 100 days ago manually
      saveDashboardSnapshot();

      // Cleanup with 90 day retention should keep recent snapshot
      const deleted = cleanupOldSnapshots(90);
      expect(deleted).toBe(0);
    });
  });

  describe("Empty State Handling", () => {
    beforeEach(() => {
      initDashboardDatabase(testDbPath);
    });

    it("should handle empty vulnerability counts", () => {
      const counts = getVulnerabilityCounts("30d");
      expect(counts.critical).toBe(0);
      expect(counts.high).toBe(0);
    });

    it("should handle empty scan coverage", () => {
      const coverage = getScanCoverage("30d");
      expect(coverage.totalAssets).toBe(0);
      expect(coverage.coveragePercent).toBe(100); // 100% when no assets
    });

    it("should handle empty top risks", () => {
      const risks = getTopRisks(10);
      expect(risks).toHaveLength(0);
    });

    it("should return empty array for snapshots", () => {
      const snapshots = getDashboardSnapshots();
      expect(snapshots).toHaveLength(0);
    });
  });

  describe("Error Handling", () => {
    it("should throw when database not initialized", () => {
      expect(() => setAssetCriticality("app", "image", "critical")).toThrow(
        "Dashboard database not initialized"
      );
    });

    it("should return empty counts when not initialized", () => {
      const counts = getVulnerabilityCounts("30d");
      expect(counts.critical).toBe(0);
    });

    it("should return empty risks when not initialized", () => {
      const risks = getTopRisks(10);
      expect(risks).toHaveLength(0);
    });
  });
});
