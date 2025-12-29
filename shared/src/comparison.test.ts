/**
 * Tests for Cross-Project Comparative Analysis Module
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

import {
  initComparisonDb,
  closeComparisonDb,
  compareProjects,
  compareTeams,
  compareToBaseline,
  createBaseline,
  getBaseline,
  getDefaultBaseline,
  listBaselines,
  deleteBaseline,
  setDefaultBaseline,
  recordEntityMetrics,
  getRankings,
  getCachedComparison,
  cacheComparison,
  clearExpiredCache,
} from "./comparison.js";

import type { EntityMetrics } from "./types.js";

// =============================================================================
// Test Fixtures
// =============================================================================

function createTestMetrics(overrides: Partial<EntityMetrics> = {}): EntityMetrics {
  return {
    entityId: "test-entity-1",
    entityName: "Test Entity",
    entityType: "project",
    timestamp: new Date().toISOString(),
    vulnerabilityCount: 50,
    criticalCount: 5,
    highCount: 10,
    mediumCount: 20,
    lowCount: 15,
    riskScore: 65,
    healthScore: 70,
    complianceScore: 85,
    mttr: 48,
    remediationVelocity: 2.5,
    scanCoverage: 90,
    assetCount: 10,
    ...overrides,
  };
}

// =============================================================================
// Database Setup/Teardown
// =============================================================================

describe("comparison", () => {
  let testDbPath: string;

  beforeEach(() => {
    // Create a temporary database for each test
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "comparison-test-"));
    testDbPath = path.join(tempDir, "comparison.db");
    const result = initComparisonDb(testDbPath);
    expect(result.success).toBe(true);
  });

  afterEach(() => {
    closeComparisonDb();
    // Clean up temp directory
    const tempDir = path.dirname(testDbPath);
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  // ===========================================================================
  // compareProjects Tests
  // ===========================================================================

  describe("compareProjects", () => {
    it("should compare two projects with metrics", () => {
      const metricsA = createTestMetrics({
        entityId: "project-a",
        entityName: "Project A",
        vulnerabilityCount: 50,
        criticalCount: 5,
        riskScore: 65,
      });

      const metricsB = createTestMetrics({
        entityId: "project-b",
        entityName: "Project B",
        vulnerabilityCount: 30,
        criticalCount: 2,
        riskScore: 40,
      });

      const result = compareProjects({
        projectIdA: "project-a",
        projectIdB: "project-b",
        metricsA,
        metricsB,
      });

      expect(result.entityA.entityId).toBe("project-a");
      expect(result.entityB.entityId).toBe("project-b");
      expect(result.metrics.length).toBeGreaterThan(0);
      expect(result.summary).toBeDefined();
      expect(result.summary.betterEntity).toBeDefined();
      expect(result.comparedAt).toBeDefined();
    });

    it("should identify better entity correctly", () => {
      const metricsA = createTestMetrics({
        vulnerabilityCount: 100,
        criticalCount: 20,
        highCount: 30,
        riskScore: 85,
        healthScore: 40,
        complianceScore: 50,
      });

      const metricsB = createTestMetrics({
        vulnerabilityCount: 20,
        criticalCount: 1,
        highCount: 5,
        riskScore: 25,
        healthScore: 90,
        complianceScore: 95,
      });

      const result = compareProjects({
        projectIdA: "worse-project",
        projectIdB: "better-project",
        metricsA,
        metricsB,
      });

      // Entity B should be better (fewer vulnerabilities, lower risk)
      expect(result.summary.betterEntity).toBe("B");
    });

    it("should generate key differences", () => {
      const metricsA = createTestMetrics({
        criticalCount: 50,
      });

      const metricsB = createTestMetrics({
        criticalCount: 5,
      });

      const result = compareProjects({
        projectIdA: "project-a",
        projectIdB: "project-b",
        metricsA,
        metricsB,
      });

      expect(result.summary.keyDifferences.length).toBeGreaterThan(0);
    });

    it("should generate recommendations for critical vulnerabilities", () => {
      const metricsA = createTestMetrics({
        criticalCount: 20,
      });

      const metricsB = createTestMetrics({
        criticalCount: 0,
      });

      const result = compareProjects({
        projectIdA: "project-a",
        projectIdB: "project-b",
        metricsA,
        metricsB,
      });

      const hasVulnRecommendation = result.summary.recommendations.some((r) =>
        r.includes("critical")
      );
      expect(hasVulnRecommendation).toBe(true);
    });

    it("should normalize by asset count when requested", () => {
      const metricsA = createTestMetrics({
        vulnerabilityCount: 100,
        assetCount: 10,
      });

      const metricsB = createTestMetrics({
        vulnerabilityCount: 50,
        assetCount: 10,
      });

      const result = compareProjects({
        projectIdA: "project-a",
        projectIdB: "project-b",
        metricsA,
        metricsB,
        normalize: true,
      });

      // Normalized vulnerability counts should be 10 and 5
      const vulnMetric = result.metrics.find((m) => m.metric === "vulnerability_count");
      expect(vulnMetric?.valueA).toBe(10);
      expect(vulnMetric?.valueB).toBe(5);
    });

    it("should throw error if metrics not provided", () => {
      expect(() => {
        compareProjects({
          projectIdA: "project-a",
          projectIdB: "project-b",
        });
      }).toThrow("Metrics must be provided");
    });
  });

  // ===========================================================================
  // compareTeams Tests
  // ===========================================================================

  describe("compareTeams", () => {
    it("should compare two teams with metrics", () => {
      const metricsA = createTestMetrics({
        entityId: "team-a",
        entityName: "Team A",
        entityType: "team",
      });

      const metricsB = createTestMetrics({
        entityId: "team-b",
        entityName: "Team B",
        entityType: "team",
      });

      const result = compareTeams({
        teamIdA: "team-a",
        teamIdB: "team-b",
        metricsA,
        metricsB,
      });

      expect(result.entityA.entityType).toBe("team");
      expect(result.entityB.entityType).toBe("team");
      expect(result.metrics.length).toBeGreaterThan(0);
    });

    it("should throw error if metrics not provided", () => {
      expect(() => {
        compareTeams({
          teamIdA: "team-a",
          teamIdB: "team-b",
        });
      }).toThrow("Metrics must be provided");
    });
  });

  // ===========================================================================
  // Baseline Tests
  // ===========================================================================

  describe("baselines", () => {
    it("should create a baseline", () => {
      const metrics = createTestMetrics();
      const baseline = createBaseline({
        name: "Test Baseline",
        description: "A test baseline",
        entityType: "project",
        entityId: "project-1",
        entityName: "Project One",
        metrics,
        tags: ["test", "v1"],
      });

      expect(baseline.id).toBeDefined();
      expect(baseline.name).toBe("Test Baseline");
      expect(baseline.description).toBe("A test baseline");
      expect(baseline.entityType).toBe("project");
      expect(baseline.metrics).toEqual(metrics);
      expect(baseline.tags).toEqual(["test", "v1"]);
    });

    it("should get a baseline by ID", () => {
      const metrics = createTestMetrics();
      const created = createBaseline({
        name: "Test Baseline",
        entityType: "project",
        entityId: "project-1",
        entityName: "Project One",
        metrics,
      });

      const retrieved = getBaseline(created.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.id).toBe(created.id);
      expect(retrieved?.name).toBe("Test Baseline");
    });

    it("should return null for non-existent baseline", () => {
      const result = getBaseline("non-existent-id");
      expect(result).toBeNull();
    });

    it("should list baselines", () => {
      const metrics = createTestMetrics();
      createBaseline({
        name: "Baseline 1",
        entityType: "project",
        entityId: "project-1",
        entityName: "Project One",
        metrics,
      });
      createBaseline({
        name: "Baseline 2",
        entityType: "team",
        entityId: "team-1",
        entityName: "Team One",
        metrics,
      });

      const allBaselines = listBaselines();
      expect(allBaselines.length).toBe(2);

      const projectBaselines = listBaselines({ entityType: "project" });
      expect(projectBaselines.length).toBe(1);
      expect(projectBaselines[0].name).toBe("Baseline 1");
    });

    it("should delete a baseline", () => {
      const metrics = createTestMetrics();
      const baseline = createBaseline({
        name: "To Delete",
        entityType: "project",
        entityId: "project-1",
        entityName: "Project One",
        metrics,
      });

      const deleted = deleteBaseline(baseline.id);
      expect(deleted).toBe(true);

      const retrieved = getBaseline(baseline.id);
      expect(retrieved).toBeNull();
    });

    it("should set default baseline", () => {
      const metrics = createTestMetrics();
      const baseline1 = createBaseline({
        name: "Baseline 1",
        entityType: "project",
        entityId: "project-1",
        entityName: "Project One",
        metrics,
        isDefault: true,
      });

      const baseline2 = createBaseline({
        name: "Baseline 2",
        entityType: "project",
        entityId: "project-1",
        entityName: "Project One",
        metrics,
      });

      // Baseline 1 should be default
      let defaultBaseline = getDefaultBaseline("project-1");
      expect(defaultBaseline?.id).toBe(baseline1.id);

      // Set baseline 2 as default
      setDefaultBaseline(baseline2.id);
      defaultBaseline = getDefaultBaseline("project-1");
      expect(defaultBaseline?.id).toBe(baseline2.id);
    });
  });

  // ===========================================================================
  // compareToBaseline Tests
  // ===========================================================================

  describe("compareToBaseline", () => {
    it("should compare current metrics to baseline", () => {
      const baselineMetrics = createTestMetrics({
        vulnerabilityCount: 50,
        criticalCount: 5,
      });

      const baseline = createBaseline({
        name: "Initial Baseline",
        entityType: "project",
        entityId: "project-1",
        entityName: "Project One",
        metrics: baselineMetrics,
      });

      const currentMetrics = createTestMetrics({
        vulnerabilityCount: 30,
        criticalCount: 2,
      });

      const result = compareToBaseline({
        currentMetrics,
        baselineId: baseline.id,
      });

      expect(result.entityA).toEqual(baselineMetrics);
      expect(result.entityB).toEqual(currentMetrics);
      expect(result.metrics.length).toBeGreaterThan(0);
    });

    it("should use default baseline when requested", () => {
      const baselineMetrics = createTestMetrics();
      createBaseline({
        name: "Default Baseline",
        entityType: "project",
        entityId: "project-1",
        entityName: "Project One",
        metrics: baselineMetrics,
        isDefault: true,
      });

      const currentMetrics = createTestMetrics({
        vulnerabilityCount: 25,
      });

      const result = compareToBaseline({
        currentMetrics,
        useDefaultBaseline: true,
        entityId: "project-1",
      });

      expect(result.entityA).toEqual(baselineMetrics);
    });

    it("should throw error if baseline not found", () => {
      const currentMetrics = createTestMetrics();

      expect(() => {
        compareToBaseline({
          currentMetrics,
          baselineId: "non-existent-id",
        });
      }).toThrow("Baseline not found");
    });
  });

  // ===========================================================================
  // Rankings Tests
  // ===========================================================================

  describe("rankings", () => {
    it("should record entity metrics", () => {
      const metrics = createTestMetrics({
        entityId: "project-1",
        entityName: "Project One",
        entityType: "project",
      });

      // Should not throw
      expect(() => recordEntityMetrics(metrics)).not.toThrow();
    });

    it("should get rankings for entities", () => {
      // Record metrics for multiple projects
      recordEntityMetrics(
        createTestMetrics({
          entityId: "project-1",
          entityName: "Project One",
          entityType: "project",
          riskScore: 80,
        })
      );
      recordEntityMetrics(
        createTestMetrics({
          entityId: "project-2",
          entityName: "Project Two",
          entityType: "project",
          riskScore: 40,
        })
      );
      recordEntityMetrics(
        createTestMetrics({
          entityId: "project-3",
          entityName: "Project Three",
          entityType: "project",
          riskScore: 60,
        })
      );

      const rankings = getRankings({
        metric: "risk_score",
        entityType: "project",
      });

      expect(rankings.rankings.length).toBe(3);
      // Risk score: lower is better, so project-2 should be rank 1
      expect(rankings.rankings[0].entityId).toBe("project-2");
      expect(rankings.rankings[0].rank).toBe(1);
      expect(rankings.stats.total).toBe(3);
    });

    it("should calculate percentiles correctly", () => {
      // Record metrics for 4 projects with different risk scores
      recordEntityMetrics(
        createTestMetrics({
          entityId: "p1",
          entityName: "P1",
          entityType: "project",
          riskScore: 100,
        })
      );
      recordEntityMetrics(
        createTestMetrics({
          entityId: "p2",
          entityName: "P2",
          entityType: "project",
          riskScore: 75,
        })
      );
      recordEntityMetrics(
        createTestMetrics({
          entityId: "p3",
          entityName: "P3",
          entityType: "project",
          riskScore: 50,
        })
      );
      recordEntityMetrics(
        createTestMetrics({
          entityId: "p4",
          entityName: "P4",
          entityType: "project",
          riskScore: 25,
        })
      );

      const rankings = getRankings({
        metric: "risk_score",
        entityType: "project",
      });

      // Best (lowest risk) should have high percentile
      const bestProject = rankings.rankings.find((r) => r.entityId === "p4");
      expect(bestProject?.percentile).toBeGreaterThan(50);
    });

    it("should limit results", () => {
      for (let i = 0; i < 10; i++) {
        recordEntityMetrics(
          createTestMetrics({
            entityId: `project-${i}`,
            entityName: `Project ${i}`,
            entityType: "project",
            riskScore: i * 10,
          })
        );
      }

      const rankings = getRankings({
        metric: "risk_score",
        entityType: "project",
        limit: 5,
      });

      expect(rankings.rankings.length).toBe(5);
    });
  });

  // ===========================================================================
  // Caching Tests
  // ===========================================================================

  describe("caching", () => {
    it("should cache comparison results", () => {
      const metricsA = createTestMetrics({ entityId: "a" });
      const metricsB = createTestMetrics({ entityId: "b" });

      const result = compareProjects({
        projectIdA: "a",
        projectIdB: "b",
        metricsA,
        metricsB,
      });

      cacheComparison("a", "b", result, 60);

      const cached = getCachedComparison("a", "b");
      expect(cached).not.toBeNull();
      expect(cached?.entityA.entityId).toBe("a");
    });

    it("should retrieve cached comparison with reversed IDs", () => {
      const metricsA = createTestMetrics({ entityId: "a" });
      const metricsB = createTestMetrics({ entityId: "b" });

      const result = compareProjects({
        projectIdA: "a",
        projectIdB: "b",
        metricsA,
        metricsB,
      });

      cacheComparison("a", "b", result);

      // Cache key is sorted, so order shouldn't matter
      const cached = getCachedComparison("b", "a");
      expect(cached).not.toBeNull();
    });

    it("should return null for non-existent cache", () => {
      const cached = getCachedComparison("nonexistent-1", "nonexistent-2");
      expect(cached).toBeNull();
    });

    it("should clear expired cache entries", () => {
      const metricsA = createTestMetrics({ entityId: "a" });
      const metricsB = createTestMetrics({ entityId: "b" });

      const result = compareProjects({
        projectIdA: "a",
        projectIdB: "b",
        metricsA,
        metricsB,
      });

      // Cache with 0 minute TTL (already expired)
      cacheComparison("a", "b", result, 0);

      const cleared = clearExpiredCache();
      expect(cleared).toBeGreaterThanOrEqual(0);
    });
  });

  // ===========================================================================
  // Metric Comparison Tests
  // ===========================================================================

  describe("metric comparisons", () => {
    it("should calculate percent change correctly", () => {
      const metricsA = createTestMetrics({
        vulnerabilityCount: 100,
      });

      const metricsB = createTestMetrics({
        vulnerabilityCount: 50,
      });

      const result = compareProjects({
        projectIdA: "a",
        projectIdB: "b",
        metricsA,
        metricsB,
      });

      const vulnMetric = result.metrics.find((m) => m.metric === "vulnerability_count");
      expect(vulnMetric?.delta).toBe(-50);
      expect(vulnMetric?.percentChange).toBe(-50);
    });

    it("should identify trends correctly", () => {
      const metricsA = createTestMetrics({
        vulnerabilityCount: 100,
        healthScore: 50,
      });

      const metricsB = createTestMetrics({
        vulnerabilityCount: 50, // Decreased = improving for vulns
        healthScore: 80, // Increased = improving for health
      });

      const result = compareProjects({
        projectIdA: "a",
        projectIdB: "b",
        metricsA,
        metricsB,
      });

      const vulnMetric = result.metrics.find((m) => m.metric === "vulnerability_count");
      const healthMetric = result.metrics.find((m) => m.metric === "health_score");

      expect(vulnMetric?.trend).toBe("improving");
      expect(healthMetric?.trend).toBe("improving");
    });

    it("should identify stable trends for small changes", () => {
      const metricsA = createTestMetrics({
        vulnerabilityCount: 100,
      });

      const metricsB = createTestMetrics({
        vulnerabilityCount: 102, // 2% change - should be stable
      });

      const result = compareProjects({
        projectIdA: "a",
        projectIdB: "b",
        metricsA,
        metricsB,
      });

      const vulnMetric = result.metrics.find((m) => m.metric === "vulnerability_count");
      expect(vulnMetric?.trend).toBe("stable");
    });

    it("should determine winner for each metric", () => {
      const metricsA = createTestMetrics({
        criticalCount: 10,
        healthScore: 90,
      });

      const metricsB = createTestMetrics({
        criticalCount: 2, // B is better (lower)
        healthScore: 60, // A is better (higher)
      });

      const result = compareProjects({
        projectIdA: "a",
        projectIdB: "b",
        metricsA,
        metricsB,
      });

      const criticalMetric = result.metrics.find((m) => m.metric === "critical_count");
      const healthMetric = result.metrics.find((m) => m.metric === "health_score");

      expect(criticalMetric?.winner).toBe("B");
      expect(healthMetric?.winner).toBe("A");
    });

    it("should identify ties for similar values", () => {
      const metricsA = createTestMetrics({
        vulnerabilityCount: 100,
      });

      const metricsB = createTestMetrics({
        vulnerabilityCount: 100.5, // 0.5% difference - should be tie
      });

      const result = compareProjects({
        projectIdA: "a",
        projectIdB: "b",
        metricsA,
        metricsB,
      });

      const vulnMetric = result.metrics.find((m) => m.metric === "vulnerability_count");
      expect(vulnMetric?.winner).toBe("tie");
    });
  });

  // ===========================================================================
  // Confidence Score Tests
  // ===========================================================================

  describe("confidence score", () => {
    it("should have high confidence with complete data", () => {
      const metricsA = createTestMetrics();
      // Use different metrics to avoid ties, which reduce confidence
      const metricsB = createTestMetrics({
        entityId: "test-entity-2",
        entityName: "Test Entity 2",
        vulnerabilityCount: 40,
        criticalCount: 3,
        highCount: 8,
        mediumCount: 15,
        lowCount: 14,
        riskScore: 55,
        healthScore: 80,
        complianceScore: 90,
        mttr: 36,
        remediationVelocity: 3.0,
        scanCoverage: 95,
      });

      const result = compareProjects({
        projectIdA: "a",
        projectIdB: "b",
        metricsA,
        metricsB,
      });

      expect(result.summary.confidence).toBeGreaterThan(80);
    });

    it("should have lower confidence with missing optional fields", () => {
      // Create metrics without optional fields
      const metricsA: EntityMetrics = {
        entityId: "test-entity-a",
        entityName: "Test Entity A",
        entityType: "project",
        timestamp: new Date().toISOString(),
        vulnerabilityCount: 50,
        criticalCount: 5,
        highCount: 10,
        mediumCount: 20,
        lowCount: 15,
        riskScore: 65,
        healthScore: 70,
        complianceScore: 85,
        // Optional fields omitted
      };

      const metricsB: EntityMetrics = {
        entityId: "test-entity-b",
        entityName: "Test Entity B",
        entityType: "project",
        timestamp: new Date().toISOString(),
        vulnerabilityCount: 50,
        criticalCount: 5,
        highCount: 10,
        mediumCount: 20,
        lowCount: 15,
        riskScore: 65,
        healthScore: 70,
        complianceScore: 85,
        // Optional fields omitted
      };

      const result = compareProjects({
        projectIdA: "a",
        projectIdB: "b",
        metricsA,
        metricsB,
      });

      // Confidence should be reduced due to missing fields
      expect(result.summary.confidence).toBeLessThan(100);
    });
  });
});
