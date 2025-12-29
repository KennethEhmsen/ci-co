import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  initRiskDatabase,
  closeRiskDatabase,
  isRiskDbInitialized,
  getRiskConfig,
  updateRiskConfig,
  setAssetCriticality,
  getAssetConfig,
  listAssetConfigs,
  deleteAssetConfig,
  calculateRiskScore,
  storeRiskScore,
  getStoredRiskScore,
  getPrioritizedList,
  clearRiskScores,
  getRiskStats,
} from "./risk-scoring.js";

describe("Risk Scoring", () => {
  beforeEach(() => {
    // Initialize with in-memory database for each test
    const result = initRiskDatabase(":memory:");
    expect(result.success).toBe(true);
  });

  afterEach(() => {
    closeRiskDatabase();
  });

  describe("Database Lifecycle", () => {
    it("should initialize and check database state", () => {
      // Already initialized in beforeEach
      expect(isRiskDbInitialized()).toBe(true);
    });

    it("should close database", () => {
      closeRiskDatabase();
      expect(isRiskDbInitialized()).toBe(false);
    });
  });

  describe("Configuration", () => {
    it("should get default risk configuration", () => {
      const config = getRiskConfig();
      expect(config.defaultCriticality).toBe("medium");
      expect(config.defaultExposure).toBe("internal-only");
      expect(config.tierThresholds.critical).toBe(80);
      expect(config.tierThresholds.high).toBe(60);
      expect(config.tierThresholds.medium).toBe(40);
      expect(config.tierThresholds.low).toBe(20);
    });

    it("should update risk configuration", () => {
      const updated = updateRiskConfig({
        defaultCriticality: "high",
        tierThresholds: {
          critical: 90,
          high: 70,
          medium: 50,
          low: 30,
        },
      });

      expect(updated.defaultCriticality).toBe("high");
      expect(updated.tierThresholds.critical).toBe(90);

      // Verify persistence
      const fetched = getRiskConfig();
      expect(fetched.defaultCriticality).toBe("high");
    });
  });

  describe("Asset Criticality", () => {
    it("should set asset criticality", () => {
      const config = setAssetCriticality({
        asset: "myapp:latest",
        assetType: "image",
        criticality: "critical",
        exposure: "internet-facing",
        businessContext: "Production API server",
        owner: "platform-team",
      });

      expect(config.asset).toBe("myapp:latest");
      expect(config.criticality).toBe("critical");
      expect(config.exposure).toBe("internet-facing");
      expect(config.businessContext).toBe("Production API server");
    });

    it("should get asset configuration", () => {
      setAssetCriticality({
        asset: "myapp:latest",
        assetType: "image",
        criticality: "high",
        exposure: "internal-only",
      });

      const config = getAssetConfig("myapp:latest");
      expect(config).not.toBeNull();
      expect(config?.criticality).toBe("high");
    });

    it("should return null for unknown asset", () => {
      const config = getAssetConfig("unknown:asset");
      expect(config).toBeNull();
    });

    it("should list all asset configurations", () => {
      setAssetCriticality({
        asset: "app1:latest",
        assetType: "image",
        criticality: "critical",
        exposure: "internet-facing",
      });
      setAssetCriticality({
        asset: "app2:latest",
        assetType: "image",
        criticality: "low",
        exposure: "development",
      });

      const configs = listAssetConfigs();
      expect(configs.length).toBe(2);
    });

    it("should update existing asset configuration", () => {
      setAssetCriticality({
        asset: "myapp:latest",
        assetType: "image",
        criticality: "medium",
        exposure: "internal-only",
      });

      setAssetCriticality({
        asset: "myapp:latest",
        assetType: "image",
        criticality: "critical",
        exposure: "internet-facing",
      });

      const config = getAssetConfig("myapp:latest");
      expect(config?.criticality).toBe("critical");
      expect(config?.exposure).toBe("internet-facing");
    });

    it("should delete asset configuration", () => {
      setAssetCriticality({
        asset: "myapp:latest",
        assetType: "image",
        criticality: "high",
        exposure: "internal-only",
      });

      const deleted = deleteAssetConfig("myapp:latest");
      expect(deleted).toBe(true);

      const config = getAssetConfig("myapp:latest");
      expect(config).toBeNull();
    });

    it("should return false when deleting non-existent asset", () => {
      const deleted = deleteAssetConfig("nonexistent");
      expect(deleted).toBe(false);
    });
  });

  describe("Risk Calculation", () => {
    it("should calculate basic risk score", () => {
      const score = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 7.5 },
        asset: "myapp:latest",
      });

      expect(score.vulnId).toBe("CVE-2024-1234");
      expect(score.baseCvss).toBe(7.5);
      expect(score.riskScore).toBeGreaterThan(0);
      expect(score.riskScore).toBeLessThanOrEqual(100);
      expect(score.riskTier).toBeDefined();
      expect(score.recommendation).toBeDefined();
    });

    it("should increase risk for critical assets", () => {
      // Set up critical asset
      setAssetCriticality({
        asset: "critical-app",
        assetType: "image",
        criticality: "critical",
        exposure: "internet-facing",
      });

      const criticalScore = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 7.5 },
        asset: "critical-app",
      });

      const defaultScore = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 7.5 },
        asset: "default-app",
      });

      expect(criticalScore.riskScore).toBeGreaterThan(defaultScore.riskScore);
      expect(criticalScore.assetCriticalityMultiplier).toBeGreaterThan(
        defaultScore.assetCriticalityMultiplier
      );
    });

    it("should decrease risk for development environments", () => {
      setAssetCriticality({
        asset: "dev-app",
        assetType: "image",
        criticality: "low",
        exposure: "development",
      });

      const devScore = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 7.5 },
        asset: "dev-app",
      });

      const defaultScore = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 7.5 },
        asset: "default-app",
      });

      expect(devScore.riskScore).toBeLessThan(defaultScore.riskScore);
    });

    it("should increase risk for active exploitation", () => {
      const exploitedScore = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 7.5 },
        asset: "myapp:latest",
        exploitability: {
          exploitInWild: true,
          pocAvailable: true,
          weaponized: true,
          activelyExploited: true,
          cisaKev: true,
        },
      });

      const normalScore = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 7.5 },
        asset: "myapp:latest",
      });

      expect(exploitedScore.riskScore).toBeGreaterThan(normalScore.riskScore);
      expect(exploitedScore.exploitabilityMultiplier).toBeGreaterThan(1.0);
    });

    it("should increase risk for older vulnerabilities", () => {
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 60); // 60 days ago

      const oldScore = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 7.5 },
        asset: "myapp:latest",
        firstDetected: oldDate.toISOString(),
      });

      const newScore = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 7.5 },
        asset: "myapp:latest",
        firstDetected: new Date().toISOString(),
      });

      expect(oldScore.ageFactor).toBeGreaterThan(newScore.ageFactor);
      expect(oldScore.ageInDays).toBeGreaterThan(newScore.ageInDays || 0);
    });

    it("should use inline asset config when provided", () => {
      const score = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 7.5 },
        asset: {
          asset: "inline-app",
          assetType: "service",
          criticality: "critical",
          exposure: "internet-facing",
          customMultiplier: 1.5,
        },
      });

      expect(score.assetCriticalityMultiplier).toBe(2.0 * 1.5); // critical (2.0) * custom (1.5)
      expect(score.exposureMultiplier).toBe(2.0); // internet-facing
    });

    it("should assign correct risk tiers", () => {
      // Critical (>=80)
      const criticalScore = calculateRiskScore({
        vulnId: "CVE-2024-CRIT",
        cvss: { baseScore: 10.0 },
        asset: {
          asset: "test",
          assetType: "image",
          criticality: "critical",
          exposure: "internet-facing",
        },
      });
      expect(criticalScore.riskTier).toBe("critical");

      // Minimal (<20)
      const minimalScore = calculateRiskScore({
        vulnId: "CVE-2024-LOW",
        cvss: { baseScore: 1.0 },
        asset: {
          asset: "test",
          assetType: "image",
          criticality: "minimal",
          exposure: "air-gapped",
        },
      });
      expect(minimalScore.riskTier).toBe("minimal");
    });

    it("should apply custom weights", () => {
      // Use lower base score to avoid both hitting the 100 cap
      const weightedScore = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 5.0 },
        asset: {
          asset: "test",
          assetType: "image",
          criticality: "high",
          exposure: "internal-only",
        },
        weights: {
          exploitability: 0.0, // Ignore exploitability
          assetCriticality: 0.5, // Half weight on criticality
          exposure: 0.5, // Half weight on exposure
          age: 0.0, // Ignore age
        },
      });

      const normalScore = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 5.0 },
        asset: {
          asset: "test",
          assetType: "image",
          criticality: "high",
          exposure: "internal-only",
        },
      });

      // Weighted score should be lower due to reduced weights
      expect(weightedScore.riskScore).toBeLessThan(normalScore.riskScore);
    });
  });

  describe("Score Storage", () => {
    it("should store and retrieve risk score", () => {
      const score = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 7.5 },
        asset: "myapp:latest",
      });

      storeRiskScore(score, "myapp:latest", "2024-01-01T00:00:00Z");

      const retrieved = getStoredRiskScore("CVE-2024-1234", "myapp:latest");
      expect(retrieved).not.toBeNull();
      expect(retrieved?.vulnId).toBe("CVE-2024-1234");
      expect(retrieved?.riskScore).toBe(score.riskScore);
    });

    it("should return null for unknown score", () => {
      const retrieved = getStoredRiskScore("CVE-UNKNOWN", "unknown:asset");
      expect(retrieved).toBeNull();
    });

    it("should update existing score on re-store", () => {
      const score1 = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 5.0 },
        asset: "myapp:latest",
      });
      storeRiskScore(score1, "myapp:latest");

      const score2 = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 9.0 },
        asset: "myapp:latest",
      });
      storeRiskScore(score2, "myapp:latest");

      const retrieved = getStoredRiskScore("CVE-2024-1234", "myapp:latest");
      expect(retrieved?.baseCvss).toBe(9.0);
    });
  });

  describe("Prioritized List", () => {
    beforeEach(() => {
      // Store some test scores
      const vulns = [
        { id: "CVE-2024-001", cvss: 9.5, asset: "app1" },
        { id: "CVE-2024-002", cvss: 7.0, asset: "app1" },
        { id: "CVE-2024-003", cvss: 4.0, asset: "app2" },
        { id: "CVE-2024-004", cvss: 2.0, asset: "app2" },
      ];

      for (const v of vulns) {
        const score = calculateRiskScore({
          vulnId: v.id,
          cvss: { baseScore: v.cvss },
          asset: v.asset,
        });
        storeRiskScore(score, v.asset);
      }
    });

    it("should get prioritized list sorted by risk score", () => {
      const result = getPrioritizedList();

      expect(result.vulnerabilities.length).toBe(4);
      expect(result.vulnerabilities[0].vulnId).toBe("CVE-2024-001"); // Highest CVSS
      expect(result.vulnerabilities[0].riskScore.priorityRank).toBe(1);

      // Verify sorted order
      for (let i = 1; i < result.vulnerabilities.length; i++) {
        expect(result.vulnerabilities[i - 1].riskScore.riskScore).toBeGreaterThanOrEqual(
          result.vulnerabilities[i].riskScore.riskScore
        );
      }
    });

    it("should filter by minimum risk score", () => {
      const result = getPrioritizedList({ minRiskScore: 50 });
      expect(result.vulnerabilities.length).toBeLessThan(4);
      for (const v of result.vulnerabilities) {
        expect(v.riskScore.riskScore).toBeGreaterThanOrEqual(50);
      }
    });

    it("should filter by assets", () => {
      const result = getPrioritizedList({ assets: ["app1"] });
      expect(result.vulnerabilities.length).toBe(2);
      for (const v of result.vulnerabilities) {
        expect(v.asset).toBe("app1");
      }
    });

    it("should limit results", () => {
      const result = getPrioritizedList({ limit: 2 });
      expect(result.vulnerabilities.length).toBe(2);
    });

    it("should filter by risk tiers", () => {
      const result = getPrioritizedList({
        includeTiers: ["critical", "high"],
      });

      for (const v of result.vulnerabilities) {
        expect(["critical", "high"]).toContain(v.riskScore.riskTier);
      }
    });

    it("should include tier summary", () => {
      const result = getPrioritizedList();

      expect(result.tierSummary).toBeDefined();
      expect(result.tierSummary.critical).toBeDefined();
      expect(result.tierSummary.high).toBeDefined();
      expect(result.tierSummary.medium).toBeDefined();
      expect(result.tierSummary.low).toBeDefined();
      expect(result.tierSummary.minimal).toBeDefined();
    });

    it("should include asset summary when grouped", () => {
      const result = getPrioritizedList({ groupByAsset: true });

      expect(result.assetSummary).toBeDefined();
      expect(result.assetSummary?.app1).toBeDefined();
      expect(result.assetSummary?.app2).toBeDefined();
      expect(result.assetSummary?.app1.count).toBe(2);
      expect(result.assetSummary?.app2.count).toBe(2);
    });
  });

  describe("Utilities", () => {
    it("should clear all risk scores", () => {
      const score = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 7.5 },
        asset: "myapp:latest",
      });
      storeRiskScore(score, "myapp:latest");

      const cleared = clearRiskScores();
      expect(cleared).toBeGreaterThan(0);

      const retrieved = getStoredRiskScore("CVE-2024-1234", "myapp:latest");
      expect(retrieved).toBeNull();
    });

    it("should get risk statistics", () => {
      // Add some test data
      setAssetCriticality({
        asset: "app1",
        assetType: "image",
        criticality: "high",
        exposure: "internet-facing",
      });

      const score = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 9.0 },
        asset: "app1",
      });
      storeRiskScore(score, "app1");

      const stats = getRiskStats();

      expect(stats.totalAssets).toBe(1);
      expect(stats.totalScores).toBe(1);
      expect(stats.tierDistribution).toBeDefined();
      expect(stats.avgRiskScore).toBeGreaterThan(0);
    });
  });

  describe("Recommendation Generation", () => {
    it("should generate IMMEDIATE ACTION for critical scores", () => {
      const score = calculateRiskScore({
        vulnId: "CVE-2024-CRIT",
        cvss: { baseScore: 10.0 },
        asset: {
          asset: "prod-api",
          assetType: "service",
          criticality: "critical",
          exposure: "internet-facing",
        },
        exploitability: {
          exploitInWild: true,
          pocAvailable: true,
          weaponized: true,
          activelyExploited: true,
          cisaKev: true,
        },
      });

      expect(score.recommendation).toContain("IMMEDIATE ACTION");
    });

    it("should mention active exploitation in recommendation", () => {
      const score = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 7.5 },
        asset: "myapp:latest",
        exploitability: {
          exploitInWild: true,
          pocAvailable: true,
          weaponized: true,
          activelyExploited: true,
          cisaKev: true,
        },
      });

      expect(score.recommendation).toContain("exploitation");
    });

    it("should mention extended time for old vulnerabilities", () => {
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 90);

      const score = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 7.5 },
        asset: "myapp:latest",
        firstDetected: oldDate.toISOString(),
      });

      expect(score.recommendation).toContain("extended period");
    });
  });

  describe("EPSS Score Integration", () => {
    it("should increase risk with high EPSS score", () => {
      const highEpss = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 7.5 },
        asset: "myapp:latest",
        exploitability: {
          exploitInWild: false,
          pocAvailable: false,
          weaponized: false,
          activelyExploited: false,
          cisaKev: false,
          epssScore: 0.95, // Very high probability
        },
      });

      const lowEpss = calculateRiskScore({
        vulnId: "CVE-2024-1234",
        cvss: { baseScore: 7.5 },
        asset: "myapp:latest",
        exploitability: {
          exploitInWild: false,
          pocAvailable: false,
          weaponized: false,
          activelyExploited: false,
          cisaKev: false,
          epssScore: 0.05, // Very low probability
        },
      });

      expect(highEpss.exploitabilityMultiplier).toBeGreaterThan(lowEpss.exploitabilityMultiplier);
    });
  });
});
