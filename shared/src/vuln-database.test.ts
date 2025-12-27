/**
 * Vulnerability Database Tests
 *
 * Comprehensive tests for the SQLite-based vulnerability database module.
 */

import { describe, it, expect, beforeEach, afterEach, afterAll } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import {
  initVulnDatabase,
  closeVulnDatabase,
  isVulnDbInitialized,
  getVulnDbPath,
  insertVulnerability,
  bulkInsertVulnerabilities,
  lookupVulnerability,
  deleteVulnerability,
  addAffectedPackages,
  getAffectedPackages,
  clearAffectedPackages,
  searchVulnerabilities,
  findVulnerabilitiesByPackage,
  updateSyncStatus,
  getSyncStatus,
  getAllSyncStatuses,
  annotateVulnerability,
  getVulnAnnotation,
  getAnnotationsByStatus,
  removeAnnotation,
  getVulnDbStats,
  vacuumDatabase,
  clearAllVulnerabilities,
  clearVulnerabilitiesBySource,
} from "./vuln-database.js";
import type { VulnDbRecord, VulnDbAffectedPackage } from "./types.js";

// =============================================================================
// TEST FIXTURES
// =============================================================================

const createTestVuln = (id: string, overrides: Partial<VulnDbRecord> = {}): VulnDbRecord => ({
  id,
  source: "nvd",
  severity: "HIGH",
  cvssScore: 7.5,
  title: `Test vulnerability ${id}`,
  description: `Description for ${id}`,
  references: ["https://example.com/vuln/" + id],
  publishedAt: "2024-01-15T00:00:00Z",
  modifiedAt: "2024-01-16T00:00:00Z",
  ...overrides,
});

// =============================================================================
// TEST SETUP
// =============================================================================

let testDbPath: string;

beforeEach(() => {
  // Create a unique test database path
  testDbPath = path.join(
    os.tmpdir(),
    `vuln-db-test-${Date.now()}-${Math.random().toString(36).slice(2)}.sqlite`
  );
});

afterEach(() => {
  // Close the database after each test
  closeVulnDatabase();

  // Clean up test database file
  if (testDbPath && fs.existsSync(testDbPath)) {
    try {
      fs.unlinkSync(testDbPath);
      // Also clean up WAL files if they exist
      if (fs.existsSync(testDbPath + "-wal")) fs.unlinkSync(testDbPath + "-wal");
      if (fs.existsSync(testDbPath + "-shm")) fs.unlinkSync(testDbPath + "-shm");
    } catch {
      // Ignore cleanup errors
    }
  }
});

afterAll(() => {
  closeVulnDatabase();
});

// =============================================================================
// DATABASE INITIALIZATION TESTS
// =============================================================================

describe("Database Initialization", () => {
  it("should initialize database with custom path", () => {
    const result = initVulnDatabase(testDbPath);

    expect(result.success).toBe(true);
    expect(result.path).toBe(testDbPath);
    expect(result.created).toBe(true);
    expect(fs.existsSync(testDbPath)).toBe(true);
  });

  it("should report database as initialized", () => {
    initVulnDatabase(testDbPath);

    expect(isVulnDbInitialized()).toBe(true);
    expect(getVulnDbPath()).toBe(testDbPath);
  });

  it("should close database properly", () => {
    initVulnDatabase(testDbPath);
    closeVulnDatabase();

    expect(isVulnDbInitialized()).toBe(false);
    expect(getVulnDbPath()).toBeNull();
  });

  it("should handle re-initialization of existing database", () => {
    // First init
    initVulnDatabase(testDbPath);
    closeVulnDatabase();

    // Second init
    const result = initVulnDatabase(testDbPath);

    expect(result.success).toBe(true);
    expect(result.created).toBe(false); // Already exists
  });
});

// =============================================================================
// VULNERABILITY CRUD TESTS
// =============================================================================

describe("Vulnerability CRUD Operations", () => {
  beforeEach(() => {
    initVulnDatabase(testDbPath);
  });

  describe("insertVulnerability", () => {
    it("should insert a new vulnerability", () => {
      const vuln = createTestVuln("CVE-2024-1234");
      const result = insertVulnerability(vuln);

      expect(result.success).toBe(true);
      expect(result.action).toBe("inserted");
    });

    it("should update an existing vulnerability", () => {
      const vuln = createTestVuln("CVE-2024-1234");
      insertVulnerability(vuln);

      const updated = createTestVuln("CVE-2024-1234", { title: "Updated title" });
      const result = insertVulnerability(updated);

      expect(result.success).toBe(true);
      expect(result.action).toBe("updated");

      const retrieved = lookupVulnerability("CVE-2024-1234");
      expect(retrieved?.title).toBe("Updated title");
    });
  });

  describe("bulkInsertVulnerabilities", () => {
    it("should bulk insert multiple vulnerabilities", () => {
      const vulns = [
        createTestVuln("CVE-2024-0001"),
        createTestVuln("CVE-2024-0002"),
        createTestVuln("CVE-2024-0003"),
      ];

      const result = bulkInsertVulnerabilities(vulns);

      expect(result.success).toBe(true);
      expect(result.inserted).toBe(3);
      expect(result.updated).toBe(0);
      expect(result.errors).toBe(0);
    });

    it("should count updates in bulk insert", () => {
      // Insert first
      insertVulnerability(createTestVuln("CVE-2024-0001"));

      // Bulk insert with one existing
      const vulns = [
        createTestVuln("CVE-2024-0001", { title: "Updated" }),
        createTestVuln("CVE-2024-0002"),
      ];

      const result = bulkInsertVulnerabilities(vulns);

      expect(result.inserted).toBe(1);
      expect(result.updated).toBe(1);
    });
  });

  describe("lookupVulnerability", () => {
    it("should find an existing vulnerability", () => {
      const vuln = createTestVuln("CVE-2024-1234", {
        cvssScore: 9.8,
        severity: "CRITICAL",
      });
      insertVulnerability(vuln);

      const result = lookupVulnerability("CVE-2024-1234");

      expect(result).not.toBeNull();
      expect(result?.id).toBe("CVE-2024-1234");
      expect(result?.cvssScore).toBe(9.8);
      expect(result?.severity).toBe("CRITICAL");
    });

    it("should return null for non-existent vulnerability", () => {
      const result = lookupVulnerability("CVE-9999-9999");

      expect(result).toBeNull();
    });

    it("should parse references correctly", () => {
      const vuln = createTestVuln("CVE-2024-1234", {
        references: ["https://ref1.com", "https://ref2.com"],
      });
      insertVulnerability(vuln);

      const result = lookupVulnerability("CVE-2024-1234");

      expect(result?.references).toEqual(["https://ref1.com", "https://ref2.com"]);
    });
  });

  describe("deleteVulnerability", () => {
    it("should delete an existing vulnerability", () => {
      insertVulnerability(createTestVuln("CVE-2024-1234"));

      const deleted = deleteVulnerability("CVE-2024-1234");

      expect(deleted).toBe(true);
      expect(lookupVulnerability("CVE-2024-1234")).toBeNull();
    });

    it("should return false for non-existent vulnerability", () => {
      const deleted = deleteVulnerability("CVE-9999-9999");

      expect(deleted).toBe(false);
    });
  });
});

// =============================================================================
// AFFECTED PACKAGES TESTS
// =============================================================================

describe("Affected Packages", () => {
  beforeEach(() => {
    initVulnDatabase(testDbPath);
    insertVulnerability(createTestVuln("CVE-2024-1234"));
  });

  it("should add affected packages", () => {
    const packages: VulnDbAffectedPackage[] = [
      {
        vulnId: "CVE-2024-1234",
        ecosystem: "npm",
        packageName: "lodash",
        versionStart: "4.0.0",
        versionEnd: "4.17.20",
        fixedVersion: "4.17.21",
      },
    ];

    const result = addAffectedPackages(packages);

    expect(result.success).toBe(true);
    expect(result.added).toBe(1);
  });

  it("should retrieve affected packages", () => {
    addAffectedPackages([
      {
        vulnId: "CVE-2024-1234",
        ecosystem: "npm",
        packageName: "express",
      },
      {
        vulnId: "CVE-2024-1234",
        ecosystem: "npm",
        packageName: "lodash",
      },
    ]);

    const packages = getAffectedPackages("CVE-2024-1234");

    expect(packages).toHaveLength(2);
    expect(packages.map((p) => p.packageName)).toContain("express");
    expect(packages.map((p) => p.packageName)).toContain("lodash");
  });

  it("should clear affected packages", () => {
    addAffectedPackages([{ vulnId: "CVE-2024-1234", ecosystem: "npm", packageName: "test" }]);

    const cleared = clearAffectedPackages("CVE-2024-1234");

    expect(cleared).toBe(1);
    expect(getAffectedPackages("CVE-2024-1234")).toHaveLength(0);
  });
});

// =============================================================================
// SEARCH TESTS
// =============================================================================

describe("Vulnerability Search", () => {
  beforeEach(() => {
    initVulnDatabase(testDbPath);

    // Insert test data
    bulkInsertVulnerabilities([
      createTestVuln("CVE-2024-0001", { severity: "CRITICAL", source: "nvd" }),
      createTestVuln("CVE-2024-0002", { severity: "HIGH", source: "ghsa" }),
      createTestVuln("CVE-2024-0003", { severity: "MEDIUM", source: "nvd" }),
      createTestVuln("CVE-2024-0004", { severity: "LOW", source: "osv" }),
      createTestVuln("CVE-2023-9999", { severity: "HIGH", source: "nvd" }),
    ]);

    // Add affected packages for some
    addAffectedPackages([
      { vulnId: "CVE-2024-0001", ecosystem: "npm", packageName: "lodash" },
      { vulnId: "CVE-2024-0002", ecosystem: "npm", packageName: "express" },
      { vulnId: "CVE-2024-0003", ecosystem: "pypi", packageName: "requests" },
    ]);
  });

  it("should search by severity", () => {
    const result = searchVulnerabilities({ severity: ["CRITICAL", "HIGH"] });

    expect(result.total).toBe(3);
    expect(result.results.every((v) => ["CRITICAL", "HIGH"].includes(v.severity))).toBe(true);
  });

  it("should search by CVE pattern", () => {
    const result = searchVulnerabilities({ cvePattern: "2024-000" });

    expect(result.total).toBe(4); // CVE-2024-0001 through 0004
  });

  it("should search by package name", () => {
    const result = searchVulnerabilities({ packageName: "lodash" });

    expect(result.total).toBe(1);
    expect(result.results[0].id).toBe("CVE-2024-0001");
  });

  it("should search by ecosystem", () => {
    const result = searchVulnerabilities({ ecosystem: "npm" });

    expect(result.total).toBe(2);
  });

  it("should paginate results", () => {
    const page1 = searchVulnerabilities({ limit: 2, offset: 0 });
    const page2 = searchVulnerabilities({ limit: 2, offset: 2 });

    expect(page1.results).toHaveLength(2);
    expect(page1.hasMore).toBe(true);
    expect(page2.results).toHaveLength(2);
    expect(page2.hasMore).toBe(true);
  });

  it("should order by severity then date", () => {
    const result = searchVulnerabilities({});

    expect(result.results[0].severity).toBe("CRITICAL");
    expect(result.results[1].severity).toBe("HIGH");
  });

  describe("findVulnerabilitiesByPackage", () => {
    it("should find vulnerabilities by package name", () => {
      const vulns = findVulnerabilitiesByPackage("express");

      expect(vulns).toHaveLength(1);
      expect(vulns[0].id).toBe("CVE-2024-0002");
    });

    it("should filter by ecosystem", () => {
      const vulns = findVulnerabilitiesByPackage("requests", "pypi");

      expect(vulns).toHaveLength(1);
    });
  });
});

// =============================================================================
// SYNC STATUS TESTS
// =============================================================================

describe("Sync Status", () => {
  beforeEach(() => {
    initVulnDatabase(testDbPath);
  });

  it("should update sync status", () => {
    updateSyncStatus("trivy", {
      status: "synced",
      lastSync: new Date().toISOString(),
      recordCount: 150000,
      dbVersion: "2024.1.0",
    });

    const status = getSyncStatus("trivy");

    expect(status).not.toBeNull();
    expect(status?.status).toBe("synced");
    expect(status?.recordCount).toBe(150000);
    expect(status?.dbVersion).toBe("2024.1.0");
  });

  it("should calculate age in hours", () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000);
    updateSyncStatus("trivy", {
      status: "synced",
      lastSync: twoHoursAgo.toISOString(),
    });

    const status = getSyncStatus("trivy");

    expect(status?.ageHours).toBe(2);
  });

  it("should return null for non-existent source", () => {
    const status = getSyncStatus("nonexistent");

    expect(status).toBeNull();
  });

  it("should get all sync statuses", () => {
    updateSyncStatus("nvd", { status: "synced" });
    updateSyncStatus("ghsa", { status: "syncing" });

    const statuses = getAllSyncStatuses();

    expect(statuses).toHaveLength(2);
    expect(statuses.map((s) => s.source)).toContain("nvd");
    expect(statuses.map((s) => s.source)).toContain("ghsa");
  });
});

// =============================================================================
// ANNOTATION TESTS
// =============================================================================

describe("Vulnerability Annotations", () => {
  beforeEach(() => {
    initVulnDatabase(testDbPath);
    insertVulnerability(createTestVuln("CVE-2024-1234"));
  });

  it("should annotate a vulnerability", () => {
    const result = annotateVulnerability("CVE-2024-1234", "false_positive", "Not applicable");

    expect(result.success).toBe(true);

    const annotation = getVulnAnnotation("CVE-2024-1234");
    expect(annotation?.status).toBe("false_positive");
    expect(annotation?.notes).toBe("Not applicable");
  });

  it("should fail to annotate non-existent vulnerability", () => {
    const result = annotateVulnerability("CVE-9999-9999", "acknowledged");

    expect(result.success).toBe(false);
    expect(result.error).toContain("not found");
  });

  it("should update existing annotation", () => {
    annotateVulnerability("CVE-2024-1234", "acknowledged");
    annotateVulnerability("CVE-2024-1234", "mitigated", "Fixed in v2.0");

    const annotation = getVulnAnnotation("CVE-2024-1234");
    expect(annotation?.status).toBe("mitigated");
    expect(annotation?.notes).toBe("Fixed in v2.0");
  });

  it("should get annotations by status", () => {
    insertVulnerability(createTestVuln("CVE-2024-1111"));
    insertVulnerability(createTestVuln("CVE-2024-2222"));

    annotateVulnerability("CVE-2024-1234", "false_positive");
    annotateVulnerability("CVE-2024-1111", "false_positive");
    annotateVulnerability("CVE-2024-2222", "acknowledged");

    const falsePositives = getAnnotationsByStatus("false_positive");

    expect(falsePositives).toHaveLength(2);
  });

  it("should remove annotation", () => {
    annotateVulnerability("CVE-2024-1234", "acknowledged");

    const removed = removeAnnotation("CVE-2024-1234");

    expect(removed).toBe(true);
    expect(getVulnAnnotation("CVE-2024-1234")).toBeNull();
  });
});

// =============================================================================
// STATISTICS TESTS
// =============================================================================

describe("Database Statistics", () => {
  beforeEach(() => {
    initVulnDatabase(testDbPath);

    bulkInsertVulnerabilities([
      createTestVuln("CVE-2024-0001", { severity: "CRITICAL", source: "nvd" }),
      createTestVuln("CVE-2024-0002", { severity: "HIGH", source: "nvd" }),
      createTestVuln("CVE-2024-0003", { severity: "HIGH", source: "ghsa" }),
      createTestVuln("CVE-2024-0004", { severity: "MEDIUM", source: "osv" }),
    ]);

    updateSyncStatus("nvd", { lastSync: new Date().toISOString() });
  });

  it("should return correct total count", () => {
    const stats = getVulnDbStats();

    expect(stats.totalVulnerabilities).toBe(4);
  });

  it("should count by severity", () => {
    const stats = getVulnDbStats();

    expect(stats.bySeverity["CRITICAL"]).toBe(1);
    expect(stats.bySeverity["HIGH"]).toBe(2);
    expect(stats.bySeverity["MEDIUM"]).toBe(1);
  });

  it("should count by source", () => {
    const stats = getVulnDbStats();

    expect(stats.bySource["nvd"]).toBe(2);
    expect(stats.bySource["ghsa"]).toBe(1);
    expect(stats.bySource["osv"]).toBe(1);
  });

  it("should include last sync times", () => {
    const stats = getVulnDbStats();

    expect(stats.lastSync["nvd"]).toBeDefined();
  });

  it("should report database size", () => {
    const stats = getVulnDbStats();

    expect(stats.dbSizeBytes).toBeGreaterThan(0);
  });
});

// =============================================================================
// MAINTENANCE TESTS
// =============================================================================

describe("Database Maintenance", () => {
  beforeEach(() => {
    initVulnDatabase(testDbPath);
  });

  it("should vacuum database", () => {
    bulkInsertVulnerabilities([createTestVuln("CVE-2024-0001"), createTestVuln("CVE-2024-0002")]);

    // Should not throw
    expect(() => vacuumDatabase()).not.toThrow();
  });

  it("should clear all vulnerabilities", () => {
    bulkInsertVulnerabilities([createTestVuln("CVE-2024-0001"), createTestVuln("CVE-2024-0002")]);

    const cleared = clearAllVulnerabilities();

    expect(cleared).toBe(2);
    expect(getVulnDbStats().totalVulnerabilities).toBe(0);
  });

  it("should clear vulnerabilities by source", () => {
    bulkInsertVulnerabilities([
      createTestVuln("CVE-2024-0001", { source: "nvd" }),
      createTestVuln("CVE-2024-0002", { source: "nvd" }),
      createTestVuln("CVE-2024-0003", { source: "ghsa" }),
    ]);

    const cleared = clearVulnerabilitiesBySource("nvd");

    expect(cleared).toBe(2);
    expect(getVulnDbStats().totalVulnerabilities).toBe(1);
  });
});

// =============================================================================
// ERROR HANDLING TESTS
// =============================================================================

describe("Error Handling", () => {
  it("should throw when database not initialized", () => {
    // Don't initialize the database
    expect(() => lookupVulnerability("CVE-2024-1234")).toThrow("Database not initialized");
  });

  it("should handle empty references gracefully", () => {
    initVulnDatabase(testDbPath);

    const vuln = createTestVuln("CVE-2024-1234", { references: [] });
    insertVulnerability(vuln);

    const result = lookupVulnerability("CVE-2024-1234");
    expect(result?.references).toEqual([]);
  });

  it("should handle null optional fields", () => {
    initVulnDatabase(testDbPath);

    const vuln: VulnDbRecord = {
      id: "CVE-2024-1234",
      source: "nvd",
      severity: "HIGH",
      title: "Test",
      description: "Test",
      references: [],
      // No optional fields
    };
    insertVulnerability(vuln);

    const result = lookupVulnerability("CVE-2024-1234");
    expect(result?.cvssScore).toBeUndefined();
    expect(result?.publishedAt).toBeUndefined();
  });
});
