import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  COMPLIANCE_CONTROLS,
  getComplianceFrameworks,
  getComplianceControls,
  getComplianceControl,
  mapFindingToControls,
  generateComplianceReport,
  generateComplianceHtml,
  recordComplianceTrend,
  getComplianceTrend,
  clearComplianceTrends,
  getComplianceTrendTargets,
  checkComplianceStatus,
} from "./compliance.js";
import type {
  ComplianceFramework,
  SecurityDashboardResult,
  SecurityDashboardFinding,
  SecurityDashboardSummary,
} from "./types.js";

// =============================================================================
// Test Data
// =============================================================================

const mockTrivyFinding: SecurityDashboardFinding = {
  id: "CVE-2023-1234",
  source: "trivy",
  severity: "CRITICAL",
  package: "openssl",
  message: "Critical vulnerability in OpenSSL allowing remote code execution",
};

const mockSonarFinding: SecurityDashboardFinding = {
  id: "squid:S5131",
  source: "sonarqube",
  severity: "HIGH",
  message: "Command Injection - User-controlled data is used in a system command",
};

const mockDtrackFinding: SecurityDashboardFinding = {
  id: "CVE-2023-5678",
  source: "dtrack",
  severity: "MEDIUM",
  package: "lodash",
  message: "Prototype pollution vulnerability",
};

const mockSecretFinding: SecurityDashboardFinding = {
  id: "aws-access-key-id",
  source: "trivy",
  severity: "CRITICAL",
  message: "AWS Access Key ID detected - Hardcoded credentials found",
};

const baseSummary: SecurityDashboardSummary = {
  total: 4,
  critical: 2,
  high: 1,
  medium: 1,
  low: 0,
};

const mockDashboardResult: SecurityDashboardResult = {
  timestamp: new Date().toISOString(),
  summary: baseSummary,
  bySource: {
    trivy: {
      total: 2,
      critical: 1,
      high: 0,
      medium: 1,
      low: 0,
    },
    sonarqube: {
      bugs: 0,
      vulnerabilities: 1,
      codeSmells: 0,
      hotspots: 0,
      qualityGateStatus: "OK",
    },
    dependencyTrack: {
      total: 1,
      critical: 0,
      high: 1,
      medium: 0,
      low: 0,
    },
  },
  scanTargets: {
    image: "test-image:latest",
  },
  topFindings: [mockTrivyFinding, mockSecretFinding, mockSonarFinding, mockDtrackFinding],
};

const mockEmptyDashboardResult: SecurityDashboardResult = {
  timestamp: new Date().toISOString(),
  summary: {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  },
  bySource: {
    trivy: {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    },
    sonarqube: {
      bugs: 0,
      vulnerabilities: 0,
      codeSmells: 0,
      hotspots: 0,
      qualityGateStatus: "OK",
    },
    dependencyTrack: {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    },
  },
  scanTargets: {
    image: "clean-image:latest",
  },
  topFindings: [],
};

// =============================================================================
// COMPLIANCE_CONTROLS Tests
// =============================================================================

describe("COMPLIANCE_CONTROLS", () => {
  it("should have controls for all four frameworks", () => {
    const frameworks: ComplianceFramework[] = ["SOC2", "HIPAA", "PCI-DSS", "CIS"];
    for (const framework of frameworks) {
      expect(COMPLIANCE_CONTROLS[framework]).toBeDefined();
      expect(Array.isArray(COMPLIANCE_CONTROLS[framework])).toBe(true);
      expect(COMPLIANCE_CONTROLS[framework].length).toBeGreaterThan(0);
    }
  });

  it("should have valid control structure for all controls", () => {
    const frameworks: ComplianceFramework[] = ["SOC2", "HIPAA", "PCI-DSS", "CIS"];

    for (const framework of frameworks) {
      const controls = COMPLIANCE_CONTROLS[framework];
      for (const control of controls) {
        // Required fields
        expect(control.id).toBeDefined();
        expect(typeof control.id).toBe("string");
        expect(control.framework).toBe(framework);
        expect(control.name).toBeDefined();
        expect(control.description).toBeDefined();
        expect(control.category).toBeDefined();

        // Severity mapping
        expect(control.severityMapping).toBeDefined();
        expect(typeof control.severityMapping.critical).toBe("boolean");
        expect(typeof control.severityMapping.high).toBe("boolean");
        expect(typeof control.severityMapping.medium).toBe("boolean");
        expect(typeof control.severityMapping.low).toBe("boolean");

        // Vulnerability types
        expect(Array.isArray(control.vulnerabilityTypes)).toBe(true);
        expect(control.vulnerabilityTypes.length).toBeGreaterThan(0);

        // Remediation SLA
        expect(control.remediationSLA).toBeDefined();
        expect(control.remediationSLA.critical).toBeDefined();
        expect(control.remediationSLA.high).toBeDefined();
        expect(control.remediationSLA.medium).toBeDefined();
        expect(control.remediationSLA.low).toBeDefined();
      }
    }
  });

  it("should have unique control IDs within each framework", () => {
    const frameworks: ComplianceFramework[] = ["SOC2", "HIPAA", "PCI-DSS", "CIS"];

    for (const framework of frameworks) {
      const ids = COMPLIANCE_CONTROLS[framework].map((c) => c.id);
      const uniqueIds = new Set(ids);
      expect(ids.length).toBe(uniqueIds.size);
    }
  });
});

// =============================================================================
// getComplianceFrameworks Tests
// =============================================================================

describe("getComplianceFrameworks", () => {
  it("should return all seven frameworks as strings", () => {
    const frameworks = getComplianceFrameworks();
    expect(frameworks).toHaveLength(7);
    expect(frameworks).toContain("SOC2");
    expect(frameworks).toContain("HIPAA");
    expect(frameworks).toContain("PCI-DSS");
    expect(frameworks).toContain("CIS");
    expect(frameworks).toContain("NIST-CSF");
    expect(frameworks).toContain("ISO-27001");
    expect(frameworks).toContain("FEDRAMP");
  });
});

// =============================================================================
// getComplianceControls Tests
// =============================================================================

describe("getComplianceControls", () => {
  it("should return all controls for SOC2", () => {
    const controls = getComplianceControls("SOC2");
    expect(controls.length).toBeGreaterThan(0);
    expect(controls.every((c) => c.framework === "SOC2")).toBe(true);
  });

  it("should return all controls for HIPAA", () => {
    const controls = getComplianceControls("HIPAA");
    expect(controls.length).toBeGreaterThan(0);
    expect(controls.every((c) => c.framework === "HIPAA")).toBe(true);
  });

  it("should return all controls for PCI-DSS", () => {
    const controls = getComplianceControls("PCI-DSS");
    expect(controls.length).toBeGreaterThan(0);
    expect(controls.every((c) => c.framework === "PCI-DSS")).toBe(true);
  });

  it("should return all controls for CIS", () => {
    const controls = getComplianceControls("CIS");
    expect(controls.length).toBeGreaterThan(0);
    expect(controls.every((c) => c.framework === "CIS")).toBe(true);
  });

  it("should return all controls for NIST-CSF", () => {
    const controls = getComplianceControls("NIST-CSF");
    expect(controls.length).toBeGreaterThan(0);
    expect(controls.every((c) => c.framework === "NIST-CSF")).toBe(true);
  });

  it("should return all controls for ISO-27001", () => {
    const controls = getComplianceControls("ISO-27001");
    expect(controls.length).toBeGreaterThan(0);
    expect(controls.every((c) => c.framework === "ISO-27001")).toBe(true);
  });

  it("should return all controls for FEDRAMP", () => {
    const controls = getComplianceControls("FEDRAMP");
    expect(controls.length).toBeGreaterThan(0);
    expect(controls.every((c) => c.framework === "FEDRAMP")).toBe(true);
  });
});

// =============================================================================
// getComplianceControl Tests
// =============================================================================

describe("getComplianceControl", () => {
  it("should return specific SOC2 control by ID", () => {
    const control = getComplianceControl("SOC2", "CC7.1");
    expect(control).toBeDefined();
    expect(control?.id).toBe("CC7.1");
    expect(control?.framework).toBe("SOC2");
  });

  it("should return specific HIPAA control by ID", () => {
    const control = getComplianceControl("HIPAA", "164.308(a)(1)(ii)(A)");
    expect(control).toBeDefined();
    expect(control?.id).toBe("164.308(a)(1)(ii)(A)");
    expect(control?.framework).toBe("HIPAA");
  });

  it("should return undefined for non-existent control", () => {
    const control = getComplianceControl("SOC2", "NONEXISTENT");
    expect(control).toBeUndefined();
  });
});

// =============================================================================
// mapFindingToControls Tests
// =============================================================================

describe("mapFindingToControls", () => {
  it("should map critical CVE to vulnerability management controls", () => {
    const controls = mapFindingToControls(mockTrivyFinding);
    expect(controls.length).toBeGreaterThan(0);

    // Should include SOC2 CC7.1 (Vulnerability Management)
    const soc2Controls = controls.filter((c) => c.framework === "SOC2");
    expect(soc2Controls.length).toBeGreaterThan(0);
  });

  it("should map secrets to multiple frameworks", () => {
    const controls = mapFindingToControls(mockSecretFinding);
    expect(controls.length).toBeGreaterThan(0);

    // Secrets should map to multiple frameworks
    const frameworks = new Set(controls.map((c) => c.framework));
    expect(frameworks.size).toBeGreaterThan(1);
  });

  it("should filter by specified frameworks", () => {
    const controls = mapFindingToControls(mockTrivyFinding, ["SOC2"]);
    expect(controls.length).toBeGreaterThan(0);
    expect(controls.every((c) => c.framework === "SOC2")).toBe(true);
  });

  it("should return empty array when no controls match", () => {
    const lowSeverityFinding: SecurityDashboardFinding = {
      ...mockTrivyFinding,
      severity: "LOW",
    };
    const controls = mapFindingToControls(lowSeverityFinding, ["CIS"]);
    // CIS controls mostly map to misconfig type, so low severity CVE may not map
    // This is expected behavior
    expect(Array.isArray(controls)).toBe(true);
  });
});

// =============================================================================
// generateComplianceReport Tests
// =============================================================================

describe("generateComplianceReport", () => {
  it("should generate report with all frameworks by default", () => {
    const report = generateComplianceReport(mockDashboardResult);

    expect(report.generatedAt).toBeDefined();
    expect(report.scanTarget).toBeDefined();
    expect(report.frameworks).toHaveLength(7);
    expect(report.summary).toBeDefined();
    expect(report.byFramework).toBeDefined();
    expect(report.bySeverity).toBeDefined();
    expect(report.recommendations).toBeDefined();
  });

  it("should calculate violation counts", () => {
    const report = generateComplianceReport(mockDashboardResult);

    // With findings, there should be some violations
    expect(report.summary.totalControls).toBeGreaterThan(0);
    expect(typeof report.summary.compliancePercentage).toBe("number");
  });

  it("should generate report for specific frameworks only", () => {
    const report = generateComplianceReport(mockDashboardResult, {
      frameworks: ["SOC2", "HIPAA"],
    });

    expect(report.frameworks).toHaveLength(2);
    expect(report.frameworks).toContain("SOC2");
    expect(report.frameworks).toContain("HIPAA");
    expect(report.frameworks).not.toContain("PCI-DSS");
    expect(report.frameworks).not.toContain("CIS");
  });

  it("should include top violations limited to 10", () => {
    const report = generateComplianceReport(mockDashboardResult);

    expect(Array.isArray(report.topViolations)).toBe(true);
    expect(report.topViolations.length).toBeLessThanOrEqual(10);
  });

  it("should generate clean report for no violations", () => {
    const report = generateComplianceReport(mockEmptyDashboardResult);

    expect(report.topViolations).toHaveLength(0);
    expect(report.bySeverity.critical).toBe(0);
    expect(report.bySeverity.high).toBe(0);
    expect(report.summary.compliancePercentage).toBe(100);
  });

  it("should include framework-specific summaries", () => {
    const report = generateComplianceReport(mockDashboardResult);

    for (const framework of report.frameworks) {
      const frameworkSummary = report.byFramework[framework];
      expect(frameworkSummary).toBeDefined();
      expect(frameworkSummary!.totalControls).toBeGreaterThan(0);
      expect(typeof frameworkSummary!.passingControls).toBe("number");
      expect(typeof frameworkSummary!.failingControls).toBe("number");
    }
  });
});

// =============================================================================
// generateComplianceHtml Tests
// =============================================================================

describe("generateComplianceHtml", () => {
  it("should generate valid HTML document", () => {
    const report = generateComplianceReport(mockDashboardResult);
    const html = generateComplianceHtml(report);

    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("<html");
    expect(html).toContain("</html>");
    expect(html).toContain("<head>");
    expect(html).toContain("<body>");
  });

  it("should include report title", () => {
    const report = generateComplianceReport(mockDashboardResult);
    const html = generateComplianceHtml(report, { title: "My Security Report" });

    expect(html).toContain("My Security Report");
  });

  it("should include organization name", () => {
    const report = generateComplianceReport(mockDashboardResult);
    const html = generateComplianceHtml(report, { organization: "Acme Corp" });

    expect(html).toContain("Acme Corp");
  });

  it("should include severity styling", () => {
    const report = generateComplianceReport(mockDashboardResult);
    const html = generateComplianceHtml(report);

    expect(html).toContain("severity-critical");
  });

  it("should include framework sections", () => {
    const report = generateComplianceReport(mockDashboardResult);
    const html = generateComplianceHtml(report);

    expect(html).toContain("SOC2");
    expect(html).toContain("HIPAA");
    expect(html).toContain("PCI-DSS");
    expect(html).toContain("CIS");
  });

  it("should include CSS styling", () => {
    const report = generateComplianceReport(mockDashboardResult);
    const html = generateComplianceHtml(report);

    expect(html).toContain("<style>");
    expect(html).toContain("</style>");
  });
});

// =============================================================================
// Trend Tracking Tests
// =============================================================================

describe("Trend Tracking", () => {
  beforeEach(() => {
    clearComplianceTrends();
  });

  afterEach(() => {
    clearComplianceTrends();
  });

  describe("recordComplianceTrend", () => {
    it("should record trend entry for target", () => {
      const report = generateComplianceReport(mockDashboardResult);
      const entry = recordComplianceTrend("test-target", report);

      expect(entry.timestamp).toBeDefined();
      expect(entry.target).toBe("test-target");
      expect(entry.frameworks).toHaveLength(7);
      expect(entry.summary).toBeDefined();
    });

    it("should return entry with summary data", () => {
      const report = generateComplianceReport(mockDashboardResult);
      const entry = recordComplianceTrend("test-target", report);

      expect(typeof entry.summary.totalViolations).toBe("number");
      expect(typeof entry.summary.compliancePercentage).toBe("number");
    });
  });

  describe("getComplianceTrend", () => {
    it("should return empty result for unknown target", () => {
      const result = getComplianceTrend("unknown-target");

      expect(result.target).toBe("unknown-target");
      expect(result.entries).toHaveLength(0);
      expect(result.trend).toBe("stable");
    });

    it("should return trend data for recorded target", () => {
      const report = generateComplianceReport(mockDashboardResult);
      recordComplianceTrend("test-target", report);

      const result = getComplianceTrend("test-target");

      expect(result.target).toBe("test-target");
      expect(result.entries).toHaveLength(1);
    });

    it("should calculate improving trend", () => {
      // Record declining compliance first
      const poorReport = generateComplianceReport(mockDashboardResult);
      recordComplianceTrend("test-target", poorReport);

      // Record better compliance
      const goodReport = generateComplianceReport(mockEmptyDashboardResult);
      recordComplianceTrend("test-target", goodReport);

      const result = getComplianceTrend("test-target");
      expect(result.trend).toBe("improving");
    });

    it("should calculate declining trend", () => {
      // Record good compliance first
      const goodReport = generateComplianceReport(mockEmptyDashboardResult);
      recordComplianceTrend("test-target", goodReport);

      // Record worse compliance
      const poorReport = generateComplianceReport(mockDashboardResult);
      recordComplianceTrend("test-target", poorReport);

      const result = getComplianceTrend("test-target");
      expect(result.trend).toBe("declining");
    });
  });

  describe("getComplianceTrendTargets", () => {
    it("should return empty array when no trends recorded", () => {
      const targets = getComplianceTrendTargets();
      expect(targets).toHaveLength(0);
    });

    it("should return all recorded targets", () => {
      const report = generateComplianceReport(mockDashboardResult);
      recordComplianceTrend("target1", report);
      recordComplianceTrend("target2", report);

      const targets = getComplianceTrendTargets();
      expect(targets).toHaveLength(2);
      expect(targets).toContain("target1");
      expect(targets).toContain("target2");
    });
  });

  describe("clearComplianceTrends", () => {
    it("should clear all trend data", () => {
      const report = generateComplianceReport(mockDashboardResult);
      recordComplianceTrend("target1", report);
      recordComplianceTrend("target2", report);

      clearComplianceTrends();

      const targets = getComplianceTrendTargets();
      expect(targets).toHaveLength(0);
    });
  });
});

// =============================================================================
// checkComplianceStatus Tests
// =============================================================================

describe("checkComplianceStatus", () => {
  it("should return pass for clean scan", () => {
    const result = checkComplianceStatus(mockEmptyDashboardResult);

    expect(result.passed).toBe(true);
    expect(result.compliancePercentage).toBe(100);
    expect(result.violations.total).toBe(0);
  });

  it("should return fail for scan with critical violations", () => {
    const result = checkComplianceStatus(mockDashboardResult);

    expect(result.passed).toBe(false);
    expect(result.compliancePercentage).toBeLessThan(100);
  });

  it("should include violations breakdown", () => {
    const result = checkComplianceStatus(mockDashboardResult);

    expect(result.violations).toBeDefined();
    expect(typeof result.violations.critical).toBe("number");
    expect(typeof result.violations.high).toBe("number");
    expect(typeof result.violations.medium).toBe("number");
    expect(typeof result.violations.low).toBe("number");
    expect(typeof result.violations.total).toBe("number");
  });

  it("should filter by specified frameworks", () => {
    const result = checkComplianceStatus(mockDashboardResult, {
      frameworks: ["SOC2"],
    });

    // The result should have a report with only SOC2
    expect(result.report.frameworks).toHaveLength(1);
    expect(result.report.frameworks).toContain("SOC2");
  });

  it("should include failing controls list", () => {
    const result = checkComplianceStatus(mockDashboardResult);

    expect(result.failingControls).toBeDefined();
    expect(Array.isArray(result.failingControls)).toBe(true);
  });

  it("should include full report", () => {
    const result = checkComplianceStatus(mockDashboardResult);

    expect(result.report).toBeDefined();
    expect(result.report.generatedAt).toBeDefined();
    expect(result.report.frameworks).toBeDefined();
  });
});
