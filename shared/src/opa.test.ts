/**
 * OPA/Rego Policy Module Tests
 */

import { describe, it, expect } from "vitest";
import {
  BUILTIN_POLICIES,
  listBuiltinPolicies,
  getBuiltinPolicy,
  getBuiltinPolicyInfo,
  validateRegoSyntax,
  evaluateOpaPolicy,
  evaluateMultiplePolicies,
  scanResultsToOpaInput,
  createOpaInput,
} from "./opa.js";
import type { ScanResults } from "./policy.js";

describe("OPA/Rego Policy Module", () => {
  // ==========================================================================
  // Built-in Policies Tests
  // ==========================================================================
  describe("BUILTIN_POLICIES", () => {
    it("should have vulnerability-threshold policy", () => {
      expect(BUILTIN_POLICIES["vulnerability-threshold"]).toBeDefined();
      expect(BUILTIN_POLICIES["vulnerability-threshold"]).toContain("package security");
      expect(BUILTIN_POLICIES["vulnerability-threshold"]).toContain("violations contains");
    });

    it("should have license-compliance policy", () => {
      expect(BUILTIN_POLICIES["license-compliance"]).toBeDefined();
      expect(BUILTIN_POLICIES["license-compliance"]).toContain("blocked_licenses");
      expect(BUILTIN_POLICIES["license-compliance"]).toContain("GPL-3.0");
    });

    it("should have secrets-detection policy", () => {
      expect(BUILTIN_POLICIES["secrets-detection"]).toBeDefined();
      expect(BUILTIN_POLICIES["secrets-detection"]).toContain("secretsFound");
    });

    it("should have container-security policy", () => {
      expect(BUILTIN_POLICIES["container-security"]).toBeDefined();
      expect(BUILTIN_POLICIES["container-security"]).toContain("latest");
      expect(BUILTIN_POLICIES["container-security"]).toContain("runAsRoot");
    });

    it("should have quality-gate policy", () => {
      expect(BUILTIN_POLICIES["quality-gate"]).toBeDefined();
      expect(BUILTIN_POLICIES["quality-gate"]).toContain("qualityGatePassed");
      expect(BUILTIN_POLICIES["quality-gate"]).toContain("codeCoverage");
    });
  });

  // ==========================================================================
  // Policy Listing Tests
  // ==========================================================================
  describe("listBuiltinPolicies", () => {
    it("should list all 5 built-in policies", () => {
      const policies = listBuiltinPolicies();
      expect(policies).toHaveLength(5);
    });

    it("should return policy info with required fields", () => {
      const policies = listBuiltinPolicies();
      policies.forEach((policy) => {
        expect(policy.name).toBeDefined();
        expect(policy.version).toBe("1.0.0");
        expect(policy.description).toBeDefined();
        expect(policy.entrypoints).toContain("security/allow");
        expect(policy.ruleCount).toBeGreaterThan(0);
        expect(policy.source).toBe("builtin");
      });
    });
  });

  describe("getBuiltinPolicy", () => {
    it("should return policy source for valid name", () => {
      const source = getBuiltinPolicy("vulnerability-threshold");
      expect(source).toBeDefined();
      expect(source).toContain("package security");
    });

    it("should return undefined for invalid name", () => {
      const source = getBuiltinPolicy("nonexistent-policy");
      expect(source).toBeUndefined();
    });
  });

  describe("getBuiltinPolicyInfo", () => {
    it("should return detailed info for valid policy", () => {
      const info = getBuiltinPolicyInfo("license-compliance");
      expect(info).toBeDefined();
      expect(info?.name).toBe("license-compliance");
      expect(info?.description).toContain("license");
      expect(info?.entrypoints).toContain("security/violations");
    });

    it("should return undefined for invalid policy", () => {
      const info = getBuiltinPolicyInfo("nonexistent-policy");
      expect(info).toBeUndefined();
    });
  });

  // ==========================================================================
  // Rego Validation Tests
  // ==========================================================================
  describe("validateRegoSyntax", () => {
    it("should validate correct Rego syntax", () => {
      const result = validateRegoSyntax(`
        package security

        default allow := false

        allow if {
          input.scan.vulnerabilities.critical == 0
        }
      `);
      expect(result.valid).toBe(true);
      expect(result.errors).toBeUndefined();
    });

    it("should detect missing package declaration", () => {
      const result = validateRegoSyntax(`
        default allow := false

        allow if {
          input.scan.vulnerabilities.critical == 0
        }
      `);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain("Missing package declaration");
    });

    it("should detect unbalanced braces", () => {
      const result = validateRegoSyntax(`
        package security

        allow if {
          input.scan.vulnerabilities.critical == 0
      `);
      expect(result.valid).toBe(false);
      expect(result.errors?.[0]).toContain("Unbalanced braces");
    });

    it("should detect missing rule definitions", () => {
      const result = validateRegoSyntax(`
        package security

        # Just a comment, no rules
      `);
      expect(result.valid).toBe(false);
      expect(result.errors?.[0]).toContain("No rule definitions found");
    });
  });

  // ==========================================================================
  // Policy Evaluation Tests
  // ==========================================================================
  describe("evaluateOpaPolicy", () => {
    describe("vulnerability-threshold policy", () => {
      it("should allow clean scan with no vulnerabilities", async () => {
        const input = createOpaInput({
          critical: 0,
          high: 0,
          medium: 5,
          low: 10,
        });

        const result = await evaluateOpaPolicy(input, {
          policy: "vulnerability-threshold",
        });

        expect(result.allow).toBe(true);
        expect(result.violations).toHaveLength(0);
        expect(result.metadata.policyName).toBe("vulnerability-threshold");
      });

      it("should deny scan with critical vulnerabilities", async () => {
        const input = createOpaInput({
          critical: 2,
          high: 5,
          medium: 10,
          low: 20,
        });

        const result = await evaluateOpaPolicy(input, {
          policy: "vulnerability-threshold",
        });

        expect(result.allow).toBe(false);
        expect(result.violations.length).toBeGreaterThan(0);
        expect(result.violations[0].severity).toBe("critical");
        expect(result.violations[0].code).toBe("critical_vulnerabilities");
      });

      it("should deny when high vulnerabilities exceed threshold", async () => {
        const input = createOpaInput({
          critical: 0,
          high: 15, // Default threshold is 10
          medium: 10,
          low: 20,
        });

        const result = await evaluateOpaPolicy(input, {
          policy: "vulnerability-threshold",
        });

        expect(result.allow).toBe(false);
        expect(result.violations.some((v) => v.code === "high_vulnerabilities_exceeded")).toBe(
          true
        );
      });

      it("should respect custom thresholds", async () => {
        const input = createOpaInput({
          critical: 0,
          high: 5,
          medium: 10,
          low: 20,
          thresholds: { high: 3 },
        });

        const result = await evaluateOpaPolicy(input, {
          policy: "vulnerability-threshold",
        });

        expect(result.allow).toBe(false);
        expect(result.violations.some((v) => v.code === "high_vulnerabilities_exceeded")).toBe(
          true
        );
      });
    });

    describe("license-compliance policy", () => {
      it("should allow permissive licenses", async () => {
        const input = createOpaInput({
          critical: 0,
          high: 0,
          licenses: ["MIT", "Apache-2.0", "BSD-3-Clause"],
        });

        const result = await evaluateOpaPolicy(input, {
          policy: "license-compliance",
        });

        expect(result.allow).toBe(true);
        expect(result.violations).toHaveLength(0);
      });

      it("should detect blocked GPL license", async () => {
        const input = createOpaInput({
          critical: 0,
          high: 0,
          licenses: ["MIT", "GPL-3.0", "Apache-2.0"],
        });

        const result = await evaluateOpaPolicy(input, {
          policy: "license-compliance",
        });

        expect(result.allow).toBe(false);
        expect(result.violations.some((v) => v.code === "blocked_license")).toBe(true);
        expect(result.violations.some((v) => v.resource === "GPL-3.0")).toBe(true);
      });

      it("should warn about restricted LGPL license", async () => {
        const input = createOpaInput({
          critical: 0,
          high: 0,
          licenses: ["MIT", "LGPL-2.1", "Apache-2.0"],
        });

        const result = await evaluateOpaPolicy(input, {
          policy: "license-compliance",
        });

        // LGPL is restricted (warning) not blocked
        expect(result.allow).toBe(true);
        expect(result.violations.some((v) => v.code === "restricted_license")).toBe(true);
      });
    });

    describe("secrets-detection policy", () => {
      it("should allow when no secrets found", async () => {
        const input = createOpaInput({
          critical: 0,
          high: 0,
          secretsFound: false,
        });

        const result = await evaluateOpaPolicy(input, {
          policy: "secrets-detection",
        });

        expect(result.allow).toBe(true);
        expect(result.violations).toHaveLength(0);
      });

      it("should deny when secrets detected", async () => {
        const input = createOpaInput({
          critical: 0,
          high: 0,
          secretsFound: true,
        });

        const result = await evaluateOpaPolicy(input, {
          policy: "secrets-detection",
        });

        expect(result.allow).toBe(false);
        expect(result.violations[0].severity).toBe("critical");
        expect(result.violations[0].code).toBe("secrets_in_code");
      });
    });

    describe("container-security policy", () => {
      it("should allow secure container configuration", async () => {
        const input = createOpaInput({
          critical: 0,
          high: 0,
          image: "myapp:v1.2.3",
          metadata: { runAsRoot: false },
        });

        const result = await evaluateOpaPolicy(input, {
          policy: "container-security",
        });

        expect(result.allow).toBe(true);
      });

      it("should warn about latest tag usage", async () => {
        const input = createOpaInput({
          critical: 0,
          high: 0,
          image: "nginx:latest",
        });

        const result = await evaluateOpaPolicy(input, {
          policy: "container-security",
        });

        expect(result.violations.some((v) => v.code === "latest_tag_used")).toBe(true);
      });

      it("should warn about running as root", async () => {
        const input = createOpaInput({
          critical: 0,
          high: 0,
          image: "myapp:v1.0",
          metadata: { runAsRoot: true },
        });

        const result = await evaluateOpaPolicy(input, {
          policy: "container-security",
        });

        expect(result.allow).toBe(false);
        expect(result.violations.some((v) => v.code === "runs_as_root")).toBe(true);
      });
    });

    describe("quality-gate policy", () => {
      it("should allow when quality gate passed with good coverage", async () => {
        const input = createOpaInput({
          critical: 0,
          high: 0,
          qualityGatePassed: true,
          codeCoverage: 85,
        });

        const result = await evaluateOpaPolicy(input, {
          policy: "quality-gate",
        });

        expect(result.allow).toBe(true);
      });

      it("should deny when quality gate failed", async () => {
        const input = createOpaInput({
          critical: 0,
          high: 0,
          qualityGatePassed: false,
          codeCoverage: 90,
        });

        const result = await evaluateOpaPolicy(input, {
          policy: "quality-gate",
        });

        expect(result.allow).toBe(false);
        expect(result.violations.some((v) => v.code === "quality_gate_failed")).toBe(true);
      });

      it("should deny when coverage is too low", async () => {
        const input = createOpaInput({
          critical: 0,
          high: 0,
          qualityGatePassed: true,
          codeCoverage: 60,
          thresholds: { coverage: 80 },
        });

        const result = await evaluateOpaPolicy(input, {
          policy: "quality-gate",
        });

        expect(result.violations.some((v) => v.code === "low_code_coverage")).toBe(true);
      });
    });

    describe("error handling", () => {
      it("should throw for unknown policy", async () => {
        const input = createOpaInput({ critical: 0, high: 0 });

        await expect(evaluateOpaPolicy(input, { policy: "nonexistent-policy" })).rejects.toThrow(
          "Unknown policy"
        );
      });
    });
  });

  // ==========================================================================
  // Multiple Policy Evaluation Tests
  // ==========================================================================
  describe("evaluateMultiplePolicies", () => {
    it("should evaluate multiple policies and combine results", async () => {
      const input = createOpaInput({
        critical: 1,
        high: 5,
        licenses: ["GPL-3.0"],
        secretsFound: true,
      });

      const result = await evaluateMultiplePolicies(input, [
        "vulnerability-threshold",
        "license-compliance",
        "secrets-detection",
      ]);

      expect(result.allow).toBe(false);
      // At least 3 violations: 1 critical vuln, 1 blocked license, 1 secrets
      expect(result.violations.length).toBeGreaterThanOrEqual(3);
      expect(result.metadata.policyName).toContain("vulnerability-threshold");
      expect(result.metadata.policyName).toContain("license-compliance");
    });

    it("should allow when all policies pass", async () => {
      const input = createOpaInput({
        critical: 0,
        high: 0,
        licenses: ["MIT"],
        secretsFound: false,
      });

      const result = await evaluateMultiplePolicies(input, [
        "vulnerability-threshold",
        "license-compliance",
        "secrets-detection",
      ]);

      expect(result.allow).toBe(true);
      expect(result.violations).toHaveLength(0);
    });
  });

  // ==========================================================================
  // Input Conversion Tests
  // ==========================================================================
  describe("scanResultsToOpaInput", () => {
    it("should convert ScanResults to OpaEvaluationInput", () => {
      const scanResults: ScanResults = {
        vulnerabilities: {
          critical: 1,
          high: 5,
          medium: 10,
          low: 20,
          unknown: 2,
        },
        licenses: ["MIT", "Apache-2.0"],
        secretsFound: false,
        codeCoverage: 85,
        qualityGatePassed: true,
      };

      const opaInput = scanResultsToOpaInput(scanResults);

      expect(opaInput.scan.vulnerabilities.critical).toBe(1);
      expect(opaInput.scan.vulnerabilities.high).toBe(5);
      expect(opaInput.scan.vulnerabilities.total).toBe(38);
      expect(opaInput.scan.licenses).toEqual(["MIT", "Apache-2.0"]);
      expect(opaInput.scan.secretsFound).toBe(false);
      expect(opaInput.scan.codeCoverage).toBe(85);
    });

    it("should include optional metadata", () => {
      const scanResults: ScanResults = {
        vulnerabilities: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          unknown: 0,
        },
      };

      const opaInput = scanResultsToOpaInput(scanResults, {
        project: "my-app",
        environment: "production",
      });

      expect(opaInput.metadata).toEqual({
        project: "my-app",
        environment: "production",
      });
    });

    it("should handle undefined vulnerabilities", () => {
      const scanResults: ScanResults = {};

      const opaInput = scanResultsToOpaInput(scanResults);

      expect(opaInput.scan.vulnerabilities.critical).toBe(0);
      expect(opaInput.scan.vulnerabilities.total).toBe(0);
    });
  });

  describe("createOpaInput", () => {
    it("should create input with vulnerability counts", () => {
      const input = createOpaInput({
        critical: 1,
        high: 5,
        medium: 10,
        low: 20,
      });

      expect(input.scan.vulnerabilities.critical).toBe(1);
      expect(input.scan.vulnerabilities.high).toBe(5);
      expect(input.scan.vulnerabilities.total).toBe(36);
    });

    it("should include optional fields", () => {
      const input = createOpaInput({
        critical: 0,
        high: 0,
        licenses: ["MIT"],
        secretsFound: true,
        codeCoverage: 80,
        qualityGatePassed: false,
        image: "nginx:latest",
        thresholds: { high: 5, coverage: 70 },
        metadata: { team: "security" },
      });

      expect(input.scan.licenses).toEqual(["MIT"]);
      expect(input.scan.secretsFound).toBe(true);
      expect(input.scan.codeCoverage).toBe(80);
      expect(input.image).toBe("nginx:latest");
      expect(input.thresholds?.high).toBe(5);
      expect(input.metadata?.team).toBe("security");
    });
  });

  // ==========================================================================
  // Metadata Tests
  // ==========================================================================
  describe("evaluation metadata", () => {
    it("should include evaluation timestamp", async () => {
      const input = createOpaInput({ critical: 0, high: 0 });
      const before = new Date().toISOString();

      const result = await evaluateOpaPolicy(input, {
        policy: "vulnerability-threshold",
      });

      const after = new Date().toISOString();
      expect(result.metadata.evaluatedAt >= before).toBe(true);
      expect(result.metadata.evaluatedAt <= after).toBe(true);
    });

    it("should include input hash", async () => {
      const input = createOpaInput({ critical: 0, high: 0 });

      const result = await evaluateOpaPolicy(input, {
        policy: "vulnerability-threshold",
      });

      expect(result.metadata.inputHash).toBeDefined();
      expect(result.metadata.inputHash?.length).toBe(16);
    });

    it("should have consistent hash for same input", async () => {
      const input = createOpaInput({ critical: 1, high: 5 });

      const result1 = await evaluateOpaPolicy(input, {
        policy: "vulnerability-threshold",
      });
      const result2 = await evaluateOpaPolicy(input, {
        policy: "vulnerability-threshold",
      });

      expect(result1.metadata.inputHash).toBe(result2.metadata.inputHash);
    });
  });
});
