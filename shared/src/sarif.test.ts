/**
 * Tests for SARIF converter module
 */

import { describe, it, expect } from "vitest";
import {
  createSarifLog,
  createSarifRun,
  trivyToSarif,
  sonarToSarif,
  dtrackToSarif,
  mergeSarifLogs,
  sarifToJson,
  getSarifSummary,
} from "./sarif.js";
import type { TrivyScanResult, TrivyVulnerability, SonarIssue, DTrackFinding } from "./types.js";

describe("SARIF Converter", () => {
  describe("createSarifLog", () => {
    it("creates a valid empty SARIF log", () => {
      const log = createSarifLog();

      expect(log.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
      expect(log.version).toBe("2.1.0");
      expect(log.runs).toEqual([]);
    });
  });

  describe("createSarifRun", () => {
    it("creates a SARIF run with tool information", () => {
      const run = createSarifRun("TestTool", "1.0.0", "https://example.com");

      expect(run.tool.driver.name).toBe("TestTool");
      expect(run.tool.driver.version).toBe("1.0.0");
      expect(run.tool.driver.informationUri).toBe("https://example.com");
      expect(run.tool.driver.rules).toEqual([]);
      expect(run.results).toEqual([]);
      expect(run.invocations?.[0].executionSuccessful).toBe(true);
    });

    it("creates a run with just tool name", () => {
      const run = createSarifRun("TestTool");

      expect(run.tool.driver.name).toBe("TestTool");
      expect(run.tool.driver.version).toBeUndefined();
    });
  });

  describe("trivyToSarif", () => {
    it("converts empty Trivy result to SARIF", () => {
      const trivyResult: TrivyScanResult = {
        SchemaVersion: 2,
        ArtifactName: "test-image",
        ArtifactType: "container_image",
        Results: [],
      };

      const sarif = trivyToSarif(trivyResult);

      expect(sarif.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
      expect(sarif.version).toBe("2.1.0");
      expect(sarif.runs).toHaveLength(1);
      expect(sarif.runs[0].tool.driver.name).toBe("Trivy");
      expect(sarif.runs[0].results).toEqual([]);
    });

    it("converts Trivy vulnerabilities to SARIF results", () => {
      const vuln: TrivyVulnerability = {
        VulnerabilityID: "CVE-2023-1234",
        PkgName: "lodash",
        InstalledVersion: "4.17.20",
        FixedVersion: "4.17.21",
        Severity: "HIGH",
        Title: "Prototype Pollution",
        Description: "A prototype pollution vulnerability exists",
        PrimaryURL: "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
      };

      const trivyResult: TrivyScanResult = {
        SchemaVersion: 2,
        ArtifactName: "test-image",
        ArtifactType: "container_image",
        Results: [
          {
            Target: "package.json",
            Class: "lang-pkgs",
            Type: "npm",
            Vulnerabilities: [vuln],
          },
        ],
      };

      const sarif = trivyToSarif(trivyResult);

      expect(sarif.runs[0].results).toHaveLength(1);
      expect(sarif.runs[0].results[0].ruleId).toBe("CVE-2023-1234");
      expect(sarif.runs[0].results[0].level).toBe("error");
      expect(sarif.runs[0].results[0].message.text).toContain("lodash@4.17.20");
      expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
      expect(sarif.runs[0].tool.driver.rules?.[0].id).toBe("CVE-2023-1234");
    });

    it("maps severity levels correctly", () => {
      const severities: Array<{ severity: TrivyVulnerability["Severity"]; expected: string }> = [
        { severity: "CRITICAL", expected: "error" },
        { severity: "HIGH", expected: "error" },
        { severity: "MEDIUM", expected: "warning" },
        { severity: "LOW", expected: "note" },
        { severity: "UNKNOWN", expected: "note" },
      ];

      for (const { severity, expected } of severities) {
        const trivyResult: TrivyScanResult = {
          Results: [
            {
              Target: "test",
              Class: "lang-pkgs",
              Type: "npm",
              Vulnerabilities: [
                {
                  VulnerabilityID: `CVE-${severity}`,
                  PkgName: "test",
                  InstalledVersion: "1.0.0",
                  Severity: severity,
                },
              ],
            },
          ],
        };

        const sarif = trivyToSarif(trivyResult);
        expect(sarif.runs[0].results[0].level).toBe(expected);
      }
    });

    it("uses custom tool name and version", () => {
      const trivyResult: TrivyScanResult = { Results: [] };
      const sarif = trivyToSarif(trivyResult, {
        toolName: "CustomTrivy",
        toolVersion: "0.50.0",
      });

      expect(sarif.runs[0].tool.driver.name).toBe("CustomTrivy");
      expect(sarif.runs[0].tool.driver.version).toBe("0.50.0");
    });
  });

  describe("sonarToSarif", () => {
    it("converts empty SonarQube issues to SARIF", () => {
      const sarif = sonarToSarif([]);

      expect(sarif.runs).toHaveLength(1);
      expect(sarif.runs[0].tool.driver.name).toBe("SonarQube");
      expect(sarif.runs[0].results).toEqual([]);
    });

    it("converts SonarQube issues to SARIF results", () => {
      const issue: SonarIssue = {
        key: "issue-1",
        rule: "javascript:S1234",
        severity: "CRITICAL",
        component: "project:src/index.js",
        project: "project",
        line: 42,
        message: "Security vulnerability detected",
        type: "VULNERABILITY",
        status: "OPEN",
      };

      const sarif = sonarToSarif([issue]);

      expect(sarif.runs[0].results).toHaveLength(1);
      expect(sarif.runs[0].results[0].ruleId).toBe("javascript:S1234");
      expect(sarif.runs[0].results[0].level).toBe("error");
      expect(sarif.runs[0].results[0].locations?.[0].physicalLocation?.region?.startLine).toBe(42);
    });

    it("maps SonarQube severity levels correctly", () => {
      const severities: Array<{ severity: SonarIssue["severity"]; expected: string }> = [
        { severity: "BLOCKER", expected: "error" },
        { severity: "CRITICAL", expected: "error" },
        { severity: "MAJOR", expected: "warning" },
        { severity: "MINOR", expected: "note" },
        { severity: "INFO", expected: "note" },
      ];

      for (const { severity, expected } of severities) {
        const sarif = sonarToSarif([
          {
            key: "issue-1",
            rule: "test:rule",
            severity,
            component: "project:src/test.js",
            project: "project",
            message: "Test message",
            type: "BUG",
            status: "OPEN",
          },
        ]);

        expect(sarif.runs[0].results[0].level).toBe(expected);
      }
    });
  });

  describe("dtrackToSarif", () => {
    it("converts empty D-Track findings to SARIF", () => {
      const sarif = dtrackToSarif([]);

      expect(sarif.runs).toHaveLength(1);
      expect(sarif.runs[0].tool.driver.name).toBe("Dependency-Track");
      expect(sarif.runs[0].results).toEqual([]);
    });

    it("converts D-Track findings to SARIF results", () => {
      const finding: DTrackFinding = {
        component: {
          uuid: "comp-uuid",
          name: "lodash",
          version: "4.17.20",
        },
        vulnerability: {
          uuid: "vuln-uuid",
          vulnId: "CVE-2023-5678",
          source: "NVD",
          severity: "HIGH",
          title: "Critical vulnerability",
          description: "A critical vulnerability in lodash",
          cvssV3BaseScore: 7.5,
        },
      };

      const sarif = dtrackToSarif([finding]);

      expect(sarif.runs[0].results).toHaveLength(1);
      expect(sarif.runs[0].results[0].ruleId).toBe("CVE-2023-5678");
      expect(sarif.runs[0].results[0].level).toBe("error");
      // Message contains either the title or the component name depending on implementation
      expect(sarif.runs[0].results[0].message.text).toBeTruthy();
      expect(sarif.runs[0].results[0].locations?.[0]?.message?.text).toContain("lodash");
    });

    it("maps D-Track severity levels correctly", () => {
      const severities: Array<{
        severity: DTrackFinding["vulnerability"]["severity"];
        expected: string;
      }> = [
        { severity: "CRITICAL", expected: "error" },
        { severity: "HIGH", expected: "error" },
        { severity: "MEDIUM", expected: "warning" },
        { severity: "LOW", expected: "note" },
        { severity: "INFO", expected: "note" },
        { severity: "UNASSIGNED", expected: "note" },
      ];

      for (const { severity, expected } of severities) {
        const sarif = dtrackToSarif([
          {
            component: { uuid: "c1", name: "test", version: "1.0.0" },
            vulnerability: {
              uuid: "v1",
              vulnId: "CVE-TEST",
              source: "NVD",
              severity,
            },
          },
        ]);

        expect(sarif.runs[0].results[0].level).toBe(expected);
      }
    });
  });

  describe("mergeSarifLogs", () => {
    it("merges multiple SARIF logs into one", () => {
      const log1 = trivyToSarif({ Results: [] });
      const log2 = sonarToSarif([]);
      const log3 = dtrackToSarif([]);

      const merged = mergeSarifLogs(log1, log2, log3);

      expect(merged.runs).toHaveLength(3);
      expect(merged.runs[0].tool.driver.name).toBe("Trivy");
      expect(merged.runs[1].tool.driver.name).toBe("SonarQube");
      expect(merged.runs[2].tool.driver.name).toBe("Dependency-Track");
    });

    it("handles single log", () => {
      const log = trivyToSarif({ Results: [] });
      const merged = mergeSarifLogs(log);

      expect(merged.runs).toHaveLength(1);
    });

    it("handles empty array", () => {
      const merged = mergeSarifLogs();

      expect(merged.runs).toHaveLength(0);
    });
  });

  describe("sarifToJson", () => {
    it("converts SARIF to JSON string", () => {
      const log = createSarifLog();
      const json = sarifToJson(log);

      expect(typeof json).toBe("string");
      expect(JSON.parse(json)).toEqual(log);
    });

    it("creates pretty-printed JSON by default", () => {
      const log = createSarifLog();
      const json = sarifToJson(log);

      expect(json).toContain("\n");
    });

    it("creates compact JSON when pretty=false", () => {
      const log = createSarifLog();
      const json = sarifToJson(log, false);

      expect(json).not.toContain("\n");
    });
  });

  describe("getSarifSummary", () => {
    it("returns summary of empty SARIF log", () => {
      const log = createSarifLog();
      const summary = getSarifSummary(log);

      expect(summary.totalResults).toBe(0);
      expect(summary.byLevel).toEqual({});
      expect(summary.byTool).toEqual({});
    });

    it("counts results by level and tool", () => {
      const trivyResult: TrivyScanResult = {
        Results: [
          {
            Target: "test",
            Class: "lang-pkgs",
            Type: "npm",
            Vulnerabilities: [
              {
                VulnerabilityID: "CVE-1",
                PkgName: "a",
                InstalledVersion: "1.0",
                Severity: "CRITICAL",
              },
              { VulnerabilityID: "CVE-2", PkgName: "b", InstalledVersion: "1.0", Severity: "HIGH" },
              {
                VulnerabilityID: "CVE-3",
                PkgName: "c",
                InstalledVersion: "1.0",
                Severity: "MEDIUM",
              },
              { VulnerabilityID: "CVE-4", PkgName: "d", InstalledVersion: "1.0", Severity: "LOW" },
            ],
          },
        ],
      };

      const sarif = trivyToSarif(trivyResult);
      const summary = getSarifSummary(sarif);

      expect(summary.totalResults).toBe(4);
      expect(summary.byLevel.error).toBe(2); // CRITICAL + HIGH
      expect(summary.byLevel.warning).toBe(1); // MEDIUM
      expect(summary.byLevel.note).toBe(1); // LOW
      expect(summary.byTool["Trivy"]).toBe(4);
    });

    it("counts results from multiple tools", () => {
      const trivyLog = trivyToSarif({
        Results: [
          {
            Target: "test",
            Class: "lang-pkgs",
            Type: "npm",
            Vulnerabilities: [
              { VulnerabilityID: "CVE-1", PkgName: "a", InstalledVersion: "1.0", Severity: "HIGH" },
            ],
          },
        ],
      });

      const sonarLog = sonarToSarif([
        {
          key: "issue-1",
          rule: "test:rule",
          severity: "CRITICAL",
          component: "project:src/test.js",
          project: "project",
          message: "Test",
          type: "BUG",
          status: "OPEN",
        },
        {
          key: "issue-2",
          rule: "test:rule2",
          severity: "MAJOR",
          component: "project:src/test.js",
          project: "project",
          message: "Test2",
          type: "CODE_SMELL",
          status: "OPEN",
        },
      ]);

      const merged = mergeSarifLogs(trivyLog, sonarLog);
      const summary = getSarifSummary(merged);

      expect(summary.totalResults).toBe(3);
      expect(summary.byTool["Trivy"]).toBe(1);
      expect(summary.byTool["SonarQube"]).toBe(2);
    });
  });
});
