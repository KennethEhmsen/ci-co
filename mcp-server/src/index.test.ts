import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  validateSeverity,
  sanitizePath,
  sanitizeImageName,
  toolDefinitions,
  resourceDefinitions,
  handleListTools,
  handleCallTool,
  handleListResources,
  handleReadResource,
} from "./index.js";

// Mock the @cicd/shared module for evaluatePolicyWithScan
vi.mock("@cicd/shared", async (importOriginal) => {
  const original = (await importOriginal()) as Record<string, unknown>;
  return {
    ...original,
    evaluatePolicyWithScan: vi.fn().mockResolvedValue({
      allowed: true,
      violations: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0 },
    }),
  };
});

// Mock the handlers module
vi.mock("./handlers.js", async (importOriginal) => {
  const original = (await importOriginal()) as Record<string, unknown>;
  return {
    ...original,
    trivyScanPath: vi.fn().mockResolvedValue({ vulnerabilities: [] }),
    trivyScanImage: vi.fn().mockResolvedValue({ vulnerabilities: [] }),
    sonarGetProjects: vi.fn().mockResolvedValue({ components: [] }),
    sonarGetIssues: vi.fn().mockResolvedValue({ issues: [] }),
    sonarGetSecurityHotspots: vi.fn().mockResolvedValue({ hotspots: [] }),
    sonarGetMetrics: vi.fn().mockResolvedValue({ metrics: [] }),
    dtrackGetProjects: vi.fn().mockResolvedValue([]),
    dtrackGetVulnerabilities: vi.fn().mockResolvedValue([]),
    dtrackGetFindings: vi.fn().mockResolvedValue([]),
    dtrackGetComponents: vi.fn().mockResolvedValue([]),
    giteaGetRepos: vi.fn().mockResolvedValue([]),
    giteaGetRepo: vi.fn().mockResolvedValue({ name: "test-repo" }),
    giteaGetBranches: vi.fn().mockResolvedValue([]),
    giteaGetCommits: vi.fn().mockResolvedValue([]),
    giteaCreateRepo: vi.fn().mockResolvedValue({ name: "new-repo" }),
    giteaMigrateRepo: vi.fn().mockResolvedValue({ name: "migrated-repo" }),
    droneGetRepos: vi.fn().mockResolvedValue([]),
    droneGetBuilds: vi.fn().mockResolvedValue([]),
    droneGetBuild: vi.fn().mockResolvedValue({ number: 1 }),
    droneGetBuildLogs: vi.fn().mockResolvedValue([]),
    droneTriggerBuild: vi.fn().mockResolvedValue({ number: 2 }),
    registryGetCatalog: vi.fn().mockResolvedValue({ repositories: [] }),
    registryGetTags: vi.fn().mockResolvedValue({ tags: [] }),
    trivyGenerateSbom: vi.fn().mockResolvedValue({ bomFormat: "CycloneDX", components: [] }),
    trivyGenerateSbomImage: vi.fn().mockResolvedValue({ bomFormat: "CycloneDX", components: [] }),
    trivyScanIac: vi.fn().mockResolvedValue({ Results: [] }),
    trivyScanSecrets: vi.fn().mockResolvedValue({ Results: [] }),
    trivyScanLicenses: vi.fn().mockResolvedValue({ Results: [] }),
    trivyScanSecretsImage: vi.fn().mockResolvedValue({ Results: [] }),
    trivyScanLicensesImage: vi.fn().mockResolvedValue({ Results: [] }),
    trivyScanImageFull: vi.fn().mockResolvedValue({
      image: "test:latest",
      timestamp: "2024-01-01T00:00:00.000Z",
      vulnerabilities: { Results: [] },
      secrets: { Results: [] },
      licenses: { Results: [] },
      sbom: { bomFormat: "CycloneDX", components: [] },
    }),
    trivyScanPathFull: vi.fn().mockResolvedValue({
      path: "/test/path",
      timestamp: "2024-01-01T00:00:00.000Z",
      vulnerabilities: { Results: [] },
      secrets: { Results: [] },
      licenses: { Results: [] },
      iac: { Results: [] },
      sbom: { bomFormat: "CycloneDX", components: [] },
    }),
    securityScanAll: vi
      .fn()
      .mockResolvedValue({ trivy: null, sonarqube: null, dependencyTrack: null }),
    checkPlatformStatus: vi.fn().mockResolvedValue({ services: {} }),
    config: {
      gitea: { url: "http://localhost:3000", user: "admin" },
      drone: { url: "http://localhost:8085", token: "test-token" },
      sonarqube: { url: "http://localhost:9000", user: "admin" },
      dependencyTrack: { url: "http://localhost:8081", apiKey: "test-key" },
      trivy: { url: "http://localhost:4954" },
      registry: { url: "http://localhost:5000" },
    },
    // Multi-registry mocks
    detectRegistryType: vi.fn().mockReturnValue({ type: "docker-hub", confidence: 0.9 }),
    configureRegistry: vi.fn(),
    getRegistryConfig: vi.fn().mockReturnValue({
      id: "test-reg",
      name: "Test Registry",
      url: "https://registry.test.com",
      type: "generic",
      enabled: true,
    }),
    listRegistryConfigs: vi.fn().mockReturnValue([
      {
        id: "reg1",
        name: "Registry 1",
        url: "https://r1.test.com",
        type: "generic",
        enabled: true,
      },
    ]),
    removeRegistryConfig: vi.fn().mockReturnValue(true),
    scanMultipleRegistries: vi.fn().mockResolvedValue({
      registries: [],
      totalVulnerabilities: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
    }),
    testRegistryConnection: vi.fn().mockResolvedValue({ success: true, latencyMs: 50 }),
    scanRegistry: vi.fn().mockResolvedValue({
      registry: "localhost:5000",
      discovery: { repositoriesFound: 0, imagesFound: 0, imagesMatched: 0, imagesScanned: 0 },
      vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
      results: [],
      failedImages: [],
      skippedImages: [],
    }),
    // SARIF mocks
    trivyToSarif: vi.fn().mockReturnValue({ $schema: "", version: "2.1.0", runs: [] }),
    sonarToSarif: vi.fn().mockReturnValue({ $schema: "", version: "2.1.0", runs: [] }),
    dtrackToSarif: vi.fn().mockReturnValue({ $schema: "", version: "2.1.0", runs: [] }),
    mergeSarifLogs: vi.fn().mockReturnValue({ $schema: "", version: "2.1.0", runs: [] }),
    getSarifSummary: vi.fn().mockReturnValue({ totalResults: 0, bySeverity: {} }),
    uploadSarifToGitHub: vi.fn().mockResolvedValue({ id: "123", url: "https://github.com/..." }),
    writeSarifFile: vi.fn().mockResolvedValue(undefined),
    // Scheduler mocks
    validateCronExpression: vi.fn().mockReturnValue({ valid: true, parsed: { minute: [0] } }),
    describeCronExpression: vi.fn().mockReturnValue("Every day at midnight"),
    getNextRunTimes: vi.fn().mockReturnValue([new Date()]),
    createSchedule: vi.fn().mockReturnValue({
      id: "sched-123",
      name: "Test Schedule",
      cron: "0 0 * * *",
      targets: [],
      enabled: true,
    }),
    getSchedule: vi.fn().mockReturnValue({
      id: "sched-123",
      name: "Test Schedule",
      cron: "0 0 * * *",
      targets: [],
      enabled: true,
    }),
    listSchedules: vi.fn().mockReturnValue([]),
    updateSchedule: vi.fn().mockReturnValue({
      id: "sched-123",
      name: "Updated Schedule",
      cron: "0 0 * * *",
      targets: [],
      enabled: true,
    }),
    deleteSchedule: vi.fn(),
    triggerSchedule: vi.fn().mockResolvedValue({
      success: true,
      scheduleId: "sched-123",
      scheduleName: "Test Schedule",
      targetsScanned: 0,
      targetsFailed: 0,
      vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
    }),
    getScheduleHistory: vi.fn().mockReturnValue([]),
    startScheduler: vi.fn(),
    stopScheduler: vi.fn(),
    // Remediation mocks
    generateRemediations: vi.fn().mockReturnValue([]),
    getRemediationSummary: vi.fn().mockReturnValue({
      total: 0,
      byConfidence: {},
      byPackageManager: {},
    }),
    formatRemediationAsMarkdown: vi.fn().mockReturnValue("# Remediation Plan"),
    getHighPriorityRemediations: vi.fn().mockReturnValue([]),
    getSafeRemediations: vi.fn().mockReturnValue([]),
    // Compliance mocks
    getComplianceFrameworks: vi.fn().mockReturnValue(["SOC2", "HIPAA", "PCI-DSS", "CIS"]),
    getComplianceControls: vi
      .fn()
      .mockReturnValue([{ id: "CC6.1", name: "Logical Access Security", framework: "SOC2" }]),
    generateComplianceReport: vi.fn().mockReturnValue({
      generatedAt: new Date().toISOString(),
      target: "test-image",
      summary: { totalViolations: 0, byFramework: {}, passingControls: 0, totalControls: 1 },
      frameworks: [],
    }),
    generateComplianceHtml: vi.fn().mockReturnValue("<html>Report</html>"),
    recordComplianceTrend: vi.fn().mockReturnValue({
      timestamp: new Date().toISOString(),
      target: "test",
      violations: 0,
      passingControls: 1,
    }),
    getComplianceTrend: vi.fn().mockReturnValue({ target: "test", entries: [], trend: "stable" }),
    checkComplianceStatus: vi.fn().mockReturnValue({
      passed: true,
      frameworks: [],
      summary: { totalViolations: 0 },
    }),
    getSecurityDashboard: vi.fn().mockResolvedValue({
      summary: { totalFindings: 0, bySeverity: {}, bySource: {} },
      findings: [],
    }),
    // OPA mocks
    listBuiltinPolicies: vi
      .fn()
      .mockReturnValue(["vulnerability-threshold", "license-compliance", "secrets-detection"]),
    getBuiltinPolicyInfo: vi.fn().mockReturnValue({
      name: "vulnerability-threshold",
      description: "Check vulnerability counts",
      defaultThresholds: { critical: 0, high: 5 },
    }),
    getBuiltinPolicy: vi.fn().mockReturnValue("package security\ndefault allow = false"),
    validateRegoSyntax: vi.fn().mockReturnValue({ valid: true }),
    // Vulnerability Database mocks
    initVulnDatabase: vi
      .fn()
      .mockReturnValue({ success: true, path: "/tmp/vuln.db", created: true }),
    isVulnDbInitialized: vi.fn().mockReturnValue(true),
    lookupVulnerability: vi.fn().mockReturnValue({
      id: "CVE-2024-1234",
      severity: "HIGH",
      title: "Test Vulnerability",
    }),
    searchVulnerabilities: vi.fn().mockReturnValue({ vulnerabilities: [], total: 0 }),
    getVulnDbStats: vi.fn().mockReturnValue({
      totalVulnerabilities: 100,
      bySeverity: { HIGH: 50, CRITICAL: 10 },
    }),
    annotateVulnerability: vi.fn().mockReturnValue({ success: true }),
    getTrivyDbStatus: vi
      .fn()
      .mockResolvedValue({ version: "2", updatedAt: new Date().toISOString() }),
    syncVulnDatabase: vi.fn().mockResolvedValue({ success: true, imported: 100 }),
    isOfflineScanAvailable: vi.fn().mockResolvedValue({ available: true }),
    offlineScanImage: vi.fn().mockResolvedValue({ Results: [] }),
    offlineScanPath: vi.fn().mockResolvedValue({ Results: [] }),
    getOfflineScanCapabilities: vi.fn().mockResolvedValue({
      available: true,
      dbAge: "1 day",
      canScanImages: true,
      canScanFilesystems: true,
    }),
  };
});

// =============================================================================
// Utility Function Tests
// =============================================================================

describe("validateSeverity", () => {
  it("should return valid severity levels unchanged", () => {
    expect(validateSeverity("HIGH,CRITICAL")).toBe("HIGH,CRITICAL");
  });

  it("should handle single valid severity", () => {
    expect(validateSeverity("HIGH")).toBe("HIGH");
  });

  it("should handle all valid severity levels", () => {
    expect(validateSeverity("UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")).toBe(
      "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
    );
  });

  it("should filter out invalid severity levels", () => {
    expect(validateSeverity("HIGH,INVALID,CRITICAL")).toBe("HIGH,CRITICAL");
  });

  it("should return default for completely invalid input", () => {
    expect(validateSeverity("INVALID,FAKE")).toBe("HIGH,CRITICAL");
  });

  it("should return default for empty string", () => {
    expect(validateSeverity("")).toBe("HIGH,CRITICAL");
  });

  it("should handle lowercase input by converting to uppercase", () => {
    expect(validateSeverity("high,critical")).toBe("HIGH,CRITICAL");
  });

  it("should handle mixed case input", () => {
    expect(validateSeverity("High,CRITICAL,low")).toBe("HIGH,CRITICAL,LOW");
  });

  it("should trim whitespace around levels", () => {
    expect(validateSeverity(" HIGH , CRITICAL ")).toBe("HIGH,CRITICAL");
  });

  it("should handle extra commas gracefully", () => {
    expect(validateSeverity("HIGH,,CRITICAL")).toBe("HIGH,CRITICAL");
  });
});

describe("sanitizePath", () => {
  it("should allow valid Unix paths", () => {
    expect(sanitizePath("/home/user/project")).toBe("/home/user/project");
  });

  it("should allow valid Windows paths", () => {
    expect(sanitizePath("C:\\Users\\project")).toBe("C:\\Users\\project");
  });

  it("should allow paths with spaces", () => {
    expect(sanitizePath("/home/user/my project")).toBe("/home/user/my project");
  });

  it("should allow paths with dots", () => {
    expect(sanitizePath("/home/user/file.txt")).toBe("/home/user/file.txt");
  });

  it("should allow paths with hyphens and underscores", () => {
    expect(sanitizePath("/home/my-project_v1")).toBe("/home/my-project_v1");
  });

  it("should remove shell metacharacters", () => {
    expect(sanitizePath("/home/user; rm -rf /")).toBe("/home/user rm -rf /");
  });

  it("should remove backticks", () => {
    expect(sanitizePath("/home/`whoami`")).toBe("/home/whoami");
  });

  it("should remove dollar signs", () => {
    expect(sanitizePath("/home/$USER")).toBe("/home/USER");
  });

  it("should remove pipe characters", () => {
    expect(sanitizePath("/home/user | cat /etc/passwd")).toBe("/home/user  cat /etc/passwd");
  });

  it("should prevent path traversal with ../", () => {
    expect(sanitizePath("/home/user/../../../etc/passwd")).toBe("/home/user/etc/passwd");
  });

  it("should prevent Windows path traversal with ..\\", () => {
    expect(sanitizePath("C:\\Users\\..\\..\\Windows")).toBe("C:\\Users\\Windows");
  });

  it("should handle multiple path traversal attempts", () => {
    expect(sanitizePath("../../../../etc/passwd")).toBe("etc/passwd");
  });

  it("should handle empty string", () => {
    expect(sanitizePath("")).toBe("");
  });
});

describe("sanitizeImageName", () => {
  it("should allow simple image names", () => {
    expect(sanitizeImageName("nginx")).toBe("nginx");
  });

  it("should allow image names with tags", () => {
    expect(sanitizeImageName("nginx:latest")).toBe("nginx:latest");
  });

  it("should allow image names with version tags", () => {
    expect(sanitizeImageName("node:20-alpine")).toBe("node:20-alpine");
  });

  it("should allow registry prefixes", () => {
    expect(sanitizeImageName("docker.io/library/nginx")).toBe("docker.io/library/nginx");
  });

  it("should allow localhost registry", () => {
    expect(sanitizeImageName("localhost:5000/myapp:v1")).toBe("localhost:5000/myapp:v1");
  });

  it("should allow digest references", () => {
    expect(sanitizeImageName("nginx@sha256:abc123")).toBe("nginx@sha256:abc123");
  });

  it("should remove shell metacharacters", () => {
    expect(sanitizeImageName("nginx; rm -rf /")).toBe("nginxrm-rf/");
  });

  it("should remove backticks", () => {
    expect(sanitizeImageName("`whoami`/nginx")).toBe("whoami/nginx");
  });

  it("should remove dollar signs", () => {
    expect(sanitizeImageName("$IMAGE_NAME")).toBe("IMAGE_NAME");
  });

  it("should handle empty string", () => {
    expect(sanitizeImageName("")).toBe("");
  });

  it("should allow underscores in image names", () => {
    expect(sanitizeImageName("my_image_name")).toBe("my_image_name");
  });
});

// =============================================================================
// Tool Definitions Tests
// =============================================================================

describe("toolDefinitions", () => {
  it("should contain all expected tools", () => {
    const toolNames = toolDefinitions.map((t) => t.name);
    expect(toolNames).toContain("trivy_scan_path");
    expect(toolNames).toContain("trivy_scan_image");
    expect(toolNames).toContain("trivy_generate_sbom");
    expect(toolNames).toContain("trivy_generate_sbom_image");
    expect(toolNames).toContain("trivy_scan_iac");
    expect(toolNames).toContain("trivy_scan_secrets");
    expect(toolNames).toContain("trivy_scan_secrets_image");
    expect(toolNames).toContain("trivy_scan_licenses");
    expect(toolNames).toContain("trivy_scan_licenses_image");
    expect(toolNames).toContain("trivy_scan_image_full");
    expect(toolNames).toContain("trivy_scan_path_full");
    expect(toolNames).toContain("sonar_list_projects");
    expect(toolNames).toContain("sonar_get_issues");
    expect(toolNames).toContain("sonar_get_security_hotspots");
    expect(toolNames).toContain("sonar_get_metrics");
    expect(toolNames).toContain("dtrack_list_projects");
    expect(toolNames).toContain("dtrack_get_vulnerabilities");
    expect(toolNames).toContain("dtrack_get_findings");
    expect(toolNames).toContain("dtrack_get_components");
    expect(toolNames).toContain("gitea_list_repos");
    expect(toolNames).toContain("gitea_get_repo");
    expect(toolNames).toContain("gitea_get_branches");
    expect(toolNames).toContain("gitea_get_commits");
    expect(toolNames).toContain("gitea_create_repo");
    expect(toolNames).toContain("gitea_migrate_repo");
    expect(toolNames).toContain("drone_list_repos");
    expect(toolNames).toContain("drone_get_builds");
    expect(toolNames).toContain("drone_get_build");
    expect(toolNames).toContain("drone_get_build_logs");
    expect(toolNames).toContain("drone_trigger_build");
    expect(toolNames).toContain("registry_list_images");
    expect(toolNames).toContain("registry_get_tags");
    expect(toolNames).toContain("security_scan_all");
  });

  it("should have 381 tools total", () => {
    expect(toolDefinitions.length).toBe(381);
  });

  it("should have valid inputSchema for each tool", () => {
    for (const tool of toolDefinitions) {
      expect(tool.inputSchema).toBeDefined();
      expect(tool.inputSchema.type).toBe("object");
      expect(tool.inputSchema.properties).toBeDefined();
    }
  });

  it("should have descriptions for all tools", () => {
    for (const tool of toolDefinitions) {
      expect(tool.description).toBeDefined();
      expect(tool.description.length).toBeGreaterThan(10);
    }
  });
});

// =============================================================================
// Resource Definitions Tests
// =============================================================================

describe("resourceDefinitions", () => {
  it("should contain status and config resources", () => {
    const uris = resourceDefinitions.map((r) => r.uri);
    expect(uris).toContain("cicd://status");
    expect(uris).toContain("cicd://config");
  });

  it("should have 2 resources total", () => {
    expect(resourceDefinitions.length).toBe(2);
  });

  it("should have valid mimeType for each resource", () => {
    for (const resource of resourceDefinitions) {
      expect(resource.mimeType).toBe("application/json");
    }
  });
});

// =============================================================================
// Handler Function Tests
// =============================================================================

describe("handleListTools", () => {
  it("should return tools array", () => {
    const result = handleListTools();
    expect(result).toHaveProperty("tools");
    expect(Array.isArray(result.tools)).toBe(true);
    expect(result.tools.length).toBe(381);
  });

  it("should return the same tools as toolDefinitions", () => {
    const result = handleListTools();
    expect(result.tools).toEqual(toolDefinitions);
  });
});

describe("handleListResources", () => {
  it("should return resources array", () => {
    const result = handleListResources();
    expect(result).toHaveProperty("resources");
    expect(Array.isArray(result.resources)).toBe(true);
    expect(result.resources.length).toBe(2);
  });

  it("should return the same resources as resourceDefinitions", () => {
    const result = handleListResources();
    expect(result.resources).toEqual(resourceDefinitions);
  });
});

describe("handleCallTool", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("Trivy tools", () => {
    it("should handle trivy_scan_path", async () => {
      const result = await handleCallTool("trivy_scan_path", { path: "/app", severity: "HIGH" });
      expect(result.content).toBeDefined();
      expect(result.content[0].type).toBe("text");
      expect(result.isError).toBeUndefined();
    });

    it("should handle trivy_scan_image", async () => {
      const result = await handleCallTool("trivy_scan_image", { image: "nginx:latest" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle trivy_scan_image_full with default sbomFormat", async () => {
      const result = await handleCallTool("trivy_scan_image_full", { image: "nginx:latest" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle trivy_scan_image_full with cyclonedx sbomFormat", async () => {
      const result = await handleCallTool("trivy_scan_image_full", {
        image: "nginx:latest",
        sbomFormat: "cyclonedx",
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle trivy_scan_image_full with spdx-json sbomFormat", async () => {
      const result = await handleCallTool("trivy_scan_image_full", {
        image: "nginx:latest",
        sbomFormat: "spdx-json",
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle trivy_scan_path_full with default sbomFormat", async () => {
      const result = await handleCallTool("trivy_scan_path_full", { path: "/app" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle trivy_scan_path_full with cyclonedx sbomFormat", async () => {
      const result = await handleCallTool("trivy_scan_path_full", {
        path: "/app",
        sbomFormat: "cyclonedx",
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle trivy_scan_path_full with spdx-json sbomFormat", async () => {
      const result = await handleCallTool("trivy_scan_path_full", {
        path: "/app",
        sbomFormat: "spdx-json",
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle trivy_generate_sbom", async () => {
      const result = await handleCallTool("trivy_generate_sbom", { path: "/app" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle trivy_generate_sbom_image", async () => {
      const result = await handleCallTool("trivy_generate_sbom_image", { image: "nginx:latest" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle trivy_scan_iac", async () => {
      const result = await handleCallTool("trivy_scan_iac", { path: "/app" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle trivy_scan_secrets", async () => {
      const result = await handleCallTool("trivy_scan_secrets", { path: "/app" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle trivy_scan_secrets_image", async () => {
      const result = await handleCallTool("trivy_scan_secrets_image", { image: "nginx:latest" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle trivy_scan_licenses", async () => {
      const result = await handleCallTool("trivy_scan_licenses", { path: "/app" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle trivy_scan_licenses_image", async () => {
      const result = await handleCallTool("trivy_scan_licenses_image", { image: "nginx:latest" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });
  });

  describe("SonarQube tools", () => {
    it("should handle sonar_list_projects", async () => {
      const result = await handleCallTool("sonar_list_projects", {});
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle sonar_get_issues", async () => {
      const result = await handleCallTool("sonar_get_issues", { projectKey: "my-project" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle sonar_get_issues with types", async () => {
      const result = await handleCallTool("sonar_get_issues", {
        projectKey: "my-project",
        types: "BUG",
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle sonar_get_security_hotspots", async () => {
      const result = await handleCallTool("sonar_get_security_hotspots", {
        projectKey: "my-project",
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle sonar_get_metrics", async () => {
      const result = await handleCallTool("sonar_get_metrics", { projectKey: "my-project" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });
  });

  describe("Dependency-Track tools", () => {
    it("should handle dtrack_list_projects", async () => {
      const result = await handleCallTool("dtrack_list_projects", {});
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle dtrack_get_vulnerabilities", async () => {
      const result = await handleCallTool("dtrack_get_vulnerabilities", {
        projectUuid: "uuid-123",
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle dtrack_get_findings", async () => {
      const result = await handleCallTool("dtrack_get_findings", { projectUuid: "uuid-123" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle dtrack_get_components", async () => {
      const result = await handleCallTool("dtrack_get_components", { projectUuid: "uuid-123" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });
  });

  describe("Gitea tools", () => {
    it("should handle gitea_list_repos", async () => {
      const result = await handleCallTool("gitea_list_repos", {});
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle gitea_get_repo", async () => {
      const result = await handleCallTool("gitea_get_repo", { owner: "admin", repo: "test" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle gitea_get_branches", async () => {
      const result = await handleCallTool("gitea_get_branches", { owner: "admin", repo: "test" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle gitea_get_commits", async () => {
      const result = await handleCallTool("gitea_get_commits", { owner: "admin", repo: "test" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle gitea_get_commits with limit", async () => {
      const result = await handleCallTool("gitea_get_commits", {
        owner: "admin",
        repo: "test",
        limit: 5,
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle gitea_create_repo", async () => {
      const result = await handleCallTool("gitea_create_repo", { name: "new-repo" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle gitea_create_repo with all options", async () => {
      const result = await handleCallTool("gitea_create_repo", {
        name: "new-repo",
        description: "A test repo",
        private: true,
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle gitea_migrate_repo", async () => {
      const result = await handleCallTool("gitea_migrate_repo", {
        cloneUrl: "https://github.com/user/repo.git",
        repoName: "migrated",
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle gitea_migrate_repo with auth token", async () => {
      const result = await handleCallTool("gitea_migrate_repo", {
        cloneUrl: "https://github.com/user/repo.git",
        repoName: "migrated",
        authToken: "ghp_token",
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });
  });

  describe("Drone tools", () => {
    it("should handle drone_list_repos", async () => {
      const result = await handleCallTool("drone_list_repos", {});
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle drone_get_builds", async () => {
      const result = await handleCallTool("drone_get_builds", { owner: "admin", repo: "test" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle drone_get_build", async () => {
      const result = await handleCallTool("drone_get_build", {
        owner: "admin",
        repo: "test",
        build: 1,
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle drone_get_build_logs", async () => {
      const result = await handleCallTool("drone_get_build_logs", {
        owner: "admin",
        repo: "test",
        build: 1,
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle drone_get_build_logs with stage and step", async () => {
      const result = await handleCallTool("drone_get_build_logs", {
        owner: "admin",
        repo: "test",
        build: 1,
        stage: 2,
        step: 3,
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle drone_trigger_build", async () => {
      const result = await handleCallTool("drone_trigger_build", { owner: "admin", repo: "test" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle drone_trigger_build with branch", async () => {
      const result = await handleCallTool("drone_trigger_build", {
        owner: "admin",
        repo: "test",
        branch: "develop",
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });
  });

  describe("Registry tools", () => {
    it("should handle registry_list_images", async () => {
      const result = await handleCallTool("registry_list_images", {});
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle registry_get_tags", async () => {
      const result = await handleCallTool("registry_get_tags", { image: "myapp" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });
  });

  describe("Combined tools", () => {
    it("should handle security_scan_all", async () => {
      const result = await handleCallTool("security_scan_all", { path: "/app" });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should handle security_scan_all with all options", async () => {
      const result = await handleCallTool("security_scan_all", {
        path: "/app",
        sonarProjectKey: "my-project",
        dtrackProjectUuid: "uuid-123",
      });
      expect(result.content).toBeDefined();
      expect(result.isError).toBeUndefined();
    });
  });

  describe("Error handling", () => {
    it("should return error for unknown tool", async () => {
      const result = await handleCallTool("unknown_tool", {});
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Unknown tool");
    });

    it("should handle errors from handlers gracefully", async () => {
      const { trivyScanPath } = await import("./handlers.js");
      vi.mocked(trivyScanPath).mockRejectedValueOnce(new Error("Scan failed"));

      const result = await handleCallTool("trivy_scan_path", { path: "/app" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Scan failed");
    });
  });
});

describe("handleReadResource", () => {
  it("should return status resource", async () => {
    const result = await handleReadResource("cicd://status");
    expect(result.contents).toBeDefined();
    expect(result.contents[0].uri).toBe("cicd://status");
    expect(result.contents[0].mimeType).toBe("application/json");
  });

  it("should return config resource", async () => {
    const result = await handleReadResource("cicd://config");
    expect(result.contents).toBeDefined();
    expect(result.contents[0].uri).toBe("cicd://config");
    expect(result.contents[0].mimeType).toBe("application/json");

    const config = JSON.parse(result.contents[0].text);
    expect(config).toHaveProperty("gitea");
    expect(config).toHaveProperty("drone");
    expect(config).toHaveProperty("sonarqube");
    expect(config).toHaveProperty("dependencyTrack");
    expect(config).toHaveProperty("trivy");
    expect(config).toHaveProperty("registry");
  });

  it("should mask sensitive config values", async () => {
    const result = await handleReadResource("cicd://config");
    const config = JSON.parse(result.contents[0].text);

    // Should have hasToken/hasApiKey instead of actual values
    expect(config.drone).toHaveProperty("hasToken");
    expect(config.dependencyTrack).toHaveProperty("hasApiKey");
    expect(config.drone).not.toHaveProperty("token");
    expect(config.dependencyTrack).not.toHaveProperty("apiKey");
  });

  it("should throw error for unknown resource", async () => {
    await expect(handleReadResource("cicd://unknown")).rejects.toThrow("Unknown resource");
  });
});

// =============================================================================
// Multi-Registry Tools Tests
// =============================================================================

describe("handleCallTool - Multi-Registry tools", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should handle registry_detect_type", async () => {
    const result = await handleCallTool("registry_detect_type", { url: "https://docker.io" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should return error for registry_detect_type without url", async () => {
    const result = await handleCallTool("registry_detect_type", {});
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("url is required");
  });

  it("should handle registry_configure", async () => {
    const result = await handleCallTool("registry_configure", {
      id: "my-reg",
      name: "My Registry",
      url: "https://my-registry.com",
    });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data.success).toBe(true);
  });

  it("should return error for registry_configure without required fields", async () => {
    const result = await handleCallTool("registry_configure", { id: "my-reg" });
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("required");
  });

  it("should handle registry_list_configs", async () => {
    const result = await handleCallTool("registry_list_configs", {});
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data).toHaveProperty("registries");
    expect(data).toHaveProperty("count");
  });

  it("should handle registry_get_config", async () => {
    const result = await handleCallTool("registry_get_config", { id: "test-reg" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should return error for registry_get_config without id", async () => {
    const result = await handleCallTool("registry_get_config", {});
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("id is required");
  });

  it("should handle registry_get_config not found", async () => {
    const { getRegistryConfig } = await import("./handlers.js");
    vi.mocked(getRegistryConfig).mockReturnValueOnce(undefined);
    const result = await handleCallTool("registry_get_config", { id: "nonexistent" });
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("not found");
  });

  it("should handle registry_remove_config", async () => {
    const result = await handleCallTool("registry_remove_config", { id: "test-reg" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data.success).toBe(true);
  });

  it("should handle registry_test_connection", async () => {
    const result = await handleCallTool("registry_test_connection", { id: "test-reg" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle registry_scan_multiple", async () => {
    const result = await handleCallTool("registry_scan_multiple", {
      registries: ["reg1", "reg2"],
    });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should return error for registry_scan_multiple without registries", async () => {
    const result = await handleCallTool("registry_scan_multiple", {});
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("registries");
  });

  it("should handle registry_scan", async () => {
    const result = await handleCallTool("registry_scan", {});
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });
});

// =============================================================================
// SARIF Tools Tests
// =============================================================================

describe("handleCallTool - SARIF tools", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should handle sarif_generate with image", async () => {
    const result = await handleCallTool("sarif_generate", { image: "nginx:latest" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle sarif_generate with path", async () => {
    const result = await handleCallTool("sarif_generate", { path: "/app" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle sarif_generate with sonarProject", async () => {
    const result = await handleCallTool("sarif_generate", { sonarProject: "my-project" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle sarif_generate with dtrackProjectUuid", async () => {
    const result = await handleCallTool("sarif_generate", { dtrackProjectUuid: "uuid-123" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle sarif_generate with outputFile", async () => {
    const result = await handleCallTool("sarif_generate", {
      image: "nginx:latest",
      outputFile: "/tmp/output.sarif",
    });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data.success).toBe(true);
  });

  it("should handle sarif_upload_github", async () => {
    const result = await handleCallTool("sarif_upload_github", {
      image: "nginx:latest",
      owner: "test-owner",
      repo: "test-repo",
      commitSha: "abc123",
      ref: "refs/heads/main",
      token: "ghp_token",
    });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data.success).toBe(true);
  });

  it("should return error for sarif_upload_github without sources", async () => {
    const result = await handleCallTool("sarif_upload_github", {
      owner: "test-owner",
      repo: "test-repo",
      commitSha: "abc123",
      ref: "refs/heads/main",
      token: "ghp_token",
    });
    expect(result.isError).toBe(true);
  });
});

// =============================================================================
// Scheduler Tools Tests
// =============================================================================

describe("handleCallTool - Scheduler tools", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should handle schedule_create", async () => {
    const result = await handleCallTool("schedule_create", {
      name: "Daily Scan",
      cron: "0 0 * * *",
      targets: [{ type: "image", value: "nginx:latest" }],
    });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data.success).toBe(true);
    expect(data.schedule).toBeDefined();
  });

  it("should handle schedule_list", async () => {
    const result = await handleCallTool("schedule_list", {});
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data).toHaveProperty("schedules");
    expect(data).toHaveProperty("count");
  });

  it("should handle schedule_get", async () => {
    const result = await handleCallTool("schedule_get", { id: "sched-123" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle schedule_get not found", async () => {
    const { getSchedule } = await import("./handlers.js");
    vi.mocked(getSchedule).mockReturnValueOnce(undefined);
    const result = await handleCallTool("schedule_get", { id: "nonexistent" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it("should handle schedule_update", async () => {
    const result = await handleCallTool("schedule_update", {
      id: "sched-123",
      name: "Updated Schedule",
    });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data.success).toBe(true);
  });

  it("should handle schedule_delete", async () => {
    const result = await handleCallTool("schedule_delete", { id: "sched-123" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data.success).toBe(true);
  });

  it("should handle schedule_delete not found", async () => {
    const { getSchedule } = await import("./handlers.js");
    vi.mocked(getSchedule).mockReturnValueOnce(undefined);
    const result = await handleCallTool("schedule_delete", { id: "nonexistent" });
    expect(result.isError).toBe(true);
  });

  it("should handle schedule_trigger", async () => {
    const result = await handleCallTool("schedule_trigger", { id: "sched-123" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data.success).toBe(true);
  });

  it("should handle schedule_history", async () => {
    const result = await handleCallTool("schedule_history", { id: "sched-123" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data).toHaveProperty("history");
  });

  it("should handle cron_validate valid expression", async () => {
    const result = await handleCallTool("cron_validate", { expression: "0 0 * * *" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data.valid).toBe(true);
  });

  it("should handle cron_validate invalid expression", async () => {
    const { validateCronExpression } = await import("./handlers.js");
    vi.mocked(validateCronExpression).mockReturnValueOnce({ valid: false, error: "Invalid" });
    const result = await handleCallTool("cron_validate", { expression: "invalid" });
    expect(result.content).toBeDefined();
    const data = JSON.parse(result.content[0].text);
    expect(data.valid).toBe(false);
  });

  it("should handle scheduler_control start", async () => {
    const result = await handleCallTool("scheduler_control", { action: "start" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data.status).toBe("running");
  });

  it("should handle scheduler_control stop", async () => {
    const result = await handleCallTool("scheduler_control", { action: "stop" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data.status).toBe("stopped");
  });

  it("should handle scheduler_control status", async () => {
    const result = await handleCallTool("scheduler_control", { action: "status" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data).toHaveProperty("status");
  });

  it("should handle scheduler_control unknown action", async () => {
    const result = await handleCallTool("scheduler_control", { action: "unknown" });
    expect(result.isError).toBe(true);
  });
});

// =============================================================================
// Remediation Tools Tests
// =============================================================================

describe("handleCallTool - Remediation tools", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should handle generate_remediations with image", async () => {
    const result = await handleCallTool("generate_remediations", { image: "nginx:latest" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle generate_remediations with path", async () => {
    const result = await handleCallTool("generate_remediations", { path: "/app" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should return error for generate_remediations without source", async () => {
    const result = await handleCallTool("generate_remediations", {});
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("image or path is required");
  });

  it("should handle get_remediation_summary with image", async () => {
    const result = await handleCallTool("get_remediation_summary", { image: "nginx:latest" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle get_remediation_markdown with image", async () => {
    const result = await handleCallTool("get_remediation_markdown", { image: "nginx:latest" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle get_high_priority_fixes with image", async () => {
    const result = await handleCallTool("get_high_priority_fixes", { image: "nginx:latest" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle get_safe_fixes with image", async () => {
    const result = await handleCallTool("get_safe_fixes", { image: "nginx:latest" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });
});

// =============================================================================
// Compliance Tools Tests
// =============================================================================

describe("handleCallTool - Compliance tools", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should handle compliance_get_frameworks", async () => {
    const result = await handleCallTool("compliance_get_frameworks", {});
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data).toHaveProperty("frameworks");
  });

  it("should handle compliance_get_controls", async () => {
    const result = await handleCallTool("compliance_get_controls", { framework: "SOC2" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data).toHaveProperty("controls");
  });

  it("should return error for compliance_get_controls without framework", async () => {
    const result = await handleCallTool("compliance_get_controls", {});
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("framework is required");
  });

  it("should handle compliance_check_status", async () => {
    const result = await handleCallTool("compliance_check_status", { image: "nginx:latest" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle compliance_generate_report JSON format", async () => {
    const result = await handleCallTool("compliance_generate_report", { image: "nginx:latest" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle compliance_generate_report HTML format", async () => {
    const result = await handleCallTool("compliance_generate_report", {
      image: "nginx:latest",
      format: "html",
    });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data.format).toBe("html");
    expect(data).toHaveProperty("html");
  });

  it("should handle compliance_trend_record", async () => {
    const result = await handleCallTool("compliance_trend_record", {
      target: "my-app",
      image: "nginx:latest",
    });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data.success).toBe(true);
  });

  it("should return error for compliance_trend_record without target", async () => {
    const result = await handleCallTool("compliance_trend_record", { image: "nginx:latest" });
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("target is required");
  });

  it("should handle compliance_trend_get", async () => {
    const result = await handleCallTool("compliance_trend_get", { target: "my-app" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should return error for compliance_trend_get without target", async () => {
    const result = await handleCallTool("compliance_trend_get", {});
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("target is required");
  });

  it("should handle compliance_trend_list_targets", async () => {
    const result = await handleCallTool("compliance_trend_list_targets", {});
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });
});

// =============================================================================
// OPA/Rego Tools Tests
// =============================================================================

describe("handleCallTool - OPA tools", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should handle opa_list_policies", async () => {
    const result = await handleCallTool("opa_list_policies", {});
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data).toHaveProperty("policies");
    expect(data).toHaveProperty("count");
  });

  it("should handle opa_get_policy_info", async () => {
    const result = await handleCallTool("opa_get_policy_info", { name: "vulnerability-threshold" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should return error for opa_get_policy_info without name", async () => {
    const result = await handleCallTool("opa_get_policy_info", {});
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("name is required");
  });

  it("should handle opa_get_policy_info not found", async () => {
    const { getBuiltinPolicyInfo } = await import("./handlers.js");
    vi.mocked(getBuiltinPolicyInfo).mockReturnValueOnce(undefined);
    const result = await handleCallTool("opa_get_policy_info", { name: "nonexistent" });
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("not found");
  });

  it("should handle opa_validate_policy", async () => {
    const result = await handleCallTool("opa_validate_policy", {
      policy: "package test\ndefault allow = false",
    });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should return error for opa_validate_policy without policy", async () => {
    const result = await handleCallTool("opa_validate_policy", {});
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("policy is required");
  });

  it("should handle opa_evaluate_policy", async () => {
    const result = await handleCallTool("opa_evaluate_policy", {
      policy: "vulnerability-threshold",
      image: "nginx:latest",
    });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should return error for opa_evaluate_policy without policy", async () => {
    const result = await handleCallTool("opa_evaluate_policy", { image: "nginx:latest" });
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("policy is required");
  });
});

// =============================================================================
// Vulnerability Database Tools Tests
// =============================================================================

describe("handleCallTool - Vulnerability Database tools", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should handle vuln_db_sync", async () => {
    const result = await handleCallTool("vuln_db_sync", {});
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle vuln_db_sync with options", async () => {
    const result = await handleCallTool("vuln_db_sync", { force: true, skipIfRecent: 24 });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle vuln_db_sync when db not initialized", async () => {
    const { isVulnDbInitialized, initVulnDatabase } = await import("./handlers.js");
    vi.mocked(isVulnDbInitialized).mockReturnValueOnce(false);
    vi.mocked(initVulnDatabase).mockReturnValueOnce({
      success: true,
      path: "/tmp/test.db",
      created: true,
    });
    const result = await handleCallTool("vuln_db_sync", {});
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle vuln_db_sync when init fails", async () => {
    const { isVulnDbInitialized, initVulnDatabase } = await import("./handlers.js");
    vi.mocked(isVulnDbInitialized).mockReturnValueOnce(false);
    vi.mocked(initVulnDatabase).mockReturnValueOnce({
      success: false,
      path: "",
      created: false,
      error: "Init failed",
    });
    const result = await handleCallTool("vuln_db_sync", {});
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("Failed to initialize");
  });

  it("should handle vuln_db_status", async () => {
    const result = await handleCallTool("vuln_db_status", {});
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data).toHaveProperty("trivyDatabase");
    expect(data).toHaveProperty("offlineScanAvailable");
  });

  it("should handle vuln_db_lookup", async () => {
    const result = await handleCallTool("vuln_db_lookup", { id: "CVE-2024-1234" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should return error for vuln_db_lookup without id", async () => {
    const result = await handleCallTool("vuln_db_lookup", {});
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("id is required");
  });

  it("should handle vuln_db_lookup not found", async () => {
    const { lookupVulnerability } = await import("./handlers.js");
    vi.mocked(lookupVulnerability).mockReturnValueOnce(null);
    const result = await handleCallTool("vuln_db_lookup", { id: "CVE-9999-9999" });
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("not found");
  });

  it("should handle vuln_db_search", async () => {
    const result = await handleCallTool("vuln_db_search", { packageName: "lodash" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle vuln_db_search with all options", async () => {
    const result = await handleCallTool("vuln_db_search", {
      packageName: "lodash",
      ecosystem: "npm",
      severity: ["HIGH", "CRITICAL"],
      limit: 10,
    });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle trivy_scan_offline with image", async () => {
    const result = await handleCallTool("trivy_scan_offline", { image: "nginx:latest" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle trivy_scan_offline with path", async () => {
    const result = await handleCallTool("trivy_scan_offline", { path: "/app" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should return error for trivy_scan_offline without source", async () => {
    const result = await handleCallTool("trivy_scan_offline", {});
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("image or path is required");
  });

  it("should handle vuln_db_annotate", async () => {
    const result = await handleCallTool("vuln_db_annotate", {
      vulnId: "CVE-2024-1234",
      status: "acknowledged",
      notes: "Reviewed by security team",
    });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should return error for vuln_db_annotate without vulnId", async () => {
    const result = await handleCallTool("vuln_db_annotate", { status: "acknowledged" });
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("vulnId is required");
  });

  it("should return error for vuln_db_annotate without status", async () => {
    const result = await handleCallTool("vuln_db_annotate", { vulnId: "CVE-2024-1234" });
    const data = JSON.parse(result.content[0].text);
    expect(data.error).toContain("status is required");
  });
});

// =============================================================================
// Additional Other Tools Tests
// =============================================================================

describe("handleCallTool - Additional tools", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should handle get_security_dashboard", async () => {
    const result = await handleCallTool("get_security_dashboard", { image: "nginx:latest" });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });

  it("should handle get_security_dashboard with all options", async () => {
    const result = await handleCallTool("get_security_dashboard", {
      image: "nginx:latest",
      sonarProject: "my-project",
      dtrackProjectUuid: "uuid-123",
    });
    expect(result.content).toBeDefined();
    expect(result.isError).toBeUndefined();
  });
});
