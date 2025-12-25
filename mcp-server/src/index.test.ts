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

  it("should have 26 tools total", () => {
    expect(toolDefinitions.length).toBe(26);
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
    expect(result.tools.length).toBe(26);
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
