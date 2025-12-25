import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { ExecOptions, ExecException, ChildProcess } from "node:child_process";
import { exec } from "node:child_process";

/** Exec callback type */
type ExecCallback = (
  error: ExecException | null,
  result: { stdout: string; stderr: string } | null
) => void;

// Import functions to test
import { validateSeverity, sanitizePath, sanitizeImageName } from "./validation.js";

import { fetchJson, basicAuth } from "./http.js";

import { config } from "./config.js";

import {
  trivyScanPath,
  trivyScanImage,
  trivyGenerateSbom,
  trivyGenerateSbomImage,
  trivyScanIac,
  trivyScanSecrets,
  trivyScanLicenses,
  trivyScanLicensesImage,
  sonarGetProjects,
  sonarGetIssues,
  sonarGetSecurityHotspots,
  sonarGetMetrics,
  dtrackGetProjects,
  dtrackGetVulnerabilities,
  dtrackGetFindings,
  dtrackGetComponents,
  giteaGetRepos,
  giteaGetRepo,
  giteaGetBranches,
  giteaGetCommits,
  giteaCreateRepo,
  giteaMigrateRepo,
  droneGetRepos,
  droneGetBuilds,
  droneGetBuild,
  droneGetBuildLogs,
  droneTriggerBuild,
  registryGetCatalog,
  registryGetTags,
  securityScanAll,
  checkPlatformStatus,
} from "./handlers.js";

// Mock child_process
vi.mock("node:child_process", () => ({
  exec: vi.fn(),
}));

// =============================================================================
// Validation Tests
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
    expect(validateSeverity("INVALID,WRONG")).toBe("HIGH,CRITICAL");
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
    expect(sanitizePath("C:\\Users\\user\\project")).toBe("C:\\Users\\user\\project");
  });

  it("should allow paths with spaces", () => {
    expect(sanitizePath("/home/user/my project")).toBe("/home/user/my project");
  });

  it("should allow paths with dots", () => {
    expect(sanitizePath("/home/user/project.name")).toBe("/home/user/project.name");
  });

  it("should allow paths with hyphens and underscores", () => {
    expect(sanitizePath("/home/user/my-project_name")).toBe("/home/user/my-project_name");
  });

  it("should remove shell metacharacters", () => {
    expect(sanitizePath("/home/user/$(whoami)")).toBe("/home/user/whoami");
  });

  it("should remove backticks", () => {
    expect(sanitizePath("/home/user/`id`")).toBe("/home/user/id");
  });

  it("should remove dollar signs", () => {
    expect(sanitizePath("/home/user/$HOME")).toBe("/home/user/HOME");
  });

  it("should remove pipe characters", () => {
    expect(sanitizePath("/home/user/file|rm")).toBe("/home/user/filerm");
  });

  it("should prevent path traversal with ../", () => {
    expect(sanitizePath("/home/user/../../../etc/passwd")).toBe("/home/user/etc/passwd");
  });

  it("should prevent Windows path traversal with ..\\", () => {
    expect(sanitizePath("C:\\Users\\..\\..\\Windows")).toBe("C:\\Users\\Windows");
  });

  it("should handle multiple path traversal attempts", () => {
    expect(sanitizePath("../../../etc/passwd")).toBe("etc/passwd");
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
    expect(sanitizeImageName("nginx:1.21.0")).toBe("nginx:1.21.0");
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
    expect(sanitizeImageName("nginx$(whoami)")).toBe("nginxwhoami");
  });

  it("should remove backticks", () => {
    expect(sanitizeImageName("nginx`id`")).toBe("nginxid");
  });

  it("should remove dollar signs", () => {
    expect(sanitizeImageName("nginx$TAG")).toBe("nginxTAG");
  });

  it("should handle empty string", () => {
    expect(sanitizeImageName("")).toBe("");
  });

  it("should allow underscores in image names", () => {
    expect(sanitizeImageName("my_app:latest")).toBe("my_app:latest");
  });
});

// =============================================================================
// HTTP Helper Tests
// =============================================================================
describe("basicAuth", () => {
  it("should encode credentials correctly", () => {
    expect(basicAuth("admin", "password")).toBe("Basic YWRtaW46cGFzc3dvcmQ=");
  });

  it("should handle empty credentials", () => {
    expect(basicAuth("", "")).toBe("Basic Og==");
  });

  it("should handle special characters in password", () => {
    const result = basicAuth("user", "p@ss:word!");
    expect(result.startsWith("Basic ")).toBe(true);
    // Decode and verify
    const decoded = Buffer.from(result.replace("Basic ", ""), "base64").toString();
    expect(decoded).toBe("user:p@ss:word!");
  });
});

describe("fetchJson", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("should return JSON for successful response", async () => {
    const mockData = { key: "value" };
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockData),
    });

    const result = await fetchJson("http://example.com/api");
    expect(result).toEqual(mockData);
  });

  it("should throw error for non-OK response", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: "Not Found",
    });

    await expect(fetchJson("http://example.com/api")).rejects.toThrow("HTTP 404: Not Found");
  });

  it("should pass options to fetch", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({}),
    });

    await fetchJson("http://example.com/api", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });

    expect(global.fetch).toHaveBeenCalledWith(
      "http://example.com/api",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
      })
    );
  });
});

// =============================================================================
// Config Tests
// =============================================================================
describe("config", () => {
  it("should have gitea configuration", () => {
    expect(config.gitea).toBeDefined();
    expect(config.gitea.url).toBeDefined();
    expect(config.gitea.user).toBeDefined();
    expect(config.gitea.password).toBeDefined();
  });

  it("should have drone configuration", () => {
    expect(config.drone).toBeDefined();
    expect(config.drone.url).toBeDefined();
  });

  it("should have sonarqube configuration", () => {
    expect(config.sonarqube).toBeDefined();
    expect(config.sonarqube.url).toBeDefined();
  });

  it("should have dependencyTrack configuration", () => {
    expect(config.dependencyTrack).toBeDefined();
    expect(config.dependencyTrack.url).toBeDefined();
  });

  it("should have registry configuration", () => {
    expect(config.registry).toBeDefined();
    expect(config.registry.url).toBeDefined();
  });
});

// =============================================================================
// Handler Tests - SonarQube
// =============================================================================
describe("SonarQube Handlers", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe("sonarGetProjects", () => {
    it("should return projects from SonarQube API", async () => {
      const mockProjects = { components: [{ key: "project1" }] };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockProjects),
      });

      const result = await sonarGetProjects();
      expect(result).toEqual(mockProjects);
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining("/api/projects/search"),
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: expect.stringMatching(/^Basic /),
          }),
        })
      );
    });
  });

  describe("sonarGetIssues", () => {
    it("should return issues for a project", async () => {
      const mockIssues = { issues: [{ key: "issue1" }] };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockIssues),
      });

      const result = await sonarGetIssues("my-project");
      expect(result).toEqual(mockIssues);
    });

    it("should include types filter when provided", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({}),
      });

      await sonarGetIssues("my-project", "BUG,VULNERABILITY");
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining("types=BUG,VULNERABILITY"),
        expect.any(Object)
      );
    });
  });

  describe("sonarGetSecurityHotspots", () => {
    it("should return security hotspots", async () => {
      const mockHotspots = { hotspots: [] };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockHotspots),
      });

      const result = await sonarGetSecurityHotspots("my-project");
      expect(result).toEqual(mockHotspots);
    });
  });

  describe("sonarGetMetrics", () => {
    it("should return metrics for a project", async () => {
      const mockMetrics = { component: { measures: [] } };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockMetrics),
      });

      const result = await sonarGetMetrics("my-project");
      expect(result).toEqual(mockMetrics);
    });
  });
});

// =============================================================================
// Handler Tests - Gitea
// =============================================================================
describe("Gitea Handlers", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe("giteaGetRepos", () => {
    it("should return repositories", async () => {
      const mockRepos = [{ name: "repo1" }];
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockRepos),
      });

      const result = await giteaGetRepos();
      expect(result).toEqual(mockRepos);
    });
  });

  describe("giteaGetRepo", () => {
    it("should return repository details", async () => {
      const mockRepo = { name: "repo1", owner: { login: "owner" } };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockRepo),
      });

      const result = await giteaGetRepo("owner", "repo1");
      expect(result).toEqual(mockRepo);
    });
  });

  describe("giteaGetBranches", () => {
    it("should return branches", async () => {
      const mockBranches = [{ name: "main" }];
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockBranches),
      });

      const result = await giteaGetBranches("owner", "repo");
      expect(result).toEqual(mockBranches);
    });
  });

  describe("giteaGetCommits", () => {
    it("should return commits with default limit", async () => {
      const mockCommits = [{ sha: "abc123" }];
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockCommits),
      });

      const result = await giteaGetCommits("owner", "repo");
      expect(result).toEqual(mockCommits);
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining("limit=10"),
        expect.any(Object)
      );
    });

    it("should use custom limit when provided", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve([]),
      });

      await giteaGetCommits("owner", "repo", 25);
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining("limit=25"),
        expect.any(Object)
      );
    });
  });

  describe("giteaCreateRepo", () => {
    it("should create a repository", async () => {
      const mockRepo = { name: "new-repo" };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockRepo),
      });

      const result = await giteaCreateRepo("new-repo");
      expect(result).toEqual(mockRepo);
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          method: "POST",
          body: expect.stringContaining("new-repo"),
        })
      );
    });
  });

  describe("giteaMigrateRepo", () => {
    it("should migrate a repository", async () => {
      const mockRepo = { name: "migrated-repo" };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockRepo),
      });

      const result = await giteaMigrateRepo("https://github.com/user/repo.git", "migrated-repo");
      expect(result).toEqual(mockRepo);
    });

    it("should include auth token when provided", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({}),
      });

      await giteaMigrateRepo("https://github.com/user/repo.git", "repo", "token123");
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: expect.stringContaining("auth_token"),
        })
      );
    });
  });
});

// =============================================================================
// Handler Tests - Drone CI
// =============================================================================
describe("Drone Handlers", () => {
  const originalToken = config.drone.token;

  beforeEach(() => {
    vi.resetAllMocks();
  });

  afterEach(() => {
    config.drone.token = originalToken;
  });

  describe("droneGetRepos", () => {
    it("should return repositories without token", async () => {
      config.drone.token = "";
      const mockRepos = [{ name: "repo1" }];
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockRepos),
      });

      const result = await droneGetRepos();
      expect(result).toEqual(mockRepos);
    });

    it("should include auth header when token is set", async () => {
      config.drone.token = "test-token";
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve([]),
      });

      await droneGetRepos();
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: "Bearer test-token",
          }),
        })
      );
    });
  });

  describe("droneGetBuilds", () => {
    it("should return builds for a repository", async () => {
      const mockBuilds = [{ number: 1 }];
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockBuilds),
      });

      const result = await droneGetBuilds("owner", "repo");
      expect(result).toEqual(mockBuilds);
    });
  });

  describe("droneGetBuild", () => {
    it("should return a specific build", async () => {
      const mockBuild = { number: 5, status: "success" };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockBuild),
      });

      const result = await droneGetBuild("owner", "repo", 5);
      expect(result).toEqual(mockBuild);
    });
  });

  describe("droneGetBuildLogs", () => {
    it("should return build logs with default stage and step", async () => {
      const mockLogs = [{ out: "log line" }];
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockLogs),
      });

      const result = await droneGetBuildLogs("owner", "repo", 5);
      expect(result).toEqual(mockLogs);
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining("/logs/1/1"),
        expect.any(Object)
      );
    });

    it("should use custom stage and step when provided", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve([]),
      });

      await droneGetBuildLogs("owner", "repo", 5, 2, 3);
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining("/logs/2/3"),
        expect.any(Object)
      );
    });
  });

  describe("droneTriggerBuild", () => {
    it("should throw error when token is not set", async () => {
      config.drone.token = "";
      await expect(droneTriggerBuild("owner", "repo")).rejects.toThrow("Drone token required");
    });

    it("should trigger a build when token is set", async () => {
      config.drone.token = "test-token";
      const mockBuild = { number: 10 };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockBuild),
      });

      const result = await droneTriggerBuild("owner", "repo");
      expect(result).toEqual(mockBuild);
    });

    it("should use custom branch when provided", async () => {
      config.drone.token = "test-token";
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({}),
      });

      await droneTriggerBuild("owner", "repo", "develop");
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining("branch=develop"),
        expect.any(Object)
      );
    });
  });
});

// =============================================================================
// Handler Tests - Registry
// =============================================================================
describe("Registry Handlers", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe("registryGetCatalog", () => {
    it("should return catalog", async () => {
      const mockCatalog = { repositories: ["image1", "image2"] };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockCatalog),
      });

      const result = await registryGetCatalog();
      expect(result).toEqual(mockCatalog);
    });
  });

  describe("registryGetTags", () => {
    it("should return tags for an image", async () => {
      const mockTags = { name: "myimage", tags: ["latest", "v1"] };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockTags),
      });

      const result = await registryGetTags("myimage");
      expect(result).toEqual(mockTags);
    });
  });
});

// =============================================================================
// Handler Tests - Dependency-Track
// =============================================================================
describe("Dependency-Track Handlers", () => {
  const originalApiKey = config.dependencyTrack.apiKey;

  beforeEach(() => {
    vi.resetAllMocks();
  });

  afterEach(() => {
    config.dependencyTrack.apiKey = originalApiKey;
  });

  describe("dtrackGetProjects", () => {
    it("should throw error when API key is not set", async () => {
      config.dependencyTrack.apiKey = "";
      await expect(dtrackGetProjects()).rejects.toThrow("Dependency-Track API key not configured");
    });

    it("should return projects when API key is set", async () => {
      config.dependencyTrack.apiKey = "test-key";
      const mockProjects = [{ uuid: "123", name: "project1" }];
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockProjects),
      });

      const result = await dtrackGetProjects();
      expect(result).toEqual(mockProjects);
    });
  });

  describe("dtrackGetVulnerabilities", () => {
    it("should throw error when API key is not set", async () => {
      config.dependencyTrack.apiKey = "";
      await expect(dtrackGetVulnerabilities("uuid")).rejects.toThrow(
        "Dependency-Track API key not configured"
      );
    });

    it("should return vulnerabilities when API key is set", async () => {
      config.dependencyTrack.apiKey = "test-key";
      const mockVulns = [{ vulnId: "CVE-2021-1234" }];
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockVulns),
      });

      const result = await dtrackGetVulnerabilities("project-uuid");
      expect(result).toEqual(mockVulns);
    });
  });

  describe("dtrackGetFindings", () => {
    it("should return findings when API key is set", async () => {
      config.dependencyTrack.apiKey = "test-key";
      const mockFindings = [{ finding: "data" }];
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockFindings),
      });

      const result = await dtrackGetFindings("project-uuid");
      expect(result).toEqual(mockFindings);
    });
  });

  describe("dtrackGetComponents", () => {
    it("should return components when API key is set", async () => {
      config.dependencyTrack.apiKey = "test-key";
      const mockComponents = [{ name: "lodash", version: "4.17.21" }];
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockComponents),
      });

      const result = await dtrackGetComponents("project-uuid");
      expect(result).toEqual(mockComponents);
    });
  });
});

// =============================================================================
// Handler Tests - Trivy
// =============================================================================
describe("Trivy Handlers", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe("trivyScanPath", () => {
    it("should throw error for invalid path", async () => {
      await expect(trivyScanPath("")).rejects.toThrow("Invalid path provided");
    });

    it("should throw error for short path", async () => {
      await expect(trivyScanPath("a")).rejects.toThrow("Invalid path provided");
    });

    it("should scan a valid path successfully", async () => {
      const mockResult = { Results: [] };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(null, { stdout: JSON.stringify(mockResult), stderr: "" });
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanPath("/valid/path");
      expect(result).toEqual(mockResult);
    });

    it("should handle exec errors with JSON stdout", async () => {
      const mockResult = { Results: [], error: true };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          const error = new Error("Command failed") as ExecException & { stdout?: string };
          error.stdout = JSON.stringify(mockResult);
          callback(error, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanPath("/valid/path");
      expect(result).toEqual(mockResult);
    });

    it("should handle exec errors with non-JSON stdout", async () => {
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          const error = new Error("Command failed") as ExecException & { stdout?: string };
          error.stdout = "Not JSON";
          callback(error, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanPath("/valid/path");
      expect(result).toHaveProperty("error");
      expect(result).toHaveProperty("output", "Not JSON");
    });

    it("should throw error when exec fails without stdout", async () => {
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(new Error("Command failed") as ExecException, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      await expect(trivyScanPath("/valid/path")).rejects.toThrow("Command failed");
    });
  });

  describe("trivyScanImage", () => {
    it("should throw error for invalid image name", async () => {
      await expect(trivyScanImage("")).rejects.toThrow("Invalid image name provided");
    });

    it("should throw error for short image name", async () => {
      await expect(trivyScanImage("a")).rejects.toThrow("Invalid image name provided");
    });

    it("should scan a valid image successfully", async () => {
      const mockResult = { Results: [] };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(null, { stdout: JSON.stringify(mockResult), stderr: "" });
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanImage("nginx:latest");
      expect(result).toEqual(mockResult);
    });
  });

  describe("trivyGenerateSbom", () => {
    it("should throw error for invalid path", async () => {
      await expect(trivyGenerateSbom("")).rejects.toThrow("Invalid path provided");
    });

    it("should throw error for short path", async () => {
      await expect(trivyGenerateSbom("a")).rejects.toThrow("Invalid path provided");
    });

    it("should generate SBOM for a valid path successfully", async () => {
      const mockResult = { bomFormat: "CycloneDX", components: [] };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(null, { stdout: JSON.stringify(mockResult), stderr: "" });
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyGenerateSbom("/valid/path");
      expect(result).toEqual(mockResult);
    });

    it("should handle exec errors with JSON stdout", async () => {
      const mockResult = { bomFormat: "CycloneDX", components: [], error: true };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          const error = new Error("Command failed") as ExecException & { stdout?: string };
          error.stdout = JSON.stringify(mockResult);
          callback(error, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyGenerateSbom("/valid/path");
      expect(result).toEqual(mockResult);
    });

    it("should handle exec errors with non-JSON stdout", async () => {
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          const error = new Error("Command failed") as ExecException & { stdout?: string };
          error.stdout = "Not JSON";
          callback(error, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyGenerateSbom("/valid/path");
      expect(result).toHaveProperty("error");
      expect(result).toHaveProperty("output", "Not JSON");
    });

    it("should throw error when exec fails without stdout", async () => {
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(new Error("Command failed") as ExecException, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      await expect(trivyGenerateSbom("/valid/path")).rejects.toThrow("Command failed");
    });

    it("should accept spdx-json format", async () => {
      const mockResult = { spdxVersion: "SPDX-2.3", packages: [] };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          expect(cmd).toContain("--format spdx-json");
          callback(null, { stdout: JSON.stringify(mockResult), stderr: "" });
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyGenerateSbom("/valid/path", "spdx-json");
      expect(result).toEqual(mockResult);
    });
  });

  describe("trivyGenerateSbomImage", () => {
    it("should throw error for invalid image name", async () => {
      await expect(trivyGenerateSbomImage("")).rejects.toThrow("Invalid image name provided");
    });

    it("should throw error for short image name", async () => {
      await expect(trivyGenerateSbomImage("a")).rejects.toThrow("Invalid image name provided");
    });

    it("should generate SBOM for a valid image successfully", async () => {
      const mockResult = { bomFormat: "CycloneDX", components: [] };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(null, { stdout: JSON.stringify(mockResult), stderr: "" });
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyGenerateSbomImage("nginx:latest");
      expect(result).toEqual(mockResult);
    });

    it("should handle exec errors with JSON stdout", async () => {
      const mockResult = { bomFormat: "CycloneDX", components: [], error: true };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          const error = new Error("Command failed") as ExecException & { stdout?: string };
          error.stdout = JSON.stringify(mockResult);
          callback(error, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyGenerateSbomImage("nginx:latest");
      expect(result).toEqual(mockResult);
    });

    it("should handle exec errors with non-JSON stdout", async () => {
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          const error = new Error("Command failed") as ExecException & { stdout?: string };
          error.stdout = "Not JSON";
          callback(error, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyGenerateSbomImage("nginx:latest");
      expect(result).toHaveProperty("error");
      expect(result).toHaveProperty("output", "Not JSON");
    });

    it("should throw error when exec fails without stdout", async () => {
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(new Error("Command failed") as ExecException, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      await expect(trivyGenerateSbomImage("nginx:latest")).rejects.toThrow("Command failed");
    });
  });

  describe("trivyScanIac", () => {
    it("should throw error for invalid path", async () => {
      await expect(trivyScanIac("")).rejects.toThrow("Invalid path provided");
    });

    it("should throw error for short path", async () => {
      await expect(trivyScanIac("a")).rejects.toThrow("Invalid path provided");
    });

    it("should scan IaC files for a valid path successfully", async () => {
      const mockResult = {
        SchemaVersion: 2,
        Results: [
          {
            Target: "/app",
            Class: "config",
            Type: "terraform",
            Misconfigurations: [],
          },
        ],
      };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(null, { stdout: JSON.stringify(mockResult), stderr: "" });
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanIac("/valid/path");
      expect(result).toEqual(mockResult);
    });

    it("should handle exec errors with JSON stdout", async () => {
      const mockResult = {
        SchemaVersion: 2,
        Results: [{ Target: "/app", Misconfigurations: [] }],
      };
      const mockExec = vi.mocked(exec);
      const error = new Error("Command failed") as ExecException;
      (error as ExecException & { stdout: string }).stdout = JSON.stringify(mockResult);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(error, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanIac("/valid/path");
      expect(result).toEqual(mockResult);
    });

    it("should handle exec errors with non-JSON stdout", async () => {
      const mockExec = vi.mocked(exec);
      const error = new Error("Command failed") as ExecException;
      (error as ExecException & { stdout: string }).stdout = "Not JSON";
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(error, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanIac("/valid/path");
      expect(result).toHaveProperty("error");
      expect(result).toHaveProperty("output", "Not JSON");
    });

    it("should throw error when exec fails without stdout", async () => {
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(new Error("Command failed") as ExecException, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      await expect(trivyScanIac("/valid/path")).rejects.toThrow("Command failed");
    });

    it("should pass custom severity levels", async () => {
      const mockResult = { SchemaVersion: 2, Results: [] };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        expect(cmd).toContain("--severity HIGH,CRITICAL");
        if (callback) {
          callback(null, { stdout: JSON.stringify(mockResult), stderr: "" });
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanIac("/valid/path", "HIGH,CRITICAL");
      expect(result).toEqual(mockResult);
    });
  });

  describe("trivyScanSecrets", () => {
    it("should throw error for invalid path", async () => {
      await expect(trivyScanSecrets("")).rejects.toThrow("Invalid path provided");
    });

    it("should throw error for short path", async () => {
      await expect(trivyScanSecrets("a")).rejects.toThrow("Invalid path provided");
    });

    it("should scan for secrets in a valid path successfully", async () => {
      const mockResult = {
        SchemaVersion: 2,
        Results: [
          {
            Target: "/app",
            Class: "secret",
            Secrets: [],
          },
        ],
      };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(null, { stdout: JSON.stringify(mockResult), stderr: "" });
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanSecrets("/valid/path");
      expect(result).toEqual(mockResult);
    });

    it("should handle exec errors with JSON stdout", async () => {
      const mockResult = {
        SchemaVersion: 2,
        Results: [{ Target: "/app", Secrets: [] }],
      };
      const mockExec = vi.mocked(exec);
      const error = new Error("Command failed") as ExecException;
      (error as ExecException & { stdout: string }).stdout = JSON.stringify(mockResult);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(error, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanSecrets("/valid/path");
      expect(result).toEqual(mockResult);
    });

    it("should handle exec errors with non-JSON stdout", async () => {
      const mockExec = vi.mocked(exec);
      const error = new Error("Command failed") as ExecException;
      (error as ExecException & { stdout: string }).stdout = "Not JSON";
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(error, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanSecrets("/valid/path");
      expect(result).toHaveProperty("error");
      expect(result).toHaveProperty("output", "Not JSON");
    });

    it("should throw error when exec fails without stdout", async () => {
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(new Error("Command failed") as ExecException, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      await expect(trivyScanSecrets("/valid/path")).rejects.toThrow("Command failed");
    });

    it("should pass custom severity levels", async () => {
      const mockResult = { SchemaVersion: 2, Results: [] };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        expect(cmd).toContain("--severity HIGH,CRITICAL");
        if (callback) {
          callback(null, { stdout: JSON.stringify(mockResult), stderr: "" });
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanSecrets("/valid/path", "HIGH,CRITICAL");
      expect(result).toEqual(mockResult);
    });

    it("should use --scanners secret flag", async () => {
      const mockResult = { SchemaVersion: 2, Results: [] };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        expect(cmd).toContain("--scanners secret");
        if (callback) {
          callback(null, { stdout: JSON.stringify(mockResult), stderr: "" });
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanSecrets("/valid/path");
      expect(result).toEqual(mockResult);
    });
  });

  describe("trivyScanLicenses", () => {
    it("should throw error for invalid path", async () => {
      await expect(trivyScanLicenses("")).rejects.toThrow("Invalid path provided");
    });

    it("should throw error for short path", async () => {
      await expect(trivyScanLicenses("a")).rejects.toThrow("Invalid path provided");
    });

    it("should scan for licenses in a valid path successfully", async () => {
      const mockResult = {
        SchemaVersion: 2,
        Results: [
          {
            Target: "/app",
            Class: "license",
            Licenses: [],
          },
        ],
      };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(null, { stdout: JSON.stringify(mockResult), stderr: "" });
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanLicenses("/valid/path");
      expect(result).toEqual(mockResult);
    });

    it("should handle exec errors with JSON stdout", async () => {
      const mockResult = {
        SchemaVersion: 2,
        Results: [{ Target: "/app", Licenses: [] }],
      };
      const mockExec = vi.mocked(exec);
      const error = new Error("Command failed") as ExecException;
      (error as ExecException & { stdout: string }).stdout = JSON.stringify(mockResult);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(error, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanLicenses("/valid/path");
      expect(result).toEqual(mockResult);
    });

    it("should handle exec errors with non-JSON stdout", async () => {
      const mockExec = vi.mocked(exec);
      const error = new Error("Command failed") as ExecException;
      (error as ExecException & { stdout: string }).stdout = "Not JSON";
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(error, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanLicenses("/valid/path");
      expect(result).toHaveProperty("error");
      expect(result).toHaveProperty("output", "Not JSON");
    });

    it("should throw error when exec fails without stdout", async () => {
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(new Error("Command failed") as ExecException, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      await expect(trivyScanLicenses("/valid/path")).rejects.toThrow("Command failed");
    });

    it("should pass custom severity levels", async () => {
      const mockResult = { SchemaVersion: 2, Results: [] };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        expect(cmd).toContain("--severity HIGH,CRITICAL");
        if (callback) {
          callback(null, { stdout: JSON.stringify(mockResult), stderr: "" });
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanLicenses("/valid/path", "HIGH,CRITICAL");
      expect(result).toEqual(mockResult);
    });

    it("should use --scanners license flag", async () => {
      const mockResult = { SchemaVersion: 2, Results: [] };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        expect(cmd).toContain("--scanners license");
        if (callback) {
          callback(null, { stdout: JSON.stringify(mockResult), stderr: "" });
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanLicenses("/valid/path");
      expect(result).toEqual(mockResult);
    });
  });

  describe("trivyScanLicensesImage", () => {
    it("should throw error for invalid image name", async () => {
      await expect(trivyScanLicensesImage("")).rejects.toThrow("Invalid image name provided");
    });

    it("should throw error for short image name", async () => {
      await expect(trivyScanLicensesImage("a")).rejects.toThrow("Invalid image name provided");
    });

    it("should scan for licenses in an image successfully", async () => {
      const mockResult = {
        SchemaVersion: 2,
        Results: [
          {
            Target: "nginx:latest",
            Class: "license",
            Licenses: [],
          },
        ],
      };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(null, { stdout: JSON.stringify(mockResult), stderr: "" });
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanLicensesImage("nginx:latest");
      expect(result).toEqual(mockResult);
    });

    it("should handle exec errors with JSON stdout", async () => {
      const mockResult = {
        SchemaVersion: 2,
        Results: [{ Target: "nginx:latest", Licenses: [] }],
      };
      const mockExec = vi.mocked(exec);
      const error = new Error("Command failed") as ExecException;
      (error as ExecException & { stdout: string }).stdout = JSON.stringify(mockResult);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(error, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanLicensesImage("nginx:latest");
      expect(result).toEqual(mockResult);
    });

    it("should handle exec errors with non-JSON stdout", async () => {
      const mockExec = vi.mocked(exec);
      const error = new Error("Command failed") as ExecException;
      (error as ExecException & { stdout: string }).stdout = "Not JSON";
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(error, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanLicensesImage("nginx:latest");
      expect(result).toHaveProperty("error");
      expect(result).toHaveProperty("output", "Not JSON");
    });

    it("should throw error when exec fails without stdout", async () => {
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        if (callback) {
          callback(new Error("Command failed") as ExecException, null);
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      await expect(trivyScanLicensesImage("nginx:latest")).rejects.toThrow("Command failed");
    });

    it("should pass custom severity levels", async () => {
      const mockResult = { SchemaVersion: 2, Results: [] };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        expect(cmd).toContain("--severity HIGH,CRITICAL");
        if (callback) {
          callback(null, { stdout: JSON.stringify(mockResult), stderr: "" });
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanLicensesImage("nginx:latest", "HIGH,CRITICAL");
      expect(result).toEqual(mockResult);
    });

    it("should use --scanners license flag with image command", async () => {
      const mockResult = { SchemaVersion: 2, Results: [] };
      const mockExec = vi.mocked(exec);
      mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
        expect(cmd).toContain("image --scanners license");
        if (callback) {
          callback(null, { stdout: JSON.stringify(mockResult), stderr: "" });
        }
        return {} as ChildProcess;
      }) as unknown as typeof exec);

      const result = await trivyScanLicensesImage("nginx:latest");
      expect(result).toEqual(mockResult);
    });
  });
});

// =============================================================================
// Handler Tests - Platform Status
// =============================================================================
describe("checkPlatformStatus", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("should check all platform services", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
    });

    const result = await checkPlatformStatus();
    expect(result).toHaveProperty("timestamp");
    expect(result).toHaveProperty("services");
    expect(result.services).toHaveProperty("gitea");
    expect(result.services).toHaveProperty("drone");
    expect(result.services).toHaveProperty("sonarqube");
    expect(result.services).toHaveProperty("dependencyTrack");
    expect(result.services).toHaveProperty("trivy");
    expect(result.services).toHaveProperty("registry");
  });

  it("should mark healthy services correctly", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
    });

    const result = await checkPlatformStatus();
    expect(result.services.gitea.status).toBe("healthy");
    expect(result.services.gitea.statusCode).toBe(200);
  });

  it("should mark unhealthy services correctly", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 503,
    });

    const result = await checkPlatformStatus();
    expect(result.services.gitea.status).toBe("unhealthy");
    expect(result.services.gitea.statusCode).toBe(503);
  });

  it("should handle service failures gracefully", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("Connection refused"));

    const result = await checkPlatformStatus();
    expect(result.services.gitea.status).toBe("unreachable");
    expect(result.services.gitea.error).toContain("Connection refused");
  });
});

// =============================================================================
// Handler Tests - Security Scan All
// =============================================================================
describe("securityScanAll", () => {
  const originalApiKey = config.dependencyTrack.apiKey;

  beforeEach(() => {
    vi.resetAllMocks();
    config.dependencyTrack.apiKey = "test-key";
  });

  afterEach(() => {
    config.dependencyTrack.apiKey = originalApiKey;
  });

  it("should return empty results when no parameters provided", async () => {
    const result = await securityScanAll();
    expect(result).toHaveProperty("timestamp");
    expect(result.trivy).toBeNull();
    expect(result.sonarqube).toBeNull();
    expect(result.dependencyTrack).toBeNull();
  });

  it("should handle errors gracefully for each scanner", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("Network error"));

    const mockExec = vi.mocked(exec);
    mockExec.mockImplementation(((cmd: string, opts: ExecOptions, callback?: ExecCallback) => {
      if (callback) {
        callback(new Error("Docker error") as ExecException, null);
      }
      return {} as ChildProcess;
    }) as unknown as typeof exec);

    const result = await securityScanAll("/path", "project-key", "project-uuid");
    expect(result.trivy).toHaveProperty("error");
    expect(result.sonarqube).toHaveProperty("error");
    expect(result.dependencyTrack).toHaveProperty("error");
  });
});
