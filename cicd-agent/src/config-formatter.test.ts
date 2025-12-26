import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

// Test config-file module
import { loadConfigFile, mergeConfig, type AgentConfig } from "./config-file.js";

describe("config-file", () => {
  const testDir = path.join(process.cwd(), "test-config-tmp");

  beforeEach(() => {
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
  });

  afterEach(() => {
    // Clean up test files
    try {
      fs.rmSync(testDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe("loadConfigFile", () => {
    it("should return null when no config file exists", () => {
      const config = loadConfigFile(testDir);
      expect(config).toBeNull();
    });

    it("should load YAML config file", () => {
      const yamlContent = `
format: json
quiet: true
severity: HIGH
`;
      fs.writeFileSync(path.join(testDir, ".cicd-agent.yaml"), yamlContent);

      const config = loadConfigFile(testDir);
      expect(config).not.toBeNull();
      expect(config?.format).toBe("json");
      expect(config?.quiet).toBe(true);
      expect(config?.severity).toBe("HIGH");
    });

    it("should load JSON config file", () => {
      const jsonContent = JSON.stringify({
        format: "markdown",
        quiet: false,
        severity: "CRITICAL",
      });
      fs.writeFileSync(path.join(testDir, ".cicd-agent.json"), jsonContent);

      const config = loadConfigFile(testDir);
      expect(config).not.toBeNull();
      expect(config?.format).toBe("markdown");
      expect(config?.quiet).toBe(false);
    });

    it("should prefer YAML over JSON when both exist", () => {
      fs.writeFileSync(path.join(testDir, ".cicd-agent.yaml"), "format: table\n");
      fs.writeFileSync(path.join(testDir, ".cicd-agent.json"), JSON.stringify({ format: "json" }));

      const config = loadConfigFile(testDir);
      expect(config?.format).toBe("table");
    });

    it("should handle invalid YAML gracefully", () => {
      fs.writeFileSync(path.join(testDir, ".cicd-agent.yaml"), "invalid: yaml: content: here:");

      // Should not throw
      const config = loadConfigFile(testDir);
      // Could be null or partial depending on implementation
      expect(config === null || typeof config === "object").toBe(true);
    });

    it("should handle invalid JSON gracefully", () => {
      fs.writeFileSync(path.join(testDir, ".cicd-agent.json"), "{ invalid json }");

      const config = loadConfigFile(testDir);
      expect(config).toBeNull();
    });

    it("should load platform configuration", () => {
      const yamlContent = `
platforms:
  gitea: http://localhost:3000
  drone: http://localhost:8085
defaults:
  owner: testowner
  repo: testrepo
`;
      fs.writeFileSync(path.join(testDir, ".cicd-agent.yaml"), yamlContent);

      const config = loadConfigFile(testDir);
      expect(config?.platforms?.gitea).toBe("http://localhost:3000");
      expect(config?.defaults?.owner).toBe("testowner");
    });
  });

  describe("mergeConfig", () => {
    it("should merge file config with defaults", () => {
      const fileConfig: AgentConfig = {
        format: "json",
        quiet: true,
      };

      const merged = mergeConfig(fileConfig, {});
      expect(merged.format).toBe("json");
      expect(merged.quiet).toBe(true);
    });

    it("should use defaults when file config is empty", () => {
      const merged = mergeConfig({}, {});
      expect(merged.format).toBe("text");
      expect(merged.quiet).toBe(false);
    });

    it("should handle null config", () => {
      const merged = mergeConfig(null, {});
      expect(merged.format).toBe("text");
      expect(merged.quiet).toBe(false);
    });

    it("should let CLI options override file config", () => {
      const fileConfig: AgentConfig = {
        format: "json",
        quiet: false,
      };
      const cliOptions: Partial<AgentConfig> = {
        format: "table",
      };

      const merged = mergeConfig(fileConfig, cliOptions);
      expect(merged.format).toBe("table");
      expect(merged.quiet).toBe(false);
    });
  });
});

// Test formatter module
import { formatOutput, setGlobalFormat, setGlobalQuiet, log, isQuiet } from "./formatter.js";

describe("formatter", () => {
  beforeEach(() => {
    // Reset to defaults
    setGlobalFormat("text");
    setGlobalQuiet(false);
  });

  describe("setGlobalFormat", () => {
    it("should set format to json", () => {
      setGlobalFormat("json");
      const output = formatOutput({ key: "value" });
      expect(output).toContain('"key"');
      expect(output).toContain('"value"');
    });

    it("should set format to text", () => {
      setGlobalFormat("text");
      const output = formatOutput({ message: "hello" });
      expect(output).toContain("hello");
    });
  });

  describe("setGlobalQuiet and isQuiet", () => {
    it("should default to not quiet", () => {
      expect(isQuiet()).toBe(false);
    });

    it("should set quiet mode", () => {
      setGlobalQuiet(true);
      expect(isQuiet()).toBe(true);
    });

    it("should unset quiet mode", () => {
      setGlobalQuiet(true);
      setGlobalQuiet(false);
      expect(isQuiet()).toBe(false);
    });
  });

  describe("log", () => {
    it("should output when not quiet", () => {
      const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
      setGlobalQuiet(false);
      log("test message");
      expect(consoleSpy).toHaveBeenCalledWith("test message");
      consoleSpy.mockRestore();
    });

    it("should not output when quiet", () => {
      const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
      setGlobalQuiet(true);
      log("test message");
      expect(consoleSpy).not.toHaveBeenCalled();
      consoleSpy.mockRestore();
    });
  });

  describe("formatOutput", () => {
    describe("json format", () => {
      beforeEach(() => setGlobalFormat("json"));

      it("should format object as JSON", () => {
        const output = formatOutput({ name: "test", value: 123 });
        const parsed = JSON.parse(output);
        expect(parsed.name).toBe("test");
        expect(parsed.value).toBe(123);
      });

      it("should format array as JSON", () => {
        const output = formatOutput([1, 2, 3]);
        const parsed = JSON.parse(output);
        expect(parsed).toEqual([1, 2, 3]);
      });

      it("should format primitives as JSON", () => {
        expect(formatOutput("string")).toBe('"string"');
        expect(formatOutput(42)).toBe("42");
        expect(formatOutput(true)).toBe("true");
      });
    });

    describe("text format", () => {
      beforeEach(() => setGlobalFormat("text"));

      it("should format object as text", () => {
        const output = formatOutput({ message: "hello world" });
        expect(output).toContain("hello world");
      });

      it("should format string as-is", () => {
        const output = formatOutput("plain text");
        expect(output).toBe("plain text");
      });
    });

    describe("table format", () => {
      beforeEach(() => setGlobalFormat("table"));

      it("should format array of objects as table", () => {
        const data = [
          { name: "Alice", age: 30 },
          { name: "Bob", age: 25 },
        ];
        const output = formatOutput(data, "Users");
        expect(output).toContain("Alice");
        expect(output).toContain("Bob");
        expect(output).toContain("30");
        expect(output).toContain("25");
      });

      it("should handle empty array", () => {
        const output = formatOutput([], "Empty");
        expect(output).toContain("No data");
      });

      it("should fall back to text for non-array", () => {
        const output = formatOutput({ single: "object" });
        expect(typeof output).toBe("string");
      });
    });

    describe("markdown format", () => {
      beforeEach(() => setGlobalFormat("markdown"));

      it("should format array as markdown table", () => {
        const data = [
          { col1: "a", col2: "b" },
          { col1: "c", col2: "d" },
        ];
        const output = formatOutput(data, "Table");
        expect(output).toContain("|");
        expect(output).toContain("---");
      });

      it("should format object as markdown list", () => {
        const output = formatOutput({ key1: "value1", key2: "value2" });
        expect(output).toContain("**key1**");
        expect(output).toContain("value1");
      });

      it("should handle primitives", () => {
        expect(formatOutput("text")).toContain("text");
        expect(formatOutput(123)).toContain("123");
      });
    });
  });
});
