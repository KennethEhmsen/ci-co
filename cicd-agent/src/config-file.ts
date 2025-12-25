/**
 * Configuration File Support
 * Loads configuration from .cicd-agent.yaml or .cicd-agent.json
 */

import * as fs from "node:fs";
import * as path from "node:path";

export interface AgentConfig {
  // Output settings
  format?: "json" | "table" | "markdown" | "text";
  quiet?: boolean;

  // Default scan settings
  severity?: string;
  sbomFormat?: "cyclonedx" | "spdx-json";

  // Platform URLs (override environment)
  platforms?: {
    gitea?: string;
    drone?: string;
    sonarqube?: string;
    dependencyTrack?: string;
    trivy?: string;
    registry?: string;
  };

  // Default repository context
  defaults?: {
    owner?: string;
    repo?: string;
  };
}

const CONFIG_FILES = [
  ".cicd-agent.yaml",
  ".cicd-agent.yml",
  ".cicd-agent.json",
  "cicd-agent.config.json",
];

/**
 * Load configuration from file
 */
export function loadConfigFile(basePath?: string): AgentConfig | null {
  const searchPath = basePath || process.cwd();

  for (const filename of CONFIG_FILES) {
    const filepath = path.join(searchPath, filename);

    if (fs.existsSync(filepath)) {
      try {
        const content = fs.readFileSync(filepath, "utf-8");

        if (filename.endsWith(".json")) {
          return JSON.parse(content) as AgentConfig;
        } else {
          // Simple YAML parsing (basic key: value support)
          return parseSimpleYaml(content);
        }
      } catch (error) {
        console.error(`Warning: Failed to parse ${filename}: ${error}`);
        return null;
      }
    }
  }

  return null;
}

/**
 * Simple YAML parser for basic configuration
 * Supports: key: value, nested objects (2 levels), comments
 */
function parseSimpleYaml(content: string): AgentConfig {
  const result: Record<string, unknown> = {};
  let currentSection: string | null = null;
  let currentObject: Record<string, unknown> = result;

  const lines = content.split("\n");

  for (const line of lines) {
    // Skip comments and empty lines
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    // Check indentation level
    const indent = line.length - line.trimStart().length;

    // Parse key: value
    const colonIndex = trimmed.indexOf(":");
    if (colonIndex === -1) continue;

    const key = trimmed.slice(0, colonIndex).trim();
    const value: string | boolean | number = trimmed.slice(colonIndex + 1).trim();

    // Handle nested sections (indent > 0)
    if (indent === 0) {
      if (value === "" || value === "{") {
        // This is a section header
        currentSection = key;
        result[key] = {};
        currentObject = result[key] as Record<string, unknown>;
      } else {
        // Top-level value
        currentSection = null;
        currentObject = result;
        result[key] = parseValue(value);
      }
    } else if (currentSection) {
      // Nested value
      currentObject[key] = parseValue(value);
    }
  }

  return result as AgentConfig;
}

/**
 * Parse a YAML value to appropriate type
 */
function parseValue(value: string): string | boolean | number {
  // Remove quotes
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }

  // Boolean
  if (value.toLowerCase() === "true") return true;
  if (value.toLowerCase() === "false") return false;

  // Number
  const num = Number(value);
  if (!isNaN(num) && value !== "") return num;

  return value;
}

/**
 * Merge configuration with defaults
 */
export function mergeConfig(
  fileConfig: AgentConfig | null,
  cliOptions: Partial<AgentConfig>
): AgentConfig {
  const defaults: AgentConfig = {
    format: "text",
    quiet: false,
    severity: "HIGH,CRITICAL",
    sbomFormat: "cyclonedx",
  };

  return {
    ...defaults,
    ...fileConfig,
    ...cliOptions,
    // Deep merge platforms
    platforms: {
      ...fileConfig?.platforms,
      ...cliOptions?.platforms,
    },
    // Deep merge defaults
    defaults: {
      ...fileConfig?.defaults,
      ...cliOptions?.defaults,
    },
  };
}

/**
 * Get configuration value with fallback chain
 */
export function getConfigValue<K extends keyof AgentConfig>(
  config: AgentConfig,
  key: K
): AgentConfig[K] {
  return config[key];
}
