/**
 * Policy File Loader
 *
 * Loads security policies from YAML/JSON files and merges with default policies.
 * Supports .security-policy.yaml, .security-policy.yml, and .security-policy.json
 */

import { readFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import type {
  PolicyLoadResult,
  PolicyFileSchema,
  PolicyFileRule,
  PolicyValidationError,
  PolicyValidationResult,
} from "./types.js";
import { type Policy, type PolicyRule, getPolicy, standardPolicy } from "./policy.js";

// Default policy file names to search for (in order of priority)
const DEFAULT_POLICY_FILES = [
  ".security-policy.yaml",
  ".security-policy.yml",
  ".security-policy.json",
  "security-policy.yaml",
  "security-policy.yml",
  "security-policy.json",
];

// =============================================================================
// File Discovery
// =============================================================================

/**
 * Find a policy file in the given directory
 */
export function findPolicyFile(directory: string): string | null {
  const resolvedDir = resolve(directory);

  for (const filename of DEFAULT_POLICY_FILES) {
    const filePath = join(resolvedDir, filename);
    if (existsSync(filePath)) {
      return filePath;
    }
  }

  return null;
}

/**
 * Check if a file path looks like a YAML file
 */
function isYamlFile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return lower.endsWith(".yaml") || lower.endsWith(".yml");
}

// =============================================================================
// File Parsing
// =============================================================================

/**
 * Read and parse a policy file
 */
export function readPolicyFile(filePath: string): PolicyFileSchema {
  const content = readFileSync(filePath, "utf-8");

  if (isYamlFile(filePath)) {
    return parseYaml(content) as PolicyFileSchema;
  }

  return JSON.parse(content) as PolicyFileSchema;
}

// =============================================================================
// Schema Validation Helpers
// =============================================================================

function validateRequiredStringField(
  obj: Record<string, unknown>,
  field: string,
  suggestion: string
): PolicyValidationError | null {
  if (!obj[field] || typeof obj[field] !== "string") {
    return {
      path: field,
      message: `Policy ${field} is required and must be a string`,
      suggestion,
    };
  }
  return null;
}

function validateOptionalStringField(
  obj: Record<string, unknown>,
  field: string
): PolicyValidationError | null {
  if (obj[field] !== undefined && typeof obj[field] !== "string") {
    return {
      path: field,
      message: `${field.charAt(0).toUpperCase() + field.slice(1)} must be a string`,
    };
  }
  return null;
}

function validateExtendsField(obj: Record<string, unknown>): {
  error?: PolicyValidationError;
  warning?: PolicyValidationError;
} {
  if (obj.extends === undefined) return {};

  if (typeof obj.extends !== "string") {
    return {
      error: {
        path: "extends",
        message: "Extends must be a string",
        suggestion: 'Use one of: "strict", "standard", "permissive"',
      },
    };
  }

  if (!["strict", "standard", "permissive"].includes((obj.extends as string).toLowerCase())) {
    return {
      warning: {
        path: "extends",
        message: `Unknown base policy: ${obj.extends}`,
        suggestion: 'Use one of: "strict", "standard", "permissive"',
      },
    };
  }

  return {};
}

// =============================================================================
// Schema Validation
// =============================================================================

/**
 * Validate a policy file schema
 */
export function validatePolicySchema(policy: unknown): PolicyValidationResult {
  const errors: PolicyValidationError[] = [];
  const warnings: PolicyValidationError[] = [];

  // Must be an object
  if (!policy || typeof policy !== "object") {
    errors.push({
      path: "",
      message: "Policy must be an object",
      suggestion: "Provide a valid policy object with name and version fields",
    });
    return { valid: false, errors, warnings };
  }

  const obj = policy as Record<string, unknown>;

  // Required fields
  const nameError = validateRequiredStringField(obj, "name", 'Add a name field: name: "my-policy"');
  if (nameError) errors.push(nameError);

  const versionError = validateRequiredStringField(
    obj,
    "version",
    'Add a version field: version: "1.0.0"'
  );
  if (versionError) errors.push(versionError);

  // Optional string field
  const descError = validateOptionalStringField(obj, "description");
  if (descError) errors.push(descError);

  // Extends field
  const extendsResult = validateExtendsField(obj);
  if (extendsResult.error) errors.push(extendsResult.error);
  if (extendsResult.warning) warnings.push(extendsResult.warning);

  // Mode field
  if (obj.mode !== undefined && obj.mode !== "all" && obj.mode !== "any") {
    errors.push({
      path: "mode",
      message: 'Mode must be "all" or "any"',
      suggestion:
        'Use mode: "all" to require all rules pass, or mode: "any" to require at least one',
    });
  }

  // Rules field
  if (obj.rules !== undefined) {
    if (Array.isArray(obj.rules)) {
      obj.rules.forEach((rule, index) => {
        const ruleErrors = validateRule(rule, `rules[${index}]`);
        errors.push(...ruleErrors.errors);
        warnings.push(...ruleErrors.warnings);
      });
    } else {
      errors.push({ path: "rules", message: "Rules must be an array" });
    }
  }

  // Settings field
  if (obj.settings !== undefined) {
    const settingsResult = validateSettings(obj.settings);
    errors.push(...settingsResult.errors);
    warnings.push(...settingsResult.warnings);
  }

  return { valid: errors.length === 0, errors, warnings };
}

/**
 * Validate a single policy rule
 */
function validateRule(
  rule: unknown,
  path: string
): { errors: PolicyValidationError[]; warnings: PolicyValidationError[] } {
  const errors: PolicyValidationError[] = [];
  const warnings: PolicyValidationError[] = [];

  if (!rule || typeof rule !== "object") {
    errors.push({
      path,
      message: "Rule must be an object",
    });
    return { errors, warnings };
  }

  const obj = rule as Record<string, unknown>;

  // Required: name
  if (!obj.name || typeof obj.name !== "string") {
    errors.push({
      path: `${path}.name`,
      message: "Rule name is required and must be a string",
    });
  }

  // Optional: enabled
  if (obj.enabled !== undefined && typeof obj.enabled !== "boolean") {
    errors.push({
      path: `${path}.enabled`,
      message: "Enabled must be a boolean",
    });
  }

  // Optional: maxVulnerabilities
  if (obj.maxVulnerabilities !== undefined) {
    if (typeof obj.maxVulnerabilities !== "object" || obj.maxVulnerabilities === null) {
      errors.push({
        path: `${path}.maxVulnerabilities`,
        message: "maxVulnerabilities must be an object",
      });
    } else {
      const vulns = obj.maxVulnerabilities as Record<string, unknown>;
      const validKeys = ["critical", "high", "medium", "low", "unknown"];

      for (const [key, value] of Object.entries(vulns)) {
        if (!validKeys.includes(key)) {
          warnings.push({
            path: `${path}.maxVulnerabilities.${key}`,
            message: `Unknown severity level: ${key}`,
            suggestion: `Valid severities: ${validKeys.join(", ")}`,
          });
        } else if (typeof value !== "number" || value < 0) {
          errors.push({
            path: `${path}.maxVulnerabilities.${key}`,
            message: "Value must be a non-negative number",
          });
        }
      }
    }
  }

  // Optional: ignoreCves
  if (obj.ignoreCves !== undefined) {
    if (!Array.isArray(obj.ignoreCves)) {
      errors.push({
        path: `${path}.ignoreCves`,
        message: "ignoreCves must be an array of strings",
      });
    } else if (!obj.ignoreCves.every((c) => typeof c === "string")) {
      errors.push({
        path: `${path}.ignoreCves`,
        message: "All CVE entries must be strings",
      });
    }
  }

  // Optional: ignorePackages
  if (obj.ignorePackages !== undefined) {
    if (!Array.isArray(obj.ignorePackages)) {
      errors.push({
        path: `${path}.ignorePackages`,
        message: "ignorePackages must be an array of strings",
      });
    } else if (!obj.ignorePackages.every((p) => typeof p === "string")) {
      errors.push({
        path: `${path}.ignorePackages`,
        message: "All package entries must be strings",
      });
    }
  }

  // Optional: blockedLicenses
  if (obj.blockedLicenses !== undefined) {
    if (!Array.isArray(obj.blockedLicenses)) {
      errors.push({
        path: `${path}.blockedLicenses`,
        message: "blockedLicenses must be an array of strings",
      });
    } else if (!obj.blockedLicenses.every((l) => typeof l === "string")) {
      errors.push({
        path: `${path}.blockedLicenses`,
        message: "All license entries must be strings",
      });
    }
  }

  // Optional: minCodeCoverage
  if (obj.minCodeCoverage !== undefined) {
    if (
      typeof obj.minCodeCoverage !== "number" ||
      obj.minCodeCoverage < 0 ||
      obj.minCodeCoverage > 100
    ) {
      errors.push({
        path: `${path}.minCodeCoverage`,
        message: "minCodeCoverage must be a number between 0 and 100",
      });
    }
  }

  // Optional: requireQualityGatePass
  if (obj.requireQualityGatePass !== undefined && typeof obj.requireQualityGatePass !== "boolean") {
    errors.push({
      path: `${path}.requireQualityGatePass`,
      message: "requireQualityGatePass must be a boolean",
    });
  }

  // Optional: blockOnSecrets
  if (obj.blockOnSecrets !== undefined && typeof obj.blockOnSecrets !== "boolean") {
    errors.push({
      path: `${path}.blockOnSecrets`,
      message: "blockOnSecrets must be a boolean",
    });
  }

  return { errors, warnings };
}

/**
 * Validate policy settings
 */
function validateSettings(settings: unknown): {
  errors: PolicyValidationError[];
  warnings: PolicyValidationError[];
} {
  const errors: PolicyValidationError[] = [];
  const warnings: PolicyValidationError[] = [];

  if (typeof settings !== "object" || settings === null) {
    errors.push({
      path: "settings",
      message: "Settings must be an object",
    });
    return { errors, warnings };
  }

  const obj = settings as Record<string, unknown>;

  if (obj.failOpen !== undefined && typeof obj.failOpen !== "boolean") {
    errors.push({
      path: "settings.failOpen",
      message: "failOpen must be a boolean",
    });
  }

  if (
    obj.reportFormat !== undefined &&
    !["text", "json", "sarif"].includes(obj.reportFormat as string)
  ) {
    errors.push({
      path: "settings.reportFormat",
      message: 'reportFormat must be "text", "json", or "sarif"',
    });
  }

  if (obj.includeWarnings !== undefined && typeof obj.includeWarnings !== "boolean") {
    errors.push({
      path: "settings.includeWarnings",
      message: "includeWarnings must be a boolean",
    });
  }

  return { errors, warnings };
}

// =============================================================================
// Policy Conversion & Merging
// =============================================================================

/**
 * Convert a PolicyFileRule to a PolicyRule (runtime format)
 */
function convertRule(fileRule: PolicyFileRule): PolicyRule {
  return {
    name: fileRule.name,
    description: fileRule.description,
    maxVulnerabilities: fileRule.maxVulnerabilities,
    ignoreCves: fileRule.ignoreCves,
    ignorePackages: fileRule.ignorePackages,
    blockedLicenses: fileRule.blockedLicenses,
    minCodeCoverage: fileRule.minCodeCoverage,
    requireQualityGatePass: fileRule.requireQualityGatePass,
    blockOnSecrets: fileRule.blockOnSecrets,
  };
}

/**
 * Convert a PolicyFileSchema to a Policy (runtime format)
 */
export function convertToPolicy(fileSchema: PolicyFileSchema): Policy {
  return {
    name: fileSchema.name,
    version: fileSchema.version,
    description: fileSchema.description,
    mode: fileSchema.mode ?? "all",
    rules: (fileSchema.rules ?? []).filter((r) => r.enabled !== false).map(convertRule),
  };
}

/**
 * Merge a file policy with a base policy
 */
export function mergePolicies(filePolicy: PolicyFileSchema, basePolicy: Policy): Policy {
  // Start with the base policy
  const merged: Policy = {
    name: filePolicy.name,
    version: filePolicy.version,
    description: filePolicy.description ?? basePolicy.description,
    mode: filePolicy.mode ?? basePolicy.mode,
    rules: [...basePolicy.rules],
  };

  // Process file rules
  if (filePolicy.rules) {
    for (const fileRule of filePolicy.rules) {
      // Skip disabled rules
      if (fileRule.enabled === false) {
        // If a base rule exists with this name, remove it
        merged.rules = merged.rules.filter((r) => r.name !== fileRule.name);
        continue;
      }

      // Check if this rule overrides a base rule
      const baseRuleIndex = merged.rules.findIndex((r) => r.name === fileRule.name);

      if (baseRuleIndex >= 0) {
        // Merge with base rule
        const baseRule = merged.rules[baseRuleIndex];
        merged.rules[baseRuleIndex] = {
          ...baseRule,
          ...convertRule(fileRule),
          // Merge arrays instead of replacing
          ignoreCves: [...(baseRule.ignoreCves || []), ...(fileRule.ignoreCves || [])],
          ignorePackages: [...(baseRule.ignorePackages || []), ...(fileRule.ignorePackages || [])],
          blockedLicenses: [
            ...(baseRule.blockedLicenses || []),
            ...(fileRule.blockedLicenses || []),
          ],
        };
      } else {
        // Add new rule
        merged.rules.push(convertRule(fileRule));
      }
    }
  }

  return merged;
}

// =============================================================================
// Main API
// =============================================================================

/**
 * Load a policy file from a specific path
 */
export function loadPolicyFromFile(filePath: string): PolicyLoadResult {
  try {
    if (!existsSync(filePath)) {
      return {
        success: false,
        error: `Policy file not found: ${filePath}`,
        source: "file",
      };
    }

    const policyData = readPolicyFile(filePath);
    const validation = validatePolicySchema(policyData);

    if (!validation.valid) {
      const errorMessages = validation.errors.map((e) => `${e.path}: ${e.message}`).join("; ");
      return {
        success: false,
        error: `Invalid policy file: ${errorMessages}`,
        filePath,
        source: "file",
      };
    }

    return {
      success: true,
      policy: policyData,
      filePath,
      source: "file",
    };
  } catch (error) {
    return {
      success: false,
      error: `Failed to load policy file: ${error instanceof Error ? error.message : String(error)}`,
      filePath,
      source: "file",
    };
  }
}

/**
 * Load a policy from a directory (auto-discovers policy file)
 */
export function loadPolicyFromDirectory(directory: string): PolicyLoadResult {
  const filePath = findPolicyFile(directory);

  if (!filePath) {
    return {
      success: false,
      error: `No policy file found in directory: ${directory}`,
      source: "file",
    };
  }

  return loadPolicyFromFile(filePath);
}

/**
 * Load and resolve a policy, applying extension/merge logic
 */
export function resolvePolicy(
  filePolicyResult: PolicyLoadResult,
  defaultPolicyName?: string
): Policy {
  // If file policy failed to load
  if (!filePolicyResult.success || !filePolicyResult.policy) {
    // Use specified default or standard policy
    const defaultPolicy = defaultPolicyName
      ? (getPolicy(defaultPolicyName) ?? standardPolicy)
      : standardPolicy;
    return defaultPolicy;
  }

  const filePolicy = filePolicyResult.policy;

  // If policy extends a base
  if (filePolicy.extends) {
    const basePolicy = getPolicy(filePolicy.extends);
    if (basePolicy) {
      return mergePolicies(filePolicy, basePolicy);
    }
  }

  // No extension - convert directly
  return convertToPolicy(filePolicy);
}

/**
 * Main entry point: Load policy from directory with fallback to default
 */
export function loadPolicy(
  directoryOrPath?: string,
  options?: {
    defaultPolicy?: string;
    strict?: boolean;
  }
): { policy: Policy; loadResult: PolicyLoadResult } {
  // If no path provided, use current directory
  const searchPath = directoryOrPath ?? process.cwd();

  // Determine if it's a file or directory
  let loadResult: PolicyLoadResult;

  if (searchPath.endsWith(".yaml") || searchPath.endsWith(".yml") || searchPath.endsWith(".json")) {
    loadResult = loadPolicyFromFile(searchPath);
  } else {
    loadResult = loadPolicyFromDirectory(searchPath);
  }

  // In strict mode, throw on load errors
  if (options?.strict && !loadResult.success) {
    throw new Error(loadResult.error ?? "Failed to load policy");
  }

  // Resolve the policy
  const policy = resolvePolicy(loadResult, options?.defaultPolicy);

  // Update source if we used default
  if (!loadResult.success) {
    loadResult.source = "default";
  } else if (loadResult.policy?.extends) {
    loadResult.source = "merged";
  }

  return { policy, loadResult };
}
