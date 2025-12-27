/**
 * OPA/Rego Policy Evaluation Module
 *
 * Provides built-in Rego policies and TypeScript-based policy evaluation
 * that mimics OPA/Rego semantics. For full Rego support, use the OPA CLI
 * or the @open-policy-agent/opa-wasm package.
 */

import type {
  OpaViolation,
  OpaEvaluationResult,
  OpaPolicyInfo,
  OpaEvaluationInput,
  OpaPolicyOptions,
  OpaValidationResult,
  TrivyScanResult,
  SecurityDashboardResult,
} from "./types.js";
import type { ScanResults } from "./policy.js";
import { createHash } from "crypto";

// =============================================================================
// BUILT-IN REGO POLICIES (for reference and documentation)
// =============================================================================

/**
 * Built-in Rego policies available for evaluation.
 * These are provided as reference Rego code and are evaluated using
 * TypeScript implementations that mirror the Rego semantics.
 */
export const BUILTIN_POLICIES: Record<string, string> = {
  "vulnerability-threshold": `
package security

default allow := false

# Allow if no critical vulnerabilities and high count is within threshold
allow if {
  input.scan.vulnerabilities.critical == 0
  input.scan.vulnerabilities.high <= object.get(input, ["thresholds", "high"], 10)
}

# Violation for critical vulnerabilities
violations contains v if {
  input.scan.vulnerabilities.critical > 0
  v := {
    "type": "vulnerability_threshold",
    "severity": "critical",
    "code": "critical_vulnerabilities",
    "message": sprintf("Found %d critical vulnerabilities", [input.scan.vulnerabilities.critical]),
    "remediation": "Fix all critical vulnerabilities before deployment"
  }
}

# Violation for too many high vulnerabilities
violations contains v if {
  threshold := object.get(input, ["thresholds", "high"], 10)
  input.scan.vulnerabilities.high > threshold
  v := {
    "type": "vulnerability_threshold",
    "severity": "high",
    "code": "high_vulnerabilities_exceeded",
    "message": sprintf("Found %d high vulnerabilities (max: %d)", [input.scan.vulnerabilities.high, threshold]),
    "remediation": "Reduce high severity vulnerabilities below threshold"
  }
}
`,

  "license-compliance": `
package security

default allow := true

blocked_licenses := {"GPL-3.0", "AGPL-3.0", "SSPL-1.0", "BUSL-1.1"}
restricted_licenses := {"LGPL-2.1", "LGPL-3.0", "MPL-2.0"}

# Violation for blocked licenses
violations contains v if {
  some license in input.scan.licenses
  license in blocked_licenses
  v := {
    "type": "license_violation",
    "severity": "critical",
    "code": "blocked_license",
    "message": sprintf("Blocked license found: %s", [license]),
    "resource": license,
    "remediation": "Replace dependency with a permissively licensed alternative"
  }
}

# Warning for restricted licenses
violations contains v if {
  some license in input.scan.licenses
  license in restricted_licenses
  v := {
    "type": "license_warning",
    "severity": "medium",
    "code": "restricted_license",
    "message": sprintf("Restricted license found: %s", [license]),
    "resource": license,
    "remediation": "Review license compatibility with your project"
  }
}

# Deny if blocked licenses found
allow if {
  not has_blocked_license
}

has_blocked_license if {
  some license in input.scan.licenses
  license in blocked_licenses
}
`,

  "secrets-detection": `
package security

default allow := false

# Allow if no secrets detected
allow if {
  not input.scan.secretsFound
}

# Violation for secrets
violations contains v if {
  input.scan.secretsFound
  v := {
    "type": "secrets_detected",
    "severity": "critical",
    "code": "secrets_in_code",
    "message": "Secrets detected in scan results",
    "remediation": "Remove hardcoded secrets and use environment variables or secret management"
  }
}
`,

  "container-security": `
package security

default allow := true

# Check for critical vulnerabilities
violations contains v if {
  input.scan.vulnerabilities.critical > 0
  v := {
    "type": "container_vulnerability",
    "severity": "critical",
    "code": "container_critical_vuln",
    "message": sprintf("Container has %d critical vulnerabilities", [input.scan.vulnerabilities.critical]),
    "remediation": "Update base image and vulnerable packages"
  }
}

# Check for use of 'latest' tag
violations contains v if {
  input.image
  contains(input.image, ":latest")
  v := {
    "type": "container_config",
    "severity": "medium",
    "code": "latest_tag_used",
    "message": "Using 'latest' tag is not recommended for production",
    "resource": input.image,
    "remediation": "Use specific version tags for container images"
  }
}

# Check for root user
violations contains v if {
  input.metadata.runAsRoot == true
  v := {
    "type": "container_config",
    "severity": "high",
    "code": "runs_as_root",
    "message": "Container runs as root user",
    "remediation": "Configure container to run as non-root user"
  }
}

# Allow if no critical violations
allow if {
  count([v | v := violations[_]; v.severity == "critical"]) == 0
}
`,

  "quality-gate": `
package security

default allow := false

# Allow if quality gate passed and coverage meets minimum
allow if {
  input.scan.qualityGatePassed == true
  input.scan.codeCoverage >= object.get(input, ["thresholds", "coverage"], 80)
}

# Violation for failed quality gate
violations contains v if {
  input.scan.qualityGatePassed == false
  v := {
    "type": "quality_gate",
    "severity": "high",
    "code": "quality_gate_failed",
    "message": "Quality gate check failed",
    "remediation": "Fix code quality issues to pass the quality gate"
  }
}

# Violation for low code coverage
violations contains v if {
  threshold := object.get(input, ["thresholds", "coverage"], 80)
  input.scan.codeCoverage < threshold
  v := {
    "type": "code_coverage",
    "severity": "medium",
    "code": "low_code_coverage",
    "message": sprintf("Code coverage %.1f%% is below minimum %.1f%%", [input.scan.codeCoverage, threshold]),
    "remediation": "Increase test coverage to meet the minimum threshold"
  }
}
`,
};

// =============================================================================
// POLICY METADATA
// =============================================================================

/**
 * Metadata for built-in policies
 */
const POLICY_METADATA: Record<string, { description: string; entrypoints: string[] }> = {
  "vulnerability-threshold": {
    description:
      "Enforces vulnerability count thresholds by severity level. Blocks deployments with critical vulnerabilities.",
    entrypoints: ["security/allow", "security/violations"],
  },
  "license-compliance": {
    description: "Checks for blocked and restricted software licenses (GPL-3.0, AGPL, SSPL, etc.).",
    entrypoints: ["security/allow", "security/violations"],
  },
  "secrets-detection": {
    description: "Blocks deployments when hardcoded secrets are detected in the codebase.",
    entrypoints: ["security/allow", "security/violations"],
  },
  "container-security": {
    description:
      "Validates container security best practices: no critical vulns, no latest tag, non-root user.",
    entrypoints: ["security/allow", "security/violations"],
  },
  "quality-gate": {
    description: "Requires SonarQube quality gate to pass and minimum code coverage threshold.",
    entrypoints: ["security/allow", "security/violations"],
  },
};

// =============================================================================
// BUILT-IN LICENSE SETS
// =============================================================================

const BLOCKED_LICENSES = new Set([
  "GPL-3.0",
  "GPL-3.0-only",
  "GPL-3.0-or-later",
  "AGPL-3.0",
  "AGPL-3.0-only",
  "AGPL-3.0-or-later",
  "SSPL-1.0",
  "BUSL-1.1",
]);

const RESTRICTED_LICENSES = new Set([
  "LGPL-2.1",
  "LGPL-2.1-only",
  "LGPL-2.1-or-later",
  "LGPL-3.0",
  "LGPL-3.0-only",
  "LGPL-3.0-or-later",
  "MPL-2.0",
  "EPL-1.0",
  "EPL-2.0",
]);

// =============================================================================
// POLICY EVALUATION IMPLEMENTATIONS
// =============================================================================

/**
 * Evaluate the vulnerability-threshold policy
 */
function evaluateVulnerabilityThreshold(input: OpaEvaluationInput): OpaViolation[] {
  const violations: OpaViolation[] = [];
  const vulns = input.scan.vulnerabilities;
  const highThreshold = input.thresholds?.high ?? 10;

  if (vulns.critical > 0) {
    violations.push({
      type: "vulnerability_threshold",
      severity: "critical",
      code: "critical_vulnerabilities",
      message: `Found ${vulns.critical} critical vulnerabilities`,
      remediation: "Fix all critical vulnerabilities before deployment",
    });
  }

  if (vulns.high > highThreshold) {
    violations.push({
      type: "vulnerability_threshold",
      severity: "high",
      code: "high_vulnerabilities_exceeded",
      message: `Found ${vulns.high} high vulnerabilities (max: ${highThreshold})`,
      remediation: "Reduce high severity vulnerabilities below threshold",
    });
  }

  return violations;
}

/**
 * Evaluate the license-compliance policy
 */
function evaluateLicenseCompliance(input: OpaEvaluationInput): OpaViolation[] {
  const violations: OpaViolation[] = [];
  const licenses = input.scan.licenses ?? [];

  for (const license of licenses) {
    if (BLOCKED_LICENSES.has(license)) {
      violations.push({
        type: "license_violation",
        severity: "critical",
        code: "blocked_license",
        message: `Blocked license found: ${license}`,
        resource: license,
        remediation: "Replace dependency with a permissively licensed alternative",
      });
    } else if (RESTRICTED_LICENSES.has(license)) {
      violations.push({
        type: "license_warning",
        severity: "medium",
        code: "restricted_license",
        message: `Restricted license found: ${license}`,
        resource: license,
        remediation: "Review license compatibility with your project",
      });
    }
  }

  return violations;
}

/**
 * Evaluate the secrets-detection policy
 */
function evaluateSecretsDetection(input: OpaEvaluationInput): OpaViolation[] {
  const violations: OpaViolation[] = [];

  if (input.scan.secretsFound) {
    violations.push({
      type: "secrets_detected",
      severity: "critical",
      code: "secrets_in_code",
      message: "Secrets detected in scan results",
      remediation: "Remove hardcoded secrets and use environment variables or secret management",
    });
  }

  return violations;
}

/**
 * Evaluate the container-security policy
 */
function evaluateContainerSecurity(input: OpaEvaluationInput): OpaViolation[] {
  const violations: OpaViolation[] = [];
  const vulns = input.scan.vulnerabilities;

  if (vulns.critical > 0) {
    violations.push({
      type: "container_vulnerability",
      severity: "critical",
      code: "container_critical_vuln",
      message: `Container has ${vulns.critical} critical vulnerabilities`,
      remediation: "Update base image and vulnerable packages",
    });
  }

  if (input.image && input.image.includes(":latest")) {
    violations.push({
      type: "container_config",
      severity: "medium",
      code: "latest_tag_used",
      message: "Using 'latest' tag is not recommended for production",
      resource: input.image,
      remediation: "Use specific version tags for container images",
    });
  }

  const runAsRoot = input.metadata?.runAsRoot;
  if (runAsRoot === true) {
    violations.push({
      type: "container_config",
      severity: "high",
      code: "runs_as_root",
      message: "Container runs as root user",
      remediation: "Configure container to run as non-root user",
    });
  }

  return violations;
}

/**
 * Evaluate the quality-gate policy
 */
function evaluateQualityGate(input: OpaEvaluationInput): OpaViolation[] {
  const violations: OpaViolation[] = [];
  const coverageThreshold = input.thresholds?.coverage ?? 80;

  if (input.scan.qualityGatePassed === false) {
    violations.push({
      type: "quality_gate",
      severity: "high",
      code: "quality_gate_failed",
      message: "Quality gate check failed",
      remediation: "Fix code quality issues to pass the quality gate",
    });
  }

  const coverage = input.scan.codeCoverage;
  if (coverage !== undefined && coverage < coverageThreshold) {
    violations.push({
      type: "code_coverage",
      severity: "medium",
      code: "low_code_coverage",
      message: `Code coverage ${coverage.toFixed(1)}% is below minimum ${coverageThreshold}%`,
      remediation: "Increase test coverage to meet the minimum threshold",
    });
  }

  return violations;
}

/**
 * Evaluate an inline/custom Rego policy (basic pattern matching)
 * This is a simplified implementation for common patterns.
 */
function evaluateInlinePolicy(input: OpaEvaluationInput, policy: string): OpaViolation[] {
  const violations: OpaViolation[] = [];

  // Check for critical vulnerability rule
  if (
    policy.includes("vulnerabilities.critical") &&
    policy.includes("critical") &&
    input.scan.vulnerabilities.critical > 0
  ) {
    violations.push({
      type: "custom_policy",
      severity: "critical",
      code: "custom_critical_vuln",
      message: `Custom policy violation: ${input.scan.vulnerabilities.critical} critical vulnerabilities`,
    });
  }

  // Check for secrets rule
  if (policy.includes("secretsFound") && input.scan.secretsFound) {
    violations.push({
      type: "custom_policy",
      severity: "critical",
      code: "custom_secrets",
      message: "Custom policy violation: secrets detected",
    });
  }

  // Check for license patterns
  if (policy.includes("licenses")) {
    const licenses = input.scan.licenses ?? [];
    for (const license of licenses) {
      if (
        policy.includes(license) ||
        (policy.includes("GPL") && license.includes("GPL")) ||
        (policy.includes("AGPL") && license.includes("AGPL"))
      ) {
        violations.push({
          type: "custom_policy",
          severity: "high",
          code: "custom_license",
          message: `Custom policy violation: license ${license}`,
          resource: license,
        });
      }
    }
  }

  return violations;
}

// =============================================================================
// PUBLIC API
// =============================================================================

/**
 * List all available built-in OPA policies
 */
export function listBuiltinPolicies(): OpaPolicyInfo[] {
  return Object.entries(BUILTIN_POLICIES).map(([name, source]) => {
    const metadata = POLICY_METADATA[name] || {
      description: "No description available",
      entrypoints: ["security/allow"],
    };

    // Count rules (simplified: count 'violations contains' and 'allow if')
    const ruleCount =
      (source.match(/violations contains/g) || []).length +
      (source.match(/allow if/g) || []).length +
      (source.match(/default allow/g) || []).length;

    return {
      name,
      version: "1.0.0",
      description: metadata.description,
      entrypoints: metadata.entrypoints,
      ruleCount,
      source: "builtin" as const,
    };
  });
}

/**
 * Get a built-in policy by name
 */
export function getBuiltinPolicy(name: string): string | undefined {
  return BUILTIN_POLICIES[name];
}

/**
 * Get detailed information about a built-in policy
 */
export function getBuiltinPolicyInfo(name: string): OpaPolicyInfo | undefined {
  const source = BUILTIN_POLICIES[name];
  if (!source) return undefined;

  const metadata = POLICY_METADATA[name] || {
    description: "No description available",
    entrypoints: ["security/allow"],
  };

  const ruleCount =
    (source.match(/violations contains/g) || []).length +
    (source.match(/allow if/g) || []).length +
    (source.match(/default allow/g) || []).length;

  return {
    name,
    version: "1.0.0",
    description: metadata.description,
    entrypoints: metadata.entrypoints,
    ruleCount,
    source: "builtin",
  };
}

/**
 * Validate Rego policy syntax (basic validation)
 */
export function validateRegoSyntax(regoSource: string): OpaValidationResult {
  const errors: string[] = [];

  // Check for package declaration
  if (!regoSource.includes("package ")) {
    errors.push("Missing package declaration");
  }

  // Check for balanced braces
  const openBraces = (regoSource.match(/{/g) || []).length;
  const closeBraces = (regoSource.match(/}/g) || []).length;
  if (openBraces !== closeBraces) {
    errors.push(`Unbalanced braces: ${openBraces} open, ${closeBraces} close`);
  }

  // Check for balanced brackets
  const openBrackets = (regoSource.match(/\[/g) || []).length;
  const closeBrackets = (regoSource.match(/\]/g) || []).length;
  if (openBrackets !== closeBrackets) {
    errors.push(`Unbalanced brackets: ${openBrackets} open, ${closeBrackets} close`);
  }

  // Check for common syntax patterns
  if (regoSource.includes("if {") && !regoSource.includes("if {\n")) {
    // This is fine, inline if
  }

  // Check for rule definitions
  if (
    !regoSource.includes(" := ") &&
    !regoSource.includes(" contains ") &&
    !regoSource.includes(" if ")
  ) {
    errors.push("No rule definitions found (missing :=, contains, or if)");
  }

  return {
    valid: errors.length === 0,
    errors: errors.length > 0 ? errors : undefined,
  };
}

/**
 * Compute a hash of the input for caching/debugging
 */
function computeInputHash(input: OpaEvaluationInput): string {
  const str = JSON.stringify(input);
  return createHash("sha256").update(str).digest("hex").substring(0, 16);
}

/**
 * Evaluate an OPA policy against scan input
 */
export async function evaluateOpaPolicy(
  input: OpaEvaluationInput,
  options: OpaPolicyOptions
): Promise<OpaEvaluationResult> {
  const policyName = options.policy;
  const evaluatedAt = new Date().toISOString();
  let violations: OpaViolation[] = [];
  let usedPolicyName = policyName;

  // Check if it's a built-in policy
  if (BUILTIN_POLICIES[policyName]) {
    switch (policyName) {
      case "vulnerability-threshold":
        violations = evaluateVulnerabilityThreshold(input);
        break;
      case "license-compliance":
        violations = evaluateLicenseCompliance(input);
        break;
      case "secrets-detection":
        violations = evaluateSecretsDetection(input);
        break;
      case "container-security":
        violations = evaluateContainerSecurity(input);
        break;
      case "quality-gate":
        violations = evaluateQualityGate(input);
        break;
      default:
        // Unknown built-in, try inline evaluation
        violations = evaluateInlinePolicy(input, BUILTIN_POLICIES[policyName]);
    }
  } else if (policyName.includes("package ") || policyName.includes(":=")) {
    // Looks like inline Rego code
    usedPolicyName = "inline";
    violations = evaluateInlinePolicy(input, policyName);
  } else {
    throw new Error(
      `Unknown policy: ${policyName}. Use a built-in policy name or provide inline Rego code.`
    );
  }

  // Determine if policy allows the input
  // Policy passes if there are no critical or high violations (configurable)
  const hasCriticalViolation = violations.some((v) => v.severity === "critical");
  const hasHighViolation = violations.some((v) => v.severity === "high");
  const allow = !hasCriticalViolation && !hasHighViolation;

  return {
    allow,
    violations,
    metadata: {
      policyName: usedPolicyName,
      policyVersion: "1.0.0",
      evaluatedAt,
      inputHash: computeInputHash(input),
    },
  };
}

/**
 * Evaluate multiple policies and merge results
 */
export async function evaluateMultiplePolicies(
  input: OpaEvaluationInput,
  policies: string[]
): Promise<OpaEvaluationResult> {
  const allViolations: OpaViolation[] = [];
  const policyNames: string[] = [];

  for (const policy of policies) {
    const result = await evaluateOpaPolicy(input, { policy });
    allViolations.push(...result.violations);
    policyNames.push(result.metadata.policyName);
  }

  const hasCriticalViolation = allViolations.some((v) => v.severity === "critical");
  const hasHighViolation = allViolations.some((v) => v.severity === "high");

  return {
    allow: !hasCriticalViolation && !hasHighViolation,
    violations: allViolations,
    metadata: {
      policyName: policyNames.join(", "),
      policyVersion: "1.0.0",
      evaluatedAt: new Date().toISOString(),
      inputHash: computeInputHash(input),
    },
  };
}

// =============================================================================
// SCAN RESULT CONVERSION UTILITIES
// =============================================================================

/**
 * Convert ScanResults (from policy.ts) to OPA input format
 */
export function scanResultsToOpaInput(
  scanResults: ScanResults,
  metadata?: Record<string, unknown>
): OpaEvaluationInput {
  const vulns = scanResults.vulnerabilities || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  };
  const total = vulns.critical + vulns.high + vulns.medium + vulns.low + vulns.unknown;

  return {
    scan: {
      vulnerabilities: {
        critical: vulns.critical,
        high: vulns.high,
        medium: vulns.medium,
        low: vulns.low,
        unknown: vulns.unknown,
        total,
      },
      licenses: scanResults.licenses,
      secretsFound: scanResults.secretsFound,
      codeCoverage: scanResults.codeCoverage,
      qualityGatePassed: scanResults.qualityGatePassed,
    },
    metadata,
  };
}

/**
 * Convert TrivyScanResult to OPA input format
 */
export function trivyResultToOpaInput(
  trivyResult: TrivyScanResult,
  image?: string,
  path?: string
): OpaEvaluationInput {
  // Count vulnerabilities by severity
  const vulnCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
    total: 0,
  };

  let hasSecrets = false;
  const licenses = new Set<string>();

  for (const result of trivyResult.Results ?? []) {
    for (const vuln of result.Vulnerabilities ?? []) {
      vulnCounts.total++;
      switch (vuln.Severity) {
        case "CRITICAL":
          vulnCounts.critical++;
          break;
        case "HIGH":
          vulnCounts.high++;
          break;
        case "MEDIUM":
          vulnCounts.medium++;
          break;
        case "LOW":
          vulnCounts.low++;
          break;
        default:
          vulnCounts.unknown++;
      }
    }

    if (result.Secrets && result.Secrets.length > 0) {
      hasSecrets = true;
    }
  }

  return {
    scan: {
      vulnerabilities: vulnCounts,
      licenses: Array.from(licenses),
      secretsFound: hasSecrets,
    },
    image,
    path,
    metadata: {
      artifactName: trivyResult.ArtifactName,
      artifactType: trivyResult.ArtifactType,
    },
  };
}

/**
 * Convert SecurityDashboardResult to OPA input format
 */
export function dashboardResultToOpaInput(
  dashboardResult: SecurityDashboardResult
): OpaEvaluationInput {
  const summary = dashboardResult.summary;
  const sonar = dashboardResult.bySource.sonarqube;

  return {
    scan: {
      vulnerabilities: {
        critical: summary.critical,
        high: summary.high,
        medium: summary.medium,
        low: summary.low,
        total: summary.total,
      },
      qualityGatePassed:
        "qualityGateStatus" in sonar ? sonar.qualityGateStatus === "OK" : undefined,
    },
    image: dashboardResult.scanTargets.image,
    path: dashboardResult.scanTargets.path,
    metadata: {
      sonarProject: dashboardResult.scanTargets.sonarProject,
      dtrackProject: dashboardResult.scanTargets.dtrackProject,
    },
  };
}

/**
 * Create an OPA input from raw vulnerability counts
 */
export function createOpaInput(options: {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  licenses?: string[];
  secretsFound?: boolean;
  codeCoverage?: number;
  qualityGatePassed?: boolean;
  image?: string;
  path?: string;
  thresholds?: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    coverage?: number;
  };
  metadata?: Record<string, unknown>;
}): OpaEvaluationInput {
  const critical = options.critical ?? 0;
  const high = options.high ?? 0;
  const medium = options.medium ?? 0;
  const low = options.low ?? 0;

  return {
    scan: {
      vulnerabilities: {
        critical,
        high,
        medium,
        low,
        total: critical + high + medium + low,
      },
      licenses: options.licenses,
      secretsFound: options.secretsFound,
      codeCoverage: options.codeCoverage,
      qualityGatePassed: options.qualityGatePassed,
    },
    image: options.image,
    path: options.path,
    thresholds: options.thresholds,
    metadata: options.metadata,
  };
}
