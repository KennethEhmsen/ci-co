/**
 * Policy-based Scan Gating
 *
 * Allows defining policies to determine pass/fail based on scan results.
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export interface SeverityThresholds {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  unknown?: number;
}

export interface PolicyRule {
  /** Rule name for identification */
  name: string;
  /** Rule description */
  description?: string;
  /** Maximum allowed vulnerabilities by severity */
  maxVulnerabilities?: SeverityThresholds;
  /** CVEs to ignore (e.g., ["CVE-2023-12345"]) */
  ignoreCves?: string[];
  /** Packages to ignore (e.g., ["lodash", "express"]) */
  ignorePackages?: string[];
  /** License types to block (e.g., ["GPL-3.0", "AGPL-3.0"]) */
  blockedLicenses?: string[];
  /** Required minimum code coverage percentage */
  minCodeCoverage?: number;
  /** Required quality gate status */
  requireQualityGatePass?: boolean;
  /** Block if secrets are found */
  blockOnSecrets?: boolean;
}

export interface Policy {
  /** Policy name */
  name: string;
  /** Policy version */
  version: string;
  /** Policy description */
  description?: string;
  /** Rules to evaluate */
  rules: PolicyRule[];
  /** Whether all rules must pass (AND) or any rule can pass (OR) */
  mode: "all" | "any";
}

export interface VulnerabilitySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  cves?: string[];
  packages?: string[];
}

export interface ScanResults {
  vulnerabilities?: VulnerabilitySummary;
  licenses?: string[];
  secretsFound?: boolean;
  codeCoverage?: number;
  qualityGatePassed?: boolean;
}

export interface PolicyViolation {
  rule: string;
  reason: string;
  severity: "error" | "warning";
}

export interface PolicyEvaluationResult {
  passed: boolean;
  policy: string;
  violations: PolicyViolation[];
  evaluatedAt: string;
}

/**
 * Evaluate a single rule against scan results
 */
function evaluateRule(rule: PolicyRule, results: ScanResults): PolicyViolation[] {
  const violations: PolicyViolation[] = [];

  // Check vulnerability thresholds
  if (rule.maxVulnerabilities && results.vulnerabilities) {
    const vulns = results.vulnerabilities;
    const thresholds = rule.maxVulnerabilities;

    if (thresholds.critical !== undefined && vulns.critical > thresholds.critical) {
      violations.push({
        rule: rule.name,
        reason: `Critical vulnerabilities (${vulns.critical}) exceed threshold (${thresholds.critical})`,
        severity: "error",
      });
    }
    if (thresholds.high !== undefined && vulns.high > thresholds.high) {
      violations.push({
        rule: rule.name,
        reason: `High vulnerabilities (${vulns.high}) exceed threshold (${thresholds.high})`,
        severity: "error",
      });
    }
    if (thresholds.medium !== undefined && vulns.medium > thresholds.medium) {
      violations.push({
        rule: rule.name,
        reason: `Medium vulnerabilities (${vulns.medium}) exceed threshold (${thresholds.medium})`,
        severity: "warning",
      });
    }
    if (thresholds.low !== undefined && vulns.low > thresholds.low) {
      violations.push({
        rule: rule.name,
        reason: `Low vulnerabilities (${vulns.low}) exceed threshold (${thresholds.low})`,
        severity: "warning",
      });
    }
  }

  // Check for blocked licenses
  if (rule.blockedLicenses && results.licenses) {
    const blocked = results.licenses.filter((license) =>
      rule.blockedLicenses!.some((blockedLicense) =>
        license.toLowerCase().includes(blockedLicense.toLowerCase())
      )
    );
    if (blocked.length > 0) {
      violations.push({
        rule: rule.name,
        reason: `Blocked licenses found: ${blocked.join(", ")}`,
        severity: "error",
      });
    }
  }

  // Check for secrets
  if (rule.blockOnSecrets && results.secretsFound) {
    violations.push({
      rule: rule.name,
      reason: "Secrets were found in the scan",
      severity: "error",
    });
  }

  // Check code coverage
  if (rule.minCodeCoverage !== undefined && results.codeCoverage !== undefined) {
    if (results.codeCoverage < rule.minCodeCoverage) {
      violations.push({
        rule: rule.name,
        reason: `Code coverage (${results.codeCoverage}%) below minimum (${rule.minCodeCoverage}%)`,
        severity: "error",
      });
    }
  }

  // Check quality gate
  if (rule.requireQualityGatePass && results.qualityGatePassed === false) {
    violations.push({
      rule: rule.name,
      reason: "Quality gate did not pass",
      severity: "error",
    });
  }

  return violations;
}

/**
 * Filter out ignored CVEs and packages from vulnerability summary
 */
function filterIgnored(vulns: VulnerabilitySummary, _rule: PolicyRule): VulnerabilitySummary {
  // If no CVEs/packages to check, return as-is
  if (!vulns.cves && !vulns.packages) {
    return vulns;
  }

  // This is a simplified version - in reality you'd need to track
  // which CVEs correspond to which severity counts
  // TODO: Implement CVE/package filtering based on _rule.ignoreCves and _rule.ignorePackages
  return vulns;
}

/**
 * Evaluate a policy against scan results
 */
export function evaluatePolicy(policy: Policy, results: ScanResults): PolicyEvaluationResult {
  const allViolations: PolicyViolation[] = [];
  const rulesPassed: boolean[] = [];

  for (const rule of policy.rules) {
    // Apply filtering for ignored items
    const filteredResults = { ...results };
    if (results.vulnerabilities && (rule.ignoreCves || rule.ignorePackages)) {
      filteredResults.vulnerabilities = filterIgnored(results.vulnerabilities, rule);
    }

    const violations = evaluateRule(rule, filteredResults);
    allViolations.push(...violations);
    rulesPassed.push(violations.filter((v) => v.severity === "error").length === 0);
  }

  // Determine overall pass/fail based on mode
  const passed =
    policy.mode === "all"
      ? rulesPassed.every((p) => p) // All rules must pass
      : rulesPassed.some((p) => p); // At least one rule must pass

  return {
    passed,
    policy: policy.name,
    violations: allViolations,
    evaluatedAt: new Date().toISOString(),
  };
}

/**
 * Default security policy - strict
 */
export const strictPolicy: Policy = {
  name: "strict",
  version: "1.0.0",
  description: "Strict security policy - no critical/high vulnerabilities allowed",
  mode: "all",
  rules: [
    {
      name: "no-critical-vulns",
      description: "Block on any critical vulnerabilities",
      maxVulnerabilities: { critical: 0 },
    },
    {
      name: "limit-high-vulns",
      description: "Allow maximum 5 high vulnerabilities",
      maxVulnerabilities: { high: 5 },
    },
    {
      name: "no-secrets",
      description: "Block if secrets are found",
      blockOnSecrets: true,
    },
    {
      name: "quality-gate",
      description: "Require quality gate to pass",
      requireQualityGatePass: true,
    },
  ],
};

/**
 * Default security policy - standard
 */
export const standardPolicy: Policy = {
  name: "standard",
  version: "1.0.0",
  description: "Standard security policy - balanced security requirements",
  mode: "all",
  rules: [
    {
      name: "vuln-limits",
      description: "Limit vulnerabilities by severity",
      maxVulnerabilities: {
        critical: 0,
        high: 10,
        medium: 50,
      },
    },
    {
      name: "no-secrets",
      description: "Block if secrets are found",
      blockOnSecrets: true,
    },
  ],
};

/**
 * Default security policy - permissive
 */
export const permissivePolicy: Policy = {
  name: "permissive",
  version: "1.0.0",
  description: "Permissive policy - only blocks on critical issues",
  mode: "all",
  rules: [
    {
      name: "critical-only",
      description: "Only block on critical vulnerabilities",
      maxVulnerabilities: { critical: 5 },
    },
  ],
};

/**
 * Get a policy by name
 */
export function getPolicy(name: string): Policy | undefined {
  const policies: Record<string, Policy> = {
    strict: strictPolicy,
    standard: standardPolicy,
    permissive: permissivePolicy,
  };
  return policies[name.toLowerCase()];
}
