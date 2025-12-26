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
 * Check a single vulnerability threshold
 */
function checkThreshold(
  ruleName: string,
  severityName: string,
  count: number,
  threshold: number | undefined,
  isError: boolean
): PolicyViolation | null {
  if (threshold === undefined || count <= threshold) {
    return null;
  }
  return {
    rule: ruleName,
    reason: `${severityName} vulnerabilities (${count}) exceed threshold (${threshold})`,
    severity: isError ? "error" : "warning",
  };
}

/**
 * Check all vulnerability thresholds
 */
function checkVulnerabilityThresholds(
  rule: PolicyRule,
  vulns: VulnerabilitySummary
): PolicyViolation[] {
  const thresholds = rule.maxVulnerabilities;
  if (!thresholds) return [];

  const checks = [
    checkThreshold(rule.name, "Critical", vulns.critical, thresholds.critical, true),
    checkThreshold(rule.name, "High", vulns.high, thresholds.high, true),
    checkThreshold(rule.name, "Medium", vulns.medium, thresholds.medium, false),
    checkThreshold(rule.name, "Low", vulns.low, thresholds.low, false),
  ];

  return checks.filter((v): v is PolicyViolation => v !== null);
}

/**
 * Check for blocked licenses
 */
function checkBlockedLicenses(rule: PolicyRule, licenses: string[]): PolicyViolation | null {
  if (!rule.blockedLicenses) return null;

  const blocked = licenses.filter((license) =>
    rule.blockedLicenses!.some((blockedLicense) =>
      license.toLowerCase().includes(blockedLicense.toLowerCase())
    )
  );

  if (blocked.length === 0) return null;

  return {
    rule: rule.name,
    reason: `Blocked licenses found: ${blocked.join(", ")}`,
    severity: "error",
  };
}

/**
 * Evaluate a single rule against scan results
 */
function evaluateRule(rule: PolicyRule, results: ScanResults): PolicyViolation[] {
  const violations: PolicyViolation[] = [];

  // Check vulnerability thresholds
  if (results.vulnerabilities) {
    violations.push(...checkVulnerabilityThresholds(rule, results.vulnerabilities));
  }

  // Check for blocked licenses
  if (results.licenses) {
    const licenseViolation = checkBlockedLicenses(rule, results.licenses);
    if (licenseViolation) violations.push(licenseViolation);
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
  if (
    rule.minCodeCoverage !== undefined &&
    results.codeCoverage !== undefined &&
    results.codeCoverage < rule.minCodeCoverage
  ) {
    violations.push({
      rule: rule.name,
      reason: `Code coverage (${results.codeCoverage}%) below minimum (${rule.minCodeCoverage}%)`,
      severity: "error",
    });
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
function filterIgnored(vulns: VulnerabilitySummary, rule: PolicyRule): VulnerabilitySummary {
  const ignoreCves = rule.ignoreCves || [];
  const ignorePackages = rule.ignorePackages || [];

  // If nothing to ignore, return as-is
  if (ignoreCves.length === 0 && ignorePackages.length === 0) {
    return vulns;
  }

  // If no CVEs/packages to filter, return as-is
  if (!vulns.cves && !vulns.packages) {
    return vulns;
  }

  // Filter out ignored CVEs
  const filteredCves = vulns.cves?.filter(
    (cve) => !ignoreCves.some((ignored) => cve.toLowerCase() === ignored.toLowerCase())
  );

  // Filter out ignored packages
  const filteredPackages = vulns.packages?.filter(
    (pkg) => !ignorePackages.some((ignored) => pkg.toLowerCase().includes(ignored.toLowerCase()))
  );

  // Calculate how many were filtered
  const cveFiltered = (vulns.cves?.length || 0) - (filteredCves?.length || 0);
  const pkgFiltered = (vulns.packages?.length || 0) - (filteredPackages?.length || 0);
  const totalFiltered = cveFiltered + pkgFiltered;

  // Return adjusted summary (proportionally reduce counts as a simple heuristic)
  if (totalFiltered === 0) {
    return vulns;
  }

  return {
    ...vulns,
    cves: filteredCves,
    packages: filteredPackages,
  };
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
