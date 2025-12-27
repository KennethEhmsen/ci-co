/**
 * Vulnerability Remediation Module
 *
 * Generates actionable remediation suggestions for discovered vulnerabilities,
 * including specific commands to fix issues across different package managers.
 */

import type {
  TrivyScanResult,
  TrivyVulnerability,
  PackageManager,
  RemediationConfidence,
  VulnerabilityInfo,
  RemediationSuggestion,
  RemediationPlan,
  RemediationOptions,
} from "./types.js";

// =============================================================================
// Constants
// =============================================================================

/** Severity ordering for sorting */
const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
};

/** Package type to package manager mapping */
const TYPE_TO_MANAGER: Record<string, PackageManager> = {
  "node-pkg": "npm",
  npm: "npm",
  yarn: "yarn",
  pnpm: "pnpm",
  pip: "pip",
  pipenv: "pipenv",
  poetry: "poetry",
  "python-pkg": "pip",
  go: "go",
  gomod: "go",
  gobinary: "go",
  maven: "maven",
  gradle: "gradle",
  jar: "maven",
  gemspec: "gem",
  bundler: "gem",
  cargo: "cargo",
  "rust-binary": "cargo",
};

// =============================================================================
// Version Utilities
// =============================================================================

/**
 * Parse a semantic version string into components
 */
function parseVersion(version: string): { major: number; minor: number; patch: number } | null {
  // Remove leading 'v' if present
  const cleaned = version.replace(/^v/, "");
  const match = cleaned.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?/);

  if (!match) {
    return null;
  }

  return {
    major: Number.parseInt(match[1], 10),
    minor: Number.parseInt(match[2] || "0", 10),
    patch: Number.parseInt(match[3] || "0", 10),
  };
}

/**
 * Check if updating from one version to another is a breaking change
 */
export function isBreakingChange(currentVersion: string, fixedVersion: string): boolean {
  const current = parseVersion(currentVersion);
  const fixed = parseVersion(fixedVersion);

  if (!current || !fixed) {
    return false; // Can't determine, assume non-breaking
  }

  // Major version bump is breaking
  return fixed.major > current.major;
}

/**
 * Determine confidence level based on vulnerability and fix information
 */
function determineConfidence(
  vuln: TrivyVulnerability,
  packageManager: PackageManager
): RemediationConfidence {
  // High confidence if we have a fixed version
  if (vuln.FixedVersion && vuln.FixedVersion !== "none" && vuln.FixedVersion !== "") {
    // Lower confidence for less common package managers
    if (["cargo", "gem", "gradle"].includes(packageManager)) {
      return "medium";
    }
    return "high";
  }

  // Low confidence if no fixed version
  return "low";
}

// =============================================================================
// Command Generation
// =============================================================================

/**
 * Generate the fix command for a specific package manager
 */
export function generateFixCommand(
  packageManager: PackageManager,
  packageName: string,
  fixedVersion: string
): string {
  // Handle "none" or empty fixed version
  if (!fixedVersion || fixedVersion === "none" || fixedVersion === "") {
    return `# No fix available for ${packageName}`;
  }

  switch (packageManager) {
    case "npm":
      return `npm install ${packageName}@${fixedVersion}`;

    case "yarn":
      return `yarn add ${packageName}@${fixedVersion}`;

    case "pnpm":
      return `pnpm add ${packageName}@${fixedVersion}`;

    case "pip":
      return `pip install ${packageName}==${fixedVersion}`;

    case "poetry":
      return `poetry add ${packageName}@${fixedVersion}`;

    case "pipenv":
      return `pipenv install ${packageName}==${fixedVersion}`;

    case "go":
      return `go get ${packageName}@v${fixedVersion}`;

    case "maven":
      return `# Update ${packageName} to version ${fixedVersion} in pom.xml`;

    case "gradle":
      return `# Update ${packageName} to version ${fixedVersion} in build.gradle`;

    case "gem":
      return `gem install ${packageName} -v ${fixedVersion}`;

    case "cargo":
      return `cargo update -p ${packageName} --precise ${fixedVersion}`;

    default:
      return `# Update ${packageName} to ${fixedVersion}`;
  }
}

/**
 * Detect package manager from Trivy result type
 */
export function detectPackageManager(type: string): PackageManager {
  const normalized = type.toLowerCase();
  return TYPE_TO_MANAGER[normalized] || "npm";
}

// =============================================================================
// Remediation Generation
// =============================================================================

/**
 * Extract vulnerability info for remediation context
 */
function extractVulnerabilityInfo(vuln: TrivyVulnerability): VulnerabilityInfo {
  return {
    id: vuln.VulnerabilityID,
    severity: vuln.Severity,
    title: vuln.Title,
    url: vuln.PrimaryURL,
  };
}

/**
 * Create a remediation suggestion from a vulnerability
 */
function createSuggestion(
  vuln: TrivyVulnerability,
  packageManager: PackageManager
): RemediationSuggestion | null {
  // Skip if no fixed version available
  if (!vuln.FixedVersion || vuln.FixedVersion === "none" || vuln.FixedVersion === "") {
    return null;
  }

  const breaking = isBreakingChange(vuln.InstalledVersion, vuln.FixedVersion);
  const confidence = determineConfidence(vuln, packageManager);
  const command = generateFixCommand(packageManager, vuln.PkgName, vuln.FixedVersion);

  return {
    vulnerability: extractVulnerabilityInfo(vuln),
    package: vuln.PkgName,
    currentVersion: vuln.InstalledVersion,
    fixedVersion: vuln.FixedVersion,
    command,
    packageManager,
    breaking,
    cvesFixed: [vuln.VulnerabilityID],
    confidence,
    notes: breaking ? "This is a major version update and may contain breaking changes" : undefined,
  };
}

/**
 * Merge suggestions for the same package
 * When multiple CVEs affect the same package, combine them into one suggestion
 */
function mergeSuggestions(suggestions: RemediationSuggestion[]): RemediationSuggestion[] {
  const byPackage = new Map<string, RemediationSuggestion>();

  for (const suggestion of suggestions) {
    const key = `${suggestion.packageManager}:${suggestion.package}`;
    const existing = byPackage.get(key);

    if (!existing) {
      byPackage.set(key, suggestion);
    } else {
      // Merge CVEs fixed
      const allCves = new Set([...existing.cvesFixed, ...suggestion.cvesFixed]);
      existing.cvesFixed = Array.from(allCves);

      // Use the highest severity
      if (
        SEVERITY_ORDER[suggestion.vulnerability.severity] >
        SEVERITY_ORDER[existing.vulnerability.severity]
      ) {
        existing.vulnerability = suggestion.vulnerability;
      }

      // Use the highest fixed version (simplified comparison)
      if (suggestion.fixedVersion > existing.fixedVersion) {
        existing.fixedVersion = suggestion.fixedVersion;
        existing.command = generateFixCommand(
          existing.packageManager,
          existing.package,
          suggestion.fixedVersion
        );
        existing.breaking = isBreakingChange(existing.currentVersion, suggestion.fixedVersion);
      }
    }
  }

  return Array.from(byPackage.values());
}

/**
 * Sort suggestions based on options
 */
function sortSuggestions(
  suggestions: RemediationSuggestion[],
  sortBy: RemediationOptions["sortBy"] = "severity"
): RemediationSuggestion[] {
  return [...suggestions].sort((a, b) => {
    switch (sortBy) {
      case "cvesFixed":
        return b.cvesFixed.length - a.cvesFixed.length;
      case "package":
        return a.package.localeCompare(b.package);
      case "severity":
      default:
        return SEVERITY_ORDER[b.vulnerability.severity] - SEVERITY_ORDER[a.vulnerability.severity];
    }
  });
}

/**
 * Filter suggestions based on options
 */
function filterSuggestions(
  suggestions: RemediationSuggestion[],
  options: RemediationOptions
): RemediationSuggestion[] {
  let filtered = suggestions;

  // Filter by minimum severity
  if (options.minSeverity) {
    const minOrder = SEVERITY_ORDER[options.minSeverity];
    filtered = filtered.filter((s) => SEVERITY_ORDER[s.vulnerability.severity] >= minOrder);
  }

  // Filter out breaking changes if requested
  if (options.includeBreaking === false) {
    filtered = filtered.filter((s) => !s.breaking);
  }

  // Filter by package managers
  if (options.packageManagers && options.packageManagers.length > 0) {
    filtered = filtered.filter((s) => options.packageManagers!.includes(s.packageManager));
  }

  // Apply limit
  if (options.limit && options.limit > 0) {
    filtered = filtered.slice(0, options.limit);
  }

  return filtered;
}

/**
 * Generate remediation suggestions from a Trivy scan result
 *
 * @param scanResult - Trivy scan result
 * @param options - Remediation options
 * @returns Remediation plan with suggestions and commands
 *
 * @example
 * ```typescript
 * const scanResult = await trivyScanPath("./");
 * const plan = generateRemediations(scanResult, {
 *   minSeverity: "HIGH",
 *   includeBreaking: false,
 * });
 * console.log(plan.commands);
 * ```
 */
export function generateRemediations(
  scanResult: TrivyScanResult,
  options: RemediationOptions = {}
): RemediationPlan {
  const suggestions: RemediationSuggestion[] = [];

  // Process each result target
  for (const result of scanResult.Results || []) {
    if (!result.Vulnerabilities) {
      continue;
    }

    const packageManager = detectPackageManager(result.Type);

    for (const vuln of result.Vulnerabilities) {
      const suggestion = createSuggestion(vuln, packageManager);
      if (suggestion) {
        suggestions.push(suggestion);
      }
    }
  }

  // Merge suggestions for the same package
  let merged = mergeSuggestions(suggestions);

  // Sort suggestions
  merged = sortSuggestions(merged, options.sortBy);

  // Filter suggestions
  merged = filterSuggestions(merged, options);

  // Build the plan
  const allCves = new Set<string>();
  let breakingCount = 0;
  const byPackageManager: RemediationPlan["byPackageManager"] =
    {} as RemediationPlan["byPackageManager"];
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const commands: string[] = [];

  for (const suggestion of merged) {
    // Collect CVEs
    suggestion.cvesFixed.forEach((cve) => allCves.add(cve));

    // Count breaking changes
    if (suggestion.breaking) {
      breakingCount++;
    }

    // Group by package manager
    if (!byPackageManager[suggestion.packageManager]) {
      byPackageManager[suggestion.packageManager] = { count: 0, commands: [] };
    }
    byPackageManager[suggestion.packageManager].count++;
    byPackageManager[suggestion.packageManager].commands.push(suggestion.command);

    // Count by severity
    switch (suggestion.vulnerability.severity) {
      case "CRITICAL":
        bySeverity.critical++;
        break;
      case "HIGH":
        bySeverity.high++;
        break;
      case "MEDIUM":
        bySeverity.medium++;
        break;
      case "LOW":
        bySeverity.low++;
        break;
    }

    // Add to ordered commands
    commands.push(suggestion.command);
  }

  return {
    generatedAt: new Date().toISOString(),
    scanTarget: scanResult.ArtifactName || "unknown",
    suggestions: merged,
    totalCvesFixed: allCves.size,
    breakingChanges: breakingCount,
    commands,
    byPackageManager,
    bySeverity,
  };
}

/**
 * Get a summary of the remediation plan
 */
export function getRemediationSummary(plan: RemediationPlan): string {
  const lines = [
    `Remediation Plan for: ${plan.scanTarget}`,
    `${"=".repeat(50)}`,
    "",
    `Total Suggestions: ${plan.suggestions.length}`,
    `CVEs Fixed: ${plan.totalCvesFixed}`,
    `Breaking Changes: ${plan.breakingChanges}`,
    "",
    "By Severity:",
    `  Critical: ${plan.bySeverity.critical}`,
    `  High: ${plan.bySeverity.high}`,
    `  Medium: ${plan.bySeverity.medium}`,
    `  Low: ${plan.bySeverity.low}`,
    "",
    "Commands to Run:",
  ];

  for (const command of plan.commands) {
    lines.push(`  ${command}`);
  }

  return lines.join("\n");
}

/**
 * Format remediation plan as markdown
 */
export function formatRemediationAsMarkdown(plan: RemediationPlan): string {
  const lines = [
    `# Remediation Plan`,
    "",
    `**Target:** ${plan.scanTarget}`,
    `**Generated:** ${plan.generatedAt}`,
    "",
    "## Summary",
    "",
    `| Metric | Value |`,
    `|--------|-------|`,
    `| Total Suggestions | ${plan.suggestions.length} |`,
    `| CVEs Fixed | ${plan.totalCvesFixed} |`,
    `| Breaking Changes | ${plan.breakingChanges} |`,
    `| Critical | ${plan.bySeverity.critical} |`,
    `| High | ${plan.bySeverity.high} |`,
    `| Medium | ${plan.bySeverity.medium} |`,
    `| Low | ${plan.bySeverity.low} |`,
    "",
    "## Remediation Steps",
    "",
  ];

  for (const suggestion of plan.suggestions) {
    lines.push(
      `### ${suggestion.package}`,
      "",
      `- **Vulnerability:** ${suggestion.vulnerability.id}`,
      `- **Severity:** ${suggestion.vulnerability.severity}`,
      `- **Current Version:** ${suggestion.currentVersion}`,
      `- **Fixed Version:** ${suggestion.fixedVersion}`
    );
    if (suggestion.breaking) {
      lines.push(`- **⚠️ Breaking Change:** Major version update`);
    }
    lines.push(
      `- **CVEs Fixed:** ${suggestion.cvesFixed.join(", ")}`,
      "",
      "```bash",
      suggestion.command,
      "```",
      ""
    );
  }

  lines.push("## Quick Fix Commands", "", "```bash", ...plan.commands, "```");

  return lines.join("\n");
}

/**
 * Get high-priority remediations (critical and high severity only)
 */
export function getHighPriorityRemediations(
  scanResult: TrivyScanResult,
  limit: number = 10
): RemediationPlan {
  return generateRemediations(scanResult, {
    minSeverity: "HIGH",
    includeBreaking: true,
    limit,
    sortBy: "severity",
  });
}

/**
 * Get safe remediations (non-breaking changes only)
 */
export function getSafeRemediations(
  scanResult: TrivyScanResult,
  limit: number = 20
): RemediationPlan {
  return generateRemediations(scanResult, {
    includeBreaking: false,
    limit,
    sortBy: "cvesFixed",
  });
}
