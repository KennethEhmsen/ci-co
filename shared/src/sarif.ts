/**
 * SARIF (Static Analysis Results Interchange Format) Formatter
 *
 * Converts security scan results to SARIF 2.1.0 format for integration with
 * GitHub Code Scanning, GitLab SAST, and other security tools.
 *
 * @see https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 * @see https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
 */

import { createHash } from "node:crypto";
import type {
  SarifLog,
  SarifRun,
  SarifResult,
  SarifReportingDescriptor,
  SarifConversionOptions,
  TrivyScanResult,
  TrivyVulnerability,
  TrivySecret,
  SonarIssue,
  DTrackFinding,
  SecurityDashboardResult,
} from "./types.js";

const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION = "2.1.0" as const;

/**
 * Map severity levels to SARIF levels
 */
type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNKNOWN";

function severityToLevel(severity: string): "error" | "warning" | "note" {
  const normalized = severity.toUpperCase() as SeverityLevel;
  switch (normalized) {
    case "CRITICAL":
    case "HIGH":
      return "error";
    case "MEDIUM":
      return "warning";
    case "LOW":
    case "INFO":
    case "UNKNOWN":
    default:
      return "note";
  }
}

/**
 * Generate a stable fingerprint for a finding
 */
function generateFingerprint(ruleId: string, location: string, message: string): string {
  const content = `${ruleId}:${location}:${message}`;
  return createHash("sha256").update(content).digest("hex").slice(0, 16);
}

/**
 * Normalize file path for SARIF (use forward slashes, remove base path)
 */
function normalizePath(filePath: string, basePath?: string): string {
  let normalized = filePath.replaceAll("\\", "/");
  if (basePath) {
    const normalizedBase = basePath.replaceAll("\\", "/");
    if (normalized.startsWith(normalizedBase)) {
      normalized = normalized.slice(normalizedBase.length);
    }
  }
  // Remove leading slash for relative paths
  return normalized.replace(/^\//, "");
}

/**
 * Create an empty SARIF log structure
 */
export function createSarifLog(): SarifLog {
  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [],
  };
}

/**
 * Create a SARIF run for a tool
 */
export function createSarifRun(
  toolName: string,
  toolVersion?: string,
  informationUri?: string
): SarifRun {
  return {
    tool: {
      driver: {
        name: toolName,
        version: toolVersion,
        informationUri,
        rules: [],
      },
    },
    results: [],
    invocations: [
      {
        executionSuccessful: true,
        endTimeUtc: new Date().toISOString(),
      },
    ],
  };
}

/**
 * Convert Trivy vulnerability to SARIF result
 */
function trivyVulnToSarifResult(
  vuln: TrivyVulnerability,
  target: string,
  options?: SarifConversionOptions
): { result: SarifResult; rule: SarifReportingDescriptor } {
  const ruleId = vuln.VulnerabilityID;
  const location = normalizePath(target, options?.basePath);
  const message = `${vuln.PkgName}@${vuln.InstalledVersion}: ${vuln.Title || vuln.VulnerabilityID}`;

  const rule: SarifReportingDescriptor = {
    id: ruleId,
    name: vuln.Title || ruleId,
    shortDescription: { text: vuln.Title || `Vulnerability ${ruleId}` },
    fullDescription: { text: vuln.Description || `Vulnerability in ${vuln.PkgName}` },
    helpUri: vuln.PrimaryURL,
    defaultConfiguration: {
      level: severityToLevel(vuln.Severity),
    },
    properties: {
      severity: vuln.Severity,
      package: vuln.PkgName,
      installedVersion: vuln.InstalledVersion,
      fixedVersion: vuln.FixedVersion,
    },
  };

  const result: SarifResult = {
    ruleId,
    level: severityToLevel(vuln.Severity),
    message: { text: message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: location },
        },
        message: { text: `Package: ${vuln.PkgName}@${vuln.InstalledVersion}` },
      },
    ],
    partialFingerprints: {
      primaryLocationLineHash: generateFingerprint(ruleId, location, message),
    },
    properties: {
      severity: vuln.Severity,
      fixedVersion: vuln.FixedVersion,
    },
  };

  return { result, rule };
}

/**
 * Convert Trivy secret to SARIF result
 */
function trivySecretToSarifResult(
  secret: TrivySecret,
  target: string,
  options?: SarifConversionOptions
): { result: SarifResult; rule: SarifReportingDescriptor } {
  const ruleId = `secret/${secret.RuleID}`;
  const location = normalizePath(target, options?.basePath);
  const message = `${secret.Category}: ${secret.Title}`;

  const rule: SarifReportingDescriptor = {
    id: ruleId,
    name: secret.Title,
    shortDescription: { text: secret.Title },
    fullDescription: { text: `Secret detected: ${secret.Category}` },
    defaultConfiguration: {
      level: severityToLevel(secret.Severity),
    },
    properties: {
      category: secret.Category,
    },
  };

  const result: SarifResult = {
    ruleId,
    level: severityToLevel(secret.Severity),
    message: { text: message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: location },
          region: {
            startLine: secret.StartLine,
            endLine: secret.EndLine,
          },
        },
      },
    ],
    partialFingerprints: {
      primaryLocationLineHash: generateFingerprint(ruleId, location, message),
    },
  };

  return { result, rule };
}

/**
 * Convert Trivy scan results to SARIF format
 */
export function trivyToSarif(
  scanResult: TrivyScanResult,
  options?: SarifConversionOptions
): SarifLog {
  const log = createSarifLog();
  const run = createSarifRun(
    options?.toolName || "Trivy",
    options?.toolVersion || "latest",
    "https://github.com/aquasecurity/trivy"
  );

  const rulesMap = new Map<string, SarifReportingDescriptor>();

  if (scanResult.Results) {
    for (const result of scanResult.Results) {
      // Process vulnerabilities
      if (result.Vulnerabilities) {
        for (const vuln of result.Vulnerabilities) {
          const { result: sarifResult, rule } = trivyVulnToSarifResult(
            vuln,
            result.Target,
            options
          );
          run.results.push(sarifResult);
          if (!rulesMap.has(rule.id)) {
            rulesMap.set(rule.id, rule);
          }
        }
      }

      // Process secrets
      if (result.Secrets) {
        for (const secret of result.Secrets) {
          const { result: sarifResult, rule } = trivySecretToSarifResult(
            secret,
            result.Target,
            options
          );
          run.results.push(sarifResult);
          if (!rulesMap.has(rule.id)) {
            rulesMap.set(rule.id, rule);
          }
        }
      }
    }
  }

  run.tool.driver.rules = Array.from(rulesMap.values());
  log.runs.push(run);
  return log;
}

/**
 * Convert SonarQube issues to SARIF format
 */
export function sonarToSarif(issues: SonarIssue[], options?: SarifConversionOptions): SarifLog {
  const log = createSarifLog();
  const run = createSarifRun(
    options?.toolName || "SonarQube",
    options?.toolVersion,
    "https://www.sonarqube.org/"
  );

  const rulesMap = new Map<string, SarifReportingDescriptor>();

  for (const issue of issues) {
    const ruleId = issue.rule;
    const location = normalizePath(issue.component, options?.basePath);
    const message = issue.message;

    // Map SonarQube severity to SARIF level
    const levelMap: Record<string, "error" | "warning" | "note"> = {
      BLOCKER: "error",
      CRITICAL: "error",
      MAJOR: "warning",
      MINOR: "note",
      INFO: "note",
    };

    const level = levelMap[issue.severity] || "note";

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: ruleId,
        shortDescription: { text: issue.message.slice(0, 100) },
        defaultConfiguration: { level },
        properties: {
          type: issue.type,
        },
      });
    }

    const result: SarifResult = {
      ruleId,
      level,
      message: { text: message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: location },
            region: issue.line ? { startLine: issue.line } : undefined,
          },
        },
      ],
      partialFingerprints: {
        primaryLocationLineHash: generateFingerprint(ruleId, location, message),
      },
      properties: {
        type: issue.type,
        status: issue.status,
        sonarKey: issue.key,
      },
    };

    run.results.push(result);
  }

  run.tool.driver.rules = Array.from(rulesMap.values());
  log.runs.push(run);
  return log;
}

/**
 * Convert Dependency-Track findings to SARIF format
 */
export function dtrackToSarif(
  findings: DTrackFinding[],
  options?: SarifConversionOptions
): SarifLog {
  const log = createSarifLog();
  const run = createSarifRun(
    options?.toolName || "Dependency-Track",
    options?.toolVersion,
    "https://dependencytrack.org/"
  );

  const rulesMap = new Map<string, SarifReportingDescriptor>();

  for (const finding of findings) {
    const vuln = finding.vulnerability;
    const comp = finding.component;
    const ruleId = vuln.vulnId;
    const location = `${comp.name}@${comp.version}`;
    const message = vuln.title || `${vuln.vulnId} in ${comp.name}`;

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: vuln.title || ruleId,
        shortDescription: { text: vuln.title || `Vulnerability ${ruleId}` },
        fullDescription: { text: vuln.description || `Vulnerability in ${comp.name}` },
        defaultConfiguration: {
          level: severityToLevel(vuln.severity),
        },
        properties: {
          source: vuln.source,
          cvssV3BaseScore: vuln.cvssV3BaseScore,
        },
      });
    }

    const result: SarifResult = {
      ruleId,
      level: severityToLevel(vuln.severity),
      message: { text: message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: location },
          },
          message: { text: `Component: ${comp.name}@${comp.version}` },
        },
      ],
      partialFingerprints: {
        primaryLocationLineHash: generateFingerprint(ruleId, location, message),
      },
      properties: {
        severity: vuln.severity,
        source: vuln.source,
        componentUuid: comp.uuid,
        suppressed: finding.analysis?.suppressed,
      },
    };

    run.results.push(result);
  }

  run.tool.driver.rules = Array.from(rulesMap.values());
  log.runs.push(run);
  return log;
}

/**
 * Convert security dashboard results to unified SARIF format
 */
export function dashboardToSarif(
  dashboard: SecurityDashboardResult,
  options?: SarifConversionOptions
): SarifLog {
  const log = createSarifLog();
  const run = createSarifRun(
    options?.toolName || "CI/CD Security Scanner",
    options?.toolVersion || "1.0.0",
    "https://github.com/localadmin/ci-co"
  );

  const rulesMap = new Map<string, SarifReportingDescriptor>();

  // Convert top findings to SARIF results
  for (const finding of dashboard.topFindings) {
    const ruleId = finding.id;
    const location = finding.package || "unknown";
    const message = finding.message || `${finding.severity} finding from ${finding.source}`;

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: ruleId,
        shortDescription: { text: message.slice(0, 100) },
        defaultConfiguration: {
          level: severityToLevel(finding.severity),
        },
        properties: {
          source: finding.source,
        },
      });
    }

    const result: SarifResult = {
      ruleId,
      level: severityToLevel(finding.severity),
      message: { text: message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: location },
          },
        },
      ],
      partialFingerprints: {
        primaryLocationLineHash: generateFingerprint(ruleId, location, message),
      },
      properties: {
        source: finding.source,
        severity: finding.severity,
      },
    };

    run.results.push(result);
  }

  run.tool.driver.rules = Array.from(rulesMap.values());

  // Add summary as properties
  run.properties = {
    summary: dashboard.summary,
    scanTargets: dashboard.scanTargets,
    timestamp: dashboard.timestamp,
  };

  log.runs.push(run);
  return log;
}

/**
 * Merge multiple SARIF logs into a single log
 */
export function mergeSarifLogs(...logs: SarifLog[]): SarifLog {
  const merged = createSarifLog();
  for (const log of logs) {
    merged.runs.push(...log.runs);
  }
  return merged;
}

/**
 * Convert SARIF log to JSON string
 */
export function sarifToJson(log: SarifLog, pretty = true): string {
  return JSON.stringify(log, null, pretty ? 2 : 0);
}

/**
 * Get summary statistics from a SARIF log
 */
export function getSarifSummary(log: SarifLog): {
  totalResults: number;
  byLevel: Record<string, number>;
  byTool: Record<string, number>;
} {
  const summary = {
    totalResults: 0,
    byLevel: {} as Record<string, number>,
    byTool: {} as Record<string, number>,
  };

  for (const run of log.runs) {
    const toolName = run.tool.driver.name;
    summary.byTool[toolName] = (summary.byTool[toolName] || 0) + run.results.length;

    for (const result of run.results) {
      summary.totalResults++;
      const level = result.level || "warning";
      summary.byLevel[level] = (summary.byLevel[level] || 0) + 1;
    }
  }

  return summary;
}

/**
 * Options for uploading SARIF to GitHub Code Scanning
 */
export interface GitHubUploadOptions {
  /** GitHub repository owner */
  owner: string;
  /** GitHub repository name */
  repo: string;
  /** Git commit SHA */
  commitSha: string;
  /** Git ref (e.g., refs/heads/main) */
  ref: string;
  /** GitHub token with security_events scope */
  token: string;
  /** GitHub API base URL (default: https://api.github.com) */
  apiUrl?: string;
  /** Tool name for tracking */
  toolName?: string;
}

/**
 * Response from GitHub SARIF upload
 */
export interface GitHubUploadResult {
  /** Upload ID for tracking */
  id: string;
  /** URL to check upload status */
  url: string;
}

/**
 * Upload SARIF to GitHub Code Scanning API
 *
 * Compresses and uploads SARIF results to GitHub for integration with
 * Code Scanning alerts.
 *
 * @see https://docs.github.com/en/rest/code-scanning#upload-an-analysis-as-sarif-data
 *
 * @example
 * ```typescript
 * const sarif = trivyToSarif(scanResult);
 * const result = await uploadSarifToGitHub(sarif, {
 *   owner: 'myorg',
 *   repo: 'myrepo',
 *   commitSha: 'abc123...',
 *   ref: 'refs/heads/main',
 *   token: process.env.GITHUB_TOKEN!,
 * });
 * console.log('Upload ID:', result.id);
 * ```
 */
export async function uploadSarifToGitHub(
  log: SarifLog,
  options: GitHubUploadOptions
): Promise<GitHubUploadResult> {
  const { gzipSync } = await import("node:zlib");

  const {
    owner,
    repo,
    commitSha,
    ref,
    token,
    apiUrl = "https://api.github.com",
    toolName,
  } = options;

  // Convert SARIF to JSON and compress with gzip
  const sarifJson = sarifToJson(log, false);
  const compressed = gzipSync(Buffer.from(sarifJson, "utf-8"));
  const base64Sarif = compressed.toString("base64");

  // Build the request payload
  const payload = {
    commit_sha: commitSha,
    ref,
    sarif: base64Sarif,
    tool_name: toolName || log.runs[0]?.tool.driver.name || "CI/CD Security Scanner",
  };

  // Upload to GitHub Code Scanning API
  const response = await fetch(`${apiUrl}/repos/${owner}/${repo}/code-scanning/sarifs`, {
    method: "POST",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`GitHub SARIF upload failed (${response.status}): ${errorText}`);
  }

  const result = (await response.json()) as { id: string; url: string };
  return {
    id: result.id,
    url: result.url,
  };
}

/**
 * Write SARIF to a file (for CI pipeline integration)
 *
 * Use this when you need to save SARIF for later upload via GitHub Actions
 * or other CI systems.
 *
 * @example
 * ```typescript
 * const sarif = trivyToSarif(scanResult);
 * await writeSarifFile(sarif, './results.sarif');
 * // Then in CI: github/codeql-action/upload-sarif@v2
 * ```
 */
export async function writeSarifFile(log: SarifLog, filePath: string): Promise<void> {
  const { writeFile } = await import("node:fs/promises");
  const sarifJson = sarifToJson(log, true);
  await writeFile(filePath, sarifJson, "utf-8");
}
