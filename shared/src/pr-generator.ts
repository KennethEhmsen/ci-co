/**
 * Pull Request Generator Module
 *
 * Generates automated pull requests for vulnerability remediation,
 * integrating with Gitea for PR creation and management.
 */

import type { RemediationSuggestion, RemediationPlan, TrivyScanResult } from "./types.js";

// =============================================================================
// Types
// =============================================================================

/** PR creation options */
export interface PrCreateOptions {
  /** Repository owner */
  owner: string;
  /** Repository name */
  repo: string;
  /** Gitea server URL */
  giteaUrl?: string;
  /** Gitea API token */
  giteaToken?: string;
  /** Base branch (default: main) */
  baseBranch?: string;
  /** Run tests before creating PR */
  runTests?: boolean;
  /** Test command to run */
  testCommand?: string;
  /** Dry run mode (don't actually create PR) */
  dryRun?: boolean;
  /** Maximum PRs to create in batch */
  maxPrs?: number;
}

/** PR creation result */
export interface PrCreateResult {
  success: boolean;
  prNumber?: number;
  prUrl?: string;
  branch?: string;
  title?: string;
  vulnerabilities?: string[];
  error?: string;
  testsPassed?: boolean;
  testOutput?: string;
}

/** Batch PR creation result */
export interface BatchPrResult {
  total: number;
  created: number;
  failed: number;
  skipped: number;
  prs: PrCreateResult[];
}

/** PR status */
export interface PrStatus {
  prNumber: number;
  state: "open" | "closed" | "merged";
  title: string;
  branch: string;
  mergeable: boolean;
  reviewStatus: "pending" | "approved" | "changes_requested";
  checksStatus: "pending" | "success" | "failure";
  url: string;
  createdAt: string;
  updatedAt: string;
}

// =============================================================================
// Branch Naming
// =============================================================================

/**
 * Generate a branch name for remediation
 */
export function generateBranchName(vulnIds: string[]): string {
  const timestamp = Date.now();
  if (vulnIds.length === 1) {
    // Single vulnerability: security/fix-CVE-2024-1234-1234567890
    const vulnId = vulnIds[0].replace(/[^a-zA-Z0-9-]/g, "-").toLowerCase();
    return `security/fix-${vulnId}-${timestamp}`;
  }
  // Multiple vulnerabilities: security/batch-fix-5-vulns-1234567890
  return `security/batch-fix-${vulnIds.length}-vulns-${timestamp}`;
}

/**
 * Generate commit message for remediation
 */
export function generateCommitMessage(
  suggestions: RemediationSuggestion[],
  options: { includeDetails?: boolean } = {}
): string {
  if (suggestions.length === 0) {
    return "fix(security): apply vulnerability remediation";
  }

  if (suggestions.length === 1) {
    const s = suggestions[0];
    const base = `fix(security): ${s.package} ${s.currentVersion} → ${s.fixedVersion}`;
    if (options.includeDetails) {
      return `${base}\n\nResolves ${s.vulnerability.id} (${s.vulnerability.severity})`;
    }
    return base;
  }

  const criticalCount = suggestions.filter((s) => s.vulnerability.severity === "CRITICAL").length;
  const highCount = suggestions.filter((s) => s.vulnerability.severity === "HIGH").length;
  const base = `fix(security): update ${suggestions.length} packages`;

  if (options.includeDetails) {
    const details = suggestions
      .slice(0, 5)
      .map((s) => `- ${s.package}: ${s.vulnerability.id}`)
      .join("\n");
    const summary =
      criticalCount > 0 || highCount > 0
        ? `\n\nResolves ${criticalCount} critical, ${highCount} high severity vulnerabilities`
        : "";
    return `${base}${summary}\n\n${details}${suggestions.length > 5 ? `\n- ... and ${suggestions.length - 5} more` : ""}`;
  }

  return base;
}

/**
 * Generate PR title for remediation
 */
export function generatePrTitle(suggestions: RemediationSuggestion[]): string {
  if (suggestions.length === 0) {
    return "[Security] Vulnerability remediation";
  }

  if (suggestions.length === 1) {
    const s = suggestions[0];
    return `[Security] Fix ${s.vulnerability.id} in ${s.package}`;
  }

  const criticalCount = suggestions.filter((s) => s.vulnerability.severity === "CRITICAL").length;
  const highCount = suggestions.filter((s) => s.vulnerability.severity === "HIGH").length;

  if (criticalCount > 0) {
    return `[Security] Fix ${suggestions.length} vulnerabilities (${criticalCount} critical)`;
  }
  if (highCount > 0) {
    return `[Security] Fix ${suggestions.length} vulnerabilities (${highCount} high)`;
  }
  return `[Security] Fix ${suggestions.length} vulnerabilities`;
}

/**
 * Generate PR body/description
 */
export function generatePrBody(
  suggestions: RemediationSuggestion[],
  _options: { scanResult?: TrivyScanResult } = {}
): string {
  const sections: string[] = [];

  // Summary
  sections.push("## Summary\n");
  sections.push(`This PR addresses **${suggestions.length}** security vulnerabilities.\n`);

  // Severity breakdown
  const bySeverity = suggestions.reduce(
    (acc, s) => {
      acc[s.vulnerability.severity] = (acc[s.vulnerability.severity] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  sections.push("### Severity Breakdown\n");
  sections.push("| Severity | Count |");
  sections.push("|----------|-------|");
  for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
    if (bySeverity[sev]) {
      sections.push(`| ${sev} | ${bySeverity[sev]} |`);
    }
  }
  sections.push("");

  // Changes table
  sections.push("### Changes\n");
  sections.push("| Package | Current | Fixed | CVE |");
  sections.push("|---------|---------|-------|-----|");
  for (const s of suggestions.slice(0, 20)) {
    sections.push(
      `| ${s.package} | ${s.currentVersion} | ${s.fixedVersion} | ${s.vulnerability.id} |`
    );
  }
  if (suggestions.length > 20) {
    sections.push(`\n*... and ${suggestions.length - 20} more changes*\n`);
  }
  sections.push("");

  // Commands section
  const commands = [...new Set(suggestions.map((s) => s.command))].filter(Boolean);
  if (commands.length > 0) {
    sections.push("### Commands Applied\n");
    sections.push("```bash");
    sections.push(commands.join("\n"));
    sections.push("```\n");
  }

  // Test checklist
  sections.push("### Test Checklist\n");
  sections.push("- [ ] Build passes");
  sections.push("- [ ] Unit tests pass");
  sections.push("- [ ] Integration tests pass");
  sections.push("- [ ] Manual testing completed\n");

  // Footer
  sections.push("---");
  sections.push("*Generated by CI/CD Security Platform*");

  return sections.join("\n");
}

// =============================================================================
// PR Creation (Gitea Integration)
// =============================================================================

/**
 * Create a pull request on Gitea
 */
export async function createPullRequest(
  suggestions: RemediationSuggestion[],
  options: PrCreateOptions
): Promise<PrCreateResult> {
  const { owner, repo, baseBranch = "main", dryRun = false } = options;
  const giteaUrl = options.giteaUrl || process.env.GITEA_URL || "http://localhost:3000";
  const giteaToken = options.giteaToken || process.env.GITEA_TOKEN;

  if (!giteaToken) {
    return {
      success: false,
      error: "GITEA_TOKEN not provided",
    };
  }

  if (suggestions.length === 0) {
    return {
      success: false,
      error: "No suggestions to create PR for",
    };
  }

  const vulnIds = suggestions.map((s) => s.vulnerability.id);
  const branch = generateBranchName(vulnIds);
  const title = generatePrTitle(suggestions);
  const body = generatePrBody(suggestions);

  if (dryRun) {
    return {
      success: true,
      branch,
      title,
      vulnerabilities: vulnIds,
      prNumber: 0,
      prUrl: `${giteaUrl}/${owner}/${repo}/pulls/0 (dry-run)`,
    };
  }

  try {
    // Create branch
    const baseRef = await fetch(
      `${giteaUrl}/api/v1/repos/${owner}/${repo}/git/refs/heads/${baseBranch}`,
      {
        headers: { Authorization: `token ${giteaToken}` },
      }
    );

    if (!baseRef.ok) {
      return {
        success: false,
        error: `Failed to get base branch: ${await baseRef.text()}`,
      };
    }

    const baseRefData = (await baseRef.json()) as { object?: { sha?: string } };
    const sha = baseRefData.object?.sha;

    if (!sha) {
      return {
        success: false,
        error: "Could not get base branch SHA",
      };
    }

    // Create new branch
    const createBranchRes = await fetch(`${giteaUrl}/api/v1/repos/${owner}/${repo}/git/refs`, {
      method: "POST",
      headers: {
        Authorization: `token ${giteaToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        ref: `refs/heads/${branch}`,
        sha,
      }),
    });

    if (!createBranchRes.ok) {
      return {
        success: false,
        error: `Failed to create branch: ${await createBranchRes.text()}`,
      };
    }

    // Create PR
    const prRes = await fetch(`${giteaUrl}/api/v1/repos/${owner}/${repo}/pulls`, {
      method: "POST",
      headers: {
        Authorization: `token ${giteaToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        title,
        body,
        head: branch,
        base: baseBranch,
      }),
    });

    if (!prRes.ok) {
      return {
        success: false,
        error: `Failed to create PR: ${await prRes.text()}`,
      };
    }

    const prData = (await prRes.json()) as { number?: number; html_url?: string };

    return {
      success: true,
      prNumber: prData.number,
      prUrl: prData.html_url,
      branch,
      title,
      vulnerabilities: vulnIds,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Create multiple PRs for batch remediation
 */
export async function createBatchPullRequests(
  plan: RemediationPlan,
  options: PrCreateOptions
): Promise<BatchPrResult> {
  const { maxPrs = 10 } = options;
  const result: BatchPrResult = {
    total: 0,
    created: 0,
    failed: 0,
    skipped: 0,
    prs: [],
  };

  // Group suggestions by package manager for separate PRs
  const byManager = new Map<string, RemediationSuggestion[]>();
  for (const s of plan.suggestions) {
    const key = s.packageManager;
    if (!byManager.has(key)) {
      byManager.set(key, []);
    }
    byManager.get(key)!.push(s);
  }

  result.total = byManager.size;

  let created = 0;
  for (const [, suggestions] of byManager) {
    if (created >= maxPrs) {
      result.skipped += 1;
      continue;
    }

    const prResult = await createPullRequest(suggestions, options);
    result.prs.push(prResult);

    if (prResult.success) {
      result.created += 1;
      created += 1;
    } else {
      result.failed += 1;
    }
  }

  return result;
}

/**
 * Get PR status from Gitea
 */
export async function getPrStatus(
  prNumber: number,
  options: { owner: string; repo: string; giteaUrl?: string; giteaToken?: string }
): Promise<PrStatus | null> {
  const giteaUrl = options.giteaUrl || process.env.GITEA_URL || "http://localhost:3000";
  const giteaToken = options.giteaToken || process.env.GITEA_TOKEN;

  if (!giteaToken) {
    return null;
  }

  try {
    const res = await fetch(
      `${giteaUrl}/api/v1/repos/${options.owner}/${options.repo}/pulls/${prNumber}`,
      {
        headers: { Authorization: `token ${giteaToken}` },
      }
    );

    if (!res.ok) {
      return null;
    }

    const data = (await res.json()) as {
      number: number;
      state: string;
      title: string;
      head?: { ref?: string };
      mergeable?: boolean;
      html_url?: string;
      created_at?: string;
      updated_at?: string;
    };

    return {
      prNumber: data.number,
      state: data.state as "open" | "closed" | "merged",
      title: data.title,
      branch: data.head?.ref || "",
      mergeable: data.mergeable || false,
      reviewStatus: "pending", // Would need additional API call
      checksStatus: "pending", // Would need additional API call
      url: data.html_url || "",
      createdAt: data.created_at || "",
      updatedAt: data.updated_at || "",
    };
  } catch {
    return null;
  }
}
