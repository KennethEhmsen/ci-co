/**
 * CI/CD Security Scanner - GitHub Action
 * Node.js helper for advanced operations
 */

import * as core from '@actions/core';
import * as github from '@actions/github';
import * as exec from '@actions/exec';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';

/**
 * Parse SARIF file and extract vulnerability counts
 */
export function parseSarif(sarifPath) {
  if (!existsSync(sarifPath)) {
    return { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
  }

  const sarif = JSON.parse(readFileSync(sarifPath, 'utf8'));
  const counts = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };

  for (const run of sarif.runs || []) {
    for (const result of run.results || []) {
      const severity = result.properties?.['security-severity'] || 0;
      const level = result.level || 'note';

      if (severity >= 9.0 || level === 'error') {
        counts.critical++;
      } else if (severity >= 7.0) {
        counts.high++;
      } else if (level === 'warning' || severity >= 4.0) {
        counts.medium++;
      } else {
        counts.low++;
      }
      counts.total++;
    }
  }

  return counts;
}

/**
 * Generate markdown summary for PR comment
 */
export function generateSummary(counts, config) {
  const { scanType, severity, failOn, scanPassed } = config;

  const statusEmoji = scanPassed ? (counts.total > 0 ? '⚠️' : '✅') : '❌';
  const statusText = scanPassed ? (counts.total > 0 ? 'Warnings' : 'Passed') : 'Failed';

  return `## 🛡️ Security Scan Results

${statusEmoji} **Status: ${statusText}**

### Vulnerability Summary

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 Critical | ${counts.critical} | ${counts.critical > 0 ? '❌' : '✅'} |
| 🟠 High | ${counts.high} | ${counts.high > 0 ? '⚠️' : '✅'} |
| 🟡 Medium | ${counts.medium} | ${counts.medium > 0 ? '⚠️' : '✅'} |
| 🟢 Low | ${counts.low} | ${counts.low > 0 ? 'ℹ️' : '✅'} |
| **Total** | **${counts.total}** | |

### Scan Configuration

- **Scan Type:** \`${scanType}\`
- **Severity Filter:** \`${severity}\`
- **Fail Threshold:** \`${failOn}\`

${counts.critical > 0 ? `
### ⚠️ Critical Vulnerabilities Detected

Please review and address critical vulnerabilities before merging.
` : ''}

---
<sub>🔒 Powered by [CI/CD Security Scanner](https://github.com/marketplace/actions/cicd-security-scanner) | [View full report]()</sub>
`;
}

/**
 * Generate badge SVG content
 */
export function generateBadgeSvg(counts) {
  let color = '#4c1';  // Green
  let status = 'passing';

  if (counts.critical > 0) {
    color = '#e05d44';  // Red
    status = `${counts.critical} critical`;
  } else if (counts.high > 0) {
    color = '#fe7d37';  // Orange
    status = `${counts.high} high`;
  } else if (counts.medium > 0) {
    color = '#dfb317';  // Yellow
    status = `${counts.medium} medium`;
  } else if (counts.low > 0) {
    color = '#a4a61d';  // Yellow-green
    status = `${counts.low} low`;
  }

  const labelWidth = 60;
  const statusWidth = Math.max(status.length * 7 + 10, 50);
  const totalWidth = labelWidth + statusWidth;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="a">
    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#a)">
    <path fill="#555" d="M0 0h${labelWidth}v20H0z"/>
    <path fill="${color}" d="M${labelWidth} 0h${statusWidth}v20H${labelWidth}z"/>
    <path fill="url(#b)" d="M0 0h${totalWidth}v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="${labelWidth / 2}" y="15" fill="#010101" fill-opacity=".3">security</text>
    <text x="${labelWidth / 2}" y="14">security</text>
    <text x="${labelWidth + statusWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${status}</text>
    <text x="${labelWidth + statusWidth / 2}" y="14">${status}</text>
  </g>
</svg>`;
}

/**
 * Post or update PR comment
 */
export async function postPrComment(octokit, prNumber, body, title) {
  const { owner, repo } = github.context.repo;

  // Find existing comment
  const { data: comments } = await octokit.rest.issues.listComments({
    owner,
    repo,
    issue_number: prNumber,
  });

  const existingComment = comments.find(c => c.body?.startsWith(`## ${title}`));

  if (existingComment) {
    // Update existing comment
    await octokit.rest.issues.updateComment({
      owner,
      repo,
      comment_id: existingComment.id,
      body,
    });
    core.info(`Updated existing PR comment #${existingComment.id}`);
  } else {
    // Create new comment
    const { data: newComment } = await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: prNumber,
      body,
    });
    core.info(`Created new PR comment #${newComment.id}`);
  }
}

/**
 * Upload SARIF to GitHub Code Scanning
 */
export async function uploadSarif(octokit, sarifPath, category) {
  const { owner, repo } = github.context.repo;
  const sarifContent = readFileSync(sarifPath, 'utf8');

  // Compress with gzip and base64 encode
  const { gzipSync } = await import('zlib');
  const compressed = gzipSync(Buffer.from(sarifContent));
  const base64Sarif = compressed.toString('base64');

  await octokit.rest.codeScanning.uploadSarif({
    owner,
    repo,
    commit_sha: github.context.sha,
    ref: github.context.ref,
    sarif: base64Sarif,
    tool_name: 'cicd-security-scanner',
    checkout_uri: `file:///${process.env.GITHUB_WORKSPACE}`,
  });

  core.info('SARIF uploaded to GitHub Code Scanning');
}

/**
 * Main action entry point
 */
async function run() {
  try {
    // Get inputs
    const scanType = core.getInput('scan-type') || 'path';
    const severity = core.getInput('severity') || 'CRITICAL,HIGH';
    const failOn = core.getInput('fail-on') || 'CRITICAL';
    const outputFile = core.getInput('output-file') || 'security-results.sarif';
    const uploadSarifEnabled = core.getInput('upload-sarif') === 'true';
    const commentOnPr = core.getInput('comment-on-pr') === 'true';
    const commentTitle = core.getInput('comment-title') || 'Security Scan Results';
    const generateBadge = core.getInput('generate-badge') === 'true';
    const badgePath = core.getInput('badge-path') || '.github/badges/security.svg';
    const token = core.getInput('github-token');

    // Parse results
    const counts = parseSarif(outputFile);

    // Determine pass/fail
    const failLevel = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[failOn] || 0;
    let scanPassed = true;

    if (failLevel >= 4 && counts.critical > 0) scanPassed = false;
    else if (failLevel >= 3 && (counts.critical + counts.high) > 0) scanPassed = false;
    else if (failLevel >= 2 && (counts.critical + counts.high + counts.medium) > 0) scanPassed = false;
    else if (failLevel >= 1 && counts.total > 0) scanPassed = false;

    // Set outputs
    core.setOutput('vulnerabilities-count', counts.total);
    core.setOutput('critical-count', counts.critical);
    core.setOutput('high-count', counts.high);
    core.setOutput('medium-count', counts.medium);
    core.setOutput('low-count', counts.low);
    core.setOutput('sarif-file', outputFile);
    core.setOutput('scan-passed', scanPassed);
    core.setOutput('summary', JSON.stringify(counts));

    // GitHub operations
    if (token) {
      const octokit = github.getOctokit(token);

      // Upload SARIF
      if (uploadSarifEnabled && existsSync(outputFile)) {
        try {
          await uploadSarif(octokit, outputFile, 'security-scan');
        } catch (error) {
          core.warning(`SARIF upload failed: ${error.message}`);
        }
      }

      // PR comment
      if (commentOnPr && github.context.payload.pull_request) {
        try {
          const prNumber = github.context.payload.pull_request.number;
          const summary = generateSummary(counts, { scanType, severity, failOn, scanPassed });
          await postPrComment(octokit, prNumber, summary, commentTitle);
        } catch (error) {
          core.warning(`PR comment failed: ${error.message}`);
        }
      }
    }

    // Generate badge
    if (generateBadge) {
      const badgeSvg = generateBadgeSvg(counts);
      mkdirSync(dirname(badgePath), { recursive: true });
      writeFileSync(badgePath, badgeSvg);
      core.info(`Badge generated: ${badgePath}`);
      core.setOutput('badge-url', `https://raw.githubusercontent.com/${github.context.repo.owner}/${github.context.repo.repo}/${github.context.ref.replace('refs/heads/', '')}/${badgePath}`);
    }

    // Fail if needed
    if (!scanPassed) {
      core.setFailed(`Security scan failed: Found ${counts.critical} critical, ${counts.high} high vulnerabilities`);
    }

  } catch (error) {
    core.setFailed(`Action failed: ${error.message}`);
  }
}

// Export for testing
export { run };

// Run if executed directly
if (process.argv[1] === new URL(import.meta.url).pathname) {
  run();
}
