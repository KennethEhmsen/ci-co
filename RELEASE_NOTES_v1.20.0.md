# Release Notes - v1.20.0

**Release Date:** December 27, 2024

## Overview

Version 1.20.0 is a major feature release that adds four significant capabilities to the CI/CD Security Platform: SARIF report generation, scheduled scanning, multi-registry support, and vulnerability remediation suggestions. This release adds 21 new MCP tools, bringing the total to 59.

## New Features

### SARIF Report Generation (#11)

Generate industry-standard SARIF (Static Analysis Results Interchange Format) reports for integration with GitHub Code Scanning and other security tools.

**New Tools:**
- `sarif_generate` - Generate SARIF report from Trivy, SonarQube, and Dependency-Track scans
- `sarif_merge` - Merge multiple SARIF logs into one
- `sarif_summary` - Get summary statistics from a SARIF log
- `sarif_upload_github` - Upload SARIF to GitHub Code Scanning
- `sarif_write_file` - Write SARIF report to a file
- `sarif_convert` - Convert scan results to SARIF format

**Key Capabilities:**
- Convert Trivy vulnerability scans to SARIF
- Convert SonarQube issues to SARIF
- Convert Dependency-Track findings to SARIF
- Merge results from multiple sources
- Direct upload to GitHub Code Scanning API

### Scheduled Scan Automation (#12)

Automate security scans with cron-based scheduling for continuous monitoring.

**New Tools:**
- `schedule_create` - Create a new scheduled scan
- `schedule_list` - List all configured schedules
- `schedule_get` - Get details of a specific schedule
- `schedule_update` - Update schedule configuration
- `schedule_delete` - Remove a schedule
- `schedule_trigger` - Manually trigger a scheduled scan
- `schedule_history` - View execution history
- `cron_validate` - Validate cron expressions
- `scheduler_control` - Start/stop the scheduler engine

**Key Capabilities:**
- Standard 5-field cron expressions
- Cron aliases (@daily, @weekly, @hourly, etc.)
- Scan images, paths, or registries on schedule
- Webhook notifications for scan results
- File-based persistence for schedules
- Execution history tracking

### Multi-Registry Support (#13)

Scan container images across multiple cloud registry providers with unified configuration.

**Supported Registries:**
- Docker Registry (standard V2 API)
- Harbor
- AWS ECR (Elastic Container Registry)
- Azure ACR (Azure Container Registry)
- Google GCR (Google Container Registry)
- Google Artifact Registry (GAR)
- GitHub Container Registry (GHCR)
- GitLab Container Registry

**New Tools:**
- `registry_detect_type` - Auto-detect registry type from URL
- `registry_configure` - Configure a registry with authentication
- `registry_list_configs` - List configured registries
- `registry_get_config` - Get registry configuration
- `registry_remove_config` - Remove a registry configuration
- `registry_test_connection` - Test registry connectivity
- `registry_scan_multiple` - Scan multiple registries at once

**Key Capabilities:**
- Automatic registry type detection from URL patterns
- Cloud-specific authentication:
  - ECR: AWS access keys or IAM roles
  - ACR: Azure service principal or admin credentials
  - GCR/GAR: GCP service account keys
  - GHCR: GitHub tokens
- Aggregated results across all registries
- Parallel scanning with configurable concurrency

### Vulnerability Remediation Suggestions (#14)

Get actionable fix commands for discovered vulnerabilities across multiple package managers.

**Supported Package Managers:**
- npm, yarn, pnpm (JavaScript/TypeScript)
- pip, poetry, pipenv (Python)
- go (Go modules)
- maven, gradle (Java)
- gem (Ruby)
- cargo (Rust)

**New Tools:**
- `generate_remediations` - Generate full remediation plan
- `get_remediation_summary` - Get text summary of fixes
- `get_remediation_markdown` - Get Markdown-formatted report
- `get_high_priority_fixes` - Get critical/high severity fixes only
- `get_safe_fixes` - Get non-breaking changes only

**Key Capabilities:**
- Automatic package manager detection from scan results
- Breaking change detection (major version bumps)
- CVE deduplication for same-package updates
- Prioritization by severity or CVEs fixed
- Ready-to-run fix commands
- Markdown output for PR descriptions

## Statistics

| Metric | Value |
|--------|-------|
| New MCP Tools | 21 |
| Total MCP Tools | 59 |
| New TypeScript Types | 25+ |
| New Modules | 3 (scheduler.ts, registry-config.ts, remediation.ts) |
| Issues Closed | 4 (#11, #12, #13, #14) |

## Breaking Changes

None. This release is fully backward compatible.

## Migration Guide

No migration required. All new features are additive.

## Installation

```bash
npm install @cicd/shared@1.20.0
npm install cicd-security-mcp-server@1.20.0
npm install cicd-security-agent@1.20.0
```

## Example Usage

### Generate SARIF Report
```typescript
import { trivyScanImage, trivyToSarif, uploadSarifToGitHub } from '@cicd/shared';

const scan = await trivyScanImage('myapp:latest');
const sarif = trivyToSarif(scan);
await uploadSarifToGitHub(sarif, {
  owner: 'myorg',
  repo: 'myapp',
  ref: 'refs/heads/main',
  token: process.env.GITHUB_TOKEN
});
```

### Schedule Daily Scans
```typescript
import { createSchedule, startScheduler } from '@cicd/shared';

createSchedule({
  name: 'Nightly Security Scan',
  cron: '0 2 * * *', // 2 AM daily
  targets: [{ target: 'myapp:latest', type: 'image' }],
  options: { severity: 'HIGH,CRITICAL' }
});

startScheduler();
```

### Scan Multiple Registries
```typescript
import { configureRegistry, scanMultipleRegistries } from '@cicd/shared';

configureRegistry({
  id: 'ecr-prod',
  name: 'Production ECR',
  url: '123456789.dkr.ecr.us-east-1.amazonaws.com',
  type: 'ecr',
  auth: { type: 'ecr', region: 'us-east-1' }
});

const results = await scanMultipleRegistries({
  registries: ['ecr-prod'],
  severity: 'CRITICAL'
});
```

### Get Remediation Commands
```typescript
import { trivyScanPath, generateRemediations } from '@cicd/shared';

const scan = await trivyScanPath('./');
const plan = generateRemediations(scan, {
  minSeverity: 'HIGH',
  includeBreaking: false
});

console.log('Fix commands:');
plan.commands.forEach(cmd => console.log(`  ${cmd}`));
```

## Contributors

- Claude Opus 4.5 (AI Assistant)

## Links

- [Milestone v1.20.0](http://localhost:3000/localadmin/ci-co/milestone/3)
- [Issue #11 - SARIF Report Generation](http://localhost:3000/localadmin/ci-co/issues/11)
- [Issue #12 - Scheduled Scan Automation](http://localhost:3000/localadmin/ci-co/issues/12)
- [Issue #13 - Multi-Registry Support](http://localhost:3000/localadmin/ci-co/issues/13)
- [Issue #14 - Vulnerability Remediation](http://localhost:3000/localadmin/ci-co/issues/14)
