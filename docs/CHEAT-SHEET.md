# CI/CD Security Platform - Cheat Sheet

Quick reference for all **296 MCP/Agent tools** across 47 functional categories.

**Version:** 1.29.0

---

## Table of Contents

1. [Trivy Scanning (11 tools)](#1-trivy-scanning-11-tools)
2. [SonarQube (4 tools)](#2-sonarqube-4-tools)
3. [Dependency-Track (5 tools)](#3-dependency-track-5-tools)
4. [Gitea (6 tools)](#4-gitea-6-tools)
5. [Drone CI (5 tools)](#5-drone-ci-5-tools)
6. [Container Registry (10 tools)](#6-container-registry-10-tools)
7. [Security Dashboard (2 tools)](#7-security-dashboard-2-tools)
8. [SARIF Reporting (2 tools)](#8-sarif-reporting-2-tools)
9. [Scheduler (9 tools)](#9-scheduler-9-tools)
10. [Remediation (5 tools)](#10-remediation-5-tools)
11. [Compliance (7 tools)](#11-compliance-7-tools)
12. [OPA/Rego Policy (4 tools)](#12-oparego-policy-4-tools)
13. [Vulnerability Database (6 tools)](#13-vulnerability-database-6-tools)
14. [Cache (6 tools)](#14-cache-6-tools)
15. [Common Workflows](#15-common-workflows)
16. [Quick Reference Table](#16-quick-reference-table)

---

## 1. Trivy Scanning (11 tools)

### trivy_scan_path
Scan local filesystem for vulnerabilities.
```json
{ "path": "/app/project", "severity": "HIGH,CRITICAL" }
```

### trivy_scan_image
Scan Docker image for vulnerabilities.
```json
{ "image": "nginx:1.25", "severity": "HIGH,CRITICAL" }
```

### trivy_generate_sbom
Generate SBOM for local path.
```json
{ "path": "/app/project", "format": "cyclonedx" }
// format: "cyclonedx" | "spdx-json"
```

### trivy_generate_sbom_image
Generate SBOM for Docker image.
```json
{ "image": "myapp:latest", "format": "cyclonedx" }
```

### trivy_scan_iac
Scan IaC files (Terraform, K8s, Docker).
```json
{ "path": "/app/infrastructure", "severity": "MEDIUM,HIGH,CRITICAL" }
```

### trivy_scan_secrets
Scan local path for hardcoded secrets.
```json
{ "path": "/app/project", "severity": "MEDIUM,HIGH,CRITICAL" }
```

### trivy_scan_secrets_image
Scan Docker image for hardcoded secrets.
```json
{ "image": "myapp:latest", "severity": "MEDIUM,HIGH,CRITICAL" }
```

### trivy_scan_licenses
Scan local path for license information.
```json
{ "path": "/app/project", "severity": "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL" }
```

### trivy_scan_licenses_image
Scan Docker image for licenses.
```json
{ "image": "myapp:latest" }
```

### trivy_scan_image_full
Comprehensive image scan (vulns + secrets + licenses + SBOM).
```json
{
  "image": "production:latest",
  "severity": "HIGH,CRITICAL",
  "sbomFormat": "cyclonedx"
}
```

### trivy_scan_path_full
Comprehensive path scan (vulns + secrets + licenses + IaC + SBOM).
```json
{
  "path": "/app/project",
  "severity": "HIGH,CRITICAL",
  "sbomFormat": "cyclonedx"
}
```

---

## 2. SonarQube (4 tools)

### sonar_list_projects
List all SonarQube projects.
```json
{}
```

### sonar_get_issues
Get bugs, vulnerabilities, code smells.
```json
{
  "projectKey": "ci-co",
  "types": "VULNERABILITY,BUG,CODE_SMELL"
}
```

### sonar_get_security_hotspots
Get security hotspots requiring review.
```json
{ "projectKey": "ci-co" }
```

### sonar_get_metrics
Get quality metrics (coverage, bugs, etc.).
```json
{ "projectKey": "ci-co" }
// Returns: bugs, vulnerabilities, coverage, duplications, etc.
```

---

## 3. Dependency-Track (5 tools)

### dtrack_list_projects
List all Dependency-Track projects.
```json
{}
// Response includes UUID, name, version, vulnerability counts
```

### dtrack_get_vulnerabilities
Get vulnerabilities for a project.
```json
{ "projectUuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890" }
```

### dtrack_get_findings
Get detailed security findings.
```json
{ "projectUuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890" }
```

### dtrack_get_components
List all components/dependencies.
```json
{ "projectUuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890" }
```

### dtrack_upload_sbom
Upload SBOM for analysis.
```json
{
  "projectName": "my-application",
  "projectVersion": "1.0.0",
  "sbom": "{\"bomFormat\":\"CycloneDX\",...}",
  "autoCreate": true
}
```

---

## 4. Gitea (6 tools)

### gitea_list_repos
List all repositories.
```json
{}
```

### gitea_get_repo
Get repository details.
```json
{ "owner": "localadmin", "repo": "ci-co" }
```

### gitea_get_branches
List repository branches.
```json
{ "owner": "localadmin", "repo": "ci-co" }
```

### gitea_get_commits
Get commit history.
```json
{ "owner": "localadmin", "repo": "ci-co", "limit": 10 }
```

### gitea_create_repo
Create new repository.
```json
{
  "name": "new-project",
  "description": "My new project",
  "private": false
}
```

### gitea_migrate_repo
Migrate repository from GitHub.
```json
{
  "cloneUrl": "https://github.com/user/repo.git",
  "repoName": "migrated-repo",
  "authToken": "ghp_xxxxx"  // optional for private repos
}
```

---

## 5. Drone CI (5 tools)

### drone_list_repos
List repositories synced with Drone.
```json
{}
```

### drone_get_builds
Get build history.
```json
{ "owner": "localadmin", "repo": "ci-co" }
```

### drone_get_build
Get specific build details.
```json
{ "owner": "localadmin", "repo": "ci-co", "build": 42 }
```

### drone_get_build_logs
Get build step logs.
```json
{
  "owner": "localadmin",
  "repo": "ci-co",
  "build": 42,
  "stage": 1,
  "step": 1
}
```

### drone_trigger_build
Trigger new build.
```json
{
  "owner": "localadmin",
  "repo": "ci-co",
  "branch": "main"
}
```

---

## 6. Container Registry (10 tools)

### registry_list_images
List images in registry.
```json
{}
```

### registry_get_tags
Get image tags.
```json
{ "image": "myapp" }
```

### registry_scan
Scan registry with filters.
```json
{
  "includePatterns": ["production-*"],
  "excludePatterns": ["*-dev"],
  "severity": "HIGH,CRITICAL",
  "maxAge": "7d"
}
```

### registry_detect_type
Auto-detect registry type.
```json
{ "url": "123456789.dkr.ecr.us-east-1.amazonaws.com" }
// Returns: ecr, acr, gcr, ghcr, harbor, docker
```

### registry_configure
Configure registry authentication.
```json
{
  "name": "production-ecr",
  "url": "123456789.dkr.ecr.us-east-1.amazonaws.com",
  "type": "ecr",
  "auth": {
    "region": "us-east-1",
    "accessKeyId": "AKIA...",
    "secretAccessKey": "..."
  }
}
```

### registry_list_configs
List configured registries.
```json
{}
```

### registry_get_config
Get registry configuration.
```json
{ "name": "production-ecr" }
```

### registry_remove_config
Remove registry configuration.
```json
{ "name": "old-registry" }
```

### registry_test_connection
Test registry connectivity.
```json
{ "name": "production-ecr" }
```

### registry_scan_multiple
Scan across multiple registries.
```json
{
  "registries": ["production-ecr", "staging-acr"],
  "includePatterns": ["**/production-*"],
  "severity": "CRITICAL",
  "concurrency": 5
}
```

---

## 7. Security Dashboard (2 tools)

### security_scan_all
Run comprehensive scan using all tools.
```json
{
  "image": "production:latest",
  "sonarProject": "ci-co"
}
```

### get_security_dashboard
Get unified security dashboard.
```json
{
  "image": "production:latest",
  "sonarProject": "ci-co",
  "severity": "HIGH,CRITICAL"
}
// Returns aggregated findings from Trivy, SonarQube, D-Track
```

---

## 8. SARIF Reporting (2 tools)

### sarif_generate
Generate SARIF report from scan results.
```json
{
  "image": "myapp:latest",
  "sources": ["trivy", "sonarqube", "dtrack"],
  "outputPath": "/tmp/results.sarif"
}
```

### sarif_upload_github
Upload SARIF to GitHub Code Scanning.
```json
{
  "sarifPath": "/tmp/results.sarif",
  "owner": "myorg",
  "repo": "myrepo",
  "ref": "refs/heads/main",
  "commitSha": "abc123...",
  "token": "ghp_xxxxx"
}
```

---

## 9. Scheduler (9 tools)

### schedule_create
Create scheduled scan job.
```json
{
  "name": "nightly-production",
  "cron": "0 2 * * *",
  "target": {
    "type": "image",
    "value": "production:latest",
    "severity": "HIGH,CRITICAL"
  },
  "enabled": true,
  "notifications": {
    "webhooks": [{
      "url": "https://hooks.slack.com/services/xxx",
      "type": "slack",
      "onFailure": true
    }]
  }
}
// Cron aliases: @hourly, @daily, @weekly, @monthly
```

### schedule_list
List all scheduled jobs.
```json
{}
// Optional: { "enabled": true } to filter
```

### schedule_get
Get schedule details.
```json
{ "id": "sch_abc123" }
```

### schedule_update
Update schedule configuration.
```json
{
  "id": "sch_abc123",
  "cron": "0 3 * * *",
  "enabled": false
}
```

### schedule_delete
Delete scheduled job.
```json
{ "id": "sch_abc123" }
```

### schedule_trigger
Manually trigger scan.
```json
{ "id": "sch_abc123" }
```

### schedule_history
Get execution history.
```json
{ "id": "sch_abc123", "limit": 10 }
```

### cron_validate
Validate cron expression.
```json
{ "expression": "0 2 * * *" }
// Returns: valid, description, next runs
```

### scheduler_control
Start/stop scheduler.
```json
{ "action": "start" }  // or "stop", "status"
```

---

## 10. Remediation (5 tools)

### generate_remediations
Generate fix commands for vulnerabilities.
```json
{ "image": "myapp:latest" }
```

### get_remediation_summary
Get text summary of remediations.
```json
{ "image": "myapp:latest" }
```

### get_remediation_markdown
Get Markdown-formatted report.
```json
{ "image": "myapp:latest" }
// Great for PR descriptions
```

### get_high_priority_fixes
Get CRITICAL/HIGH severity fixes.
```json
{ "image": "myapp:latest" }
```

### get_safe_fixes
Get non-breaking upgrades only.
```json
{
  "image": "myapp:latest",
  "excludeBreaking": true
}
```

---

## 11. Compliance (7 tools)

### compliance_get_frameworks
List available frameworks.
```json
{}
// Returns: SOC2, HIPAA, PCI-DSS, CIS
```

### compliance_get_controls
Get framework controls.
```json
{ "framework": "SOC2" }
// Optional: { "framework": "SOC2", "controlId": "CC7.1" }
```

### compliance_check_status
Check compliance pass/fail.
```json
{
  "image": "production:latest",
  "frameworks": ["SOC2", "PCI-DSS"],
  "severity": "HIGH,CRITICAL"
}
```

### compliance_generate_report
Generate JSON/HTML report.
```json
{
  "image": "production:latest",
  "frameworks": ["SOC2", "PCI-DSS"],
  "format": "html",
  "title": "Q4 2024 Compliance Report",
  "organization": "Acme Corp"
}
```

### compliance_trend_record
Record compliance snapshot.
```json
{
  "target": "production-api",
  "image": "production-api:latest",
  "frameworks": ["SOC2", "PCI-DSS"]
}
```

### compliance_trend_get
Get trends over time.
```json
{ "target": "production-api", "days": 30 }
```

### compliance_trend_list_targets
List tracked targets.
```json
{}
```

---

## 12. OPA/Rego Policy (4 tools)

### opa_list_policies
List built-in policies.
```json
{}
// Returns: vulnerability-threshold, license-compliance,
//          secrets-detection, container-security, quality-gate
```

### opa_get_policy_info
Get policy details and Rego source.
```json
{ "name": "vulnerability-threshold" }
```

### opa_validate_policy
Validate Rego syntax.
```json
{
  "policy": "package security.custom\n\ndefault allow = false\n..."
}
```

### opa_evaluate_policy
Evaluate scan against policy.
```json
{
  "image": "production:latest",
  "policy": "vulnerability-threshold",
  "thresholds": {
    "critical": 0,
    "high": 5,
    "medium": 20
  }
}
// Response: { "allow": true/false, "violations": [...] }
```

---

## 13. Vulnerability Database (6 tools)

### vuln_db_sync
Download/update vulnerability database.
```json
{}
// Optional: { "force": true } or { "skipIfRecent": 48 }
```

### vuln_db_status
Get database status and statistics.
```json
{}
// Returns: version, age, vulnerability count, ecosystems
```

### vuln_db_lookup
Look up CVE by ID.
```json
{ "id": "CVE-2024-1234" }
```

### vuln_db_search
Search vulnerabilities by criteria.
```json
{
  "packageName": "lodash",
  "ecosystem": "npm",
  "severity": ["CRITICAL", "HIGH"],
  "limit": 50
}
```

### trivy_scan_offline
Scan using local database (no internet).
```json
{
  "image": "myapp:latest",
  "severity": "HIGH,CRITICAL",
  "ignoreUnfixed": true
}
// Also supports: { "path": "/app/project" }
```

### vuln_db_annotate
Annotate vulnerability status.
```json
{
  "vulnId": "CVE-2024-1234",
  "status": "false_positive",
  "notes": "Not applicable - code path not used"
}
// Status: active, acknowledged, false_positive, mitigated
```

---

## 14. Cache (6 tools)

### cache_init
Initialize distributed caching with optional Redis backend.
```json
{
  "useRedis": true,
  "config": {
    "host": "redis.example.com",
    "port": 6379,
    "password": "secret"
  }
}
// Falls back to in-memory cache if Redis unavailable
```

### cache_status
Get cache health and connection status.
```json
{}
// Returns: connected, mode (redis/memory), uptime, memory usage
```

### cache_stats
Get cache hit/miss statistics by scan type.
```json
{}
// Returns: trivy, sonarqube, dtrack, registry stats
// Includes hit count, miss count, hit rate percentage
```

### cache_clear
Clear all cached data.
```json
{}
// Clears all scan type caches
```

### cache_invalidate
Invalidate cache entries by pattern.
```json
{ "pattern": "trivy:*" }
// Patterns: "trivy:*", "sonarqube:*", "dtrack:*", "registry:*"
// Also supports: "*:myapp:*" for specific targets
```

### cache_config
Get current cache configuration.
```json
{}
// Returns: TTL settings, Redis config (if enabled)
```

---

## 15. Common Workflows

### Full Security Pipeline
```bash
# 1. Sync vuln database (optional)
vuln_db_sync

# 2. Scan container
trivy_scan_image --image myapp:latest

# 3. Evaluate policy
opa_evaluate_policy --image myapp:latest --policy vulnerability-threshold

# 4. Check compliance
compliance_check_status --image myapp:latest --frameworks SOC2,PCI-DSS

# 5. Generate report
compliance_generate_report --image myapp:latest --format html
```

### Set Up Continuous Monitoring
```bash
# 1. Create schedule
schedule_create --name "nightly" --cron "@daily" --target.type image --target.value prod:latest

# 2. Verify
schedule_list

# 3. Check history
schedule_history --id sch_xxx --limit 10
```

### Compliance Trend Analysis
```bash
# Daily (automated)
compliance_trend_record --target prod --image prod:latest

# Monthly review
compliance_trend_get --target prod --days 30
compliance_generate_report --format html --title "Monthly Report"
```

### Air-Gapped Setup
```bash
# Internet zone
vuln_db_sync --force
# Transfer ~/.trivy/db/ to air-gapped

# Air-gapped zone
vuln_db_status
trivy_scan_offline --image internal:latest
```

### Multi-Registry Scan
```bash
# Configure registries
registry_configure --name ecr --type ecr --url xxx.dkr.ecr.us-east-1.amazonaws.com
registry_configure --name acr --type acr --url myacr.azurecr.io

# Scan all
registry_scan_multiple --registries ecr,acr --severity CRITICAL
```

---

## 16. Quick Reference Table

| Category | Tool | Purpose |
|----------|------|---------|
| **Trivy** | `trivy_scan_path` | Scan filesystem |
| | `trivy_scan_image` | Scan container |
| | `trivy_generate_sbom` | Generate SBOM (path) |
| | `trivy_generate_sbom_image` | Generate SBOM (image) |
| | `trivy_scan_iac` | Scan IaC files |
| | `trivy_scan_secrets` | Find secrets (path) |
| | `trivy_scan_secrets_image` | Find secrets (image) |
| | `trivy_scan_licenses` | License scan (path) |
| | `trivy_scan_licenses_image` | License scan (image) |
| | `trivy_scan_image_full` | Full image scan |
| | `trivy_scan_path_full` | Full path scan |
| **SonarQube** | `sonar_list_projects` | List projects |
| | `sonar_get_issues` | Get code issues |
| | `sonar_get_security_hotspots` | Get hotspots |
| | `sonar_get_metrics` | Get metrics |
| **D-Track** | `dtrack_list_projects` | List projects |
| | `dtrack_get_vulnerabilities` | Get vulns |
| | `dtrack_get_findings` | Get findings |
| | `dtrack_get_components` | Get components |
| | `dtrack_upload_sbom` | Upload SBOM |
| **Gitea** | `gitea_list_repos` | List repos |
| | `gitea_get_repo` | Get repo |
| | `gitea_get_branches` | List branches |
| | `gitea_get_commits` | Get commits |
| | `gitea_create_repo` | Create repo |
| | `gitea_migrate_repo` | Migrate from GitHub |
| **Drone** | `drone_list_repos` | List repos |
| | `drone_get_builds` | Get builds |
| | `drone_get_build` | Get build |
| | `drone_get_build_logs` | Get logs |
| | `drone_trigger_build` | Trigger build |
| **Registry** | `registry_list_images` | List images |
| | `registry_get_tags` | Get tags |
| | `registry_scan` | Scan registry |
| | `registry_detect_type` | Detect type |
| | `registry_configure` | Configure auth |
| | `registry_list_configs` | List configs |
| | `registry_get_config` | Get config |
| | `registry_remove_config` | Remove config |
| | `registry_test_connection` | Test connection |
| | `registry_scan_multiple` | Multi-registry scan |
| **Dashboard** | `security_scan_all` | Full scan |
| | `get_security_dashboard` | Unified dashboard |
| **SARIF** | `sarif_generate` | Generate SARIF |
| | `sarif_upload_github` | Upload to GitHub |
| **Scheduler** | `schedule_create` | Create schedule |
| | `schedule_list` | List schedules |
| | `schedule_get` | Get schedule |
| | `schedule_update` | Update schedule |
| | `schedule_delete` | Delete schedule |
| | `schedule_trigger` | Manual trigger |
| | `schedule_history` | Get history |
| | `cron_validate` | Validate cron |
| | `scheduler_control` | Start/stop |
| **Remediation** | `generate_remediations` | Generate fixes |
| | `get_remediation_summary` | Text summary |
| | `get_remediation_markdown` | Markdown report |
| | `get_high_priority_fixes` | CRITICAL/HIGH |
| | `get_safe_fixes` | Non-breaking only |
| **Compliance** | `compliance_get_frameworks` | List frameworks |
| | `compliance_get_controls` | Get controls |
| | `compliance_check_status` | Check pass/fail |
| | `compliance_generate_report` | Generate report |
| | `compliance_trend_record` | Record snapshot |
| | `compliance_trend_get` | Get trends |
| | `compliance_trend_list_targets` | List targets |
| **OPA/Rego** | `opa_list_policies` | List policies |
| | `opa_get_policy_info` | Get policy info |
| | `opa_validate_policy` | Validate Rego |
| | `opa_evaluate_policy` | Evaluate policy |
| **VulnDB** | `vuln_db_sync` | Sync database |
| | `vuln_db_status` | Get status |
| | `vuln_db_lookup` | Lookup CVE |
| | `vuln_db_search` | Search vulns |
| | `trivy_scan_offline` | Offline scan |
| | `vuln_db_annotate` | Annotate vuln |
| **Cache** | `cache_init` | Initialize caching |
| | `cache_status` | Get connection status |
| | `cache_stats` | Get hit/miss stats |
| | `cache_clear` | Clear all caches |
| | `cache_invalidate` | Invalidate by pattern |
| | `cache_config` | Get configuration |

---

## Severity Levels

| Level | Description |
|-------|-------------|
| `CRITICAL` | Immediate action required |
| `HIGH` | Fix in current sprint |
| `MEDIUM` | Plan for near term |
| `LOW` | Technical debt |
| `UNKNOWN` | Needs triage |

## Cron Expressions

| Expression | Description |
|------------|-------------|
| `0 * * * *` | Every hour |
| `0 0 * * *` | Daily at midnight |
| `0 2 * * *` | Daily at 2 AM |
| `0 0 * * 0` | Weekly on Sunday |
| `0 0 1 * *` | Monthly on 1st |
| `@hourly` | Alias for hourly |
| `@daily` | Alias for daily |
| `@weekly` | Alias for weekly |
| `@monthly` | Alias for monthly |

---

## Quick Links

- [Features Documentation](./FEATURES.md)
- [API Reference](./API.md)
- [Configuration Guide](./CONFIGURATION.md)
- [Troubleshooting](./TROUBLESHOOTING.md)
