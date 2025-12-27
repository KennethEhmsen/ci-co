# CI/CD Security Platform - Cheat Sheet

Quick reference for all 25 MCP/Agent tools across the four feature areas.

---

## Table of Contents

1. [Compliance Reporting (7 tools)](#compliance-reporting-7-tools)
2. [OPA/Rego Policy Engine (5 tools)](#oparego-policy-engine-5-tools)
3. [Scheduled Scanning (7 tools)](#scheduled-scanning-7-tools)
4. [Offline Vulnerability Database (6 tools)](#offline-vulnerability-database-6-tools)
5. [Common Workflows](#common-workflows)
6. [Troubleshooting](#troubleshooting)

---

## Compliance Reporting (7 tools)

### compliance_get_frameworks

List all available compliance frameworks.

```json
// No input required
{}

// Response
{
  "frameworks": [
    { "id": "SOC2", "name": "SOC 2 Type II", "controlCount": 12 },
    { "id": "HIPAA", "name": "HIPAA Security Rule", "controlCount": 18 },
    { "id": "PCI-DSS", "name": "PCI DSS v4.0", "controlCount": 15 },
    { "id": "CIS", "name": "CIS Controls v8", "controlCount": 18 }
  ]
}
```

---

### compliance_get_controls

Get controls for a specific framework.

```json
// Get all controls for SOC2
{
  "framework": "SOC2"
}

// Get specific control
{
  "framework": "SOC2",
  "controlId": "CC7.1"
}

// Response (single control)
{
  "id": "CC7.1",
  "name": "System Security",
  "description": "Security controls for system protection",
  "category": "Security",
  "remediationSlaHours": 72,
  "mappedFindings": ["CRITICAL", "HIGH"]
}
```

---

### compliance_check_status

Check compliance status for scan results.

```json
{
  "image": "myapp:latest",
  "frameworks": ["SOC2", "PCI-DSS"],
  "severity": "HIGH,CRITICAL"
}

// Response
{
  "overallStatus": "FAIL",
  "frameworks": {
    "SOC2": {
      "status": "FAIL",
      "compliancePercentage": 75,
      "passedControls": 9,
      "failedControls": 3,
      "violations": [
        {
          "controlId": "CC7.1",
          "reason": "5 critical vulnerabilities found"
        }
      ]
    }
  }
}
```

---

### compliance_generate_report

Generate compliance reports in JSON or HTML format.

```json
// JSON Report
{
  "image": "myapp:latest",
  "frameworks": ["SOC2"],
  "format": "json"
}

// HTML Report for audit
{
  "image": "myapp:latest",
  "frameworks": ["SOC2", "HIPAA", "PCI-DSS"],
  "format": "html",
  "title": "Q4 2024 Compliance Report",
  "organization": "Acme Corp"
}
```

---

### compliance_trend_record

Record a compliance snapshot for trend tracking.

```json
{
  "target": "production-api",
  "image": "production-api:latest",
  "frameworks": ["SOC2", "PCI-DSS"]
}

// Response
{
  "recorded": true,
  "timestamp": "2024-12-27T10:30:00Z",
  "target": "production-api",
  "complianceScore": 85
}
```

---

### compliance_trend_get

Get compliance trends over time.

```json
{
  "target": "production-api",
  "days": 30
}

// Response
{
  "target": "production-api",
  "trend": "improving",
  "dataPoints": [
    { "date": "2024-12-01", "score": 75 },
    { "date": "2024-12-15", "score": 82 },
    { "date": "2024-12-27", "score": 85 }
  ],
  "change": "+10%"
}
```

---

### compliance_trend_list_targets

List all targets with trend data.

```json
// No input required
{}

// Response
{
  "targets": [
    { "name": "production-api", "lastRecorded": "2024-12-27T10:30:00Z" },
    { "name": "frontend-app", "lastRecorded": "2024-12-27T08:00:00Z" }
  ]
}
```

---

## OPA/Rego Policy Engine (5 tools)

### opa_list_policies

List all available built-in policies.

```json
// No input required
{}

// Response
{
  "count": 5,
  "policies": [
    {
      "name": "vulnerability-threshold",
      "description": "Enforce vulnerability count limits",
      "entrypoint": "security.vulnerability.allow"
    },
    {
      "name": "license-compliance",
      "description": "Block forbidden software licenses",
      "entrypoint": "security.license.allow"
    },
    {
      "name": "secrets-detection",
      "description": "Fail if secrets are detected",
      "entrypoint": "security.secrets.allow"
    },
    {
      "name": "container-security",
      "description": "Container security best practices",
      "entrypoint": "security.container.allow"
    },
    {
      "name": "quality-gate",
      "description": "Code quality requirements",
      "entrypoint": "security.quality.allow"
    }
  ]
}
```

---

### opa_get_policy_info

Get detailed policy information including Rego source.

```json
{
  "name": "vulnerability-threshold"
}

// Response
{
  "name": "vulnerability-threshold",
  "description": "Enforce vulnerability count limits",
  "entrypoint": "security.vulnerability.allow",
  "ruleCount": 4,
  "source": "package security.vulnerability\n\ndefault allow = false\n..."
}
```

---

### opa_validate_policy

Validate Rego policy syntax.

```json
{
  "policy": "package security.custom\n\ndefault allow = false\n\nallow {\n  input.critical == 0\n}"
}

// Response (valid)
{
  "valid": true,
  "errors": []
}

// Response (invalid)
{
  "valid": false,
  "errors": [
    { "line": 3, "message": "Missing closing brace" }
  ]
}
```

---

### opa_evaluate_policy

Evaluate a policy against scan results.

```json
// Using built-in policy
{
  "image": "myapp:latest",
  "policy": "vulnerability-threshold",
  "thresholds": {
    "critical": 0,
    "high": 5
  }
}

// Using custom inline Rego
{
  "image": "myapp:latest",
  "policy": "package custom\n\ndefault allow = false\n\nallow { input.scan.critical == 0 }"
}

// Response
{
  "allow": false,
  "violations": [
    "Found 3 critical vulnerabilities (threshold: 0)"
  ],
  "details": {
    "critical": 3,
    "high": 12,
    "medium": 45
  }
}
```

---

### policy_evaluate_many (Agent Only)

Evaluate policies against multiple targets.

```json
{
  "targets": [
    { "type": "image", "value": "app1:latest" },
    { "type": "image", "value": "app2:latest" }
  ],
  "policy": "vulnerability-threshold"
}

// Response
{
  "results": [
    { "target": "app1:latest", "allow": true },
    { "target": "app2:latest", "allow": false, "violations": [...] }
  ]
}
```

---

## Scheduled Scanning (7 tools)

### scheduler_create_job

Create a new scheduled scan job.

```json
{
  "name": "nightly-production-scan",
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
      "onFailure": true,
      "minSeverity": "HIGH"
    }]
  }
}

// Cron aliases: @hourly, @daily, @weekly, @monthly
{
  "name": "weekly-registry-scan",
  "cron": "@weekly",
  "target": {
    "type": "registry",
    "value": "localhost:5000"
  }
}

// Response
{
  "id": "sch_abc123",
  "name": "nightly-production-scan",
  "nextRun": "2024-12-28T02:00:00Z",
  "created": true
}
```

---

### scheduler_list_jobs

List all scheduled jobs.

```json
// List all
{}

// Filter by status
{
  "enabled": true
}

// Filter by target type
{
  "targetType": "image"
}

// Response
{
  "jobs": [
    {
      "id": "sch_abc123",
      "name": "nightly-production-scan",
      "cron": "0 2 * * *",
      "enabled": true,
      "nextRun": "2024-12-28T02:00:00Z",
      "lastRun": "2024-12-27T02:00:00Z",
      "lastStatus": "success"
    }
  ]
}
```

---

### scheduler_get_job

Get job details.

```json
{
  "id": "sch_abc123"
}

// Response
{
  "id": "sch_abc123",
  "name": "nightly-production-scan",
  "cron": "0 2 * * *",
  "cronDescription": "At 02:00 AM every day",
  "target": {
    "type": "image",
    "value": "production:latest"
  },
  "enabled": true,
  "nextRun": "2024-12-28T02:00:00Z",
  "stats": {
    "totalRuns": 30,
    "successRate": 96.7
  }
}
```

---

### scheduler_update_job

Update job configuration.

```json
{
  "id": "sch_abc123",
  "cron": "0 3 * * *",
  "enabled": false
}

// Response
{
  "id": "sch_abc123",
  "updated": true,
  "nextRun": "2024-12-28T03:00:00Z"
}
```

---

### scheduler_delete_job

Delete a scheduled job.

```json
{
  "id": "sch_abc123"
}

// Response
{
  "deleted": true,
  "id": "sch_abc123"
}
```

---

### scheduler_trigger_job

Manually trigger a job execution.

```json
{
  "id": "sch_abc123"
}

// Response
{
  "triggered": true,
  "executionId": "exec_xyz789",
  "startTime": "2024-12-27T14:30:00Z"
}
```

---

### scheduler_get_history

Get job execution history.

```json
{
  "id": "sch_abc123",
  "limit": 10
}

// Response
{
  "history": [
    {
      "executionId": "exec_001",
      "startTime": "2024-12-27T02:00:00Z",
      "endTime": "2024-12-27T02:05:32Z",
      "status": "success",
      "findings": {
        "critical": 0,
        "high": 3
      }
    },
    {
      "executionId": "exec_002",
      "startTime": "2024-12-26T02:00:00Z",
      "endTime": "2024-12-26T02:04:15Z",
      "status": "success",
      "findings": {
        "critical": 0,
        "high": 5
      }
    }
  ]
}
```

---

## Offline Vulnerability Database (6 tools)

### vuln_db_sync

Download/update the vulnerability database.

```json
// Standard sync (skip if recent)
{}

// Force sync regardless of age
{
  "force": true
}

// Skip if synced within N hours
{
  "skipIfRecent": 48
}

// Response
{
  "success": true,
  "version": "2024.12.27",
  "vulnerabilities": 215432,
  "downloadTime": "45s",
  "size": "512MB"
}
```

---

### vuln_db_status

Get database status and statistics.

```json
// No input required
{}

// Response
{
  "trivyDatabase": {
    "version": "2024.12.27",
    "lastUpdated": "2024-12-27T00:00:00Z",
    "age": "10h 30m"
  },
  "offlineScanAvailable": true,
  "capabilities": {
    "imageScanning": true,
    "pathScanning": true,
    "sbomGeneration": true
  },
  "localCache": {
    "totalVulnerabilities": 215432,
    "ecosystems": ["npm", "pypi", "go", "maven", "rubygems"],
    "lastSync": "2024-12-27T00:00:00Z"
  }
}
```

---

### vuln_db_lookup

Look up a specific vulnerability.

```json
{
  "id": "CVE-2024-1234"
}

// Response
{
  "id": "CVE-2024-1234",
  "title": "Remote Code Execution in Example Package",
  "description": "A vulnerability in example-package allows...",
  "severity": "CRITICAL",
  "cvss": 9.8,
  "publishedDate": "2024-01-15",
  "affectedPackages": [
    {
      "name": "example-package",
      "ecosystem": "npm",
      "affectedVersions": "<2.0.0",
      "fixedVersion": "2.0.0"
    }
  ],
  "references": [
    "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
  ]
}
```

---

### vuln_db_search

Search vulnerabilities by criteria.

```json
// Search by package name
{
  "packageName": "lodash"
}

// Search by ecosystem and severity
{
  "ecosystem": "npm",
  "severity": ["CRITICAL", "HIGH"],
  "limit": 50
}

// Search by CVE pattern
{
  "cvePattern": "CVE-2024",
  "limit": 100
}

// Response
{
  "total": 150,
  "returned": 50,
  "vulnerabilities": [
    {
      "id": "CVE-2024-1234",
      "severity": "CRITICAL",
      "package": "lodash",
      "ecosystem": "npm"
    }
  ]
}
```

---

### trivy_scan_offline

Scan using local database only (no internet required).

```json
// Scan image
{
  "image": "myapp:latest",
  "severity": "HIGH,CRITICAL",
  "ignoreUnfixed": true
}

// Scan path
{
  "path": "/app/source",
  "severity": "HIGH,CRITICAL"
}

// Response
{
  "scanType": "offline",
  "databaseVersion": "2024.12.27",
  "target": "myapp:latest",
  "vulnerabilities": {
    "critical": 0,
    "high": 5,
    "medium": 23,
    "low": 12
  },
  "findings": [...]
}
```

---

### vuln_db_annotate

Annotate vulnerabilities with status.

```json
{
  "vulnId": "CVE-2024-1234",
  "status": "false_positive",
  "notes": "Not applicable - affected code path not used"
}

// Status options: acknowledged, false_positive, mitigated, active

// Response
{
  "annotated": true,
  "vulnId": "CVE-2024-1234",
  "status": "false_positive",
  "updatedAt": "2024-12-27T14:30:00Z"
}
```

---

## Common Workflows

### Workflow 1: Full Security Pipeline

```bash
# 1. Sync vulnerability database (optional, for offline capability)
vuln_db_sync

# 2. Scan the image
trivy_scan_image --image myapp:latest --severity HIGH,CRITICAL

# 3. Evaluate against security policy
opa_evaluate_policy --image myapp:latest --policy vulnerability-threshold

# 4. Check compliance status
compliance_check_status --image myapp:latest --frameworks SOC2,PCI-DSS

# 5. Generate report
compliance_generate_report --image myapp:latest --format html
```

### Workflow 2: Set Up Continuous Monitoring

```bash
# 1. Create nightly scan schedule
scheduler_create_job \
  --name "production-nightly" \
  --cron "@daily" \
  --target.type image \
  --target.value production:latest

# 2. Verify schedule
scheduler_list_jobs

# 3. Check history (after runs)
scheduler_get_history --id sch_xxx --limit 10
```

### Workflow 3: Compliance Trend Analysis

```bash
# 1. Record daily snapshots (automated via scheduler)
compliance_trend_record --target production-api --image production-api:latest

# 2. Get trend analysis
compliance_trend_get --target production-api --days 30

# 3. Generate monthly report
compliance_generate_report \
  --image production-api:latest \
  --format html \
  --title "Monthly Compliance Report"
```

### Workflow 4: Air-Gapped Environment Setup

```bash
# On internet-connected machine:
vuln_db_sync --force

# Transfer database files to air-gapped environment
# (Database location: ~/.trivy/db/)

# On air-gapped machine:
vuln_db_status  # Verify database available

trivy_scan_offline --image internal-app:latest
```

---

## Troubleshooting

### Issue: "Vulnerability database not found"

```bash
# Solution: Sync the database
vuln_db_sync --force
```

### Issue: "Policy evaluation failed"

```bash
# Solution: Validate policy syntax first
opa_validate_policy --policy "<your_rego_code>"
```

### Issue: "Schedule not triggering"

```bash
# Solution: Check if scheduler is running
scheduler_control --action start

# Verify cron expression
cron_validate --expression "0 2 * * *"
```

### Issue: "Compliance check shows no data"

```bash
# Solution: Ensure scan target is accessible
check_platform_status

# Verify image exists
trivy_scan_image --image <your-image>
```

### Issue: "Offline scan returns stale results"

```bash
# Solution: Check database age
vuln_db_status

# Force database update if stale
vuln_db_sync --force
```

---

## Quick Reference Table

| Category | Tool | Purpose |
|----------|------|---------|
| **Compliance** | `compliance_get_frameworks` | List frameworks |
| | `compliance_get_controls` | Get control details |
| | `compliance_check_status` | Check pass/fail |
| | `compliance_generate_report` | Generate reports |
| | `compliance_trend_record` | Record snapshot |
| | `compliance_trend_get` | Get trends |
| | `compliance_trend_list_targets` | List tracked targets |
| **Policy** | `opa_list_policies` | List built-in policies |
| | `opa_get_policy_info` | Get policy details |
| | `opa_validate_policy` | Validate Rego syntax |
| | `opa_evaluate_policy` | Evaluate against scan |
| | `policy_evaluate_many` | Batch evaluation |
| **Scheduler** | `scheduler_create_job` | Create schedule |
| | `scheduler_list_jobs` | List all schedules |
| | `scheduler_get_job` | Get schedule details |
| | `scheduler_update_job` | Modify schedule |
| | `scheduler_delete_job` | Remove schedule |
| | `scheduler_trigger_job` | Manual trigger |
| | `scheduler_get_history` | Execution history |
| **VulnDB** | `vuln_db_sync` | Download/update DB |
| | `vuln_db_status` | Database status |
| | `vuln_db_lookup` | Lookup CVE |
| | `vuln_db_search` | Search vulnerabilities |
| | `trivy_scan_offline` | Offline scanning |
| | `vuln_db_annotate` | Mark false positives |
