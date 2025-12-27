# CI/CD Security Scanning Platform - Feature Documentation

## Executive Summary

The CI/CD Security Scanning Platform provides a comprehensive suite of security tools designed for enterprise environments. This document details four major features that extend the platform's capabilities beyond basic vulnerability scanning into compliance management, policy enforcement, automated scheduling, and offline operations.

**Key Capabilities:**
- **Compliance Reporting**: Map vulnerabilities to SOC2, HIPAA, PCI-DSS, and CIS frameworks
- **OPA/Rego Policy Engine**: Define and evaluate custom security policies using industry-standard Rego
- **Scheduled Scanning**: Automate security scans with cron-based scheduling and notifications
- **Offline Vulnerability Database**: Air-gapped environments support with local vulnerability data

**Total Tools Available**: 25 new MCP tools across 4 feature areas

---

## Table of Contents

1. [Compliance Reporting](#1-compliance-reporting-issue-15)
2. [OPA/Rego Policy Engine](#2-oparego-policy-engine-issue-16)
3. [Scheduled Scanning](#3-scheduled-scanning-issue-17)
4. [Offline Vulnerability Database](#4-offline-vulnerability-database-issue-18)
5. [Architecture Overview](#5-architecture-overview)
6. [Integration Patterns](#6-integration-patterns)

---

## 1. Compliance Reporting (Issue #15)

### Overview

The Compliance Reporting feature maps security scan findings to industry-standard compliance frameworks, enabling organizations to demonstrate compliance with regulatory requirements and internal security policies.

### Supported Frameworks

| Framework | Description | Use Cases |
|-----------|-------------|-----------|
| **SOC2** | Service Organization Control 2 | SaaS providers, cloud services |
| **HIPAA** | Health Insurance Portability and Accountability Act | Healthcare, PHI handling |
| **PCI-DSS** | Payment Card Industry Data Security Standard | Payment processing, e-commerce |
| **CIS** | Center for Internet Security Benchmarks | General security hardening |

### Tools (7 MCP Tools)

| Tool | Description |
|------|-------------|
| `compliance_get_frameworks` | List all available compliance frameworks with descriptions |
| `compliance_get_controls` | Get controls for a specific framework (optionally by ID) |
| `compliance_check_status` | Check compliance pass/fail status against scan results |
| `compliance_generate_report` | Generate JSON or HTML compliance reports |
| `compliance_trend_record` | Record a compliance snapshot for trend tracking |
| `compliance_trend_get` | Retrieve compliance trends over time |
| `compliance_trend_list_targets` | List all targets with recorded trend data |

### Architecture

```
+------------------+     +-------------------+     +------------------+
|   Scan Results   | --> | Compliance Engine | --> | Compliance       |
| (Trivy, Sonar,   |     |                   |     | Reports (JSON/   |
|  Dependency-     |     | - Control Mapping |     | HTML)            |
|  Track)          |     | - Status Checking |     |                  |
+------------------+     | - Trend Recording |     +------------------+
                         +-------------------+
                                  |
                                  v
                         +-------------------+
                         | Trend Database    |
                         | (In-memory/File)  |
                         +-------------------+
```

### Control Mapping

Each compliance framework contains controls that map to specific security finding types:

```
SOC2 CC7.1 (System Security) --> CRITICAL/HIGH vulnerabilities
                            --> Container misconfigurations
                            --> Secret exposures

HIPAA 164.312(e)(1)         --> Encryption requirements
(Transmission Security)     --> TLS configuration
                            --> Key management

PCI-DSS 6.5.x               --> Web application vulnerabilities
(Secure Development)        --> SQL Injection
                            --> Cross-site Scripting
```

### Use Cases

1. **Audit Preparation**
   - Generate compliance reports before SOC2 Type II audits
   - Track remediation progress over time
   - Provide evidence of continuous monitoring

2. **Pre-Release Compliance Gates**
   - Block deployments that fail compliance checks
   - Ensure all CRITICAL findings are addressed before release
   - Document compliance status for each release

3. **Executive Reporting**
   - Generate HTML reports for non-technical stakeholders
   - Track compliance trends across teams and projects
   - Identify systemic compliance gaps

### Example: Generate Compliance Report

```json
{
  "tool": "compliance_generate_report",
  "input": {
    "image": "myapp:latest",
    "frameworks": ["SOC2", "PCI-DSS"],
    "format": "html",
    "title": "Q4 2024 Security Compliance Report",
    "organization": "Acme Corp"
  }
}
```

---

## 2. OPA/Rego Policy Engine (Issue #16)

### Overview

The OPA (Open Policy Agent) integration enables declarative security policies written in Rego, the policy language used by industry-standard tools like Kubernetes admission controllers, Terraform Sentinel, and enterprise security platforms.

### Built-in Policies

| Policy Name | Description | Default Thresholds |
|-------------|-------------|-------------------|
| `vulnerability-threshold` | Enforce vulnerability count limits | critical: 0, high: 5 |
| `license-compliance` | Block forbidden licenses | GPL, AGPL, SSPL |
| `secrets-detection` | Fail if secrets found | Zero tolerance |
| `container-security` | Container best practices | Root user, privileged mode |
| `quality-gate` | Code quality requirements | Coverage > 80% |

### Tools (5 MCP Tools)

| Tool | Description |
|------|-------------|
| `policy_evaluate` | Evaluate Rego policy against scan results |
| `policy_evaluate_many` | Evaluate policies against multiple targets |
| `policy_get_violations` | Get policy violations for scan results |
| `policy_get_examples` | Get example Rego policies for common use cases |
| `policy_validate` | Validate Rego policy syntax before deployment |

### Architecture

```
+------------------+     +------------------+     +------------------+
|   Scan Input     | --> | OPA Evaluator    | --> | Policy Decision  |
|                  |     |                  |     |                  |
| - Vulnerabilities|     | - Built-in Rules |     | - allow: boolean |
| - Licenses       |     | - Custom Rego    |     | - violations: [] |
| - Secrets        |     | - Thresholds     |     | - reasons: []    |
| - Coverage       |     +------------------+     +------------------+
+------------------+
```

### Rego Policy Structure

```rego
package security.vulnerability

# Default deny
default allow = false

# Allow if no critical vulnerabilities and high count below threshold
allow {
    input.scan.critical == 0
    input.scan.high <= input.thresholds.high
}

# Generate violation messages
violations[msg] {
    input.scan.critical > 0
    msg := sprintf("Found %d critical vulnerabilities", [input.scan.critical])
}

violations[msg] {
    input.scan.high > input.thresholds.high
    msg := sprintf("High vulnerabilities (%d) exceed threshold (%d)",
                   [input.scan.high, input.thresholds.high])
}
```

### Use Cases

1. **CI/CD Pipeline Gates**
   - Fail builds that violate security policies
   - Enforce organization-specific security standards
   - Custom thresholds per project or environment

2. **License Compliance**
   - Block copyleft licenses in proprietary software
   - Audit open-source license usage
   - Automated license policy enforcement

3. **Security Governance**
   - Centralized policy management
   - Version-controlled security rules
   - Auditable policy decisions

### Example: Custom Policy Evaluation

```json
{
  "tool": "opa_evaluate_policy",
  "input": {
    "image": "production-app:v2.1.0",
    "policy": "vulnerability-threshold",
    "thresholds": {
      "critical": 0,
      "high": 0,
      "medium": 10
    }
  }
}
```

---

## 3. Scheduled Scanning (Issue #17)

### Overview

Scheduled Scanning enables automated security scans using cron expressions. Supports webhook notifications, execution history tracking, and manual triggering for ad-hoc scans.

### Features

- **Cron Scheduling**: Standard cron expressions plus aliases (@daily, @weekly, @hourly, @monthly)
- **Multiple Targets**: Scan images, paths, or entire registries
- **Webhook Notifications**: Slack, Microsoft Teams, or generic webhooks
- **Execution History**: Track past scan results and timing
- **Manual Trigger**: Run scheduled scans on-demand

### Tools (7 MCP Tools)

| Tool | Description |
|------|-------------|
| `scheduler_create_job` | Create a new scheduled scan job |
| `scheduler_list_jobs` | List all scheduled jobs with status |
| `scheduler_get_job` | Get detailed job configuration |
| `scheduler_delete_job` | Remove a scheduled job |
| `scheduler_trigger_job` | Manually trigger a job execution |
| `scheduler_get_history` | Get job execution history |
| `scheduler_update_job` | Modify job configuration |

### Architecture

```
+------------------+     +------------------+     +------------------+
|   Cron Parser    | --> | Schedule Manager | --> | Scan Executor    |
|                  |     |                  |     |                  |
| - Parse cron     |     | - Job storage    |     | - Image scans    |
| - Calculate next |     | - Enable/disable |     | - Path scans     |
| - Validate       |     | - History track  |     | - Registry scans |
+------------------+     +------------------+     +------------------+
                                  |
                                  v
                         +-------------------+
                         | Notification      |
                         | Handler           |
                         |                   |
                         | - Slack           |
                         | - Teams           |
                         | - Generic webhook |
                         +-------------------+
```

### Cron Expression Reference

| Expression | Description |
|------------|-------------|
| `0 2 * * *` | Daily at 2:00 AM |
| `0 0 * * 0` | Weekly on Sunday at midnight |
| `0 */6 * * *` | Every 6 hours |
| `@daily` | Alias for `0 0 * * *` |
| `@weekly` | Alias for `0 0 * * 0` |
| `@hourly` | Alias for `0 * * * *` |
| `@monthly` | Alias for `0 0 1 * *` |

### Use Cases

1. **Nightly Security Scans**
   - Scan production images daily
   - Detect new vulnerabilities from updated databases
   - Generate morning security reports

2. **Continuous Registry Monitoring**
   - Scan all images in private registry
   - Track vulnerability counts over time
   - Alert on new critical findings

3. **Compliance Scheduled Checks**
   - Weekly compliance status snapshots
   - Trend tracking for audit documentation
   - Automated executive reporting

### Example: Create Nightly Scan

```json
{
  "tool": "schedule_create",
  "input": {
    "name": "production-nightly-scan",
    "cron": "0 2 * * *",
    "target": {
      "type": "image",
      "value": "production-app:latest",
      "severity": "HIGH,CRITICAL"
    },
    "enabled": true,
    "notifications": {
      "webhooks": [{
        "url": "https://hooks.slack.com/services/xxx",
        "type": "slack",
        "onSuccess": false,
        "onFailure": true,
        "minSeverity": "HIGH"
      }]
    }
  }
}
```

---

## 4. Offline Vulnerability Database (Issue #18)

### Overview

The Offline Vulnerability Database feature enables security scanning in air-gapped environments by maintaining a local copy of the Trivy vulnerability database. This is critical for organizations with strict network isolation requirements.

### Features

- **Database Sync**: Download and update Trivy vulnerability database locally
- **Offline Scanning**: Scan images and paths without internet connectivity
- **Vulnerability Lookup**: Query CVE details from local database
- **Search Capabilities**: Find vulnerabilities by package, ecosystem, or severity
- **Annotations**: Mark vulnerabilities as false positives or acknowledged

### Tools (6 MCP Tools)

| Tool | Description |
|------|-------------|
| `vuln_db_sync` | Download/update the vulnerability database |
| `vuln_db_status` | Get database status, version, and statistics |
| `vuln_db_lookup` | Look up a specific CVE by ID |
| `vuln_db_search` | Search vulnerabilities by criteria |
| `trivy_scan_offline` | Scan using only local database |
| `vuln_db_annotate` | Annotate vulnerabilities with status |

### Architecture

```
+------------------+     +------------------+     +------------------+
|  Trivy DB Source | --> | Sync Manager     | --> | Local Database   |
|  (aquasec.com)   |     |                  |     | (SQLite/JSON)    |
+------------------+     | - Download       |     |                  |
                         | - Verify         |     | - CVE data       |
                         | - Extract        |     | - Advisories     |
                         +------------------+     | - Fix versions   |
                                                  +------------------+
                                                           |
                                  +------------------------+
                                  |
                         +------------------+     +------------------+
                         | Offline Scanner  | <-- | Annotation Store |
                         |                  |     |                  |
                         | - Image scanning |     | - False positive |
                         | - Path scanning  |     | - Acknowledged   |
                         | - No network     |     | - Mitigated      |
                         +------------------+     +------------------+
```

### Database Statistics

The local vulnerability database typically contains:

| Metric | Typical Value |
|--------|--------------|
| Total CVEs | 200,000+ |
| Last 30 days CVEs | 2,000+ |
| Supported ecosystems | 15+ |
| Database size | ~500MB |

### Use Cases

1. **Air-Gapped Environments**
   - Government/defense systems
   - Financial trading platforms
   - Critical infrastructure

2. **Consistent Scanning**
   - Lock vulnerability database to specific version
   - Reproducible scan results
   - Audit trail of database versions

3. **Vulnerability Management**
   - Mark false positives across scans
   - Track acknowledged vulnerabilities
   - Document mitigation status

### Annotation Status Values

| Status | Description |
|--------|-------------|
| `active` | Vulnerability requires attention (default) |
| `acknowledged` | Vulnerability reviewed, scheduled for fix |
| `false_positive` | Not applicable to this context |
| `mitigated` | Risk mitigated through other controls |

### Example: Sync and Scan Offline

```json
// Step 1: Sync database (requires network)
{
  "tool": "vuln_db_sync",
  "input": {
    "force": false,
    "skipIfRecent": 24
  }
}

// Step 2: Scan offline (no network required)
{
  "tool": "trivy_scan_offline",
  "input": {
    "image": "myapp:latest",
    "severity": "HIGH,CRITICAL",
    "ignoreUnfixed": true
  }
}
```

---

## 5. Architecture Overview

### System Component Diagram

```
+------------------------------------------------------------------+
|                    CI/CD Security Platform                        |
+------------------------------------------------------------------+
|                                                                   |
|  +------------------------+    +------------------------+         |
|  |     MCP Server         |    |    CICD Agent          |         |
|  |                        |    |    (Anthropic API)     |         |
|  | - 25 Feature Tools     |    |                        |         |
|  | - MCP Protocol         |    | - Same 25 Tools        |         |
|  | - Claude Integration   |    | - Direct API calls     |         |
|  +------------------------+    +------------------------+         |
|             |                           |                         |
|             +-----------+---------------+                         |
|                         |                                         |
|                         v                                         |
|  +----------------------------------------------------------+    |
|  |                   Shared Library (@cicd/shared)           |    |
|  +----------------------------------------------------------+    |
|  |                                                           |    |
|  |  +---------------+  +---------------+  +---------------+  |    |
|  |  | Compliance    |  | OPA/Rego      |  | Scheduler     |  |    |
|  |  | Engine        |  | Engine        |  | Engine        |  |    |
|  |  +---------------+  +---------------+  +---------------+  |    |
|  |                                                           |    |
|  |  +---------------+  +---------------+  +---------------+  |    |
|  |  | Vuln Database |  | Trivy         |  | SonarQube     |  |    |
|  |  | Manager       |  | Integration   |  | Integration   |  |    |
|  |  +---------------+  +---------------+  +---------------+  |    |
|  |                                                           |    |
|  +----------------------------------------------------------+    |
|                                                                   |
+------------------------------------------------------------------+
|                     External Services                             |
+------------------------------------------------------------------+
|                                                                   |
|  +-------------+  +---------------+  +------------------+         |
|  | Trivy       |  | SonarQube     |  | Dependency-Track |         |
|  | Server      |  | Server        |  | Server           |         |
|  +-------------+  +---------------+  +------------------+         |
|                                                                   |
+------------------------------------------------------------------+
```

### Data Flow

```
User Request
     |
     v
+------------------+
| Tool Router      |---> Compliance Tools ---> Compliance Engine
| (MCP or Agent)   |---> Policy Tools ------> OPA Engine
|                  |---> Scheduler Tools ---> Schedule Manager
|                  |---> VulnDB Tools ------> Database Manager
+------------------+
     |
     v
+------------------+
| Scan Services    |
| (Trivy, Sonar)   |
+------------------+
     |
     v
+------------------+
| Result Processor |
| & Formatter      |
+------------------+
     |
     v
JSON Response
```

---

## 6. Integration Patterns

### Pattern 1: CI/CD Pipeline Integration

```yaml
# .drone.yml / GitHub Actions / GitLab CI
security-scan:
  steps:
    - name: Sync vulnerability database
      run: cicd-agent vuln_db_sync

    - name: Scan container image
      run: cicd-agent trivy_scan_offline --image $IMAGE

    - name: Evaluate security policy
      run: cicd-agent opa_evaluate_policy --policy vulnerability-threshold

    - name: Check compliance
      run: cicd-agent compliance_check_status --frameworks SOC2,PCI-DSS

    - name: Record trend
      run: cicd-agent compliance_trend_record --target $IMAGE
```

### Pattern 2: Scheduled Monitoring

```
+------------------+
| Schedule Manager | -----> Nightly at 2AM
+------------------+
         |
         v
+------------------+     +------------------+
| Scan All Images  | --> | Generate Report  |
| in Registry      |     |                  |
+------------------+     +------------------+
                                  |
                                  v
                         +------------------+
                         | Send Webhook     |
                         | Notifications    |
                         +------------------+
                                  |
                    +-------------+-------------+
                    |             |             |
                    v             v             v
               +--------+   +---------+   +----------+
               | Slack  |   | Teams   |   | Email    |
               +--------+   +---------+   +----------+
```

### Pattern 3: Air-Gapped Deployment

```
Internet Zone                    Air-Gapped Zone
+------------------+            +------------------+
|                  |            |                  |
| 1. Sync VulnDB   |  Transfer  | 3. Import DB     |
|    on bastion    | =========> |    on air-gapped |
|                  |  (USB/DVD) |    server        |
+------------------+            |                  |
                                | 4. Scan offline  |
                                |                  |
                                | 5. Generate      |
                                |    reports       |
                                +------------------+
```

### Pattern 4: Compliance Audit Workflow

```
+------------------+     +------------------+     +------------------+
| Daily Scans      | --> | Record Trends    | --> | Generate Monthly |
| (Scheduled)      |     | (Automated)      |     | Reports          |
+------------------+     +------------------+     +------------------+
                                                          |
                                                          v
                                                 +------------------+
                                                 | Compliance       |
                                                 | Dashboard        |
                                                 |                  |
                                                 | - Trend charts   |
                                                 | - Control status |
                                                 | - Violations     |
                                                 +------------------+
```

---

## Benefits Summary

### For Security Teams

- Unified view of security posture across tools
- Automated compliance monitoring and reporting
- Policy-as-code for consistent enforcement
- Historical trend analysis

### For DevOps Teams

- Automated scheduled scans reduce manual work
- CI/CD integration with standard tools
- Fast feedback on policy violations
- Offline capability for restricted environments

### For Compliance Officers

- Pre-built framework mappings (SOC2, HIPAA, PCI-DSS, CIS)
- Audit-ready HTML reports
- Trend data for continuous compliance demonstration
- Evidence of remediation progress

### For Architects

- Extensible policy engine (Rego)
- Modular architecture for custom integrations
- API-first design for automation
- Support for air-gapped deployments

---

## Next Steps

1. Review the [Cheat Sheet](./CHEAT-SHEET.md) for quick tool reference
2. Explore [Configuration Options](../CONFIGURATION.md) for customization
3. Follow [Usage Examples](../USAGE.md) for hands-on tutorials
4. Check [Security Scanning Guide](../SECURITY-SCANNING.md) for Trivy integration details
