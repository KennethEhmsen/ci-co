# Milestone: v1.21.0

**Release Date:** December 27, 2024

## Summary

Version 1.21.0 introduces **4 major feature areas** with **25 new MCP tools**, bringing the platform total to **76 tools** for comprehensive security automation.

## Features Implemented

### Issue #15: Compliance Reporting (7 tools)
Map vulnerabilities to compliance frameworks with trend tracking and audit-ready reports.
- **Frameworks:** SOC2, HIPAA, PCI-DSS, CIS
- **23 compliance controls** mapped across frameworks
- JSON and HTML report generation with professional styling
- Compliance trend tracking over time

**Tools:** `compliance_get_frameworks`, `compliance_get_controls`, `compliance_check_status`, `compliance_generate_report`, `compliance_trend_record`, `compliance_trend_get`, `compliance_trend_list_targets`

### Issue #16: Policy as Code (OPA/Rego) (4 tools)
Define and enforce security policies using Open Policy Agent and Rego.
- **5 built-in policies:** vulnerability-threshold, license-compliance, secrets-detection, container-security, quality-gate
- Custom Rego policy support
- Policy validation and evaluation

**Tools:** `opa_list_policies`, `opa_get_policy_info`, `opa_validate_policy`, `opa_evaluate_policy`

### Issue #17: Scheduled Scanning (9 tools)
Cron-based automated security scanning with notifications.
- Standard cron expressions with aliases (@daily, @weekly, @hourly, @monthly)
- Webhook notifications (Slack, Microsoft Teams, generic)
- Execution history tracking
- Manual trigger support

**Tools:** `schedule_create`, `schedule_list`, `schedule_get`, `schedule_update`, `schedule_delete`, `schedule_trigger`, `schedule_history`, `cron_validate`, `scheduler_control`

### Issue #18: Offline Vulnerability Database (6 tools)
Local vulnerability database for air-gapped environments.
- SQLite-based persistent storage (200,000+ CVEs)
- Trivy database synchronization
- Offline scanning without internet connectivity
- Vulnerability annotation (false positive, acknowledged, mitigated)

**Tools:** `vuln_db_sync`, `vuln_db_status`, `vuln_db_lookup`, `vuln_db_search`, `trivy_scan_offline`, `vuln_db_annotate`

## Technical Highlights

- **better-sqlite3** integration for high-performance local database
- Comprehensive test coverage across all new modules
- Full TypeScript type definitions for all new features
- Documentation: Feature paper, cheat sheet, and API reference updated

## Platform Statistics

| Metric | Value |
|--------|-------|
| Total MCP Tools | 76 |
| New Tools (v1.21.0) | 25 |
| Compliance Frameworks | 4 |
| Compliance Controls | 23 |
| Built-in OPA Policies | 5 |

## Documentation

- [Features Documentation](./FEATURES.md) - Complete feature paper
- [Cheat Sheet](./CHEAT-SHEET.md) - Quick reference for all 76 tools
- [API Reference](./API.md) - Complete API documentation

## CI/CD

- Build #185 passing on Drone CI
- SonarQube analysis complete
- Coverage thresholds met across all modules
