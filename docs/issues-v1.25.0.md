# v1.25.0 Issues - Advanced Reporting & Visualization

Create these 7 issues in Gitea for the v1.25.0 milestone.

---

## Issue 1: Executive Dashboard with Security KPIs

**Title:** Executive Dashboard with Security KPIs

**Body:**

## Overview

Implement a high-level executive dashboard showing security posture overview with key performance indicators.

## Features

### Dashboard Components
- Overall security health score (0-100)
- Critical/High vulnerability counts with trend arrows
- Compliance status across frameworks (SOC2, HIPAA, PCI-DSS, CIS)
- Top 10 most vulnerable projects/images
- Mean time to remediation (MTTR) metrics
- Scan coverage percentage

### Visualizations
- Severity distribution pie chart
- Vulnerability trend line chart (30/60/90 days)
- Compliance status heatmap
- Risk distribution by project

## New MCP Tools (3)

| Tool | Description |
|------|-------------|
| `dashboard_get_summary` | Get executive summary with all KPIs |
| `dashboard_get_health_score` | Calculate overall security health score |
| `dashboard_get_top_risks` | Get top N riskiest projects/images |

## Technical Requirements

```yaml
database_tables:
  - dashboard_snapshots (for caching)
  - health_score_history

performance:
  - Dashboard must render in <3 seconds
  - Cache invalidation on new scan results
```

## Success Criteria

- [ ] Health score accurately reflects security posture
- [ ] All KPIs update in real-time
- [ ] Dashboard loads in under 3 seconds
- [ ] Trend indicators show correct direction
- [ ] Works with 1000+ projects

## Milestone

v1.25.0 - Advanced Reporting & Visualization

---

## Issue 2: Vulnerability Trend Analysis with Forecasting

**Title:** Vulnerability Trend Analysis with Forecasting

**Body:**

## Overview

Implement trend analysis for vulnerabilities over time with forecasting capabilities to predict future security posture.

## Features

### Trend Tracking
- Daily/weekly/monthly vulnerability counts by severity
- New vs fixed vulnerability rates
- Regression detection (re-introduced vulnerabilities)
- Trend comparison across time periods

### Forecasting
- Linear regression for trend prediction
- Seasonal pattern detection
- "Days to zero critical" estimation
- Alert when trend indicates increasing risk

### Visualization Data
- Time series data for charting
- Moving averages (7-day, 30-day)
- Anomaly highlighting

## New MCP Tools (4)

| Tool | Description |
|------|-------------|
| `trend_get_vulnerability_history` | Get historical vulnerability counts |
| `trend_get_forecast` | Get predicted future vulnerability counts |
| `trend_detect_anomalies` | Detect unusual spikes or drops |
| `trend_compare_periods` | Compare two time periods |

## Technical Requirements

```yaml
database_tables:
  - trend_snapshots (daily aggregates)
  - trend_forecasts (cached predictions)

algorithms:
  - Simple linear regression for forecasting
  - Z-score for anomaly detection
  - Moving average smoothing
```

## Success Criteria

- [ ] 90-day history available for all projects
- [ ] Forecasting accuracy within 20% for 7-day predictions
- [ ] Anomaly detection catches 90% of significant changes
- [ ] Trend data updates automatically after each scan

## Milestone

v1.25.0 - Advanced Reporting & Visualization

---

## Issue 3: CVSS-Based Risk Scoring with Business Context

**Title:** CVSS-Based Risk Scoring with Business Context

**Body:**

## Overview

Implement risk scoring that combines CVSS scores with business context to provide actionable prioritization.

## Features

### Risk Score Components
- Base CVSS score (0-10)
- Exploitability factor (EPSS integration)
- Asset criticality multiplier (business context)
- Exposure factor (public vs internal)
- Age factor (older unfixed = higher risk)

### Business Context
- Project/image criticality levels (critical, high, medium, low)
- Data sensitivity classification
- Compliance requirements weight
- SLA requirements

### Aggregation
- Project-level risk scores
- Team-level risk scores
- Organization-wide risk score

## New MCP Tools (3)

| Tool | Description |
|------|-------------|
| `risk_calculate_score` | Calculate risk score for a target |
| `risk_set_asset_criticality` | Set business criticality for an asset |
| `risk_get_prioritized_list` | Get vulnerabilities sorted by risk score |

## Technical Requirements

```yaml
database_tables:
  - asset_criticality (business context)
  - risk_scores (calculated scores)
  - risk_config (scoring weights)

formula:
  risk_score = base_cvss * exploitability * asset_criticality * exposure * age_factor
```

## Success Criteria

- [ ] Risk scores correlate with actual exploit likelihood
- [ ] Business context properly weights priorities
- [ ] Top 10 risk items match security team expectations
- [ ] Scores update automatically when context changes

## Milestone

v1.25.0 - Advanced Reporting & Visualization

---

## Issue 4: Customizable Report Builder with Templates

**Title:** Customizable Report Builder with Templates

**Body:**

## Overview

Implement a flexible report builder with customizable templates and scheduling capabilities.

## Features

### Report Templates
- Executive summary template
- Technical detail template
- Compliance audit template
- Trend analysis template
- Custom template creation

### Template Components
- Header/footer customization
- Section selection (which data to include)
- Filtering options (severity, date range, projects)
- Branding/logo support

### Scheduling
- One-time report generation
- Recurring reports (daily, weekly, monthly)
- Email delivery
- Webhook notification on completion

## New MCP Tools (4)

| Tool | Description |
|------|-------------|
| `report_create_template` | Create a new report template |
| `report_list_templates` | List available templates |
| `report_generate` | Generate a report from template |
| `report_schedule` | Schedule recurring report generation |

## Technical Requirements

```yaml
database_tables:
  - report_templates (template definitions)
  - report_schedules (scheduled reports)
  - report_history (generated reports)

template_format:
  - JSON schema for template definition
  - Mustache/Handlebars for content templating
```

## Success Criteria

- [ ] 5+ built-in templates available
- [ ] Custom templates can include any data source
- [ ] Scheduled reports deliver on time
- [ ] Templates shareable across teams

## Milestone

v1.25.0 - Advanced Reporting & Visualization

---

## Issue 5: PDF and Excel Report Export

**Title:** PDF and Excel Report Export

**Body:**

## Overview

Implement professional PDF and Excel export capabilities for security reports.

## Features

### PDF Export
- Professional formatting with headers/footers
- Table of contents for long reports
- Charts and graphs embedded
- Page numbers and timestamps
- Company branding support

### Excel Export
- Multiple worksheets (summary, details, trends)
- Formatted tables with filters
- Charts in separate sheets
- Pivot table ready data
- Conditional formatting for severity

### CSV Export
- Simple flat file export
- Configurable columns
- UTF-8 encoding with BOM

## New MCP Tools (3)

| Tool | Description |
|------|-------------|
| `export_to_pdf` | Export report to PDF format |
| `export_to_excel` | Export report to Excel format |
| `export_to_csv` | Export data to CSV format |

## Technical Requirements

```yaml
dependencies:
  - puppeteer: "^21.0.0"  # PDF generation via headless Chrome
  - exceljs: "^4.4.0"     # Excel generation

pdf_options:
  - A4/Letter page sizes
  - Portrait/Landscape orientation
  - Header/footer templates

excel_options:
  - .xlsx format (Office 2007+)
  - Multiple worksheet support
  - Chart generation
```

## Success Criteria

- [ ] PDF reports render correctly in all viewers
- [ ] Excel files open without errors in Excel/Google Sheets
- [ ] Charts display correctly in exports
- [ ] Large reports (1000+ vulnerabilities) export successfully
- [ ] Export completes in under 30 seconds

## Milestone

v1.25.0 - Advanced Reporting & Visualization

---

## Issue 6: Cross-Project Comparative Analysis

**Title:** Cross-Project Comparative Analysis

**Body:**

## Overview

Implement comparative analysis capabilities to compare security posture across projects, teams, and time periods.

## Features

### Comparison Types
- Project vs project
- Team vs team
- Current vs historical
- Against baseline/benchmark

### Comparison Metrics
- Vulnerability counts by severity
- Risk scores
- Remediation velocity
- Compliance status
- MTTR (Mean Time to Remediate)

### Visualization Data
- Side-by-side comparison tables
- Radar/spider charts data
- Ranking lists

## New MCP Tools (3)

| Tool | Description |
|------|-------------|
| `compare_projects` | Compare security metrics between projects |
| `compare_teams` | Compare security metrics between teams |
| `compare_to_baseline` | Compare current state to a saved baseline |

## Technical Requirements

```yaml
database_tables:
  - baselines (saved snapshots for comparison)
  - comparison_cache (cached comparison results)

metrics:
  - Normalized scores for fair comparison
  - Percentile rankings
  - Delta calculations
```

## Success Criteria

- [ ] Comparisons complete in under 5 seconds
- [ ] Metrics normalized for fair comparison (size-adjusted)
- [ ] Historical comparisons available for 90+ days
- [ ] Baseline snapshots can be saved and restored

## Milestone

v1.25.0 - Advanced Reporting & Visualization

---

## Issue 7: SLA Tracking and Escalation Workflows

**Title:** SLA Tracking and Escalation Workflows

**Body:**

## Overview

Implement SLA tracking for vulnerability remediation with automated escalation workflows.

## Features

### SLA Configuration
- Per-severity SLA targets (e.g., Critical: 7 days, High: 30 days)
- Per-project overrides
- Business hours consideration
- Holiday calendar support

### SLA Tracking
- Time-to-remediation tracking
- SLA breach detection
- Approaching deadline warnings
- SLA compliance percentage

### Escalation Workflows
- Configurable escalation levels
- Notification on approaching breach
- Notification on breach
- Auto-assignment to escalation contacts

## New MCP Tools (3)

| Tool | Description |
|------|-------------|
| `sla_configure` | Configure SLA targets for a project/org |
| `sla_get_status` | Get current SLA compliance status |
| `sla_get_breaches` | Get list of SLA breaches and approaching |

## Technical Requirements

```yaml
database_tables:
  - sla_config (SLA target definitions)
  - sla_tracking (per-vulnerability SLA status)
  - escalation_config (escalation workflows)

notifications:
  - Slack/Teams webhook integration
  - Email notifications
  - PagerDuty integration (optional)
```

## Success Criteria

- [ ] SLA tracking accurate to the hour
- [ ] Escalation notifications sent on time
- [ ] Business hours correctly calculated
- [ ] SLA compliance reports generated
- [ ] Works with 10,000+ tracked vulnerabilities

## Milestone

v1.25.0 - Advanced Reporting & Visualization

---

## Summary

| Issue | Feature | Tools |
|-------|---------|-------|
| 1 | Executive Dashboard | 3 |
| 2 | Trend Analysis | 4 |
| 3 | Risk Scoring | 3 |
| 4 | Report Builder | 4 |
| 5 | PDF/Excel Export | 3 |
| 6 | Comparative Analysis | 3 |
| 7 | SLA Tracking | 3 |
| **Total** | | **23** |
