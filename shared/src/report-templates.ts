/**
 * Report Templates Module
 *
 * Provides customizable report generation with templates, scheduling,
 * and multiple output formats (HTML, Markdown, JSON).
 */

import Database from "better-sqlite3";
import * as crypto from "crypto";
import type {
  ReportFormat,
  ReportScheduleFrequency,
  BuiltinTemplateName,
  ReportSectionType,
  ReportSection,
  ReportBranding,
  ReportFilters,
  ReportTemplate,
  ReportGenerateOptions,
  GeneratedReport,
  ReportSchedule,
  ReportHistoryEntry,
  CreateTemplateOptions,
  CreateScheduleOptions,
  ReportDbInitResult,
  DashboardTimeRange,
  SeverityLevel,
} from "./types.js";

// =============================================================================
// Database Management
// =============================================================================

let db: Database.Database | null = null;

/**
 * Initialize the report templates database
 */
export function initReportDatabase(dbPath?: string): ReportDbInitResult {
  try {
    const path = dbPath || "./.data/report-templates.db";

    // Close existing connection if any
    if (db) {
      db.close();
    }

    db = new Database(path);
    db.pragma("journal_mode = WAL");

    // Create tables
    db.exec(`
      -- Report templates table
      CREATE TABLE IF NOT EXISTS report_templates (
        id TEXT PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        description TEXT,
        is_builtin INTEGER DEFAULT 0,
        format TEXT DEFAULT 'html',
        sections_json TEXT NOT NULL,
        default_filters_json TEXT,
        branding_json TEXT,
        header_template TEXT,
        footer_template TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        created_by TEXT
      );

      -- Report schedules table
      CREATE TABLE IF NOT EXISTS report_schedules (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        template_id TEXT NOT NULL,
        frequency TEXT NOT NULL,
        cron_expression TEXT,
        day_of_week INTEGER,
        day_of_month INTEGER,
        hour INTEGER DEFAULT 8,
        minute INTEGER DEFAULT 0,
        timezone TEXT DEFAULT 'UTC',
        filters_json TEXT,
        email_recipients_json TEXT,
        webhook_json TEXT,
        enabled INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_run_at TEXT,
        next_run_at TEXT,
        last_run_status TEXT,
        last_run_error TEXT,
        FOREIGN KEY (template_id) REFERENCES report_templates(id) ON DELETE CASCADE
      );

      -- Report history table
      CREATE TABLE IF NOT EXISTS report_history (
        id TEXT PRIMARY KEY,
        schedule_id TEXT,
        template_id TEXT NOT NULL,
        title TEXT NOT NULL,
        format TEXT NOT NULL,
        generated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        duration_ms INTEGER,
        status TEXT NOT NULL,
        error TEXT,
        file_path TEXT,
        summary_json TEXT,
        FOREIGN KEY (template_id) REFERENCES report_templates(id) ON DELETE SET NULL,
        FOREIGN KEY (schedule_id) REFERENCES report_schedules(id) ON DELETE SET NULL
      );

      -- Create indexes
      CREATE INDEX IF NOT EXISTS idx_templates_name ON report_templates(name);
      CREATE INDEX IF NOT EXISTS idx_schedules_template ON report_schedules(template_id);
      CREATE INDEX IF NOT EXISTS idx_schedules_next_run ON report_schedules(next_run_at);
      CREATE INDEX IF NOT EXISTS idx_history_template ON report_history(template_id);
      CREATE INDEX IF NOT EXISTS idx_history_generated ON report_history(generated_at);
    `);

    // Seed built-in templates
    const builtinCount = seedBuiltinTemplates();

    return {
      success: true,
      path,
      created: new Date().toISOString(),
      builtinTemplates: builtinCount,
    };
  } catch (error) {
    return {
      success: false,
      path: dbPath || "./.data/report-templates.db",
      created: new Date().toISOString(),
      builtinTemplates: 0,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Close the report database connection
 */
export function closeReportDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

/**
 * Check if the database is initialized
 */
export function isReportDbInitialized(): boolean {
  return db !== null;
}

/**
 * Get the database instance (throws if not initialized)
 */
function getDb(): Database.Database {
  if (!db) {
    throw new Error("Report database not initialized. Call initReportDatabase() first.");
  }
  return db;
}

// =============================================================================
// Built-in Templates
// =============================================================================

/**
 * Built-in template definitions
 */
const BUILTIN_TEMPLATES: Record<
  BuiltinTemplateName,
  Omit<ReportTemplate, "id" | "createdAt" | "updatedAt">
> = {
  "executive-summary": {
    name: "Executive Summary",
    description: "High-level security overview for executives and stakeholders",
    isBuiltin: true,
    format: "html",
    sections: [
      { type: "health-score", enabled: true },
      { type: "vulnerability-summary", enabled: true },
      { type: "compliance-status", enabled: true },
      { type: "top-risks", enabled: true, options: { limit: 5 } },
      { type: "mttr-metrics", enabled: true },
    ],
    defaultFilters: { timeRange: "30d" },
    headerTemplate: `<div class="header">
      <h1>Security Executive Summary</h1>
      <p class="date">Generated: {{generatedAt}}</p>
    </div>`,
    footerTemplate: `<div class="footer">
      <p>Confidential - {{companyName}}</p>
      <p class="page-number">Page {{page}}</p>
    </div>`,
  },
  "technical-detail": {
    name: "Technical Detail Report",
    description: "Detailed technical report with full vulnerability listings",
    isBuiltin: true,
    format: "html",
    sections: [
      { type: "vulnerability-summary", enabled: true },
      { type: "vulnerability-list", enabled: true, options: { limit: 100 } },
      { type: "remediation-status", enabled: true },
      { type: "scan-coverage", enabled: true },
    ],
    defaultFilters: { timeRange: "7d", severities: ["CRITICAL", "HIGH", "MEDIUM"] },
    headerTemplate: `<div class="header">
      <h1>Technical Security Report</h1>
      <p class="subtitle">Detailed Vulnerability Analysis</p>
      <p class="date">{{generatedAt}}</p>
    </div>`,
  },
  "compliance-audit": {
    name: "Compliance Audit Report",
    description: "Compliance status report for auditors (SOC2, HIPAA, PCI-DSS, CIS)",
    isBuiltin: true,
    format: "html",
    sections: [
      { type: "compliance-status", enabled: true },
      { type: "vulnerability-summary", enabled: true },
      { type: "remediation-status", enabled: true },
      { type: "scan-coverage", enabled: true },
    ],
    defaultFilters: { timeRange: "90d" },
    headerTemplate: `<div class="header">
      <h1>Compliance Audit Report</h1>
      <p class="frameworks">SOC2 | HIPAA | PCI-DSS | CIS</p>
      <p class="date">Audit Period: {{timeRange}} ending {{generatedAt}}</p>
    </div>`,
    footerTemplate: `<div class="footer">
      <p>This report is intended for compliance audit purposes only.</p>
      <p class="page-number">Page {{page}}</p>
    </div>`,
  },
  "trend-analysis": {
    name: "Trend Analysis Report",
    description: "Security trends over time with forecasting",
    isBuiltin: true,
    format: "html",
    sections: [
      { type: "health-score", enabled: true },
      { type: "trend-chart", enabled: true, options: { timeRange: "90d" } },
      { type: "vulnerability-summary", enabled: true },
      { type: "mttr-metrics", enabled: true },
    ],
    defaultFilters: { timeRange: "90d" },
    headerTemplate: `<div class="header">
      <h1>Security Trend Analysis</h1>
      <p class="period">Analysis Period: {{timeRange}}</p>
      <p class="date">Generated: {{generatedAt}}</p>
    </div>`,
  },
  "vulnerability-list": {
    name: "Vulnerability List",
    description: "Simple list of all vulnerabilities with details",
    isBuiltin: true,
    format: "markdown",
    sections: [{ type: "vulnerability-list", enabled: true, options: { limit: 500 } }],
    defaultFilters: { timeRange: "30d", status: "open" },
  },
};

/**
 * Seed built-in templates into the database
 */
function seedBuiltinTemplates(): number {
  const database = getDb();
  let count = 0;

  const stmt = database.prepare(`
    INSERT OR IGNORE INTO report_templates
    (id, name, description, is_builtin, format, sections_json, default_filters_json, branding_json, header_template, footer_template, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const now = new Date().toISOString();

  for (const [key, template] of Object.entries(BUILTIN_TEMPLATES)) {
    const id = `builtin-${key}`;
    const result = stmt.run(
      id,
      template.name,
      template.description,
      template.format,
      JSON.stringify(template.sections),
      template.defaultFilters ? JSON.stringify(template.defaultFilters) : null,
      template.branding ? JSON.stringify(template.branding) : null,
      template.headerTemplate || null,
      template.footerTemplate || null,
      now,
      now
    );
    if (result.changes > 0) {
      count++;
    }
  }

  return count;
}

// =============================================================================
// Template Management
// =============================================================================

/**
 * Create a new report template
 */
export function createTemplate(options: CreateTemplateOptions): ReportTemplate {
  const database = getDb();
  const id = `tmpl-${crypto.randomUUID()}`;
  const now = new Date().toISOString();

  const stmt = database.prepare(`
    INSERT INTO report_templates
    (id, name, description, is_builtin, format, sections_json, default_filters_json, branding_json, header_template, footer_template, created_at, updated_at, created_by)
    VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    id,
    options.name,
    options.description || "",
    options.format || "html",
    JSON.stringify(options.sections),
    options.defaultFilters ? JSON.stringify(options.defaultFilters) : null,
    options.branding ? JSON.stringify(options.branding) : null,
    options.headerTemplate || null,
    options.footerTemplate || null,
    now,
    now,
    options.createdBy || null
  );

  return getTemplate(id)!;
}

/**
 * Get a template by ID
 */
export function getTemplate(id: string): ReportTemplate | null {
  const database = getDb();
  const row = database.prepare("SELECT * FROM report_templates WHERE id = ?").get(id) as
    | TemplateRow
    | undefined;

  if (!row) {
    return null;
  }

  return rowToTemplate(row);
}

/**
 * Get a template by name
 */
export function getTemplateByName(name: string): ReportTemplate | null {
  const database = getDb();
  const row = database.prepare("SELECT * FROM report_templates WHERE name = ?").get(name) as
    | TemplateRow
    | undefined;

  if (!row) {
    return null;
  }

  return rowToTemplate(row);
}

/**
 * List all templates
 */
export function listTemplates(options?: {
  includeBuiltin?: boolean;
  format?: ReportFormat;
}): ReportTemplate[] {
  const database = getDb();
  let sql = "SELECT * FROM report_templates WHERE 1=1";
  const params: (string | number)[] = [];

  if (options?.includeBuiltin === false) {
    sql += " AND is_builtin = 0";
  }

  if (options?.format) {
    sql += " AND format = ?";
    params.push(options.format);
  }

  sql += " ORDER BY is_builtin DESC, name ASC";

  const rows = database.prepare(sql).all(...params) as TemplateRow[];
  return rows.map(rowToTemplate);
}

/**
 * Update a template
 */
export function updateTemplate(
  id: string,
  updates: Partial<CreateTemplateOptions>
): ReportTemplate | null {
  const database = getDb();
  const existing = getTemplate(id);

  if (!existing) {
    return null;
  }

  if (existing.isBuiltin) {
    throw new Error("Cannot modify built-in templates");
  }

  const now = new Date().toISOString();
  const setClauses: string[] = ["updated_at = ?"];
  const params: (string | null)[] = [now];

  if (updates.name !== undefined) {
    setClauses.push("name = ?");
    params.push(updates.name);
  }
  if (updates.description !== undefined) {
    setClauses.push("description = ?");
    params.push(updates.description);
  }
  if (updates.format !== undefined) {
    setClauses.push("format = ?");
    params.push(updates.format);
  }
  if (updates.sections !== undefined) {
    setClauses.push("sections_json = ?");
    params.push(JSON.stringify(updates.sections));
  }
  if (updates.defaultFilters !== undefined) {
    setClauses.push("default_filters_json = ?");
    params.push(JSON.stringify(updates.defaultFilters));
  }
  if (updates.branding !== undefined) {
    setClauses.push("branding_json = ?");
    params.push(JSON.stringify(updates.branding));
  }
  if (updates.headerTemplate !== undefined) {
    setClauses.push("header_template = ?");
    params.push(updates.headerTemplate);
  }
  if (updates.footerTemplate !== undefined) {
    setClauses.push("footer_template = ?");
    params.push(updates.footerTemplate);
  }

  params.push(id);

  database
    .prepare(`UPDATE report_templates SET ${setClauses.join(", ")} WHERE id = ?`)
    .run(...params);

  return getTemplate(id);
}

/**
 * Delete a template
 */
export function deleteTemplate(id: string): boolean {
  const database = getDb();
  const existing = getTemplate(id);

  if (!existing) {
    return false;
  }

  if (existing.isBuiltin) {
    throw new Error("Cannot delete built-in templates");
  }

  const result = database.prepare("DELETE FROM report_templates WHERE id = ?").run(id);
  return result.changes > 0;
}

// =============================================================================
// Report Generation
// =============================================================================

/**
 * Generate a report from a template
 */
export function generateReport(options: ReportGenerateOptions): GeneratedReport {
  const startTime = Date.now();
  const template = getTemplate(options.templateId);

  if (!template) {
    throw new Error(`Template not found: ${options.templateId}`);
  }

  const filters: ReportFilters = {
    ...template.defaultFilters,
    ...options.filters,
  };

  const branding: ReportBranding = {
    ...template.branding,
    ...options.branding,
  };

  const reportId = `rpt-${crypto.randomUUID()}`;
  const generatedAt = new Date().toISOString();
  const title = options.title || template.name;

  // Collect data for each section
  const sectionData = collectSectionData(template.sections, filters);

  // Calculate summary
  const summary = calculateReportSummary(sectionData);

  // Generate content based on format
  let content: string;
  switch (template.format) {
    case "html":
      content = generateHtmlReport(template, sectionData, {
        title,
        generatedAt,
        branding,
        filters,
        includeToc: options.includeToc,
        includeTimestamp: options.includeTimestamp,
      });
      break;
    case "markdown":
      content = generateMarkdownReport(template, sectionData, {
        title,
        generatedAt,
        filters,
        includeToc: options.includeToc,
        includeTimestamp: options.includeTimestamp,
      });
      break;
    case "json":
      content = JSON.stringify(
        {
          title,
          generatedAt,
          filters,
          sections: sectionData,
          summary,
        },
        null,
        2
      );
      break;
    default:
      throw new Error(`Unsupported format: ${template.format}`);
  }

  const durationMs = Date.now() - startTime;

  // Record in history
  recordReportHistory({
    id: reportId,
    templateId: template.id,
    title,
    format: template.format,
    generatedAt,
    durationMs,
    status: "success",
    summary,
  });

  return {
    id: reportId,
    templateId: template.id,
    templateName: template.name,
    title,
    format: template.format,
    content,
    generatedAt,
    filters,
    durationMs,
    summary,
  };
}

/**
 * Collect data for all sections
 */
function collectSectionData(
  sections: ReportSection[],
  filters: ReportFilters
): Record<string, unknown> {
  const data: Record<string, unknown> = {};

  for (const section of sections) {
    if (!section.enabled) {
      continue;
    }

    try {
      data[section.type] = collectSectionTypeData(section, filters);
    } catch {
      // Section data collection failed, use empty data
      data[section.type] = { error: "Failed to collect data" };
    }
  }

  return data;
}

/**
 * Collect data for a specific section type
 */
function collectSectionTypeData(section: ReportSection, filters: ReportFilters): unknown {
  const timeRange = section.options?.timeRange || filters.timeRange || "30d";

  switch (section.type) {
    case "health-score":
      return {
        score: 85,
        grade: "B",
        trend: { direction: "up", change: 5 },
        components: {
          vulnerability: 80,
          compliance: 90,
          coverage: 85,
          remediation: 85,
        },
      };

    case "vulnerability-summary":
      return {
        total: 45,
        critical: 2,
        high: 8,
        medium: 20,
        low: 15,
        trend: { direction: "down", change: -10 },
      };

    case "vulnerability-list":
      return {
        items: generateMockVulnerabilities(section.options?.limit || 50),
        total: 45,
        showing: Math.min(section.options?.limit || 50, 45),
      };

    case "compliance-status":
      return {
        frameworks: [
          { name: "SOC2", status: "compliant", percentage: 95 },
          { name: "HIPAA", status: "compliant", percentage: 92 },
          { name: "PCI-DSS", status: "partial", percentage: 85 },
          { name: "CIS", status: "partial", percentage: 78 },
        ],
        overallPercentage: 87.5,
      };

    case "top-risks":
      return {
        items: [
          { target: "payment-service", score: 95, criticalCount: 2 },
          { target: "auth-api", score: 78, criticalCount: 1 },
          { target: "user-db", score: 65, criticalCount: 0 },
        ].slice(0, section.options?.limit || 10),
      };

    case "trend-chart":
      return {
        timeRange,
        dataPoints: generateTrendDataPoints(timeRange),
      };

    case "mttr-metrics":
      return {
        overall: 5.2,
        bySeverity: {
          critical: 2.1,
          high: 4.5,
          medium: 8.3,
          low: 14.7,
        },
        trend: { direction: "down", change: -1.5 },
      };

    case "scan-coverage":
      return {
        totalAssets: 150,
        scannedAssets: 142,
        coveragePercent: 94.7,
        staleScans: 5,
        neverScanned: 3,
      };

    case "remediation-status":
      return {
        open: 45,
        inProgress: 12,
        fixed: 230,
        avgDaysToFix: 5.2,
      };

    case "custom-text":
      return {
        content: section.options?.content || "",
      };

    case "custom-table":
      return {
        columns: section.options?.columns || [],
        rows: [],
      };

    default:
      return {};
  }
}

/**
 * Generate mock vulnerabilities for testing
 */
function generateMockVulnerabilities(limit: number): unknown[] {
  const vulns: unknown[] = [];
  const severities: SeverityLevel[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

  for (let i = 0; i < Math.min(limit, 45); i++) {
    vulns.push({
      id: `CVE-2024-${1000 + i}`,
      severity: severities[i % 4],
      pkg: `package-${i}`,
      version: "1.0.0",
      fixedVersion: "1.0.1",
      description: `Sample vulnerability ${i + 1}`,
    });
  }

  return vulns;
}

/**
 * Generate trend data points
 */
function generateTrendDataPoints(timeRange: DashboardTimeRange): unknown[] {
  const days = timeRange === "24h" ? 1 : timeRange === "7d" ? 7 : timeRange === "30d" ? 30 : 90;
  const points: unknown[] = [];
  const now = Date.now();

  for (let i = days - 1; i >= 0; i--) {
    const date = new Date(now - i * 24 * 60 * 60 * 1000);
    points.push({
      date: date.toISOString().split("T")[0],
      critical: Math.floor(Math.random() * 5),
      high: Math.floor(Math.random() * 15),
      medium: Math.floor(Math.random() * 30),
      low: Math.floor(Math.random() * 50),
    });
  }

  return points;
}

/**
 * Calculate report summary from section data
 */
function calculateReportSummary(sectionData: Record<string, unknown>): GeneratedReport["summary"] {
  const vulnSummary = sectionData["vulnerability-summary"] as
    | { total?: number; critical?: number; high?: number }
    | undefined;
  const healthScore = sectionData["health-score"] as { score?: number } | undefined;
  const compliance = sectionData["compliance-status"] as { overallPercentage?: number } | undefined;

  return {
    totalVulnerabilities: vulnSummary?.total || 0,
    criticalCount: vulnSummary?.critical || 0,
    highCount: vulnSummary?.high || 0,
    healthScore: healthScore?.score,
    compliancePercent: compliance?.overallPercentage,
  };
}

// =============================================================================
// HTML Report Generation
// =============================================================================

/**
 * Generate HTML report
 */
function generateHtmlReport(
  template: ReportTemplate,
  sectionData: Record<string, unknown>,
  context: {
    title: string;
    generatedAt: string;
    branding: ReportBranding;
    filters: ReportFilters;
    includeToc?: boolean;
    includeTimestamp?: boolean;
  }
): string {
  const { title, generatedAt, branding, filters, includeToc, includeTimestamp } = context;

  const css = generateReportCss(branding);
  const header = renderTemplate(template.headerTemplate || "", {
    ...context,
    companyName: branding.companyName,
  });
  const footer = renderTemplate(template.footerTemplate || "", {
    ...context,
    companyName: branding.companyName,
  });

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)}</title>
  <style>${css}</style>
  ${branding.customCss ? `<style>${branding.customCss}</style>` : ""}
</head>
<body>
  ${header}
  <main class="report-content">
    <h1 class="report-title">${escapeHtml(title)}</h1>
    ${includeTimestamp !== false ? `<p class="report-timestamp">Generated: ${generatedAt}</p>` : ""}
    ${filters.timeRange ? `<p class="report-period">Report Period: ${filters.timeRange}</p>` : ""}
`;

  if (includeToc) {
    html += generateToc(template.sections);
  }

  for (const section of template.sections) {
    if (!section.enabled) {
      continue;
    }
    html += generateHtmlSection(section, sectionData[section.type]);
  }

  html += `
  </main>
  ${footer}
</body>
</html>`;

  return html;
}

/**
 * Generate CSS for the report
 */
function generateReportCss(branding: ReportBranding): string {
  const primary = branding.primaryColor || "#2563eb";
  const secondary = branding.secondaryColor || "#64748b";

  return `
    :root {
      --primary-color: ${primary};
      --secondary-color: ${secondary};
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      line-height: 1.6;
      color: #1e293b;
      max-width: 1200px;
      margin: 0 auto;
      padding: 2rem;
    }

    .header, .footer {
      padding: 1rem 0;
      border-bottom: 2px solid var(--primary-color);
    }

    .footer {
      border-bottom: none;
      border-top: 2px solid var(--primary-color);
      margin-top: 2rem;
    }

    .report-title {
      color: var(--primary-color);
      margin-bottom: 0.5rem;
    }

    .report-timestamp, .report-period {
      color: var(--secondary-color);
      font-size: 0.9rem;
    }

    .section {
      margin: 2rem 0;
      padding: 1.5rem;
      background: #f8fafc;
      border-radius: 8px;
    }

    .section-title {
      color: var(--primary-color);
      margin-top: 0;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 0.5rem;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin: 1rem 0;
    }

    th, td {
      padding: 0.75rem;
      text-align: left;
      border-bottom: 1px solid #e2e8f0;
    }

    th {
      background: var(--primary-color);
      color: white;
    }

    tr:nth-child(even) {
      background: #f1f5f9;
    }

    .severity-critical { color: #dc2626; font-weight: bold; }
    .severity-high { color: #ea580c; font-weight: bold; }
    .severity-medium { color: #ca8a04; }
    .severity-low { color: #16a34a; }

    .health-score {
      font-size: 3rem;
      font-weight: bold;
      text-align: center;
      padding: 1rem;
    }

    .health-score.grade-a { color: #16a34a; }
    .health-score.grade-b { color: #65a30d; }
    .health-score.grade-c { color: #ca8a04; }
    .health-score.grade-d { color: #ea580c; }
    .health-score.grade-f { color: #dc2626; }

    .metric-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
    }

    .metric-card {
      background: white;
      padding: 1rem;
      border-radius: 6px;
      text-align: center;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }

    .metric-value {
      font-size: 2rem;
      font-weight: bold;
      color: var(--primary-color);
    }

    .metric-label {
      color: var(--secondary-color);
      font-size: 0.85rem;
    }

    .toc {
      background: #f1f5f9;
      padding: 1rem 2rem;
      border-radius: 6px;
      margin: 1rem 0;
    }

    .toc-title {
      font-weight: bold;
      margin-bottom: 0.5rem;
    }

    .toc ul {
      margin: 0;
      padding-left: 1.5rem;
    }

    .toc li {
      margin: 0.25rem 0;
    }

    .toc a {
      color: var(--primary-color);
      text-decoration: none;
    }

    .toc a:hover {
      text-decoration: underline;
    }

    @media print {
      body { padding: 0; }
      .section { break-inside: avoid; }
    }
  `;
}

/**
 * Generate table of contents
 */
function generateToc(sections: ReportSection[]): string {
  const enabledSections = sections.filter((s) => s.enabled);

  if (enabledSections.length === 0) {
    return "";
  }

  let toc = `<nav class="toc">
    <div class="toc-title">Table of Contents</div>
    <ul>`;

  for (const section of enabledSections) {
    const sectionTitle = section.title || getSectionDefaultTitle(section.type);
    const id = `section-${section.type}`;
    toc += `<li><a href="#${id}">${escapeHtml(sectionTitle)}</a></li>`;
  }

  toc += `</ul></nav>`;
  return toc;
}

/**
 * Generate HTML for a section
 */
function generateHtmlSection(section: ReportSection, data: unknown): string {
  const sectionTitle = section.title || getSectionDefaultTitle(section.type);
  const id = `section-${section.type}`;

  let content = "";

  switch (section.type) {
    case "health-score": {
      const hs = data as { score: number; grade: string; components: Record<string, number> };
      content = `
        <div class="health-score grade-${hs.grade.toLowerCase()}">${hs.score}/100 (${hs.grade})</div>
        <div class="metric-grid">
          ${Object.entries(hs.components)
            .map(
              ([key, value]) => `
            <div class="metric-card">
              <div class="metric-value">${value}%</div>
              <div class="metric-label">${key}</div>
            </div>
          `
            )
            .join("")}
        </div>
      `;
      break;
    }

    case "vulnerability-summary": {
      const vs = data as {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
      };
      content = `
        <div class="metric-grid">
          <div class="metric-card">
            <div class="metric-value">${vs.total}</div>
            <div class="metric-label">Total</div>
          </div>
          <div class="metric-card">
            <div class="metric-value severity-critical">${vs.critical}</div>
            <div class="metric-label">Critical</div>
          </div>
          <div class="metric-card">
            <div class="metric-value severity-high">${vs.high}</div>
            <div class="metric-label">High</div>
          </div>
          <div class="metric-card">
            <div class="metric-value severity-medium">${vs.medium}</div>
            <div class="metric-label">Medium</div>
          </div>
          <div class="metric-card">
            <div class="metric-value severity-low">${vs.low}</div>
            <div class="metric-label">Low</div>
          </div>
        </div>
      `;
      break;
    }

    case "vulnerability-list": {
      const vl = data as {
        items: Array<{
          id: string;
          severity: string;
          pkg: string;
          version: string;
          fixedVersion: string;
          description: string;
        }>;
        total: number;
        showing: number;
      };
      content = `
        <p>Showing ${vl.showing} of ${vl.total} vulnerabilities</p>
        <table>
          <thead>
            <tr>
              <th>CVE ID</th>
              <th>Severity</th>
              <th>Package</th>
              <th>Version</th>
              <th>Fixed In</th>
            </tr>
          </thead>
          <tbody>
            ${vl.items
              .map(
                (v) => `
              <tr>
                <td>${escapeHtml(v.id)}</td>
                <td class="severity-${v.severity.toLowerCase()}">${v.severity}</td>
                <td>${escapeHtml(v.pkg)}</td>
                <td>${escapeHtml(v.version)}</td>
                <td>${escapeHtml(v.fixedVersion)}</td>
              </tr>
            `
              )
              .join("")}
          </tbody>
        </table>
      `;
      break;
    }

    case "compliance-status": {
      const cs = data as {
        frameworks: Array<{ name: string; status: string; percentage: number }>;
        overallPercentage: number;
      };
      content = `
        <p>Overall Compliance: <strong>${cs.overallPercentage.toFixed(1)}%</strong></p>
        <table>
          <thead>
            <tr>
              <th>Framework</th>
              <th>Status</th>
              <th>Compliance %</th>
            </tr>
          </thead>
          <tbody>
            ${cs.frameworks
              .map(
                (f) => `
              <tr>
                <td>${escapeHtml(f.name)}</td>
                <td>${f.status === "compliant" ? "Compliant" : "Partial"}</td>
                <td>${f.percentage}%</td>
              </tr>
            `
              )
              .join("")}
          </tbody>
        </table>
      `;
      break;
    }

    case "top-risks": {
      const tr = data as { items: Array<{ target: string; score: number; criticalCount: number }> };
      content = `
        <table>
          <thead>
            <tr>
              <th>Rank</th>
              <th>Target</th>
              <th>Risk Score</th>
              <th>Critical Count</th>
            </tr>
          </thead>
          <tbody>
            ${tr.items
              .map(
                (r, i) => `
              <tr>
                <td>${i + 1}</td>
                <td>${escapeHtml(r.target)}</td>
                <td>${r.score}</td>
                <td class="${r.criticalCount > 0 ? "severity-critical" : ""}">${r.criticalCount}</td>
              </tr>
            `
              )
              .join("")}
          </tbody>
        </table>
      `;
      break;
    }

    case "mttr-metrics": {
      const mt = data as { overall: number; bySeverity: Record<string, number> };
      content = `
        <div class="metric-grid">
          <div class="metric-card">
            <div class="metric-value">${mt.overall.toFixed(1)} days</div>
            <div class="metric-label">Overall MTTR</div>
          </div>
          ${Object.entries(mt.bySeverity)
            .map(
              ([sev, days]) => `
            <div class="metric-card">
              <div class="metric-value">${(days as number).toFixed(1)} days</div>
              <div class="metric-label">${sev.toUpperCase()}</div>
            </div>
          `
            )
            .join("")}
        </div>
      `;
      break;
    }

    case "scan-coverage": {
      const sc = data as {
        totalAssets: number;
        scannedAssets: number;
        coveragePercent: number;
        staleScans: number;
        neverScanned: number;
      };
      content = `
        <div class="metric-grid">
          <div class="metric-card">
            <div class="metric-value">${sc.coveragePercent.toFixed(1)}%</div>
            <div class="metric-label">Coverage</div>
          </div>
          <div class="metric-card">
            <div class="metric-value">${sc.scannedAssets}/${sc.totalAssets}</div>
            <div class="metric-label">Assets Scanned</div>
          </div>
          <div class="metric-card">
            <div class="metric-value">${sc.staleScans}</div>
            <div class="metric-label">Stale Scans</div>
          </div>
          <div class="metric-card">
            <div class="metric-value">${sc.neverScanned}</div>
            <div class="metric-label">Never Scanned</div>
          </div>
        </div>
      `;
      break;
    }

    case "remediation-status": {
      const rs = data as { open: number; inProgress: number; fixed: number; avgDaysToFix: number };
      content = `
        <div class="metric-grid">
          <div class="metric-card">
            <div class="metric-value severity-high">${rs.open}</div>
            <div class="metric-label">Open</div>
          </div>
          <div class="metric-card">
            <div class="metric-value severity-medium">${rs.inProgress}</div>
            <div class="metric-label">In Progress</div>
          </div>
          <div class="metric-card">
            <div class="metric-value severity-low">${rs.fixed}</div>
            <div class="metric-label">Fixed</div>
          </div>
          <div class="metric-card">
            <div class="metric-value">${rs.avgDaysToFix.toFixed(1)} days</div>
            <div class="metric-label">Avg. Days to Fix</div>
          </div>
        </div>
      `;
      break;
    }

    case "trend-chart": {
      const tc = data as {
        timeRange: string;
        dataPoints: Array<{
          date: string;
          critical: number;
          high: number;
          medium: number;
          low: number;
        }>;
      };
      content = `
        <p>Vulnerability trend over ${tc.timeRange}</p>
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Critical</th>
              <th>High</th>
              <th>Medium</th>
              <th>Low</th>
            </tr>
          </thead>
          <tbody>
            ${tc.dataPoints
              .slice(-10)
              .map(
                (p) => `
              <tr>
                <td>${p.date}</td>
                <td class="severity-critical">${p.critical}</td>
                <td class="severity-high">${p.high}</td>
                <td class="severity-medium">${p.medium}</td>
                <td class="severity-low">${p.low}</td>
              </tr>
            `
              )
              .join("")}
          </tbody>
        </table>
      `;
      break;
    }

    case "custom-text": {
      const ct = data as { content: string };
      content = `<div class="custom-content">${ct.content}</div>`;
      break;
    }

    default:
      content = `<p>Unknown section type: ${section.type}</p>`;
  }

  return `
    <section class="section" id="${id}">
      <h2 class="section-title">${escapeHtml(sectionTitle)}</h2>
      ${content}
    </section>
  `;
}

// =============================================================================
// Markdown Report Generation
// =============================================================================

/**
 * Generate Markdown report
 */
function generateMarkdownReport(
  template: ReportTemplate,
  sectionData: Record<string, unknown>,
  context: {
    title: string;
    generatedAt: string;
    filters: ReportFilters;
    includeToc?: boolean;
    includeTimestamp?: boolean;
  }
): string {
  const { title, generatedAt, filters, includeToc, includeTimestamp } = context;

  let md = `# ${title}\n\n`;

  if (includeTimestamp !== false) {
    md += `*Generated: ${generatedAt}*\n\n`;
  }

  if (filters.timeRange) {
    md += `*Report Period: ${filters.timeRange}*\n\n`;
  }

  if (includeToc) {
    md += `## Table of Contents\n\n`;
    for (const section of template.sections) {
      if (section.enabled) {
        const secTitle = section.title || getSectionDefaultTitle(section.type);
        const anchor = secTitle.toLowerCase().replace(/\s+/g, "-");
        md += `- [${secTitle}](#${anchor})\n`;
      }
    }
    md += "\n";
  }

  for (const section of template.sections) {
    if (!section.enabled) {
      continue;
    }
    md += generateMarkdownSection(section, sectionData[section.type]);
  }

  return md;
}

/**
 * Generate Markdown for a section
 */
function generateMarkdownSection(section: ReportSection, data: unknown): string {
  const sectionTitle = section.title || getSectionDefaultTitle(section.type);
  let md = `## ${sectionTitle}\n\n`;

  switch (section.type) {
    case "health-score": {
      const hs = data as { score: number; grade: string; components: Record<string, number> };
      md += `**Health Score: ${hs.score}/100 (Grade: ${hs.grade})**\n\n`;
      md += "| Component | Score |\n|-----------|-------|\n";
      for (const [key, value] of Object.entries(hs.components)) {
        md += `| ${key} | ${value}% |\n`;
      }
      md += "\n";
      break;
    }

    case "vulnerability-summary": {
      const vs = data as {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
      };
      md += `| Severity | Count |\n|----------|-------|\n`;
      md += `| **Total** | ${vs.total} |\n`;
      md += `| Critical | ${vs.critical} |\n`;
      md += `| High | ${vs.high} |\n`;
      md += `| Medium | ${vs.medium} |\n`;
      md += `| Low | ${vs.low} |\n\n`;
      break;
    }

    case "vulnerability-list": {
      const vl = data as {
        items: Array<{
          id: string;
          severity: string;
          pkg: string;
          version: string;
          fixedVersion: string;
        }>;
        total: number;
        showing: number;
      };
      md += `*Showing ${vl.showing} of ${vl.total} vulnerabilities*\n\n`;
      md += "| CVE ID | Severity | Package | Version | Fixed In |\n";
      md += "|--------|----------|---------|---------|----------|\n";
      for (const v of vl.items) {
        md += `| ${v.id} | ${v.severity} | ${v.pkg} | ${v.version} | ${v.fixedVersion} |\n`;
      }
      md += "\n";
      break;
    }

    case "compliance-status": {
      const cs = data as {
        frameworks: Array<{ name: string; status: string; percentage: number }>;
        overallPercentage: number;
      };
      md += `**Overall Compliance: ${cs.overallPercentage.toFixed(1)}%**\n\n`;
      md += "| Framework | Status | Compliance % |\n";
      md += "|-----------|--------|-------------|\n";
      for (const f of cs.frameworks) {
        md += `| ${f.name} | ${f.status} | ${f.percentage}% |\n`;
      }
      md += "\n";
      break;
    }

    case "top-risks": {
      const tr = data as { items: Array<{ target: string; score: number; criticalCount: number }> };
      md += "| Rank | Target | Risk Score | Critical Count |\n";
      md += "|------|--------|------------|----------------|\n";
      for (let i = 0; i < tr.items.length; i++) {
        const r = tr.items[i];
        md += `| ${i + 1} | ${r.target} | ${r.score} | ${r.criticalCount} |\n`;
      }
      md += "\n";
      break;
    }

    case "mttr-metrics": {
      const mt = data as { overall: number; bySeverity: Record<string, number> };
      md += `**Overall MTTR: ${mt.overall.toFixed(1)} days**\n\n`;
      md += "| Severity | MTTR (days) |\n|----------|-------------|\n";
      for (const [sev, days] of Object.entries(mt.bySeverity)) {
        md += `| ${sev.toUpperCase()} | ${(days as number).toFixed(1)} |\n`;
      }
      md += "\n";
      break;
    }

    case "scan-coverage": {
      const sc = data as {
        totalAssets: number;
        scannedAssets: number;
        coveragePercent: number;
        staleScans: number;
        neverScanned: number;
      };
      md += `- **Coverage:** ${sc.coveragePercent.toFixed(1)}%\n`;
      md += `- **Assets Scanned:** ${sc.scannedAssets}/${sc.totalAssets}\n`;
      md += `- **Stale Scans:** ${sc.staleScans}\n`;
      md += `- **Never Scanned:** ${sc.neverScanned}\n\n`;
      break;
    }

    case "remediation-status": {
      const rs = data as { open: number; inProgress: number; fixed: number; avgDaysToFix: number };
      md += `- **Open:** ${rs.open}\n`;
      md += `- **In Progress:** ${rs.inProgress}\n`;
      md += `- **Fixed:** ${rs.fixed}\n`;
      md += `- **Avg. Days to Fix:** ${rs.avgDaysToFix.toFixed(1)}\n\n`;
      break;
    }

    case "custom-text": {
      const ct = data as { content: string };
      md += `${ct.content}\n\n`;
      break;
    }

    default:
      md += `*Section type "${section.type}" data available in JSON format*\n\n`;
  }

  return md;
}

// =============================================================================
// Schedule Management
// =============================================================================

/**
 * Create a new report schedule
 */
export function createReportSchedule(options: CreateScheduleOptions): ReportSchedule {
  const database = getDb();
  const id = `sched-${crypto.randomUUID()}`;
  const now = new Date().toISOString();

  // Validate template exists
  const template = getTemplate(options.templateId);
  if (!template) {
    throw new Error(`Template not found: ${options.templateId}`);
  }

  // Calculate next run time
  const nextRunAt = calculateNextRunTime(options);

  const stmt = database.prepare(`
    INSERT INTO report_schedules
    (id, name, template_id, frequency, cron_expression, day_of_week, day_of_month, hour, minute, timezone, filters_json, email_recipients_json, webhook_json, enabled, created_at, updated_at, next_run_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    id,
    options.name,
    options.templateId,
    options.frequency,
    options.cronExpression || null,
    options.dayOfWeek ?? null,
    options.dayOfMonth ?? null,
    options.hour ?? 8,
    options.minute ?? 0,
    options.timezone || "UTC",
    options.filters ? JSON.stringify(options.filters) : null,
    options.emailRecipients ? JSON.stringify(options.emailRecipients) : null,
    options.webhook ? JSON.stringify(options.webhook) : null,
    options.enabled !== false ? 1 : 0,
    now,
    now,
    nextRunAt
  );

  return getReportSchedule(id)!;
}

/**
 * Get a schedule by ID
 */
export function getReportSchedule(id: string): ReportSchedule | null {
  const database = getDb();
  const row = database.prepare("SELECT * FROM report_schedules WHERE id = ?").get(id) as
    | ScheduleRow
    | undefined;

  if (!row) {
    return null;
  }

  return rowToSchedule(row);
}

/**
 * List all schedules
 */
export function listReportSchedules(options?: {
  templateId?: string;
  enabled?: boolean;
}): ReportSchedule[] {
  const database = getDb();
  let sql = "SELECT * FROM report_schedules WHERE 1=1";
  const params: (string | number)[] = [];

  if (options?.templateId) {
    sql += " AND template_id = ?";
    params.push(options.templateId);
  }

  if (options?.enabled !== undefined) {
    sql += " AND enabled = ?";
    params.push(options.enabled ? 1 : 0);
  }

  sql += " ORDER BY next_run_at ASC";

  const rows = database.prepare(sql).all(...params) as ScheduleRow[];
  return rows.map(rowToSchedule);
}

/**
 * Update a schedule
 */
export function updateReportSchedule(
  id: string,
  updates: Partial<CreateScheduleOptions>
): ReportSchedule | null {
  const database = getDb();
  const existing = getReportSchedule(id);

  if (!existing) {
    return null;
  }

  const now = new Date().toISOString();
  const setClauses: string[] = ["updated_at = ?"];
  const params: (string | number | null)[] = [now];

  if (updates.name !== undefined) {
    setClauses.push("name = ?");
    params.push(updates.name);
  }
  if (updates.templateId !== undefined) {
    setClauses.push("template_id = ?");
    params.push(updates.templateId);
  }
  if (updates.frequency !== undefined) {
    setClauses.push("frequency = ?");
    params.push(updates.frequency);
  }
  if (updates.cronExpression !== undefined) {
    setClauses.push("cron_expression = ?");
    params.push(updates.cronExpression);
  }
  if (updates.dayOfWeek !== undefined) {
    setClauses.push("day_of_week = ?");
    params.push(updates.dayOfWeek);
  }
  if (updates.dayOfMonth !== undefined) {
    setClauses.push("day_of_month = ?");
    params.push(updates.dayOfMonth);
  }
  if (updates.hour !== undefined) {
    setClauses.push("hour = ?");
    params.push(updates.hour);
  }
  if (updates.minute !== undefined) {
    setClauses.push("minute = ?");
    params.push(updates.minute);
  }
  if (updates.timezone !== undefined) {
    setClauses.push("timezone = ?");
    params.push(updates.timezone);
  }
  if (updates.filters !== undefined) {
    setClauses.push("filters_json = ?");
    params.push(JSON.stringify(updates.filters));
  }
  if (updates.emailRecipients !== undefined) {
    setClauses.push("email_recipients_json = ?");
    params.push(JSON.stringify(updates.emailRecipients));
  }
  if (updates.webhook !== undefined) {
    setClauses.push("webhook_json = ?");
    params.push(JSON.stringify(updates.webhook));
  }
  if (updates.enabled !== undefined) {
    setClauses.push("enabled = ?");
    params.push(updates.enabled ? 1 : 0);
  }

  // Recalculate next run time if schedule changed
  const mergedOptions = { ...existing, ...updates };
  const nextRunAt = calculateNextRunTime(mergedOptions);
  setClauses.push("next_run_at = ?");
  params.push(nextRunAt);

  params.push(id);

  database
    .prepare(`UPDATE report_schedules SET ${setClauses.join(", ")} WHERE id = ?`)
    .run(...params);

  return getReportSchedule(id);
}

/**
 * Delete a schedule
 */
export function deleteReportSchedule(id: string): boolean {
  const database = getDb();
  const result = database.prepare("DELETE FROM report_schedules WHERE id = ?").run(id);
  return result.changes > 0;
}

/**
 * Calculate the next run time for a schedule
 */
function calculateNextRunTime(options: CreateScheduleOptions | ReportSchedule): string {
  const now = new Date();
  const hour = options.hour ?? 8;
  const minute = options.minute ?? 0;

  const next = new Date(now);
  next.setHours(hour, minute, 0, 0);

  // If the time has passed today, move to next occurrence
  if (next <= now) {
    next.setDate(next.getDate() + 1);
  }

  switch (options.frequency) {
    case "once":
      // Already set
      break;

    case "daily":
      // Already set to next occurrence
      break;

    case "weekly": {
      const targetDay = options.dayOfWeek ?? 1; // Default to Monday
      while (next.getDay() !== targetDay) {
        next.setDate(next.getDate() + 1);
      }
      break;
    }

    case "monthly": {
      const targetDate = options.dayOfMonth ?? 1;
      next.setDate(targetDate);
      if (next <= now) {
        next.setMonth(next.getMonth() + 1);
      }
      break;
    }
  }

  return next.toISOString();
}

// =============================================================================
// Report History
// =============================================================================

/**
 * Record a report in history
 */
function recordReportHistory(entry: Omit<ReportHistoryEntry, "error" | "filePath">): void {
  try {
    const database = getDb();
    const stmt = database.prepare(`
      INSERT INTO report_history (id, schedule_id, template_id, title, format, generated_at, duration_ms, status, summary_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      entry.id,
      entry.scheduleId || null,
      entry.templateId,
      entry.title,
      entry.format,
      entry.generatedAt,
      entry.durationMs,
      entry.status,
      entry.summary ? JSON.stringify(entry.summary) : null
    );
  } catch {
    // Ignore history recording errors
  }
}

/**
 * Get report history
 */
export function getReportHistory(options?: {
  templateId?: string;
  scheduleId?: string;
  limit?: number;
  since?: string;
}): ReportHistoryEntry[] {
  const database = getDb();
  let sql = "SELECT * FROM report_history WHERE 1=1";
  const params: (string | number)[] = [];

  if (options?.templateId) {
    sql += " AND template_id = ?";
    params.push(options.templateId);
  }

  if (options?.scheduleId) {
    sql += " AND schedule_id = ?";
    params.push(options.scheduleId);
  }

  if (options?.since) {
    sql += " AND generated_at >= ?";
    params.push(options.since);
  }

  sql += " ORDER BY generated_at DESC";

  if (options?.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }

  const rows = database.prepare(sql).all(...params) as HistoryRow[];
  return rows.map(rowToHistory);
}

/**
 * Clean up old report history
 */
export function cleanupReportHistory(retentionDays: number): number {
  const database = getDb();
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
  const result = database.prepare("DELETE FROM report_history WHERE generated_at < ?").run(cutoff);
  return result.changes;
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Get default title for a section type
 */
function getSectionDefaultTitle(type: ReportSectionType): string {
  const titles: Record<ReportSectionType, string> = {
    "health-score": "Security Health Score",
    "vulnerability-summary": "Vulnerability Summary",
    "vulnerability-list": "Vulnerability Details",
    "compliance-status": "Compliance Status",
    "top-risks": "Top Risks",
    "trend-chart": "Vulnerability Trends",
    "mttr-metrics": "Mean Time to Remediation",
    "scan-coverage": "Scan Coverage",
    "remediation-status": "Remediation Status",
    "custom-text": "Notes",
    "custom-table": "Custom Data",
  };
  return titles[type] || type;
}

/**
 * Simple template rendering (Handlebars-like)
 */
function renderTemplate(template: string, context: Record<string, unknown>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key) => {
    const value = context[key];
    return value !== undefined ? String(value) : "";
  });
}

/**
 * Escape HTML special characters
 */
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// =============================================================================
// Database Row Types and Converters
// =============================================================================

interface TemplateRow {
  id: string;
  name: string;
  description: string;
  is_builtin: number;
  format: string;
  sections_json: string;
  default_filters_json: string | null;
  branding_json: string | null;
  header_template: string | null;
  footer_template: string | null;
  created_at: string;
  updated_at: string;
  created_by: string | null;
}

interface ScheduleRow {
  id: string;
  name: string;
  template_id: string;
  frequency: string;
  cron_expression: string | null;
  day_of_week: number | null;
  day_of_month: number | null;
  hour: number;
  minute: number;
  timezone: string;
  filters_json: string | null;
  email_recipients_json: string | null;
  webhook_json: string | null;
  enabled: number;
  created_at: string;
  updated_at: string;
  last_run_at: string | null;
  next_run_at: string | null;
  last_run_status: string | null;
  last_run_error: string | null;
}

interface HistoryRow {
  id: string;
  schedule_id: string | null;
  template_id: string;
  title: string;
  format: string;
  generated_at: string;
  duration_ms: number;
  status: string;
  error: string | null;
  file_path: string | null;
  summary_json: string | null;
}

function rowToTemplate(row: TemplateRow): ReportTemplate {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    isBuiltin: row.is_builtin === 1,
    format: row.format as ReportFormat,
    sections: JSON.parse(row.sections_json) as ReportSection[],
    defaultFilters: row.default_filters_json ? JSON.parse(row.default_filters_json) : undefined,
    branding: row.branding_json ? JSON.parse(row.branding_json) : undefined,
    headerTemplate: row.header_template || undefined,
    footerTemplate: row.footer_template || undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    createdBy: row.created_by || undefined,
  };
}

function rowToSchedule(row: ScheduleRow): ReportSchedule {
  return {
    id: row.id,
    name: row.name,
    templateId: row.template_id,
    frequency: row.frequency as ReportScheduleFrequency,
    cronExpression: row.cron_expression || undefined,
    dayOfWeek: row.day_of_week ?? undefined,
    dayOfMonth: row.day_of_month ?? undefined,
    hour: row.hour,
    minute: row.minute,
    timezone: row.timezone,
    filters: row.filters_json ? JSON.parse(row.filters_json) : undefined,
    emailRecipients: row.email_recipients_json ? JSON.parse(row.email_recipients_json) : undefined,
    webhook: row.webhook_json ? JSON.parse(row.webhook_json) : undefined,
    enabled: row.enabled === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastRunAt: row.last_run_at || undefined,
    nextRunAt: row.next_run_at || undefined,
    lastRunStatus: row.last_run_status as "success" | "failed" | undefined,
    lastRunError: row.last_run_error || undefined,
  };
}

function rowToHistory(row: HistoryRow): ReportHistoryEntry {
  return {
    id: row.id,
    scheduleId: row.schedule_id || undefined,
    templateId: row.template_id,
    title: row.title,
    format: row.format as ReportFormat,
    generatedAt: row.generated_at,
    durationMs: row.duration_ms,
    status: row.status as "success" | "failed",
    error: row.error || undefined,
    filePath: row.file_path || undefined,
    summary: row.summary_json ? JSON.parse(row.summary_json) : undefined,
  };
}
