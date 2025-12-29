/**
 * Report Export Module - PDF, Excel, CSV export functionality
 *
 * Provides professional report generation capabilities:
 * - PDF export with branding and table of contents
 * - Excel export with multiple worksheets and charts
 * - CSV export with configurable formatting
 */

import * as fs from "fs";
import * as path from "path";
import type {
  PdfExportOptions,
  PdfExportResult,
  ExcelExportOptions,
  ExcelExportResult,
  CsvExportOptions,
  ExportResult,
  ReportData,
  PdfPageSize,
  PdfOrientation,
} from "./types.js";

// Dynamic imports for optional dependencies
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let puppeteerModule: any = null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let ExcelJSModule: any = null;

/**
 * Lazy load puppeteer
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function getPuppeteer(): Promise<any> {
  if (!puppeteerModule) {
    puppeteerModule = await import("puppeteer");
  }
  return puppeteerModule;
}

/**
 * Lazy load ExcelJS
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function getExcelJS(): Promise<any> {
  if (!ExcelJSModule) {
    ExcelJSModule = await import("exceljs");
  }
  return ExcelJSModule;
}

/**
 * Get page dimensions for PDF export
 */
function getPageDimensions(
  size: PdfPageSize,
  orientation: PdfOrientation
): { width: string; height: string } {
  const sizes: Record<PdfPageSize, { width: string; height: string }> = {
    A4: { width: "210mm", height: "297mm" },
    Letter: { width: "8.5in", height: "11in" },
    Legal: { width: "8.5in", height: "14in" },
    A3: { width: "297mm", height: "420mm" },
    Tabloid: { width: "11in", height: "17in" },
  };

  const dims = sizes[size] || sizes.A4;
  if (orientation === "landscape") {
    return { width: dims.height, height: dims.width };
  }
  return dims;
}

/**
 * Generate HTML content for PDF export
 */
function generatePdfHtml(data: ReportData, options: PdfExportOptions): string {
  const branding = options.branding || {};
  const primaryColor = branding.primaryColor || "#2563eb";
  const secondaryColor = branding.secondaryColor || "#64748b";

  // Severity color mapping
  const severityColors: Record<string, string> = {
    CRITICAL: "#dc2626",
    HIGH: "#ea580c",
    MEDIUM: "#ca8a04",
    LOW: "#16a34a",
    UNKNOWN: "#6b7280",
  };

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(data.title)}</title>
  <style>
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      font-size: 12px;
      line-height: 1.5;
      color: #1f2937;
      padding: 40px;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 30px;
      padding-bottom: 20px;
      border-bottom: 2px solid ${primaryColor};
    }
    .header-left {
      display: flex;
      align-items: center;
      gap: 15px;
    }
    .logo {
      max-height: 50px;
      max-width: 150px;
    }
    .company-name {
      font-size: 18px;
      font-weight: bold;
      color: ${primaryColor};
    }
    .report-title {
      font-size: 24px;
      font-weight: bold;
      color: ${primaryColor};
      text-align: right;
    }
    .report-meta {
      color: ${secondaryColor};
      font-size: 11px;
      text-align: right;
      margin-top: 5px;
    }
    .toc {
      margin-bottom: 30px;
      padding: 20px;
      background: #f8fafc;
      border-radius: 8px;
    }
    .toc h2 {
      font-size: 16px;
      margin-bottom: 15px;
      color: ${primaryColor};
    }
    .toc ul {
      list-style: none;
    }
    .toc li {
      padding: 5px 0;
    }
    .toc a {
      color: #374151;
      text-decoration: none;
    }
    .section {
      margin-bottom: 30px;
      page-break-inside: avoid;
    }
    .section h2 {
      font-size: 18px;
      color: ${primaryColor};
      margin-bottom: 15px;
      padding-bottom: 8px;
      border-bottom: 1px solid #e5e7eb;
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 15px;
      margin-bottom: 20px;
    }
    .summary-card {
      background: #f8fafc;
      padding: 15px;
      border-radius: 8px;
      text-align: center;
    }
    .summary-card .value {
      font-size: 28px;
      font-weight: bold;
      color: ${primaryColor};
    }
    .summary-card .label {
      font-size: 11px;
      color: ${secondaryColor};
      margin-top: 5px;
    }
    .severity-critical { color: ${severityColors.CRITICAL}; }
    .severity-high { color: ${severityColors.HIGH}; }
    .severity-medium { color: ${severityColors.MEDIUM}; }
    .severity-low { color: ${severityColors.LOW}; }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 15px;
      font-size: 11px;
    }
    th, td {
      padding: 10px;
      text-align: left;
      border-bottom: 1px solid #e5e7eb;
    }
    th {
      background: #f1f5f9;
      font-weight: 600;
      color: #374151;
    }
    tr:nth-child(even) {
      background: #f8fafc;
    }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
    }
    .badge-critical { background: #fef2f2; color: ${severityColors.CRITICAL}; }
    .badge-high { background: #fff7ed; color: ${severityColors.HIGH}; }
    .badge-medium { background: #fefce8; color: ${severityColors.MEDIUM}; }
    .badge-low { background: #f0fdf4; color: ${severityColors.LOW}; }
    .badge-unknown { background: #f3f4f6; color: ${severityColors.UNKNOWN}; }
    .footer {
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid #e5e7eb;
      text-align: center;
      color: ${secondaryColor};
      font-size: 10px;
    }
    @media print {
      body { padding: 20px; }
      .section { page-break-inside: avoid; }
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="header-left">
`;

  if (branding.logo) {
    html += `      <img src="${branding.logo}" alt="Logo" class="logo" />\n`;
  }
  if (branding.companyName) {
    html += `      <span class="company-name">${escapeHtml(branding.companyName)}</span>\n`;
  }

  html += `    </div>
    <div>
      <div class="report-title">${escapeHtml(data.title)}</div>
      <div class="report-meta">
        Generated: ${escapeHtml(data.generatedAt)}
        ${data.target ? `<br/>Target: ${escapeHtml(data.target)}` : ""}
      </div>
    </div>
  </div>
`;

  // Table of Contents
  if (options.includeTableOfContents) {
    html += `  <div class="toc">
    <h2>Table of Contents</h2>
    <ul>
      ${data.summary ? '<li><a href="#summary">Executive Summary</a></li>' : ""}
      ${data.vulnerabilities?.length ? '<li><a href="#vulnerabilities">Vulnerability Details</a></li>' : ""}
      ${data.compliance?.length ? '<li><a href="#compliance">Compliance Status</a></li>' : ""}
      ${data.trends?.length ? '<li><a href="#trends">Trend Analysis</a></li>' : ""}
    </ul>
  </div>
`;
  }

  // Summary Section
  if (data.summary) {
    html += `  <div class="section" id="summary">
    <h2>Executive Summary</h2>
    <div class="summary-grid">
      <div class="summary-card">
        <div class="value">${data.summary.totalVulnerabilities}</div>
        <div class="label">Total Vulnerabilities</div>
      </div>
      <div class="summary-card">
        <div class="value severity-critical">${data.summary.criticalCount}</div>
        <div class="label">Critical</div>
      </div>
      <div class="summary-card">
        <div class="value severity-high">${data.summary.highCount}</div>
        <div class="label">High</div>
      </div>
      <div class="summary-card">
        <div class="value severity-medium">${data.summary.mediumCount}</div>
        <div class="label">Medium</div>
      </div>
      <div class="summary-card">
        <div class="value severity-low">${data.summary.lowCount}</div>
        <div class="label">Low</div>
      </div>
      ${
        data.summary.healthScore !== undefined
          ? `<div class="summary-card">
        <div class="value">${data.summary.healthScore}</div>
        <div class="label">Health Score</div>
      </div>`
          : ""
      }
    </div>
  </div>
`;
  }

  // Vulnerabilities Section
  if (data.vulnerabilities?.length) {
    html += `  <div class="section" id="vulnerabilities">
    <h2>Vulnerability Details</h2>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Severity</th>
          <th>Package</th>
          <th>Version</th>
          <th>Fixed Version</th>
          <th>CVSS</th>
        </tr>
      </thead>
      <tbody>
`;
    for (const vuln of data.vulnerabilities) {
      const badgeClass = `badge-${vuln.severity.toLowerCase()}`;
      html += `        <tr>
          <td>${escapeHtml(vuln.id)}</td>
          <td><span class="badge ${badgeClass}">${escapeHtml(vuln.severity)}</span></td>
          <td>${escapeHtml(vuln.package || "-")}</td>
          <td>${escapeHtml(vuln.version || "-")}</td>
          <td>${escapeHtml(vuln.fixedVersion || "-")}</td>
          <td>${vuln.cvss !== undefined ? vuln.cvss.toFixed(1) : "-"}</td>
        </tr>
`;
    }
    html += `      </tbody>
    </table>
  </div>
`;
  }

  // Compliance Section
  if (data.compliance?.length) {
    html += `  <div class="section" id="compliance">
    <h2>Compliance Status</h2>
    <table>
      <thead>
        <tr>
          <th>Framework</th>
          <th>Control</th>
          <th>Status</th>
          <th>Findings</th>
        </tr>
      </thead>
      <tbody>
`;
    for (const item of data.compliance) {
      const statusClass =
        item.status === "PASS"
          ? "badge-low"
          : item.status === "FAIL"
            ? "badge-critical"
            : "badge-medium";
      html += `        <tr>
          <td>${escapeHtml(item.framework)}</td>
          <td>${escapeHtml(item.control)}</td>
          <td><span class="badge ${statusClass}">${escapeHtml(item.status)}</span></td>
          <td>${item.findings}</td>
        </tr>
`;
    }
    html += `      </tbody>
    </table>
  </div>
`;
  }

  // Footer
  if (options.includeTimestamp) {
    html += `  <div class="footer">
    Generated by CI/CD Security Platform | ${new Date().toISOString()}
  </div>
`;
  }

  html += `</body>
</html>`;

  return html;
}

/**
 * Export report data to PDF format
 */
export async function exportToPdf(
  data: ReportData,
  options: PdfExportOptions
): Promise<PdfExportResult> {
  const startTime = Date.now();

  try {
    const pptr = await getPuppeteer();
    const browser = await pptr.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });

    try {
      const page = await browser.newPage();

      // Generate HTML content
      const html = generatePdfHtml(data, options);
      await page.setContent(html, { waitUntil: "networkidle0" });

      // Get page dimensions
      const pageSize = options.pageSize || "A4";
      const orientation = options.orientation || "portrait";
      const dims = getPageDimensions(pageSize, orientation);

      // Generate PDF
      const pdfBuffer = await page.pdf({
        width: dims.width,
        height: dims.height,
        printBackground: options.printBackground ?? true,
        margin: options.margins || {
          top: "20mm",
          right: "15mm",
          bottom: "20mm",
          left: "15mm",
        },
        displayHeaderFooter: !!(options.header || options.footer),
        headerTemplate: formatHeaderFooterTemplate(options.header, options),
        footerTemplate: formatHeaderFooterTemplate(options.footer, options),
      });

      // Ensure output directory exists
      const outputDir = path.dirname(options.outputPath);
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }

      // Write file
      fs.writeFileSync(options.outputPath, pdfBuffer);
      const stats = fs.statSync(options.outputPath);

      // Estimate page count (rough approximation)
      const pageCount = Math.max(1, Math.ceil(pdfBuffer.length / 50000));

      return {
        success: true,
        path: options.outputPath,
        size: stats.size,
        format: "pdf",
        duration: Date.now() - startTime,
        rowCount: data.vulnerabilities?.length || 0,
        pageCount,
        hasToc: options.includeTableOfContents || false,
      };
    } finally {
      await browser.close();
    }
  } catch (error) {
    return {
      success: false,
      path: options.outputPath,
      size: 0,
      format: "pdf",
      duration: Date.now() - startTime,
      rowCount: 0,
      pageCount: 0,
      hasToc: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Format header/footer template for puppeteer
 */
function formatHeaderFooterTemplate(
  config: PdfExportOptions["header"],
  options: PdfExportOptions
): string {
  if (!config) {
    return '<div style="font-size: 10px;"></div>';
  }

  const fontSize = config.fontSize || 10;
  const replacePlaceholders = (text: string): string => {
    return text
      .replace("{page}", '<span class="pageNumber"></span>')
      .replace("{pages}", '<span class="totalPages"></span>')
      .replace("{date}", new Date().toLocaleDateString())
      .replace("{title}", options.title || "");
  };

  return `
    <div style="width: 100%; font-size: ${fontSize}px; padding: 0 20px; display: flex; justify-content: space-between;">
      <span>${config.left ? replacePlaceholders(config.left) : ""}</span>
      <span>${config.center ? replacePlaceholders(config.center) : ""}</span>
      <span>${config.right ? replacePlaceholders(config.right) : ""}</span>
    </div>
  `;
}

/**
 * Export report data to Excel format
 */
export async function exportToExcel(
  data: ReportData,
  options: ExcelExportOptions
): Promise<ExcelExportResult> {
  const startTime = Date.now();

  try {
    const Excel = await getExcelJS();
    const workbook = new Excel.Workbook();

    // Set workbook properties
    workbook.creator = options.author || "CI/CD Security Platform";
    workbook.created = new Date();
    workbook.title = options.title || data.title;
    if (options.company) {
      workbook.company = options.company;
    }

    let totalRows = 0;
    let hasCharts = false;

    // Add worksheets from options
    for (const wsConfig of options.worksheets) {
      const worksheet = workbook.addWorksheet(wsConfig.name);

      // Handle array of objects
      if (
        Array.isArray(wsConfig.data) &&
        wsConfig.data.length > 0 &&
        typeof wsConfig.data[0] === "object" &&
        !Array.isArray(wsConfig.data[0])
      ) {
        const objData = wsConfig.data as Record<string, unknown>[];

        // Set up columns
        if (wsConfig.columns) {
          worksheet.columns = wsConfig.columns.map((col) => ({
            header: col.header,
            key: col.key || col.header,
            width: col.width || 15,
          }));
        } else {
          // Auto-generate columns from data keys
          const keys = Object.keys(objData[0]);
          worksheet.columns = keys.map((key) => ({
            header: key,
            key,
            width: 15,
          }));
        }

        // Add data rows
        for (const row of objData) {
          worksheet.addRow(row);
          totalRows++;
        }
      } else if (Array.isArray(wsConfig.data)) {
        // Handle 2D array
        const arrData = wsConfig.data as unknown[][];
        for (const row of arrData) {
          worksheet.addRow(row);
          totalRows++;
        }
      }

      // Apply formatting
      if (wsConfig.freezeHeader) {
        worksheet.views = [{ state: "frozen", ySplit: 1 }];
      }

      if (wsConfig.includeFilters && worksheet.rowCount > 1) {
        worksheet.autoFilter = {
          from: { row: 1, column: 1 },
          to: { row: 1, column: worksheet.columnCount },
        };
      }

      // Style header row
      const headerRow = worksheet.getRow(1);
      headerRow.font = { bold: true };
      headerRow.fill = {
        type: "pattern",
        pattern: "solid",
        fgColor: { argb: "FFE2E8F0" },
      };

      // Apply conditional formatting for severity columns
      if (wsConfig.columns) {
        for (let i = 0; i < wsConfig.columns.length; i++) {
          const col = wsConfig.columns[i];
          if (col.conditionalSeverity) {
            applySeverityFormatting(worksheet, i + 1);
          }
          if (col.numFmt) {
            worksheet.getColumn(i + 1).numFmt = col.numFmt;
          }
          if (col.alignment) {
            worksheet.getColumn(i + 1).alignment = {
              horizontal: col.alignment,
            };
          }
        }
      }

      // Auto-width columns if requested
      if (wsConfig.autoWidth) {
        autoSizeColumns(worksheet);
      }
    }

    // Add charts if requested and trend data available
    if (options.includeCharts && data.trends?.length) {
      addTrendChart(workbook, data.trends);
      hasCharts = true;
    }

    // Ensure output directory exists
    const outputDir = path.dirname(options.outputPath);
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    // Write file
    await workbook.xlsx.writeFile(options.outputPath);
    const stats = fs.statSync(options.outputPath);

    return {
      success: true,
      path: options.outputPath,
      size: stats.size,
      format: "excel",
      duration: Date.now() - startTime,
      rowCount: totalRows,
      worksheetCount: options.worksheets.length,
      hasCharts,
    };
  } catch (error) {
    return {
      success: false,
      path: options.outputPath,
      size: 0,
      format: "excel",
      duration: Date.now() - startTime,
      rowCount: 0,
      worksheetCount: 0,
      hasCharts: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Apply severity-based conditional formatting to a column
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function applySeverityFormatting(worksheet: any, colIndex: number): void {
  const severityStyles: Record<string, { bg: string; fg: string }> = {
    CRITICAL: { bg: "FFFEF2F2", fg: "FFDC2626" },
    HIGH: { bg: "FFFFF7ED", fg: "FFEA580C" },
    MEDIUM: { bg: "FFFEFCE8", fg: "FFCA8A04" },
    LOW: { bg: "FFF0FDF4", fg: "FF16A34A" },
    UNKNOWN: { bg: "FFF3F4F6", fg: "FF6B7280" },
  };

  for (let row = 2; row <= worksheet.rowCount; row++) {
    const cell = worksheet.getCell(row, colIndex);
    const value = String(cell.value).toUpperCase();
    const style = severityStyles[value];
    if (style) {
      cell.fill = {
        type: "pattern",
        pattern: "solid",
        fgColor: { argb: style.bg },
      };
      cell.font = { color: { argb: style.fg }, bold: true };
    }
  }
}

/**
 * Auto-size columns based on content
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function autoSizeColumns(worksheet: any): void {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  worksheet.columns.forEach((column: any) => {
    let maxLength = 10;
    if (column && column.eachCell) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      column.eachCell({ includeEmpty: false }, (cell: any) => {
        const cellValue = cell.value ? String(cell.value) : "";
        maxLength = Math.max(maxLength, cellValue.length);
      });
      column.width = Math.min(50, maxLength + 2);
    }
  });
}

/**
 * Add trend chart to workbook
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function addTrendChart(workbook: any, trends: NonNullable<ReportData["trends"]>): void {
  const chartSheet = workbook.addWorksheet("Trend Chart Data");

  // Add data for chart
  chartSheet.columns = [
    { header: "Date", key: "date", width: 12 },
    { header: "Critical", key: "critical", width: 10 },
    { header: "High", key: "high", width: 10 },
    { header: "Medium", key: "medium", width: 10 },
    { header: "Low", key: "low", width: 10 },
  ];

  for (const point of trends) {
    chartSheet.addRow(point);
  }

  // Style header
  const headerRow = chartSheet.getRow(1);
  headerRow.font = { bold: true };
  headerRow.fill = {
    type: "pattern",
    pattern: "solid",
    fgColor: { argb: "FFE2E8F0" },
  };

  // Note: ExcelJS has limited chart support
  // For full charts, consider using a dedicated charting library
}

/**
 * Export data to CSV format
 */
export async function exportToCsv(options: CsvExportOptions): Promise<ExportResult> {
  const startTime = Date.now();

  try {
    const delimiter = options.delimiter || ",";
    const lineEnding = options.lineEnding || "\n";
    const columns = options.columns || Object.keys(options.data[0] || {});
    const headers = options.headers || {};

    const lines: string[] = [];

    // Add header row
    const headerRow = columns.map((col) =>
      formatCsvField(headers[col] || col, delimiter, options.quoteAll)
    );
    lines.push(headerRow.join(delimiter));

    // Add data rows
    for (const row of options.data) {
      const dataRow = columns.map((col) => {
        const value = row[col];
        return formatCsvField(
          value === null || value === undefined ? "" : String(value),
          delimiter,
          options.quoteAll
        );
      });
      lines.push(dataRow.join(delimiter));
    }

    let content = lines.join(lineEnding);

    // Add UTF-8 BOM if requested
    if (options.includeBom) {
      content = "\uFEFF" + content;
    }

    // Ensure output directory exists
    const outputDir = path.dirname(options.outputPath);
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    // Write file
    fs.writeFileSync(options.outputPath, content, "utf8");
    const stats = fs.statSync(options.outputPath);

    return {
      success: true,
      path: options.outputPath,
      size: stats.size,
      format: "csv",
      duration: Date.now() - startTime,
      rowCount: options.data.length,
    };
  } catch (error) {
    return {
      success: false,
      path: options.outputPath,
      size: 0,
      format: "csv",
      duration: Date.now() - startTime,
      rowCount: 0,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Format a value for CSV output
 */
function formatCsvField(value: string, delimiter: string, quoteAll?: boolean): string {
  const needsQuotes =
    quoteAll ||
    value.includes(delimiter) ||
    value.includes('"') ||
    value.includes("\n") ||
    value.includes("\r");

  if (needsQuotes) {
    return '"' + value.replace(/"/g, '""') + '"';
  }
  return value;
}

/**
 * Escape HTML special characters
 */
function escapeHtml(text: string): string {
  const htmlEscapes: Record<string, string> = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  };
  return text.replace(/[&<>"']/g, (char) => htmlEscapes[char]);
}

/**
 * Create vulnerability worksheet data from report data
 */
export function createVulnerabilityWorksheet(
  data: ReportData
): import("./types.js").ExcelWorksheet {
  const vulnData =
    data.vulnerabilities?.map((v) => ({
      id: v.id,
      severity: v.severity,
      package: v.package || "",
      version: v.version || "",
      fixedVersion: v.fixedVersion || "",
      title: v.title || "",
      cvss: v.cvss,
      riskScore: v.riskScore,
    })) || [];

  return {
    name: "Vulnerabilities",
    data: vulnData,
    columns: [
      { header: "ID", key: "id", width: 20 },
      {
        header: "Severity",
        key: "severity",
        width: 12,
        conditionalSeverity: true,
      },
      { header: "Package", key: "package", width: 25 },
      { header: "Version", key: "version", width: 15 },
      { header: "Fixed Version", key: "fixedVersion", width: 15 },
      { header: "Title", key: "title", width: 40 },
      { header: "CVSS", key: "cvss", width: 8, numFmt: "0.0" },
      { header: "Risk Score", key: "riskScore", width: 12, numFmt: "0.00" },
    ],
    includeFilters: true,
    freezeHeader: true,
    autoWidth: false,
  };
}

/**
 * Create summary worksheet data from report data
 */
export function createSummaryWorksheet(data: ReportData): import("./types.js").ExcelWorksheet {
  const summaryData = [];

  if (data.summary) {
    summaryData.push(
      { metric: "Total Vulnerabilities", value: data.summary.totalVulnerabilities },
      { metric: "Critical", value: data.summary.criticalCount },
      { metric: "High", value: data.summary.highCount },
      { metric: "Medium", value: data.summary.mediumCount },
      { metric: "Low", value: data.summary.lowCount }
    );

    if (data.summary.healthScore !== undefined) {
      summaryData.push({ metric: "Health Score", value: data.summary.healthScore });
    }
    if (data.summary.complianceStatus) {
      summaryData.push({
        metric: "Compliance Status",
        value: data.summary.complianceStatus,
      });
    }
  }

  return {
    name: "Summary",
    data: summaryData,
    columns: [
      { header: "Metric", key: "metric", width: 25 },
      { header: "Value", key: "value", width: 20 },
    ],
    freezeHeader: true,
  };
}

/**
 * Create compliance worksheet data from report data
 */
export function createComplianceWorksheet(data: ReportData): import("./types.js").ExcelWorksheet {
  const complianceData =
    data.compliance?.map((c) => ({
      framework: c.framework,
      control: c.control,
      status: c.status,
      findings: c.findings,
    })) || [];

  return {
    name: "Compliance",
    data: complianceData,
    columns: [
      { header: "Framework", key: "framework", width: 15 },
      { header: "Control", key: "control", width: 25 },
      { header: "Status", key: "status", width: 12, conditionalSeverity: true },
      { header: "Findings", key: "findings", width: 10 },
    ],
    includeFilters: true,
    freezeHeader: true,
  };
}

/**
 * Create a complete Excel export from report data with standard worksheets
 */
export async function exportReportToExcel(
  data: ReportData,
  outputPath: string,
  options?: Partial<ExcelExportOptions>
): Promise<ExcelExportResult> {
  const worksheets: ExcelExportOptions["worksheets"] = [createSummaryWorksheet(data)];

  if (data.vulnerabilities?.length) {
    worksheets.push(createVulnerabilityWorksheet(data));
  }

  if (data.compliance?.length) {
    worksheets.push(createComplianceWorksheet(data));
  }

  return exportToExcel(data, {
    outputPath,
    worksheets,
    title: data.title,
    includeCharts: !!data.trends?.length,
    ...options,
  });
}

/**
 * Create a complete PDF export from report data
 */
export async function exportReportToPdf(
  data: ReportData,
  outputPath: string,
  options?: Partial<PdfExportOptions>
): Promise<PdfExportResult> {
  return exportToPdf(data, {
    outputPath,
    title: data.title,
    includeTableOfContents: true,
    includePageNumbers: true,
    includeTimestamp: true,
    printBackground: true,
    ...options,
  });
}

/**
 * Create a complete CSV export from vulnerability data
 */
export async function exportVulnerabilitiesToCsv(
  data: ReportData,
  outputPath: string,
  options?: Partial<CsvExportOptions>
): Promise<ExportResult> {
  const csvData =
    data.vulnerabilities?.map((v) => ({
      id: v.id,
      severity: v.severity,
      package: v.package || "",
      version: v.version || "",
      fixedVersion: v.fixedVersion || "",
      title: v.title || "",
      description: v.description || "",
      cvss: v.cvss !== undefined ? String(v.cvss) : "",
      riskScore: v.riskScore !== undefined ? String(v.riskScore) : "",
    })) || [];

  return exportToCsv({
    outputPath,
    data: csvData,
    columns: [
      "id",
      "severity",
      "package",
      "version",
      "fixedVersion",
      "title",
      "description",
      "cvss",
      "riskScore",
    ],
    headers: {
      id: "Vulnerability ID",
      severity: "Severity",
      package: "Package",
      version: "Version",
      fixedVersion: "Fixed Version",
      title: "Title",
      description: "Description",
      cvss: "CVSS Score",
      riskScore: "Risk Score",
    },
    includeBom: true,
    ...options,
  });
}

/**
 * Check if export dependencies are available
 */
export async function checkExportDependencies(): Promise<{
  pdf: boolean;
  excel: boolean;
  csv: boolean;
}> {
  let pdfAvailable = false;
  let excelAvailable = false;

  try {
    await getPuppeteer();
    pdfAvailable = true;
  } catch {
    // Puppeteer not available
  }

  try {
    await getExcelJS();
    excelAvailable = true;
  } catch {
    // ExcelJS not available
  }

  return {
    pdf: pdfAvailable,
    excel: excelAvailable,
    csv: true, // CSV always available (pure JS)
  };
}
