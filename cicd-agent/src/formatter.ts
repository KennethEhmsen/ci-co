/**
 * Output Formatter - Formats tool output in different formats (json, table, markdown)
 */

export type OutputFormat = "json" | "table" | "markdown" | "text";

export interface FormatterOptions {
  format: OutputFormat;
  quiet?: boolean;
  noColor?: boolean;
}

// Global formatter state
let globalFormat: OutputFormat = "text";
let globalQuiet = false;

export function setGlobalFormat(format: OutputFormat): void {
  globalFormat = format;
}

export function getGlobalFormat(): OutputFormat {
  return globalFormat;
}

export function setGlobalQuiet(quiet: boolean): void {
  globalQuiet = quiet;
}

export function isQuiet(): boolean {
  return globalQuiet;
}

/**
 * Format data based on global format setting
 */
export function formatOutput(data: unknown, title?: string): string {
  switch (globalFormat) {
    case "json":
      return formatJson(data);
    case "table":
      return formatTable(data, title);
    case "markdown":
      return formatMarkdown(data, title);
    case "text":
    default:
      return formatText(data);
  }
}

/**
 * JSON format - raw JSON output for scripting
 */
function formatJson(data: unknown): string {
  return JSON.stringify(data, null, 2);
}

/**
 * Text format - human readable (default)
 */
function formatText(data: unknown): string {
  if (typeof data === "string") {
    return data;
  }
  return JSON.stringify(data, null, 2);
}

/**
 * Safely stringify a value, handling objects properly
 */
function stringifyValue(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  // At this point value is a primitive (string, number, boolean, symbol, bigint)
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
    return value.toString();
  }
  // Symbol - use description or empty string
  if (typeof value === "symbol") {
    return value.description ?? "";
  }
  return "";
}

/**
 * Calculate column widths for array table
 */
function calculateColumnWidths(
  data: Record<string, unknown>[],
  keys: string[]
): Record<string, number> {
  const columnWidths: Record<string, number> = {};
  for (const key of keys) {
    columnWidths[key] = key.length;
    for (const row of data) {
      const val = stringifyValue(row[key]);
      columnWidths[key] = Math.max(columnWidths[key], Math.min(val.length, 40));
    }
  }
  return columnWidths;
}

/**
 * Format array data as ASCII table rows
 */
function formatArrayAsTable(data: Record<string, unknown>[], lines: string[]): void {
  if (data.length === 0) {
    lines.push("No data");
    return;
  }

  const keys = Object.keys(data[0]);
  const columnWidths = calculateColumnWidths(data, keys);

  // Header
  const header = keys.map((k) => k.padEnd(columnWidths[k])).join(" | ");
  const separator = keys.map((k) => "-".repeat(columnWidths[k])).join("-+-");
  lines.push(header, separator);

  // Rows
  for (const row of data) {
    const rowStr = keys
      .map((k) => {
        const val = stringifyValue(row[k]);
        return val.slice(0, 40).padEnd(columnWidths[k]);
      })
      .join(" | ");
    lines.push(rowStr);
  }
}

/**
 * Format object as key-value pairs
 */
function formatObjectAsTable(obj: Record<string, unknown>, lines: string[]): void {
  const keys = Object.keys(obj);
  if (keys.length === 0) {
    lines.push("No data");
    return;
  }

  const maxKeyLen = Math.max(...keys.map((k) => k.length));

  for (const [key, value] of Object.entries(obj)) {
    const valStr = stringifyValue(value);
    lines.push(`${key.padEnd(maxKeyLen)} : ${valStr}`);
  }
}

/**
 * Table format - ASCII table for terminal
 */
function formatTable(data: unknown, title?: string): string {
  const lines: string[] = [];

  if (title) {
    lines.push(`\n${title}`, "=".repeat(title.length));
  }

  if (Array.isArray(data)) {
    formatArrayAsTable(data as Record<string, unknown>[], lines);
  } else if (typeof data === "object" && data !== null) {
    formatObjectAsTable(data as Record<string, unknown>, lines);
  } else {
    lines.push(String(data));
  }

  return lines.join("\n");
}

/**
 * Markdown format - for documentation/reports
 */
function formatMarkdown(data: unknown, title?: string): string {
  const lines: string[] = [];

  if (title) {
    lines.push(`## ${title}\n`);
  }

  if (Array.isArray(data)) {
    if (data.length === 0) {
      return lines.join("\n") + "\n*No data*\n";
    }

    // Get all keys from first item
    const keys = Object.keys(data[0] as Record<string, unknown>);

    // Header
    const mdHeader = "| " + keys.join(" | ") + " |";
    const mdSeparator = "| " + keys.map(() => "---").join(" | ") + " |";
    lines.push(mdHeader, mdSeparator);

    // Rows
    for (const row of data) {
      const rowStr = keys
        .map((k) => {
          const val = (row as Record<string, unknown>)[k];
          if (typeof val === "object") {
            return "`" + JSON.stringify(val).slice(0, 30) + "`";
          }
          return stringifyValue(val).replaceAll("|", String.raw`\|`);
        })
        .join(" | ");
      lines.push("| " + rowStr + " |");
    }
  } else if (typeof data === "object" && data !== null) {
    // Single object as definition list
    const obj = data as Record<string, unknown>;
    for (const [key, value] of Object.entries(obj)) {
      const valStr =
        typeof value === "object"
          ? "\n```json\n" + JSON.stringify(value, null, 2) + "\n```"
          : stringifyValue(value);
      lines.push(`- **${key}**: ${valStr}`);
    }
  } else {
    lines.push(String(data));
  }

  return lines.join("\n");
}

/**
 * Log a message (respects quiet mode)
 */
export function log(message: string): void {
  if (!globalQuiet) {
    console.log(message);
  }
}

/**
 * Log an error (always shown)
 */
export function logError(message: string): void {
  console.error(message);
}

/**
 * Format scan results specifically
 */
export function formatScanResults(
  results: {
    vulnerabilities?: number;
    secrets?: number;
    licenses?: number;
    misconfigurations?: number;
    components?: number;
  },
  title?: string
): string {
  const data = [
    { metric: "Vulnerabilities", count: results.vulnerabilities ?? 0 },
    { metric: "Secrets", count: results.secrets ?? 0 },
    { metric: "Licenses", count: results.licenses ?? 0 },
    { metric: "Misconfigurations", count: results.misconfigurations ?? 0 },
    { metric: "Components", count: results.components ?? 0 },
  ].filter((r) => r.count > 0 || r.metric === "Vulnerabilities");

  return formatOutput(data, title);
}

/**
 * Format build status
 */
export function formatBuildStatus(
  builds: Array<{
    number: number;
    status: string;
    message?: string;
    finished?: number;
  }>
): string {
  const statusEmoji: Record<string, string> = {
    success: "✅",
    failure: "❌",
    running: "🔄",
    pending: "⏳",
    killed: "💀",
  };

  if (globalFormat === "json") {
    return formatJson(builds);
  }

  const formatted = builds.map((b) => ({
    build: `#${b.number}`,
    status: `${statusEmoji[b.status] || "❓"} ${b.status}`,
    message: (b.message || "").slice(0, 50),
  }));

  return formatOutput(formatted, "Recent Builds");
}
