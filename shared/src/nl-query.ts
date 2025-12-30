/**
 * Natural Language Query Module
 *
 * Enables natural language queries for security data using AI to interpret
 * user questions and generate appropriate queries/responses.
 *
 * Features:
 * - Natural language to structured query conversion
 * - Context-aware security question answering
 * - Query history and suggestions
 * - Multi-source data aggregation
 */

import Anthropic from "@anthropic-ai/sdk";
import type {
  TrivyScanResult,
  TrivyVulnerability,
  SonarIssue,
  DTrackFinding,
  SecurityDashboardResult,
  SeverityLevel,
} from "./types.js";

// =============================================================================
// Types
// =============================================================================

export interface NLQueryConfig {
  /** Anthropic API key (defaults to ANTHROPIC_API_KEY env var) */
  apiKey?: string;
  /** Model to use (defaults to claude-sonnet-4-20250514) */
  model?: string;
  /** Max tokens for response */
  maxTokens?: number;
}

export interface NLQueryContext {
  /** Available scan results */
  trivyResults?: TrivyScanResult;
  /** SonarQube issues */
  sonarIssues?: SonarIssue[];
  /** Dependency-Track findings */
  dtrackFindings?: DTrackFinding[];
  /** Security dashboard */
  dashboard?: SecurityDashboardResult;
  /** Target being analyzed */
  target?: string;
  /** Additional context */
  metadata?: Record<string, unknown>;
}

export interface NLQueryResult {
  /** Original query */
  query: string;
  /** Interpreted intent */
  intent: QueryIntent;
  /** Structured query generated */
  structuredQuery?: StructuredQuery;
  /** Natural language response */
  response: string;
  /** Relevant data extracted */
  data?: QueryResultData;
  /** Confidence in interpretation */
  confidence: number;
  /** Suggestions for follow-up queries */
  suggestions: string[];
}

export type QueryIntent =
  | "list_vulnerabilities"
  | "count_vulnerabilities"
  | "find_critical"
  | "find_by_package"
  | "find_by_cve"
  | "compare_scans"
  | "get_summary"
  | "find_remediations"
  | "check_compliance"
  | "risk_assessment"
  | "trend_analysis"
  | "general_question"
  | "unknown";

export interface StructuredQuery {
  type: QueryIntent;
  filters?: {
    severity?: SeverityLevel[];
    package?: string;
    cveId?: string;
    dateRange?: { start?: string; end?: string };
    source?: ("trivy" | "sonarqube" | "dtrack")[];
    fixAvailable?: boolean;
  };
  limit?: number;
  orderBy?: string;
  groupBy?: string;
}

export interface QueryResultData {
  vulnerabilities?: VulnSummary[];
  counts?: Record<string, number>;
  packages?: PackageSummary[];
  timeline?: TimelineEntry[];
  compliance?: ComplianceStatus;
  custom?: unknown;
}

export interface VulnSummary {
  id: string;
  severity: SeverityLevel;
  package: string;
  version: string;
  fixVersion?: string;
  title: string;
  source: string;
}

export interface PackageSummary {
  name: string;
  version: string;
  vulnCount: number;
  criticalCount: number;
  highCount: number;
}

export interface TimelineEntry {
  date: string;
  count: number;
  severity: SeverityLevel;
}

export interface ComplianceStatus {
  compliant: boolean;
  framework: string;
  score: number;
  violations: number;
}

export interface QuerySuggestion {
  query: string;
  description: string;
  category: string;
}

// =============================================================================
// AI Client
// =============================================================================

let anthropicClient: Anthropic | null = null;

/**
 * Initialize the NL query client
 */
export function initNLQueryClient(config?: NLQueryConfig): Anthropic {
  const apiKey = config?.apiKey || process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error(
      "Anthropic API key is required. Set ANTHROPIC_API_KEY environment variable or pass apiKey in config."
    );
  }

  anthropicClient = new Anthropic({ apiKey });
  return anthropicClient;
}

/**
 * Get or create client
 */
function getClient(config?: NLQueryConfig): Anthropic {
  if (!anthropicClient) {
    return initNLQueryClient(config);
  }
  return anthropicClient;
}

/**
 * Make an AI request
 */
async function aiRequest(
  systemPrompt: string,
  userPrompt: string,
  config?: NLQueryConfig
): Promise<string> {
  const client = getClient(config);
  const model = config?.model || "claude-sonnet-4-20250514";
  const maxTokens = config?.maxTokens || 4096;

  const response = await client.messages.create({
    model,
    max_tokens: maxTokens,
    temperature: 0.2,
    system: systemPrompt,
    messages: [{ role: "user", content: userPrompt }],
  });

  const textBlock = response.content.find((block) => block.type === "text");
  if (!textBlock || textBlock.type !== "text") {
    throw new Error("No text response from AI");
  }

  return textBlock.text;
}

/**
 * Parse JSON from AI response
 */
function parseAIJson<T>(response: string): T {
  let cleaned = response.trim();
  if (cleaned.startsWith("```json")) {
    cleaned = cleaned.slice(7);
  } else if (cleaned.startsWith("```")) {
    cleaned = cleaned.slice(3);
  }
  if (cleaned.endsWith("```")) {
    cleaned = cleaned.slice(0, -3);
  }
  cleaned = cleaned.trim();

  return JSON.parse(cleaned) as T;
}

// =============================================================================
// Query Processing
// =============================================================================

/**
 * Process a natural language security query
 */
export async function processNLQuery(
  query: string,
  context: NLQueryContext,
  config?: NLQueryConfig
): Promise<NLQueryResult> {
  const systemPrompt = `You are a security analyst assistant that helps users query and understand security scan data.
You interpret natural language questions about vulnerabilities, security issues, and compliance.

Available data context:
- Trivy scan results (container/code vulnerabilities)
- SonarQube issues (code quality and security)
- Dependency-Track findings (component vulnerabilities)
- Security dashboard aggregated data

Your role is to:
1. Understand the user's question
2. Identify the intent (what they want to know)
3. Generate a structured query if applicable
4. Provide a clear, helpful response
5. Suggest follow-up questions`;

  const contextSummary = buildContextSummary(context);

  const userPrompt = `User query: "${query}"

Available data:
${contextSummary}

Respond with JSON:
{
  "intent": "list_vulnerabilities|count_vulnerabilities|find_critical|find_by_package|find_by_cve|compare_scans|get_summary|find_remediations|check_compliance|risk_assessment|trend_analysis|general_question|unknown",
  "structuredQuery": {
    "type": "same as intent",
    "filters": {
      "severity": ["CRITICAL", "HIGH", ...] or null,
      "package": "package name" or null,
      "cveId": "CVE-XXXX-XXXXX" or null,
      "source": ["trivy", "sonarqube", "dtrack"] or null,
      "fixAvailable": true/false or null
    },
    "limit": number or null,
    "orderBy": "severity|date|package" or null
  },
  "response": "Natural language answer to the user's question based on the available data",
  "data": {
    "vulnerabilities": [{"id": "...", "severity": "...", "package": "...", "version": "...", "title": "...", "source": "..."}] or null,
    "counts": {"total": X, "critical": X, ...} or null,
    "packages": [{"name": "...", "version": "...", "vulnCount": X}] or null
  },
  "confidence": 0.0-1.0,
  "suggestions": ["follow-up question 1", "follow-up question 2", "follow-up question 3"]
}`;

  const response = await aiRequest(systemPrompt, userPrompt, config);
  const parsed = parseAIJson<{
    intent: QueryIntent;
    structuredQuery?: StructuredQuery;
    response: string;
    data?: QueryResultData;
    confidence: number;
    suggestions: string[];
  }>(response);

  return {
    query,
    intent: parsed.intent,
    structuredQuery: parsed.structuredQuery,
    response: parsed.response,
    data: parsed.data,
    confidence: parsed.confidence,
    suggestions: parsed.suggestions,
  };
}

/**
 * Build a context summary for the AI
 */
function buildContextSummary(context: NLQueryContext): string {
  const parts: string[] = [];

  if (context.target) {
    parts.push(`Target: ${context.target}`);
  }

  if (context.trivyResults?.Results?.[0]?.Vulnerabilities) {
    const vulns = context.trivyResults.Results[0].Vulnerabilities;
    const bySeverity = countBySeverity(vulns);
    parts.push(`Trivy scan: ${vulns.length} vulnerabilities`);
    parts.push(
      `  - Critical: ${bySeverity.CRITICAL}, High: ${bySeverity.HIGH}, Medium: ${bySeverity.MEDIUM}, Low: ${bySeverity.LOW}`
    );

    // Add sample vulns
    const samples = vulns
      .slice(0, 5)
      .map((v) => `    ${v.VulnerabilityID}: ${v.PkgName} (${v.Severity})`);
    if (samples.length > 0) {
      parts.push("  Sample vulnerabilities:");
      parts.push(...samples);
    }
  }

  if (context.sonarIssues) {
    parts.push(`SonarQube: ${context.sonarIssues.length} issues`);
  }

  if (context.dtrackFindings) {
    parts.push(`Dependency-Track: ${context.dtrackFindings.length} findings`);
  }

  if (context.dashboard) {
    const s = context.dashboard.summary;
    parts.push(`Dashboard summary:`);
    parts.push(`  - Total: ${s.total}`);
    parts.push(
      `  - By severity: Critical=${s.critical}, High=${s.high}, Medium=${s.medium}, Low=${s.low}`
    );
  }

  return parts.join("\n");
}

/**
 * Count vulnerabilities by severity
 */
function countBySeverity(vulns: TrivyVulnerability[]): Record<string, number> {
  const counts: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    UNKNOWN: 0,
  };

  for (const v of vulns) {
    const sev = v.Severity?.toUpperCase() || "UNKNOWN";
    if (sev in counts) {
      counts[sev]++;
    }
  }

  return counts;
}

// =============================================================================
// Query Suggestions
// =============================================================================

/**
 * Get query suggestions based on context
 */
export function getQuerySuggestions(context: NLQueryContext): QuerySuggestion[] {
  const suggestions: QuerySuggestion[] = [];

  // Always include general suggestions
  suggestions.push({
    query: "Show me a summary of all security issues",
    description: "Get an overview of all vulnerabilities and issues",
    category: "overview",
  });

  suggestions.push({
    query: "What are the critical vulnerabilities?",
    description: "List all critical severity vulnerabilities",
    category: "severity",
  });

  suggestions.push({
    query: "Which packages have the most vulnerabilities?",
    description: "Find the most vulnerable packages",
    category: "packages",
  });

  suggestions.push({
    query: "What vulnerabilities have fixes available?",
    description: "Find vulnerabilities that can be remediated",
    category: "remediation",
  });

  // Context-specific suggestions
  if (context.trivyResults?.Results?.[0]?.Vulnerabilities) {
    const vulns = context.trivyResults.Results[0].Vulnerabilities;
    const packages = new Set(vulns.map((v) => v.PkgName));

    if (packages.size > 0) {
      const topPackage = Array.from(packages)[0];
      suggestions.push({
        query: `What vulnerabilities affect ${topPackage}?`,
        description: `Check issues in ${topPackage} package`,
        category: "package",
      });
    }

    const criticalVulns = vulns.filter((v) => v.Severity === "CRITICAL");
    if (criticalVulns.length > 0) {
      suggestions.push({
        query: `Tell me about ${criticalVulns[0].VulnerabilityID}`,
        description: "Get details on a specific CVE",
        category: "details",
      });
    }
  }

  if (context.dashboard) {
    suggestions.push({
      query: "Compare security across different sources",
      description: "Compare Trivy, SonarQube, and Dependency-Track findings",
      category: "comparison",
    });
  }

  return suggestions;
}

// =============================================================================
// Pre-built Queries
// =============================================================================

/**
 * Execute a pre-built query type
 */
export function executeStructuredQuery(
  query: StructuredQuery,
  context: NLQueryContext
): QueryResultData {
  const result: QueryResultData = {};

  switch (query.type) {
    case "list_vulnerabilities":
    case "find_critical":
    case "find_by_package":
    case "find_by_cve":
      result.vulnerabilities = filterVulnerabilities(context, query.filters, query.limit);
      break;

    case "count_vulnerabilities":
      result.counts = countVulnerabilities(context, query.filters);
      break;

    case "get_summary":
      result.counts = countVulnerabilities(context);
      result.packages = getPackageSummary(context, query.limit);
      break;

    default:
      // General query - return all available data
      result.counts = countVulnerabilities(context);
      result.vulnerabilities = filterVulnerabilities(context, query.filters, 10);
  }

  return result;
}

/**
 * Filter vulnerabilities based on query filters
 */
function filterVulnerabilities(
  context: NLQueryContext,
  filters?: StructuredQuery["filters"],
  limit?: number
): VulnSummary[] {
  const results: VulnSummary[] = [];

  // Process Trivy results
  if (context.trivyResults?.Results) {
    for (const scanResult of context.trivyResults.Results) {
      if (!scanResult.Vulnerabilities) continue;

      for (const vuln of scanResult.Vulnerabilities) {
        // Apply filters
        if (filters?.severity && !filters.severity.includes(vuln.Severity as SeverityLevel)) {
          continue;
        }
        if (
          filters?.package &&
          !vuln.PkgName.toLowerCase().includes(filters.package.toLowerCase())
        ) {
          continue;
        }
        if (filters?.cveId && vuln.VulnerabilityID !== filters.cveId) {
          continue;
        }
        if (filters?.fixAvailable !== undefined) {
          const hasfix = !!vuln.FixedVersion;
          if (filters.fixAvailable !== hasfix) continue;
        }

        results.push({
          id: vuln.VulnerabilityID,
          severity: vuln.Severity as SeverityLevel,
          package: vuln.PkgName,
          version: vuln.InstalledVersion,
          fixVersion: vuln.FixedVersion,
          title: vuln.Title || vuln.Description?.substring(0, 100) || "",
          source: "trivy",
        });
      }
    }
  }

  // Process SonarQube issues
  if (context.sonarIssues && (!filters?.source || filters.source.includes("sonarqube"))) {
    for (const issue of context.sonarIssues) {
      const severity = mapSonarSeverity(issue.severity);
      if (filters?.severity && !filters.severity.includes(severity)) {
        continue;
      }

      results.push({
        id: issue.key,
        severity,
        package: issue.component,
        version: "",
        title: issue.message,
        source: "sonarqube",
      });
    }
  }

  // Process Dependency-Track findings
  if (context.dtrackFindings && (!filters?.source || filters.source.includes("dtrack"))) {
    for (const finding of context.dtrackFindings) {
      const severity = finding.vulnerability.severity as SeverityLevel;
      if (filters?.severity && !filters.severity.includes(severity)) {
        continue;
      }

      results.push({
        id: finding.vulnerability.vulnId,
        severity,
        package: finding.component.name,
        version: finding.component.version,
        title:
          finding.vulnerability.title || finding.vulnerability.description?.substring(0, 100) || "",
        source: "dtrack",
      });
    }
  }

  // Sort by severity
  const severityOrder: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
  };
  results.sort((a, b) => (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4));

  // Apply limit
  if (limit) {
    return results.slice(0, limit);
  }

  return results;
}

/**
 * Map SonarQube severity to standard severity
 */
function mapSonarSeverity(sonarSeverity: string): SeverityLevel {
  const map: Record<string, SeverityLevel> = {
    BLOCKER: "CRITICAL",
    CRITICAL: "CRITICAL",
    MAJOR: "HIGH",
    MINOR: "MEDIUM",
    INFO: "LOW",
  };
  return map[sonarSeverity.toUpperCase()] || "MEDIUM";
}

/**
 * Count vulnerabilities
 */
function countVulnerabilities(
  context: NLQueryContext,
  _filters?: StructuredQuery["filters"]
): Record<string, number> {
  const counts: Record<string, number> = {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    withFix: 0,
    trivy: 0,
    sonarqube: 0,
    dtrack: 0,
  };

  // Count Trivy
  if (context.trivyResults?.Results) {
    for (const result of context.trivyResults.Results) {
      if (!result.Vulnerabilities) continue;
      for (const vuln of result.Vulnerabilities) {
        counts.total++;
        counts.trivy++;
        const sev = vuln.Severity?.toLowerCase() || "unknown";
        if (sev in counts) counts[sev]++;
        if (vuln.FixedVersion) counts.withFix++;
      }
    }
  }

  // Count SonarQube
  if (context.sonarIssues) {
    counts.sonarqube = context.sonarIssues.length;
    counts.total += context.sonarIssues.length;
  }

  // Count Dependency-Track
  if (context.dtrackFindings) {
    counts.dtrack = context.dtrackFindings.length;
    counts.total += context.dtrackFindings.length;
  }

  return counts;
}

/**
 * Get package vulnerability summary
 */
function getPackageSummary(context: NLQueryContext, limit?: number): PackageSummary[] {
  const packages = new Map<string, PackageSummary>();

  if (context.trivyResults?.Results) {
    for (const result of context.trivyResults.Results) {
      if (!result.Vulnerabilities) continue;
      for (const vuln of result.Vulnerabilities) {
        const key = `${vuln.PkgName}@${vuln.InstalledVersion}`;
        if (!packages.has(key)) {
          packages.set(key, {
            name: vuln.PkgName,
            version: vuln.InstalledVersion,
            vulnCount: 0,
            criticalCount: 0,
            highCount: 0,
          });
        }
        const pkg = packages.get(key)!;
        pkg.vulnCount++;
        if (vuln.Severity === "CRITICAL") pkg.criticalCount++;
        if (vuln.Severity === "HIGH") pkg.highCount++;
      }
    }
  }

  // Sort by vulnerability count
  const sorted = Array.from(packages.values()).sort(
    (a, b) =>
      b.criticalCount * 100 +
      b.highCount * 10 +
      b.vulnCount -
      (a.criticalCount * 100 + a.highCount * 10 + a.vulnCount)
  );

  return limit ? sorted.slice(0, limit) : sorted;
}

// =============================================================================
// Conversational Interface
// =============================================================================

export interface ConversationMessage {
  role: "user" | "assistant";
  content: string;
  timestamp: string;
  queryResult?: NLQueryResult;
}

export interface ConversationSession {
  id: string;
  messages: ConversationMessage[];
  context: NLQueryContext;
  created: string;
  lastUpdated: string;
}

/**
 * Create a new conversation session
 */
export function createConversationSession(context: NLQueryContext): ConversationSession {
  return {
    id: `session-${Date.now()}`,
    messages: [],
    context,
    created: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
  };
}

/**
 * Send a message in a conversation
 */
export async function sendConversationMessage(
  session: ConversationSession,
  message: string,
  config?: NLQueryConfig
): Promise<{ session: ConversationSession; response: NLQueryResult }> {
  // Add user message
  session.messages.push({
    role: "user",
    content: message,
    timestamp: new Date().toISOString(),
  });

  // Process the query
  const result = await processNLQuery(message, session.context, config);

  // Add assistant response
  session.messages.push({
    role: "assistant",
    content: result.response,
    timestamp: new Date().toISOString(),
    queryResult: result,
  });

  session.lastUpdated = new Date().toISOString();

  return { session, response: result };
}

// =============================================================================
// Exports
// =============================================================================

export const nlQueryExports = {
  // Client
  initNLQueryClient,

  // Query processing
  processNLQuery,
  executeStructuredQuery,

  // Suggestions
  getQuerySuggestions,

  // Conversation
  createConversationSession,
  sendConversationMessage,
};
