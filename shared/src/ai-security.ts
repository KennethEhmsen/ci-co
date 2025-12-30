/**
 * AI Security Module
 *
 * Provides AI-powered vulnerability analysis and code security analysis
 * using Claude API for intelligent security insights.
 *
 * Features:
 * - Vulnerability impact analysis with AI explanations
 * - Code security analysis for detecting vulnerabilities
 * - Remediation suggestions with context-aware recommendations
 * - Risk scoring and prioritization
 * - Pattern-based vulnerability detection
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

export interface AIAnalysisConfig {
  /** Anthropic API key (defaults to ANTHROPIC_API_KEY env var) */
  apiKey?: string;
  /** Model to use (defaults to claude-sonnet-4-20250514) */
  model?: string;
  /** Max tokens for response */
  maxTokens?: number;
  /** Temperature for response variety (0-1) */
  temperature?: number;
}

export interface VulnerabilityAnalysis {
  vulnId: string;
  severity: SeverityLevel;
  summary: string;
  impact: {
    confidentiality: "HIGH" | "MEDIUM" | "LOW" | "NONE";
    integrity: "HIGH" | "MEDIUM" | "LOW" | "NONE";
    availability: "HIGH" | "MEDIUM" | "LOW" | "NONE";
  };
  exploitability: {
    attackVector: string;
    attackComplexity: "HIGH" | "LOW";
    privilegesRequired: "NONE" | "LOW" | "HIGH";
    userInteraction: "NONE" | "REQUIRED";
  };
  affectedComponents: string[];
  businessRisk: string;
  technicalDetails: string;
  recommendations: string[];
  priority: number; // 1-10, higher = more urgent
  aiConfidence: number; // 0-1
}

export interface CodeSecurityAnalysis {
  file: string;
  language: string;
  findings: CodeSecurityFinding[];
  overallRisk: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE";
  securityScore: number; // 0-100
  summary: string;
  recommendations: string[];
}

export interface CodeSecurityFinding {
  type: SecurityFindingType;
  severity: SeverityLevel;
  line?: number;
  column?: number;
  snippet?: string;
  description: string;
  cweId?: string;
  owaspCategory?: string;
  remediation: string;
  confidence: number; // 0-1
}

export type SecurityFindingType =
  | "SQL_INJECTION"
  | "XSS"
  | "COMMAND_INJECTION"
  | "PATH_TRAVERSAL"
  | "SENSITIVE_DATA_EXPOSURE"
  | "INSECURE_DESERIALIZATION"
  | "BROKEN_AUTH"
  | "INSECURE_CRYPTO"
  | "HARDCODED_SECRET"
  | "INSECURE_DEPENDENCY"
  | "SSRF"
  | "XXE"
  | "RACE_CONDITION"
  | "BUFFER_OVERFLOW"
  | "OTHER";

export interface AIRemediationPlan {
  vulnId: string;
  title: string;
  currentState: string;
  targetState: string;
  steps: RemediationStep[];
  estimatedEffort: "MINIMAL" | "LOW" | "MEDIUM" | "HIGH" | "EXTENSIVE";
  riskIfNotFixed: string;
  verificationSteps: string[];
}

export interface RemediationStep {
  order: number;
  action: string;
  details: string;
  automated: boolean;
  commands?: string[];
  files?: string[];
}

export interface SecurityInsight {
  category: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  affectedAreas: string[];
  recommendations: string[];
  relatedVulns: string[];
}

export interface ThreatModelAnalysis {
  target: string;
  threats: ThreatEntry[];
  attackSurface: AttackSurfaceEntry[];
  mitigations: MitigationRecommendation[];
  overallRiskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  summary: string;
}

export interface ThreatEntry {
  id: string;
  category: string;
  description: string;
  likelihood: "HIGH" | "MEDIUM" | "LOW";
  impact: "HIGH" | "MEDIUM" | "LOW";
  mitigated: boolean;
}

export interface AttackSurfaceEntry {
  component: string;
  exposures: string[];
  entryPoints: string[];
  riskLevel: "HIGH" | "MEDIUM" | "LOW";
}

export interface MitigationRecommendation {
  threatId: string;
  recommendation: string;
  priority: number;
  effort: "LOW" | "MEDIUM" | "HIGH";
}

// =============================================================================
// AI Client
// =============================================================================

let anthropicClient: Anthropic | null = null;

/**
 * Initialize the AI client
 */
export function initAIClient(config?: AIAnalysisConfig): Anthropic {
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
 * Get or create AI client
 */
function getClient(config?: AIAnalysisConfig): Anthropic {
  if (!anthropicClient) {
    return initAIClient(config);
  }
  return anthropicClient;
}

/**
 * Make an AI request
 */
async function aiRequest(
  systemPrompt: string,
  userPrompt: string,
  config?: AIAnalysisConfig
): Promise<string> {
  const client = getClient(config);
  const model = config?.model || "claude-sonnet-4-20250514";
  const maxTokens = config?.maxTokens || 4096;
  const temperature = config?.temperature ?? 0.3;

  const response = await client.messages.create({
    model,
    max_tokens: maxTokens,
    temperature,
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
 * Parse JSON from AI response, handling markdown code blocks
 */
function parseAIJson<T>(response: string): T {
  // Remove markdown code blocks if present
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
// Vulnerability Analysis
// =============================================================================

/**
 * Analyze a vulnerability with AI for detailed insights
 */
export async function analyzeVulnerability(
  vuln: TrivyVulnerability,
  context?: {
    packageManager?: string;
    runtime?: string;
    application?: string;
  },
  config?: AIAnalysisConfig
): Promise<VulnerabilityAnalysis> {
  const systemPrompt = `You are a security expert analyzing vulnerabilities. Provide detailed, accurate analysis in JSON format.
Your analysis should be practical and actionable for developers. Focus on real-world impact and prioritization.`;

  const userPrompt = `Analyze this vulnerability and provide a detailed assessment:

Vulnerability ID: ${vuln.VulnerabilityID}
Package: ${vuln.PkgName} ${vuln.InstalledVersion}
Fixed Version: ${vuln.FixedVersion || "No fix available"}
Severity: ${vuln.Severity}
Title: ${vuln.Title || "N/A"}
Description: ${vuln.Description || "N/A"}

Context:
- Package Manager: ${context?.packageManager || "Unknown"}
- Runtime: ${context?.runtime || "Unknown"}
- Application: ${context?.application || "Unknown"}

Respond with JSON in this exact format:
{
  "vulnId": "CVE-XXXX-XXXXX",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "summary": "Brief 1-2 sentence summary",
  "impact": {
    "confidentiality": "HIGH|MEDIUM|LOW|NONE",
    "integrity": "HIGH|MEDIUM|LOW|NONE",
    "availability": "HIGH|MEDIUM|LOW|NONE"
  },
  "exploitability": {
    "attackVector": "NETWORK|ADJACENT|LOCAL|PHYSICAL",
    "attackComplexity": "HIGH|LOW",
    "privilegesRequired": "NONE|LOW|HIGH",
    "userInteraction": "NONE|REQUIRED"
  },
  "affectedComponents": ["list of affected components/services"],
  "businessRisk": "Description of business impact",
  "technicalDetails": "Technical explanation of the vulnerability",
  "recommendations": ["Specific actionable recommendations"],
  "priority": 1-10,
  "aiConfidence": 0.0-1.0
}`;

  const response = await aiRequest(systemPrompt, userPrompt, config);
  return parseAIJson<VulnerabilityAnalysis>(response);
}

/**
 * Batch analyze multiple vulnerabilities
 */
export async function analyzeVulnerabilities(
  vulns: TrivyVulnerability[],
  context?: {
    packageManager?: string;
    runtime?: string;
    application?: string;
  },
  config?: AIAnalysisConfig
): Promise<VulnerabilityAnalysis[]> {
  // Limit batch size to avoid token limits
  const batchSize = Math.min(vulns.length, 10);
  const batch = vulns.slice(0, batchSize);

  const systemPrompt = `You are a security expert analyzing multiple vulnerabilities. Provide detailed analysis for each vulnerability.
Focus on prioritization and practical remediation guidance. Return a JSON array.`;

  const vulnSummaries = batch.map((v) => ({
    id: v.VulnerabilityID,
    pkg: `${v.PkgName}@${v.InstalledVersion}`,
    fixed: v.FixedVersion || "No fix",
    severity: v.Severity,
    title: v.Title || "N/A",
  }));

  const userPrompt = `Analyze these vulnerabilities and prioritize them:

${JSON.stringify(vulnSummaries, null, 2)}

Context:
- Package Manager: ${context?.packageManager || "Unknown"}
- Runtime: ${context?.runtime || "Unknown"}
- Application: ${context?.application || "Unknown"}

Return a JSON array of vulnerability analyses with this structure for each:
{
  "vulnId": "string",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "summary": "string",
  "impact": { "confidentiality": "...", "integrity": "...", "availability": "..." },
  "exploitability": { "attackVector": "...", "attackComplexity": "...", "privilegesRequired": "...", "userInteraction": "..." },
  "affectedComponents": ["string"],
  "businessRisk": "string",
  "technicalDetails": "string",
  "recommendations": ["string"],
  "priority": 1-10,
  "aiConfidence": 0.0-1.0
}`;

  const response = await aiRequest(systemPrompt, userPrompt, config);
  return parseAIJson<VulnerabilityAnalysis[]>(response);
}

// =============================================================================
// Code Security Analysis
// =============================================================================

/**
 * Analyze code for security vulnerabilities
 */
export async function analyzeCodeSecurity(
  code: string,
  options?: {
    filename?: string;
    language?: string;
    context?: string;
  },
  config?: AIAnalysisConfig
): Promise<CodeSecurityAnalysis> {
  const systemPrompt = `You are a security code reviewer. Analyze code for security vulnerabilities following OWASP guidelines and CWE classifications.
Be thorough but avoid false positives. Only report findings you are confident about.`;

  const language = options?.language || detectLanguage(options?.filename || "");

  const userPrompt = `Analyze this ${language} code for security vulnerabilities:

File: ${options?.filename || "unknown"}
${options?.context ? `Context: ${options.context}` : ""}

\`\`\`${language}
${code}
\`\`\`

Return JSON with this structure:
{
  "file": "filename",
  "language": "detected language",
  "findings": [
    {
      "type": "SQL_INJECTION|XSS|COMMAND_INJECTION|PATH_TRAVERSAL|SENSITIVE_DATA_EXPOSURE|INSECURE_DESERIALIZATION|BROKEN_AUTH|INSECURE_CRYPTO|HARDCODED_SECRET|INSECURE_DEPENDENCY|SSRF|XXE|RACE_CONDITION|BUFFER_OVERFLOW|OTHER",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "line": number or null,
      "column": number or null,
      "snippet": "relevant code snippet",
      "description": "what the vulnerability is",
      "cweId": "CWE-XXX",
      "owaspCategory": "OWASP category",
      "remediation": "how to fix it",
      "confidence": 0.0-1.0
    }
  ],
  "overallRisk": "CRITICAL|HIGH|MEDIUM|LOW|SAFE",
  "securityScore": 0-100,
  "summary": "Overall security assessment",
  "recommendations": ["General security improvements"]
}`;

  const response = await aiRequest(systemPrompt, userPrompt, config);
  return parseAIJson<CodeSecurityAnalysis>(response);
}

/**
 * Detect programming language from filename
 */
function detectLanguage(filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase() || "";
  const langMap: Record<string, string> = {
    js: "javascript",
    mjs: "javascript",
    cjs: "javascript",
    ts: "typescript",
    mts: "typescript",
    cts: "typescript",
    jsx: "javascript",
    tsx: "typescript",
    py: "python",
    rb: "ruby",
    go: "go",
    rs: "rust",
    java: "java",
    kt: "kotlin",
    scala: "scala",
    cs: "csharp",
    cpp: "cpp",
    c: "c",
    h: "c",
    hpp: "cpp",
    php: "php",
    swift: "swift",
    sh: "bash",
    bash: "bash",
    zsh: "zsh",
    sql: "sql",
    yaml: "yaml",
    yml: "yaml",
    json: "json",
    xml: "xml",
    html: "html",
    css: "css",
    scss: "scss",
  };
  return langMap[ext] || "unknown";
}

// =============================================================================
// Remediation Planning
// =============================================================================

/**
 * Generate a detailed remediation plan for a vulnerability
 */
export async function generateRemediationPlan(
  vuln: TrivyVulnerability,
  context?: {
    packageManager?: string;
    currentVersion?: string;
    lockfile?: string;
  },
  config?: AIAnalysisConfig
): Promise<AIRemediationPlan> {
  const systemPrompt = `You are a security engineer creating detailed remediation plans.
Provide step-by-step instructions that are practical and safe to execute.
Include both manual and automated options where applicable.`;

  const userPrompt = `Create a remediation plan for this vulnerability:

Vulnerability: ${vuln.VulnerabilityID}
Package: ${vuln.PkgName}
Current Version: ${vuln.InstalledVersion}
Fixed Version: ${vuln.FixedVersion || "No fix available"}
Severity: ${vuln.Severity}

Context:
- Package Manager: ${context?.packageManager || "npm/yarn"}
- Lockfile: ${context?.lockfile || "package-lock.json"}

Return JSON with this structure:
{
  "vulnId": "CVE-XXXX-XXXXX",
  "title": "Remediation plan title",
  "currentState": "Description of current vulnerable state",
  "targetState": "Description of secure state after remediation",
  "steps": [
    {
      "order": 1,
      "action": "Action title",
      "details": "Detailed instructions",
      "automated": true/false,
      "commands": ["command1", "command2"],
      "files": ["file1", "file2"]
    }
  ],
  "estimatedEffort": "MINIMAL|LOW|MEDIUM|HIGH|EXTENSIVE",
  "riskIfNotFixed": "Description of risk if vulnerability is not fixed",
  "verificationSteps": ["How to verify the fix was successful"]
}`;

  const response = await aiRequest(systemPrompt, userPrompt, config);
  return parseAIJson<AIRemediationPlan>(response);
}

// =============================================================================
// Security Insights
// =============================================================================

/**
 * Generate security insights from scan results
 */
export async function generateSecurityInsights(
  dashboard: SecurityDashboardResult,
  config?: AIAnalysisConfig
): Promise<SecurityInsight[]> {
  const systemPrompt = `You are a security analyst identifying patterns and insights from security scan data.
Focus on actionable insights that help prioritize security work.
Look for patterns, trends, and areas of concern.`;

  const summary = {
    totalVulns: dashboard.summary.total,
    bySeverity: {
      critical: dashboard.summary.critical,
      high: dashboard.summary.high,
      medium: dashboard.summary.medium,
      low: dashboard.summary.low,
    },
    bySource: dashboard.bySource,
    findings: dashboard.topFindings.slice(0, 20).map((f) => ({
      id: f.id,
      severity: f.severity,
      source: f.source,
      package: f.package,
    })),
  };

  const userPrompt = `Analyze this security scan data and provide insights:

${JSON.stringify(summary, null, 2)}

Return JSON array of insights:
[
  {
    "category": "Insight category (e.g., 'Dependency Risk', 'Attack Surface', 'Compliance')",
    "title": "Insight title",
    "description": "Detailed explanation",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "affectedAreas": ["affected areas"],
    "recommendations": ["actionable recommendations"],
    "relatedVulns": ["CVE-IDs"]
  }
]`;

  const response = await aiRequest(systemPrompt, userPrompt, config);
  return parseAIJson<SecurityInsight[]>(response);
}

// =============================================================================
// Threat Modeling
// =============================================================================

/**
 * Generate threat model analysis for a target
 */
export async function generateThreatModel(
  target: string,
  context: {
    type: "container" | "application" | "infrastructure" | "api";
    technologies?: string[];
    exposures?: string[];
    scanResults?: TrivyScanResult;
  },
  config?: AIAnalysisConfig
): Promise<ThreatModelAnalysis> {
  const systemPrompt = `You are a security architect performing threat modeling using STRIDE methodology.
Identify threats, attack surfaces, and provide mitigation recommendations.
Be comprehensive but practical.`;

  const userPrompt = `Generate a threat model for:

Target: ${target}
Type: ${context.type}
Technologies: ${context.technologies?.join(", ") || "Unknown"}
Known Exposures: ${context.exposures?.join(", ") || "None specified"}

${
  context.scanResults?.Results?.[0]?.Vulnerabilities
    ? `Known vulnerabilities: ${context.scanResults.Results[0].Vulnerabilities.length} found`
    : ""
}

Return JSON with this structure:
{
  "target": "target name",
  "threats": [
    {
      "id": "THREAT-001",
      "category": "STRIDE category",
      "description": "threat description",
      "likelihood": "HIGH|MEDIUM|LOW",
      "impact": "HIGH|MEDIUM|LOW",
      "mitigated": true/false
    }
  ],
  "attackSurface": [
    {
      "component": "component name",
      "exposures": ["exposure1"],
      "entryPoints": ["entry point1"],
      "riskLevel": "HIGH|MEDIUM|LOW"
    }
  ],
  "mitigations": [
    {
      "threatId": "THREAT-001",
      "recommendation": "mitigation recommendation",
      "priority": 1-10,
      "effort": "LOW|MEDIUM|HIGH"
    }
  ],
  "overallRiskLevel": "CRITICAL|HIGH|MEDIUM|LOW",
  "summary": "Overall threat model summary"
}`;

  const response = await aiRequest(systemPrompt, userPrompt, config);
  return parseAIJson<ThreatModelAnalysis>(response);
}

// =============================================================================
// Risk Scoring
// =============================================================================

export interface RiskScore {
  overall: number; // 0-100
  categories: {
    vulnerabilities: number;
    codeQuality: number;
    dependencies: number;
    configuration: number;
    exposure: number;
  };
  trend: "IMPROVING" | "STABLE" | "DEGRADING";
  topRisks: {
    risk: string;
    score: number;
    mitigation: string;
  }[];
  recommendations: string[];
}

/**
 * Calculate comprehensive risk score
 */
export async function calculateRiskScore(
  data: {
    trivyResults?: TrivyScanResult;
    sonarIssues?: SonarIssue[];
    dtrackFindings?: DTrackFinding[];
    previousScore?: number;
  },
  config?: AIAnalysisConfig
): Promise<RiskScore> {
  const systemPrompt = `You are a security risk analyst. Calculate a comprehensive risk score based on security scan data.
Provide category scores and actionable recommendations.`;

  const allVulns = data.trivyResults?.Results?.flatMap((r) => r.Vulnerabilities || []) || [];
  const summary = {
    vulnCount: allVulns.length,
    criticalVulns: allVulns.filter((v) => v.Severity === "CRITICAL").length,
    highVulns: allVulns.filter((v) => v.Severity === "HIGH").length,
    sonarIssues: data.sonarIssues?.length || 0,
    dtrackFindings: data.dtrackFindings?.length || 0,
    previousScore: data.previousScore,
  };

  const userPrompt = `Calculate a risk score based on this security data:

${JSON.stringify(summary, null, 2)}

Return JSON with this structure:
{
  "overall": 0-100 (0 is best, 100 is worst),
  "categories": {
    "vulnerabilities": 0-100,
    "codeQuality": 0-100,
    "dependencies": 0-100,
    "configuration": 0-100,
    "exposure": 0-100
  },
  "trend": "IMPROVING|STABLE|DEGRADING",
  "topRisks": [
    { "risk": "risk description", "score": 0-100, "mitigation": "how to mitigate" }
  ],
  "recommendations": ["prioritized recommendations"]
}`;

  const response = await aiRequest(systemPrompt, userPrompt, config);
  return parseAIJson<RiskScore>(response);
}

// =============================================================================
// Export Summary
// =============================================================================

export const aiSecurityExports = {
  // Client management
  initAIClient,

  // Vulnerability analysis
  analyzeVulnerability,
  analyzeVulnerabilities,

  // Code security
  analyzeCodeSecurity,

  // Remediation
  generateRemediationPlan,

  // Insights
  generateSecurityInsights,

  // Threat modeling
  generateThreatModel,

  // Risk scoring
  calculateRiskScore,
};
