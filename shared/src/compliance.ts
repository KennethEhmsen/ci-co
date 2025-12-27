/**
 * Compliance Framework Module
 *
 * Maps security vulnerabilities to regulatory compliance frameworks:
 * - SOC2 (Service Organization Control 2)
 * - HIPAA (Health Insurance Portability and Accountability Act)
 * - PCI-DSS (Payment Card Industry Data Security Standard)
 * - CIS (Center for Internet Security Benchmarks)
 */

import type {
  ComplianceFramework,
  ComplianceControl,
  ComplianceViolation,
  ComplianceReport,
  ComplianceReportOptions,
  ComplianceFrameworkSummary,
  ComplianceTrendEntry,
  ComplianceTrendResult,
  ComplianceCheckOptions,
  ComplianceCheckResult,
  ComplianceVulnerabilityType,
  ComplianceSeverity,
  SecurityDashboardResult,
  SecurityDashboardFinding,
} from "./types.js";

// =============================================================================
// COMPLIANCE CONTROL DEFINITIONS
// =============================================================================

/**
 * Complete mapping of compliance controls for all supported frameworks.
 * Each control includes severity mappings, vulnerability types, and SLAs.
 */
export const COMPLIANCE_CONTROLS: Record<ComplianceFramework, ComplianceControl[]> = {
  SOC2: [
    {
      id: "CC6.1",
      framework: "SOC2",
      name: "Logical and Physical Access Controls",
      description:
        "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
      category: "Access Control",
      severityMapping: { critical: true, high: true, medium: true, low: false },
      vulnerabilityTypes: ["cve", "misconfig"],
      remediationSLA: { critical: "24h", high: "7d", medium: "30d", low: "90d" },
    },
    {
      id: "CC6.6",
      framework: "SOC2",
      name: "Boundary Protection",
      description:
        "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
      category: "Access Control",
      severityMapping: { critical: true, high: true, medium: true, low: false },
      vulnerabilityTypes: ["cve", "misconfig"],
      remediationSLA: { critical: "24h", high: "7d", medium: "30d", low: "90d" },
    },
    {
      id: "CC6.7",
      framework: "SOC2",
      name: "Transmission Security",
      description:
        "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes.",
      category: "Access Control",
      severityMapping: { critical: true, high: true, medium: false, low: false },
      vulnerabilityTypes: ["cve", "secret"],
      remediationSLA: { critical: "24h", high: "7d", medium: "30d", low: "90d" },
    },
    {
      id: "CC7.1",
      framework: "SOC2",
      name: "System Operations and Vulnerability Management",
      description:
        "To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities.",
      category: "Vulnerability Management",
      severityMapping: { critical: true, high: true, medium: true, low: true },
      vulnerabilityTypes: ["cve", "secret", "misconfig", "license"],
      remediationSLA: { critical: "24h", high: "7d", medium: "30d", low: "90d" },
    },
    {
      id: "CC7.2",
      framework: "SOC2",
      name: "Incident Response",
      description:
        "The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts.",
      category: "Incident Response",
      severityMapping: { critical: true, high: true, medium: false, low: false },
      vulnerabilityTypes: ["cve", "secret", "misconfig"],
      remediationSLA: { critical: "24h", high: "7d", medium: "30d", low: "90d" },
    },
  ],

  HIPAA: [
    {
      id: "164.308(a)(1)(ii)(A)",
      framework: "HIPAA",
      name: "Risk Analysis",
      description:
        "Conduct an accurate and thorough assessment of the potential risks and vulnerabilities to the confidentiality, integrity, and availability of ePHI.",
      category: "Administrative Safeguards",
      severityMapping: { critical: true, high: true, medium: true, low: true },
      vulnerabilityTypes: ["cve", "secret", "misconfig"],
      remediationSLA: { critical: "immediate", high: "14d", medium: "30d", low: "60d" },
    },
    {
      id: "164.308(a)(1)(ii)(B)",
      framework: "HIPAA",
      name: "Risk Management",
      description:
        "Implement security measures sufficient to reduce risks and vulnerabilities to a reasonable and appropriate level.",
      category: "Administrative Safeguards",
      severityMapping: { critical: true, high: true, medium: true, low: true },
      vulnerabilityTypes: ["cve", "secret", "misconfig"],
      remediationSLA: { critical: "immediate", high: "14d", medium: "30d", low: "60d" },
    },
    {
      id: "164.308(a)(5)(ii)(B)",
      framework: "HIPAA",
      name: "Protection from Malicious Software",
      description: "Procedures for guarding against, detecting, and reporting malicious software.",
      category: "Administrative Safeguards",
      severityMapping: { critical: true, high: true, medium: true, low: false },
      vulnerabilityTypes: ["cve"],
      remediationSLA: { critical: "immediate", high: "14d", medium: "30d", low: "60d" },
    },
    {
      id: "164.312(a)(1)",
      framework: "HIPAA",
      name: "Access Control",
      description:
        "Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to authorized persons.",
      category: "Technical Safeguards",
      severityMapping: { critical: true, high: true, medium: false, low: false },
      vulnerabilityTypes: ["cve", "misconfig"],
      remediationSLA: { critical: "immediate", high: "14d", medium: "30d", low: "60d" },
    },
    {
      id: "164.312(e)(1)",
      framework: "HIPAA",
      name: "Transmission Security",
      description:
        "Implement technical security measures to guard against unauthorized access to ePHI being transmitted over an electronic network.",
      category: "Technical Safeguards",
      severityMapping: { critical: true, high: true, medium: false, low: false },
      vulnerabilityTypes: ["secret", "misconfig"],
      remediationSLA: { critical: "immediate", high: "14d", medium: "30d", low: "60d" },
    },
  ],

  // NOSONAR: IDs like "11.3.1.1" are PCI-DSS requirement identifiers, not IP addresses
  "PCI-DSS": [
    {
      id: "6.3.1",
      framework: "PCI-DSS",
      name: "Vulnerability Risk Ranking",
      description:
        "Security vulnerabilities are identified and ranked according to risk with critical and high-security vulnerabilities addressed first.",
      category: "Secure Development",
      severityMapping: { critical: true, high: true, medium: true, low: true },
      vulnerabilityTypes: ["cve"],
      remediationSLA: { critical: "30d", high: "30d", medium: "90d", low: "90d" },
    },
    {
      id: "6.5.1",
      framework: "PCI-DSS",
      name: "Injection Flaws",
      description:
        "Protect against injection attacks such as SQL injection, LDAP injection, XPath injection.",
      category: "Secure Coding",
      severityMapping: { critical: true, high: true, medium: true, low: false },
      vulnerabilityTypes: ["cve"],
      remediationSLA: { critical: "30d", high: "30d", medium: "90d", low: "90d" },
    },
    {
      id: "11.3.1.1",
      framework: "PCI-DSS",
      name: "Vulnerability Management Program",
      description:
        "Maintain a vulnerability management program that addresses all vulnerabilities, not just critical and high.",
      category: "Vulnerability Scanning",
      severityMapping: { critical: true, high: true, medium: true, low: true },
      vulnerabilityTypes: ["cve", "misconfig"],
      remediationSLA: { critical: "30d", high: "30d", medium: "90d", low: "90d" },
    },
    {
      id: "11.3.1.2",
      framework: "PCI-DSS",
      name: "Authenticated Internal Vulnerability Scans",
      description:
        "Internal vulnerability scans are performed via authenticated scanning with sufficient privileges.",
      category: "Vulnerability Scanning",
      severityMapping: { critical: true, high: true, medium: true, low: true },
      vulnerabilityTypes: ["cve", "misconfig"],
      remediationSLA: { critical: "30d", high: "30d", medium: "90d", low: "90d" },
    },
    {
      id: "11.3.1.3",
      framework: "PCI-DSS",
      name: "Post-Change Vulnerability Scans",
      description: "Internal and external scans are performed after any significant change.",
      category: "Vulnerability Scanning",
      severityMapping: { critical: true, high: true, medium: false, low: false },
      vulnerabilityTypes: ["cve"],
      remediationSLA: { critical: "30d", high: "30d", medium: "90d", low: "90d" },
    },
  ],

  CIS: [
    {
      id: "CIS-4.1",
      framework: "CIS",
      name: "Ensure Container Image is Created with a Non-root User",
      description:
        "Container images should be configured to run as a non-root user to reduce the attack surface.",
      category: "Container Images",
      severityMapping: { critical: true, high: true, medium: true, low: false },
      vulnerabilityTypes: ["misconfig"],
      remediationSLA: { critical: "7d", high: "14d", medium: "30d", low: "90d" },
    },
    {
      id: "CIS-4.5",
      framework: "CIS",
      name: "Ensure Content Trust for Docker is Enabled",
      description:
        "Content trust provides the ability to verify the integrity and publisher of container images.",
      category: "Container Images",
      severityMapping: { critical: false, high: true, medium: true, low: false },
      vulnerabilityTypes: ["misconfig"],
      remediationSLA: { critical: "7d", high: "14d", medium: "30d", low: "90d" },
    },
    {
      id: "CIS-5.1",
      framework: "CIS",
      name: "Ensure AppArmor Profile is Set",
      description: "AppArmor protects the operating system from container breakouts.",
      category: "Container Runtime",
      severityMapping: { critical: false, high: true, medium: false, low: false },
      vulnerabilityTypes: ["misconfig"],
      remediationSLA: { critical: "7d", high: "14d", medium: "30d", low: "90d" },
    },
    {
      id: "CIS-5.9",
      framework: "CIS",
      name: "Ensure the Host Network Namespace is Not Shared",
      description:
        "Container should not share the host network namespace to prevent network access to host services.",
      category: "Container Runtime",
      severityMapping: { critical: true, high: true, medium: false, low: false },
      vulnerabilityTypes: ["misconfig"],
      remediationSLA: { critical: "7d", high: "14d", medium: "30d", low: "90d" },
    },
    {
      id: "CIS-5.12",
      framework: "CIS",
      name: "Ensure Container Root Filesystem is Mounted Read-Only",
      description:
        "The container root filesystem should be treated as an immutable infrastructure.",
      category: "Container Runtime",
      severityMapping: { critical: true, high: true, medium: false, low: false },
      vulnerabilityTypes: ["misconfig"],
      remediationSLA: { critical: "7d", high: "14d", medium: "30d", low: "90d" },
    },
    {
      id: "CIS-5.25",
      framework: "CIS",
      name: "Ensure Container is Restricted from Acquiring New Privileges",
      description:
        "Restrict the container from acquiring additional privileges via setuid or setgid binaries.",
      category: "Container Runtime",
      severityMapping: { critical: true, high: true, medium: true, low: false },
      vulnerabilityTypes: ["misconfig"],
      remediationSLA: { critical: "7d", high: "14d", medium: "30d", low: "90d" },
    },
  ],
};

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Get list of all supported compliance frameworks.
 */
export function getComplianceFrameworks(): ComplianceFramework[] {
  return ["SOC2", "HIPAA", "PCI-DSS", "CIS"];
}

/**
 * Get all controls for a specific framework.
 */
export function getComplianceControls(framework: ComplianceFramework): ComplianceControl[] {
  return COMPLIANCE_CONTROLS[framework] || [];
}

/**
 * Get a specific control by framework and ID.
 */
export function getComplianceControl(
  framework: ComplianceFramework,
  controlId: string
): ComplianceControl | undefined {
  return COMPLIANCE_CONTROLS[framework]?.find((c) => c.id === controlId);
}

/**
 * Normalize severity from various sources to ComplianceSeverity.
 */
function normalizeSeverity(severity: string): ComplianceSeverity {
  const upper = severity.toUpperCase();
  switch (upper) {
    case "CRITICAL":
    case "BLOCKER":
      return "critical";
    case "HIGH":
    case "MAJOR":
      return "high";
    case "MEDIUM":
    case "MODERATE":
    case "MINOR":
      return "medium";
    default:
      return "low";
  }
}

/**
 * Determine vulnerability type from finding source and characteristics.
 */
function determineVulnerabilityType(
  finding: SecurityDashboardFinding
): ComplianceVulnerabilityType {
  const id = finding.id?.toLowerCase() || "";
  const message = finding.message?.toLowerCase() || "";

  // CVE pattern
  if (id.startsWith("cve-") || id.match(/^cve-\d{4}-\d+$/i)) {
    return "cve";
  }

  // Secret patterns
  if (
    message.includes("secret") ||
    message.includes("password") ||
    message.includes("api key") ||
    message.includes("credential") ||
    message.includes("token")
  ) {
    return "secret";
  }

  // License patterns
  if (message.includes("license") || id.includes("license")) {
    return "license";
  }

  // Misconfiguration (default for non-CVE issues)
  if (finding.source === "sonarqube" || message.includes("config") || message.includes("policy")) {
    return "misconfig";
  }

  // Default to CVE for vulnerability IDs
  return "cve";
}

/**
 * Check if a control matches a vulnerability based on type and severity.
 */
function controlMatchesVulnerability(
  control: ComplianceControl,
  vulnType: ComplianceVulnerabilityType,
  severity: ComplianceSeverity
): boolean {
  // Check if vulnerability type matches
  if (!control.vulnerabilityTypes.includes(vulnType)) {
    return false;
  }

  // Check if severity is covered by this control
  return control.severityMapping[severity] === true;
}

/**
 * Calculate due date based on SLA.
 */
function calculateDueDate(sla: string, detectedAt: Date = new Date()): string {
  const dueDate = new Date(detectedAt);

  if (sla === "immediate") {
    dueDate.setHours(dueDate.getHours() + 24);
  } else if (sla.endsWith("h")) {
    const hours = parseInt(sla);
    dueDate.setHours(dueDate.getHours() + hours);
  } else if (sla.endsWith("d")) {
    const days = parseInt(sla);
    dueDate.setDate(dueDate.getDate() + days);
  }

  return dueDate.toISOString();
}

// =============================================================================
// MAPPING FUNCTIONS
// =============================================================================

/**
 * Map a single finding to all applicable compliance controls.
 */
export function mapFindingToControls(
  finding: SecurityDashboardFinding,
  frameworks?: ComplianceFramework[]
): ComplianceControl[] {
  const vulnType = determineVulnerabilityType(finding);
  const severity = normalizeSeverity(finding.severity);
  const targetFrameworks = frameworks || getComplianceFrameworks();

  const matchingControls: ComplianceControl[] = [];

  for (const framework of targetFrameworks) {
    const controls = COMPLIANCE_CONTROLS[framework];
    if (!controls) continue;

    for (const control of controls) {
      if (controlMatchesVulnerability(control, vulnType, severity)) {
        matchingControls.push(control);
      }
    }
  }

  return matchingControls;
}

/**
 * Create a compliance violation from a finding and control.
 */
function createViolation(
  finding: SecurityDashboardFinding,
  control: ComplianceControl,
  detectedAt: Date = new Date()
): ComplianceViolation {
  const severity = normalizeSeverity(finding.severity);
  const sla = control.remediationSLA[severity];

  return {
    control,
    vulnerability: {
      id: finding.id,
      severity: finding.severity,
      type: determineVulnerabilityType(finding),
      package: finding.package,
      description: finding.message,
      source: finding.source,
    },
    status: "open",
    dueDate: calculateDueDate(sla, detectedAt),
    detectedAt: detectedAt.toISOString(),
  };
}

// =============================================================================
// REPORT GENERATION
// =============================================================================

/**
 * Generate a compliance report from security dashboard results.
 */
export function generateComplianceReport(
  dashboardResult: SecurityDashboardResult,
  options: ComplianceReportOptions = {}
): ComplianceReport {
  const frameworks = options.frameworks || getComplianceFrameworks();
  const detectedAt = new Date(dashboardResult.timestamp);
  const allViolations: ComplianceViolation[] = [];

  // Track which controls have violations
  const controlViolations = new Map<string, ComplianceViolation[]>();

  // Process all findings from the dashboard
  for (const finding of dashboardResult.topFindings) {
    const matchingControls = mapFindingToControls(finding, frameworks);

    for (const control of matchingControls) {
      const key = `${control.framework}:${control.id}`;
      const violation = createViolation(finding, control, detectedAt);
      allViolations.push(violation);

      if (!controlViolations.has(key)) {
        controlViolations.set(key, []);
      }
      controlViolations.get(key)!.push(violation);
    }
  }

  // Build per-framework summaries
  const byFramework: Partial<Record<ComplianceFramework, ComplianceFrameworkSummary>> = {};

  for (const framework of frameworks) {
    const controls = COMPLIANCE_CONTROLS[framework];
    const frameworkViolations = allViolations.filter((v) => v.control.framework === framework);

    // Count unique failing controls
    const failingControlIds = new Set<string>();
    for (const violation of frameworkViolations) {
      failingControlIds.add(violation.control.id);
    }

    const totalControls = controls.length;
    const failingControls = failingControlIds.size;
    const passingControls = totalControls - failingControls;
    const compliancePercentage =
      totalControls > 0 ? Math.round((passingControls / totalControls) * 100) : 100;

    byFramework[framework] = {
      framework,
      totalControls,
      passingControls,
      failingControls,
      compliancePercentage,
      violations: frameworkViolations,
    };
  }

  // Calculate overall summary
  let totalControls = 0;
  let totalPassing = 0;
  let totalFailing = 0;

  for (const summary of Object.values(byFramework)) {
    if (summary) {
      totalControls += summary.totalControls;
      totalPassing += summary.passingControls;
      totalFailing += summary.failingControls;
    }
  }

  const overallPercentage =
    totalControls > 0 ? Math.round((totalPassing / totalControls) * 100) : 100;

  // Count by severity
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const violation of allViolations) {
    const sev = normalizeSeverity(violation.vulnerability.severity);
    bySeverity[sev]++;
  }

  // Sort violations by severity for top list
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const sortedViolations = [...allViolations].sort((a, b) => {
    const sevA = normalizeSeverity(a.vulnerability.severity);
    const sevB = normalizeSeverity(b.vulnerability.severity);
    return severityOrder[sevA] - severityOrder[sevB];
  });

  // Generate recommendations
  const recommendations = generateRecommendations(byFramework, bySeverity);

  // Determine scan target
  const scanTarget =
    dashboardResult.scanTargets.image ||
    dashboardResult.scanTargets.path ||
    dashboardResult.scanTargets.sonarProject ||
    "Unknown";

  return {
    generatedAt: new Date().toISOString(),
    scanTarget,
    frameworks,
    summary: {
      totalControls,
      passingControls: totalPassing,
      failingControls: totalFailing,
      compliancePercentage: overallPercentage,
    },
    byFramework,
    bySeverity,
    topViolations: sortedViolations.slice(0, 10),
    recommendations,
  };
}

/**
 * Generate remediation recommendations based on violations.
 */
function generateRecommendations(
  byFramework: Partial<Record<ComplianceFramework, ComplianceFrameworkSummary>>,
  bySeverity: { critical: number; high: number; medium: number; low: number }
): string[] {
  const recommendations: string[] = [];

  // Critical severity recommendation
  if (bySeverity.critical > 0) {
    recommendations.push(
      `URGENT: ${bySeverity.critical} critical vulnerabilities require immediate attention within 24-48 hours.`
    );
  }

  // High severity recommendation
  if (bySeverity.high > 0) {
    recommendations.push(
      `HIGH PRIORITY: ${bySeverity.high} high-severity issues should be remediated within 7-14 days.`
    );
  }

  // Framework-specific recommendations
  for (const [framework, summary] of Object.entries(byFramework)) {
    if (!summary || summary.compliancePercentage >= 100) continue;

    if (summary.compliancePercentage < 50) {
      recommendations.push(
        `${framework} compliance is at ${summary.compliancePercentage}%. Immediate attention required to meet regulatory requirements.`
      );
    } else if (summary.compliancePercentage < 80) {
      recommendations.push(
        `${framework} compliance is at ${summary.compliancePercentage}%. Create a remediation plan to address ${summary.failingControls} failing controls.`
      );
    }
  }

  // Add general recommendations
  if (recommendations.length === 0) {
    recommendations.push(
      "All compliance controls are passing. Continue monitoring for new vulnerabilities."
    );
  } else {
    recommendations.push(
      "Document all remediation activities for audit purposes.",
      "Schedule a follow-up scan after implementing fixes to verify remediation."
    );
  }

  return recommendations;
}

// =============================================================================
// HTML REPORT GENERATION
// =============================================================================

/**
 * Generate an HTML compliance report with professional styling.
 */
export function generateComplianceHtml(
  report: ComplianceReport,
  options: ComplianceReportOptions = {}
): string {
  const title = options.title || "Security Compliance Report";
  const organization = options.organization || "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)}${organization ? ` - ${escapeHtml(organization)}` : ""}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header { background: linear-gradient(135deg, #1a365d 0%, #2c5282 100%); color: white; padding: 40px 20px; margin-bottom: 30px; border-radius: 8px; }
    header h1 { font-size: 2.5em; margin-bottom: 10px; }
    header .meta { opacity: 0.9; font-size: 0.95em; }
    .card { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 25px; margin-bottom: 25px; }
    .card h2 { color: #1a365d; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; margin-bottom: 20px; }
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
    .summary-item { text-align: center; padding: 20px; background: #f7fafc; border-radius: 8px; }
    .summary-item .value { font-size: 2.5em; font-weight: bold; color: #1a365d; }
    .summary-item .label { color: #718096; font-size: 0.9em; text-transform: uppercase; letter-spacing: 0.5px; }
    .gauge-container { display: flex; justify-content: center; gap: 40px; flex-wrap: wrap; margin: 30px 0; }
    .gauge { width: 150px; height: 150px; position: relative; }
    .gauge svg { transform: rotate(-90deg); }
    .gauge circle { fill: none; stroke-width: 12; }
    .gauge .bg { stroke: #e2e8f0; }
    .gauge .progress { stroke-linecap: round; transition: stroke-dashoffset 0.5s; }
    .gauge .value { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 1.8em; font-weight: bold; }
    .gauge .label { text-align: center; margin-top: 10px; font-weight: 500; color: #4a5568; }
    .progress-green { stroke: #48bb78; }
    .progress-yellow { stroke: #ecc94b; }
    .progress-orange { stroke: #ed8936; }
    .progress-red { stroke: #f56565; }
    .severity-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: 600; text-transform: uppercase; }
    .severity-critical { background: #fed7d7; color: #c53030; }
    .severity-high { background: #feebc8; color: #c05621; }
    .severity-medium { background: #fefcbf; color: #975a16; }
    .severity-low { background: #c6f6d5; color: #276749; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #e2e8f0; }
    th { background: #f7fafc; font-weight: 600; color: #4a5568; text-transform: uppercase; font-size: 0.85em; letter-spacing: 0.5px; }
    tr:hover { background: #f7fafc; }
    .recommendation { padding: 15px 20px; background: #ebf8ff; border-left: 4px solid #3182ce; margin-bottom: 15px; border-radius: 0 8px 8px 0; }
    .recommendation.urgent { background: #fff5f5; border-left-color: #c53030; }
    .recommendation.high { background: #fffaf0; border-left-color: #dd6b20; }
    .framework-section { margin-bottom: 30px; }
    .framework-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
    .framework-header h3 { color: #2d3748; }
    .compliance-badge { padding: 8px 16px; border-radius: 20px; font-weight: 600; }
    .compliance-pass { background: #c6f6d5; color: #276749; }
    .compliance-warn { background: #fefcbf; color: #975a16; }
    .compliance-fail { background: #fed7d7; color: #c53030; }
    footer { text-align: center; padding: 30px; color: #718096; font-size: 0.9em; }
    @media print { body { background: white; } .card { box-shadow: none; border: 1px solid #e2e8f0; } }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>${escapeHtml(title)}</h1>
      <div class="meta">
        ${organization ? `<strong>${escapeHtml(organization)}</strong> | ` : ""}
        Generated: ${new Date(report.generatedAt).toLocaleString()} |
        Target: ${escapeHtml(report.scanTarget)}
      </div>
    </header>

    <div class="card">
      <h2>Executive Summary</h2>
      <div class="summary-grid">
        <div class="summary-item">
          <div class="value">${report.summary.compliancePercentage}%</div>
          <div class="label">Overall Compliance</div>
        </div>
        <div class="summary-item">
          <div class="value">${report.summary.totalControls}</div>
          <div class="label">Total Controls</div>
        </div>
        <div class="summary-item">
          <div class="value" style="color: #48bb78;">${report.summary.passingControls}</div>
          <div class="label">Passing</div>
        </div>
        <div class="summary-item">
          <div class="value" style="color: #f56565;">${report.summary.failingControls}</div>
          <div class="label">Failing</div>
        </div>
      </div>

      <div class="gauge-container">
        ${report.frameworks
          .map((framework) => {
            const summary = report.byFramework[framework];
            if (!summary) return "";
            const percentage = summary.compliancePercentage;
            const circumference = 2 * Math.PI * 54;
            const offset = circumference - (percentage / 100) * circumference;
            const colorClass =
              percentage >= 80
                ? "progress-green"
                : percentage >= 60
                  ? "progress-yellow"
                  : percentage >= 40
                    ? "progress-orange"
                    : "progress-red";

            return `
            <div class="gauge">
              <svg width="150" height="150">
                <circle class="bg" cx="75" cy="75" r="54"></circle>
                <circle class="progress ${colorClass}" cx="75" cy="75" r="54"
                  stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"></circle>
              </svg>
              <div class="value">${percentage}%</div>
              <div class="label">${framework}</div>
            </div>
          `;
          })
          .join("")}
      </div>
    </div>

    <div class="card">
      <h2>Violations by Severity</h2>
      <div class="summary-grid">
        <div class="summary-item">
          <div class="value" style="color: #c53030;">${report.bySeverity.critical}</div>
          <div class="label">Critical</div>
        </div>
        <div class="summary-item">
          <div class="value" style="color: #dd6b20;">${report.bySeverity.high}</div>
          <div class="label">High</div>
        </div>
        <div class="summary-item">
          <div class="value" style="color: #d69e2e;">${report.bySeverity.medium}</div>
          <div class="label">Medium</div>
        </div>
        <div class="summary-item">
          <div class="value" style="color: #38a169;">${report.bySeverity.low}</div>
          <div class="label">Low</div>
        </div>
      </div>
    </div>

    ${report.frameworks
      .map((framework) => {
        const summary = report.byFramework[framework];
        if (!summary) return "";

        const badgeClass =
          summary.compliancePercentage >= 80
            ? "compliance-pass"
            : summary.compliancePercentage >= 50
              ? "compliance-warn"
              : "compliance-fail";

        return `
        <div class="card framework-section">
          <div class="framework-header">
            <h3>${framework} Compliance</h3>
            <span class="compliance-badge ${badgeClass}">${summary.compliancePercentage}% Compliant</span>
          </div>
          <p style="margin-bottom: 20px; color: #718096;">
            ${summary.passingControls} of ${summary.totalControls} controls passing |
            ${summary.violations.length} violations found
          </p>
          ${
            summary.violations.length > 0
              ? `
          <table>
            <thead>
              <tr>
                <th>Control</th>
                <th>Vulnerability</th>
                <th>Severity</th>
                <th>Due Date</th>
              </tr>
            </thead>
            <tbody>
              ${summary.violations
                .slice(0, 10)
                .map(
                  (v) => `
                <tr>
                  <td><strong>${escapeHtml(v.control.id)}</strong><br><small>${escapeHtml(v.control.name)}</small></td>
                  <td>${escapeHtml(v.vulnerability.id)}${v.vulnerability.package ? `<br><small>${escapeHtml(v.vulnerability.package)}</small>` : ""}</td>
                  <td><span class="severity-badge severity-${normalizeSeverity(v.vulnerability.severity)}">${escapeHtml(v.vulnerability.severity)}</span></td>
                  <td>${new Date(v.dueDate).toLocaleDateString()}</td>
                </tr>
              `
                )
                .join("")}
            </tbody>
          </table>
          ${summary.violations.length > 10 ? `<p style="margin-top: 15px; color: #718096;">... and ${summary.violations.length - 10} more violations</p>` : ""}
          `
              : '<p style="color: #48bb78;">All controls passing</p>'
          }
        </div>
      `;
      })
      .join("")}

    <div class="card">
      <h2>Recommendations</h2>
      ${report.recommendations
        .map((rec) => {
          const isUrgent =
            rec.toLowerCase().includes("urgent") || rec.toLowerCase().includes("critical");
          const isHigh = rec.toLowerCase().includes("high priority");
          const className = isUrgent ? "urgent" : isHigh ? "high" : "";
          return `<div class="recommendation ${className}">${escapeHtml(rec)}</div>`;
        })
        .join("")}
    </div>

    <footer>
      Generated by CI/CD Security Platform v1.21.0 |
      Report covers: ${report.frameworks.join(", ")}
    </footer>
  </div>
</body>
</html>`;
}

/**
 * Escape HTML special characters.
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
// TREND TRACKING
// =============================================================================

/** In-memory storage for compliance trends */
const trendStore = new Map<string, ComplianceTrendEntry[]>();

/**
 * Record a compliance trend snapshot.
 */
export function recordComplianceTrend(
  target: string,
  report: ComplianceReport
): ComplianceTrendEntry {
  const entry: ComplianceTrendEntry = {
    timestamp: report.generatedAt,
    target,
    frameworks: report.frameworks,
    summary: {
      totalViolations: report.topViolations.length,
      critical: report.bySeverity.critical,
      high: report.bySeverity.high,
      medium: report.bySeverity.medium,
      low: report.bySeverity.low,
      compliancePercentage: report.summary.compliancePercentage,
    },
  };

  if (!trendStore.has(target)) {
    trendStore.set(target, []);
  }

  const entries = trendStore.get(target)!;
  entries.push(entry);

  // Keep only last 100 entries per target
  if (entries.length > 100) {
    entries.shift();
  }

  return entry;
}

/**
 * Get compliance trends for a target over a time period.
 */
export function getComplianceTrend(target: string, days: number = 30): ComplianceTrendResult {
  const entries = trendStore.get(target) || [];
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - days);

  const filteredEntries = entries.filter((e) => new Date(e.timestamp) >= cutoff);

  // Calculate trend direction
  let trend: "improving" | "declining" | "stable" = "stable";
  let changeFromFirst = 0;

  if (filteredEntries.length >= 2) {
    const first = filteredEntries[0];
    const last = filteredEntries[filteredEntries.length - 1];
    changeFromFirst = last.summary.compliancePercentage - first.summary.compliancePercentage;

    if (changeFromFirst > 5) {
      trend = "improving";
    } else if (changeFromFirst < -5) {
      trend = "declining";
    }
  }

  return {
    target,
    period: {
      start: cutoff.toISOString(),
      end: new Date().toISOString(),
    },
    entries: filteredEntries,
    trend,
    changeFromFirst,
  };
}

/**
 * Clear all trend data (useful for testing).
 */
export function clearComplianceTrends(): void {
  trendStore.clear();
}

/**
 * Get all targets with trend data.
 */
export function getComplianceTrendTargets(): string[] {
  return Array.from(trendStore.keys());
}

// =============================================================================
// COMPLIANCE CHECK
// =============================================================================

/**
 * Check compliance status and return pass/fail result.
 */
export function checkComplianceStatus(
  dashboardResult: SecurityDashboardResult,
  options: ComplianceCheckOptions = {}
): ComplianceCheckResult {
  const report = generateComplianceReport(dashboardResult, {
    frameworks: options.frameworks,
    severity: options.severity,
  });

  // Determine if passed (no critical or high violations)
  const passed = report.bySeverity.critical === 0 && report.bySeverity.high === 0;

  // Get failing controls
  const failingControls: ComplianceCheckResult["failingControls"] = [];
  const controlCounts = new Map<string, number>();

  for (const violation of report.topViolations) {
    const key = `${violation.control.framework}:${violation.control.id}`;
    controlCounts.set(key, (controlCounts.get(key) || 0) + 1);
  }

  for (const [key, count] of controlCounts) {
    const [framework, controlId] = key.split(":") as [ComplianceFramework, string];
    const control = getComplianceControl(framework, controlId);
    if (control) {
      failingControls.push({
        framework,
        controlId,
        controlName: control.name,
        violationCount: count,
      });
    }
  }

  return {
    passed,
    compliancePercentage: report.summary.compliancePercentage,
    violations: {
      critical: report.bySeverity.critical,
      high: report.bySeverity.high,
      medium: report.bySeverity.medium,
      low: report.bySeverity.low,
      total:
        report.bySeverity.critical +
        report.bySeverity.high +
        report.bySeverity.medium +
        report.bySeverity.low,
    },
    failingControls,
    report,
  };
}
