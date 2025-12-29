/**
 * IDE Integration Module
 *
 * Provides LSP-compatible diagnostics and code actions for vulnerability
 * remediation, supporting VS Code, JetBrains, and other LSP-compatible editors.
 */

import type { TrivyScanResult, RemediationSuggestion } from "./types.js";

// =============================================================================
// LSP Types (subset for diagnostics)
// =============================================================================

/** LSP Diagnostic Severity */
export enum DiagnosticSeverity {
  Error = 1,
  Warning = 2,
  Information = 3,
  Hint = 4,
}

/** LSP Position (0-indexed) */
export interface Position {
  line: number;
  character: number;
}

/** LSP Range */
export interface Range {
  start: Position;
  end: Position;
}

/** LSP Diagnostic */
export interface Diagnostic {
  range: Range;
  message: string;
  severity: DiagnosticSeverity;
  code?: string;
  source: string;
  data?: Record<string, unknown>;
  relatedInformation?: DiagnosticRelatedInformation[];
}

/** Related information for diagnostics */
export interface DiagnosticRelatedInformation {
  location: {
    uri: string;
    range: Range;
  };
  message: string;
}

/** LSP Code Action */
export interface CodeAction {
  title: string;
  kind: string;
  diagnostics?: Diagnostic[];
  isPreferred?: boolean;
  edit?: WorkspaceEdit;
  command?: Command;
  data?: Record<string, unknown>;
}

/** LSP Workspace Edit */
export interface WorkspaceEdit {
  changes?: Record<string, TextEdit[]>;
  documentChanges?: (TextDocumentEdit | CreateFile | RenameFile | DeleteFile)[];
}

/** LSP Text Edit */
export interface TextEdit {
  range: Range;
  newText: string;
}

/** LSP Text Document Edit */
export interface TextDocumentEdit {
  textDocument: { uri: string; version: number | null };
  edits: TextEdit[];
}

/** LSP Create File */
export interface CreateFile {
  kind: "create";
  uri: string;
}

/** LSP Rename File */
export interface RenameFile {
  kind: "rename";
  oldUri: string;
  newUri: string;
}

/** LSP Delete File */
export interface DeleteFile {
  kind: "delete";
  uri: string;
}

/** LSP Command */
export interface Command {
  title: string;
  command: string;
  arguments?: unknown[];
}

// =============================================================================
// IDE Diagnostics Result
// =============================================================================

/** Result of generating IDE diagnostics */
export interface IdeDiagnosticsResult {
  /** File path to diagnostics mapping */
  diagnostics: Record<string, Diagnostic[]>;
  /** Total diagnostic count */
  totalCount: number;
  /** Count by severity */
  bySeverity: {
    error: number;
    warning: number;
    info: number;
    hint: number;
  };
}

/** IDE Code Actions Result */
export interface IdeCodeActionsResult {
  actions: CodeAction[];
  appliedCount: number;
}

// =============================================================================
// Severity Mapping
// =============================================================================

/**
 * Map vulnerability severity to LSP diagnostic severity
 */
function mapSeverity(severity: string): DiagnosticSeverity {
  switch (severity.toUpperCase()) {
    case "CRITICAL":
    case "HIGH":
      return DiagnosticSeverity.Error;
    case "MEDIUM":
      return DiagnosticSeverity.Warning;
    case "LOW":
      return DiagnosticSeverity.Information;
    default:
      return DiagnosticSeverity.Hint;
  }
}

/**
 * Get file path for a vulnerability based on package type
 */
function getFilePath(targetType: string): string {
  const pkgType = targetType;

  switch (pkgType) {
    case "node-pkg":
    case "npm":
    case "yarn":
    case "pnpm":
      return "package.json";
    case "pip":
    case "python-pkg":
      return "requirements.txt";
    case "pipenv":
      return "Pipfile";
    case "poetry":
      return "pyproject.toml";
    case "go":
    case "gomod":
      return "go.mod";
    case "maven":
    case "jar":
      return "pom.xml";
    case "gradle":
      return "build.gradle";
    case "gemspec":
    case "bundler":
      return "Gemfile";
    case "cargo":
      return "Cargo.toml";
    default:
      return "package.json"; // Default assumption
  }
}

/**
 * Find line number for a package in a file
 * Returns 0 if not found (LSP uses 0-indexed lines)
 */
function findPackageLine(fileContent: string, packageName: string, filePath: string): number {
  const lines = fileContent.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // package.json: "package-name": "version"
    if (filePath.endsWith("package.json")) {
      if (line.includes(`"${packageName}":`)) {
        return i;
      }
    }

    // requirements.txt: package-name==version or package-name>=version
    if (filePath.endsWith("requirements.txt")) {
      if (line.startsWith(packageName) && /[=<>~!]/.test(line)) {
        return i;
      }
    }

    // go.mod: require github.com/pkg/name vX.X.X
    if (filePath.endsWith("go.mod")) {
      if (line.includes(packageName)) {
        return i;
      }
    }

    // pom.xml: <artifactId>package-name</artifactId>
    if (filePath.endsWith("pom.xml")) {
      if (line.includes(`<artifactId>${packageName}</artifactId>`)) {
        return i;
      }
    }

    // Cargo.toml: package-name = "version"
    if (filePath.endsWith("Cargo.toml")) {
      if (line.startsWith(packageName) && line.includes("=")) {
        return i;
      }
    }

    // Gemfile: gem 'package-name'
    if (filePath.endsWith("Gemfile")) {
      if (line.includes(`'${packageName}'`) || line.includes(`"${packageName}"`)) {
        return i;
      }
    }
  }

  return 0; // Default to first line if not found
}

// =============================================================================
// Diagnostic Generation
// =============================================================================

/**
 * Generate LSP diagnostics from Trivy scan results
 */
export function generateDiagnostics(
  scanResult: TrivyScanResult,
  options: {
    fileContents?: Record<string, string>;
    minSeverity?: string;
    basePath?: string;
  } = {}
): IdeDiagnosticsResult {
  const { fileContents = {}, minSeverity = "LOW", basePath = "" } = options;
  const diagnosticsMap: Record<string, Diagnostic[]> = {};
  const counts = { error: 0, warning: 0, info: 0, hint: 0 };

  const severityOrder: Record<string, number> = {
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1,
    UNKNOWN: 0,
  };

  const minSevLevel = severityOrder[minSeverity.toUpperCase()] || 0;

  for (const result of scanResult.Results || []) {
    for (const vuln of result.Vulnerabilities || []) {
      const vulnSevLevel = severityOrder[vuln.Severity?.toUpperCase() || "UNKNOWN"] || 0;

      if (vulnSevLevel < minSevLevel) {
        continue;
      }

      const filePath = getFilePath(result.Type || "");
      const fullPath = basePath ? `${basePath}/${filePath}` : filePath;
      const fileContent = fileContents[filePath] || fileContents[fullPath] || "";

      const line = findPackageLine(fileContent, vuln.PkgName, filePath);
      const severity = mapSeverity(vuln.Severity || "UNKNOWN");

      const diagnostic: Diagnostic = {
        range: {
          start: { line, character: 0 },
          end: { line, character: 100 },
        },
        message: `${vuln.VulnerabilityID}: ${vuln.Title || vuln.Description || "Security vulnerability"} (${vuln.Severity})`,
        severity,
        code: vuln.VulnerabilityID,
        source: "cicd-security",
        data: {
          vulnId: vuln.VulnerabilityID,
          packageName: vuln.PkgName,
          currentVersion: vuln.InstalledVersion,
          fixedVersion: vuln.FixedVersion,
          severity: vuln.Severity,
        },
      };

      // Add primary URL as related information if available
      if (vuln.PrimaryURL) {
        diagnostic.relatedInformation = [
          {
            location: {
              uri: vuln.PrimaryURL,
              range: { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } },
            },
            message: `Reference: ${vuln.PrimaryURL}`,
          },
        ];
      }

      if (!diagnosticsMap[fullPath]) {
        diagnosticsMap[fullPath] = [];
      }
      diagnosticsMap[fullPath].push(diagnostic);

      // Update counts
      switch (severity) {
        case DiagnosticSeverity.Error:
          counts.error++;
          break;
        case DiagnosticSeverity.Warning:
          counts.warning++;
          break;
        case DiagnosticSeverity.Information:
          counts.info++;
          break;
        case DiagnosticSeverity.Hint:
          counts.hint++;
          break;
      }
    }
  }

  return {
    diagnostics: diagnosticsMap,
    totalCount: counts.error + counts.warning + counts.info + counts.hint,
    bySeverity: counts,
  };
}

// =============================================================================
// Code Action Generation
// =============================================================================

/**
 * Generate LSP code actions from remediation suggestions
 */
export function generateCodeActions(
  suggestions: RemediationSuggestion[],
  options: {
    filePath?: string;
    diagnostics?: Diagnostic[];
  } = {}
): CodeAction[] {
  const { diagnostics = [] } = options;
  const actions: CodeAction[] = [];

  for (const suggestion of suggestions) {
    const vulnId = suggestion.vulnerability.id;

    // Find matching diagnostic if any
    const matchingDiagnostic = diagnostics.find((d) => d.code === vulnId);

    // Quick fix action
    const quickFix: CodeAction = {
      title: `Fix ${vulnId}: Update ${suggestion.package} to ${suggestion.fixedVersion}`,
      kind: "quickfix",
      isPreferred: true,
      diagnostics: matchingDiagnostic ? [matchingDiagnostic] : undefined,
      command: {
        title: "Apply Security Fix",
        command: "cicd-security.applyFix",
        arguments: [
          {
            vulnId,
            package: suggestion.package,
            currentVersion: suggestion.currentVersion,
            fixedVersion: suggestion.fixedVersion,
            command: suggestion.command,
          },
        ],
      },
      data: {
        vulnId,
        package: suggestion.package,
        fixedVersion: suggestion.fixedVersion,
      },
    };

    actions.push(quickFix);

    // Source action for running remediation command
    if (suggestion.command) {
      const runCommand: CodeAction = {
        title: `Run: ${suggestion.command}`,
        kind: "source.fixAll.security",
        command: {
          title: "Run Remediation Command",
          command: "cicd-security.runCommand",
          arguments: [suggestion.command],
        },
      };
      actions.push(runCommand);
    }
  }

  // Add "Fix all" action if multiple suggestions
  if (suggestions.length > 1) {
    const fixAll: CodeAction = {
      title: `Fix all ${suggestions.length} security issues`,
      kind: "source.fixAll.security",
      isPreferred: false,
      command: {
        title: "Fix All Security Issues",
        command: "cicd-security.fixAll",
        arguments: [suggestions],
      },
    };
    actions.push(fixAll);
  }

  return actions;
}

/**
 * Apply a fix by generating the text edit
 */
export function generateFixEdit(
  suggestion: RemediationSuggestion,
  fileContent: string,
  filePath: string
): TextEdit | null {
  const lines = fileContent.split("\n");
  const packageName = suggestion.package;

  // Find the line with the package
  let lineIndex = -1;
  let originalLine = "";

  for (let i = 0; i < lines.length; i++) {
    if (filePath.endsWith("package.json")) {
      if (lines[i].includes(`"${packageName}"`)) {
        lineIndex = i;
        originalLine = lines[i];
        break;
      }
    } else if (filePath.endsWith("requirements.txt")) {
      if (lines[i].startsWith(packageName) && /[=<>~!]/.test(lines[i])) {
        lineIndex = i;
        originalLine = lines[i];
        break;
      }
    }
    // Add other file types as needed
  }

  if (lineIndex === -1) {
    return null;
  }

  // Generate the new line
  let newLine: string;

  if (filePath.endsWith("package.json")) {
    // Replace version in package.json
    newLine = originalLine.replace(
      new RegExp(`"${suggestion.currentVersion.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`),
      `"${suggestion.fixedVersion}"`
    );
  } else if (filePath.endsWith("requirements.txt")) {
    // Replace version in requirements.txt
    newLine = `${packageName}==${suggestion.fixedVersion}`;
  } else {
    return null;
  }

  return {
    range: {
      start: { line: lineIndex, character: 0 },
      end: { line: lineIndex, character: originalLine.length },
    },
    newText: newLine,
  };
}

/**
 * Apply multiple fixes and return the workspace edit
 */
export function applyFixes(
  suggestions: RemediationSuggestion[],
  fileContents: Record<string, string>
): WorkspaceEdit {
  const changes: Record<string, TextEdit[]> = {};

  for (const suggestion of suggestions) {
    // Determine file path based on package manager
    let filePath: string;
    switch (suggestion.packageManager) {
      case "npm":
      case "yarn":
      case "pnpm":
        filePath = "package.json";
        break;
      case "pip":
        filePath = "requirements.txt";
        break;
      case "poetry":
        filePath = "pyproject.toml";
        break;
      case "go":
        filePath = "go.mod";
        break;
      case "maven":
        filePath = "pom.xml";
        break;
      case "cargo":
        filePath = "Cargo.toml";
        break;
      case "gem":
        filePath = "Gemfile";
        break;
      default:
        filePath = "package.json";
    }

    const content = fileContents[filePath];
    if (!content) continue;

    const edit = generateFixEdit(suggestion, content, filePath);
    if (edit) {
      if (!changes[filePath]) {
        changes[filePath] = [];
      }
      changes[filePath].push(edit);
    }
  }

  return { changes };
}
