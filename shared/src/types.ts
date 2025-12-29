/**
 * Type definitions for CI/CD Platform API responses
 */

// =============================================================================
// Common Type Aliases
// =============================================================================

/** Severity levels for Trivy vulnerabilities (includes UNKNOWN) */
export type TrivySeverity = "UNKNOWN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** Standard severity levels without UNKNOWN */
export type SeverityLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** Security data sources */
export type SecuritySource = "trivy" | "sonarqube" | "dtrack";

/** SARIF result levels */
export type SarifLevel = "none" | "note" | "warning" | "error";

// =============================================================================
// Trivy Types
// =============================================================================

export interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Severity: TrivySeverity;
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
}

export interface TrivyResult {
  Target: string;
  Class: string;
  Type: string;
  Vulnerabilities?: TrivyVulnerability[];
  Secrets?: TrivySecret[];
}

export interface TrivySecret {
  RuleID: string;
  Category: string;
  Severity: string;
  Title: string;
  StartLine: number;
  EndLine: number;
  Match: string;
}

export interface TrivyScanResult {
  SchemaVersion?: number;
  ArtifactName?: string;
  ArtifactType?: string;
  Results?: TrivyResult[];
}

// SBOM (Software Bill of Materials) Types - CycloneDX format
export interface SbomComponent {
  type: "library" | "framework" | "application" | "container" | "file";
  name: string;
  version: string;
  purl?: string;
  licenses?: SbomLicense[];
  hashes?: SbomHash[];
}

export interface SbomLicense {
  license: {
    id?: string;
    name?: string;
  };
}

export interface SbomHash {
  alg: string;
  content: string;
}

export interface SbomMetadata {
  timestamp: string;
  tools?: {
    name: string;
    version: string;
    vendor?: string;
  }[];
  component?: {
    name: string;
    version: string;
    type: string;
  };
}

export interface TrivySbomResult {
  bomFormat: "CycloneDX";
  specVersion: string;
  version: number;
  metadata: SbomMetadata;
  components: SbomComponent[];
  dependencies?: {
    ref: string;
    dependsOn?: string[];
  }[];
}

// IaC (Infrastructure as Code) Misconfiguration Types
export interface IacMisconfiguration {
  Type: string;
  ID: string;
  AVDID?: string;
  Title: string;
  Description: string;
  Message: string;
  Namespace?: string;
  Query?: string;
  Resolution: string;
  Severity: SeverityLevel;
  PrimaryURL?: string;
  References?: string[];
  Status: "FAIL" | "PASS" | "EXCEPTION";
  Layer?: {
    Digest?: string;
    DiffID?: string;
    CreatedBy?: string;
  };
  CauseMetadata?: {
    Resource?: string;
    Provider?: string;
    Service?: string;
    StartLine?: number;
    EndLine?: number;
    Code?: {
      Lines?: {
        Number: number;
        Content: string;
        IsCause: boolean;
        Annotation: string;
        Truncated: boolean;
        Highlighted?: string;
        FirstCause: boolean;
        LastCause: boolean;
      }[];
    };
  };
}

export interface IacResult {
  Target: string;
  Class: "config";
  Type: string;
  MisconfSummary?: {
    Successes: number;
    Failures: number;
    Exceptions: number;
  };
  Misconfigurations?: IacMisconfiguration[];
}

export interface TrivyIacScanResult {
  SchemaVersion?: number;
  CreatedAt?: string;
  ArtifactName?: string;
  ArtifactType?: string;
  Results?: IacResult[];
}

// Secret Scanning Types
export interface SecretResult {
  Target: string;
  Class: "secret";
  Secrets?: TrivySecret[];
}

export interface TrivySecretScanResult {
  SchemaVersion?: number;
  CreatedAt?: string;
  ArtifactName?: string;
  ArtifactType?: string;
  Results?: SecretResult[];
}

// License Scanning Types
export interface LicenseFinding {
  Severity: TrivySeverity;
  Category:
    | "forbidden"
    | "restricted"
    | "reciprocal"
    | "notice"
    | "permissive"
    | "unencumbered"
    | "unknown";
  PkgName: string;
  FilePath?: string;
  Name: string;
  Confidence: number;
  Link?: string;
}

export interface LicenseResult {
  Target: string;
  Class: "license";
  Licenses?: LicenseFinding[];
}

export interface TrivyLicenseScanResult {
  SchemaVersion?: number;
  CreatedAt?: string;
  ArtifactName?: string;
  ArtifactType?: string;
  Results?: LicenseResult[];
}

// Combined Image Scan Types
export interface TrivyCombinedImageScanResult {
  image: string;
  timestamp: string;
  vulnerabilities: TrivyScanResult | { error: string } | null;
  secrets: TrivySecretScanResult | { error: string } | null;
  licenses: TrivyLicenseScanResult | { error: string } | null;
  sbom: TrivySbomResult | { error: string } | null;
}

// Combined Path Scan Types
export interface TrivyCombinedPathScanResult {
  path: string;
  timestamp: string;
  vulnerabilities: TrivyScanResult | { error: string } | null;
  secrets: TrivySecretScanResult | { error: string } | null;
  licenses: TrivyLicenseScanResult | { error: string } | null;
  iac: TrivyIacScanResult | { error: string } | null;
  sbom: TrivySbomResult | { error: string } | null;
}

// =============================================================================
// SonarQube Types
// =============================================================================

export interface SonarProject {
  key: string;
  name: string;
  qualifier: string;
  visibility: string;
  lastAnalysisDate?: string;
}

export interface SonarProjectsResponse {
  paging: {
    pageIndex: number;
    pageSize: number;
    total: number;
  };
  components: SonarProject[];
}

export interface SonarIssue {
  key: string;
  rule: string;
  severity: "INFO" | "MINOR" | "MAJOR" | "CRITICAL" | "BLOCKER";
  component: string;
  project: string;
  line?: number;
  message: string;
  type: "CODE_SMELL" | "BUG" | "VULNERABILITY" | "SECURITY_HOTSPOT";
  status: string;
}

export interface SonarIssuesResponse {
  total: number;
  issues: SonarIssue[];
}

export interface SonarHotspot {
  key: string;
  component: string;
  project: string;
  securityCategory: string;
  vulnerabilityProbability: "HIGH" | "MEDIUM" | "LOW";
  status: string;
  line?: number;
  message: string;
}

export interface SonarHotspotsResponse {
  paging: {
    pageIndex: number;
    pageSize: number;
    total: number;
  };
  hotspots: SonarHotspot[];
}

export interface SonarMeasure {
  metric: string;
  value: string;
}

export interface SonarMetricsResponse {
  component: {
    key: string;
    name: string;
    measures: SonarMeasure[];
  };
}

// =============================================================================
// Dependency-Track Types
// =============================================================================

export interface DTrackProject {
  uuid: string;
  name: string;
  version?: string;
  lastBomImport?: string;
  metrics?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    unassigned: number;
    vulnerabilities: number;
  };
}

export interface DTrackVulnerability {
  uuid: string;
  vulnId: string;
  source: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNASSIGNED";
  title?: string;
  description?: string;
  cvssV3BaseScore?: number;
}

export interface DTrackFinding {
  component: {
    uuid: string;
    name: string;
    version: string;
  };
  vulnerability: DTrackVulnerability;
  analysis?: {
    state: string;
    suppressed: boolean;
  };
}

export interface DTrackComponent {
  uuid: string;
  name: string;
  version: string;
  group?: string;
  purl?: string;
  license?: string;
}

// =============================================================================
// Gitea Types
// =============================================================================

export interface GiteaUser {
  id: number;
  login: string;
  full_name?: string;
  email: string;
  avatar_url: string;
}

export interface GiteaRepository {
  id: number;
  owner: GiteaUser;
  name: string;
  full_name: string;
  description?: string;
  html_url: string;
  clone_url: string;
  default_branch: string;
  private: boolean;
  fork: boolean;
  stars_count: number;
  forks_count: number;
  created_at: string;
  updated_at: string;
}

export interface GiteaBranch {
  name: string;
  commit: {
    id: string;
    message: string;
    author: {
      name: string;
      email: string;
      date: string;
    };
  };
  protected: boolean;
}

export interface GiteaCommit {
  sha: string;
  commit: {
    message: string;
    author: {
      name: string;
      email: string;
      date: string;
    };
  };
  html_url: string;
}

// =============================================================================
// Drone CI Types
// =============================================================================

export interface DroneRepository {
  id: number;
  uid: string;
  namespace: string;
  name: string;
  slug: string;
  scm: string;
  git_http_url: string;
  link: string;
  default_branch: string;
  private: boolean;
  active: boolean;
  build_count?: number;
}

export interface DroneBuild {
  id: number;
  number: number;
  status: "pending" | "running" | "success" | "failure" | "killed" | "skipped";
  event: string;
  action?: string;
  message: string;
  before?: string;
  after: string;
  ref: string;
  source_repo?: string;
  source?: string;
  target: string;
  author_login: string;
  author_name: string;
  author_email: string;
  author_avatar: string;
  sender: string;
  started?: number;
  finished?: number;
  created: number;
  updated: number;
  stages?: DroneStage[];
}

export interface DroneStage {
  id: number;
  number: number;
  name: string;
  status: string;
  started?: number;
  stopped?: number;
  steps?: DroneStep[];
}

export interface DroneStep {
  id: number;
  number: number;
  name: string;
  status: string;
  exit_code?: number;
  started?: number;
  stopped?: number;
}

export interface DroneLogLine {
  pos: number;
  out: string;
  time: number;
}

// =============================================================================
// Docker Registry Types
// =============================================================================

export interface RegistryCatalog {
  repositories: string[];
}

export interface RegistryTags {
  name: string;
  tags: string[];
}

// =============================================================================
// Platform Status Types
// =============================================================================

export interface ServiceStatus {
  name: string;
  status: "up" | "down" | "unknown";
  url: string;
  responseTime?: number;
  error?: string;
}

export interface PlatformStatus {
  timestamp: string;
  services: ServiceStatus[];
  healthy: boolean;
}

// =============================================================================
// Security Scan Types
// =============================================================================

export interface SecurityScanResult {
  trivy?: TrivyScanResult;
  sonar?: {
    issues: SonarIssuesResponse;
    hotspots: SonarHotspotsResponse;
  };
  dtrack?: {
    findings: DTrackFinding[];
  };
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
}

// =============================================================================
// Security Dashboard Types
// =============================================================================

/**
 * Summary of vulnerability counts by severity level
 */
export interface SecurityDashboardSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

/**
 * SonarQube-specific metrics for the dashboard
 */
export interface SonarDashboardMetrics {
  bugs: number;
  vulnerabilities: number;
  codeSmells: number;
  hotspots: number;
  qualityGateStatus: string;
  error?: string;
}

/**
 * Individual finding from any security source
 */
export interface SecurityDashboardFinding {
  id: string;
  severity: SeverityLevel;
  source: SecuritySource;
  package?: string;
  message?: string;
}

/**
 * Unified security dashboard result aggregating all sources
 */
export interface SecurityDashboardResult {
  timestamp: string;
  summary: SecurityDashboardSummary;
  bySource: {
    trivy: SecurityDashboardSummary | { error: string };
    sonarqube: SonarDashboardMetrics;
    dependencyTrack: SecurityDashboardSummary | { error: string };
  };
  topFindings: SecurityDashboardFinding[];
  scanTargets: {
    image?: string;
    path?: string;
    sonarProject?: string;
    dtrackProject?: string;
  };
}

/**
 * Options for getSecurityDashboard function
 */
export interface SecurityDashboardOptions {
  image?: string;
  path?: string;
  sonarProject?: string;
  dtrackProjectUuid?: string;
  severity?: string;
}

// =============================================================================
// Configuration Types
// =============================================================================

export interface ServiceConfig {
  url: string;
}

export interface AuthenticatedServiceConfig extends ServiceConfig {
  user: string;
  password: string;
}

export interface TokenAuthServiceConfig extends ServiceConfig {
  token?: string;
}

export interface ApiKeyServiceConfig extends ServiceConfig {
  apiKey?: string;
}

export interface PlatformConfig {
  gitea: AuthenticatedServiceConfig;
  drone: TokenAuthServiceConfig;
  sonarqube: AuthenticatedServiceConfig;
  dependencyTrack: ApiKeyServiceConfig;
  trivy: ServiceConfig;
  registry: ServiceConfig;
}

// =============================================================================
// Error Types
// =============================================================================

export interface ApiError {
  error: string;
  message?: string;
  statusCode?: number;
  details?: unknown;
}

// =============================================================================
// Combined Scan Response
// =============================================================================

export interface CombinedScanResponse {
  timestamp: string;
  trivy: TrivyScanResult | ApiError | null;
  sonarqube: SonarIssuesResponse | ApiError | null;
  dependencyTrack: DTrackFinding[] | ApiError | null;
}

// =============================================================================
// Platform Health Response
// =============================================================================

export interface ServiceHealthStatus {
  status: "healthy" | "unhealthy" | "unreachable";
  statusCode?: number;
  error?: string;
}

export interface PlatformHealthResponse {
  timestamp: string;
  services: {
    gitea: ServiceHealthStatus;
    drone: ServiceHealthStatus;
    sonarqube: ServiceHealthStatus;
    dependencyTrack: ServiceHealthStatus;
    trivy: ServiceHealthStatus;
    registry: ServiceHealthStatus;
  };
}

// =============================================================================
// MCP Resource Types
// =============================================================================

export interface McpConfigResource {
  gitea: {
    url: string;
    user: string;
    hasPassword: boolean;
  };
  drone: {
    url: string;
    hasToken: boolean;
  };
  sonarqube: {
    url: string;
    user: string;
    hasPassword: boolean;
  };
  dependencyTrack: {
    url: string;
    hasApiKey: boolean;
  };
  trivy: {
    url: string;
  };
  registry: {
    url: string;
  };
}

// =============================================================================
// SARIF (Static Analysis Results Interchange Format) Types
// =============================================================================

/**
 * SARIF 2.1.0 compliant types for GitHub/GitLab integration
 * @see https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

export interface SarifMessage {
  text: string;
  markdown?: string;
}

export interface SarifArtifactLocation {
  uri: string;
  uriBaseId?: string;
}

export interface SarifRegion {
  startLine?: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
}

export interface SarifPhysicalLocation {
  artifactLocation: SarifArtifactLocation;
  region?: SarifRegion;
}

export interface SarifLocation {
  physicalLocation?: SarifPhysicalLocation;
  message?: SarifMessage;
}

export interface SarifReportingDescriptor {
  id: string;
  name?: string;
  shortDescription?: SarifMessage;
  fullDescription?: SarifMessage;
  helpUri?: string;
  help?: SarifMessage;
  defaultConfiguration?: {
    level?: SarifLevel;
  };
  properties?: Record<string, unknown>;
}

export interface SarifToolDriver {
  name: string;
  version?: string;
  informationUri?: string;
  rules?: SarifReportingDescriptor[];
}

export interface SarifTool {
  driver: SarifToolDriver;
}

export interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  level?: SarifLevel;
  message: SarifMessage;
  locations?: SarifLocation[];
  partialFingerprints?: {
    primaryLocationLineHash?: string;
    [key: string]: string | undefined;
  };
  properties?: Record<string, unknown>;
}

export interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
  invocations?: Array<{
    executionSuccessful: boolean;
    endTimeUtc?: string;
  }>;
  properties?: Record<string, unknown>;
}

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: SarifRun[];
}

/**
 * Options for converting scan results to SARIF format
 */
export interface SarifConversionOptions {
  /** Tool name to use in SARIF output */
  toolName?: string;
  /** Tool version */
  toolVersion?: string;
  /** Base path to strip from file paths */
  basePath?: string;
  /** Include only findings at or above this level */
  minLevel?: "none" | "note" | "warning" | "error";
}

// =============================================================================
// Webhook Types
// =============================================================================

/**
 * Supported webhook formats
 */
export type WebhookFormat = "slack" | "teams" | "generic";

/**
 * Severity threshold for webhook notifications
 */
export type WebhookSeverityThreshold = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/**
 * Configuration for a single webhook endpoint
 */
export interface WebhookEndpoint {
  /** Unique identifier for this webhook */
  id: string;
  /** Display name for the webhook */
  name: string;
  /** Webhook URL to POST to */
  url: string;
  /** Format of the webhook payload */
  format: WebhookFormat;
  /** Only notify if findings meet this severity threshold */
  severityThreshold?: WebhookSeverityThreshold;
  /** Custom headers to include in the request */
  headers?: Record<string, string>;
  /** Whether this webhook is enabled */
  enabled?: boolean;
}

/**
 * Configuration for all webhooks
 */
export interface WebhookConfig {
  /** List of webhook endpoints */
  endpoints: WebhookEndpoint[];
  /** Default severity threshold if not specified per endpoint */
  defaultSeverityThreshold?: WebhookSeverityThreshold;
  /** Number of retry attempts for failed deliveries */
  retryAttempts?: number;
  /** Delay between retries in milliseconds */
  retryDelayMs?: number;
}

/**
 * Summary of scan results for webhook notifications
 */
export interface WebhookScanSummary {
  /** Scan target (image name, path, project) */
  target: string;
  /** Type of scan performed */
  scanType: "image" | "path" | "combined" | "dashboard";
  /** Timestamp of the scan */
  timestamp: string;
  /** Vulnerability counts by severity */
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  /** Whether the scan passed policy checks */
  policyPassed?: boolean;
  /** Top findings to highlight */
  topFindings?: Array<{
    id: string;
    severity: string;
    title: string;
    package?: string;
  }>;
  /** Link to full scan results */
  detailsUrl?: string;
}

/**
 * Result of sending a webhook notification
 */
export interface WebhookDeliveryResult {
  /** Webhook endpoint ID */
  endpointId: string;
  /** Whether the delivery was successful */
  success: boolean;
  /** HTTP status code received */
  statusCode?: number;
  /** Error message if failed */
  error?: string;
  /** Number of attempts made */
  attempts: number;
  /** Timestamp of the delivery */
  timestamp: string;
}

/**
 * Slack message block types
 */
export interface SlackBlock {
  type: "section" | "header" | "divider" | "context" | "actions";
  text?: {
    type: "mrkdwn" | "plain_text";
    text: string;
    emoji?: boolean;
  };
  fields?: Array<{
    type: "mrkdwn" | "plain_text";
    text: string;
  }>;
  elements?: Array<{
    type: string;
    text?: { type: string; text: string; emoji?: boolean };
    url?: string;
    action_id?: string;
  }>;
}

/**
 * Slack webhook payload
 */
export interface SlackWebhookPayload {
  text?: string;
  blocks?: SlackBlock[];
  attachments?: Array<{
    color?: string;
    title?: string;
    text?: string;
    fields?: Array<{ title: string; value: string; short?: boolean }>;
  }>;
}

/**
 * Microsoft Teams Adaptive Card element
 */
export interface TeamsAdaptiveCardElement {
  type: "TextBlock" | "FactSet" | "Container" | "ColumnSet" | "ActionSet";
  text?: string;
  size?: "small" | "default" | "medium" | "large" | "extraLarge";
  weight?: "lighter" | "default" | "bolder";
  color?: "default" | "dark" | "light" | "accent" | "good" | "warning" | "attention";
  wrap?: boolean;
  facts?: Array<{ title: string; value: string }>;
  items?: TeamsAdaptiveCardElement[];
  columns?: Array<{ type: "Column"; width: string; items: TeamsAdaptiveCardElement[] }>;
  actions?: Array<{ type: string; title: string; url?: string }>;
}

/**
 * Microsoft Teams webhook payload (Adaptive Card)
 */
export interface TeamsWebhookPayload {
  type: "message";
  attachments: Array<{
    contentType: "application/vnd.microsoft.card.adaptive";
    content: {
      $schema: string;
      type: "AdaptiveCard";
      version: string;
      body: TeamsAdaptiveCardElement[];
      actions?: Array<{ type: string; title: string; url: string }>;
    };
  }>;
}

/**
 * Generic webhook payload
 */
export interface GenericWebhookPayload {
  event: "scan_completed";
  timestamp: string;
  target: string;
  scanType: string;
  summary: WebhookScanSummary["vulnerabilities"];
  policyPassed?: boolean;
  topFindings?: WebhookScanSummary["topFindings"];
  detailsUrl?: string;
}

// =============================================================================
// Policy File Types
// =============================================================================

/**
 * Result of loading a policy file
 */
export interface PolicyLoadResult {
  /** Whether the policy was loaded successfully */
  success: boolean;
  /** The loaded policy (if successful) */
  policy?: PolicyFileSchema;
  /** Error message (if failed) */
  error?: string;
  /** Path to the loaded policy file */
  filePath?: string;
  /** Source of the policy (file, default, merged) */
  source: "file" | "default" | "merged";
}

/**
 * Policy file schema - matches what users write in YAML/JSON
 */
export interface PolicyFileSchema {
  /** Policy name */
  name: string;
  /** Policy version (semver) */
  version: string;
  /** Policy description */
  description?: string;
  /** Base policy to extend (strict, standard, permissive) */
  extends?: string;
  /** Rule evaluation mode */
  mode?: "all" | "any";
  /** Policy rules */
  rules?: PolicyFileRule[];
  /** Global settings */
  settings?: PolicySettings;
}

/**
 * Policy rule as defined in file
 */
export interface PolicyFileRule {
  /** Rule name */
  name: string;
  /** Rule description */
  description?: string;
  /** Whether this rule is enabled */
  enabled?: boolean;
  /** Maximum vulnerabilities by severity */
  maxVulnerabilities?: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    unknown?: number;
  };
  /** CVEs to ignore */
  ignoreCves?: string[];
  /** Packages to ignore */
  ignorePackages?: string[];
  /** Blocked license patterns */
  blockedLicenses?: string[];
  /** Minimum code coverage percentage */
  minCodeCoverage?: number;
  /** Require quality gate to pass */
  requireQualityGatePass?: boolean;
  /** Block on secrets found */
  blockOnSecrets?: boolean;
}

/**
 * Global policy settings
 */
export interface PolicySettings {
  /** Fail open (continue on policy load error) */
  failOpen?: boolean;
  /** Report format for violations */
  reportFormat?: "text" | "json" | "sarif";
  /** Include warnings in output */
  includeWarnings?: boolean;
}

/**
 * Policy validation error
 */
export interface PolicyValidationError {
  /** Path to the invalid field */
  path: string;
  /** Error message */
  message: string;
  /** Suggested fix */
  suggestion?: string;
}

/**
 * Result of validating a policy file
 */
export interface PolicyValidationResult {
  /** Whether the policy is valid */
  valid: boolean;
  /** Validation errors */
  errors: PolicyValidationError[];
  /** Validation warnings */
  warnings: PolicyValidationError[];
}

// =============================================================================
// Parallel Scanning Types
// =============================================================================

/**
 * Type of scan target
 */
export type ScanTargetType = "image" | "path";

/**
 * A single scan target
 */
export interface ScanTarget {
  /** Target identifier (image name or path) */
  target: string;
  /** Type of target */
  type: ScanTargetType;
  /** Optional label for display */
  label?: string;
}

/**
 * Options for parallel scanning
 */
export interface ParallelScanOptions {
  /** Array of targets to scan */
  targets: ScanTarget[];
  /** Maximum concurrent scans (default: 3) */
  concurrency?: number;
  /** Stop on first failure (default: false) */
  failFast?: boolean;
  /** Severity filter for vulnerability scans */
  severity?: string;
  /** Progress callback */
  onProgress?: (progress: ScanProgress) => void;
  /** Per-target completion callback */
  onTargetComplete?: (result: TargetScanResult) => void;
}

/**
 * Progress information for parallel scanning
 */
export interface ScanProgress {
  /** Total number of targets */
  total: number;
  /** Number of completed scans */
  completed: number;
  /** Number of failed scans */
  failed: number;
  /** Number of currently running scans */
  running: number;
  /** Currently scanning targets */
  currentTargets: string[];
  /** Percentage complete (0-100) */
  percentage: number;
}

/**
 * Result of scanning a single target
 */
export interface TargetScanResult {
  /** The target that was scanned */
  target: ScanTarget;
  /** Whether the scan succeeded */
  success: boolean;
  /** Scan result data (if successful) */
  result?: TrivyScanResult;
  /** Error message (if failed) */
  error?: string;
  /** Scan duration in milliseconds */
  durationMs: number;
  /** Timestamp when scan started */
  startedAt: string;
  /** Timestamp when scan completed */
  completedAt: string;
}

/**
 * Vulnerability counts by severity
 */
export interface VulnerabilityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  total: number;
}

/**
 * Aggregated result from parallel scanning
 */
export interface ParallelScanResult {
  /** Timestamp when scanning started */
  startedAt: string;
  /** Timestamp when scanning completed */
  completedAt: string;
  /** Total duration in milliseconds */
  durationMs: number;
  /** Summary of all results */
  summary: {
    /** Total targets scanned */
    totalTargets: number;
    /** Number of successful scans */
    successfulScans: number;
    /** Number of failed scans */
    failedScans: number;
    /** Whether scanning was aborted (fail-fast) */
    aborted: boolean;
    /** Aggregated vulnerability counts */
    vulnerabilities: VulnerabilityCounts;
  };
  /** Individual results per target */
  results: TargetScanResult[];
  /** List of targets that failed */
  failedTargets: string[];
  /** Whether all policy checks passed */
  policyPassed?: boolean;
}

// =============================================================================
// Metrics Types
// =============================================================================

/**
 * Metric type enumeration
 */
export type MetricType = "counter" | "gauge" | "histogram";

/**
 * Labels for a metric
 */
export type MetricLabels = Record<string, string>;

/**
 * Base metric definition
 */
export interface MetricDefinition {
  /** Metric name (Prometheus format) */
  name: string;
  /** Human-readable description */
  help: string;
  /** Metric type */
  type: MetricType;
  /** Label names */
  labelNames?: readonly string[];
}

/**
 * Counter metric value
 */
export interface CounterValue {
  value: number;
  labels?: MetricLabels;
}

/**
 * Gauge metric value
 */
export interface GaugeValue {
  value: number;
  labels?: MetricLabels;
}

/**
 * Histogram bucket
 */
export interface HistogramBucket {
  le: number | "+Inf";
  count: number;
}

/**
 * Histogram metric value
 */
export interface HistogramValue {
  buckets: HistogramBucket[];
  sum: number;
  count: number;
  labels?: MetricLabels;
}

/**
 * Collected metric data
 */
export interface CollectedMetric {
  definition: MetricDefinition;
  values: Array<CounterValue | GaugeValue | HistogramValue>;
}

/**
 * All metrics snapshot
 */
export interface MetricsSnapshot {
  timestamp: string;
  metrics: CollectedMetric[];
}

/**
 * Scan metrics for a single scan
 */
export interface ScanMetrics {
  /** Scan target */
  target: string;
  /** Scan type (image/path) */
  type: "image" | "path";
  /** Duration in seconds */
  durationSeconds: number;
  /** Whether scan succeeded */
  success: boolean;
  /** Vulnerability counts by severity */
  vulnerabilities?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  /** Error message if failed */
  error?: string;
}

/**
 * Pushgateway configuration
 */
export interface PushgatewayConfig {
  /** Pushgateway URL */
  url: string;
  /** Job name */
  job: string;
  /** Instance label */
  instance?: string;
  /** Additional labels */
  labels?: MetricLabels;
  /** Basic auth username */
  username?: string;
  /** Basic auth password */
  password?: string;
}

/**
 * Pushgateway result
 */
export interface PushgatewayResult {
  success: boolean;
  statusCode?: number;
  error?: string;
}

// =============================================================================
// Scan Diff Types
// =============================================================================

/**
 * Unique identifier for a vulnerability finding
 */
export interface VulnerabilityFingerprint {
  /** CVE or vulnerability ID */
  id: string;
  /** Package name */
  package: string;
  /** Installed version */
  version: string;
  /** Target file or layer */
  target: string;
  /** Source of the finding */
  source: SecuritySource;
}

/**
 * A vulnerability with its fingerprint for comparison
 */
export interface FingerprintedVulnerability {
  fingerprint: string;
  id: string;
  package: string;
  version: string;
  severity: string;
  title?: string;
  fixedVersion?: string;
  target: string;
  source: SecuritySource;
}

/**
 * Status of a vulnerability in a diff
 */
export type VulnerabilityDiffStatus = "new" | "fixed" | "unchanged";

/**
 * A vulnerability in a diff result
 */
export interface DiffVulnerability extends FingerprintedVulnerability {
  status: VulnerabilityDiffStatus;
}

/**
 * Summary counts for a scan diff
 */
export interface ScanDiffSummary {
  /** Total vulnerabilities in current scan */
  currentTotal: number;
  /** Total vulnerabilities in baseline scan */
  baselineTotal: number;
  /** New vulnerabilities introduced */
  new: number;
  /** Vulnerabilities that were fixed */
  fixed: number;
  /** Vulnerabilities unchanged between scans */
  unchanged: number;
  /** Breakdown by severity */
  bySeverity: {
    critical: { new: number; fixed: number; unchanged: number };
    high: { new: number; fixed: number; unchanged: number };
    medium: { new: number; fixed: number; unchanged: number };
    low: { new: number; fixed: number; unchanged: number };
  };
}

/**
 * Result of comparing two scans
 */
export interface ScanDiffResult {
  /** Timestamp of the comparison */
  timestamp: string;
  /** Current scan identifier */
  current: {
    target: string;
    scannedAt: string;
    identifier?: string;
  };
  /** Baseline scan identifier */
  baseline: {
    target: string;
    scannedAt: string;
    identifier?: string;
  };
  /** Summary of changes */
  summary: ScanDiffSummary;
  /** New vulnerabilities (not in baseline) */
  newVulnerabilities: FingerprintedVulnerability[];
  /** Fixed vulnerabilities (in baseline but not current) */
  fixedVulnerabilities: FingerprintedVulnerability[];
  /** Unchanged vulnerabilities (in both) */
  unchangedVulnerabilities: FingerprintedVulnerability[];
}

/**
 * Stored scan record for history tracking
 */
export interface StoredScanRecord {
  /** Unique ID for this scan */
  id: string;
  /** Target that was scanned (image name or path) */
  target: string;
  /** When the scan was performed */
  scannedAt: string;
  /** Optional identifier (git commit, tag, etc.) */
  identifier?: string;
  /** Fingerprinted vulnerabilities for comparison */
  vulnerabilities: FingerprintedVulnerability[];
  /** Summary counts */
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
}

/**
 * Options for scan comparison
 */
export interface ScanCompareOptions {
  /** Include unchanged vulnerabilities in result */
  includeUnchanged?: boolean;
  /** Filter by minimum severity */
  minSeverity?: SeverityLevel;
}

/**
 * Options for scan history storage
 */
export interface ScanHistoryOptions {
  /** Maximum number of records to keep per target */
  maxRecordsPerTarget?: number;
  /** Storage backend */
  storage?: "memory" | "file";
  /** File path for file storage */
  filePath?: string;
}

// =============================================================================
// Suppression Types
// =============================================================================

/**
 * Type of suppression rule
 */
export type SuppressionType = "cve" | "package" | "path";

/**
 * A suppression rule for ignoring specific vulnerabilities
 */
export interface Suppression {
  /** Unique identifier for this suppression */
  id: string;
  /** Type of suppression */
  type: SuppressionType;
  /** Pattern to match (CVE ID, package name, or path glob) */
  pattern: string;
  /** Reason for suppression */
  reason: string;
  /** Optional expiration date (ISO 8601) */
  expires?: string;
  /** Optional package version constraint (for package type) */
  versionConstraint?: string;
  /** Who created this suppression */
  createdBy?: string;
  /** When this suppression was created */
  createdAt?: string;
  /** Optional notes or comments */
  notes?: string;
}

/**
 * Result of matching a suppression against a vulnerability
 */
export interface SuppressionMatch {
  /** The suppression that matched */
  suppression: Suppression;
  /** The vulnerability that was suppressed */
  vulnerabilityId: string;
  /** Package name if applicable */
  package?: string;
  /** File path if applicable */
  path?: string;
  /** Whether the suppression has expired */
  expired: boolean;
}

/**
 * A suppressed vulnerability with its suppression info
 */
export interface SuppressedVulnerability {
  /** Original vulnerability ID */
  id: string;
  /** Package name */
  package: string;
  /** Package version */
  version: string;
  /** Severity level */
  severity: string;
  /** Target/path */
  target: string;
  /** The suppression that matched */
  suppression: Suppression;
}

/**
 * Result of applying suppressions to scan results
 */
export interface SuppressionResult {
  /** Vulnerabilities that remain after suppression */
  remaining: TrivyVulnerability[];
  /** Vulnerabilities that were suppressed */
  suppressed: SuppressedVulnerability[];
  /** Summary of suppression actions */
  summary: {
    total: number;
    suppressed: number;
    remaining: number;
    expiredSuppressions: number;
  };
  /** Applied suppressions with match details */
  appliedSuppressions: SuppressionMatch[];
}

/**
 * Suppression file schema (YAML/JSON)
 */
export interface SuppressionFileSchema {
  /** Schema version */
  version?: string;
  /** List of suppressions */
  suppressions: Suppression[];
  /** Global settings */
  settings?: {
    /** Whether to fail on expired suppressions */
    failOnExpired?: boolean;
    /** Whether to require reasons */
    requireReasons?: boolean;
  };
}

/**
 * Options for loading suppressions
 */
export interface SuppressionLoadOptions {
  /** Validate suppression patterns */
  validatePatterns?: boolean;
  /** Skip expired suppressions */
  skipExpired?: boolean;
  /** Default creator if not specified */
  defaultCreatedBy?: string;
}

/**
 * Options for applying suppressions
 */
export interface SuppressionApplyOptions {
  /** Include expired suppressions (default: false) */
  includeExpired?: boolean;
  /** Audit suppression applications */
  audit?: boolean;
  /** Minimum severity to suppress (won't suppress above this) */
  maxSeverityToSuppress?: SeverityLevel;
}

// =============================================================================
// SBOM Upload Types
// =============================================================================

/**
 * Target type for SBOM generation
 */
export type SbomTargetType = "image" | "path";

/**
 * Options for uploading SBOM to Dependency-Track
 */
export interface SbomUploadOptions {
  /** Target to scan (image name or file path) */
  target: string;
  /** Type of target */
  targetType?: SbomTargetType;
  /** Project name in Dependency-Track (defaults to target name) */
  projectName?: string;
  /** Project version (defaults to 'latest' or git tag/commit) */
  projectVersion?: string;
  /** Auto-create project if it doesn't exist */
  autoCreateProject?: boolean;
  /** Tags to apply to the project */
  tags?: string[];
  /** Parent project UUID (for hierarchical projects) */
  parentUuid?: string;
  /** SBOM format */
  sbomFormat?: "cyclonedx" | "spdx-json";
  /** Wait for BOM processing to complete */
  waitForProcessing?: boolean;
  /** Timeout for waiting (ms) */
  processingTimeout?: number;
}

/**
 * Result of SBOM upload to Dependency-Track
 */
export interface SbomUploadResult {
  /** Whether the upload was successful */
  success: boolean;
  /** Project UUID in Dependency-Track */
  projectUuid: string;
  /** Project name */
  projectName: string;
  /** Project version */
  projectVersion: string;
  /** Number of components in the SBOM */
  componentsCount: number;
  /** BOM processing token */
  token: string;
  /** Whether the project was newly created */
  projectCreated: boolean;
  /** Timestamp of upload */
  uploadedAt: string;
  /** Error message if failed */
  error?: string;
}

/**
 * Options for creating a project in Dependency-Track
 */
export interface DTrackProjectCreateOptions {
  /** Project name */
  name: string;
  /** Project version */
  version?: string;
  /** Project description */
  description?: string;
  /** Tags */
  tags?: string[];
  /** Parent project UUID */
  parent?: string;
  /** Classifier (APPLICATION, LIBRARY, etc.) */
  classifier?: string;
}

/**
 * Result of project creation
 */
export interface DTrackProjectCreateResult {
  uuid: string;
  name: string;
  version: string;
  created: boolean;
}

// =============================================================================
// Registry Scanner Types
// =============================================================================

/**
 * Supported registry types
 */
export type RegistryType = "docker-registry" | "harbor" | "gitlab" | "ecr" | "acr" | "gcr" | "ghcr";

/**
 * Image discovered in registry
 */
export interface RegistryImage {
  /** Full image reference (registry/repo:tag) */
  fullName: string;
  /** Repository name */
  repository: string;
  /** Tag */
  tag: string;
  /** Image digest (if available) */
  digest?: string;
  /** Created/pushed date (if available) */
  createdAt?: string;
  /** Image size in bytes (if available) */
  size?: number;
}

/**
 * Options for scanning a container registry
 */
export interface RegistryScanOptions {
  /** Registry URL (e.g., registry.example.com, localhost:5000) */
  registry?: string;
  /** Filter repositories by pattern (glob or regex) */
  repositories?: string[];
  /** Filter tags by regex pattern */
  tagFilter?: string;
  /** Only scan images newer than this duration (e.g., "7d", "24h", "30d") */
  maxAge?: string;
  /** Maximum concurrent scans */
  concurrency?: number;
  /** Severity levels to report */
  severity?: string;
  /** Maximum number of images to scan (default: unlimited) */
  limit?: number;
  /** Skip scanning, just list images */
  listOnly?: boolean;
  /** Include all tags or just latest */
  allTags?: boolean;
  /** Fail fast on first scan error */
  failFast?: boolean;
  /** Progress callback */
  onProgress?: (progress: RegistryScanProgress) => void;
}

/**
 * Progress information for registry scan
 */
export interface RegistryScanProgress {
  /** Phase of scanning */
  phase: "discovering" | "scanning" | "complete";
  /** Total images discovered */
  imagesDiscovered: number;
  /** Images scanned so far */
  imagesScanned: number;
  /** Failed scans */
  failedScans: number;
  /** Currently scanning images */
  currentImages: string[];
  /** Percentage complete (scanning phase) */
  percentage: number;
}

/**
 * Result of registry batch scan
 */
export interface RegistryScanResult {
  /** Registry URL that was scanned */
  registry: string;
  /** When scan started */
  startedAt: string;
  /** When scan completed */
  completedAt: string;
  /** Total duration in milliseconds */
  durationMs: number;
  /** Summary of discovered images */
  discovery: {
    /** Total repositories found */
    repositoriesFound: number;
    /** Total images (repo:tag combinations) found */
    imagesFound: number;
    /** Images matching filters */
    imagesMatched: number;
    /** Images actually scanned */
    imagesScanned: number;
  };
  /** Aggregated vulnerability counts */
  vulnerabilities: VulnerabilityCounts;
  /** Per-image scan results */
  results: TargetScanResult[];
  /** Images that failed to scan */
  failedImages: string[];
  /** Images that were skipped (filtered out) */
  skippedImages: string[];
}

// =============================================================================
// Scan Scheduler Types
// =============================================================================

/**
 * Cron expression field representing allowed values
 */
export interface CronField {
  /** Raw expression string */
  expression: string;
  /** Computed values for this field */
  values: number[];
}

/**
 * Parsed cron expression
 */
export interface ParsedCronExpression {
  /** Minutes (0-59) */
  minute: CronField;
  /** Hours (0-23) */
  hour: CronField;
  /** Day of month (1-31) */
  dayOfMonth: CronField;
  /** Month (1-12) */
  month: CronField;
  /** Day of week (0-6, Sunday = 0) */
  dayOfWeek: CronField;
  /** Original expression string */
  original: string;
}

/**
 * Target for scheduled scanning
 */
export interface ScheduledScanTarget {
  /** Target identifier (image name, path, or registry URL) */
  target: string;
  /** Type of target */
  type: "image" | "path" | "registry";
  /** Optional label for display */
  label?: string;
}

/**
 * Options for scheduled scans
 */
export interface ScheduledScanOptions {
  /** Severity levels to report */
  severity?: string;
  /** Maximum concurrent scans (for registry scans) */
  concurrency?: number;
  /** Whether to fail fast on first error */
  failFast?: boolean;
  /** Generate SARIF report */
  generateSarif?: boolean;
  /** Upload to Dependency-Track */
  uploadToDtrack?: boolean;
}

/**
 * Webhook configuration for schedule notifications
 */
export interface ScheduleWebhookConfig {
  /** Webhook URL */
  url: string;
  /** Webhook format */
  format: "slack" | "teams" | "generic";
  /** Only notify on certain conditions */
  notifyOn?: ("success" | "failure" | "vulnerabilities")[];
  /** Minimum severity to trigger notification */
  minSeverity?: SeverityLevel;
}

/**
 * Scan schedule definition
 */
export interface ScanSchedule {
  /** Unique identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Cron expression (e.g., "0 0 * * *" for daily at midnight) */
  cron: string;
  /** Timezone for schedule (e.g., "America/New_York") */
  timezone?: string;
  /** Targets to scan */
  targets: ScheduledScanTarget[];
  /** Scan options */
  options?: ScheduledScanOptions;
  /** Webhook notifications */
  notifications?: ScheduleWebhookConfig[];
  /** Whether schedule is enabled */
  enabled: boolean;
  /** Timestamp of last run */
  lastRun?: string;
  /** Timestamp of next scheduled run */
  nextRun?: string;
  /** Created timestamp */
  createdAt: string;
  /** Updated timestamp */
  updatedAt: string;
}

/**
 * Input for creating a new schedule
 */
export interface CreateScheduleInput {
  /** Human-readable name */
  name: string;
  /** Cron expression */
  cron: string;
  /** Timezone (default: UTC) */
  timezone?: string;
  /** Targets to scan */
  targets: ScheduledScanTarget[];
  /** Scan options */
  options?: ScheduledScanOptions;
  /** Webhook notifications */
  notifications?: ScheduleWebhookConfig[];
  /** Whether schedule is enabled (default: true) */
  enabled?: boolean;
}

/**
 * Input for updating a schedule
 */
export interface UpdateScheduleInput {
  /** Human-readable name */
  name?: string;
  /** Cron expression */
  cron?: string;
  /** Timezone */
  timezone?: string;
  /** Targets to scan */
  targets?: ScheduledScanTarget[];
  /** Scan options */
  options?: ScheduledScanOptions;
  /** Webhook notifications */
  notifications?: ScheduleWebhookConfig[];
  /** Whether schedule is enabled */
  enabled?: boolean;
}

/**
 * Result of a scheduled scan execution
 */
export interface ScheduleExecutionResult {
  /** Schedule ID */
  scheduleId: string;
  /** Schedule name */
  scheduleName: string;
  /** Execution timestamp */
  executedAt: string;
  /** Duration in milliseconds */
  durationMs: number;
  /** Whether execution was successful */
  success: boolean;
  /** Targets scanned */
  targetsScanned: number;
  /** Targets that failed */
  targetsFailed: number;
  /** Aggregated vulnerability counts */
  vulnerabilities?: VulnerabilityCounts;
  /** Per-target results */
  results: TargetScanResult[];
  /** Error message if failed */
  error?: string;
  /** Webhook delivery results */
  webhookResults?: Array<{
    url: string;
    success: boolean;
    error?: string;
  }>;
}

/**
 * Schedule execution history entry
 */
export interface ScheduleHistoryEntry {
  /** Unique execution ID */
  executionId: string;
  /** Schedule ID */
  scheduleId: string;
  /** Execution timestamp */
  executedAt: string;
  /** Duration in milliseconds */
  durationMs: number;
  /** Whether execution was successful */
  success: boolean;
  /** Summary of results */
  summary: {
    targetsScanned: number;
    targetsFailed: number;
    vulnerabilities: VulnerabilityCounts;
  };
  /** Error message if failed */
  error?: string;
}

/**
 * Options for listing schedules
 */
export interface ListSchedulesOptions {
  /** Filter by enabled status */
  enabled?: boolean;
  /** Filter by target type */
  targetType?: "image" | "path" | "registry";
  /** Include execution history */
  includeHistory?: boolean;
  /** Maximum history entries to include */
  historyLimit?: number;
}

/**
 * Cron validation result
 */
export interface CronValidationResult {
  /** Whether the expression is valid */
  valid: boolean;
  /** Error message if invalid */
  error?: string;
  /** Parsed expression if valid */
  parsed?: ParsedCronExpression;
  /** Human-readable description of the schedule */
  description?: string;
  /** Next N run times */
  nextRuns?: string[];
}

// =============================================================================
// Multi-Registry Configuration Types
// =============================================================================

/**
 * Extended registry type with cloud providers
 */
export type CloudRegistryType =
  | "docker-registry"
  | "harbor"
  | "gitlab"
  | "ecr"
  | "acr"
  | "gcr"
  | "gar"
  | "ghcr";

/**
 * Docker/Harbor basic authentication
 */
export interface BasicRegistryAuth {
  type: "basic";
  username: string;
  password: string;
}

/**
 * AWS ECR authentication
 */
export interface EcrAuth {
  type: "ecr";
  /** AWS region (e.g., us-east-1) */
  region: string;
  /** AWS access key ID (optional, uses default credentials if not provided) */
  accessKeyId?: string;
  /** AWS secret access key */
  secretAccessKey?: string;
  /** AWS session token for temporary credentials */
  sessionToken?: string;
  /** Use IAM role authentication */
  useIamRole?: boolean;
}

/**
 * Azure ACR authentication
 */
export interface AcrAuth {
  type: "acr";
  /** Azure tenant ID */
  tenantId?: string;
  /** Azure client/application ID */
  clientId?: string;
  /** Azure client secret */
  clientSecret?: string;
  /** Use managed identity */
  useManagedIdentity?: boolean;
  /** ACR admin username (alternative auth) */
  username?: string;
  /** ACR admin password (alternative auth) */
  password?: string;
}

/**
 * Google GCR/Artifact Registry authentication
 */
export interface GcrAuth {
  type: "gcr";
  /** Service account JSON key (base64 or object) */
  serviceAccountKey?: string | object;
  /** Use default credentials (ADC) */
  useDefaultCredentials?: boolean;
  /** GCP project ID */
  projectId?: string;
}

/**
 * GitHub Container Registry authentication
 */
export interface GhcrAuth {
  type: "ghcr";
  /** GitHub personal access token or GITHUB_TOKEN */
  token: string;
  /** GitHub username (optional, derived from token if not provided) */
  username?: string;
}

/**
 * Anonymous authentication (for public registries)
 */
export interface AnonymousAuth {
  type: "anonymous";
}

/**
 * Union type for all registry authentication methods
 */
export type RegistryAuth =
  | BasicRegistryAuth
  | EcrAuth
  | AcrAuth
  | GcrAuth
  | GhcrAuth
  | AnonymousAuth;

/**
 * Registry configuration
 */
export interface RegistryConfig {
  /** Unique identifier for this registry config */
  id: string;
  /** Display name */
  name: string;
  /** Registry type */
  type: CloudRegistryType;
  /** Registry URL (e.g., registry.example.com, 123456789.dkr.ecr.us-east-1.amazonaws.com) */
  url: string;
  /** Authentication configuration */
  auth?: RegistryAuth;
  /** Whether this is the default registry */
  isDefault?: boolean;
  /** Whether the registry is enabled */
  enabled?: boolean;
  /** Description */
  description?: string;
  /** Additional registry-specific settings */
  settings?: Record<string, unknown>;
}

/**
 * Result of registry auto-detection
 */
export interface RegistryDetectionResult {
  /** Detected registry type */
  type: CloudRegistryType;
  /** Confidence level (0-1) */
  confidence: number;
  /** Extracted details */
  details?: {
    /** AWS region for ECR */
    region?: string;
    /** GCP project for GCR/GAR */
    project?: string;
    /** Azure registry name */
    registry?: string;
    /** GitHub organization for GHCR */
    org?: string;
  };
  /** Suggestions for authentication */
  authSuggestions?: string[];
}

/**
 * Registry authentication result
 */
export interface RegistryAuthResult {
  /** Whether authentication succeeded */
  success: boolean;
  /** Auth token (if applicable) */
  token?: string;
  /** Token expiration time */
  expiresAt?: string;
  /** Error message if failed */
  error?: string;
  /** Username for Docker login */
  username?: string;
  /** Password for Docker login */
  password?: string;
}

/**
 * Multi-registry scan options
 */
export interface MultiRegistryScanOptions {
  /** Registry IDs or URLs to scan */
  registries: string[];
  /** Filter repositories by pattern */
  repositories?: string[];
  /** Filter tags by regex */
  tagFilter?: string;
  /** Maximum concurrent scans per registry */
  concurrency?: number;
  /** Severity filter */
  severity?: string;
  /** Maximum images per registry */
  limitPerRegistry?: number;
  /** Only scan latest tags */
  latestOnly?: boolean;
  /** Continue on registry errors */
  continueOnError?: boolean;
}

/**
 * Result of multi-registry scan
 */
export interface MultiRegistryScanResult {
  /** When the scan started */
  startedAt: string;
  /** When the scan completed */
  completedAt: string;
  /** Total duration in milliseconds */
  durationMs: number;
  /** Results per registry */
  registries: Array<{
    /** Registry ID or URL */
    registry: string;
    /** Registry type */
    type: CloudRegistryType;
    /** Whether scan succeeded */
    success: boolean;
    /** Error if failed */
    error?: string;
    /** Scan result if succeeded */
    result?: RegistryScanResult;
  }>;
  /** Aggregated vulnerability counts */
  totalVulnerabilities: VulnerabilityCounts;
  /** Total images scanned across all registries */
  totalImagesScanned: number;
  /** Total failed scans across all registries */
  totalFailedScans: number;
}

// =============================================================================
// Vulnerability Remediation Types
// =============================================================================

/**
 * Package manager types supported for remediation
 */
export type PackageManager =
  | "npm"
  | "yarn"
  | "pnpm"
  | "pip"
  | "poetry"
  | "pipenv"
  | "go"
  | "maven"
  | "gradle"
  | "gem"
  | "cargo";

/**
 * Confidence level for remediation suggestions
 */
export type RemediationConfidence = "high" | "medium" | "low";

/**
 * Information about a vulnerability for remediation context
 */
export interface VulnerabilityInfo {
  /** CVE or vulnerability ID */
  id: string;
  /** Severity level */
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  /** Brief title */
  title?: string;
  /** URL for more information */
  url?: string;
}

/**
 * A single remediation suggestion
 */
export interface RemediationSuggestion {
  /** The vulnerability being fixed */
  vulnerability: VulnerabilityInfo;
  /** Affected package name */
  package: string;
  /** Current installed version */
  currentVersion: string;
  /** Version that fixes the vulnerability */
  fixedVersion: string;
  /** Command to apply the fix */
  command: string;
  /** Package manager type */
  packageManager: PackageManager;
  /** Whether this is a breaking change (major version bump) */
  breaking: boolean;
  /** All CVEs fixed by this update */
  cvesFixed: string[];
  /** Confidence level of the suggestion */
  confidence: RemediationConfidence;
  /** Additional notes or warnings */
  notes?: string;
}

/**
 * A complete remediation plan
 */
export interface RemediationPlan {
  /** Timestamp when plan was generated */
  generatedAt: string;
  /** Source of the scan (image name, path, etc.) */
  scanTarget: string;
  /** All remediation suggestions */
  suggestions: RemediationSuggestion[];
  /** Total unique CVEs that would be fixed */
  totalCvesFixed: number;
  /** Number of suggestions with breaking changes */
  breakingChanges: number;
  /** Ordered list of all commands to run */
  commands: string[];
  /** Summary by package manager */
  byPackageManager: Record<
    PackageManager,
    {
      count: number;
      commands: string[];
    }
  >;
  /** Summary by severity */
  bySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

/**
 * Options for generating remediation suggestions
 */
export interface RemediationOptions {
  /** Only include suggestions above this severity */
  minSeverity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  /** Include breaking changes */
  includeBreaking?: boolean;
  /** Maximum number of suggestions to return */
  limit?: number;
  /** Package managers to include (default: all) */
  packageManagers?: PackageManager[];
  /** Sort order for suggestions */
  sortBy?: "severity" | "cvesFixed" | "package";
}

/**
 * Options for applying remediation
 */
export interface ApplyRemediationOptions {
  /** Working directory */
  workDir?: string;
  /** Dry run - just show commands without executing */
  dryRun?: boolean;
  /** Skip breaking changes */
  skipBreaking?: boolean;
  /** Commit changes after applying */
  commit?: boolean;
  /** Commit message template */
  commitMessage?: string;
}

/**
 * Result of applying remediation
 */
export interface ApplyRemediationResult {
  /** Whether all remediations were applied successfully */
  success: boolean;
  /** Number of packages updated */
  packagesUpdated: number;
  /** Commands that were executed */
  commandsExecuted: string[];
  /** Commands that failed */
  commandsFailed: string[];
  /** Error messages for failed commands */
  errors: string[];
  /** Commit SHA if commit was created */
  commitSha?: string;
}

/**
 * Options for generating a PR with remediations
 */
export interface RemediationPROptions {
  /** Repository owner */
  owner: string;
  /** Repository name */
  repo: string;
  /** Base branch to create PR against */
  baseBranch?: string;
  /** New branch name for the PR */
  branchName?: string;
  /** PR title */
  title?: string;
  /** Additional PR body content */
  bodyExtra?: string;
  /** Labels to add to the PR */
  labels?: string[];
  /** Assignees for the PR */
  assignees?: string[];
  /** Whether to set auto-merge */
  autoMerge?: boolean;
}

/**
 * Result of creating a remediation PR
 */
export interface RemediationPRResult {
  /** Whether PR was created successfully */
  success: boolean;
  /** PR number */
  prNumber?: number;
  /** PR URL */
  prUrl?: string;
  /** Branch that was created */
  branchName?: string;
  /** Error message if failed */
  error?: string;
}

// =============================================================================
// Compliance Framework Types
// =============================================================================

/**
 * Supported compliance frameworks
 */
export type ComplianceFramework = "SOC2" | "HIPAA" | "PCI-DSS" | "CIS";

/**
 * Vulnerability types for compliance mapping
 */
export type ComplianceVulnerabilityType = "cve" | "secret" | "misconfig" | "license";

/**
 * Severity levels for compliance SLA mapping
 */
export type ComplianceSeverity = "critical" | "high" | "medium" | "low";

/**
 * A compliance control definition from a framework
 */
export interface ComplianceControl {
  /** Control identifier (e.g., "CC7.1", "164.308(a)(1)", "11.3.1.2") */
  id: string;
  /** Framework this control belongs to */
  framework: ComplianceFramework;
  /** Short name of the control */
  name: string;
  /** Full description of what the control requires */
  description: string;
  /** Category within the framework */
  category: string;
  /** Which severity levels this control applies to */
  severityMapping: {
    critical: boolean;
    high: boolean;
    medium: boolean;
    low: boolean;
  };
  /** Which vulnerability types trigger this control */
  vulnerabilityTypes: ComplianceVulnerabilityType[];
  /** Remediation SLA by severity level */
  remediationSLA: {
    critical: string;
    high: string;
    medium: string;
    low: string;
  };
}

/**
 * A compliance violation - a vulnerability mapped to a control
 */
export interface ComplianceViolation {
  /** The control that was violated */
  control: ComplianceControl;
  /** The vulnerability that caused the violation */
  vulnerability: {
    /** Vulnerability ID (e.g., CVE-2024-1234) */
    id: string;
    /** Severity level */
    severity: string;
    /** Type of vulnerability */
    type: ComplianceVulnerabilityType;
    /** Affected package name */
    package?: string;
    /** Description of the vulnerability */
    description?: string;
    /** Source of the finding */
    source?: "trivy" | "sonarqube" | "dtrack";
  };
  /** Current status of the violation */
  status: "open" | "remediated" | "accepted" | "in_progress";
  /** Due date for remediation based on SLA */
  dueDate: string;
  /** When the violation was first detected */
  detectedAt: string;
}

/**
 * Framework-specific compliance summary
 */
export interface ComplianceFrameworkSummary {
  /** Framework name */
  framework: ComplianceFramework;
  /** Total controls in scope */
  totalControls: number;
  /** Controls with no violations */
  passingControls: number;
  /** Controls with violations */
  failingControls: number;
  /** Compliance percentage */
  compliancePercentage: number;
  /** All violations for this framework */
  violations: ComplianceViolation[];
}

/**
 * Compliance report aggregating results from all frameworks
 */
export interface ComplianceReport {
  /** When the report was generated */
  generatedAt: string;
  /** Target that was scanned (image, path, project) */
  scanTarget: string;
  /** Frameworks included in the report */
  frameworks: ComplianceFramework[];
  /** Overall summary across all frameworks */
  summary: {
    totalControls: number;
    passingControls: number;
    failingControls: number;
    compliancePercentage: number;
  };
  /** Per-framework breakdown */
  byFramework: Partial<Record<ComplianceFramework, ComplianceFrameworkSummary>>;
  /** Violation counts by severity */
  bySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  /** Top violations sorted by severity */
  topViolations: ComplianceViolation[];
  /** Remediation recommendations */
  recommendations: string[];
}

/**
 * Options for generating a compliance report
 */
export interface ComplianceReportOptions {
  /** Frameworks to include (default: all) */
  frameworks?: ComplianceFramework[];
  /** Include remediated violations (default: false) */
  includeRemediated?: boolean;
  /** Output format */
  format?: "json" | "html";
  /** Report title */
  title?: string;
  /** Organization name for the report */
  organization?: string;
  /** Severity filter */
  severity?: string;
}

/**
 * A snapshot of compliance status for trend tracking
 */
export interface ComplianceTrendEntry {
  /** When this snapshot was taken */
  timestamp: string;
  /** Target that was scanned */
  target: string;
  /** Frameworks included */
  frameworks: ComplianceFramework[];
  /** Summary at this point in time */
  summary: {
    totalViolations: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    compliancePercentage: number;
  };
}

/**
 * Result of compliance trend analysis
 */
export interface ComplianceTrendResult {
  /** Target that was analyzed */
  target: string;
  /** Time period analyzed */
  period: {
    start: string;
    end: string;
  };
  /** All trend entries in the period */
  entries: ComplianceTrendEntry[];
  /** Overall trend direction */
  trend: "improving" | "declining" | "stable";
  /** Percentage change from first to last entry */
  changeFromFirst: number;
}

/**
 * Options for checking compliance status
 */
export interface ComplianceCheckOptions {
  /** Docker image to scan */
  image?: string;
  /** Local path to scan */
  path?: string;
  /** SonarQube project key */
  sonarProject?: string;
  /** Dependency-Track project UUID */
  dtrackProjectUuid?: string;
  /** Frameworks to check */
  frameworks?: ComplianceFramework[];
  /** Severity filter */
  severity?: string;
}

/**
 * Result of a compliance status check
 */
export interface ComplianceCheckResult {
  /** Overall pass/fail status */
  passed: boolean;
  /** Compliance percentage */
  compliancePercentage: number;
  /** Number of violations by severity */
  violations: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  /** Failing controls by framework */
  failingControls: Array<{
    framework: ComplianceFramework;
    controlId: string;
    controlName: string;
    violationCount: number;
  }>;
  /** Full report for details */
  report: ComplianceReport;
}

// =============================================================================
// OPA/Rego Policy Types
// =============================================================================

/**
 * A violation detected by OPA policy evaluation
 */
export interface OpaViolation {
  /** Type of violation (e.g., "vulnerability_threshold", "license_violation") */
  type: string;
  /** Severity of the violation */
  severity: "critical" | "high" | "medium" | "low";
  /** Unique code for this violation type */
  code: string;
  /** Human-readable message describing the violation */
  message: string;
  /** Resource that caused the violation (e.g., package name) */
  resource?: string;
  /** Rego package that produced this violation */
  package?: string;
  /** Suggested remediation action */
  remediation?: string;
}

/**
 * Result of evaluating an OPA policy
 */
export interface OpaEvaluationResult {
  /** Whether the policy allows the input (no critical violations) */
  allow: boolean;
  /** List of violations found during evaluation */
  violations: OpaViolation[];
  /** Metadata about the evaluation */
  metadata: {
    /** Name of the policy that was evaluated */
    policyName: string;
    /** Version of the policy */
    policyVersion: string;
    /** ISO timestamp when evaluation occurred */
    evaluatedAt: string;
    /** Hash of the input for caching/debugging */
    inputHash?: string;
  };
}

/**
 * Information about an available OPA policy
 */
export interface OpaPolicyInfo {
  /** Policy name (e.g., "vulnerability-threshold") */
  name: string;
  /** Policy version */
  version: string;
  /** Description of what the policy does */
  description?: string;
  /** Entry points available in the policy */
  entrypoints: string[];
  /** Number of rules in the policy */
  ruleCount: number;
  /** Where the policy came from */
  source: "builtin" | "file" | "inline";
}

/**
 * Vulnerability counts for OPA input
 */
export interface OpaVulnerabilityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown?: number;
  total: number;
}

/**
 * Input structure for OPA policy evaluation
 */
export interface OpaEvaluationInput {
  /** Scan results to evaluate */
  scan: {
    /** Vulnerability counts by severity */
    vulnerabilities: OpaVulnerabilityCounts;
    /** License identifiers found (e.g., ["MIT", "GPL-3.0"]) */
    licenses?: string[];
    /** Whether secrets were detected */
    secretsFound?: boolean;
    /** Code coverage percentage (0-100) */
    codeCoverage?: number;
    /** Whether quality gate passed */
    qualityGatePassed?: boolean;
  };
  /** Docker image name if scanning an image */
  image?: string;
  /** File path if scanning a directory */
  path?: string;
  /** Thresholds for policy evaluation */
  thresholds?: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    coverage?: number;
  };
  /** Additional metadata for policy evaluation */
  metadata?: Record<string, unknown>;
}

/**
 * Options for OPA policy evaluation
 */
export interface OpaPolicyOptions {
  /** Policy name (for builtin) or inline Rego code */
  policy: string;
  /** Policy entrypoint (default: "security/allow") */
  entrypoint?: string;
  /** External data to provide to the policy */
  data?: Record<string, unknown>;
  /** Fail on undefined result (default: false) */
  strict?: boolean;
}

/**
 * Options for compiling Rego to WASM
 */
export interface OpaCompileOptions {
  /** Policy entrypoint */
  entrypoint: string;
  /** Output path for the WASM file */
  outputPath?: string;
  /** Enable optimization */
  optimize?: boolean;
}

/**
 * Result of Rego to WASM compilation
 */
export interface OpaCompileResult {
  /** Whether compilation succeeded */
  success: boolean;
  /** Path to the generated WASM file */
  wasmPath?: string;
  /** Error message if compilation failed */
  error?: string;
}

/**
 * Result of Rego syntax validation
 */
export interface OpaValidationResult {
  /** Whether the Rego syntax is valid */
  valid: boolean;
  /** Syntax errors if invalid */
  errors?: string[];
}

// =============================================================================
// Vulnerability Database Types
// =============================================================================

/**
 * A vulnerability record stored in the local database
 */
export interface VulnDbRecord {
  /** Vulnerability ID (e.g., CVE-2024-1234) */
  id: string;
  /** Source of the vulnerability data */
  source: "nvd" | "ghsa" | "osv" | "trivy";
  /** Severity level */
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  /** CVSS v3 base score */
  cvssScore?: number;
  /** Brief title */
  title: string;
  /** Full description */
  description: string;
  /** Reference URLs */
  references: string[];
  /** When the vulnerability was published */
  publishedAt?: string;
  /** When the vulnerability was last modified */
  modifiedAt?: string;
}

/**
 * An affected package entry linked to a vulnerability
 */
export interface VulnDbAffectedPackage {
  /** Vulnerability ID this package is affected by */
  vulnId: string;
  /** Package ecosystem (npm, pypi, go, etc.) */
  ecosystem: string;
  /** Package name */
  packageName: string;
  /** First affected version */
  versionStart?: string;
  /** Last affected version */
  versionEnd?: string;
  /** Version that fixes the vulnerability */
  fixedVersion?: string;
}

/**
 * Sync status for a vulnerability data source
 */
export interface VulnDbSyncStatus {
  /** Source name */
  source: string;
  /** Last sync timestamp (ISO 8601) */
  lastSync: string | null;
  /** Number of records from this source */
  recordCount: number;
  /** Database version (if applicable) */
  dbVersion: string | null;
  /** Current sync status */
  status: "synced" | "syncing" | "error" | "never";
  /** Hours since last sync */
  ageHours?: number;
}

/**
 * Options for syncing vulnerability databases
 */
export interface VulnDbSyncOptions {
  /** Sources to sync */
  sources?: ("nvd" | "ghsa" | "osv" | "trivy")[];
  /** Force sync even if recently synced */
  force?: boolean;
  /** Skip sync if synced within this many hours */
  skipIfRecent?: number;
}

/**
 * Query parameters for searching vulnerabilities
 */
export interface VulnDbSearchQuery {
  /** Filter by package name (partial match) */
  packageName?: string;
  /** Filter by ecosystem */
  ecosystem?: string;
  /** Filter by severity levels */
  severity?: string[];
  /** Filter by CVE pattern (partial match) */
  cvePattern?: string;
  /** Maximum results to return */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
}

/**
 * Statistics about the vulnerability database
 */
export interface VulnDbStats {
  /** Total number of vulnerabilities */
  totalVulnerabilities: number;
  /** Count by severity level */
  bySeverity: Record<string, number>;
  /** Count by source */
  bySource: Record<string, number>;
  /** Last sync timestamp by source */
  lastSync: Record<string, string>;
  /** Database file size in bytes */
  dbSizeBytes: number;
}

/**
 * Options for offline scanning
 */
export interface OfflineScanOptions {
  /** Skip database update (always true for offline) */
  skipDbUpdate: true;
  /** Enable offline scan mode (always true for offline) */
  offlineScan: true;
  /** Severity filter */
  severity?: string;
  /** Ignore unfixed vulnerabilities */
  ignoreUnfixed?: boolean;
}

/**
 * User annotation on a vulnerability
 */
export interface VulnAnnotation {
  /** Vulnerability ID */
  vulnId: string;
  /** Status assigned by user */
  status: "acknowledged" | "false_positive" | "mitigated" | "active";
  /** User notes */
  notes?: string;
  /** When the annotation was last updated */
  updatedAt: string;
}

/**
 * Result of Trivy database sync
 */
export interface TrivyDbSyncResult {
  /** Whether sync succeeded */
  success: boolean;
  /** Database version after sync */
  dbVersion?: string;
  /** Number of vulnerabilities imported */
  vulnerabilitiesImported?: number;
  /** Error message if failed */
  error?: string;
  /** Sync duration in milliseconds */
  durationMs?: number;
}

/**
 * Status of the Trivy vulnerability database
 */
export interface TrivyDbStatus {
  /** Whether the database exists */
  exists: boolean;
  /** Database version */
  version?: string;
  /** Last update timestamp */
  lastUpdate?: string;
  /** Age in hours */
  ageHours?: number;
  /** Database file size in bytes */
  sizeBytes?: number;
  /** Whether the database is considered stale (>24h) */
  isStale: boolean;
}

/**
 * Configuration for the vulnerability database
 */
export interface VulnDbConfig {
  /** Custom database file path */
  dbPath?: string;
  /** Auto-initialize database on first use */
  autoInit?: boolean;
  /** Maximum database age before warning (hours) */
  maxAgeHours?: number;
  /** Enable automatic background sync */
  autoSync?: boolean;
  /** Sync interval in hours */
  syncIntervalHours?: number;
}

// =============================================================================
// SSO (Single Sign-On) Types
// =============================================================================

/** SSO provider types */
export type SsoProviderType = "saml" | "oidc";

/** SSO event types for audit logging */
export type SsoEventType =
  | "LOGIN"
  | "LOGOUT"
  | "TOKEN_REFRESH"
  | "TOKEN_VALIDATION"
  | "CONFIG_CHANGE"
  | "SESSION_EXPIRED";

/** SSO validation error codes */
export type SsoErrorCode =
  | "INVALID_TOKEN"
  | "EXPIRED"
  | "PROVIDER_NOT_FOUND"
  | "PROVIDER_DISABLED"
  | "INVALID_SIGNATURE"
  | "INVALID_AUDIENCE"
  | "INVALID_ISSUER";

/**
 * Attribute mapping for SSO providers
 */
export interface SsoAttributeMapping {
  /** Attribute name for email */
  email: string;
  /** Attribute name for display name */
  name: string;
  /** Attribute name for groups (optional) */
  groups?: string;
  /** Attribute name for user ID (optional, defaults to sub/nameId) */
  userId?: string;
}

/**
 * SAML 2.0 provider configuration
 */
export interface SamlProviderConfig {
  /** Unique provider ID */
  id: string;
  /** Display name */
  name: string;
  /** Whether provider is enabled */
  enabled: boolean;
  /** IdP metadata URL (auto-fetch) */
  idpMetadataUrl?: string;
  /** IdP metadata XML (manual) */
  idpMetadataXml?: string;
  /** IdP X.509 certificate (PEM format) */
  idpCertificate: string;
  /** IdP SSO URL */
  idpSsoUrl: string;
  /** IdP SLO URL (optional) */
  idpSloUrl?: string;
  /** Service Provider entity ID */
  spEntityId: string;
  /** Assertion Consumer Service URL */
  spAcsUrl: string;
  /** Single Logout URL (optional) */
  spSloUrl?: string;
  /** Attribute mapping */
  attributeMapping: SsoAttributeMapping;
  /** Want assertions signed */
  wantAssertionsSigned?: boolean;
  /** Want response signed */
  wantResponseSigned?: boolean;
  /** Created timestamp */
  createdAt: string;
  /** Updated timestamp */
  updatedAt: string;
}

/**
 * OIDC provider configuration
 */
export interface OidcProviderConfig {
  /** Unique provider ID */
  id: string;
  /** Display name */
  name: string;
  /** Whether provider is enabled */
  enabled: boolean;
  /** Token issuer */
  issuer: string;
  /** OIDC discovery URL (/.well-known/openid-configuration) */
  discoveryUrl?: string;
  /** OAuth client ID */
  clientId: string;
  /** OAuth client secret */
  clientSecret: string;
  /** Redirect URI for callbacks */
  redirectUri: string;
  /** OAuth scopes */
  scopes: string[];
  /** JWKS URI for token validation */
  jwksUri?: string;
  /** Attribute mapping */
  attributeMapping: SsoAttributeMapping;
  /** Token endpoint auth method */
  tokenEndpointAuthMethod?: "client_secret_basic" | "client_secret_post";
  /** Created timestamp */
  createdAt: string;
  /** Updated timestamp */
  updatedAt: string;
}

/**
 * Union type for SSO provider configurations
 */
export type SsoProviderConfigUnion =
  | { type: "saml"; config: SamlProviderConfig }
  | { type: "oidc"; config: OidcProviderConfig };

/**
 * SSO session data
 */
export interface SsoSession {
  /** Session ID */
  id: string;
  /** Provider ID that created this session */
  providerId: string;
  /** Provider type */
  providerType: SsoProviderType;
  /** User ID from IdP */
  userId: string;
  /** User email */
  email: string;
  /** User display name */
  name: string;
  /** User groups */
  groups: string[];
  /** Raw claims from token */
  claims: Record<string, unknown>;
  /** Access token (for OIDC) */
  accessToken?: string;
  /** Refresh token (for OIDC) */
  refreshToken?: string;
  /** Session expiration time */
  expiresAt: string;
  /** Session creation time */
  createdAt: string;
  /** Last activity time */
  lastActivityAt: string;
}

/**
 * Result of SSO token/assertion validation
 */
export interface SsoValidationResult {
  /** Whether validation succeeded */
  valid: boolean;
  /** Session created from valid token */
  session?: SsoSession;
  /** Error message */
  error?: string;
  /** Error code */
  errorCode?: SsoErrorCode;
}

/**
 * Result of SAML SP metadata generation
 */
export interface SsoMetadataResult {
  /** SP metadata XML */
  xml: string;
  /** Entity ID */
  entityId: string;
  /** ACS URL */
  acsUrl: string;
}

/**
 * SSO audit event
 */
export interface SsoAuditEvent {
  /** Event ID */
  id: string;
  /** Event type */
  eventType: SsoEventType;
  /** Provider ID */
  providerId?: string;
  /** Session ID */
  sessionId?: string;
  /** User ID */
  userId?: string;
  /** User email */
  email?: string;
  /** Event status */
  status: "SUCCESS" | "FAILURE";
  /** Error message if failed */
  errorMessage?: string;
  /** IP address */
  ipAddress?: string;
  /** User agent */
  userAgent?: string;
  /** Additional details */
  details?: Record<string, unknown>;
  /** Event timestamp */
  timestamp: string;
}

/**
 * SSO database initialization result
 */
export interface SsoDbInitResult {
  /** Whether initialization succeeded */
  success: boolean;
  /** Database path */
  path: string;
  /** Whether database was created (vs opened) */
  created: boolean;
  /** Error message if failed */
  error?: string;
}

/**
 * SSO provider list item (summary)
 */
export interface SsoProviderSummary {
  /** Provider ID */
  id: string;
  /** Provider type */
  type: SsoProviderType;
  /** Display name */
  name: string;
  /** Whether enabled */
  enabled: boolean;
  /** Issuer (OIDC) or IdP entity ID (SAML) */
  issuer: string;
  /** Created timestamp */
  createdAt: string;
}

// =============================================================================
// RBAC (Role-Based Access Control) Types
// =============================================================================

/** RBAC event types for audit logging */
export type RbacEventType =
  | "ROLE_CREATED"
  | "ROLE_UPDATED"
  | "ROLE_DELETED"
  | "PERMISSION_GRANTED"
  | "PERMISSION_REVOKED"
  | "ROLE_ASSIGNED"
  | "ROLE_UNASSIGNED"
  | "PERMISSION_CHECK";

/**
 * RBAC role definition
 */
export interface RbacRole {
  /** Unique role ID */
  id: string;
  /** Role name (unique) */
  name: string;
  /** Role description */
  description?: string;
  /** Whether this is a system role (cannot be deleted) */
  isSystem: boolean;
  /** Created timestamp */
  createdAt: string;
  /** Updated timestamp */
  updatedAt: string;
}

/**
 * RBAC permission definition
 */
export interface RbacPermission {
  /** Unique permission ID */
  id: string;
  /** Permission name in resource:action format (e.g., "scan:execute") */
  name: string;
  /** Permission description */
  description?: string;
  /** Resource this permission applies to */
  resource: string;
  /** Action this permission allows */
  action: string;
  /** Created timestamp */
  createdAt: string;
}

/**
 * User-role assignment
 */
export interface RbacUserRole {
  /** User ID */
  userId: string;
  /** Role ID */
  roleId: string;
  /** Role name (for convenience) */
  roleName: string;
  /** When the role was assigned */
  assignedAt: string;
  /** Who assigned the role */
  assignedBy?: string;
  /** Optional expiration */
  expiresAt?: string;
}

/**
 * Result of a permission check
 */
export interface RbacCheckResult {
  /** Whether the permission is allowed */
  allowed: boolean;
  /** The permission that was checked */
  permission: string;
  /** The role that granted the permission (if allowed) */
  matchedRole?: string;
  /** Reason for denial (if not allowed) */
  reason?: string;
}

/**
 * RBAC audit event
 */
export interface RbacAuditEvent {
  /** Event ID */
  id: string;
  /** Event type */
  eventType: RbacEventType;
  /** Who performed the action */
  actorId?: string;
  /** Target user (for role assignments) */
  targetUserId?: string;
  /** Role ID involved */
  roleId?: string;
  /** Permission ID involved */
  permissionId?: string;
  /** Event status */
  status: "SUCCESS" | "FAILURE";
  /** Additional details */
  details?: Record<string, unknown>;
  /** Event timestamp */
  timestamp: string;
}

/**
 * Role with its permissions
 */
export interface RbacRoleWithPermissions extends RbacRole {
  /** Permissions granted to this role */
  permissions: RbacPermission[];
}

/**
 * RBAC database initialization result
 */
export interface RbacDbInitResult {
  /** Whether initialization succeeded */
  success: boolean;
  /** Database path */
  path: string;
  /** Whether database was created (vs opened) */
  created: boolean;
  /** Error message if failed */
  error?: string;
}

// =============================================================================
// API Key Management Types
// =============================================================================

/**
 * Available API key scopes
 */
export type ApiKeyScope =
  | "scan:read"
  | "scan:write"
  | "policy:read"
  | "policy:write"
  | "suppression:read"
  | "suppression:write"
  | "report:read"
  | "report:write"
  | "admin:*";

/**
 * API key audit event types
 */
export type ApiKeyEventType =
  | "KEY_CREATED"
  | "KEY_ROTATED"
  | "KEY_REVOKED"
  | "KEY_USED"
  | "KEY_EXPIRED"
  | "KEY_RATE_LIMITED";

/**
 * API key status
 */
export type ApiKeyStatus = "active" | "revoked" | "expired";

/**
 * API key record (stored in database)
 */
export interface ApiKey {
  /** Unique key ID (UUID) */
  id: string;
  /** Human-readable name */
  name: string;
  /** Optional description */
  description?: string;
  /** Prefix for identification (first 8 chars, e.g., "ci-co_abc12345") */
  keyPrefix: string;
  /** bcrypt hash of the full key */
  keyHash: string;
  /** Granted scopes */
  scopes: ApiKeyScope[];
  /** Key status */
  status: ApiKeyStatus;
  /** Expiration timestamp (ISO 8601) */
  expiresAt?: string;
  /** Last used timestamp */
  lastUsedAt?: string;
  /** User who created the key */
  createdBy: string;
  /** Creation timestamp */
  createdAt: string;
  /** IP allowlist (optional) */
  ipAllowlist?: string[];
  /** Rate limit (requests per minute) */
  rateLimit: number;
  /** Current request count in rate window */
  requestCount?: number;
  /** Rate window start timestamp */
  rateWindowStart?: string;
}

/**
 * API key creation options
 */
export interface ApiKeyCreateOptions {
  /** Human-readable name for the key */
  name: string;
  /** Optional description */
  description?: string;
  /** Scopes to grant */
  scopes: ApiKeyScope[];
  /** Expiration in days (default: 90) */
  expiresInDays?: number;
  /** Custom expiration date */
  expiresAt?: string;
  /** User creating the key */
  createdBy: string;
  /** IP allowlist (optional) */
  ipAllowlist?: string[];
  /** Rate limit in requests per minute (default: 100) */
  rateLimit?: number;
}

/**
 * Result of creating an API key
 * Note: The full key is only shown once at creation time
 */
export interface ApiKeyCreateResult {
  /** The created key record (without full key) */
  key: ApiKey;
  /** The full API key - ONLY shown once at creation */
  fullKey: string;
}

/**
 * API key for display (masked)
 */
export interface ApiKeyDisplay {
  /** Key ID */
  id: string;
  /** Human-readable name */
  name: string;
  /** Description */
  description?: string;
  /** Key prefix for identification */
  keyPrefix: string;
  /** Granted scopes */
  scopes: ApiKeyScope[];
  /** Status */
  status: ApiKeyStatus;
  /** Expiration */
  expiresAt?: string;
  /** Last used */
  lastUsedAt?: string;
  /** Created by */
  createdBy: string;
  /** Created at */
  createdAt: string;
  /** Days until expiration (negative if expired) */
  daysUntilExpiration?: number;
}

/**
 * API key validation result
 */
export interface ApiKeyValidationResult {
  /** Whether the key is valid */
  valid: boolean;
  /** The key record if valid */
  key?: ApiKey;
  /** Reason for invalidity */
  reason?: string;
  /** Whether rate limited */
  rateLimited?: boolean;
}

/**
 * API key rotation result
 */
export interface ApiKeyRotateResult {
  /** The updated key record */
  key: ApiKey;
  /** The new full API key - ONLY shown once */
  newFullKey: string;
  /** Previous key prefix (for reference) */
  previousKeyPrefix: string;
}

/**
 * API key audit event
 */
export interface ApiKeyAuditEvent {
  /** Event ID */
  id: string;
  /** Event type */
  eventType: ApiKeyEventType;
  /** Key ID */
  keyId: string;
  /** Key name (for reference) */
  keyName: string;
  /** Actor who triggered the event */
  actorId?: string;
  /** Client IP address */
  clientIp?: string;
  /** Event status */
  status: "SUCCESS" | "FAILURE";
  /** Additional details */
  details?: Record<string, unknown>;
  /** Event timestamp */
  timestamp: string;
}

/**
 * API key list options
 */
export interface ApiKeyListOptions {
  /** Filter by status */
  status?: ApiKeyStatus;
  /** Filter by creator */
  createdBy?: string;
  /** Include expired keys */
  includeExpired?: boolean;
  /** Limit results */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
}

/**
 * API key database initialization result
 */
export interface ApiKeyDbInitResult {
  /** Whether initialization succeeded */
  success: boolean;
  /** Database path */
  path: string;
  /** Whether database was created (vs opened) */
  created: boolean;
  /** Error message if failed */
  error?: string;
}

// =============================================================================
// Team Management Types (Issue #26)
// =============================================================================

/**
 * Team member role within a team
 */
export type TeamMemberRole = "owner" | "admin" | "member" | "viewer";

/**
 * Team event types for audit logging
 */
export type TeamEventType =
  | "ORG_CREATED"
  | "ORG_UPDATED"
  | "ORG_DELETED"
  | "TEAM_CREATED"
  | "TEAM_UPDATED"
  | "TEAM_DELETED"
  | "MEMBER_ADDED"
  | "MEMBER_REMOVED"
  | "MEMBER_ROLE_CHANGED"
  | "TEAM_SETTING_CHANGED";

/**
 * Organization - top-level grouping for teams
 */
export interface Organization {
  /** Organization ID */
  id: string;
  /** Organization name (unique) */
  name: string;
  /** Display name */
  displayName?: string;
  /** Organization description */
  description?: string;
  /** Owner user ID */
  ownerId: string;
  /** Settings JSON */
  settings?: OrganizationSettings;
  /** Creation timestamp */
  createdAt: string;
  /** Last update timestamp */
  updatedAt: string;
}

/**
 * Organization settings
 */
export interface OrganizationSettings {
  /** Default team visibility */
  defaultTeamVisibility?: "public" | "private";
  /** Allow external members */
  allowExternalMembers?: boolean;
  /** Require 2FA for members */
  require2FA?: boolean;
  /** Maximum teams per organization */
  maxTeams?: number;
  /** Maximum members per team */
  maxMembersPerTeam?: number;
}

/**
 * Team - belongs to an organization
 */
export interface Team {
  /** Team ID */
  id: string;
  /** Organization ID this team belongs to */
  organizationId: string;
  /** Team name (unique within org) */
  name: string;
  /** Display name */
  displayName?: string;
  /** Team description */
  description?: string;
  /** Team visibility */
  visibility: "public" | "private";
  /** Settings JSON */
  settings?: TeamSettings;
  /** Creation timestamp */
  createdAt: string;
  /** Last update timestamp */
  updatedAt: string;
}

/**
 * Team settings
 */
export interface TeamSettings {
  /** Notification preferences */
  notifications?: {
    scanComplete?: boolean;
    vulnerabilityFound?: boolean;
    policyViolation?: boolean;
  };
  /** Default scan severity threshold */
  defaultSeverityThreshold?: SeverityLevel;
  /** Auto-assign new projects */
  autoAssignProjects?: boolean;
}

/**
 * Team membership - user belongs to team with role
 */
export interface TeamMember {
  /** User ID */
  userId: string;
  /** Team ID */
  teamId: string;
  /** Member role in the team */
  role: TeamMemberRole;
  /** When the member joined */
  joinedAt: string;
  /** Who added this member */
  addedBy?: string;
  /** Optional expiration for temporary membership */
  expiresAt?: string;
}

/**
 * Team with member count and other metadata
 */
export interface TeamWithStats extends Team {
  /** Number of members */
  memberCount: number;
  /** Organization name */
  organizationName?: string;
}

/**
 * Organization with team count
 */
export interface OrganizationWithStats extends Organization {
  /** Number of teams */
  teamCount: number;
  /** Total members across all teams */
  totalMembers: number;
}

/**
 * Team membership with user and team details
 */
export interface TeamMembershipDetails {
  /** User ID */
  userId: string;
  /** Team ID */
  teamId: string;
  /** Team name */
  teamName: string;
  /** Organization ID */
  organizationId: string;
  /** Organization name */
  organizationName: string;
  /** Member role */
  role: TeamMemberRole;
  /** When joined */
  joinedAt: string;
}

/**
 * Options for creating an organization
 */
export interface CreateOrganizationOptions {
  /** Organization name (unique) */
  name: string;
  /** Display name */
  displayName?: string;
  /** Description */
  description?: string;
  /** Owner user ID */
  ownerId: string;
  /** Initial settings */
  settings?: OrganizationSettings;
}

/**
 * Options for creating a team
 */
export interface CreateTeamOptions {
  /** Organization ID */
  organizationId: string;
  /** Team name (unique within org) */
  name: string;
  /** Display name */
  displayName?: string;
  /** Description */
  description?: string;
  /** Visibility (default: private) */
  visibility?: "public" | "private";
  /** Initial settings */
  settings?: TeamSettings;
  /** Actor creating the team */
  createdBy?: string;
}

/**
 * Options for adding a team member
 */
export interface AddTeamMemberOptions {
  /** Team ID */
  teamId: string;
  /** User ID to add */
  userId: string;
  /** Role (default: member) */
  role?: TeamMemberRole;
  /** Who is adding the member */
  addedBy?: string;
  /** Optional expiration */
  expiresAt?: string;
}

/**
 * Options for listing teams
 */
export interface ListTeamsOptions {
  /** Filter by organization */
  organizationId?: string;
  /** Filter by visibility */
  visibility?: "public" | "private";
  /** Filter by user membership */
  userId?: string;
  /** Search by team name */
  search?: string;
  /** Include member count */
  includeStats?: boolean;
  /** Limit results */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
}

/**
 * Options for listing team members
 */
export interface ListTeamMembersOptions {
  /** Filter by role */
  role?: TeamMemberRole;
  /** Include expired members */
  includeExpired?: boolean;
  /** Limit results */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
}

/**
 * Team audit event
 */
export interface TeamAuditEvent {
  /** Event ID */
  id: string;
  /** Event type */
  eventType: TeamEventType;
  /** Actor who triggered the event */
  actorId?: string;
  /** Target organization ID */
  organizationId?: string;
  /** Target team ID */
  teamId?: string;
  /** Target user ID */
  targetUserId?: string;
  /** Event status */
  status: "SUCCESS" | "FAILURE";
  /** Additional details */
  details?: Record<string, unknown>;
  /** Event timestamp */
  timestamp: string;
}

/**
 * Team database initialization result
 */
export interface TeamDbInitResult {
  /** Whether initialization succeeded */
  success: boolean;
  /** Database path */
  path: string;
  /** Whether database was created (vs opened) */
  created: boolean;
  /** Error message if failed */
  error?: string;
}

/**
 * Team statistics
 */
export interface TeamStats {
  /** Total organizations */
  totalOrganizations: number;
  /** Total teams */
  totalTeams: number;
  /** Total memberships */
  totalMemberships: number;
  /** Members by role */
  membersByRole: Record<TeamMemberRole, number>;
}

// =============================================================================
// Session Management Types (Issue #27)
// =============================================================================

/**
 * Session audit event types
 */
export type SessionEventType =
  | "SESSION_CREATED"
  | "SESSION_REFRESHED"
  | "SESSION_REVOKED"
  | "SESSION_EXPIRED"
  | "TOKEN_BLACKLISTED"
  | "CONCURRENT_LIMIT_EXCEEDED"
  | "SUSPICIOUS_ACTIVITY";

/**
 * Device information for session tracking
 */
export interface SessionDevice {
  /** User agent string */
  userAgent?: string;
  /** Browser name */
  browser?: string;
  /** Browser version */
  browserVersion?: string;
  /** Operating system */
  os?: string;
  /** Device type (desktop, mobile, tablet) */
  deviceType?: string;
  /** Device name if available */
  deviceName?: string;
}

/**
 * Session record
 */
export interface Session {
  /** Unique session ID */
  id: string;
  /** User ID who owns the session */
  userId: string;
  /** Hash of the refresh token */
  refreshTokenHash: string;
  /** JWT ID of current access token */
  accessTokenJti: string;
  /** Device information */
  device?: SessionDevice;
  /** IP address of the client */
  ipAddress?: string;
  /** Session creation time */
  createdAt: string;
  /** Last activity timestamp */
  lastActivity: string;
  /** Session expiration time */
  expiresAt: string;
  /** Whether session is active */
  isActive: boolean;
}

/**
 * JWT token claims
 */
export interface TokenClaims {
  /** Subject (user ID) */
  sub: string;
  /** User email */
  email?: string;
  /** User roles */
  roles?: string[];
  /** Team memberships */
  teams?: string[];
  /** Granted permissions */
  permissions?: string[];
  /** Session ID */
  sid: string;
  /** JWT ID for tracking */
  jti: string;
  /** Issued at timestamp */
  iat: number;
  /** Expiration timestamp */
  exp: number;
  /** Token type (access or refresh) */
  type: "access" | "refresh";
}

/**
 * Token pair (access + refresh)
 */
export interface TokenPair {
  /** Access token (short-lived) */
  accessToken: string;
  /** Refresh token (long-lived) */
  refreshToken: string;
  /** Access token expiration (ISO date) */
  accessExpiresAt: string;
  /** Refresh token expiration (ISO date) */
  refreshExpiresAt: string;
  /** Token type (always "Bearer") */
  tokenType: "Bearer";
}

/**
 * Options for creating a session
 */
export interface CreateSessionOptions {
  /** User ID */
  userId: string;
  /** User email (included in token claims) */
  email?: string;
  /** User roles (included in token claims) */
  roles?: string[];
  /** Team memberships (included in token claims) */
  teams?: string[];
  /** Permissions (included in token claims) */
  permissions?: string[];
  /** Device information */
  device?: SessionDevice;
  /** Client IP address */
  ipAddress?: string;
  /** Custom access token expiry (seconds) */
  accessExpirySeconds?: number;
  /** Custom refresh token expiry (seconds) */
  refreshExpirySeconds?: number;
}

/**
 * Result of session creation
 */
export interface CreateSessionResult {
  /** Created session */
  session: Session;
  /** Token pair */
  tokens: TokenPair;
}

/**
 * Result of token validation
 */
export interface TokenValidationResult {
  /** Whether token is valid */
  valid: boolean;
  /** Decoded claims if valid */
  claims?: TokenClaims;
  /** Session if valid */
  session?: Session;
  /** Error message if invalid */
  error?: string;
  /** Error code for programmatic handling */
  errorCode?:
    | "INVALID_TOKEN"
    | "TOKEN_EXPIRED"
    | "TOKEN_REVOKED"
    | "SESSION_INACTIVE"
    | "INVALID_TYPE"
    | "UNKNOWN_ERROR";
}

/**
 * Result of token refresh
 */
export interface RefreshTokenResult {
  /** Whether refresh succeeded */
  success: boolean;
  /** New token pair if successful */
  tokens?: TokenPair;
  /** Error message if failed */
  error?: string;
}

/**
 * Options for listing sessions
 */
export interface SessionListOptions {
  /** Filter by user ID */
  userId?: string;
  /** Include only active sessions */
  activeOnly?: boolean;
  /** Include expired sessions */
  includeExpired?: boolean;
  /** Limit results */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
}

/**
 * Session audit event
 */
export interface SessionAuditEvent {
  /** Event ID */
  id: string;
  /** Event type */
  eventType: SessionEventType;
  /** Session ID */
  sessionId?: string;
  /** User ID */
  userId?: string;
  /** IP address */
  ipAddress?: string;
  /** Event status */
  status: "SUCCESS" | "FAILURE";
  /** Additional details */
  details?: Record<string, unknown>;
  /** Event timestamp */
  timestamp: string;
}

/**
 * Session database initialization result
 */
export interface SessionDbInitResult {
  /** Whether initialization succeeded */
  success: boolean;
  /** Database file path */
  path: string;
  /** Whether database was created (vs opened) */
  created: boolean;
  /** Error message if failed */
  error?: string;
}

/**
 * Session statistics
 */
export interface SessionStats {
  /** Total sessions */
  totalSessions: number;
  /** Active sessions */
  activeSessions: number;
  /** Expired sessions */
  expiredSessions: number;
  /** Revoked sessions */
  revokedSessions: number;
  /** Blacklisted tokens */
  blacklistedTokens: number;
  /** Audit events count */
  auditEvents: number;
}

/**
 * Blacklisted token record
 */
export interface BlacklistedToken {
  /** JWT ID */
  jti: string;
  /** When blacklisted */
  blacklistedAt: string;
  /** Reason for blacklisting */
  reason: string;
  /** Token expiration (for cleanup) */
  expiresAt: string;
}

/**
 * Session configuration
 */
export interface SessionConfig {
  /** JWT secret key */
  jwtSecret: string;
  /** Access token expiry in seconds (default: 900 = 15 min) */
  accessExpirySeconds: number;
  /** Refresh token expiry in seconds (default: 604800 = 7 days) */
  refreshExpirySeconds: number;
  /** Maximum concurrent sessions per user (default: 5) */
  maxConcurrentSessions: number;
  /** Whether to rotate refresh tokens on use (default: true) */
  rotateRefreshTokens: boolean;
}

// =============================================================================
// Audit Trail Types
// =============================================================================

/**
 * Type of actor performing an audited action
 */
export type AuditActorType = "user" | "apikey" | "system";

/**
 * Audit action categories
 */
export type AuditActionCategory =
  | "authentication"
  | "authorization"
  | "scan"
  | "policy"
  | "suppression"
  | "admin"
  | "data";

/**
 * Specific audit actions
 */
export type AuditAction =
  // Authentication
  | "auth.login"
  | "auth.logout"
  | "auth.login_failed"
  | "auth.password_change"
  | "auth.mfa_enabled"
  | "auth.mfa_disabled"
  | "auth.token_refresh"
  | "auth.session_created"
  | "auth.session_revoked"
  // Authorization
  | "authz.permission_denied"
  | "authz.role_assigned"
  | "authz.role_removed"
  | "authz.apikey_used"
  | "authz.apikey_created"
  | "authz.apikey_revoked"
  // Scans
  | "scan.triggered"
  | "scan.completed"
  | "scan.failed"
  | "scan.config_changed"
  | "scan.scheduled"
  | "scan.cancelled"
  // Policies
  | "policy.created"
  | "policy.updated"
  | "policy.deleted"
  | "policy.evaluated"
  | "policy.violation"
  // Suppressions
  | "suppression.created"
  | "suppression.approved"
  | "suppression.rejected"
  | "suppression.expired"
  | "suppression.deleted"
  // Admin
  | "admin.user_created"
  | "admin.user_deleted"
  | "admin.user_updated"
  | "admin.settings_changed"
  | "admin.role_created"
  | "admin.role_deleted"
  | "admin.team_created"
  | "admin.team_deleted"
  // Data
  | "data.export"
  | "data.download"
  | "data.share"
  | "data.delete";

/**
 * Type of resource being acted upon
 */
export type AuditResourceType =
  | "user"
  | "session"
  | "apikey"
  | "role"
  | "permission"
  | "team"
  | "organization"
  | "image"
  | "path"
  | "scan"
  | "policy"
  | "suppression"
  | "report"
  | "config"
  | "schedule";

/**
 * Outcome of an audited action
 */
export type AuditOutcome = "success" | "failure";

/**
 * Actor information for audit entry
 */
export interface AuditActor {
  /** Type of actor */
  type: AuditActorType;
  /** Actor ID (user ID, API key ID, or "system") */
  id: string;
  /** Actor email (for users) */
  email?: string;
  /** Actor display name */
  name?: string;
}

/**
 * Resource information for audit entry
 */
export interface AuditResource {
  /** Type of resource */
  type: AuditResourceType;
  /** Resource identifier */
  id: string;
  /** Resource display name */
  name?: string;
}

/**
 * Context information for audit entry
 */
export interface AuditContext {
  /** IP address of the request */
  ipAddress?: string;
  /** User agent string */
  userAgent?: string;
  /** Session ID if applicable */
  sessionId?: string;
  /** Request ID for tracing */
  requestId?: string;
  /** Additional context data */
  [key: string]: unknown;
}

/**
 * Audit event/entry
 */
export interface AuditEvent {
  /** Unique event ID */
  id: string;
  /** Event timestamp */
  timestamp: string;
  /** Actor who performed the action */
  actor: AuditActor;
  /** Action performed */
  action: AuditAction;
  /** Resource acted upon */
  resource: AuditResource;
  /** Request context */
  context: AuditContext;
  /** Action outcome */
  outcome: AuditOutcome;
  /** Additional details */
  details?: Record<string, unknown>;
  /** Checksum for tamper detection */
  checksum?: string;
}

/**
 * Options for creating an audit event
 */
export interface CreateAuditEventOptions {
  /** Actor who performed the action */
  actor: AuditActor;
  /** Action performed */
  action: AuditAction;
  /** Resource acted upon */
  resource: AuditResource;
  /** Action outcome */
  outcome: AuditOutcome;
  /** Request context */
  context?: AuditContext;
  /** Additional details */
  details?: Record<string, unknown>;
}

/**
 * Search filters for audit events
 */
export interface AuditSearchOptions {
  /** Filter by actor ID */
  actorId?: string;
  /** Filter by actor type */
  actorType?: AuditActorType;
  /** Filter by action */
  action?: AuditAction;
  /** Filter by action category */
  actionCategory?: AuditActionCategory;
  /** Filter by resource type */
  resourceType?: AuditResourceType;
  /** Filter by resource ID */
  resourceId?: string;
  /** Filter by outcome */
  outcome?: AuditOutcome;
  /** Filter by start time */
  startTime?: string;
  /** Filter by end time */
  endTime?: string;
  /** Full-text search query */
  query?: string;
  /** Maximum results to return */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
  /** Sort order */
  sortOrder?: "asc" | "desc";
}

/**
 * Export format for audit logs
 */
export type AuditExportFormat = "json" | "csv" | "ndjson";

/**
 * Options for exporting audit logs
 */
export interface AuditExportOptions {
  /** Search filters to apply */
  filters?: AuditSearchOptions;
  /** Export format */
  format?: AuditExportFormat;
  /** Include checksum column */
  includeChecksum?: boolean;
  /** Output file path (optional) */
  outputPath?: string;
}

/**
 * Result of audit export
 */
export interface AuditExportResult {
  /** Whether export succeeded */
  success: boolean;
  /** Number of events exported */
  count: number;
  /** Export format used */
  format: AuditExportFormat;
  /** Output file path if written */
  path?: string;
  /** Export data if not written to file */
  data?: string;
  /** Error message if failed */
  error?: string;
}

/**
 * SIEM integration configuration
 */
export interface AuditSiemConfig {
  /** SIEM endpoint URL */
  endpoint: string;
  /** Authentication token/key */
  authToken?: string;
  /** Custom headers */
  headers?: Record<string, string>;
  /** Batch size for sending */
  batchSize?: number;
  /** Retry attempts on failure */
  retryAttempts?: number;
  /** Whether SIEM integration is enabled */
  enabled: boolean;
}

/**
 * Audit trail configuration
 */
export interface AuditConfig {
  /** Retention period in days (default: 90) */
  retentionDays: number;
  /** Enable tamper-proof checksums */
  tamperProof: boolean;
  /** SIEM integration config */
  siem?: AuditSiemConfig;
  /** Enable real-time streaming */
  realTimeStreaming: boolean;
}

/**
 * Audit database initialization result
 */
export interface AuditDbInitResult {
  /** Whether initialization succeeded */
  success: boolean;
  /** Database file path */
  path: string;
  /** Whether database was created (vs opened) */
  created: boolean;
  /** Error message if failed */
  error?: string;
}

/**
 * Audit statistics
 */
export interface AuditStats {
  /** Total events */
  totalEvents: number;
  /** Events by outcome */
  byOutcome: {
    success: number;
    failure: number;
  };
  /** Events by action category */
  byCategory: Record<AuditActionCategory, number>;
  /** Events by actor type */
  byActorType: Record<AuditActorType, number>;
  /** Events in last 24 hours */
  last24Hours: number;
  /** Events in last 7 days */
  last7Days: number;
  /** Events in last 30 days */
  last30Days: number;
  /** Oldest event timestamp */
  oldestEvent?: string;
  /** Newest event timestamp */
  newestEvent?: string;
  /** Tamper detection status */
  tamperDetected: boolean;
  /** Number of tampered records (if any) */
  tamperedCount: number;
}

/**
 * Aggregation options for audit analytics
 */
export interface AuditAggregateOptions {
  /** Group by field */
  groupBy: "action" | "actorId" | "actorType" | "resourceType" | "outcome" | "hour" | "day";
  /** Time range start */
  startTime?: string;
  /** Time range end */
  endTime?: string;
  /** Additional filters */
  filters?: AuditSearchOptions;
}

/**
 * Aggregation result
 */
export interface AuditAggregateResult {
  /** Grouping key */
  key: string;
  /** Count of events */
  count: number;
  /** First event timestamp in group */
  firstEvent?: string;
  /** Last event timestamp in group */
  lastEvent?: string;
}

// =============================================================================
// Executive Dashboard Types
// =============================================================================

/**
 * Asset criticality levels for business context
 */
export type AssetCriticality = "critical" | "high" | "medium" | "low";

/**
 * Trend direction indicator
 */
export type TrendDirection = "up" | "down" | "stable";

/**
 * Dashboard time range options
 */
export type DashboardTimeRange = "24h" | "7d" | "30d" | "90d";

/**
 * Vulnerability counts by severity
 */
export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown?: number;
}

/**
 * Trend data with direction indicator
 */
export interface TrendData {
  /** Current count */
  current: number;
  /** Previous period count */
  previous: number;
  /** Change amount (current - previous) */
  change: number;
  /** Change percentage */
  changePercent: number;
  /** Trend direction */
  direction: TrendDirection;
}

/**
 * Compliance status for a framework
 */
export interface ComplianceStatusSummary {
  /** Framework name */
  framework: string;
  /** Total controls */
  totalControls: number;
  /** Passing controls */
  passingControls: number;
  /** Failing controls */
  failingControls: number;
  /** Compliance percentage (0-100) */
  compliancePercent: number;
  /** Status indicator */
  status: "compliant" | "non-compliant" | "partial";
}

/**
 * Project/image risk summary
 */
export interface RiskSummary {
  /** Target identifier (project name or image) */
  target: string;
  /** Target type */
  targetType: "project" | "image" | "repository";
  /** Risk score (0-100, higher = more risk) */
  riskScore: number;
  /** Vulnerability counts by severity */
  vulnerabilities: SeverityCounts;
  /** Total vulnerability count */
  totalVulnerabilities: number;
  /** Asset criticality */
  criticality: AssetCriticality;
  /** Last scan timestamp */
  lastScan?: string;
  /** Days since last scan */
  daysSinceLastScan?: number;
}

/**
 * Health score breakdown components
 */
export interface HealthScoreComponents {
  /** Vulnerability score (0-100, higher = better) */
  vulnerabilityScore: number;
  /** Compliance score (0-100, higher = better) */
  complianceScore: number;
  /** Coverage score (0-100, higher = better) */
  coverageScore: number;
  /** Remediation velocity score (0-100, higher = better) */
  remediationScore: number;
}

/**
 * Overall security health score
 */
export interface HealthScore {
  /** Overall score (0-100, higher = better) */
  score: number;
  /** Score grade (A-F) */
  grade: "A" | "B" | "C" | "D" | "F";
  /** Score components breakdown */
  components: HealthScoreComponents;
  /** Trend compared to previous period */
  trend: TrendData;
  /** Timestamp of calculation */
  calculatedAt: string;
}

/**
 * Mean Time to Remediation metrics
 */
export interface MTTRMetrics {
  /** Overall MTTR in days */
  overall: number;
  /** MTTR by severity in days */
  bySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  /** Trend compared to previous period */
  trend: TrendData;
}

/**
 * Scan coverage metrics
 */
export interface ScanCoverage {
  /** Total known assets */
  totalAssets: number;
  /** Assets scanned in period */
  scannedAssets: number;
  /** Coverage percentage */
  coveragePercent: number;
  /** Assets never scanned */
  neverScanned: number;
  /** Assets with stale scans (>7 days) */
  staleScans: number;
}

/**
 * Executive dashboard summary
 */
export interface DashboardSummary {
  /** Overall health score */
  healthScore: HealthScore;
  /** Vulnerability counts with trends */
  vulnerabilities: {
    counts: SeverityCounts;
    total: number;
    trend: TrendData;
  };
  /** Compliance status by framework */
  compliance: ComplianceStatusSummary[];
  /** Overall compliance percentage */
  overallCompliance: number;
  /** Top risks */
  topRisks: RiskSummary[];
  /** MTTR metrics */
  mttr: MTTRMetrics;
  /** Scan coverage */
  coverage: ScanCoverage;
  /** Dashboard generation timestamp */
  generatedAt: string;
  /** Time range used */
  timeRange: DashboardTimeRange;
}

/**
 * Dashboard configuration
 */
export interface DashboardConfig {
  /** Default time range */
  defaultTimeRange: DashboardTimeRange;
  /** Number of top risks to show */
  topRisksCount: number;
  /** Health score weights */
  weights: {
    vulnerability: number;
    compliance: number;
    coverage: number;
    remediation: number;
  };
  /** Cache TTL in seconds */
  cacheTtlSeconds: number;
  /** Stale scan threshold in days */
  staleScanDays: number;
}

/**
 * Dashboard snapshot for history
 */
export interface DashboardSnapshot {
  /** Snapshot ID */
  id: string;
  /** Timestamp */
  timestamp: string;
  /** Health score at time of snapshot */
  healthScore: number;
  /** Vulnerability counts at time of snapshot */
  vulnerabilities: SeverityCounts;
  /** Compliance percentage at time of snapshot */
  compliancePercent: number;
}

/**
 * Asset criticality configuration
 */
export interface AssetCriticalityConfig {
  /** Asset identifier (project/image name) */
  asset: string;
  /** Asset type */
  assetType: "project" | "image" | "repository";
  /** Criticality level */
  criticality: AssetCriticality;
  /** Optional notes */
  notes?: string;
  /** Who set this criticality */
  setBy?: string;
  /** When criticality was set */
  setAt: string;
}

/**
 * Dashboard database initialization result
 */
export interface DashboardDbInitResult {
  /** Whether initialization was successful */
  success: boolean;
  /** Database path */
  path: string;
  /** Timestamp */
  created: string;
  /** Error message if failed */
  error?: string;
}

// =============================================================================
// Report Templates Types
// =============================================================================

/**
 * Report output format
 */
export type ReportFormat = "html" | "markdown" | "json";

/**
 * Report schedule frequency
 */
export type ReportScheduleFrequency = "once" | "daily" | "weekly" | "monthly";

/**
 * Built-in template names
 */
export type BuiltinTemplateName =
  | "executive-summary"
  | "technical-detail"
  | "compliance-audit"
  | "trend-analysis"
  | "vulnerability-list";

/**
 * Report section types
 */
export type ReportSectionType =
  | "health-score"
  | "vulnerability-summary"
  | "vulnerability-list"
  | "compliance-status"
  | "top-risks"
  | "trend-chart"
  | "mttr-metrics"
  | "scan-coverage"
  | "remediation-status"
  | "custom-text"
  | "custom-table";

/**
 * Report section configuration
 */
export interface ReportSection {
  /** Section type */
  type: ReportSectionType;
  /** Section title (optional, uses default if not provided) */
  title?: string;
  /** Whether to include this section */
  enabled: boolean;
  /** Section-specific options */
  options?: {
    /** Limit number of items (for lists) */
    limit?: number;
    /** Severity filter */
    severities?: SeverityLevel[];
    /** Time range for trends */
    timeRange?: DashboardTimeRange;
    /** Custom content for custom-text section */
    content?: string;
    /** Column configuration for custom-table */
    columns?: string[];
    /** Data source for custom-table */
    dataSource?: string;
  };
}

/**
 * Report branding configuration
 */
export interface ReportBranding {
  /** Company/organization name */
  companyName?: string;
  /** Logo URL or base64 data */
  logo?: string;
  /** Primary color (hex) */
  primaryColor?: string;
  /** Secondary color (hex) */
  secondaryColor?: string;
  /** Custom CSS for HTML reports */
  customCss?: string;
}

/**
 * Report filter configuration
 */
export interface ReportFilters {
  /** Time range */
  timeRange?: DashboardTimeRange;
  /** Severity levels to include */
  severities?: SeverityLevel[];
  /** Specific projects/images to include */
  targets?: string[];
  /** Compliance frameworks to include */
  frameworks?: ComplianceFramework[];
  /** Only show items with status */
  status?: "open" | "fixed" | "all";
}

/**
 * Report template definition
 */
export interface ReportTemplate {
  /** Unique template ID */
  id: string;
  /** Template name */
  name: string;
  /** Template description */
  description: string;
  /** Whether this is a built-in template */
  isBuiltin: boolean;
  /** Output format */
  format: ReportFormat;
  /** Sections to include */
  sections: ReportSection[];
  /** Default filters */
  defaultFilters?: ReportFilters;
  /** Branding configuration */
  branding?: ReportBranding;
  /** Header template (Handlebars) */
  headerTemplate?: string;
  /** Footer template (Handlebars) */
  footerTemplate?: string;
  /** Created timestamp */
  createdAt: string;
  /** Updated timestamp */
  updatedAt: string;
  /** Created by user ID */
  createdBy?: string;
}

/**
 * Report generation options
 */
export interface ReportGenerateOptions {
  /** Template ID to use */
  templateId: string;
  /** Override filters */
  filters?: ReportFilters;
  /** Override branding */
  branding?: ReportBranding;
  /** Report title override */
  title?: string;
  /** Include table of contents */
  includeToc?: boolean;
  /** Include generation timestamp */
  includeTimestamp?: boolean;
}

/**
 * Generated report
 */
export interface GeneratedReport {
  /** Report ID */
  id: string;
  /** Template used */
  templateId: string;
  /** Template name */
  templateName: string;
  /** Report title */
  title: string;
  /** Output format */
  format: ReportFormat;
  /** Report content */
  content: string;
  /** Generation timestamp */
  generatedAt: string;
  /** Filters applied */
  filters: ReportFilters;
  /** Generation duration in ms */
  durationMs: number;
  /** Summary statistics */
  summary: {
    totalVulnerabilities: number;
    criticalCount: number;
    highCount: number;
    healthScore?: number;
    compliancePercent?: number;
  };
}

/**
 * Webhook configuration for report delivery
 */
export interface ReportWebhook {
  /** Webhook URL */
  url: string;
  /** HTTP method */
  method?: "POST" | "PUT";
  /** Custom headers */
  headers?: Record<string, string>;
  /** Include report content in payload */
  includeContent?: boolean;
}

/**
 * Report schedule configuration
 */
export interface ReportSchedule {
  /** Schedule ID */
  id: string;
  /** Schedule name */
  name: string;
  /** Template to use */
  templateId: string;
  /** Schedule frequency */
  frequency: ReportScheduleFrequency;
  /** Cron expression (for custom schedules) */
  cronExpression?: string;
  /** Day of week for weekly (0-6, Sunday = 0) */
  dayOfWeek?: number;
  /** Day of month for monthly (1-31) */
  dayOfMonth?: number;
  /** Hour to run (0-23) */
  hour: number;
  /** Minute to run (0-59) */
  minute: number;
  /** Timezone */
  timezone?: string;
  /** Filters to apply */
  filters?: ReportFilters;
  /** Email recipients */
  emailRecipients?: string[];
  /** Webhook for delivery */
  webhook?: ReportWebhook;
  /** Whether schedule is enabled */
  enabled: boolean;
  /** Created timestamp */
  createdAt: string;
  /** Updated timestamp */
  updatedAt: string;
  /** Last run timestamp */
  lastRunAt?: string;
  /** Next run timestamp */
  nextRunAt?: string;
  /** Last run status */
  lastRunStatus?: "success" | "failed";
  /** Last run error */
  lastRunError?: string;
}

/**
 * Report history entry
 */
export interface ReportHistoryEntry {
  /** Report ID */
  id: string;
  /** Schedule ID (if scheduled) */
  scheduleId?: string;
  /** Template ID */
  templateId: string;
  /** Report title */
  title: string;
  /** Output format */
  format: ReportFormat;
  /** Generation timestamp */
  generatedAt: string;
  /** Duration in ms */
  durationMs: number;
  /** Status */
  status: "success" | "failed";
  /** Error message if failed */
  error?: string;
  /** File path (if saved) */
  filePath?: string;
  /** Summary statistics */
  summary?: {
    totalVulnerabilities: number;
    criticalCount: number;
    highCount: number;
  };
}

/**
 * Report template creation options
 */
export interface CreateTemplateOptions {
  /** Template name */
  name: string;
  /** Template description */
  description?: string;
  /** Output format */
  format?: ReportFormat;
  /** Sections to include */
  sections: ReportSection[];
  /** Default filters */
  defaultFilters?: ReportFilters;
  /** Branding configuration */
  branding?: ReportBranding;
  /** Header template */
  headerTemplate?: string;
  /** Footer template */
  footerTemplate?: string;
  /** Created by user ID */
  createdBy?: string;
}

/**
 * Report schedule creation options
 */
export interface CreateScheduleOptions {
  /** Schedule name */
  name: string;
  /** Template ID */
  templateId: string;
  /** Frequency */
  frequency: ReportScheduleFrequency;
  /** Cron expression (optional) */
  cronExpression?: string;
  /** Day of week (0-6) */
  dayOfWeek?: number;
  /** Day of month (1-31) */
  dayOfMonth?: number;
  /** Hour (0-23) */
  hour?: number;
  /** Minute (0-59) */
  minute?: number;
  /** Timezone */
  timezone?: string;
  /** Filters */
  filters?: ReportFilters;
  /** Email recipients */
  emailRecipients?: string[];
  /** Webhook */
  webhook?: ReportWebhook;
  /** Whether enabled */
  enabled?: boolean;
}

/**
 * Report templates database initialization result
 */
export interface ReportDbInitResult {
  /** Whether initialization was successful */
  success: boolean;
  /** Database path */
  path: string;
  /** Timestamp */
  created: string;
  /** Number of built-in templates */
  builtinTemplates: number;
  /** Error message if failed */
  error?: string;
}

// =============================================================================
// Trend Analysis Types
// =============================================================================

/**
 * Time granularity for trend data
 */
export type TrendGranularity = "daily" | "weekly" | "monthly";

/**
 * Trend data point
 */
export interface TrendDataPoint {
  /** Date of the data point (ISO string) */
  date: string;
  /** Total vulnerability count */
  total: number;
  /** Critical severity count */
  critical: number;
  /** High severity count */
  high: number;
  /** Medium severity count */
  medium: number;
  /** Low severity count */
  low: number;
  /** Unknown severity count */
  unknown: number;
  /** New vulnerabilities introduced */
  newCount: number;
  /** Fixed vulnerabilities */
  fixedCount: number;
  /** Net change (new - fixed) */
  netChange: number;
}

/**
 * Vulnerability history result
 */
export interface VulnerabilityHistory {
  /** Target identifier (image or project) */
  target: string;
  /** Target type */
  targetType: "image" | "project" | "organization";
  /** Start date of the history */
  startDate: string;
  /** End date of the history */
  endDate: string;
  /** Granularity of the data */
  granularity: TrendGranularity;
  /** Data points */
  dataPoints: TrendDataPoint[];
  /** Summary statistics */
  summary: {
    /** Average total vulnerabilities */
    avgTotal: number;
    /** Peak total vulnerabilities */
    peakTotal: number;
    /** Minimum total vulnerabilities */
    minTotal: number;
    /** Total new vulnerabilities in period */
    totalNew: number;
    /** Total fixed vulnerabilities in period */
    totalFixed: number;
    /** Net change over period */
    netChange: number;
    /** Trend direction */
    trend: "improving" | "stable" | "worsening";
  };
  /** Moving averages */
  movingAverages?: {
    /** 7-day moving average (for daily data) */
    ma7?: number[];
    /** 30-day moving average (for daily data) */
    ma30?: number[];
  };
}

/**
 * Forecast prediction
 */
export interface TrendForecast {
  /** Target identifier */
  target: string;
  /** Target type */
  targetType: "image" | "project" | "organization";
  /** Date forecast was generated */
  generatedAt: string;
  /** Forecast horizon in days */
  horizonDays: number;
  /** Predicted data points */
  predictions: TrendForecastPoint[];
  /** Model information */
  model: {
    /** Type of model used */
    type: "linear_regression" | "moving_average" | "exponential_smoothing";
    /** R-squared value (goodness of fit) */
    rSquared: number;
    /** Slope of trend line (vulnerabilities per day) */
    slope: number;
    /** Y-intercept */
    intercept: number;
    /** Confidence level (0-1) */
    confidence: number;
  };
  /** Key predictions */
  insights: {
    /** Estimated days to reach zero critical vulnerabilities */
    daysToZeroCritical: number | null;
    /** Estimated days to reach zero high vulnerabilities */
    daysToZeroHigh: number | null;
    /** Predicted total in 7 days */
    totalIn7Days: number;
    /** Predicted total in 30 days */
    totalIn30Days: number;
    /** Risk trend assessment */
    riskTrend: "decreasing" | "stable" | "increasing";
  };
}

/**
 * Forecast data point
 */
export interface TrendForecastPoint {
  /** Date of prediction */
  date: string;
  /** Predicted total vulnerabilities */
  predictedTotal: number;
  /** Lower bound (confidence interval) */
  lowerBound: number;
  /** Upper bound (confidence interval) */
  upperBound: number;
  /** Predicted critical count */
  predictedCritical: number;
  /** Predicted high count */
  predictedHigh: number;
}

/**
 * Anomaly detection result
 */
export interface TrendAnomaly {
  /** Date of anomaly */
  date: string;
  /** Type of anomaly */
  type: "spike" | "drop" | "unusual_pattern";
  /** Severity of the anomaly */
  severity: "low" | "medium" | "high";
  /** Metric that triggered the anomaly */
  metric: "total" | "critical" | "high" | "new" | "fixed";
  /** Actual value */
  actualValue: number;
  /** Expected value (based on historical data) */
  expectedValue: number;
  /** Z-score (standard deviations from mean) */
  zScore: number;
  /** Percentage deviation from expected */
  deviationPercent: number;
  /** Human-readable description */
  description: string;
}

/**
 * Anomaly detection result set
 */
export interface AnomalyDetectionResult {
  /** Target identifier */
  target: string;
  /** Target type */
  targetType: "image" | "project" | "organization";
  /** Analysis period start */
  startDate: string;
  /** Analysis period end */
  endDate: string;
  /** Detected anomalies */
  anomalies: TrendAnomaly[];
  /** Detection parameters */
  parameters: {
    /** Z-score threshold used */
    zScoreThreshold: number;
    /** Minimum deviation percentage to flag */
    minDeviationPercent: number;
  };
  /** Summary */
  summary: {
    /** Total anomalies detected */
    totalAnomalies: number;
    /** High severity anomalies */
    highSeverity: number;
    /** Spikes detected */
    spikes: number;
    /** Drops detected */
    drops: number;
  };
}

/**
 * Period comparison result
 */
export interface PeriodComparison {
  /** Target identifier */
  target: string;
  /** Target type */
  targetType: "image" | "project" | "organization";
  /** First period */
  period1: {
    /** Start date */
    startDate: string;
    /** End date */
    endDate: string;
    /** Label for the period */
    label: string;
  };
  /** Second period */
  period2: {
    /** Start date */
    startDate: string;
    /** End date */
    endDate: string;
    /** Label for the period */
    label: string;
  };
  /** Comparison metrics */
  comparison: {
    /** Total vulnerabilities comparison */
    total: MetricComparison;
    /** Critical vulnerabilities comparison */
    critical: MetricComparison;
    /** High vulnerabilities comparison */
    high: MetricComparison;
    /** Medium vulnerabilities comparison */
    medium: MetricComparison;
    /** Low vulnerabilities comparison */
    low: MetricComparison;
    /** New vulnerabilities rate comparison */
    newRate: MetricComparison;
    /** Fix rate comparison */
    fixRate: MetricComparison;
  };
  /** Overall assessment */
  assessment: {
    /** Overall change direction */
    direction: "improved" | "unchanged" | "worsened";
    /** Confidence in assessment */
    confidence: "low" | "medium" | "high";
    /** Key observations */
    observations: string[];
  };
}

/**
 * Metric comparison between periods
 */
export interface MetricComparison {
  /** Value in period 1 */
  period1Value: number;
  /** Value in period 2 */
  period2Value: number;
  /** Absolute change */
  absoluteChange: number;
  /** Percentage change */
  percentChange: number;
  /** Direction of change */
  direction: "increased" | "unchanged" | "decreased";
}

/**
 * Trend snapshot stored in database
 */
export interface TrendSnapshot {
  /** Unique identifier */
  id: string;
  /** Target identifier */
  target: string;
  /** Target type */
  targetType: "image" | "project" | "organization";
  /** Snapshot date */
  date: string;
  /** Total vulnerabilities */
  total: number;
  /** Critical count */
  critical: number;
  /** High count */
  high: number;
  /** Medium count */
  medium: number;
  /** Low count */
  low: number;
  /** Unknown count */
  unknown: number;
  /** New vulnerabilities since last snapshot */
  newCount: number;
  /** Fixed vulnerabilities since last snapshot */
  fixedCount: number;
  /** Created timestamp */
  createdAt: string;
}

/**
 * Options for getting vulnerability history
 */
export interface GetHistoryOptions {
  /** Target identifier */
  target: string;
  /** Target type */
  targetType?: "image" | "project" | "organization";
  /** Start date (ISO string or relative like "30d", "90d") */
  startDate?: string;
  /** End date (ISO string) */
  endDate?: string;
  /** Granularity of data points */
  granularity?: TrendGranularity;
  /** Include moving averages */
  includeMovingAverages?: boolean;
}

/**
 * Options for getting forecast
 */
export interface GetForecastOptions {
  /** Target identifier */
  target: string;
  /** Target type */
  targetType?: "image" | "project" | "organization";
  /** Number of days to forecast */
  horizonDays?: number;
  /** Confidence level (0-1) */
  confidenceLevel?: number;
  /** Historical data range to use for model */
  historicalDays?: number;
}

/**
 * Options for detecting anomalies
 */
export interface DetectAnomaliesOptions {
  /** Target identifier */
  target: string;
  /** Target type */
  targetType?: "image" | "project" | "organization";
  /** Start date */
  startDate?: string;
  /** End date */
  endDate?: string;
  /** Z-score threshold for anomaly detection (default: 2.0) */
  zScoreThreshold?: number;
  /** Minimum deviation percentage to flag (default: 20) */
  minDeviationPercent?: number;
}

/**
 * Options for comparing periods
 */
export interface ComparePeriodOptions {
  /** Target identifier */
  target: string;
  /** Target type */
  targetType?: "image" | "project" | "organization";
  /** Period 1 start date */
  period1Start: string;
  /** Period 1 end date */
  period1End: string;
  /** Period 1 label */
  period1Label?: string;
  /** Period 2 start date */
  period2Start: string;
  /** Period 2 end date */
  period2End: string;
  /** Period 2 label */
  period2Label?: string;
}

/**
 * Options for recording a trend snapshot
 */
export interface RecordSnapshotOptions {
  /** Target identifier */
  target: string;
  /** Target type */
  targetType?: "image" | "project" | "organization";
  /** Snapshot date (defaults to now) */
  date?: string;
  /** Vulnerability counts */
  counts: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown?: number;
  };
  /** New vulnerabilities since last snapshot */
  newCount?: number;
  /** Fixed vulnerabilities since last snapshot */
  fixedCount?: number;
}

/**
 * Trend analysis database initialization result
 */
export interface TrendDbInitResult {
  /** Whether initialization was successful */
  success: boolean;
  /** Database path */
  path: string;
  /** Timestamp */
  created: string;
  /** Error message if failed */
  error?: string;
}

// =============================================================================
// Risk Scoring Types
// =============================================================================

/**
 * Asset criticality level for business context
 */
export type RiskAssetCriticality = "critical" | "high" | "medium" | "low" | "minimal";

/**
 * Exposure level of an asset
 */
export type RiskExposureLevel = "internet-facing" | "internal-only" | "air-gapped" | "development";

/**
 * Risk score tier based on calculated risk
 */
export type RiskTier = "critical" | "high" | "medium" | "low" | "minimal";

/**
 * Configuration for asset criticality
 */
export interface RiskAssetConfig {
  /** Asset identifier (image name, project name, etc.) */
  asset: string;
  /** Asset type */
  assetType: "image" | "project" | "repository" | "service";
  /** Business criticality level */
  criticality: RiskAssetCriticality;
  /** Exposure level */
  exposure: RiskExposureLevel;
  /** Business context/description */
  businessContext?: string;
  /** Owner/team responsible */
  owner?: string;
  /** Associated compliance frameworks */
  complianceFrameworks?: string[];
  /** Custom risk multiplier (default: 1.0) */
  customMultiplier?: number;
  /** When the config was created */
  createdAt?: string;
  /** When the config was last updated */
  updatedAt?: string;
}

/**
 * CVSS vector components for risk calculation
 */
export interface CvssComponents {
  /** Base CVSS score (0-10) */
  baseScore: number;
  /** Attack vector */
  attackVector?: "network" | "adjacent" | "local" | "physical";
  /** Attack complexity */
  attackComplexity?: "low" | "high";
  /** Privileges required */
  privilegesRequired?: "none" | "low" | "high";
  /** User interaction required */
  userInteraction?: "none" | "required";
  /** Scope change */
  scope?: "unchanged" | "changed";
  /** Confidentiality impact */
  confidentialityImpact?: "none" | "low" | "high";
  /** Integrity impact */
  integrityImpact?: "none" | "low" | "high";
  /** Availability impact */
  availabilityImpact?: "none" | "low" | "high";
}

/**
 * Exploitability factors for temporal scoring
 */
export interface ExploitabilityFactors {
  /** Known exploit in the wild */
  exploitInWild: boolean;
  /** Proof of concept available */
  pocAvailable: boolean;
  /** Weaponized exploit available */
  weaponized: boolean;
  /** Active exploitation reported */
  activelyExploited: boolean;
  /** CISA KEV listed */
  cisaKev: boolean;
  /** EPSS score (0-1) if available */
  epssScore?: number;
}

/**
 * Risk score calculation result for a single vulnerability
 */
export interface RiskScore {
  /** Vulnerability ID (CVE) */
  vulnId: string;
  /** Base CVSS score */
  baseCvss: number;
  /** Exploitability multiplier (1.0-2.0) */
  exploitabilityMultiplier: number;
  /** Asset criticality multiplier (0.5-2.0) */
  assetCriticalityMultiplier: number;
  /** Exposure multiplier (0.5-2.0) */
  exposureMultiplier: number;
  /** Age factor (1.0-1.5, older = higher) */
  ageFactor: number;
  /** Final calculated risk score (0-100) */
  riskScore: number;
  /** Risk tier based on score */
  riskTier: RiskTier;
  /** Priority rank (1 = highest priority) */
  priorityRank?: number;
  /** Recommendation for remediation */
  recommendation?: string;
  /** Days since vulnerability was first detected */
  ageInDays?: number;
}

/**
 * Options for calculating risk score
 */
export interface CalculateRiskOptions {
  /** Vulnerability ID (CVE) */
  vulnId: string;
  /** CVSS components */
  cvss: CvssComponents;
  /** Asset configuration (or asset name to look up) */
  asset: string | RiskAssetConfig;
  /** Exploitability factors */
  exploitability?: ExploitabilityFactors;
  /** First detected date (for age calculation) */
  firstDetected?: string;
  /** Custom weights for scoring components */
  weights?: RiskWeights;
}

/**
 * Custom weights for risk score calculation
 */
export interface RiskWeights {
  /** Weight for exploitability (default: 1.0) */
  exploitability?: number;
  /** Weight for asset criticality (default: 1.0) */
  assetCriticality?: number;
  /** Weight for exposure (default: 1.0) */
  exposure?: number;
  /** Weight for age factor (default: 1.0) */
  age?: number;
}

/**
 * Prioritized vulnerability list entry
 */
export interface PrioritizedVulnerability {
  /** Vulnerability ID */
  vulnId: string;
  /** Package name */
  packageName?: string;
  /** Installed version */
  installedVersion?: string;
  /** Fixed version */
  fixedVersion?: string;
  /** Asset identifier */
  asset: string;
  /** Risk score details */
  riskScore: RiskScore;
  /** Title/description */
  title?: string;
  /** Severity from original scan */
  originalSeverity?: string;
  /** When first detected */
  firstDetected?: string;
  /** Remediation recommendation */
  remediation?: string;
}

/**
 * Options for getting prioritized vulnerability list
 */
export interface GetPrioritizedListOptions {
  /** Assets to include (or all if not specified) */
  assets?: string[];
  /** Minimum risk score to include */
  minRiskScore?: number;
  /** Maximum number of results */
  limit?: number;
  /** Risk tiers to include */
  includeTiers?: RiskTier[];
  /** Group by asset */
  groupByAsset?: boolean;
  /** Include only remediable vulnerabilities */
  remediableOnly?: boolean;
}

/**
 * Prioritized list result
 */
export interface PrioritizedListResult {
  /** Total vulnerabilities analyzed */
  totalAnalyzed: number;
  /** Vulnerabilities included in result */
  included: number;
  /** Prioritized list */
  vulnerabilities: PrioritizedVulnerability[];
  /** Summary by risk tier */
  tierSummary: Record<RiskTier, number>;
  /** Summary by asset (if grouped) */
  assetSummary?: Record<string, { count: number; avgRiskScore: number }>;
  /** Generated at timestamp */
  generatedAt: string;
}

/**
 * Risk scoring database initialization result
 */
export interface RiskDbInitResult {
  /** Whether initialization was successful */
  success: boolean;
  /** Database path */
  path: string;
  /** Timestamp */
  created: string;
  /** Error message if failed */
  error?: string;
}

/**
 * Options for setting asset criticality
 */
export interface SetAssetCriticalityOptions {
  /** Asset identifier */
  asset: string;
  /** Asset type */
  assetType: "image" | "project" | "repository" | "service";
  /** Criticality level */
  criticality: RiskAssetCriticality;
  /** Exposure level */
  exposure: RiskExposureLevel;
  /** Business context description */
  businessContext?: string;
  /** Owner/team */
  owner?: string;
  /** Compliance frameworks */
  complianceFrameworks?: string[];
  /** Custom multiplier */
  customMultiplier?: number;
}

/**
 * Risk configuration for global settings
 */
export interface RiskConfig {
  /** Default criticality for unknown assets */
  defaultCriticality: RiskAssetCriticality;
  /** Default exposure for unknown assets */
  defaultExposure: RiskExposureLevel;
  /** Risk tier thresholds */
  tierThresholds: {
    critical: number; // >= this is critical
    high: number; // >= this is high
    medium: number; // >= this is medium
    low: number; // >= this is low
    // Below low threshold is minimal
  };
  /** Age factor configuration */
  ageFactorConfig: {
    /** Days after which age factor starts increasing */
    startDays: number;
    /** Maximum age factor multiplier */
    maxFactor: number;
    /** Days to reach max factor */
    maxDays: number;
  };
  /** Custom weights for scoring */
  weights: RiskWeights;
}

// =============================================================================
// Report Export Types (PDF, Excel, CSV)
// =============================================================================

/**
 * PDF page size options
 */
export type PdfPageSize = "A4" | "Letter" | "Legal" | "A3" | "Tabloid";

/**
 * PDF page orientation
 */
export type PdfOrientation = "portrait" | "landscape";

/**
 * Export format options
 */
export type ExportFormat = "pdf" | "excel" | "csv" | "json";

/**
 * PDF header/footer configuration
 */
export interface PdfHeaderFooter {
  /** Left content (can include {page}, {pages}, {date}, {title}) */
  left?: string;
  /** Center content */
  center?: string;
  /** Right content */
  right?: string;
  /** Font size in points */
  fontSize?: number;
}

/**
 * PDF branding configuration
 */
export interface PdfBranding {
  /** Company logo URL or base64 data URI */
  logo?: string;
  /** Primary color (hex) */
  primaryColor?: string;
  /** Secondary color (hex) */
  secondaryColor?: string;
  /** Company name for header */
  companyName?: string;
}

/**
 * PDF export options
 */
export interface PdfExportOptions {
  /** Output file path */
  outputPath: string;
  /** Page size */
  pageSize?: PdfPageSize;
  /** Page orientation */
  orientation?: PdfOrientation;
  /** Page margins in CSS format (e.g., "1in" or "25mm") */
  margins?: {
    top?: string;
    right?: string;
    bottom?: string;
    left?: string;
  };
  /** Header configuration */
  header?: PdfHeaderFooter;
  /** Footer configuration */
  footer?: PdfHeaderFooter;
  /** Branding configuration */
  branding?: PdfBranding;
  /** Document title */
  title?: string;
  /** Document author */
  author?: string;
  /** Include table of contents */
  includeTableOfContents?: boolean;
  /** Include page numbers */
  includePageNumbers?: boolean;
  /** Include generation timestamp */
  includeTimestamp?: boolean;
  /** Print background colors/images */
  printBackground?: boolean;
}

/**
 * Excel worksheet configuration
 */
export interface ExcelWorksheet {
  /** Sheet name */
  name: string;
  /** Data rows (array of objects or 2D array) */
  data: Record<string, unknown>[] | unknown[][];
  /** Column configuration */
  columns?: ExcelColumn[];
  /** Include filters */
  includeFilters?: boolean;
  /** Freeze first row (header) */
  freezeHeader?: boolean;
  /** Auto-width columns */
  autoWidth?: boolean;
}

/**
 * Excel column configuration
 */
export interface ExcelColumn {
  /** Header text */
  header: string;
  /** Data key (for object data) */
  key?: string;
  /** Column width */
  width?: number;
  /** Number format (e.g., "0.00", "#,##0", "yyyy-mm-dd") */
  numFmt?: string;
  /** Horizontal alignment */
  alignment?: "left" | "center" | "right";
  /** Apply conditional formatting based on severity */
  conditionalSeverity?: boolean;
}

/**
 * Excel export options
 */
export interface ExcelExportOptions {
  /** Output file path */
  outputPath: string;
  /** Worksheets to include */
  worksheets: ExcelWorksheet[];
  /** Document title */
  title?: string;
  /** Document author */
  author?: string;
  /** Company name */
  company?: string;
  /** Include charts */
  includeCharts?: boolean;
  /** Password protect the file */
  password?: string;
}

/**
 * CSV export options
 */
export interface CsvExportOptions {
  /** Output file path */
  outputPath: string;
  /** Data rows */
  data: Record<string, unknown>[];
  /** Column order (defaults to object keys) */
  columns?: string[];
  /** Column headers (defaults to column names) */
  headers?: Record<string, string>;
  /** Field delimiter (default: comma) */
  delimiter?: "," | ";" | "\t" | "|";
  /** Include UTF-8 BOM for Excel compatibility */
  includeBom?: boolean;
  /** Quote all fields */
  quoteAll?: boolean;
  /** Line ending (default: \n) */
  lineEnding?: "\n" | "\r\n";
}

/**
 * Export result
 */
export interface ExportResult {
  /** Whether export was successful */
  success: boolean;
  /** Output file path */
  path: string;
  /** File size in bytes */
  size: number;
  /** Export format */
  format: ExportFormat;
  /** Generation time in milliseconds */
  duration: number;
  /** Row count */
  rowCount: number;
  /** Error message if failed */
  error?: string;
}

/**
 * Report data for export
 */
export interface ReportData {
  /** Report title */
  title: string;
  /** Generation timestamp */
  generatedAt: string;
  /** Target (image, project, etc.) */
  target?: string;
  /** Summary section */
  summary?: {
    totalVulnerabilities: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    unknownCount?: number;
    healthScore?: number;
    complianceStatus?: string;
  };
  /** Vulnerability details */
  vulnerabilities?: Array<{
    id: string;
    severity: string;
    package?: string;
    version?: string;
    fixedVersion?: string;
    title?: string;
    description?: string;
    cvss?: number;
    riskScore?: number;
  }>;
  /** Compliance findings */
  compliance?: Array<{
    framework: string;
    control: string;
    status: string;
    findings: number;
  }>;
  /** Trend data for charts */
  trends?: Array<{
    date: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * PDF generation result with additional details
 */
export interface PdfExportResult extends ExportResult {
  /** Number of pages */
  pageCount: number;
  /** Whether TOC was included */
  hasToc: boolean;
}

/**
 * Excel generation result with additional details
 */
export interface ExcelExportResult extends ExportResult {
  /** Number of worksheets */
  worksheetCount: number;
  /** Whether charts were included */
  hasCharts: boolean;
}

// =============================================================================
// Cross-Project Comparative Analysis Types
// =============================================================================

/**
 * Entity type for comparison
 */
export type ComparisonEntityType = "project" | "team" | "image" | "repository";

/**
 * Metric types available for comparison
 */
export type ComparisonMetric =
  | "vulnerability_count"
  | "critical_count"
  | "high_count"
  | "medium_count"
  | "low_count"
  | "risk_score"
  | "health_score"
  | "compliance_score"
  | "mttr"
  | "remediation_velocity"
  | "scan_coverage";

/**
 * Trend direction for comparison deltas
 */
export type ComparisonTrend = "improving" | "stable" | "declining";

/**
 * Security metrics for a single entity
 */
export interface EntityMetrics {
  /** Entity identifier */
  entityId: string;
  /** Entity name */
  entityName: string;
  /** Entity type */
  entityType: ComparisonEntityType;
  /** Timestamp of metrics collection */
  timestamp: string;
  /** Total vulnerability count */
  vulnerabilityCount: number;
  /** Critical vulnerabilities */
  criticalCount: number;
  /** High vulnerabilities */
  highCount: number;
  /** Medium vulnerabilities */
  mediumCount: number;
  /** Low vulnerabilities */
  lowCount: number;
  /** Unknown severity vulnerabilities */
  unknownCount?: number;
  /** Overall risk score (0-100) */
  riskScore: number;
  /** Health score (0-100) */
  healthScore: number;
  /** Compliance score (0-100) */
  complianceScore: number;
  /** Mean time to remediate in hours */
  mttr?: number;
  /** Vulnerabilities fixed per day */
  remediationVelocity?: number;
  /** Percentage of assets scanned */
  scanCoverage?: number;
  /** Total assets count */
  assetCount?: number;
}

/**
 * Metric comparison result between two entities
 */
export interface ComparisonMetricResult {
  /** Metric name */
  metric: ComparisonMetric;
  /** First entity value */
  valueA: number;
  /** Second entity value */
  valueB: number;
  /** Absolute difference (B - A) */
  delta: number;
  /** Percentage change */
  percentChange: number;
  /** Trend direction */
  trend: ComparisonTrend;
  /** Which entity is "better" for this metric */
  winner?: "A" | "B" | "tie";
}

/**
 * Full comparison result between two entities
 */
export interface ComparisonResult {
  /** First entity metrics */
  entityA: EntityMetrics;
  /** Second entity metrics */
  entityB: EntityMetrics;
  /** Metric-by-metric comparisons */
  metrics: ComparisonMetricResult[];
  /** Overall comparison summary */
  summary: {
    /** Entity with better overall security posture */
    betterEntity: "A" | "B" | "tie";
    /** Confidence score for the comparison (0-100) */
    confidence: number;
    /** Key differences identified */
    keyDifferences: string[];
    /** Recommendations */
    recommendations: string[];
  };
  /** Comparison timestamp */
  comparedAt: string;
}

/**
 * Baseline snapshot for comparison
 */
export interface Baseline {
  /** Unique baseline ID */
  id: string;
  /** Baseline name */
  name: string;
  /** Description */
  description?: string;
  /** Entity type */
  entityType: ComparisonEntityType;
  /** Entity ID */
  entityId: string;
  /** Entity name */
  entityName: string;
  /** Metrics snapshot */
  metrics: EntityMetrics;
  /** When baseline was created */
  createdAt: string;
  /** Who created the baseline */
  createdBy?: string;
  /** Tags for organization */
  tags?: string[];
  /** Whether this is the default baseline for the entity */
  isDefault?: boolean;
}

/**
 * Options for creating a baseline
 */
export interface CreateBaselineOptions {
  /** Baseline name */
  name: string;
  /** Description */
  description?: string;
  /** Entity type */
  entityType: ComparisonEntityType;
  /** Entity ID */
  entityId: string;
  /** Entity name */
  entityName: string;
  /** Metrics to snapshot */
  metrics: EntityMetrics;
  /** Creator ID */
  createdBy?: string;
  /** Tags */
  tags?: string[];
  /** Set as default baseline */
  isDefault?: boolean;
}

/**
 * Options for comparing projects
 */
export interface CompareProjectsOptions {
  /** First project ID */
  projectIdA: string;
  /** Second project ID */
  projectIdB: string;
  /** Optional: Metrics to use (if provided externally) */
  metricsA?: EntityMetrics;
  metricsB?: EntityMetrics;
  /** Normalize by asset count */
  normalize?: boolean;
}

/**
 * Options for comparing teams
 */
export interface CompareTeamsOptions {
  /** First team ID */
  teamIdA: string;
  /** Second team ID */
  teamIdB: string;
  /** Optional: Metrics to use (if provided externally) */
  metricsA?: EntityMetrics;
  metricsB?: EntityMetrics;
  /** Normalize by project count */
  normalize?: boolean;
}

/**
 * Options for comparing to baseline
 */
export interface CompareToBaselineOptions {
  /** Current entity metrics */
  currentMetrics: EntityMetrics;
  /** Baseline ID to compare against */
  baselineId?: string;
  /** Or use default baseline for entity */
  useDefaultBaseline?: boolean;
  /** Entity ID if using default baseline */
  entityId?: string;
}

/**
 * Ranking entry for leaderboard
 */
export interface RankingEntry {
  /** Rank position (1 = best) */
  rank: number;
  /** Entity ID */
  entityId: string;
  /** Entity name */
  entityName: string;
  /** Entity type */
  entityType: ComparisonEntityType;
  /** Score for ranking metric */
  score: number;
  /** Percentile (0-100) */
  percentile: number;
  /** Change from previous period */
  changeFromPrevious?: number;
  /** Trend direction */
  trend?: ComparisonTrend;
}

/**
 * Options for generating rankings
 */
export interface GetRankingsOptions {
  /** Metric to rank by */
  metric: ComparisonMetric;
  /** Entity type to rank */
  entityType: ComparisonEntityType;
  /** Entity IDs to include (optional, all if not specified) */
  entityIds?: string[];
  /** Maximum results */
  limit?: number;
  /** Sort order */
  order?: "asc" | "desc";
}

/**
 * Rankings result
 */
export interface RankingsResult {
  /** Metric used for ranking */
  metric: ComparisonMetric;
  /** Entity type */
  entityType: ComparisonEntityType;
  /** Ranked entries */
  rankings: RankingEntry[];
  /** Statistics */
  stats: {
    /** Total entities ranked */
    total: number;
    /** Average score */
    average: number;
    /** Median score */
    median: number;
    /** Standard deviation */
    stdDev: number;
    /** Best score */
    best: number;
    /** Worst score */
    worst: number;
  };
  /** Generated timestamp */
  generatedAt: string;
}

/**
 * Comparison database initialization result
 */
export interface ComparisonDbInitResult {
  /** Whether initialization succeeded */
  success: boolean;
  /** Database path */
  path: string;
  /** Timestamp */
  created: string;
  /** Error if failed */
  error?: string;
}

/**
 * Options for listing baselines
 */
export interface ListBaselinesOptions {
  /** Filter by entity type */
  entityType?: ComparisonEntityType;
  /** Filter by entity ID */
  entityId?: string;
  /** Filter by tags */
  tags?: string[];
  /** Maximum results */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
}
