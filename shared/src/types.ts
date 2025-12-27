/**
 * Type definitions for CI/CD Platform API responses
 */

// =============================================================================
// Trivy Types
// =============================================================================

export interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Severity: "UNKNOWN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
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
  Severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
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
  Severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";
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
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  source: "trivy" | "sonarqube" | "dtrack";
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
    level?: "none" | "note" | "warning" | "error";
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
  level?: "none" | "note" | "warning" | "error";
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
  source: "trivy" | "sonarqube" | "dtrack";
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
  source: "trivy" | "sonarqube" | "dtrack";
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
  minSeverity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
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
  maxSeverityToSuppress?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
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
  minSeverity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
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
