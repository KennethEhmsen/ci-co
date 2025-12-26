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
