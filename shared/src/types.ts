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
