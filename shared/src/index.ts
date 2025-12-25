// Re-export all shared modules
export { config, type Config } from "./config.js";
export { validateSeverity, sanitizePath, sanitizeImageName } from "./validation.js";
export { fetchJson, basicAuth } from "./http.js";

// Export all types
export type {
  // Trivy Types
  TrivyVulnerability,
  TrivyResult,
  TrivySecret,
  TrivyScanResult,
  // SBOM Types
  SbomComponent,
  SbomLicense,
  SbomHash,
  SbomMetadata,
  TrivySbomResult,
  // IaC Types
  IacMisconfiguration,
  IacResult,
  TrivyIacScanResult,
  // Secret Scan Types
  SecretResult,
  TrivySecretScanResult,
  // License Scan Types
  LicenseFinding,
  LicenseResult,
  TrivyLicenseScanResult,
  // Combined Scan Types
  TrivyCombinedImageScanResult,
  TrivyCombinedPathScanResult,
  // SonarQube Types
  SonarProject,
  SonarProjectsResponse,
  SonarIssue,
  SonarIssuesResponse,
  SonarHotspot,
  SonarHotspotsResponse,
  SonarMeasure,
  SonarMetricsResponse,
  // Dependency-Track Types
  DTrackProject,
  DTrackVulnerability,
  DTrackFinding,
  DTrackComponent,
  // Gitea Types
  GiteaUser,
  GiteaRepository,
  GiteaBranch,
  GiteaCommit,
  // Drone CI Types
  DroneRepository,
  DroneBuild,
  DroneStage,
  DroneStep,
  DroneLogLine,
  // Registry Types
  RegistryCatalog,
  RegistryTags,
  // Platform Types
  ServiceStatus,
  PlatformStatus,
  SecurityScanResult,
  // Configuration Types
  ServiceConfig,
  AuthenticatedServiceConfig,
  TokenAuthServiceConfig,
  ApiKeyServiceConfig,
  PlatformConfig,
  // Error Types
  ApiError,
  // Response Types
  CombinedScanResponse,
  ServiceHealthStatus,
  PlatformHealthResponse,
  McpConfigResource,
} from "./types.js";
export {
  // Trivy
  trivyScanPath,
  trivyScanImage,
  trivyGenerateSbom,
  trivyGenerateSbomImage,
  trivyScanIac,
  trivyScanSecrets,
  trivyScanSecretsImage,
  trivyScanLicenses,
  trivyScanLicensesImage,
  trivyScanImageFull,
  trivyScanPathFull,
  // SonarQube
  sonarGetProjects,
  sonarGetIssues,
  sonarGetSecurityHotspots,
  sonarGetMetrics,
  sonarGetQualityGateStatus,
  // Dependency-Track
  dtrackGetProjects,
  dtrackGetVulnerabilities,
  dtrackGetFindings,
  dtrackGetComponents,
  dtrackUploadSbom,
  // Gitea
  giteaGetRepos,
  giteaGetRepo,
  giteaGetBranches,
  giteaGetCommits,
  giteaCreateRepo,
  giteaMigrateRepo,
  giteaListPullRequests,
  giteaGetPullRequest,
  giteaCreatePullRequest,
  giteaMergePullRequest,
  giteaCreateIssue,
  giteaListIssues,
  // Drone
  droneGetRepos,
  droneGetBuilds,
  droneGetBuild,
  droneGetBuildLogs,
  droneTriggerBuild,
  // Registry
  registryGetCatalog,
  registryGetTags,
  // Combined
  securityScanAll,
  checkPlatformStatus,
} from "./handlers.js";
