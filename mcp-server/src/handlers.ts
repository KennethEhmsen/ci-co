// Re-export everything from the shared library
export {
  // Config
  config,
  type Config,
  // Validation
  validateSeverity,
  sanitizePath,
  sanitizeImageName,
  // HTTP helpers
  fetchJson,
  basicAuth,
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
  // Dependency-Track
  dtrackGetProjects,
  dtrackGetVulnerabilities,
  dtrackGetFindings,
  dtrackGetComponents,
  uploadSbomToDtrack,
  // Gitea
  giteaGetRepos,
  giteaGetRepo,
  giteaGetBranches,
  giteaGetCommits,
  giteaCreateRepo,
  giteaMigrateRepo,
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
  // Security Dashboard
  getSecurityDashboard,
  // Registry Scanner
  listRegistryImages,
  scanRegistry,
} from "@cicd/shared";
