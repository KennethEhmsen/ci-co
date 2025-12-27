// Re-export all shared modules
export { config, type Config } from "./config.js";
export { validateSeverity, sanitizePath, sanitizeImageName } from "./validation.js";
export { fetchJson, basicAuth } from "./http.js";
export { ScanCache, withCache, trivyScanCache, sonarCache, dtrackCache } from "./cache.js";
export {
  CircuitBreaker,
  CircuitOpenError,
  circuitBreakers,
  getAllCircuitStats,
  type CircuitState,
  type CircuitBreakerOptions,
} from "./circuit-breaker.js";
export {
  evaluatePolicy,
  getPolicy,
  strictPolicy,
  standardPolicy,
  permissivePolicy,
  type Policy,
  type PolicyRule,
  type PolicyViolation,
  type PolicyEvaluationResult,
  type ScanResults,
  type VulnerabilitySummary,
  type SeverityThresholds,
} from "./policy.js";
export {
  auditLogger,
  auditOperation,
  auditSecurityEvent,
  getSecurityEvents,
  getFailedOperations,
  type AuditEntry,
  type AuditLevel,
  type AuditLogger,
} from "./audit.js";
export {
  RateLimiter,
  QueuedRateLimiter,
  rateLimiters,
  withRateLimit,
  type RateLimiterOptions,
} from "./rate-limiter.js";
export {
  validateConfig,
  validateConnectivity,
  validateStartup,
  logValidationResults,
  type ValidationResult,
  type ServiceValidation,
} from "./config-validation.js";

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
  // Security Dashboard Types
  SecurityDashboardSummary,
  SonarDashboardMetrics,
  SecurityDashboardFinding,
  SecurityDashboardResult,
  SecurityDashboardOptions,
  // SARIF Types
  SarifLog,
  SarifRun,
  SarifResult,
  SarifReportingDescriptor,
  SarifTool,
  SarifToolDriver,
  SarifLocation,
  SarifPhysicalLocation,
  SarifArtifactLocation,
  SarifRegion,
  SarifMessage,
  SarifConversionOptions,
  // Webhook Types
  WebhookFormat,
  WebhookSeverityThreshold,
  WebhookEndpoint,
  WebhookConfig,
  WebhookScanSummary,
  WebhookDeliveryResult,
  SlackBlock,
  SlackWebhookPayload,
  TeamsAdaptiveCardElement,
  TeamsWebhookPayload,
  GenericWebhookPayload,
  // Policy File Types
  PolicyLoadResult,
  PolicyFileSchema,
  PolicyFileRule,
  PolicySettings,
  PolicyValidationError,
  PolicyValidationResult,
  // Parallel Scanning Types
  ScanTargetType,
  ScanTarget,
  ParallelScanOptions,
  ScanProgress,
  TargetScanResult,
  VulnerabilityCounts,
  ParallelScanResult,
  // Metrics Types
  MetricType,
  MetricLabels,
  MetricDefinition,
  CounterValue,
  GaugeValue,
  HistogramBucket,
  HistogramValue,
  CollectedMetric,
  MetricsSnapshot,
  ScanMetrics,
  PushgatewayConfig,
  PushgatewayResult,
  // Scan Diff Types
  VulnerabilityFingerprint,
  FingerprintedVulnerability,
  VulnerabilityDiffStatus,
  DiffVulnerability,
  ScanDiffSummary,
  ScanDiffResult,
  StoredScanRecord,
  ScanCompareOptions,
  ScanHistoryOptions,
  // Suppression Types
  SuppressionType,
  Suppression,
  SuppressionMatch,
  SuppressedVulnerability,
  SuppressionResult,
  SuppressionFileSchema,
  SuppressionLoadOptions,
  SuppressionApplyOptions,
  // SBOM Upload Types
  SbomTargetType,
  SbomUploadOptions,
  SbomUploadResult,
  DTrackProjectCreateOptions,
  DTrackProjectCreateResult,
  // Registry Scanner Types
  RegistryType,
  RegistryImage,
  RegistryScanOptions,
  RegistryScanProgress,
  RegistryScanResult,
  // Multi-Registry Types
  CloudRegistryType,
  BasicRegistryAuth,
  EcrAuth,
  AcrAuth,
  GcrAuth,
  GhcrAuth,
  AnonymousAuth,
  RegistryAuth,
  RegistryConfig,
  RegistryDetectionResult,
  RegistryAuthResult,
  MultiRegistryScanOptions,
  MultiRegistryScanResult,
  // Scheduler Types
  CronField,
  ParsedCronExpression,
  ScheduledScanTarget,
  ScheduledScanOptions,
  ScheduleWebhookConfig,
  ScanSchedule,
  CreateScheduleInput,
  UpdateScheduleInput,
  ScheduleExecutionResult,
  ScheduleHistoryEntry,
  ListSchedulesOptions,
  CronValidationResult,
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
  // Security Dashboard
  getSecurityDashboard,
} from "./handlers.js";

// SARIF exports
export {
  createSarifLog,
  createSarifRun,
  trivyToSarif,
  sonarToSarif,
  dtrackToSarif,
  dashboardToSarif,
  mergeSarifLogs,
  sarifToJson,
  getSarifSummary,
  uploadSarifToGitHub,
  writeSarifFile,
  type GitHubUploadOptions,
  type GitHubUploadResult,
} from "./sarif.js";

// Webhook exports
export {
  meetsSeverityThreshold,
  formatSlackMessage,
  formatTeamsMessage,
  formatGenericMessage,
  sendWebhook,
  sendWebhooks,
  createScanSummary,
  parseWebhookConfig,
} from "./webhook.js";

// Policy loader exports
export {
  findPolicyFile,
  readPolicyFile,
  validatePolicySchema,
  convertToPolicy,
  mergePolicies,
  loadPolicyFromFile,
  loadPolicyFromDirectory,
  resolvePolicy,
  loadPolicy,
} from "./policy-loader.js";

// Parallel scanner exports
export {
  parseTargets,
  parseImages,
  parsePaths,
  scanParallel,
  scanImagesParallel,
  scanPathsParallel,
  scanMixedParallel,
} from "./parallel-scanner.js";

// Metrics exports
export {
  METRICS,
  metricsCollector,
  toPrometheusFormat,
  getMetrics,
  pushToGateway,
  deleteFromGateway,
  recordScanMetrics,
  recordCacheHit,
  recordCacheMiss,
  recordCircuitBreakerFailure,
  resetMetrics,
  getMetricsSnapshot,
} from "./metrics.js";

// Scan diff exports
export {
  createFingerprint,
  fingerprintTrivyVulnerability,
  fingerprintDtrackFinding,
  fingerprintSonarIssue,
  extractTrivyVulnerabilities,
  extractDtrackVulnerabilities,
  extractSonarVulnerabilities,
  compareVulnerabilities,
  compareScanResults,
  compareTrivyScans,
  getScanHistory,
  resetScanHistory,
  createScanRecord,
  storeTrivyScan,
  compareWithPrevious,
  storeAndCompare,
} from "./scan-diff.js";

// Suppression exports
export {
  createSuppression,
  suppressCve,
  suppressPackage,
  suppressPath,
  isExpired,
  getDaysUntilExpiration,
  filterExpired,
  getExpiredSuppressions,
  matchesCve,
  matchesPackage,
  matchesVersion,
  matchesPath,
  matchesSuppression,
  findSuppressionFile,
  parseSuppressionFile,
  validateSuppression,
  loadSuppressions,
  loadSuppressionsFromDirectory,
  applySuppressionsToVulnerabilities,
  applySuppressions,
  generateSuppressionReport,
  writeSuppressions,
} from "./suppression.js";

// SBOM upload exports
export {
  dtrackLookupProject,
  dtrackCreateProject,
  dtrackGetOrCreateProject,
  dtrackUploadSbomToProject,
  dtrackCheckBomProcessing,
  dtrackWaitForProcessing,
  uploadSbomToDtrack,
  uploadSbomsBatch,
} from "./sbom-upload.js";

// Registry scanner exports
export {
  parseDuration,
  isWithinMaxAge,
  matchesRepositoryPattern,
  matchesTagFilter,
  discoverImages,
  listRegistryImages,
  scanRegistry,
  getRegistryScanSummary,
} from "./registry-scanner.js";

// Multi-registry config exports
export {
  detectRegistryType,
  isHarborRegistry,
  configureRegistry,
  getRegistryConfig,
  listRegistryConfigs,
  removeRegistryConfig,
  getDefaultRegistry,
  clearRegistryConfigs,
  getRegistryAuth,
  scanMultipleRegistries,
  testRegistryConnection,
} from "./registry-config.js";

// Scheduler exports
export {
  parseCronExpression,
  validateCronExpression,
  describeCronExpression,
  getNextRunTime,
  getNextRunTimes,
  createSchedule,
  getSchedule,
  listSchedules,
  updateSchedule,
  deleteSchedule,
  triggerSchedule,
  getScheduleHistory,
  startScheduler,
  stopScheduler,
  saveSchedulesToFile,
  loadSchedulesFromFile,
  clearAllSchedules,
} from "./scheduler.js";
