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
  // Remediation Types
  PackageManager,
  RemediationConfidence,
  VulnerabilityInfo,
  RemediationSuggestion,
  RemediationPlan,
  RemediationOptions,
  ApplyRemediationOptions,
  ApplyRemediationResult,
  RemediationPROptions,
  RemediationPRResult,
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
  // Compliance Types
  ComplianceFramework,
  ComplianceVulnerabilityType,
  ComplianceSeverity,
  ComplianceControl,
  ComplianceViolation,
  ComplianceFrameworkSummary,
  ComplianceReport,
  ComplianceReportOptions,
  ComplianceTrendEntry,
  ComplianceTrendResult,
  ComplianceCheckOptions,
  ComplianceCheckResult,
  // OPA/Rego Types
  OpaVulnerabilityCounts,
  OpaViolation,
  OpaEvaluationResult,
  OpaPolicyInfo,
  OpaEvaluationInput,
  OpaPolicyOptions,
  OpaCompileOptions,
  OpaCompileResult,
  OpaValidationResult,
  // Vulnerability Database Types
  VulnDbRecord,
  VulnDbAffectedPackage,
  VulnDbSyncStatus,
  VulnDbSyncOptions,
  VulnDbSearchQuery,
  VulnDbStats,
  OfflineScanOptions,
  VulnAnnotation,
  TrivyDbSyncResult,
  TrivyDbStatus,
  VulnDbConfig,
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
  // Suppression creation (in-memory)
  createSuppression,
  suppressCve,
  suppressPackage,
  suppressPath,
  // Expiration helpers
  isExpired,
  getDaysUntilExpiration,
  filterExpired,
  getExpiredSuppressions,
  // Pattern matching
  matchesCve,
  matchesPackage,
  matchesVersion,
  matchesPath,
  matchesSuppression,
  // File-based operations
  findSuppressionFile,
  parseSuppressionFile,
  validateSuppression,
  loadSuppressions,
  loadSuppressionsFromDirectory,
  applySuppressionsToVulnerabilities,
  applySuppressions,
  generateSuppressionReport,
  writeSuppressions,
  // Database operations
  getDefaultSuppressionDbPath,
  initSuppressionDatabase,
  closeSuppressionDatabase,
  getSuppressionDatabase,
  isSuppressionDbInitialized,
  createDbSuppression,
  getDbSuppression,
  listDbSuppressions,
  updateDbSuppression,
  deleteDbSuppression,
  // Audit operations
  logSuppressionApplication,
  getSuppressionAuditLog,
  getSuppressionDbStats,
  // Database utilities
  applyDbSuppressions,
  importSuppressionsToDb,
  exportSuppressionsFromDb,
  markExpiredSuppressions,
  getSuppressionDbPath,
  // Types
  type SuppressionStatus,
  type SuppressionAuditAction,
  type SuppressionAuditEntry,
  type SuppressionListOptions,
  type SuppressionDbStats,
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

// Remediation exports
export {
  isBreakingChange,
  generateFixCommand,
  detectPackageManager,
  generateRemediations,
  getRemediationSummary,
  formatRemediationAsMarkdown,
  getHighPriorityRemediations,
  getSafeRemediations,
} from "./remediation.js";

// Compliance exports
export {
  COMPLIANCE_CONTROLS,
  getComplianceFrameworks,
  getComplianceControls,
  getComplianceControl,
  mapFindingToControls,
  generateComplianceReport,
  generateComplianceHtml,
  recordComplianceTrend,
  getComplianceTrend,
  clearComplianceTrends,
  getComplianceTrendTargets,
  checkComplianceStatus,
} from "./compliance.js";

// OPA/Rego exports
export {
  BUILTIN_POLICIES,
  listBuiltinPolicies,
  getBuiltinPolicy,
  getBuiltinPolicyInfo,
  validateRegoSyntax,
  evaluateOpaPolicy,
  evaluateMultiplePolicies,
  scanResultsToOpaInput,
  trivyResultToOpaInput,
  dashboardResultToOpaInput,
  createOpaInput,
  evaluatePolicyWithScan,
} from "./opa.js";
export type { EvaluatePolicyInput } from "./opa.js";

// OPA Compiler exports
export {
  isOpaInstalled,
  getOpaVersion,
  getOpaInstallInstructions,
  compileRegoToWasm,
  compileRegoFileToWasm,
  loadWasmPolicy,
  createPolicyBundle,
  checkRegoSyntax,
  formatRego,
} from "./opa-compiler.js";

// Vulnerability Database exports
export {
  getDefaultDbPath,
  initVulnDatabase,
  closeVulnDatabase,
  getVulnDatabase,
  isVulnDbInitialized,
  insertVulnerability,
  bulkInsertVulnerabilities,
  lookupVulnerability,
  deleteVulnerability,
  addAffectedPackages,
  getAffectedPackages,
  clearAffectedPackages,
  searchVulnerabilities,
  findVulnerabilitiesByPackage,
  updateSyncStatus,
  getSyncStatus,
  getAllSyncStatuses,
  annotateVulnerability,
  getVulnAnnotation,
  getAnnotationsByStatus,
  removeAnnotation,
  getVulnDbStats,
  vacuumDatabase,
  clearAllVulnerabilities,
  clearVulnerabilitiesBySource,
  getVulnDbPath,
} from "./vuln-database.js";

// Database Sync exports
export {
  getTrivyCacheDir,
  getTrivyDbPath,
  getTrivyDbStatus,
  downloadTrivyDb,
  parseVulnFromTrivy,
  importTrivyScanResult,
  syncVulnDatabase,
  getVulnDbSyncStatus,
  isOfflineScanAvailable,
  scheduleDatabaseSync,
} from "./db-sync.js";

// Offline Scanner exports
export {
  offlineScanImage,
  offlineScanPath,
  isOfflineScanError,
  getOfflineDbAge,
  isOfflineDbStale,
  getOfflineScanCapabilities,
  offlineScanImages,
  offlineScanPaths,
} from "./offline-scanner.js";

// Redis Cache exports
export {
  getRedisConfig,
  getTTLConfig,
  initRedisConnection,
  closeRedisConnection,
  isRedisConnected,
  getRedisClient,
  DistributedCache,
  initDistributedCaches,
  getTrivyCache,
  getSonarqubeCache,
  getDtrackCache,
  getRegistryCache,
  getAllCacheStats,
  clearAllCaches,
  invalidateCacheByPattern,
  getCacheHealth,
  createCacheKey,
  type RedisConfig,
  type CacheStats,
  type CacheTTLConfig,
  type CacheHealthStatus,
} from "./redis-cache.js";

// SSO Configuration exports
export {
  initSsoDatabase,
  closeSsoDatabase,
  isSsoDbInitialized,
  configureSamlProvider,
  configureOidcProvider,
  getSsoProvider,
  getSamlProvider,
  getOidcProvider,
  listSsoProviders,
  deleteSsoProvider,
  setSsoProviderEnabled,
  getSsoProviderByIssuer,
  createSsoSession,
  getSsoSession,
  validateSsoSession,
  terminateSsoSession,
  terminateAllUserSessions,
  listUserSessions,
  listAllSessions,
  cleanupExpiredSessions,
  updateSessionTokens,
  logSsoAudit,
  getSsoAuditEvents,
  cleanupOldAuditEvents,
} from "./sso-config.js";

// SSO SAML exports
export {
  generateSpMetadata,
  validateSamlAssertion,
  generateSamlLogoutRequest,
  validateSamlLogoutResponse,
  generateSamlAuthRequest,
  clearSamlInstanceCache,
} from "./sso-saml.js";

// SSO OIDC exports
export {
  discoverOidcProvider,
  validateOidcToken,
  validateOidcTokenByIssuer,
  introspectOidcToken,
  refreshOidcToken,
  getOidcUserInfo,
  clearJwksCache,
  clearDiscoveryCache,
} from "./sso-oidc.js";

// SSO Types re-export
export type {
  SsoProviderType,
  SsoEventType,
  SsoErrorCode,
  SsoAttributeMapping,
  SamlProviderConfig,
  OidcProviderConfig,
  SsoProviderConfigUnion,
  SsoSession,
  SsoValidationResult,
  SsoMetadataResult,
  SsoAuditEvent,
  SsoDbInitResult,
  SsoProviderSummary,
} from "./types.js";

// RBAC Configuration exports
export {
  initRbacDatabase,
  closeRbacDatabase,
  isRbacDbInitialized,
  createRole,
  getRole,
  getRoleByName,
  listRoles,
  updateRole,
  deleteRole,
  getPermission,
  getPermissionByName,
  listPermissions,
  grantPermissionToRole,
  revokePermissionFromRole,
  getRolePermissions,
  assignRoleToUser,
  unassignRoleFromUser,
  getUserRoles,
  getUsersWithRole,
  checkPermission,
  listUserPermissions,
  isUserAdmin,
  logRbacAudit,
  getRbacAuditEvents,
  cleanupOldRbacAuditEvents,
  cleanupExpiredRoleAssignments,
} from "./rbac-config.js";

// RBAC Types re-export
export type {
  RbacEventType,
  RbacRole,
  RbacPermission,
  RbacUserRole,
  RbacCheckResult,
  RbacAuditEvent,
  RbacRoleWithPermissions,
  RbacDbInitResult,
} from "./types.js";

// =============================================================================
// API Key Management
// =============================================================================

export {
  VALID_SCOPES,
  initApiKeyDatabase,
  closeApiKeyDatabase,
  isApiKeyDbInitialized,
  createApiKey,
  getApiKey,
  listApiKeys,
  revokeApiKey,
  rotateApiKey,
  validateApiKey,
  getApiKeyAuditEvents,
  markExpiredApiKeys,
  getApiKeyStats,
  cleanupApiKeyAuditLogs,
} from "./apikey-manager.js";

// API Key Types re-export
export type {
  ApiKeyScope,
  ApiKeyEventType,
  ApiKeyStatus,
  ApiKey,
  ApiKeyCreateOptions,
  ApiKeyCreateResult,
  ApiKeyDisplay,
  ApiKeyValidationResult,
  ApiKeyRotateResult,
  ApiKeyAuditEvent,
  ApiKeyListOptions,
  ApiKeyDbInitResult,
} from "./types.js";

// =============================================================================
// Team Management
// =============================================================================

export {
  initTeamDatabase,
  closeTeamDatabase,
  isTeamDbInitialized,
  // Organization management
  createOrganization,
  getOrganization,
  getOrganizationByName,
  listOrganizations,
  updateOrganization,
  deleteOrganization,
  // Team management
  createTeam,
  getTeam,
  getTeamByName,
  listTeams,
  updateTeam,
  deleteTeam,
  // Member management
  addTeamMember,
  removeTeamMember,
  updateTeamMemberRole,
  getTeamMember,
  listTeamMembers,
  getUserTeamMemberships,
  isTeamMember,
  hasTeamRole,
  // Audit
  logTeamAudit,
  getTeamAuditEvents,
  // Maintenance
  cleanupExpiredMemberships,
  cleanupTeamAuditEvents,
  getTeamStats,
} from "./team-manager.js";

// Team Management Types re-export
export type {
  TeamMemberRole,
  TeamEventType,
  Organization,
  OrganizationSettings,
  OrganizationWithStats,
  Team,
  TeamSettings,
  TeamWithStats,
  TeamMember,
  TeamMembershipDetails,
  CreateOrganizationOptions,
  CreateTeamOptions,
  AddTeamMemberOptions,
  ListTeamsOptions,
  ListTeamMembersOptions,
  TeamAuditEvent,
  TeamDbInitResult,
  TeamStats,
} from "./types.js";

// =============================================================================
// Session Management
// =============================================================================

export {
  initSessionDatabase,
  closeSessionDatabase,
  isSessionDbInitialized,
  getSessionConfig,
  updateSessionConfig,
  // Session operations
  createSession,
  getSession,
  listSessions,
  revokeSession,
  revokeAllUserSessions,
  // Token operations
  validateAccessToken,
  refreshTokens,
  // Token blacklist
  blacklistToken,
  isTokenBlacklisted,
  getBlacklistedTokens,
  // Audit
  logSessionAudit,
  getSessionAuditEvents,
  // Maintenance
  cleanupExpiredSessions as cleanupExpiredSessionsMgmt,
  cleanupExpiredBlacklistEntries,
  cleanupSessionAuditEvents,
  getSessionStats,
} from "./session-manager.js";

// Session Management Types re-export
export type {
  SessionEventType,
  SessionDevice,
  Session,
  TokenClaims,
  TokenPair,
  CreateSessionOptions,
  CreateSessionResult,
  TokenValidationResult,
  RefreshTokenResult,
  SessionListOptions,
  SessionAuditEvent,
  SessionDbInitResult,
  SessionStats,
  BlacklistedToken,
  SessionConfig,
} from "./types.js";

// =============================================================================
// Audit Trail
// =============================================================================

export {
  // Database lifecycle
  initAuditDatabase,
  closeAuditDatabase,
  isAuditDbInitialized,
  getAuditConfig,
  updateAuditConfig,
  // Event operations
  logAuditEvent,
  getAuditEvent,
  searchAuditEvents,
  getActionCategory,
  // Export
  exportAuditLogs,
  // Checksum/Tamper detection
  verifyEventChecksum,
  verifyAuditIntegrity,
  // Event listeners (real-time streaming)
  addAuditEventListener,
  removeAuditEventListener,
  // SIEM integration
  configureSiem,
  flushSiemQueue,
  getSiemQueueStatus,
  // Statistics
  getAuditStats,
  aggregateAuditEvents,
  // Maintenance
  cleanupExpiredAuditEvents,
  cleanupFailedSiemQueue,
} from "./audit-trail.js";

// Audit Trail Types re-export
export type {
  AuditActorType,
  AuditActionCategory,
  AuditAction,
  AuditResourceType,
  AuditOutcome,
  AuditActor,
  AuditResource,
  AuditContext,
  AuditEvent,
  CreateAuditEventOptions,
  AuditSearchOptions,
  AuditExportFormat,
  AuditExportOptions,
  AuditExportResult,
  AuditSiemConfig,
  AuditConfig,
  AuditDbInitResult,
  AuditStats,
  AuditAggregateOptions,
  AuditAggregateResult,
} from "./types.js";

// Executive Dashboard
export {
  // Database lifecycle
  initDashboardDatabase,
  closeDashboardDatabase,
  isDashboardDbInitialized,
  // Configuration
  getDashboardConfig,
  updateDashboardConfig,
  // Asset criticality
  setAssetCriticality,
  getAssetCriticality,
  listAssetCriticalities,
  // Scan recording
  recordScan,
  getScanRecords,
  // Remediation tracking
  recordVulnerabilityDetected,
  markVulnerabilityRemediated,
  // Health score
  calculateHealthScore,
  getHealthScore,
  // Dashboard data
  getVulnerabilityCounts,
  getScanCoverage,
  getMTTRMetrics,
  getTopRisks,
  getComplianceStatus,
  getDashboardSummary,
  // Snapshots
  saveDashboardSnapshot,
  getDashboardSnapshots,
  cleanupOldSnapshots,
} from "./executive-dashboard.js";

// Executive Dashboard Types re-export
export type {
  AssetCriticality,
  TrendDirection,
  DashboardTimeRange,
  SeverityCounts,
  TrendData,
  ComplianceStatusSummary,
  RiskSummary,
  HealthScoreComponents,
  HealthScore,
  MTTRMetrics,
  ScanCoverage,
  DashboardSummary,
  DashboardConfig,
  DashboardSnapshot,
  AssetCriticalityConfig,
  DashboardDbInitResult,
} from "./types.js";

// Report Templates
export {
  // Database lifecycle
  initReportDatabase,
  closeReportDatabase,
  isReportDbInitialized,
  // Template management
  createTemplate,
  getTemplate,
  getTemplateByName,
  listTemplates,
  updateTemplate,
  deleteTemplate,
  // Report generation
  generateReport,
  // Report schedule management
  createReportSchedule,
  getReportSchedule,
  listReportSchedules,
  updateReportSchedule,
  deleteReportSchedule,
  // Report history
  getReportHistory,
  cleanupReportHistory,
} from "./report-templates.js";

// Report Templates Types re-export
export type {
  ReportFormat,
  ReportScheduleFrequency,
  BuiltinTemplateName,
  ReportSectionType,
  ReportSection,
  ReportBranding,
  ReportFilters,
  ReportTemplate,
  ReportGenerateOptions,
  GeneratedReport,
  ReportWebhook,
  ReportSchedule,
  ReportHistoryEntry,
  CreateTemplateOptions,
  CreateScheduleOptions,
  ReportDbInitResult,
} from "./types.js";

// Trend Analysis
export {
  // Database lifecycle
  initTrendDatabase,
  closeTrendDatabase,
  isTrendDbInitialized,
  // Snapshot management
  recordTrendSnapshot,
  // History retrieval
  getVulnerabilityHistory,
  // Forecasting
  getTrendForecast,
  // Anomaly detection
  detectTrendAnomalies,
  // Period comparison
  compareTrendPeriods,
  // Utilities
  listTrendTargets,
  cleanupTrendSnapshots,
  getTrendSnapshotCount,
} from "./trend-analysis.js";

// Trend Analysis Types re-export
export type {
  TrendGranularity,
  TrendDataPoint,
  VulnerabilityHistory,
  TrendForecast,
  TrendForecastPoint,
  TrendAnomaly,
  AnomalyDetectionResult,
  PeriodComparison,
  MetricComparison,
  TrendSnapshot,
  GetHistoryOptions,
  GetForecastOptions,
  DetectAnomaliesOptions,
  ComparePeriodOptions,
  RecordSnapshotOptions,
  TrendDbInitResult,
} from "./types.js";

// Risk Scoring
export {
  // Database lifecycle
  initRiskDatabase,
  closeRiskDatabase,
  isRiskDbInitialized,
  // Configuration
  getRiskConfig,
  updateRiskConfig,
  // Asset management
  setAssetCriticality as setRiskAssetConfig,
  getAssetConfig as getRiskAssetConfig,
  listAssetConfigs as listRiskAssetConfigs,
  deleteAssetConfig as deleteRiskAssetConfig,
  // Risk calculation
  calculateRiskScore,
  storeRiskScore,
  getStoredRiskScore,
  // Prioritized list
  getPrioritizedList,
  // Utilities
  clearRiskScores,
  getRiskStats,
} from "./risk-scoring.js";

// Risk Scoring Types re-export
export type {
  RiskAssetCriticality,
  RiskExposureLevel,
  RiskTier,
  RiskAssetConfig,
  CvssComponents,
  ExploitabilityFactors,
  RiskScore,
  CalculateRiskOptions,
  RiskWeights,
  PrioritizedVulnerability,
  GetPrioritizedListOptions,
  PrioritizedListResult,
  RiskDbInitResult,
  SetAssetCriticalityOptions,
  RiskConfig,
} from "./types.js";

// Report Export (PDF, Excel, CSV)
export {
  // Core export functions
  exportToPdf,
  exportToExcel,
  exportToCsv,
  // Convenience functions
  exportReportToPdf,
  exportReportToExcel,
  exportVulnerabilitiesToCsv,
  // Worksheet helpers
  createVulnerabilityWorksheet,
  createSummaryWorksheet,
  createComplianceWorksheet,
  // Dependency check
  checkExportDependencies,
} from "./export.js";

// Report Export Types re-export
export type {
  PdfPageSize,
  PdfOrientation,
  ExportFormat,
  PdfHeaderFooter,
  PdfBranding,
  PdfExportOptions,
  ExcelWorksheet,
  ExcelColumn,
  ExcelExportOptions,
  CsvExportOptions,
  ExportResult,
  ReportData,
  PdfExportResult,
  ExcelExportResult,
} from "./types.js";
