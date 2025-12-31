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
  // Comparison Types
  ComparisonEntityType,
  ComparisonMetric,
  ComparisonTrend,
  EntityMetrics,
  ComparisonMetricResult,
  ComparisonResult,
  Baseline,
  CreateBaselineOptions,
  CompareProjectsOptions,
  CompareTeamsOptions,
  CompareToBaselineOptions,
  RankingEntry,
  GetRankingsOptions,
  RankingsResult,
  ComparisonDbInitResult,
  ListBaselinesOptions,
} from "./types.js";

// =============================================================================
// Cross-Project Comparative Analysis
// =============================================================================

export {
  // Database lifecycle
  initComparisonDb,
  closeComparisonDb,
  getComparisonDbPath,
  // Comparison functions
  compareProjects,
  compareTeams,
  compareToBaseline,
  // Baseline management
  createBaseline,
  getBaseline,
  getDefaultBaseline,
  listBaselines,
  deleteBaseline,
  setDefaultBaseline,
  // Rankings / Leaderboard
  recordEntityMetrics,
  getRankings,
  // Caching
  getCachedComparison,
  cacheComparison,
  clearExpiredCache,
} from "./comparison.js";

// PR Generator exports
export {
  generateBranchName,
  generateCommitMessage,
  generatePrTitle,
  generatePrBody,
  createPullRequest,
  createBatchPullRequests,
  getPrStatus,
  type PrCreateOptions,
  type PrCreateResult,
  type BatchPrResult,
  type PrStatus,
} from "./pr-generator.js";

// IDE Integration exports
export {
  DiagnosticSeverity,
  generateDiagnostics,
  generateCodeActions,
  generateFixEdit,
  applyFixes,
  type Position,
  type Range,
  type Diagnostic,
  type DiagnosticRelatedInformation,
  type CodeAction,
  type WorkspaceEdit,
  type TextEdit,
  type Command,
  type IdeDiagnosticsResult,
  type IdeCodeActionsResult,
} from "./ide-integration.js";

// Dependency Updater exports
export {
  getUpdateType,
  isBreakingUpdate,
  detectPackageManager as detectProjectPackageManager,
  checkUpdates,
  previewUpdate,
  applyUpdate,
  applyUpdates,
  rollbackUpdates,
  type AvailableUpdate,
  type UpdateCheckResult,
  type UpdatePreview,
  type UpdateApplyResult,
  type BatchUpdateResult,
} from "./deps-updater.js";

// Fix Verification exports
export {
  extractVulnerabilities,
  findVulnerability,
  verifySingleFix,
  verifyFixes,
  compareScanResults as compareScanResultsForVerification,
  generateVerificationSummary,
  isCvePresent,
  getAllCveIds,
  countBySeverity,
  calculateFixRate,
  type VulnVerificationResult,
  type FixVerificationResult,
  type RescanOptions,
} from "./fix-verification.js";

// SLA Tracking (v1.25.0)
export {
  initSlaDatabase,
  closeSlaDatabase,
  configureSla,
  getSlaConfig,
  getDefaultSlaConfig,
  listSlaConfigs,
  deleteSlaConfig,
  trackVulnerability,
  acknowledgeVulnerability,
  remediateVulnerability,
  getSlaStatus,
  getSlaBreaches,
  clearTrackedVulnerabilities,
  type SlaSeverity,
  type SlaTarget,
  type SlaConfig,
  type SlaConfigureOptions,
  type VulnSlaStatus,
  type SlaStatusSummary,
  type SlaGetStatusOptions,
  type SlaStatusResult,
  type SlaBreach,
  type SlaApproaching,
  type SlaBreachesResult,
  type SlaGetBreachesOptions,
} from "./sla-tracking.js";

// Governance Workflow (v1.26.0)
export {
  initGovernanceDatabase,
  closeGovernanceDatabase,
  createGovernancePolicy,
  getGovernancePolicy,
  listGovernancePolicies,
  updateGovernancePolicy,
  activateGovernancePolicy,
  deprecateGovernancePolicy,
  deleteGovernancePolicy,
  requestPolicyException,
  getPolicyException,
  listPolicyExceptions,
  approvePolicyException,
  rejectPolicyException,
  getGovernanceAuditLog,
  type GovernanceDbInitResult,
  type GovernanceAuditEntry,
  type GovernancePolicyStatusLocal,
  type ExceptionStatusLocal,
  type EnforcementLevel,
  type GovernancePolicyLocal,
  type GovernancePolicyRuleLocal,
  type PolicyExceptionLocal,
  type CreatePolicyOptionsLocal,
  type RequestExceptionOptionsLocal,
} from "./governance-workflow.js";

// Evidence Collection (v1.26.0)
export {
  initEvidenceDatabase,
  closeEvidenceDatabase,
  collectEvidence,
  getEvidence,
  listEvidence,
  deleteEvidence,
  attachToEvidence,
  getEvidenceAttachments,
  deleteAttachment,
  exportEvidencePackage,
  getEvidenceAuditLog,
  type EvidenceDbInitResult,
  type ListEvidenceOptions,
  type ExportEvidenceOptions,
  type EvidenceAuditEntry,
  type EvidenceTypeLocal,
  type EvidenceRecordLocal,
  type EvidenceAttachmentLocal,
  type CollectEvidenceOptionsLocal,
  type EvidencePackageLocal,
} from "./evidence-collection.js";

// Audit Preparation (v1.26.0)
export {
  initAuditPrepDatabase,
  closeAuditPrepDatabase,
  prepareAuditPackage,
  getAuditPackage,
  listAuditPackages,
  finalizeAuditPackage,
  archiveAuditPackage,
  generateAttestation,
  getAttestation,
  listAttestations,
  recordTimelineEvent,
  getComplianceTimeline,
  getAuditPrepLog,
  type AuditPrepDbInitResult,
  type AuditPrepAuditEntry,
  type AuditTypeLocal,
  type AuditStatusLocal,
  type AuditPackageLocal,
  type AttestationRecordLocal,
  type ComplianceTimelineEventLocal,
  type PrepareAuditOptionsLocal,
  type GenerateAttestationOptionsLocal,
  type TimelineOptionsLocal,
} from "./audit-preparation.js";

// =============================================================================
// Advanced Notifications & Alerting (v1.27.0)
// =============================================================================

// Notification Channels
export {
  initNotificationDatabase,
  closeNotificationDatabase,
  createNotificationChannel,
  getNotificationChannel,
  listNotificationChannels,
  updateNotificationChannel,
  deleteNotificationChannel,
  testNotificationChannel,
  sendNotification,
  getNotificationAuditLog,
  type NotificationDbInitResult,
  type NotificationChannelType,
  type ChannelStatus,
  type ChannelConfig,
  type NotificationChannel,
  type CreateChannelOptions,
  type TestChannelResult,
  type NotificationPayload,
  type SendNotificationResult,
  type NotificationAuditEntry,
} from "./notification-channels.js";

// Alert Rules
export {
  initAlertRulesDatabase,
  closeAlertRulesDatabase,
  createAlertRule,
  getAlertRule,
  getAlertRuleByName,
  listAlertRules,
  updateAlertRule,
  deleteAlertRule,
  evaluateAlertRule,
  evaluateAllRules,
  triggerAlert,
  acknowledgeAlertEvent,
  resolveAlertEvent,
  getAlertEvent,
  listAlertEvents,
  getAlertRulesAuditLog,
  type AlertRulesDbInitResult,
  type AlertRuleSeverity,
  type AlertRuleStatus,
  type AlertConditionOperator,
  type AlertMetricType,
  type AlertCondition,
  type AlertRule,
  type CreateAlertRuleOptions,
  type UpdateAlertRuleOptions,
  type EvaluateRuleContext,
  type EvaluateRuleResult,
  type AlertEvent,
  type AlertRulesAuditEntry,
} from "./alert-rules.js";

// Escalation Policies
export {
  initEscalationDatabase,
  closeEscalationDatabase,
  createEscalationPolicy,
  getEscalationPolicy,
  listEscalationPolicies,
  updateEscalationPolicy,
  activateEscalationPolicy,
  deactivateEscalationPolicy,
  deleteEscalationPolicy,
  startEscalation,
  getEscalationInstance,
  listEscalationInstances,
  escalateInstance,
  resolveEscalation,
  getEscalationAuditLog,
  getActiveEscalationsCount,
  getEscalationStats,
  type EscalationDbInitResult,
  type EscalationPolicyStatus,
  type EscalationState,
  type EscalationTier,
  type EscalationPolicy,
  type EscalationInstance,
  type CreateEscalationPolicyOptions,
  type StartEscalationOptions,
  type EscalateResult,
  type EscalationAuditEntry,
} from "./escalation-policies.js";

// =============================================================================
// Security Metrics & KPIs (v1.28.0)
// =============================================================================

export {
  initMetricsDatabase,
  closeMetricsDatabase,
  getMetricsDatabase,
  getMetricsAuditLog,
  recordSnapshot,
  getSnapshot,
  getSnapshotsForTarget,
  getLatestSnapshot,
  recordVulnerabilityDiscovery,
  recordVulnerabilityResolution,
  getMTTRStats,
  getTrends,
  setMetricsBaseline,
  getMetricsBaseline,
  listMetricsBaselines,
  deleteMetricsBaseline,
  compareMetricsBaseline,
  getMetricsSummary,
  type MetricsSeverity,
  type MetricsTrendDirection,
  type SecuritySnapshot,
  type SnapshotMetrics,
  type VulnerabilityLifecycle,
  type MetricsBaseline,
  type MTTRStats,
  type TrendAnalysis,
  type BaselineComparison,
  type MetricsDbInitResult,
  type RecordMetricsSnapshotOptions,
  type GetMTTROptions,
  type GetTrendsOptions,
  type SetBaselineOptions,
  type MetricsAuditEntry,
  type MetricsSummary,
} from "./security-metrics.js";

// =============================================================================
// Integration Webhooks (v1.28.0)
// =============================================================================

export {
  // Database lifecycle
  initWebhooksDatabase,
  closeWebhooksDatabase,
  getWebhooksDatabase,
  // CRUD operations
  createWebhook,
  getWebhook,
  listWebhooks,
  updateWebhook,
  deleteWebhook,
  // Triggering
  triggerWebhooks,
  testWebhook,
  // Delivery history
  getDeliveryHistory,
  // Statistics
  getWebhookStats,
  // Cleanup
  cleanupOldDeliveries,
  // Audit
  getWebhooksAuditLog,
  // Signature utilities
  generateSignature,
  verifySignature,
  // Types
  type WebhookEventType,
  type WebhookStatus,
  type Webhook,
  type WebhookDelivery,
  type WebhookDbInitResult,
  type CreateWebhookOptions,
  type UpdateWebhookOptions,
  type TriggerWebhookOptions,
  type WebhookTestResult,
  type WebhookAuditEntry,
  type TriggerResult,
  type DeliveryHistoryOptions,
  type WebhookStats,
} from "./integration-webhooks.js";

// =============================================================================
// Asset Inventory (v1.28.0)
// =============================================================================

export {
  // Database lifecycle
  initAssetDatabase,
  closeAssetDatabase,
  getAssetDatabase,
  // Asset CRUD
  registerAsset,
  getAsset,
  getAssetByIdentifier,
  listAssets,
  updateAssetMetadata,
  deleteAsset,
  // Posture tracking
  recordAssetPosture,
  getAssetPosture,
  getAssetPostureHistory,
  // Stale detection
  findStaleAssets,
  getAssetScanAge,
  // Statistics
  getAssetSummary,
  // Bulk operations
  bulkRegisterAssets,
  bulkUpdateCriticality,
  getOrCreateAsset,
  linkScanToAsset,
  // Audit
  getAssetAuditLog,
  // Types
  type AssetType,
  type AssetCriticality as AssetInventoryCriticality,
  type ComplianceStatus as AssetComplianceStatus,
  type Asset,
  type AssetPosture,
  type SecurityFinding,
  type RegisterAssetOptions,
  type UpdateAssetMetadataOptions,
  type AssetListOptions,
  type RecordPostureOptions,
  type StaleAssetOptions,
  type AssetSummary,
  type AssetDbInitResult,
  type AssetAuditEntry,
} from "./asset-inventory.js";

// =============================================================================
// Kubernetes Security (v1.28.0)
// =============================================================================

export {
  // Cluster/Namespace scanning
  isKubectlAvailable,
  getClusterInfo,
  scanK8sCluster,
  scanK8sNamespace,
  getSecurityContexts,
  // RBAC analysis
  auditRbac,
  // Network Policy analysis
  analyzeNetworkPolicies,
  // Trivy K8s integration
  runTrivyK8sScan,
  // Types
  type K8sResourceType,
  type K8sSeverity,
  type K8sMisconfigCategory,
  type K8sMisconfiguration,
  type K8sSecurityContext,
  type K8sSecurityContextAnalysis,
  type K8sRbacRule,
  type K8sRbacBinding,
  type K8sRbacAuditResult,
  type K8sNetworkPolicy,
  type K8sNetworkPolicyAnalysis,
  type K8sClusterScanResult,
  type K8sNamespaceScanResult,
  type K8sScanOptions,
} from "./k8s-security.js";

// =============================================================================
// Container Runtime Security (v1.28.0)
// =============================================================================

export {
  // Database lifecycle
  initRuntimeDatabase,
  closeRuntimeDatabase,
  // Container scanning
  isDockerAvailable,
  listRunningContainers,
  scanRunningContainer,
  getContainerRuntimeState,
  // Anomaly detection
  detectAnomalies,
  createContainerBaseline,
  getContainerBaseline,
  getStoredAnomalies,
  // Security profiles
  generateSecurityProfile,
  // Audit logging
  getRuntimeAuditLog,
  // Types
  type RuntimeSeverity,
  type AnomalyType,
  type ProfileType,
  type ContainerInfo,
  type RuntimeVulnerability,
  type RuntimeScanResult,
  type ProcessInfo,
  type NetworkConnection,
  type ContainerRuntimeState,
  type RuntimeAnomaly,
  type AnomalyDetectionResult as RuntimeAnomalyResult,
  type SeccompProfile,
  type AppArmorProfile,
  type SecurityProfile,
  type ContainerBaseline,
  type RuntimeScanOptions,
  type ProfileGenerationOptions,
  type AnomalyDetectionOptions,
  type RuntimeDbInitResult,
} from "./runtime-security.js";

// =============================================================================
// Image Signing & Verification (v1.28.0)
// =============================================================================

export {
  // Database lifecycle
  initSigningDatabase,
  closeSigningDatabase,
  // Cosign operations
  isCosignInstalled,
  getCosignVersion,
  generateCosignKeyPair,
  cosignSign,
  cosignVerify,
  cosignAttest,
  cosignVerifyAttestation,
  // Notary operations
  isNotaryInstalled,
  notaryVerify,
  // Policy management
  createSigningPolicy,
  getSigningPolicy,
  listSigningPolicies,
  deleteSigningPolicy,
  checkPolicy,
  // Verification history
  getVerificationHistory,
  // Audit
  getSigningAuditLog,
  // Types
  type SignatureType,
  type VerificationStatus,
  type AttestationType,
  type ImageReference,
  type SignatureInfo,
  type VerificationResult,
  type AttestationInfo,
  type TrustChainInfo,
  type SigningOptions,
  type VerifyOptions,
  type AttestOptions,
  type CosignKeyPair,
  type SigningPolicy,
  type PolicyCheckResult,
  type SigningDbInitResult,
} from "./image-signing.js";

// =============================================================================
// Supply Chain Security (v1.28.0)
// =============================================================================

export {
  // Database lifecycle
  initSupplyChainDb,
  closeSupplyChainDb,
  getSupplyChainDb,
  // SLSA verification
  verifySlsaProvenance,
  // in-toto verification
  verifyInToto,
  // SBOM attestation
  verifySbomAttestation,
  // Policy management
  createSupplyChainPolicy,
  getSupplyChainPolicy,
  listSupplyChainPolicies,
  evaluateSupplyChainPolicy,
  // Trusted builders
  addTrustedBuilder,
  listTrustedBuilders,
  removeTrustedBuilder,
  // Audit & Summary
  getSupplyChainAuditLog,
  getSupplyChainSummary,
  // Types
  type SlsaLevel,
  type ProvenanceStatus,
  type AttestationFormat,
  type BuilderTrust,
  type SlsaProvenance,
  type SlsaVerificationResult,
  type InTotoStatement,
  type InTotoLink,
  type InTotoLayout,
  type InTotoKey,
  type InTotoStep,
  type InTotoInspection,
  type InTotoVerificationResult,
  type SbomAttestation,
  type SbomVerificationResult,
  type SupplyChainPolicy,
  type SupplyChainRule,
  type SupplyChainPolicyResult,
  type TrustedBuilder,
} from "./supply-chain.js";

// =============================================================================
// AI-Powered Security (v1.29.0)
// =============================================================================

// AI Security Analysis
export {
  // Client management
  initAIClient,
  // Vulnerability analysis
  analyzeVulnerability,
  analyzeVulnerabilities,
  // Code security
  analyzeCodeSecurity,
  // Remediation
  generateRemediationPlan,
  // Insights
  generateSecurityInsights,
  // Threat modeling
  generateThreatModel,
  // Risk scoring
  calculateRiskScore as calculateAIRiskScore,
  // Types
  type AIAnalysisConfig,
  type VulnerabilityAnalysis,
  type CodeSecurityAnalysis,
  type CodeSecurityFinding,
  type SecurityFindingType,
  type AIRemediationPlan,
  type RemediationStep,
  type SecurityInsight,
  type ThreatModelAnalysis,
  type ThreatEntry,
  type AttackSurfaceEntry,
  type MitigationRecommendation,
  type RiskScore as AIRiskScore,
} from "./ai-security.js";

// Threat Intelligence
export {
  // Database lifecycle
  initThreatIntelDb,
  closeThreatIntelDb,
  // CVE Enrichment
  getCveEnrichment,
  saveCveEnrichment,
  getVulnThreatContext,
  getBatchThreatContext,
  // Threat Feeds
  listThreatFeeds,
  addThreatFeed,
  setThreatFeedEnabled,
  updateFeedSyncStatus,
  // IOCs
  saveIOC,
  searchIOCs,
  checkIOC,
  deleteIOC,
  // Threat Actors
  saveThreatActor,
  getThreatActor,
  searchThreatActors,
  // Threat Reports
  saveThreatReport,
  searchThreatReports,
  // Statistics
  getThreatIntelStats,
  // Types
  type ThreatIntelConfig,
  type CVEEnrichment,
  type ExploitInfo,
  type ThreatFeed,
  type IOC,
  type IOCType,
  type ThreatActor,
  type ThreatReport,
  type VulnThreatContext,
  type ThreatIntelStats,
} from "./threat-intel.js";

// Natural Language Query
export {
  // Client management
  initNLQueryClient,
  // Query processing
  processNLQuery,
  executeStructuredQuery,
  // Suggestions
  getQuerySuggestions,
  // Conversation
  createConversationSession,
  sendConversationMessage,
  // Types
  type NLQueryConfig,
  type NLQueryContext,
  type NLQueryResult,
  type QueryIntent,
  type StructuredQuery,
  type QueryResultData,
  type VulnSummary,
  type PackageSummary,
  type TimelineEntry,
  type ComplianceStatus as NLComplianceStatus,
  type QuerySuggestion,
  type ConversationMessage,
  type ConversationSession,
} from "./nl-query.js";

// ============================================================================
// v1.30.0 - Enterprise Scale & Multi-Cloud Security
// ============================================================================

// Multi-Cloud Security Scanning
export {
  multiCloud,
  initMultiCloudDb,
  // Credentials
  saveCloudCredentials,
  getCloudCredentials,
  listCloudCredentials,
  deleteCloudCredentials,
  // AWS
  scanAwsEcr,
  scanAwsEcs,
  scanAwsLambda,
  getAwsSecurityHubFindings,
  // Azure
  scanAzureAcr,
  scanAzureAks,
  getAzureDefenderAlerts,
  // GCP
  scanGcpGcr,
  scanGcpGke,
  getGcpSccFindings,
  // Unified
  saveCloudFinding,
  getCloudFindings,
  recordCloudPosture,
  compareCloudPosture,
  getMultiCloudDashboard,
  // Types
  type CloudProvider,
  type CloudCredentials,
  type CloudRegistry,
  type CloudSecurityFinding,
  type CloudPostureScore,
  type MultiCloudDashboard,
  type AwsEcrScanResult,
  type AwsEcsScanResult,
  type AwsLambdaScanResult,
  type AzureAcrScanResult,
  type AzureAksScanResult,
  type GcpGcrScanResult,
  type GcpGkeScanResult,
} from "./multi-cloud.js";

// High Availability & Resilience
export {
  highAvailability,
  initHaDb,
  // Node management
  registerNode,
  getNode,
  listNodes,
  removeNode,
  updateNodeStatus,
  recordHeartbeat,
  initializeLocalNode,
  // Cluster status
  getClusterStatus,
  getReplicationStatus,
  // Failover
  getFailoverConfig,
  setFailoverConfig,
  promoteNode,
  demoteNode,
  testFailover,
  getFailoverHistory,
  // Split brain
  detectSplitBrain,
  // Types
  type NodeRole,
  type NodeStatus,
  type ClusterHealth,
  type ClusterNode,
  type ClusterStatus,
  type ReplicationStatus,
  type FailoverConfig,
  type FailoverEvent,
  type SplitBrainStatus,
} from "./high-availability.js";

// Backup & Disaster Recovery
export {
  backup,
  initBackupDb,
  createBackup,
  listBackups,
  getBackup,
  deleteBackup,
  restoreBackup,
  verifyBackup,
  createBackupSchedule,
  listBackupSchedules,
  exportBackupOffsite,
  cleanupExpiredBackups,
  // Types
  type BackupStatus,
  type BackupType,
  type StorageProvider,
  type BackupMetadata,
  type BackupSchedule,
  type RestoreResult,
  type BackupVerification,
  type OffsiteExport,
} from "./backup.js";

// Resource Quotas & Limits
export {
  quotas,
  initQuotasDb,
  setQuota,
  getQuota,
  listQuotas,
  deleteQuota,
  getQuotaUsage,
  incrementUsage,
  checkQuota,
  listBreaches,
  resolveBreach,
  listAlerts as listQuotaAlerts,
  acknowledgeAlert,
  getQuotaSummary,
  // Types
  type QuotaType,
  type QuotaScope,
  type QuotaConfig,
  type QuotaUsage,
  type QuotaBreach,
  type QuotaAlert,
} from "./quotas.js";

// Performance Optimization
export {
  performance,
  initPerformanceDb,
  recordMetrics as recordPerfMetrics,
  getMetrics as getPerfMetrics,
  getAggregatedMetrics,
  recordSlowQuery,
  analyzeSlowQueries,
  suggestIndexes,
  applyIndexSuggestion,
  recordCacheStats as recordPerfCacheStats,
  getCacheStats as getPerfCacheStats,
  warmupCache,
  getPerformanceSummary,
  // Types
  type PerformanceMetrics,
  type SlowQuery,
  type IndexSuggestion,
  type CacheStats as PerfCacheStats,
} from "./performance.js";

// =============================================================================
// v1.31.0 - GitOps & Zero-Trust Security
// =============================================================================

// GitOps Integration
export {
  gitops,
  initGitOpsDb,
  registerRepository as registerGitOpsRepo,
  listRepositories as listGitOpsRepos,
  getRepository as getGitOpsRepo,
  scanRepository as scanGitOpsRepo,
  validateManifests,
  createSecurityGate,
  getSecurityGate,
  listSecurityGates,
  evaluateSecurityGate,
  getSyncStatus as getGitOpsSyncStatus,
  checkDrift,
  scanHelmChart,
  recordDeployment,
  getDeploymentHistory,
  checkPromotionSafety,
  checkRollbackSafety,
  // Types
  type GitOpsProvider,
  type GateStatus,
  type ManifestType,
  type GitOpsConfig,
  type GitOpsRepository,
  type ManifestScanResult,
  type ManifestIssue,
  type SecurityGate,
  type GateRule,
  type GateEvaluation,
  type SyncStatus as GitOpsSyncStatus,
  type DriftDetection,
  type HelmChartScan,
  type DeploymentHistory,
} from "./gitops.js";

// Zero-Trust Security
export {
  zeroTrust,
  initZeroTrustDb,
  verifyImageSignature as verifyZtImageSignature,
  verifySbomAttestation as verifyZtSbomAttestation,
  checkProvenance,
  recordProvenance,
  getSlsaLevel as getZtSlsaLevel,
  getTrustChain,
  createAttestation as createZtAttestation,
  verifyAttestation as verifyZtAttestation,
  createZtPolicy,
  getZtPolicy,
  listZtPolicies,
  evaluateZtPolicy,
  keylessSign,
  queryTransparencyLog,
  // Types
  type SlsaLevel as ZtSlsaLevel,
  type AttestationType as ZtAttestationType,
  type SignatureType as ZtSignatureType,
  type ImageSignature as ZtImageSignature,
  type Attestation as ZtAttestation,
  type ProvenanceRecord,
  type TrustChain,
  type ZeroTrustPolicy,
  type ZeroTrustRule,
  type PolicyEvaluation as ZtPolicyEvaluation,
  type TransparencyLogEntry,
} from "./zero-trust.js";

// Service Mesh Security
export {
  serviceMesh,
  initMeshDb,
  scanMeshConfig,
  getMtlsStatus,
  auditAuthorizationPolicies,
  createMeshPolicy,
  listPolicies as listMeshPolicies,
  checkCertExpiry,
  analyzeTrafficPolicies,
  checkSidecarVersions,
  checkMeshCves,
  getSecureUpgradePath,
  getMeshSecuritySummary,
  // Types
  type MeshProvider,
  type MtlsMode,
  type PolicyAction as MeshPolicyAction,
  type MeshConfig,
  type MeshScanResult,
  type MeshIssue,
  type MtlsStatus,
  type AuthorizationPolicy,
  type PolicyAuditResult,
  type CertificateInfo,
  type TrafficPolicy,
  type SidecarInfo,
  type MeshCveInfo,
  type UpgradePath,
} from "./service-mesh.js";

// API Security Gateway
export {
  apiSecurity,
  initApiSecurityDb,
  scanOpenApiSpec,
  scanGraphQlSchema,
  auditApiAuth,
  auditRateLimits,
  testForInjection,
  createApiPolicy,
  listApiPolicies,
  checkOwaspApiTop10,
  // Types
  type ApiType,
  type AuthMethod,
  type OwaspCategory,
  type ApiSpec,
  type ApiScanResult,
  type ApiFinding,
  type AuthAuditResult,
  type RateLimitConfig,
  type RateLimitAudit,
  type InjectionTestResult,
  type ApiPolicy,
  type OwaspApiTop10Check,
} from "./api-security.js";
