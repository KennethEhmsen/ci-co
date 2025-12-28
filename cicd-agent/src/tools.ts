import Anthropic from "@anthropic-ai/sdk";
import {
  // Handlers
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
  sonarGetProjects,
  sonarGetIssues,
  sonarGetSecurityHotspots,
  sonarGetMetrics,
  sonarGetQualityGateStatus,
  dtrackGetProjects,
  dtrackGetVulnerabilities,
  dtrackGetFindings,
  dtrackGetComponents,
  dtrackUploadSbom,
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
  droneGetRepos,
  droneGetBuilds,
  droneGetBuild,
  droneGetBuildLogs,
  droneTriggerBuild,
  registryGetCatalog,
  registryGetTags,
  checkPlatformStatus,
  getSecurityDashboard,
  // Compliance
  getComplianceFrameworks,
  getComplianceControls,
  getComplianceControl,
  generateComplianceReport,
  generateComplianceHtml,
  recordComplianceTrend,
  getComplianceTrend,
  getComplianceTrendTargets,
  checkComplianceStatus,
  // OPA/Rego
  listBuiltinPolicies,
  getBuiltinPolicyInfo,
  getBuiltinPolicy,
  validateRegoSyntax,
  evaluatePolicyWithScan,
  // Scheduler
  validateCronExpression,
  describeCronExpression,
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
  clearAllSchedules,
  // Vulnerability Database
  initVulnDatabase,
  isVulnDbInitialized,
  lookupVulnerability,
  searchVulnerabilities,
  getVulnDbStats,
  annotateVulnerability,
  // Database Sync
  getTrivyDbStatus,
  syncVulnDatabase,
  isOfflineScanAvailable,
  // Offline Scanner
  offlineScanImage,
  offlineScanPath,
  getOfflineScanCapabilities,
  // Suppression Database
  initSuppressionDatabase,
  isSuppressionDbInitialized,
  createDbSuppression,
  getDbSuppression,
  listDbSuppressions,
  deleteDbSuppression,
  getSuppressionAuditLog,
  getSuppressionDbStats,
  applyDbSuppressions,
  // Prometheus Metrics
  getMetrics,
  getMetricsSnapshot,
  pushToGateway,
  deleteFromGateway,
  recordScanMetrics,
  resetMetrics,
  // Scan Comparison
  compareTrivyScans,
  getScanHistory,
  storeTrivyScan,
  storeAndCompare,
  // SSO Configuration
  initSsoDatabase,
  configureSamlProvider,
  configureOidcProvider,
  getSsoProvider,
  listSsoProviders,
  deleteSsoProvider,
  setSsoProviderEnabled,
  getSsoSession,
  validateSsoSession,
  terminateSsoSession,
  terminateAllUserSessions,
  listUserSessions,
  listAllSessions,
  cleanupExpiredSessions,
  getSsoAuditEvents,
  // SSO SAML
  generateSpMetadata,
  validateSamlAssertion,
  generateSamlLogoutRequest,
  // SSO OIDC
  validateOidcToken,
  validateOidcTokenByIssuer,
  refreshOidcToken,
  getOidcUserInfo,
  // RBAC
  initRbacDatabase,
  isRbacDbInitialized,
  createRole,
  getRoleByName,
  listRoles,
  listPermissions,
  assignRoleToUser,
  getUserRoles,
  checkPermission,
  listUserPermissions,
  // API Key Management
  VALID_SCOPES,
  initApiKeyDatabase,
  isApiKeyDbInitialized,
  createApiKey,
  listApiKeys,
  revokeApiKey,
  rotateApiKey,
  // Types
  type ComplianceFramework,
  type CreateScheduleInput,
  type UpdateScheduleInput,
  type ListSchedulesOptions,
  type SuppressionType,
  type SsoSession,
} from "@cicd/shared";

// Re-export validation functions and config for tests
export { validateSeverity, sanitizePath, sanitizeImageName, config } from "@cicd/shared";

// =============================================================================
// Tool Handler Map
// =============================================================================
type ToolHandler = (input: Record<string, unknown>) => Promise<unknown>;

const toolHandlers: Record<string, ToolHandler> = {
  // Trivy
  trivy_scan_path: async (input) => trivyScanPath(input.path as string, input.severity as string),
  trivy_scan_image: async (input) =>
    trivyScanImage(input.image as string, input.severity as string),
  trivy_generate_sbom: async (input) =>
    trivyGenerateSbom(input.path as string, input.format as "cyclonedx" | "spdx-json"),
  trivy_generate_sbom_image: async (input) =>
    trivyGenerateSbomImage(input.image as string, input.format as "cyclonedx" | "spdx-json"),
  trivy_scan_iac: async (input) => trivyScanIac(input.path as string, input.severity as string),
  trivy_scan_secrets: async (input) =>
    trivyScanSecrets(input.path as string, input.severity as string),
  trivy_scan_secrets_image: async (input) =>
    trivyScanSecretsImage(input.image as string, input.severity as string),
  trivy_scan_licenses: async (input) =>
    trivyScanLicenses(input.path as string, input.severity as string),
  trivy_scan_licenses_image: async (input) =>
    trivyScanLicensesImage(input.image as string, input.severity as string),
  trivy_scan_image_full: async (input) =>
    trivyScanImageFull(
      input.image as string,
      input.severity as string,
      input.sbomFormat as "cyclonedx" | "spdx-json"
    ),
  trivy_scan_path_full: async (input) =>
    trivyScanPathFull(
      input.path as string,
      input.severity as string,
      input.sbomFormat as "cyclonedx" | "spdx-json"
    ),
  // SonarQube
  sonar_list_projects: async () => sonarGetProjects(),
  sonar_get_issues: async (input) =>
    sonarGetIssues(input.projectKey as string, input.types as string),
  sonar_get_security_hotspots: async (input) =>
    sonarGetSecurityHotspots(input.projectKey as string),
  sonar_get_metrics: async (input) => sonarGetMetrics(input.projectKey as string),
  sonar_get_quality_gate_status: async (input) =>
    sonarGetQualityGateStatus(input.projectKey as string),
  // Dependency-Track
  dtrack_list_projects: async () => dtrackGetProjects(),
  dtrack_get_vulnerabilities: async (input) =>
    dtrackGetVulnerabilities(input.projectUuid as string),
  dtrack_get_findings: async (input) => dtrackGetFindings(input.projectUuid as string),
  dtrack_get_components: async (input) => dtrackGetComponents(input.projectUuid as string),
  dtrack_upload_sbom: async (input) =>
    dtrackUploadSbom(
      input.projectName as string,
      input.projectVersion as string,
      input.sbom as string,
      input.autoCreate as boolean
    ),
  // Gitea
  gitea_list_repos: async () => giteaGetRepos(),
  gitea_get_repo: async (input) => giteaGetRepo(input.owner as string, input.repo as string),
  gitea_get_branches: async (input) =>
    giteaGetBranches(input.owner as string, input.repo as string),
  gitea_get_commits: async (input) =>
    giteaGetCommits(input.owner as string, input.repo as string, input.limit as number),
  gitea_create_repo: async (input) =>
    giteaCreateRepo(input.name as string, input.description as string, input.private as boolean),
  gitea_migrate_repo: async (input) =>
    giteaMigrateRepo(input.cloneUrl as string, input.repoName as string, input.authToken as string),
  gitea_list_pull_requests: async (input) =>
    giteaListPullRequests(
      input.owner as string,
      input.repo as string,
      input.state as "open" | "closed" | "all" | undefined
    ),
  gitea_get_pull_request: async (input) =>
    giteaGetPullRequest(input.owner as string, input.repo as string, input.pullNumber as number),
  gitea_create_pull_request: async (input) =>
    giteaCreatePullRequest(
      input.owner as string,
      input.repo as string,
      input.title as string,
      input.head as string,
      input.base as string,
      input.body as string
    ),
  gitea_merge_pull_request: async (input) =>
    giteaMergePullRequest(
      input.owner as string,
      input.repo as string,
      input.pullNumber as number,
      input.mergeStyle as "merge" | "rebase" | "squash"
    ),
  gitea_create_issue: async (input) =>
    giteaCreateIssue(
      input.owner as string,
      input.repo as string,
      input.title as string,
      input.body as string,
      input.labels as string[]
    ),
  gitea_list_issues: async (input) =>
    giteaListIssues(
      input.owner as string,
      input.repo as string,
      input.state as "open" | "closed" | "all" | undefined
    ),
  // Drone
  drone_list_repos: async () => droneGetRepos(),
  drone_get_builds: async (input) => droneGetBuilds(input.owner as string, input.repo as string),
  drone_get_build: async (input) =>
    droneGetBuild(input.owner as string, input.repo as string, input.build as number),
  drone_get_build_logs: async (input) =>
    droneGetBuildLogs(
      input.owner as string,
      input.repo as string,
      input.build as number,
      input.stage as number,
      input.step as number
    ),
  drone_trigger_build: async (input) =>
    droneTriggerBuild(input.owner as string, input.repo as string, input.branch as string),
  // Registry
  registry_list_images: async () => registryGetCatalog(),
  registry_get_tags: async (input) => registryGetTags(input.image as string),
  // Platform
  check_platform_status: async () => checkPlatformStatus(),
  // Security Dashboard
  get_security_dashboard: async (input) =>
    getSecurityDashboard({
      image: input.image as string | undefined,
      path: input.path as string | undefined,
      sonarProject: input.sonarProject as string | undefined,
      dtrackProjectUuid: input.dtrackProjectUuid as string | undefined,
      severity: input.severity as string | undefined,
    }),
  // Compliance
  compliance_get_frameworks: async () => getComplianceFrameworks(),
  compliance_get_controls: async (input) => {
    const framework = input.framework as ComplianceFramework;
    const controlId = input.controlId as string | undefined;
    if (controlId) {
      return getComplianceControl(framework, controlId);
    }
    return getComplianceControls(framework);
  },
  compliance_check_status: async (input) => {
    const dashboardResult = await getSecurityDashboard({
      image: input.image as string | undefined,
      path: input.path as string | undefined,
      sonarProject: input.sonarProject as string | undefined,
      dtrackProjectUuid: input.dtrackProjectUuid as string | undefined,
      severity: input.severity as string | undefined,
    });
    return checkComplianceStatus(dashboardResult, {
      frameworks: input.frameworks as ComplianceFramework[] | undefined,
      severity: input.severity as string | undefined,
    });
  },
  compliance_generate_report: async (input) => {
    const dashboardResult = await getSecurityDashboard({
      image: input.image as string | undefined,
      path: input.path as string | undefined,
      sonarProject: input.sonarProject as string | undefined,
      dtrackProjectUuid: input.dtrackProjectUuid as string | undefined,
      severity: input.severity as string | undefined,
    });
    const options = {
      frameworks: input.frameworks as ComplianceFramework[] | undefined,
      title: input.title as string | undefined,
      organization: input.organization as string | undefined,
    };
    const report = generateComplianceReport(dashboardResult, options);
    if (input.format === "html") {
      return { html: generateComplianceHtml(report, options) };
    }
    return report;
  },
  compliance_trend_record: async (input) => {
    const target = input.target as string;
    const dashboardResult = await getSecurityDashboard({
      image: input.image as string | undefined,
      path: input.path as string | undefined,
      sonarProject: input.sonarProject as string | undefined,
      dtrackProjectUuid: input.dtrackProjectUuid as string | undefined,
      severity: input.severity as string | undefined,
    });
    const report = generateComplianceReport(dashboardResult, {
      frameworks: input.frameworks as ComplianceFramework[] | undefined,
    });
    return recordComplianceTrend(target, report);
  },
  compliance_trend_get: async (input) => {
    const target = input.target as string;
    const days = (input.days as number) || 30;
    return getComplianceTrend(target, days);
  },
  compliance_trend_list_targets: async () => getComplianceTrendTargets(),
  // OPA/Rego
  opa_list_policies: async () => {
    const policies = listBuiltinPolicies();
    return { count: policies.length, policies };
  },
  opa_get_policy_info: async (input) => {
    const name = input.name as string;
    if (!name) {
      return { error: "name is required" };
    }
    const info = getBuiltinPolicyInfo(name);
    if (!info) {
      return {
        error: `Policy '${name}' not found. Available policies: vulnerability-threshold, license-compliance, secrets-detection, container-security, quality-gate`,
      };
    }
    const source = getBuiltinPolicy(name);
    return { ...info, source };
  },
  opa_validate_policy: async (input) => {
    const policy = input.policy as string;
    if (!policy) {
      return { error: "policy is required" };
    }
    return validateRegoSyntax(policy);
  },
  opa_evaluate_policy: async (input) => {
    const policy = input.policy as string;
    if (!policy) {
      return { error: "policy is required" };
    }

    return evaluatePolicyWithScan({
      policy,
      severity: input.severity as string | undefined,
      image: input.image as string | undefined,
      path: input.path as string | undefined,
      licenses: input.licenses as string[] | undefined,
      secretsFound: input.secretsFound as boolean | undefined,
      codeCoverage: input.codeCoverage as number | undefined,
      qualityGatePassed: input.qualityGatePassed as boolean | undefined,
      thresholds: input.thresholds as {
        critical?: number;
        high?: number;
        medium?: number;
        low?: number;
        coverage?: number;
      },
    });
  },
  // Scheduler
  schedule_create: async (input) => {
    // Convert single target to targets array for API compatibility
    const target = input.target as { type: string; value: string; severity?: string } | undefined;
    const targets = input.targets as CreateScheduleInput["targets"] | undefined;

    const scheduleInput: CreateScheduleInput = {
      name: input.name as string,
      cron: input.cron as string,
      targets:
        targets ||
        (target
          ? [{ type: target.type as "image" | "path" | "registry", target: target.value }]
          : []),
      enabled: input.enabled as boolean | undefined,
      timezone: input.timezone as string | undefined,
      options: target?.severity
        ? { severity: target.severity }
        : (input.options as CreateScheduleInput["options"]),
      notifications: input.notifications as CreateScheduleInput["notifications"],
    };
    return createSchedule(scheduleInput);
  },
  schedule_list: async (input) => {
    const options: ListSchedulesOptions = {
      enabled: input.enabled as boolean | undefined,
      targetType: input.targetType as "image" | "path" | "registry" | undefined,
    };
    return listSchedules(options);
  },
  schedule_get: async (input) => {
    const id = input.id as string;
    if (!id) {
      return { error: "id is required" };
    }
    return getSchedule(id);
  },
  schedule_update: async (input) => {
    const id = input.id as string;
    if (!id) {
      return { error: "id is required" };
    }
    // Convert single target to targets array for API compatibility
    const target = input.target as { type: string; value: string; severity?: string } | undefined;
    const targets = input.targets as UpdateScheduleInput["targets"] | undefined;

    const updates: UpdateScheduleInput = {
      name: input.name as string | undefined,
      cron: input.cron as string | undefined,
      targets:
        targets ||
        (target
          ? [{ type: target.type as "image" | "path" | "registry", target: target.value }]
          : undefined),
      enabled: input.enabled as boolean | undefined,
      timezone: input.timezone as string | undefined,
      options: target?.severity
        ? { severity: target.severity }
        : (input.options as UpdateScheduleInput["options"]),
      notifications: input.notifications as UpdateScheduleInput["notifications"],
    };
    return updateSchedule(id, updates);
  },
  schedule_delete: async (input) => {
    const id = input.id as string;
    if (!id) {
      return { error: "id is required" };
    }
    return deleteSchedule(id);
  },
  schedule_trigger: async (input) => {
    const id = input.id as string;
    if (!id) {
      return { error: "id is required" };
    }
    return triggerSchedule(id);
  },
  schedule_history: async (input) => {
    const id = input.id as string;
    if (!id) {
      return { error: "id is required" };
    }
    const limit = (input.limit as number) || 10;
    return getScheduleHistory(id, limit);
  },
  cron_validate: async (input) => {
    const expression = input.expression as string;
    if (!expression) {
      return { error: "expression is required" };
    }
    const result = validateCronExpression(expression);
    if (!result.valid || !result.parsed) {
      return result;
    }
    // Add additional info using the parsed expression
    const description = describeCronExpression(result.parsed);
    const nextRuns = getNextRunTimes(expression, 5);
    return {
      valid: true,
      description,
      nextRuns: nextRuns.map((d) => d.toISOString()),
    };
  },
  scheduler_control: async (input) => {
    const action = input.action as string;
    if (action === "start") {
      return startScheduler();
    }
    if (action === "stop") {
      return stopScheduler();
    }
    if (action === "clear") {
      return clearAllSchedules();
    }
    return { error: "Invalid action. Use 'start', 'stop', or 'clear'" };
  },

  // Vulnerability Database
  vuln_db_sync: async (input) => {
    if (!isVulnDbInitialized()) {
      const initResult = initVulnDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize database: ${initResult.error}` };
      }
    }

    const result = await syncVulnDatabase({
      force: input?.force as boolean | undefined,
      skipIfRecent: input?.skipIfRecent as number | undefined,
    });
    return result;
  },

  vuln_db_status: async () => {
    const trivyStatus = await getTrivyDbStatus();
    const offlineAvailable = await isOfflineScanAvailable();
    const capabilities = await getOfflineScanCapabilities();

    let dbStats = null;
    if (isVulnDbInitialized()) {
      dbStats = getVulnDbStats();
    }

    return {
      trivyDatabase: trivyStatus,
      offlineScanAvailable: offlineAvailable.available,
      capabilities,
      localCache: dbStats,
    };
  },

  vuln_db_lookup: async (input) => {
    const id = input?.id as string;
    if (!id) {
      return { error: "id is required" };
    }

    if (!isVulnDbInitialized()) {
      const initResult = initVulnDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize database: ${initResult.error}` };
      }
    }

    const vuln = lookupVulnerability(id);
    if (!vuln) {
      return { error: `Vulnerability ${id} not found in local database` };
    }

    return vuln;
  },

  vuln_db_search: async (input) => {
    if (!isVulnDbInitialized()) {
      const initResult = initVulnDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize database: ${initResult.error}` };
      }
    }

    const result = searchVulnerabilities({
      packageName: input?.packageName as string | undefined,
      ecosystem: input?.ecosystem as string | undefined,
      severity: input?.severity as string[] | undefined,
      cvePattern: input?.cvePattern as string | undefined,
      limit: input?.limit as number | undefined,
      offset: input?.offset as number | undefined,
    });

    return result;
  },

  trivy_scan_offline: async (input) => {
    const image = input?.image as string | undefined;
    const path = input?.path as string | undefined;

    if (!image && !path) {
      return { error: "Either image or path is required" };
    }

    const options = {
      severity: input?.severity as string | undefined,
      ignoreUnfixed: input?.ignoreUnfixed as boolean | undefined,
    };

    if (image) {
      return offlineScanImage(image, options as Parameters<typeof offlineScanImage>[1]);
    } else {
      return offlineScanPath(path!, options as Parameters<typeof offlineScanPath>[1]);
    }
  },

  vuln_db_annotate: async (input) => {
    const vulnId = input?.vulnId as string;
    const status = input?.status as "acknowledged" | "false_positive" | "mitigated" | "active";
    const notes = input?.notes as string | undefined;

    if (!vulnId) {
      return { error: "vulnId is required" };
    }
    if (!status) {
      return { error: "status is required" };
    }

    if (!isVulnDbInitialized()) {
      const initResult = initVulnDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize database: ${initResult.error}` };
      }
    }

    const result = annotateVulnerability(vulnId, status, notes);
    return result;
  },

  // Suppression Management
  suppression_create: async (input) => {
    if (!isSuppressionDbInitialized()) {
      const initResult = initSuppressionDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize suppression database: ${initResult.error}` };
      }
    }

    const type = input?.type as SuppressionType;
    const pattern = input?.pattern as string;
    const reason = input?.reason as string;

    if (!type || !pattern || !reason) {
      return { error: "type, pattern, and reason are required" };
    }

    const result = createDbSuppression(type, pattern, reason, {
      expires: input?.expires as string | undefined,
      createdBy: input?.createdBy as string | undefined,
      notes: input?.notes as string | undefined,
    });

    if (!result.success) {
      return { error: result.error };
    }

    return {
      success: true,
      suppression: result.suppression,
      message: `Created ${type} suppression for pattern "${pattern}"`,
    };
  },

  suppression_list: async (input) => {
    if (!isSuppressionDbInitialized()) {
      const initResult = initSuppressionDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize suppression database: ${initResult.error}` };
      }
    }

    const result = listDbSuppressions({
      type: input?.type as SuppressionType | undefined,
      status: input?.status as "active" | "expired" | undefined,
      pattern: input?.pattern as string | undefined,
      createdBy: input?.createdBy as string | undefined,
      includeExpired: input?.includeExpired as boolean | undefined,
      limit: input?.limit as number | undefined,
      offset: input?.offset as number | undefined,
    });

    const stats = getSuppressionDbStats();

    return {
      suppressions: result.suppressions,
      total: result.total,
      stats: {
        active: stats.active,
        expired: stats.expired,
        byType: stats.byType,
      },
    };
  },

  suppression_delete: async (input) => {
    if (!isSuppressionDbInitialized()) {
      const initResult = initSuppressionDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize suppression database: ${initResult.error}` };
      }
    }

    const id = input?.id as string;
    if (!id) {
      return { error: "id is required" };
    }

    const suppression = getDbSuppression(id);
    if (!suppression) {
      return { error: `Suppression not found: ${id}` };
    }

    const result = deleteDbSuppression(id, input?.deletedBy as string | undefined);

    if (!result.success) {
      return { error: result.error };
    }

    return {
      success: true,
      deleted: {
        id: suppression.id,
        type: suppression.type,
        pattern: suppression.pattern,
      },
      message: `Deleted suppression for pattern "${suppression.pattern}"`,
    };
  },

  suppression_audit: async (input) => {
    if (!isSuppressionDbInitialized()) {
      const initResult = initSuppressionDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize suppression database: ${initResult.error}` };
      }
    }

    const result = getSuppressionAuditLog({
      suppressionId: input?.suppressionId as string | undefined,
      action: input?.action as
        | "created"
        | "updated"
        | "deleted"
        | "applied"
        | "expired"
        | undefined,
      user: input?.user as string | undefined,
      since: input?.since as string | undefined,
      until: input?.until as string | undefined,
      limit: input?.limit as number | undefined,
    });

    return {
      entries: result.entries,
      total: result.total,
    };
  },

  suppression_apply: async (input) => {
    if (!isSuppressionDbInitialized()) {
      const initResult = initSuppressionDatabase();
      if (!initResult.success) {
        return { error: `Failed to initialize suppression database: ${initResult.error}` };
      }
    }

    const scanResult = input?.scanResult as Record<string, unknown>;
    if (!scanResult) {
      return { error: "scanResult is required" };
    }

    const result = applyDbSuppressions(scanResult as Parameters<typeof applyDbSuppressions>[0], {
      includeExpired: input?.includeExpired as boolean | undefined,
      user: input?.user as string | undefined,
      audit: input?.audit as boolean | undefined,
    });

    return {
      result: result.result,
      summary: result.suppressionResult.summary,
      appliedSuppressions: result.suppressionResult.appliedSuppressions.map((s) => ({
        suppressionId: s.suppression.id,
        type: s.suppression.type,
        pattern: s.suppression.pattern,
        vulnerabilityId: s.vulnerabilityId,
        package: s.package,
      })),
      suppressed: result.suppressionResult.suppressed.map((v) => ({
        id: v.id,
        package: v.package,
        severity: v.severity,
        reason: v.suppression.reason,
      })),
    };
  },

  // Prometheus Metrics
  metrics_get: async (input) => {
    const format = (input?.format as string) || "prometheus";

    if (format === "json") {
      const snapshot = getMetricsSnapshot();
      return {
        format: "json",
        timestamp: snapshot.timestamp,
        metrics: snapshot.metrics.map((m) => ({
          name: m.definition.name,
          type: m.definition.type,
          help: m.definition.help,
          values: m.values,
        })),
      };
    }

    const prometheusOutput = getMetrics();
    return {
      format: "prometheus",
      contentType: "text/plain; version=0.0.4; charset=utf-8",
      data: prometheusOutput,
    };
  },

  metrics_record_scan: async (input) => {
    const target = input?.target as string;
    const type = input?.type as "image" | "path";
    const durationSeconds = input?.durationSeconds as number;
    const success = input?.success as boolean;

    if (!target || !type || durationSeconds === undefined || success === undefined) {
      return { error: "target, type, durationSeconds, and success are required" };
    }

    const vulns = input?.vulnerabilities as
      | { critical?: number; high?: number; medium?: number; low?: number }
      | undefined;

    recordScanMetrics({
      target,
      type,
      durationSeconds,
      success,
      vulnerabilities: vulns
        ? {
            critical: vulns.critical || 0,
            high: vulns.high || 0,
            medium: vulns.medium || 0,
            low: vulns.low || 0,
          }
        : undefined,
      error: input?.error as string | undefined,
    });

    return {
      success: true,
      message: `Recorded metrics for ${type} scan of ${target}`,
      recorded: {
        target,
        type,
        durationSeconds,
        success,
        vulnerabilities: vulns,
      },
    };
  },

  metrics_push: async (input) => {
    const url = input?.url as string;
    const job = input?.job as string;

    if (!url || !job) {
      return { error: "url and job are required" };
    }

    const result = await pushToGateway({
      url,
      job,
      instance: input?.instance as string | undefined,
      username: input?.username as string | undefined,
      password: input?.password as string | undefined,
      labels: input?.labels as Record<string, string> | undefined,
    });

    if (result.success) {
      return {
        success: true,
        message: `Pushed metrics to ${url} for job ${job}`,
        statusCode: result.statusCode,
      };
    }

    return {
      success: false,
      error: result.error,
      statusCode: result.statusCode,
    };
  },

  metrics_delete: async (input) => {
    const url = input?.url as string;
    const job = input?.job as string;

    if (!url || !job) {
      return { error: "url and job are required" };
    }

    const result = await deleteFromGateway({
      url,
      job,
      instance: input?.instance as string | undefined,
      username: input?.username as string | undefined,
      password: input?.password as string | undefined,
    });

    if (result.success) {
      return {
        success: true,
        message: `Deleted metrics from ${url} for job ${job}`,
        statusCode: result.statusCode,
      };
    }

    return {
      success: false,
      error: result.error,
      statusCode: result.statusCode,
    };
  },

  metrics_reset: async () => {
    resetMetrics();
    return {
      success: true,
      message: "All metrics have been reset",
    };
  },

  // Scan Comparison
  scan_compare: async (input) => {
    const current = input?.current as Record<string, unknown>;
    const baseline = input?.baseline as Record<string, unknown>;

    if (!current || !baseline) {
      return { error: "current and baseline scan results are required" };
    }

    const result = compareTrivyScans(
      current as Parameters<typeof compareTrivyScans>[0],
      baseline as Parameters<typeof compareTrivyScans>[1],
      {
        minSeverity: input?.minSeverity as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | undefined,
        includeUnchanged: input?.includeUnchanged as boolean | undefined,
      }
    );

    return {
      timestamp: result.timestamp,
      current: result.current,
      baseline: result.baseline,
      summary: result.summary,
      newVulnerabilities: result.newVulnerabilities,
      fixedVulnerabilities: result.fixedVulnerabilities,
      unchangedCount: result.unchangedVulnerabilities.length,
    };
  },

  scan_store: async (input) => {
    const scanResult = input?.scanResult as Record<string, unknown>;
    if (!scanResult) {
      return { error: "scanResult is required" };
    }

    const record = storeTrivyScan(
      scanResult as Parameters<typeof storeTrivyScan>[0],
      input?.identifier as string | undefined
    );

    return {
      success: true,
      record: {
        id: record.id,
        target: record.target,
        scannedAt: record.scannedAt,
        identifier: record.identifier,
        summary: record.summary,
      },
      message: `Stored scan for ${record.target} with ${record.summary.total} vulnerabilities`,
    };
  },

  scan_compare_with_previous: async (input) => {
    const scanResult = input?.scanResult as Record<string, unknown>;
    if (!scanResult) {
      return { error: "scanResult is required" };
    }

    const { record, diff } = storeAndCompare(
      scanResult as Parameters<typeof storeAndCompare>[0],
      input?.identifier as string | undefined,
      {
        minSeverity: input?.minSeverity as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | undefined,
        includeUnchanged: input?.includeUnchanged as boolean | undefined,
      }
    );

    if (!diff) {
      return {
        success: true,
        isFirstScan: true,
        record: {
          id: record.id,
          target: record.target,
          scannedAt: record.scannedAt,
          identifier: record.identifier,
          summary: record.summary,
        },
        message: `First scan for ${record.target}. Stored for future comparison.`,
      };
    }

    return {
      success: true,
      isFirstScan: false,
      record: {
        id: record.id,
        target: record.target,
        scannedAt: record.scannedAt,
        identifier: record.identifier,
        summary: record.summary,
      },
      diff: {
        timestamp: diff.timestamp,
        current: diff.current,
        baseline: diff.baseline,
        summary: diff.summary,
        newVulnerabilities: diff.newVulnerabilities,
        fixedVulnerabilities: diff.fixedVulnerabilities,
        unchangedCount: diff.unchangedVulnerabilities.length,
      },
    };
  },

  scan_history_list: async (input) => {
    const target = input?.target as string;
    if (!target) {
      return { error: "target is required" };
    }

    const limit = input?.limit as number | undefined;
    const history = getScanHistory();
    const records = history.getHistory(target, limit);

    return {
      target,
      count: records.length,
      records: records.map((r) => ({
        id: r.id,
        target: r.target,
        scannedAt: r.scannedAt,
        identifier: r.identifier,
        summary: r.summary,
      })),
    };
  },

  scan_history_get: async (input) => {
    const id = input?.id as string;
    if (!id) {
      return { error: "id is required" };
    }

    const history = getScanHistory();
    const record = history.getById(id);

    if (!record) {
      return { error: `Scan record not found: ${id}` };
    }

    return {
      id: record.id,
      target: record.target,
      scannedAt: record.scannedAt,
      identifier: record.identifier,
      summary: record.summary,
      vulnerabilityCount: record.vulnerabilities.length,
      vulnerabilities: record.vulnerabilities,
    };
  },

  scan_history_clear: async (input) => {
    const target = input?.target as string | undefined;
    const history = getScanHistory();

    if (target) {
      history.clearTarget(target);
      return {
        success: true,
        message: `Cleared scan history for ${target}`,
      };
    }

    history.clear();
    return {
      success: true,
      message: "Cleared all scan history",
    };
  },

  scan_history_targets: async () => {
    const history = getScanHistory();
    const targets = history.getTargets();

    return {
      count: targets.length,
      targets,
    };
  },

  // SSO Tools
  sso_init_database: async (input) => {
    const result = initSsoDatabase(input?.dbPath as string | undefined);
    return {
      success: result.success,
      path: result.path,
      created: result.created,
      error: result.error,
    };
  },

  sso_configure_saml: async (input) => {
    const inputMapping = input?.attributeMapping as
      | { email?: string; name?: string; groups?: string }
      | undefined;
    const config = {
      id: input?.id as string,
      name: input?.name as string,
      enabled: input?.enabled !== false, // Default to enabled
      idpCertificate: input?.idpCertificate as string,
      idpSsoUrl: input?.idpSsoUrl as string,
      idpSloUrl: input?.idpSloUrl as string | undefined,
      spEntityId: input?.spEntityId as string,
      spAcsUrl: input?.spAcsUrl as string,
      spSloUrl: input?.spSloUrl as string | undefined,
      attributeMapping: {
        email: inputMapping?.email || "email",
        name: inputMapping?.name || "name",
        groups: inputMapping?.groups,
      },
      wantAssertionsSigned: input?.wantAssertionsSigned as boolean | undefined,
      wantResponseSigned: input?.wantResponseSigned as boolean | undefined,
    };
    return configureSamlProvider(config);
  },

  sso_configure_oidc: async (input) => {
    const inputMapping = input?.attributeMapping as
      | { email?: string; name?: string; groups?: string }
      | undefined;
    const config = {
      id: input?.id as string,
      name: input?.name as string,
      enabled: input?.enabled !== false, // Default to enabled
      issuer: input?.issuer as string,
      clientId: input?.clientId as string,
      clientSecret: input?.clientSecret as string,
      redirectUri: input?.redirectUri as string,
      scopes: (input?.scopes as string[]) || ["openid", "profile", "email"],
      discoveryUrl: input?.discoveryUrl as string | undefined,
      jwksUri: input?.jwksUri as string | undefined,
      attributeMapping: {
        email: inputMapping?.email || "email",
        name: inputMapping?.name || "name",
        groups: inputMapping?.groups,
      },
    };
    return configureOidcProvider(config);
  },

  sso_list_providers: async () => listSsoProviders(),

  sso_get_provider: async (input) => {
    const id = input?.id as string;
    if (!id) return { error: "Provider ID is required" };
    const provider = getSsoProvider(id);
    if (!provider) return { error: `Provider not found: ${id}` };
    return provider;
  },

  sso_delete_provider: async (input) => {
    const id = input?.id as string;
    if (!id) return { error: "Provider ID is required" };
    return { success: deleteSsoProvider(id), id };
  },

  sso_set_provider_enabled: async (input) => {
    const id = input?.id as string;
    const enabled = input?.enabled as boolean;
    if (!id) return { error: "Provider ID is required" };
    if (typeof enabled !== "boolean") return { error: "enabled must be a boolean" };
    return { success: setSsoProviderEnabled(id, enabled), id, enabled };
  },

  sso_get_metadata: async (input) => {
    const providerId = input?.providerId as string;
    if (!providerId) return { error: "Provider ID is required" };
    const metadata = generateSpMetadata(providerId);
    if (!metadata) return { error: `Provider not found or not a SAML provider: ${providerId}` };
    return metadata;
  },

  sso_validate_saml: async (input) => {
    const providerId = input?.providerId as string;
    const samlResponse = input?.samlResponse as string;
    if (!providerId || !samlResponse) return { error: "providerId and samlResponse are required" };
    return validateSamlAssertion(providerId, samlResponse, {
      ipAddress: input?.ipAddress as string | undefined,
      userAgent: input?.userAgent as string | undefined,
    });
  },

  sso_validate_oidc: async (input) => {
    const providerId = input?.providerId as string;
    const token = input?.token as string;
    if (!providerId || !token) return { error: "providerId and token are required" };
    return validateOidcToken(providerId, token, {
      tokenType: input?.tokenType as "id_token" | "access_token" | undefined,
      nonce: input?.nonce as string | undefined,
      ipAddress: input?.ipAddress as string | undefined,
      userAgent: input?.userAgent as string | undefined,
    });
  },

  sso_validate_token_by_issuer: async (input) => {
    const token = input?.token as string;
    if (!token) return { error: "token is required" };
    return validateOidcTokenByIssuer(token, {
      tokenType: input?.tokenType as "id_token" | "access_token" | undefined,
    });
  },

  sso_refresh_token: async (input) => {
    const providerId = input?.providerId as string;
    const refreshToken = input?.refreshToken as string;
    if (!providerId || !refreshToken) return { error: "providerId and refreshToken are required" };
    return refreshOidcToken(providerId, refreshToken);
  },

  sso_get_user_info: async (input) => {
    const providerId = input?.providerId as string;
    const accessToken = input?.accessToken as string;
    if (!providerId || !accessToken) return { error: "providerId and accessToken are required" };
    return getOidcUserInfo(providerId, accessToken);
  },

  sso_get_session: async (input) => {
    const sessionId = input?.sessionId as string;
    if (!sessionId) return { error: "Session ID is required" };
    const session = getSsoSession(sessionId);
    if (!session) return { error: `Session not found: ${sessionId}` };
    return session;
  },

  sso_validate_session: async (input) => {
    const sessionId = input?.sessionId as string;
    if (!sessionId) return { error: "Session ID is required" };
    return validateSsoSession(sessionId);
  },

  sso_logout: async (input) => {
    const sessionId = input?.sessionId as string;
    if (!sessionId) return { error: "Session ID is required" };

    const generateLogoutRequest = input?.generateLogoutRequest as boolean;
    let logoutRequest = null;

    if (generateLogoutRequest) {
      const session = getSsoSession(sessionId);
      if (session && session.providerType === "saml") {
        logoutRequest = await generateSamlLogoutRequest(session.providerId, session);
      }
    }

    return {
      success: terminateSsoSession(sessionId),
      sessionId,
      logoutRequest,
    };
  },

  sso_logout_user: async (input) => {
    const userId = input?.userId as string;
    if (!userId) return { error: "User ID is required" };
    return {
      success: true,
      userId,
      terminatedSessions: terminateAllUserSessions(userId),
    };
  },

  sso_list_sessions: async (input) => {
    const userId = input?.userId as string | undefined;
    const includeExpired = input?.includeExpired as boolean | undefined;

    const sessions = userId ? listUserSessions(userId) : listAllSessions();
    const filtered = includeExpired
      ? sessions
      : sessions.filter((s: SsoSession) => new Date(s.expiresAt) > new Date());
    return { count: filtered.length, sessions: filtered };
  },

  sso_cleanup_sessions: async () => ({
    success: true,
    removedSessions: cleanupExpiredSessions(),
  }),

  sso_get_audit_log: async (input) => {
    const events = getSsoAuditEvents({
      userId: input?.userId as string | undefined,
      providerId: input?.providerId as string | undefined,
      eventType: input?.eventType as
        | "LOGIN"
        | "LOGOUT"
        | "TOKEN_REFRESH"
        | "TOKEN_VALIDATION"
        | "CONFIG_CHANGE"
        | "SESSION_EXPIRED"
        | undefined,
      status: input?.status as "SUCCESS" | "FAILURE" | undefined,
      limit: input?.limit as number | undefined,
    });
    return { count: events.length, events };
  },

  // RBAC handlers
  rbac_create_role: async (input) => {
    if (!isRbacDbInitialized()) {
      const result = initRbacDatabase();
      if (!result.success) {
        return { error: `Failed to initialize RBAC database: ${result.error}` };
      }
    }

    const name = input?.name as string;
    if (!name) {
      return { error: "Role name is required" };
    }

    try {
      const role = createRole(
        name,
        input?.description as string | undefined,
        input?.permissions as string[] | undefined
      );
      return { success: true, role, message: `Role '${name}' created successfully` };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  rbac_list_roles: async (input) => {
    if (!isRbacDbInitialized()) {
      const result = initRbacDatabase();
      if (!result.success) {
        return { error: `Failed to initialize RBAC database: ${result.error}` };
      }
    }

    const includePermissions = input?.includePermissions !== false;
    const roles = listRoles(includePermissions);
    const permissions = listPermissions();

    return {
      roles,
      availablePermissions: permissions.map((p) => ({
        name: p.name,
        description: p.description,
        resource: p.resource,
        action: p.action,
      })),
    };
  },

  rbac_assign_role: async (input) => {
    if (!isRbacDbInitialized()) {
      const result = initRbacDatabase();
      if (!result.success) {
        return { error: `Failed to initialize RBAC database: ${result.error}` };
      }
    }

    const userId = input?.userId as string;
    const roleName = input?.roleName as string;
    if (!userId || !roleName) {
      return { error: "userId and roleName are required" };
    }

    const role = getRoleByName(roleName);
    if (!role) {
      return { error: `Role not found: ${roleName}` };
    }

    const success = assignRoleToUser(
      userId,
      role.id,
      undefined,
      input?.expiresAt as string | undefined
    );
    if (success) {
      return {
        success: true,
        userId,
        role: roleName,
        expiresAt: input?.expiresAt,
        message: `Role '${roleName}' assigned to user '${userId}'`,
      };
    }
    return { error: "Failed to assign role" };
  },

  rbac_check_permission: async (input) => {
    if (!isRbacDbInitialized()) {
      const result = initRbacDatabase();
      if (!result.success) {
        return { error: `Failed to initialize RBAC database: ${result.error}` };
      }
    }

    const userId = input?.userId as string;
    const permission = input?.permission as string;
    if (!userId || !permission) {
      return { error: "userId and permission are required" };
    }

    return checkPermission(userId, permission);
  },

  rbac_list_user_permissions: async (input) => {
    if (!isRbacDbInitialized()) {
      const result = initRbacDatabase();
      if (!result.success) {
        return { error: `Failed to initialize RBAC database: ${result.error}` };
      }
    }

    const userId = input?.userId as string;
    if (!userId) {
      return { error: "userId is required" };
    }

    const roles = getUserRoles(userId);
    const permissions = listUserPermissions(userId);

    return {
      userId,
      roles: roles.map((r) => ({
        name: r.roleName,
        assignedAt: r.assignedAt,
        expiresAt: r.expiresAt,
      })),
      permissions: permissions.map((p) => ({
        name: p.name,
        description: p.description,
        resource: p.resource,
        action: p.action,
      })),
    };
  },

  // API Key handlers
  apikey_create: async (input) => {
    if (!isApiKeyDbInitialized()) {
      const result = initApiKeyDatabase();
      if (!result.success) {
        return { error: `Failed to initialize API key database: ${result.error}` };
      }
    }

    const name = input?.name as string;
    const scopes = input?.scopes as string[];
    const createdBy = input?.createdBy as string;

    if (!name || !scopes || !createdBy) {
      return { error: "name, scopes, and createdBy are required" };
    }

    for (const scope of scopes) {
      if (!VALID_SCOPES.includes(scope as any)) {
        return { error: `Invalid scope: ${scope}. Valid scopes: ${VALID_SCOPES.join(", ")}` };
      }
    }

    try {
      const result = createApiKey({
        name,
        description: input?.description as string | undefined,
        scopes: scopes as any,
        expiresInDays: input?.expiresInDays as number | undefined,
        createdBy,
        rateLimit: input?.rateLimit as number | undefined,
        ipAllowlist: input?.ipAllowlist as string[] | undefined,
      });

      return {
        message:
          "API key created successfully. IMPORTANT: Save the fullKey now - it will not be shown again!",
        key: {
          id: result.key.id,
          name: result.key.name,
          keyPrefix: result.key.keyPrefix,
          scopes: result.key.scopes,
          expiresAt: result.key.expiresAt,
          rateLimit: result.key.rateLimit,
        },
        fullKey: result.fullKey,
      };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },

  apikey_list: async (input) => {
    if (!isApiKeyDbInitialized()) {
      const result = initApiKeyDatabase();
      if (!result.success) {
        return { error: `Failed to initialize API key database: ${result.error}` };
      }
    }

    const keys = listApiKeys({
      status: input?.status as "active" | "revoked" | "expired" | undefined,
      createdBy: input?.createdBy as string | undefined,
      includeExpired: input?.includeExpired as boolean | undefined,
    });

    return {
      count: keys.length,
      keys: keys.map((k) => ({
        id: k.id,
        name: k.name,
        keyPrefix: k.keyPrefix,
        scopes: k.scopes,
        status: k.status,
        expiresAt: k.expiresAt,
        lastUsedAt: k.lastUsedAt,
        daysUntilExpiration: k.daysUntilExpiration,
        createdBy: k.createdBy,
        createdAt: k.createdAt,
      })),
    };
  },

  apikey_revoke: async (input) => {
    if (!isApiKeyDbInitialized()) {
      const result = initApiKeyDatabase();
      if (!result.success) {
        return { error: `Failed to initialize API key database: ${result.error}` };
      }
    }

    const keyId = input?.keyId as string;
    if (!keyId) {
      return { error: "keyId is required" };
    }

    const revoked = revokeApiKey(keyId, input?.actorId as string | undefined);

    if (revoked) {
      return { success: true, message: "API key revoked successfully" };
    } else {
      return { error: "Failed to revoke API key. It may not exist or is already revoked." };
    }
  },

  apikey_rotate: async (input) => {
    if (!isApiKeyDbInitialized()) {
      const result = initApiKeyDatabase();
      if (!result.success) {
        return { error: `Failed to initialize API key database: ${result.error}` };
      }
    }

    const keyId = input?.keyId as string;
    if (!keyId) {
      return { error: "keyId is required" };
    }

    try {
      const result = rotateApiKey(keyId, input?.actorId as string | undefined);

      if (!result) {
        return { error: "API key not found" };
      }

      return {
        message:
          "API key rotated successfully. IMPORTANT: Save the new key now - it will not be shown again!",
        previousKeyPrefix: result.previousKeyPrefix,
        key: {
          id: result.key.id,
          name: result.key.name,
          keyPrefix: result.key.keyPrefix,
          scopes: result.key.scopes,
          expiresAt: result.key.expiresAt,
        },
        newFullKey: result.newFullKey,
      };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  },
};

// =============================================================================
// Tool Definitions for Claude
// =============================================================================
export const tools: Anthropic.Tool[] = [
  // Trivy Tools
  {
    name: "trivy_scan_path",
    description:
      "Scan a local file path for vulnerabilities using Trivy. Detects vulnerabilities in dependencies (npm, pip, go, maven, etc.) and secrets in code.",
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory to scan",
        },
        severity: {
          type: "string",
          description:
            "Severity levels to report: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL (default: HIGH,CRITICAL)",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "trivy_scan_image",
    description:
      "Scan a Docker image for vulnerabilities using Trivy. Works with local images and registry images.",
    input_schema: {
      type: "object" as const,
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)",
        },
        severity: {
          type: "string",
          description: "Severity levels to report (default: HIGH,CRITICAL)",
        },
      },
      required: ["image"],
    },
  },
  {
    name: "trivy_generate_sbom",
    description:
      "Generate a Software Bill of Materials (SBOM) for a local path using Trivy. Creates a CycloneDX format SBOM listing all components and dependencies.",
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory to scan",
        },
        format: {
          type: "string",
          description: "SBOM format: cyclonedx (default) or spdx-json",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "trivy_generate_sbom_image",
    description:
      "Generate a Software Bill of Materials (SBOM) for a Docker image using Trivy. Creates a CycloneDX format SBOM listing all components in the container.",
    input_schema: {
      type: "object" as const,
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)",
        },
        format: {
          type: "string",
          description: "SBOM format: cyclonedx (default) or spdx-json",
        },
      },
      required: ["image"],
    },
  },
  {
    name: "trivy_scan_iac",
    description:
      "Scan Infrastructure as Code (IaC) files for misconfigurations using Trivy. Detects security issues in Terraform, Kubernetes, Docker, CloudFormation, and other IaC files.",
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory containing IaC files",
        },
        severity: {
          type: "string",
          description:
            "Severity levels to report: LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM,HIGH,CRITICAL)",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "trivy_scan_secrets",
    description:
      "Scan a local path for hardcoded secrets using Trivy. Detects API keys, passwords, tokens, private keys, and other sensitive data in code.",
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory to scan for secrets",
        },
        severity: {
          type: "string",
          description:
            "Severity levels to report: LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM,HIGH,CRITICAL)",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "trivy_scan_secrets_image",
    description:
      "Scan a Docker image for hardcoded secrets using Trivy. Detects API keys, passwords, tokens, private keys, and other sensitive data in container images.",
    input_schema: {
      type: "object" as const,
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)",
        },
        severity: {
          type: "string",
          description:
            "Severity levels to report: LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM,HIGH,CRITICAL)",
        },
      },
      required: ["image"],
    },
  },
  {
    name: "trivy_scan_licenses",
    description:
      "Scan a local path for license information using Trivy. Detects licenses in dependencies and flags potentially problematic licenses (forbidden, restricted, etc.).",
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory to scan for licenses",
        },
        severity: {
          type: "string",
          description:
            "Severity levels to report: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL (default: all)",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "trivy_scan_licenses_image",
    description:
      "Scan a Docker image for license information using Trivy. Detects licenses in dependencies and flags potentially problematic licenses (forbidden, restricted, etc.).",
    input_schema: {
      type: "object" as const,
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)",
        },
        severity: {
          type: "string",
          description:
            "Severity levels to report: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL (default: all)",
        },
      },
      required: ["image"],
    },
  },
  {
    name: "trivy_scan_image_full",
    description:
      "Run a comprehensive security scan on a Docker image using Trivy. Combines vulnerability, secret, license scanning, and SBOM generation in one operation for complete image analysis.",
    input_schema: {
      type: "object" as const,
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest, localhost:5000/myapp:v1)",
        },
        severity: {
          type: "string",
          description: "Severity levels to report: HIGH, CRITICAL (default: HIGH,CRITICAL)",
        },
        sbomFormat: {
          type: "string",
          description: "SBOM format: cyclonedx (default) or spdx-json",
          enum: ["cyclonedx", "spdx-json"],
        },
      },
      required: ["image"],
    },
  },
  {
    name: "trivy_scan_path_full",
    description:
      "Run a comprehensive security scan on a local path using Trivy. Combines vulnerability, secret, license, IaC scanning, and SBOM generation in one operation for complete codebase analysis.",
    input_schema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the directory to scan",
        },
        severity: {
          type: "string",
          description: "Severity levels to report: HIGH, CRITICAL (default: HIGH,CRITICAL)",
        },
        sbomFormat: {
          type: "string",
          description: "SBOM format: cyclonedx (default) or spdx-json",
          enum: ["cyclonedx", "spdx-json"],
        },
      },
      required: ["path"],
    },
  },

  // SonarQube Tools
  {
    name: "sonar_list_projects",
    description: "List all projects analyzed in SonarQube",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "sonar_get_issues",
    description: "Get code issues (bugs, vulnerabilities, code smells) for a SonarQube project",
    input_schema: {
      type: "object" as const,
      properties: {
        projectKey: {
          type: "string",
          description: "The SonarQube project key",
        },
        types: {
          type: "string",
          description: "Issue types to filter: VULNERABILITY, BUG, CODE_SMELL (comma-separated)",
        },
      },
      required: ["projectKey"],
    },
  },
  {
    name: "sonar_get_security_hotspots",
    description: "Get security hotspots (potential security issues requiring review) for a project",
    input_schema: {
      type: "object" as const,
      properties: {
        projectKey: {
          type: "string",
          description: "The SonarQube project key",
        },
      },
      required: ["projectKey"],
    },
  },
  {
    name: "sonar_get_metrics",
    description:
      "Get quality metrics (bugs count, vulnerabilities, coverage, duplication) for a project",
    input_schema: {
      type: "object" as const,
      properties: {
        projectKey: {
          type: "string",
          description: "The SonarQube project key",
        },
      },
      required: ["projectKey"],
    },
  },
  {
    name: "sonar_get_quality_gate_status",
    description:
      "Get the quality gate status for a SonarQube project. Returns whether the project passes or fails the quality gate with condition details.",
    input_schema: {
      type: "object" as const,
      properties: {
        projectKey: {
          type: "string",
          description: "The SonarQube project key",
        },
      },
      required: ["projectKey"],
    },
  },

  // Dependency-Track Tools
  {
    name: "dtrack_list_projects",
    description: "List all projects in Dependency-Track with their vulnerability counts",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "dtrack_get_vulnerabilities",
    description: "Get all vulnerabilities affecting a Dependency-Track project",
    input_schema: {
      type: "object" as const,
      properties: {
        projectUuid: {
          type: "string",
          description: "The project UUID (get from dtrack_list_projects)",
        },
      },
      required: ["projectUuid"],
    },
  },
  {
    name: "dtrack_get_findings",
    description:
      "Get detailed security findings for a project including component and vulnerability info",
    input_schema: {
      type: "object" as const,
      properties: {
        projectUuid: {
          type: "string",
          description: "The project UUID",
        },
      },
      required: ["projectUuid"],
    },
  },
  {
    name: "dtrack_get_components",
    description: "Get all components (dependencies) for a project with their details",
    input_schema: {
      type: "object" as const,
      properties: {
        projectUuid: {
          type: "string",
          description: "The project UUID",
        },
      },
      required: ["projectUuid"],
    },
  },
  {
    name: "dtrack_upload_sbom",
    description:
      "Upload a Software Bill of Materials (SBOM) to Dependency-Track for vulnerability analysis. Supports CycloneDX and SPDX formats.",
    input_schema: {
      type: "object" as const,
      properties: {
        projectName: {
          type: "string",
          description: "Name of the project in Dependency-Track",
        },
        projectVersion: {
          type: "string",
          description: "Version of the project (e.g., 1.0.0)",
        },
        sbom: {
          type: "string",
          description: "The SBOM content as JSON string (CycloneDX or SPDX format)",
        },
        autoCreate: {
          type: "boolean",
          description: "Auto-create project if it doesn't exist (default: true)",
        },
      },
      required: ["projectName", "projectVersion", "sbom"],
    },
  },

  // Gitea Tools
  {
    name: "gitea_list_repos",
    description: "List all Git repositories in Gitea for the current user",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "gitea_get_repo",
    description: "Get detailed information about a specific repository",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: {
          type: "string",
          description: "Repository owner username",
        },
        repo: {
          type: "string",
          description: "Repository name",
        },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "gitea_get_branches",
    description: "List all branches in a repository",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "gitea_get_commits",
    description: "Get recent commits for a repository",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        limit: {
          type: "number",
          description: "Number of commits to retrieve (default: 10)",
        },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "gitea_create_repo",
    description: "Create a new Git repository in Gitea",
    input_schema: {
      type: "object" as const,
      properties: {
        name: { type: "string", description: "Repository name" },
        description: { type: "string", description: "Repository description" },
        private: {
          type: "boolean",
          description: "Whether the repository is private (default: false)",
        },
      },
      required: ["name"],
    },
  },
  {
    name: "gitea_migrate_repo",
    description: "Migrate a repository from GitHub to Gitea (preserves issues, PRs, releases)",
    input_schema: {
      type: "object" as const,
      properties: {
        cloneUrl: {
          type: "string",
          description: "GitHub clone URL (e.g., https://github.com/user/repo.git)",
        },
        repoName: {
          type: "string",
          description: "Name for the new repository in Gitea",
        },
        authToken: {
          type: "string",
          description: "GitHub personal access token (required for private repos)",
        },
      },
      required: ["cloneUrl", "repoName"],
    },
  },
  {
    name: "gitea_list_pull_requests",
    description: "List pull requests for a repository in Gitea",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        state: {
          type: "string",
          description: "PR state filter: open, closed, all (default: open)",
        },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "gitea_get_pull_request",
    description: "Get details of a specific pull request",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        pullNumber: { type: "number", description: "Pull request number" },
      },
      required: ["owner", "repo", "pullNumber"],
    },
  },
  {
    name: "gitea_create_pull_request",
    description: "Create a new pull request in Gitea",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        title: { type: "string", description: "Pull request title" },
        head: { type: "string", description: "Source branch (e.g., feature-branch)" },
        base: { type: "string", description: "Target branch (e.g., main)" },
        body: { type: "string", description: "Pull request description" },
      },
      required: ["owner", "repo", "title", "head", "base"],
    },
  },
  {
    name: "gitea_merge_pull_request",
    description: "Merge a pull request in Gitea",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        pullNumber: { type: "number", description: "Pull request number" },
        mergeStyle: {
          type: "string",
          description: "Merge style: merge, rebase, or squash (default: merge)",
          enum: ["merge", "rebase", "squash"],
        },
      },
      required: ["owner", "repo", "pullNumber"],
    },
  },
  {
    name: "gitea_create_issue",
    description: "Create a new issue in a Gitea repository",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        title: { type: "string", description: "Issue title" },
        body: { type: "string", description: "Issue description" },
        labels: {
          type: "array",
          items: { type: "string" },
          description: "Labels to apply to the issue",
        },
      },
      required: ["owner", "repo", "title"],
    },
  },
  {
    name: "gitea_list_issues",
    description: "List issues for a repository in Gitea",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        state: {
          type: "string",
          description: "Issue state filter: open, closed, all (default: open)",
        },
      },
      required: ["owner", "repo"],
    },
  },

  // Drone CI Tools
  {
    name: "drone_list_repos",
    description: "List all repositories synced with Drone CI",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "drone_get_builds",
    description: "Get build history for a repository",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
      },
      required: ["owner", "repo"],
    },
  },
  {
    name: "drone_get_build",
    description: "Get detailed information about a specific build",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        build: { type: "number", description: "Build number" },
      },
      required: ["owner", "repo", "build"],
    },
  },
  {
    name: "drone_get_build_logs",
    description: "Get logs for a specific build step",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        build: { type: "number", description: "Build number" },
        stage: { type: "number", description: "Stage number (default: 1)" },
        step: { type: "number", description: "Step number (default: 1)" },
      },
      required: ["owner", "repo", "build"],
    },
  },
  {
    name: "drone_trigger_build",
    description: "Trigger a new CI/CD build for a repository",
    input_schema: {
      type: "object" as const,
      properties: {
        owner: { type: "string", description: "Repository owner" },
        repo: { type: "string", description: "Repository name" },
        branch: {
          type: "string",
          description: "Branch to build (default: main)",
        },
      },
      required: ["owner", "repo"],
    },
  },

  // Registry Tools
  {
    name: "registry_list_images",
    description: "List all images in the local Docker registry",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "registry_get_tags",
    description: "Get all tags for an image in the registry",
    input_schema: {
      type: "object" as const,
      properties: {
        image: { type: "string", description: "Image name" },
      },
      required: ["image"],
    },
  },

  // Platform Status
  {
    name: "check_platform_status",
    description:
      "Check the health status of all CI/CD platform services (Gitea, Drone, SonarQube, etc.)",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  // Security Dashboard
  {
    name: "get_security_dashboard",
    description:
      "Get unified security dashboard aggregating Trivy, SonarQube, and Dependency-Track results. Provides a single-call overview of security posture with aggregated counts and top findings.",
    input_schema: {
      type: "object" as const,
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan with Trivy (optional)",
        },
        path: {
          type: "string",
          description: "Local path to scan with Trivy (optional)",
        },
        sonarProject: {
          type: "string",
          description: "SonarQube project key (optional)",
        },
        dtrackProjectUuid: {
          type: "string",
          description: "Dependency-Track project UUID (optional)",
        },
        severity: {
          type: "string",
          description: "Severity filter for Trivy (default: HIGH,CRITICAL)",
        },
      },
    },
  },

  // Compliance Tools
  {
    name: "compliance_get_frameworks",
    description:
      "Get list of all available compliance frameworks with their descriptions. Returns SOC2, HIPAA, PCI-DSS, and CIS framework information.",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "compliance_get_controls",
    description:
      "Get compliance controls for a specific framework. Optionally get a single control by ID. Controls define security requirements and remediation SLAs.",
    input_schema: {
      type: "object" as const,
      properties: {
        framework: {
          type: "string",
          description: "Compliance framework: SOC2, HIPAA, PCI-DSS, or CIS",
          enum: ["SOC2", "HIPAA", "PCI-DSS", "CIS"],
        },
        controlId: {
          type: "string",
          description: "Optional: specific control ID to retrieve (e.g., CC7.1, 164.308(a)(1))",
        },
      },
      required: ["framework"],
    },
  },
  {
    name: "compliance_check_status",
    description:
      "Check compliance status for scan results. Returns pass/fail status, compliance percentage, and violations by framework.",
    input_schema: {
      type: "object" as const,
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan with Trivy",
        },
        path: {
          type: "string",
          description: "Local path to scan with Trivy",
        },
        sonarProject: {
          type: "string",
          description: "SonarQube project key",
        },
        dtrackProjectUuid: {
          type: "string",
          description: "Dependency-Track project UUID",
        },
        severity: {
          type: "string",
          description: "Severity filter (default: HIGH,CRITICAL)",
        },
        frameworks: {
          type: "array",
          items: { type: "string", enum: ["SOC2", "HIPAA", "PCI-DSS", "CIS"] },
          description: "Frameworks to check (default: all)",
        },
      },
    },
  },
  {
    name: "compliance_generate_report",
    description:
      "Generate a compliance report for scan results. Can output JSON or styled HTML for audit documentation.",
    input_schema: {
      type: "object" as const,
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan with Trivy",
        },
        path: {
          type: "string",
          description: "Local path to scan with Trivy",
        },
        sonarProject: {
          type: "string",
          description: "SonarQube project key",
        },
        dtrackProjectUuid: {
          type: "string",
          description: "Dependency-Track project UUID",
        },
        severity: {
          type: "string",
          description: "Severity filter (default: HIGH,CRITICAL)",
        },
        frameworks: {
          type: "array",
          items: { type: "string", enum: ["SOC2", "HIPAA", "PCI-DSS", "CIS"] },
          description: "Frameworks to include (default: all)",
        },
        format: {
          type: "string",
          enum: ["json", "html"],
          description: "Output format (default: json)",
        },
        title: {
          type: "string",
          description: "Report title",
        },
        organization: {
          type: "string",
          description: "Organization name for report header",
        },
      },
    },
  },
  {
    name: "compliance_trend_record",
    description:
      "Record a compliance snapshot for trend tracking. Call periodically to build compliance trend history.",
    input_schema: {
      type: "object" as const,
      properties: {
        target: {
          type: "string",
          description: "Target identifier (e.g., image name, project key)",
        },
        image: {
          type: "string",
          description: "Docker image to scan with Trivy",
        },
        path: {
          type: "string",
          description: "Local path to scan with Trivy",
        },
        sonarProject: {
          type: "string",
          description: "SonarQube project key",
        },
        dtrackProjectUuid: {
          type: "string",
          description: "Dependency-Track project UUID",
        },
        severity: {
          type: "string",
          description: "Severity filter (default: HIGH,CRITICAL)",
        },
        frameworks: {
          type: "array",
          items: { type: "string", enum: ["SOC2", "HIPAA", "PCI-DSS", "CIS"] },
          description: "Frameworks to track (default: all)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "compliance_trend_get",
    description:
      "Get compliance trend data for a target over time. Shows improvement, decline, or stability.",
    input_schema: {
      type: "object" as const,
      properties: {
        target: {
          type: "string",
          description: "Target identifier to get trends for",
        },
        days: {
          type: "number",
          description: "Number of days to include (default: 30)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "compliance_trend_list_targets",
    description: "List all targets that have compliance trend data recorded.",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },

  // OPA/Rego Policy Tools
  {
    name: "opa_list_policies",
    description:
      "List all available built-in OPA/Rego security policies. Returns policy names, descriptions, entrypoints, and rule counts.",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "opa_get_policy_info",
    description:
      "Get detailed information about a specific built-in OPA/Rego policy including its Rego source code.",
    input_schema: {
      type: "object" as const,
      properties: {
        name: {
          type: "string",
          description:
            "Policy name: vulnerability-threshold, license-compliance, secrets-detection, container-security, or quality-gate",
        },
      },
      required: ["name"],
    },
  },
  {
    name: "opa_validate_policy",
    description:
      "Validate Rego policy syntax. Checks for common syntax errors like missing package declarations, unbalanced braces, and missing rule definitions.",
    input_schema: {
      type: "object" as const,
      properties: {
        policy: {
          type: "string",
          description: "Rego policy source code to validate",
        },
      },
      required: ["policy"],
    },
  },
  {
    name: "opa_evaluate_policy",
    description:
      "Evaluate scan results against an OPA/Rego policy. Can use a built-in policy name or provide inline Rego code. Optionally scans an image or path first.",
    input_schema: {
      type: "object" as const,
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan before policy evaluation",
        },
        path: {
          type: "string",
          description: "Local path to scan before policy evaluation",
        },
        policy: {
          type: "string",
          description:
            "Policy name (built-in) or inline Rego code. Built-in: vulnerability-threshold, license-compliance, secrets-detection, container-security, quality-gate",
        },
        severity: {
          type: "string",
          description: "Severity filter for scan (default: HIGH,CRITICAL)",
        },
        thresholds: {
          type: "object",
          description:
            "Threshold values for policy evaluation (critical, high, medium, low, coverage)",
        },
        licenses: {
          type: "array",
          items: { type: "string" },
          description: "License identifiers to check (for license-compliance policy)",
        },
        secretsFound: {
          type: "boolean",
          description: "Whether secrets were found (for secrets-detection policy)",
        },
        codeCoverage: {
          type: "number",
          description: "Code coverage percentage (for quality-gate policy)",
        },
        qualityGatePassed: {
          type: "boolean",
          description: "Whether quality gate passed (for quality-gate policy)",
        },
      },
      required: ["policy"],
    },
  },

  // Scheduler Tools
  {
    name: "schedule_create",
    description:
      "Create a new scheduled security scan. Supports cron expressions with aliases (@daily, @weekly, @hourly, @monthly).",
    input_schema: {
      type: "object" as const,
      properties: {
        name: {
          type: "string",
          description: "Name for the schedule",
        },
        cron: {
          type: "string",
          description:
            "Cron expression (e.g., '0 2 * * *' for 2AM daily) or alias (@daily, @weekly, @hourly, @monthly)",
        },
        target: {
          type: "object",
          description: "Scan target configuration",
          properties: {
            type: {
              type: "string",
              enum: ["image", "path", "registry"],
              description: "Type of target to scan",
            },
            value: {
              type: "string",
              description: "Target value (image name, file path, or registry URL)",
            },
            severity: {
              type: "string",
              description: "Severity filter (default: HIGH,CRITICAL)",
            },
          },
          required: ["type", "value"],
        },
        enabled: {
          type: "boolean",
          description: "Whether schedule is enabled (default: true)",
        },
        description: {
          type: "string",
          description: "Optional description of the schedule",
        },
        webhooks: {
          type: "array",
          description: "Webhook notifications to send on completion",
          items: {
            type: "object",
            properties: {
              url: { type: "string" },
              type: { type: "string", enum: ["slack", "teams", "generic"] },
              onSuccess: { type: "boolean" },
              onFailure: { type: "boolean" },
              minSeverity: { type: "string" },
            },
          },
        },
      },
      required: ["name", "cron", "target"],
    },
  },
  {
    name: "schedule_list",
    description: "List all scheduled scans with optional filtering by status or target type.",
    input_schema: {
      type: "object" as const,
      properties: {
        enabled: {
          type: "boolean",
          description: "Filter by enabled status",
        },
        targetType: {
          type: "string",
          enum: ["image", "path", "registry"],
          description: "Filter by target type",
        },
      },
    },
  },
  {
    name: "schedule_get",
    description: "Get details of a specific scheduled scan by ID.",
    input_schema: {
      type: "object" as const,
      properties: {
        id: {
          type: "string",
          description: "Schedule ID",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "schedule_update",
    description: "Update an existing scheduled scan. Only specified fields will be updated.",
    input_schema: {
      type: "object" as const,
      properties: {
        id: {
          type: "string",
          description: "Schedule ID to update",
        },
        name: {
          type: "string",
          description: "New name for the schedule",
        },
        cron: {
          type: "string",
          description: "New cron expression",
        },
        target: {
          type: "object",
          description: "New scan target configuration",
          properties: {
            type: { type: "string", enum: ["image", "path", "registry"] },
            value: { type: "string" },
            severity: { type: "string" },
          },
        },
        enabled: {
          type: "boolean",
          description: "Enable or disable the schedule",
        },
        description: {
          type: "string",
          description: "New description",
        },
        webhooks: {
          type: "array",
          description: "Updated webhook configurations",
          items: { type: "object" },
        },
      },
      required: ["id"],
    },
  },
  {
    name: "schedule_delete",
    description: "Delete a scheduled scan by ID.",
    input_schema: {
      type: "object" as const,
      properties: {
        id: {
          type: "string",
          description: "Schedule ID to delete",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "schedule_trigger",
    description: "Manually trigger a scheduled scan immediately, regardless of its cron schedule.",
    input_schema: {
      type: "object" as const,
      properties: {
        id: {
          type: "string",
          description: "Schedule ID to trigger",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "schedule_history",
    description: "Get execution history for a scheduled scan, showing past runs and their results.",
    input_schema: {
      type: "object" as const,
      properties: {
        id: {
          type: "string",
          description: "Schedule ID",
        },
        limit: {
          type: "number",
          description: "Maximum number of history entries to return (default: 10)",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "cron_validate",
    description:
      "Validate a cron expression and show when it will next run. Returns human-readable description and next 5 run times.",
    input_schema: {
      type: "object" as const,
      properties: {
        expression: {
          type: "string",
          description:
            "Cron expression to validate (e.g., '0 2 * * *') or alias (@daily, @weekly, @hourly, @monthly)",
        },
      },
      required: ["expression"],
    },
  },
  {
    name: "scheduler_control",
    description: "Control the scheduler: start, stop, or clear all schedules.",
    input_schema: {
      type: "object" as const,
      properties: {
        action: {
          type: "string",
          enum: ["start", "stop", "clear"],
          description:
            "Action to perform: start (begin scheduling), stop (pause scheduling), clear (remove all schedules)",
        },
      },
      required: ["action"],
    },
  },
  // Vulnerability Database Tools
  {
    name: "vuln_db_sync",
    description:
      "Download and sync vulnerability database for offline scanning. " +
      "Downloads the Trivy vulnerability database to enable scanning without internet access.",
    input_schema: {
      type: "object" as const,
      properties: {
        force: {
          type: "boolean",
          description: "Force sync even if recently synced (default: false)",
        },
        skipIfRecent: {
          type: "number",
          description: "Skip sync if synced within this many hours (default: 24)",
        },
      },
    },
  },
  {
    name: "vuln_db_status",
    description:
      "Get status of the local vulnerability database including last sync time, version, and statistics.",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "vuln_db_lookup",
    description: "Look up a specific vulnerability by CVE ID from the local database.",
    input_schema: {
      type: "object" as const,
      properties: {
        id: {
          type: "string",
          description: "Vulnerability ID (e.g., CVE-2024-1234)",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "vuln_db_search",
    description:
      "Search vulnerabilities in the local database by package name, ecosystem, severity, or CVE pattern.",
    input_schema: {
      type: "object" as const,
      properties: {
        packageName: {
          type: "string",
          description: "Filter by package name (partial match)",
        },
        ecosystem: {
          type: "string",
          description: "Filter by ecosystem (npm, pypi, go, etc.)",
        },
        severity: {
          type: "array",
          items: { type: "string" },
          description: "Filter by severity levels (CRITICAL, HIGH, MEDIUM, LOW)",
        },
        cvePattern: {
          type: "string",
          description: "Filter by CVE pattern (partial match)",
        },
        limit: {
          type: "number",
          description: "Maximum results to return (default: 100)",
        },
        offset: {
          type: "number",
          description: "Offset for pagination",
        },
      },
    },
  },
  {
    name: "trivy_scan_offline",
    description:
      "Scan a Docker image or path using the locally cached vulnerability database. " +
      "Requires vuln_db_sync to be run first. Works without internet connectivity.",
    input_schema: {
      type: "object" as const,
      properties: {
        image: {
          type: "string",
          description: "Docker image to scan (e.g., nginx:latest)",
        },
        path: {
          type: "string",
          description: "Local path to scan (alternative to image)",
        },
        severity: {
          type: "string",
          description: "Severity levels to report (default: HIGH,CRITICAL)",
        },
        ignoreUnfixed: {
          type: "boolean",
          description: "Ignore vulnerabilities without fixes (default: false)",
        },
      },
    },
  },
  {
    name: "vuln_db_annotate",
    description:
      "Annotate a vulnerability with a status and notes. " +
      "Use to mark vulnerabilities as false positives, acknowledged, or mitigated.",
    input_schema: {
      type: "object" as const,
      properties: {
        vulnId: {
          type: "string",
          description: "Vulnerability ID (e.g., CVE-2024-1234)",
        },
        status: {
          type: "string",
          enum: ["acknowledged", "false_positive", "mitigated", "active"],
          description: "Status to assign to the vulnerability",
        },
        notes: {
          type: "string",
          description: "Optional notes about the annotation",
        },
      },
      required: ["vulnId", "status"],
    },
  },

  // Suppression Management Tools
  {
    name: "suppression_create",
    description:
      "Create a new vulnerability suppression rule. Suppressions can target specific CVEs, packages, or file paths. " +
      "Use to mark false positives or accepted risks with audit trail.",
    input_schema: {
      type: "object" as const,
      properties: {
        type: {
          type: "string",
          enum: ["cve", "package", "path"],
          description:
            "Type of suppression: 'cve' for specific CVE IDs, 'package' for package names, 'path' for file path patterns",
        },
        pattern: {
          type: "string",
          description:
            "Pattern to match. For CVE: 'CVE-2024-1234' or 'CVE-2024-*'. For package: 'lodash' or 'lodash@<4.17.21'. For path: 'src/legacy/*'",
        },
        reason: {
          type: "string",
          description: "Required justification for the suppression",
        },
        expires: {
          type: "string",
          description: "Optional ISO 8601 expiration date (e.g., '2025-03-01')",
        },
        createdBy: {
          type: "string",
          description: "User or team creating the suppression",
        },
        notes: {
          type: "string",
          description: "Additional notes or context",
        },
      },
      required: ["type", "pattern", "reason"],
    },
  },
  {
    name: "suppression_list",
    description:
      "List all active vulnerability suppressions with optional filters. " +
      "Returns suppressions from the database with their status and metadata.",
    input_schema: {
      type: "object" as const,
      properties: {
        type: {
          type: "string",
          enum: ["cve", "package", "path"],
          description: "Filter by suppression type",
        },
        status: {
          type: "string",
          enum: ["active", "expired"],
          description: "Filter by status (default: active)",
        },
        pattern: {
          type: "string",
          description: "Filter by pattern (partial match)",
        },
        createdBy: {
          type: "string",
          description: "Filter by creator",
        },
        includeExpired: {
          type: "boolean",
          description: "Include expired suppressions (default: false)",
        },
        limit: {
          type: "number",
          description: "Maximum results to return (default: 100)",
        },
        offset: {
          type: "number",
          description: "Offset for pagination",
        },
      },
    },
  },
  {
    name: "suppression_delete",
    description:
      "Delete (soft-delete) a suppression rule by ID. " +
      "The suppression is marked as deleted and remains in the audit trail.",
    input_schema: {
      type: "object" as const,
      properties: {
        id: {
          type: "string",
          description: "Suppression ID to delete",
        },
        deletedBy: {
          type: "string",
          description: "User performing the deletion",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "suppression_audit",
    description:
      "Get the audit log for suppressions. Shows history of all suppression actions " +
      "including creation, application, and deletion.",
    input_schema: {
      type: "object" as const,
      properties: {
        suppressionId: {
          type: "string",
          description: "Filter by specific suppression ID",
        },
        action: {
          type: "string",
          enum: ["created", "updated", "deleted", "applied", "expired"],
          description: "Filter by action type",
        },
        user: {
          type: "string",
          description: "Filter by user",
        },
        since: {
          type: "string",
          description: "Show entries since this ISO 8601 date",
        },
        until: {
          type: "string",
          description: "Show entries until this ISO 8601 date",
        },
        limit: {
          type: "number",
          description: "Maximum entries to return (default: 100)",
        },
      },
    },
  },
  {
    name: "suppression_apply",
    description:
      "Apply all active suppressions to a Trivy scan result. " +
      "Returns filtered results with suppressed vulnerabilities removed and a summary.",
    input_schema: {
      type: "object" as const,
      properties: {
        scanResult: {
          type: "object",
          description: "Trivy scan result object to filter",
        },
        includeExpired: {
          type: "boolean",
          description: "Include expired suppressions (default: false)",
        },
        user: {
          type: "string",
          description: "User applying suppressions (for audit)",
        },
        audit: {
          type: "boolean",
          description: "Log suppression applications to audit trail (default: true)",
        },
      },
      required: ["scanResult"],
    },
  },

  // Prometheus Metrics Tools
  {
    name: "metrics_get",
    description:
      "Get current metrics in Prometheus exposition format. " +
      "Returns scan metrics, vulnerability counts, cache stats, and circuit breaker states.",
    input_schema: {
      type: "object" as const,
      properties: {
        format: {
          type: "string",
          enum: ["prometheus", "json"],
          description:
            "Output format: 'prometheus' for exposition format (default), 'json' for raw snapshot",
        },
      },
    },
  },
  {
    name: "metrics_record_scan",
    description:
      "Record metrics from a security scan. " +
      "Call after each scan to track duration, success/failure rates, and vulnerability counts.",
    input_schema: {
      type: "object" as const,
      properties: {
        target: {
          type: "string",
          description: "Scan target (image name or path)",
        },
        type: {
          type: "string",
          enum: ["image", "path"],
          description: "Type of scan performed",
        },
        durationSeconds: {
          type: "number",
          description: "Scan duration in seconds",
        },
        success: {
          type: "boolean",
          description: "Whether the scan succeeded",
        },
        vulnerabilities: {
          type: "object",
          description: "Vulnerability counts by severity",
          properties: {
            critical: { type: "number" },
            high: { type: "number" },
            medium: { type: "number" },
            low: { type: "number" },
          },
        },
        error: {
          type: "string",
          description: "Error message if scan failed",
        },
      },
      required: ["target", "type", "durationSeconds", "success"],
    },
  },
  {
    name: "metrics_push",
    description:
      "Push current metrics to a Prometheus Pushgateway. " +
      "Use to send metrics to central monitoring in environments where Prometheus cannot scrape directly.",
    input_schema: {
      type: "object" as const,
      properties: {
        url: {
          type: "string",
          description: "Pushgateway URL (e.g., http://pushgateway:9091)",
        },
        job: {
          type: "string",
          description: "Job name for grouping metrics",
        },
        instance: {
          type: "string",
          description: "Instance label for identifying the source",
        },
        username: {
          type: "string",
          description: "Basic auth username (if required)",
        },
        password: {
          type: "string",
          description: "Basic auth password (if required)",
        },
        labels: {
          type: "object",
          description: "Additional labels to add to all metrics",
        },
      },
      required: ["url", "job"],
    },
  },
  {
    name: "metrics_delete",
    description:
      "Delete metrics from a Prometheus Pushgateway. " +
      "Removes all metrics for a specific job/instance combination.",
    input_schema: {
      type: "object" as const,
      properties: {
        url: {
          type: "string",
          description: "Pushgateway URL",
        },
        job: {
          type: "string",
          description: "Job name to delete",
        },
        instance: {
          type: "string",
          description: "Instance label to delete",
        },
        username: {
          type: "string",
          description: "Basic auth username (if required)",
        },
        password: {
          type: "string",
          description: "Basic auth password (if required)",
        },
      },
      required: ["url", "job"],
    },
  },
  {
    name: "metrics_reset",
    description:
      "Reset all collected metrics. " +
      "Clears all counters, gauges, and histograms. Useful for testing or restarting metric collection.",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },

  // Scan Comparison Tools
  {
    name: "scan_compare",
    description:
      "Compare two Trivy scan results to identify new, fixed, and unchanged vulnerabilities. " +
      "Uses fingerprinting to reliably track vulnerabilities across scans.",
    input_schema: {
      type: "object" as const,
      properties: {
        current: {
          type: "object",
          description: "Current Trivy scan result object",
        },
        baseline: {
          type: "object",
          description: "Baseline Trivy scan result to compare against",
        },
        minSeverity: {
          type: "string",
          enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
          description: "Minimum severity to include in comparison (default: all)",
        },
        includeUnchanged: {
          type: "boolean",
          description: "Include unchanged vulnerabilities in results (default: true)",
        },
      },
      required: ["current", "baseline"],
    },
  },
  {
    name: "scan_store",
    description:
      "Store a Trivy scan result in history for later comparison. " +
      "Scans are stored per-target and can be compared using scan_compare_with_previous.",
    input_schema: {
      type: "object" as const,
      properties: {
        scanResult: {
          type: "object",
          description: "Trivy scan result object to store",
        },
        identifier: {
          type: "string",
          description: "Optional identifier (e.g., git commit, version, branch)",
        },
      },
      required: ["scanResult"],
    },
  },
  {
    name: "scan_compare_with_previous",
    description:
      "Compare a current scan with the most recent stored scan for the same target. " +
      "Automatically stores the current scan after comparison.",
    input_schema: {
      type: "object" as const,
      properties: {
        scanResult: {
          type: "object",
          description: "Current Trivy scan result object",
        },
        identifier: {
          type: "string",
          description: "Optional identifier for this scan (e.g., git commit)",
        },
        minSeverity: {
          type: "string",
          enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
          description: "Minimum severity to include in comparison",
        },
        includeUnchanged: {
          type: "boolean",
          description: "Include unchanged vulnerabilities in results (default: true)",
        },
      },
      required: ["scanResult"],
    },
  },
  {
    name: "scan_history_list",
    description:
      "List stored scan records for a target. Returns scan metadata and vulnerability summaries.",
    input_schema: {
      type: "object" as const,
      properties: {
        target: {
          type: "string",
          description: "Target name (image or path) to get history for",
        },
        limit: {
          type: "number",
          description: "Maximum number of records to return (default: 10)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "scan_history_get",
    description:
      "Get a specific stored scan record by ID. " +
      "Returns full scan details including all fingerprinted vulnerabilities.",
    input_schema: {
      type: "object" as const,
      properties: {
        id: {
          type: "string",
          description: "Scan record ID to retrieve",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "scan_history_clear",
    description: "Clear scan history. Can clear all history or just for a specific target.",
    input_schema: {
      type: "object" as const,
      properties: {
        target: {
          type: "string",
          description: "Target to clear history for. If not provided, clears all history.",
        },
      },
    },
  },
  {
    name: "scan_history_targets",
    description: "List all targets that have stored scan history.",
    input_schema: {
      type: "object" as const,
      properties: {},
    },
  },
  // SSO Tools
  {
    name: "sso_init_database",
    description:
      "Initialize the SSO database for storing provider configurations and sessions. Call this before using other SSO tools.",
    input_schema: {
      type: "object" as const,
      properties: {
        dbPath: {
          type: "string",
          description:
            "Optional path for the SQLite database file. Defaults to sso.db in current directory.",
        },
      },
    },
  },
  {
    name: "sso_configure_saml",
    description:
      "Configure a SAML 2.0 identity provider. Stores IDP certificate, SSO URL, and attribute mappings.",
    input_schema: {
      type: "object" as const,
      properties: {
        id: { type: "string", description: "Unique identifier for this provider" },
        name: { type: "string", description: "Display name for the provider" },
        idpCertificate: {
          type: "string",
          description: "X.509 certificate from the IdP (PEM format)",
        },
        idpSsoUrl: { type: "string", description: "IdP Single Sign-On URL" },
        idpSloUrl: { type: "string", description: "Optional IdP Single Logout URL" },
        spEntityId: { type: "string", description: "Service Provider Entity ID" },
        spAcsUrl: { type: "string", description: "Assertion Consumer Service URL" },
        attributeMapping: {
          type: "object",
          description: "Mapping of SAML attributes to user properties",
          properties: {
            email: { type: "string" },
            name: { type: "string" },
            groups: { type: "string" },
          },
        },
        wantAssertionsSigned: {
          type: "boolean",
          description: "Require signed assertions (default: true)",
        },
      },
      required: ["id", "name", "idpCertificate", "idpSsoUrl", "spEntityId", "spAcsUrl"],
    },
  },
  {
    name: "sso_configure_oidc",
    description: "Configure an OpenID Connect identity provider.",
    input_schema: {
      type: "object" as const,
      properties: {
        id: { type: "string", description: "Unique identifier for this provider" },
        name: { type: "string", description: "Display name for the provider" },
        issuer: { type: "string", description: "OIDC issuer URL" },
        clientId: { type: "string", description: "OAuth 2.0 client ID" },
        clientSecret: { type: "string", description: "OAuth 2.0 client secret" },
        redirectUri: { type: "string", description: "Callback URL for OAuth flow" },
        scopes: {
          type: "array",
          items: { type: "string" },
          description: "OAuth scopes to request",
        },
        discoveryUrl: { type: "string", description: "Optional discovery URL" },
        attributeMapping: {
          type: "object",
          properties: {
            email: { type: "string" },
            name: { type: "string" },
            groups: { type: "string" },
          },
        },
      },
      required: ["id", "name", "issuer", "clientId", "clientSecret", "redirectUri"],
    },
  },
  {
    name: "sso_list_providers",
    description: "List all configured SSO providers (SAML and OIDC).",
    input_schema: { type: "object" as const, properties: {} },
  },
  {
    name: "sso_get_provider",
    description: "Get detailed configuration for a specific SSO provider.",
    input_schema: {
      type: "object" as const,
      properties: { id: { type: "string", description: "Provider ID to retrieve" } },
      required: ["id"],
    },
  },
  {
    name: "sso_delete_provider",
    description: "Delete an SSO provider configuration.",
    input_schema: {
      type: "object" as const,
      properties: { id: { type: "string", description: "Provider ID to delete" } },
      required: ["id"],
    },
  },
  {
    name: "sso_set_provider_enabled",
    description: "Enable or disable an SSO provider.",
    input_schema: {
      type: "object" as const,
      properties: {
        id: { type: "string", description: "Provider ID" },
        enabled: { type: "boolean", description: "Whether to enable or disable the provider" },
      },
      required: ["id", "enabled"],
    },
  },
  {
    name: "sso_get_metadata",
    description: "Generate SAML Service Provider metadata XML for configuring your IdP.",
    input_schema: {
      type: "object" as const,
      properties: { providerId: { type: "string", description: "SAML provider ID" } },
      required: ["providerId"],
    },
  },
  {
    name: "sso_validate_saml",
    description: "Validate a SAML assertion and create a session.",
    input_schema: {
      type: "object" as const,
      properties: {
        providerId: { type: "string", description: "SAML provider ID" },
        samlResponse: { type: "string", description: "Base64-encoded SAML response" },
        ipAddress: { type: "string", description: "Optional IP address for audit logging" },
        userAgent: { type: "string", description: "Optional user agent for audit logging" },
      },
      required: ["providerId", "samlResponse"],
    },
  },
  {
    name: "sso_validate_oidc",
    description: "Validate an OIDC token and create a session.",
    input_schema: {
      type: "object" as const,
      properties: {
        providerId: { type: "string", description: "OIDC provider ID" },
        token: { type: "string", description: "JWT token to validate" },
        tokenType: {
          type: "string",
          enum: ["id_token", "access_token"],
          description: "Token type",
        },
        nonce: { type: "string", description: "Optional nonce to verify" },
        ipAddress: { type: "string", description: "Optional IP for audit logging" },
        userAgent: { type: "string", description: "Optional user agent for audit logging" },
      },
      required: ["providerId", "token"],
    },
  },
  {
    name: "sso_validate_token_by_issuer",
    description:
      "Validate an OIDC token by automatically detecting the provider from the issuer claim.",
    input_schema: {
      type: "object" as const,
      properties: {
        token: { type: "string", description: "JWT token to validate" },
        tokenType: {
          type: "string",
          enum: ["id_token", "access_token"],
          description: "Token type",
        },
      },
      required: ["token"],
    },
  },
  {
    name: "sso_refresh_token",
    description: "Refresh an OIDC access token using a refresh token.",
    input_schema: {
      type: "object" as const,
      properties: {
        providerId: { type: "string", description: "OIDC provider ID" },
        refreshToken: { type: "string", description: "Refresh token" },
      },
      required: ["providerId", "refreshToken"],
    },
  },
  {
    name: "sso_get_user_info",
    description: "Get user information from the OIDC userinfo endpoint.",
    input_schema: {
      type: "object" as const,
      properties: {
        providerId: { type: "string", description: "OIDC provider ID" },
        accessToken: { type: "string", description: "Access token" },
      },
      required: ["providerId", "accessToken"],
    },
  },
  {
    name: "sso_get_session",
    description: "Get details of an SSO session by ID.",
    input_schema: {
      type: "object" as const,
      properties: { sessionId: { type: "string", description: "Session ID to retrieve" } },
      required: ["sessionId"],
    },
  },
  {
    name: "sso_validate_session",
    description: "Check if an SSO session is still valid (not expired).",
    input_schema: {
      type: "object" as const,
      properties: { sessionId: { type: "string", description: "Session ID to validate" } },
      required: ["sessionId"],
    },
  },
  {
    name: "sso_logout",
    description: "Terminate an SSO session. For SAML, can generate a logout request.",
    input_schema: {
      type: "object" as const,
      properties: {
        sessionId: { type: "string", description: "Session ID to terminate" },
        generateLogoutRequest: {
          type: "boolean",
          description: "Generate IdP logout request URL for SAML",
        },
      },
      required: ["sessionId"],
    },
  },
  {
    name: "sso_logout_user",
    description: "Terminate all sessions for a specific user across all providers.",
    input_schema: {
      type: "object" as const,
      properties: { userId: { type: "string", description: "User ID to logout" } },
      required: ["userId"],
    },
  },
  {
    name: "sso_list_sessions",
    description: "List active SSO sessions. Can filter by user.",
    input_schema: {
      type: "object" as const,
      properties: {
        userId: { type: "string", description: "Optional user ID to filter by" },
        includeExpired: {
          type: "boolean",
          description: "Include expired sessions (default: false)",
        },
      },
    },
  },
  {
    name: "sso_cleanup_sessions",
    description: "Remove expired SSO sessions from the database.",
    input_schema: { type: "object" as const, properties: {} },
  },
  {
    name: "sso_get_audit_log",
    description: "Get SSO audit events for security monitoring.",
    input_schema: {
      type: "object" as const,
      properties: {
        userId: { type: "string", description: "Filter by user ID" },
        providerId: { type: "string", description: "Filter by provider ID" },
        eventType: {
          type: "string",
          enum: [
            "LOGIN",
            "LOGOUT",
            "TOKEN_REFRESH",
            "TOKEN_VALIDATION",
            "CONFIG_CHANGE",
            "SESSION_EXPIRED",
          ],
          description: "Filter by event type",
        },
        status: { type: "string", enum: ["SUCCESS", "FAILURE"], description: "Filter by status" },
        limit: { type: "number", description: "Maximum number of events to return (default: 100)" },
      },
    },
  },

  // RBAC Tools
  {
    name: "rbac_create_role",
    description:
      "Create a custom RBAC role with specified permissions. Predefined roles (Admin, Auditor, Developer, Viewer) are created automatically on database initialization.",
    input_schema: {
      type: "object" as const,
      properties: {
        name: { type: "string", description: "Unique name for the role" },
        description: { type: "string", description: "Description of the role's purpose" },
        permissions: {
          type: "array",
          items: { type: "string" },
          description:
            "List of permission names to grant (e.g., scan:read, scan:execute, report:generate)",
        },
      },
      required: ["name"],
    },
  },
  {
    name: "rbac_list_roles",
    description:
      "List all RBAC roles and available permissions. Returns predefined roles (Admin, Auditor, Developer, Viewer) plus any custom roles.",
    input_schema: {
      type: "object" as const,
      properties: {
        includePermissions: {
          type: "boolean",
          description: "Include permissions for each role (default: true)",
        },
      },
    },
  },
  {
    name: "rbac_assign_role",
    description:
      "Assign an RBAC role to a user. Optionally set an expiration date for temporary access.",
    input_schema: {
      type: "object" as const,
      properties: {
        userId: {
          type: "string",
          description: "User ID to assign the role to (e.g., SSO user ID or email)",
        },
        roleName: {
          type: "string",
          description: "Name of the role to assign (e.g., Admin, Developer, Viewer)",
        },
        expiresAt: {
          type: "string",
          description: "Optional ISO 8601 expiration date for temporary access",
        },
      },
      required: ["userId", "roleName"],
    },
  },
  {
    name: "rbac_check_permission",
    description:
      "Check if a user has a specific permission. Returns whether allowed and which role granted it.",
    input_schema: {
      type: "object" as const,
      properties: {
        userId: { type: "string", description: "User ID to check" },
        permission: {
          type: "string",
          description: "Permission to check (e.g., scan:execute, report:read, system:admin)",
        },
      },
      required: ["userId", "permission"],
    },
  },
  {
    name: "rbac_list_user_permissions",
    description: "List all effective permissions for a user based on their assigned roles.",
    input_schema: {
      type: "object" as const,
      properties: {
        userId: { type: "string", description: "User ID to get permissions for" },
      },
      required: ["userId"],
    },
  },

  // API Key Management Tools
  {
    name: "apikey_create",
    description:
      "Create a new API key with specified scopes and expiration. Returns the full key only once at creation time.",
    input_schema: {
      type: "object" as const,
      properties: {
        name: { type: "string", description: "Human-readable name for the API key" },
        description: { type: "string", description: "Optional description of the key's purpose" },
        scopes: {
          type: "array",
          items: {
            type: "string",
            enum: [
              "scan:read",
              "scan:write",
              "policy:read",
              "policy:write",
              "suppression:read",
              "suppression:write",
              "report:read",
              "report:write",
              "admin:*",
            ],
          },
          description: "Scopes to grant to the key",
        },
        expiresInDays: { type: "number", description: "Days until expiration (default: 90)" },
        createdBy: { type: "string", description: "User ID creating the key" },
        rateLimit: {
          type: "number",
          description: "Rate limit in requests per minute (default: 100)",
        },
        ipAllowlist: {
          type: "array",
          items: { type: "string" },
          description: "Optional list of allowed IP addresses",
        },
      },
      required: ["name", "scopes", "createdBy"],
    },
  },
  {
    name: "apikey_list",
    description:
      "List all API keys (masked for security). Shows key prefix, scopes, status, and expiration.",
    input_schema: {
      type: "object" as const,
      properties: {
        status: {
          type: "string",
          enum: ["active", "revoked", "expired"],
          description: "Filter by status",
        },
        createdBy: { type: "string", description: "Filter by creator" },
        includeExpired: { type: "boolean", description: "Include expired keys (default: false)" },
      },
      required: [],
    },
  },
  {
    name: "apikey_revoke",
    description:
      "Revoke an API key immediately. The key will no longer be valid for authentication.",
    input_schema: {
      type: "object" as const,
      properties: {
        keyId: { type: "string", description: "ID of the API key to revoke" },
        actorId: { type: "string", description: "User ID performing the revocation (for audit)" },
      },
      required: ["keyId"],
    },
  },
  {
    name: "apikey_rotate",
    description:
      "Rotate an API key, generating a new key while preserving the ID and settings. Returns the new key only once.",
    input_schema: {
      type: "object" as const,
      properties: {
        keyId: { type: "string", description: "ID of the API key to rotate" },
        actorId: { type: "string", description: "User ID performing the rotation (for audit)" },
      },
      required: ["keyId"],
    },
  },
];

// =============================================================================
// Tool Executor
// =============================================================================
export async function executeTool(name: string, input: Record<string, unknown>): Promise<string> {
  try {
    const handler = toolHandlers[name];
    if (!handler) {
      throw new Error(`Unknown tool: ${name}`);
    }
    const result = await handler(input);
    return JSON.stringify(result, null, 2);
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return JSON.stringify({ error: errorMessage }, null, 2);
  }
}
