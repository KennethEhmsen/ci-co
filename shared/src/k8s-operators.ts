/**
 * Kubernetes Operators Security Module
 * Security scanning and validation for Kubernetes operators and CRDs
 * Part of v1.31.0 - GitOps & Zero-Trust Security
 */

import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";

export type OperatorType = "helm" | "ansible" | "go" | "java" | "unknown";
export type CrdValidationLevel = "strict" | "warn" | "permissive";

export interface OperatorInfo {
  id: string;
  name: string;
  namespace: string;
  version: string;
  type: OperatorType;
  crdCount: number;
  permissions: string[];
  registeredAt: string;
  lastScanned?: string;
  status: "healthy" | "degraded" | "unknown";
}

export interface CrdDefinition {
  id: string;
  name: string;
  group: string;
  version: string;
  kind: string;
  scope: "Namespaced" | "Cluster";
  operatorId: string;
  schema?: Record<string, unknown>;
  registeredAt: string;
}

export interface OperatorScanResult {
  operatorId: string;
  operatorName: string;
  scannedAt: string;
  issues: OperatorIssue[];
  passed: boolean;
  score: number;
  recommendations: string[];
}

export interface OperatorIssue {
  id: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  category: "permission" | "crd" | "rbac" | "config" | "version";
  resource: string;
  message: string;
  remediation?: string;
}

export interface CrdValidationResult {
  crdId: string;
  crdName: string;
  valid: boolean;
  errors: string[];
  warnings: string[];
  validatedAt: string;
}

export interface RbacAnalysis {
  operatorId: string;
  roles: Array<{
    name: string;
    namespace: string;
    rules: Array<{
      apiGroups: string[];
      resources: string[];
      verbs: string[];
    }>;
  }>;
  clusterRoles: Array<{
    name: string;
    rules: Array<{
      apiGroups: string[];
      resources: string[];
      verbs: string[];
    }>;
  }>;
  findings: Array<{
    severity: "LOW" | "MEDIUM" | "HIGH";
    issue: string;
    recommendation: string;
  }>;
  analyzedAt: string;
}

export interface OperatorCompatibility {
  operatorId: string;
  currentVersion: string;
  k8sVersions: string[];
  deprecatedApis: Array<{
    api: string;
    deprecatedIn: string;
    removedIn: string;
    replacement: string;
  }>;
  compatible: boolean;
  checkedAt: string;
}

export interface WebhookConfig {
  id: string;
  operatorId: string;
  name: string;
  type: "validating" | "mutating";
  failurePolicy: "Fail" | "Ignore";
  timeoutSeconds: number;
  rules: Array<{
    operations: string[];
    apiGroups: string[];
    apiVersions: string[];
    resources: string[];
  }>;
}

export interface WebhookAudit {
  operatorId: string;
  webhooks: WebhookConfig[];
  findings: Array<{
    webhook: string;
    severity: "LOW" | "MEDIUM" | "HIGH";
    issue: string;
    recommendation: string;
  }>;
  auditedAt: string;
}

let db: Database.Database | null = null;
const DEFAULT_DB_PATH = path.join(process.cwd(), ".cicd-security", "k8s-operators.db");

export function initOperatorsDb(dbPath: string = DEFAULT_DB_PATH): {
  path: string;
  tables: string[];
} {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  db = new Database(dbPath);
  db.pragma("journal_mode = WAL");

  db.prepare(
    `CREATE TABLE IF NOT EXISTS operators (
    id TEXT PRIMARY KEY, name TEXT, namespace TEXT, version TEXT,
    type TEXT, crd_count INTEGER, permissions TEXT,
    registered_at TEXT, last_scanned TEXT, status TEXT
  )`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS crds (
    id TEXT PRIMARY KEY, name TEXT, group_name TEXT, version TEXT,
    kind TEXT, scope TEXT, operator_id TEXT, schema TEXT, registered_at TEXT
  )`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS operator_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, operator_id TEXT,
    scanned_at TEXT, issues TEXT, passed INTEGER, score INTEGER
  )`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY, operator_id TEXT, name TEXT, type TEXT,
    failure_policy TEXT, timeout_seconds INTEGER, rules TEXT
  )`
  ).run();

  return { path: dbPath, tables: ["operators", "crds", "operator_scans", "webhooks"] };
}

function getDb(): Database.Database {
  if (!db) initOperatorsDb();
  return db!;
}

// Operator Management
export function registerOperator(
  operator: Omit<OperatorInfo, "id" | "registeredAt" | "status">
): OperatorInfo {
  const id = `op-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const now = new Date().toISOString();

  const record: OperatorInfo = { ...operator, id, registeredAt: now, status: "unknown" };

  getDb()
    .prepare(
      `INSERT INTO operators (id, name, namespace, version, type, crd_count, permissions, registered_at, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      id,
      operator.name,
      operator.namespace,
      operator.version,
      operator.type,
      operator.crdCount,
      JSON.stringify(operator.permissions),
      now,
      "unknown"
    );

  return record;
}

export function listOperators(namespace?: string): OperatorInfo[] {
  let sql = "SELECT * FROM operators";
  const params: string[] = [];
  if (namespace) {
    sql += " WHERE namespace = ?";
    params.push(namespace);
  }
  sql += " ORDER BY name";

  return (
    getDb()
      .prepare(sql)
      .all(...params) as Array<Record<string, unknown>>
  ).map((r) => ({
    id: r.id as string,
    name: r.name as string,
    namespace: r.namespace as string,
    version: r.version as string,
    type: r.type as OperatorType,
    crdCount: r.crd_count as number,
    permissions: JSON.parse(r.permissions as string),
    registeredAt: r.registered_at as string,
    lastScanned: r.last_scanned as string | undefined,
    status: r.status as "healthy" | "degraded" | "unknown",
  }));
}

export function getOperator(operatorId: string): OperatorInfo | null {
  const row = getDb().prepare("SELECT * FROM operators WHERE id = ?").get(operatorId) as
    | Record<string, unknown>
    | undefined;
  if (!row) return null;

  return {
    id: row.id as string,
    name: row.name as string,
    namespace: row.namespace as string,
    version: row.version as string,
    type: row.type as OperatorType,
    crdCount: row.crd_count as number,
    permissions: JSON.parse(row.permissions as string),
    registeredAt: row.registered_at as string,
    lastScanned: row.last_scanned as string | undefined,
    status: row.status as "healthy" | "degraded" | "unknown",
  };
}

// Operator Scanning
export function scanOperator(operatorId: string): OperatorScanResult {
  const operator = getOperator(operatorId);
  if (!operator) throw new Error(`Operator not found: ${operatorId}`);

  const issues: OperatorIssue[] = [];
  const recommendations: string[] = [];
  let score = 100;

  // Check for overly permissive RBAC
  if (operator.permissions.includes("*")) {
    issues.push({
      id: "rbac-wildcard",
      severity: "CRITICAL",
      category: "rbac",
      resource: operator.name,
      message: "Operator has wildcard (*) permissions",
      remediation: "Restrict permissions to specific resources and verbs",
    });
    score -= 30;
  }

  // Check for cluster-admin equivalent
  if (operator.permissions.includes("cluster-admin")) {
    issues.push({
      id: "rbac-cluster-admin",
      severity: "HIGH",
      category: "rbac",
      resource: operator.name,
      message: "Operator has cluster-admin equivalent permissions",
      remediation: "Use least-privilege principle for operator permissions",
    });
    score -= 20;
  }

  // Check for secrets access
  if (operator.permissions.some((p) => p.includes("secrets"))) {
    issues.push({
      id: "rbac-secrets-access",
      severity: "MEDIUM",
      category: "rbac",
      resource: operator.name,
      message: "Operator has access to secrets",
      remediation: "Ensure secrets access is necessary and properly scoped",
    });
    score -= 10;
    recommendations.push(
      "Consider using sealed-secrets or external-secrets-operator for secret management"
    );
  }

  // Add general recommendations
  if (operator.type === "unknown") {
    recommendations.push("Identify operator type for better security recommendations");
  }

  const result: OperatorScanResult = {
    operatorId,
    operatorName: operator.name,
    scannedAt: new Date().toISOString(),
    issues,
    passed: issues.filter((i) => i.severity === "CRITICAL" || i.severity === "HIGH").length === 0,
    score: Math.max(0, score),
    recommendations,
  };

  // Store scan result
  getDb()
    .prepare(
      `INSERT INTO operator_scans (operator_id, scanned_at, issues, passed, score)
     VALUES (?, ?, ?, ?, ?)`
    )
    .run(operatorId, result.scannedAt, JSON.stringify(issues), result.passed ? 1 : 0, result.score);

  // Update operator status
  getDb()
    .prepare(`UPDATE operators SET last_scanned = ?, status = ? WHERE id = ?`)
    .run(result.scannedAt, result.passed ? "healthy" : "degraded", operatorId);

  return result;
}

// CRD Management
export function registerCrd(crd: Omit<CrdDefinition, "id" | "registeredAt">): CrdDefinition {
  const id = `crd-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const now = new Date().toISOString();

  const record: CrdDefinition = { ...crd, id, registeredAt: now };

  getDb()
    .prepare(
      `INSERT INTO crds (id, name, group_name, version, kind, scope, operator_id, schema, registered_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      id,
      crd.name,
      crd.group,
      crd.version,
      crd.kind,
      crd.scope,
      crd.operatorId,
      crd.schema ? JSON.stringify(crd.schema) : null,
      now
    );

  // Update operator CRD count
  getDb()
    .prepare(
      `UPDATE operators SET crd_count = (SELECT COUNT(*) FROM crds WHERE operator_id = ?) WHERE id = ?`
    )
    .run(crd.operatorId, crd.operatorId);

  return record;
}

export function listCrds(operatorId?: string): CrdDefinition[] {
  let sql = "SELECT * FROM crds";
  const params: string[] = [];
  if (operatorId) {
    sql += " WHERE operator_id = ?";
    params.push(operatorId);
  }
  sql += " ORDER BY name";

  return (
    getDb()
      .prepare(sql)
      .all(...params) as Array<Record<string, unknown>>
  ).map((r) => ({
    id: r.id as string,
    name: r.name as string,
    group: r.group_name as string,
    version: r.version as string,
    kind: r.kind as string,
    scope: r.scope as "Namespaced" | "Cluster",
    operatorId: r.operator_id as string,
    schema: r.schema ? JSON.parse(r.schema as string) : undefined,
    registeredAt: r.registered_at as string,
  }));
}

// CRD Validation
export function validateCrd(
  crdId: string,
  level: CrdValidationLevel = "warn"
): CrdValidationResult {
  const crd = getDb().prepare("SELECT * FROM crds WHERE id = ?").get(crdId) as
    | Record<string, unknown>
    | undefined;
  if (!crd) throw new Error(`CRD not found: ${crdId}`);

  const errors: string[] = [];
  const warnings: string[] = [];

  const schema = crd.schema ? JSON.parse(crd.schema as string) : null;

  // Validate schema presence
  if (!schema) {
    if (level === "strict") {
      errors.push("CRD has no OpenAPI v3 schema defined");
    } else {
      warnings.push("CRD has no OpenAPI v3 schema - validation will be limited");
    }
  }

  // Check for structural schema
  if (schema && !schema.openAPIV3Schema) {
    warnings.push("CRD does not use structural schema (openAPIV3Schema)");
  }

  // Check naming conventions
  const name = crd.name as string;
  if (!name.includes(".")) {
    warnings.push("CRD name should follow <plural>.<group> format");
  }

  // Check for version in spec
  if (crd.version === "v1alpha1" || crd.version === "v1beta1") {
    warnings.push(`CRD uses pre-release version: ${crd.version}`);
  }

  return {
    crdId,
    crdName: name,
    valid: errors.length === 0,
    errors,
    warnings,
    validatedAt: new Date().toISOString(),
  };
}

// RBAC Analysis
export function analyzeOperatorRbac(operatorId: string): RbacAnalysis {
  const operator = getOperator(operatorId);
  if (!operator) throw new Error(`Operator not found: ${operatorId}`);

  const findings: RbacAnalysis["findings"] = [];

  // Mock RBAC data - in production would query K8s API
  const roles: RbacAnalysis["roles"] = [
    {
      name: `${operator.name}-role`,
      namespace: operator.namespace,
      rules: [
        { apiGroups: [""], resources: ["pods", "services"], verbs: ["get", "list", "watch"] },
        { apiGroups: ["apps"], resources: ["deployments"], verbs: ["*"] },
      ],
    },
  ];

  const clusterRoles: RbacAnalysis["clusterRoles"] = [];

  // Analyze permissions
  for (const role of roles) {
    for (const rule of role.rules) {
      if (rule.verbs.includes("*")) {
        findings.push({
          severity: "MEDIUM",
          issue: `Role ${role.name} uses wildcard verbs on ${rule.resources.join(", ")}`,
          recommendation: "Specify explicit verbs instead of using wildcard",
        });
      }

      if (rule.apiGroups.includes("*")) {
        findings.push({
          severity: "HIGH",
          issue: `Role ${role.name} has access to all API groups`,
          recommendation: "Restrict to specific API groups needed by the operator",
        });
      }
    }
  }

  return {
    operatorId,
    roles,
    clusterRoles,
    findings,
    analyzedAt: new Date().toISOString(),
  };
}

// Compatibility Check
export function checkOperatorCompatibility(
  operatorId: string,
  k8sVersion: string
): OperatorCompatibility {
  const operator = getOperator(operatorId);
  if (!operator) throw new Error(`Operator not found: ${operatorId}`);

  const deprecatedApis: OperatorCompatibility["deprecatedApis"] = [];

  // Check for deprecated APIs based on K8s version
  const majorMinor = k8sVersion.replace(/^v/, "").split(".").slice(0, 2).join(".");

  if (parseFloat(majorMinor) >= 1.25) {
    deprecatedApis.push({
      api: "policy/v1beta1 PodSecurityPolicy",
      deprecatedIn: "v1.21",
      removedIn: "v1.25",
      replacement: "Pod Security Admission",
    });
  }

  if (parseFloat(majorMinor) >= 1.22) {
    deprecatedApis.push({
      api: "networking.k8s.io/v1beta1 Ingress",
      deprecatedIn: "v1.19",
      removedIn: "v1.22",
      replacement: "networking.k8s.io/v1 Ingress",
    });
  }

  return {
    operatorId,
    currentVersion: operator.version,
    k8sVersions: ["1.24", "1.25", "1.26", "1.27", "1.28", "1.29"],
    deprecatedApis,
    compatible: deprecatedApis.length === 0,
    checkedAt: new Date().toISOString(),
  };
}

// Webhook Management
export function registerWebhook(webhook: Omit<WebhookConfig, "id">): WebhookConfig {
  const id = `wh-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const record: WebhookConfig = { ...webhook, id };

  getDb()
    .prepare(
      `INSERT INTO webhooks (id, operator_id, name, type, failure_policy, timeout_seconds, rules)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      id,
      webhook.operatorId,
      webhook.name,
      webhook.type,
      webhook.failurePolicy,
      webhook.timeoutSeconds,
      JSON.stringify(webhook.rules)
    );

  return record;
}

export function auditWebhooks(operatorId: string): WebhookAudit {
  const webhooks = (
    getDb().prepare("SELECT * FROM webhooks WHERE operator_id = ?").all(operatorId) as Array<
      Record<string, unknown>
    >
  ).map((r) => ({
    id: r.id as string,
    operatorId: r.operator_id as string,
    name: r.name as string,
    type: r.type as "validating" | "mutating",
    failurePolicy: r.failure_policy as "Fail" | "Ignore",
    timeoutSeconds: r.timeout_seconds as number,
    rules: JSON.parse(r.rules as string),
  }));

  const findings: WebhookAudit["findings"] = [];

  for (const webhook of webhooks) {
    // Check for Ignore failure policy
    if (webhook.failurePolicy === "Ignore") {
      findings.push({
        webhook: webhook.name,
        severity: "MEDIUM",
        issue: "Webhook uses Ignore failure policy",
        recommendation: "Consider using Fail policy to prevent bypassing validation",
      });
    }

    // Check for high timeout
    if (webhook.timeoutSeconds > 10) {
      findings.push({
        webhook: webhook.name,
        severity: "LOW",
        issue: `Webhook has high timeout: ${webhook.timeoutSeconds}s`,
        recommendation: "Consider reducing timeout to improve API server responsiveness",
      });
    }

    // Check for wildcard rules
    for (const rule of webhook.rules) {
      if (rule.resources.includes("*")) {
        findings.push({
          webhook: webhook.name,
          severity: "HIGH",
          issue: "Webhook intercepts all resources",
          recommendation: "Restrict webhook to specific resources it needs to validate",
        });
      }
    }
  }

  return {
    operatorId,
    webhooks,
    findings,
    auditedAt: new Date().toISOString(),
  };
}

// Summary
export function getOperatorSecuritySummary(namespace?: string): {
  totalOperators: number;
  healthyOperators: number;
  degradedOperators: number;
  totalCrds: number;
  totalWebhooks: number;
  criticalIssues: number;
  overallScore: number;
} {
  let operatorSql = "SELECT status FROM operators";
  let crdSql = "SELECT COUNT(*) as count FROM crds";
  let webhookSql = "SELECT COUNT(*) as count FROM webhooks";

  if (namespace) {
    operatorSql += " WHERE namespace = ?";
    crdSql += " WHERE operator_id IN (SELECT id FROM operators WHERE namespace = ?)";
    webhookSql += " WHERE operator_id IN (SELECT id FROM operators WHERE namespace = ?)";
  }

  const operators = namespace
    ? (getDb().prepare(operatorSql).all(namespace) as Array<{ status: string }>)
    : (getDb().prepare(operatorSql).all() as Array<{ status: string }>);

  const crdCount = namespace
    ? (getDb().prepare(crdSql).get(namespace) as { count: number })
    : (getDb().prepare(crdSql).get() as { count: number });

  const webhookCount = namespace
    ? (getDb().prepare(webhookSql).get(namespace) as { count: number })
    : (getDb().prepare(webhookSql).get() as { count: number });

  const healthy = operators.filter((o) => o.status === "healthy").length;
  const degraded = operators.filter((o) => o.status === "degraded").length;

  return {
    totalOperators: operators.length,
    healthyOperators: healthy,
    degradedOperators: degraded,
    totalCrds: crdCount.count,
    totalWebhooks: webhookCount.count,
    criticalIssues: degraded,
    overallScore: operators.length > 0 ? Math.round((healthy / operators.length) * 100) : 100,
  };
}

export const k8sOperators = {
  initOperatorsDb,
  registerOperator,
  listOperators,
  getOperator,
  scanOperator,
  registerCrd,
  listCrds,
  validateCrd,
  analyzeOperatorRbac,
  checkOperatorCompatibility,
  registerWebhook,
  auditWebhooks,
  getOperatorSecuritySummary,
};
