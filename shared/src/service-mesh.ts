/**
 * Service Mesh Security Module
 * Security scanning and policy enforcement for service mesh deployments
 * Part of v1.31.0 - GitOps & Zero-Trust Security
 */

import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";

export type MeshProvider = "istio" | "linkerd" | "cilium" | "consul";
export type MtlsMode = "STRICT" | "PERMISSIVE" | "DISABLE";
export type PolicyAction = "ALLOW" | "DENY" | "AUDIT";

export interface MeshConfig {
  provider: MeshProvider;
  version: string;
  namespace: string;
  mtlsMode: MtlsMode;
  proxyVersion?: string;
}

export interface MeshScanResult {
  provider: MeshProvider;
  namespace: string;
  scannedAt: string;
  issues: MeshIssue[];
  passed: boolean;
  score: number;
}

export interface MeshIssue {
  id: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  category: "mtls" | "policy" | "config" | "version" | "certificate";
  resource: string;
  message: string;
  remediation?: string;
}

export interface MtlsStatus {
  namespace: string;
  mode: MtlsMode;
  enabled: boolean;
  coverage: number;
  services: Array<{
    name: string;
    mtlsEnabled: boolean;
    peerAuthentication?: string;
  }>;
}

export interface AuthorizationPolicy {
  id: string;
  name: string;
  namespace: string;
  action: PolicyAction;
  rules: Array<{
    from?: Array<{ source: Record<string, string> }>;
    to?: Array<{ operation: Record<string, string[]> }>;
    when?: Array<{ key: string; values: string[] }>;
  }>;
  createdAt: string;
}

export interface PolicyAuditResult {
  namespace: string;
  policies: AuthorizationPolicy[];
  findings: Array<{
    policy: string;
    severity: "LOW" | "MEDIUM" | "HIGH";
    issue: string;
    recommendation: string;
  }>;
  auditedAt: string;
}

export interface CertificateInfo {
  namespace: string;
  service: string;
  issuer: string;
  subject: string;
  notBefore: string;
  notAfter: string;
  daysUntilExpiry: number;
  isExpired: boolean;
  isExpiringSoon: boolean;
}

export interface TrafficPolicy {
  id: string;
  name: string;
  namespace: string;
  host: string;
  trafficPolicy: {
    connectionPool?: {
      tcp?: { maxConnections?: number };
      http?: { h2UpgradePolicy?: string; http1MaxPendingRequests?: number };
    };
    loadBalancer?: { simple?: string };
    tls?: { mode?: string };
  };
}

export interface SidecarInfo {
  namespace: string;
  pod: string;
  proxyVersion: string;
  proxyStatus: "healthy" | "degraded" | "unknown";
  lastUpdated: string;
  needsUpgrade: boolean;
  latestVersion?: string;
}

export interface MeshCveInfo {
  cveId: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  affectedVersions: string[];
  fixedVersion: string;
  description: string;
  published: string;
}

export interface UpgradePath {
  currentVersion: string;
  targetVersion: string;
  steps: Array<{
    version: string;
    breaking: boolean;
    notes: string[];
  }>;
  securityFixes: string[];
}

let db: Database.Database | null = null;
const DEFAULT_DB_PATH = path.join(process.cwd(), ".cicd-security", "service-mesh.db");

export function initMeshDb(dbPath: string = DEFAULT_DB_PATH): { path: string; tables: string[] } {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  db = new Database(dbPath);
  db.pragma("journal_mode = WAL");

  db.prepare(
    `CREATE TABLE IF NOT EXISTS mesh_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT, namespace TEXT,
    scanned_at TEXT, issues TEXT, passed INTEGER, score INTEGER
  )`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS mesh_policies (
    id TEXT PRIMARY KEY, name TEXT, namespace TEXT, action TEXT,
    rules TEXT, created_at TEXT
  )`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS mesh_cves (
    cve_id TEXT PRIMARY KEY, severity TEXT, affected_versions TEXT,
    fixed_version TEXT, description TEXT, published TEXT
  )`
  ).run();

  return { path: dbPath, tables: ["mesh_scans", "mesh_policies", "mesh_cves"] };
}

function getDb(): Database.Database {
  if (!db) initMeshDb();
  return db!;
}

// Mesh Configuration Scanning
export function scanMeshConfig(config: MeshConfig): MeshScanResult {
  const issues: MeshIssue[] = [];
  let score = 100;

  // Check mTLS mode
  if (config.mtlsMode === "DISABLE") {
    issues.push({
      id: "mtls-disabled",
      severity: "CRITICAL",
      category: "mtls",
      resource: config.namespace,
      message: "mTLS is disabled - traffic is not encrypted",
      remediation: "Enable STRICT mTLS mode for encrypted service-to-service communication",
    });
    score -= 40;
  } else if (config.mtlsMode === "PERMISSIVE") {
    issues.push({
      id: "mtls-permissive",
      severity: "HIGH",
      category: "mtls",
      resource: config.namespace,
      message: "mTLS is in permissive mode - allows plaintext traffic",
      remediation: "Switch to STRICT mTLS mode to enforce encryption",
    });
    score -= 20;
  }

  // Check proxy version
  if (config.proxyVersion) {
    const isOld = isOutdatedVersion(config.proxyVersion, "1.20.0");
    if (isOld) {
      issues.push({
        id: "outdated-proxy",
        severity: "MEDIUM",
        category: "version",
        resource: config.namespace,
        message: `Proxy version ${config.proxyVersion} is outdated`,
        remediation: "Upgrade to the latest stable proxy version",
      });
      score -= 10;
    }
  }

  const result: MeshScanResult = {
    provider: config.provider,
    namespace: config.namespace,
    scannedAt: new Date().toISOString(),
    issues,
    passed: issues.filter((i) => i.severity === "CRITICAL" || i.severity === "HIGH").length === 0,
    score: Math.max(0, score),
  };

  // Store scan result
  getDb()
    .prepare(
      `INSERT INTO mesh_scans (provider, namespace, scanned_at, issues, passed, score)
     VALUES (?, ?, ?, ?, ?, ?)`
    )
    .run(
      config.provider,
      config.namespace,
      result.scannedAt,
      JSON.stringify(issues),
      result.passed ? 1 : 0,
      result.score
    );

  return result;
}

function isOutdatedVersion(current: string, minimum: string): boolean {
  const currentParts = current.split(".").map(Number);
  const minimumParts = minimum.split(".").map(Number);

  for (let i = 0; i < 3; i++) {
    if ((currentParts[i] || 0) < (minimumParts[i] || 0)) return true;
    if ((currentParts[i] || 0) > (minimumParts[i] || 0)) return false;
  }
  return false;
}

// mTLS Status
export function getMtlsStatus(namespace: string): MtlsStatus {
  // In production would query the mesh control plane
  return {
    namespace,
    mode: "STRICT",
    enabled: true,
    coverage: 100,
    services: [
      { name: "frontend", mtlsEnabled: true, peerAuthentication: "default" },
      { name: "backend", mtlsEnabled: true, peerAuthentication: "default" },
      { name: "database", mtlsEnabled: true, peerAuthentication: "strict" },
    ],
  };
}

// Policy Audit
export function auditAuthorizationPolicies(namespace: string): PolicyAuditResult {
  const policies = listPolicies(namespace);
  const findings: PolicyAuditResult["findings"] = [];

  for (const policy of policies) {
    // Check for overly permissive rules
    if (policy.action === "ALLOW" && (!policy.rules || policy.rules.length === 0)) {
      findings.push({
        policy: policy.name,
        severity: "HIGH",
        issue: "Policy allows all traffic without any rules",
        recommendation: "Add specific source/destination rules to limit access",
      });
    }

    // Check for missing authentication requirements
    const hasAuthCheck = policy.rules.some((r) => r.when?.some((w) => w.key.includes("auth")));
    if (!hasAuthCheck && policy.action === "ALLOW") {
      findings.push({
        policy: policy.name,
        severity: "MEDIUM",
        issue: "Policy does not require authentication",
        recommendation: "Add authentication requirements using request.auth claims",
      });
    }
  }

  return {
    namespace,
    policies,
    findings,
    auditedAt: new Date().toISOString(),
  };
}

// Policy Management
export function createMeshPolicy(
  policy: Omit<AuthorizationPolicy, "id" | "createdAt">
): AuthorizationPolicy {
  const id = `policy-${Date.now()}`;
  const now = new Date().toISOString();

  const record: AuthorizationPolicy = { ...policy, id, createdAt: now };

  getDb()
    .prepare(
      `INSERT INTO mesh_policies (id, name, namespace, action, rules, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`
    )
    .run(id, policy.name, policy.namespace, policy.action, JSON.stringify(policy.rules), now);

  return record;
}

export function listPolicies(namespace?: string): AuthorizationPolicy[] {
  let sql = "SELECT * FROM mesh_policies";
  const params: string[] = [];
  if (namespace) {
    sql += " WHERE namespace = ?";
    params.push(namespace);
  }
  sql += " ORDER BY name";

  return (
    getDb()
      .prepare(sql)
      .all(...params) as any[]
  ).map((r) => ({
    id: r.id,
    name: r.name,
    namespace: r.namespace,
    action: r.action,
    rules: JSON.parse(r.rules),
    createdAt: r.created_at,
  }));
}

// Certificate Expiry Checking
export function checkCertExpiry(namespace: string): CertificateInfo[] {
  const now = new Date();
  const warningDays = 30;

  // In production would query actual certificates from the mesh
  const certs: CertificateInfo[] = [
    {
      namespace,
      service: "frontend",
      issuer: "cluster.local",
      subject: "spiffe://cluster.local/ns/default/sa/frontend",
      notBefore: new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString(),
      notAfter: new Date(now.getTime() + 60 * 24 * 60 * 60 * 1000).toISOString(),
      daysUntilExpiry: 60,
      isExpired: false,
      isExpiringSoon: false,
    },
    {
      namespace,
      service: "backend",
      issuer: "cluster.local",
      subject: "spiffe://cluster.local/ns/default/sa/backend",
      notBefore: new Date(now.getTime() - 80 * 24 * 60 * 60 * 1000).toISOString(),
      notAfter: new Date(now.getTime() + 10 * 24 * 60 * 60 * 1000).toISOString(),
      daysUntilExpiry: 10,
      isExpired: false,
      isExpiringSoon: true,
    },
  ];

  return certs.map((cert) => ({
    ...cert,
    isExpiringSoon: cert.daysUntilExpiry <= warningDays && !cert.isExpired,
  }));
}

// Traffic Policy Analysis
export function analyzeTrafficPolicies(namespace: string): {
  policies: TrafficPolicy[];
  recommendations: string[];
} {
  // In production would fetch actual policies from mesh
  const policies: TrafficPolicy[] = [
    {
      id: "tp-1",
      name: "frontend-policy",
      namespace,
      host: "frontend.default.svc.cluster.local",
      trafficPolicy: {
        connectionPool: {
          tcp: { maxConnections: 100 },
          http: { h2UpgradePolicy: "UPGRADE", http1MaxPendingRequests: 1024 },
        },
        loadBalancer: { simple: "ROUND_ROBIN" },
        tls: { mode: "ISTIO_MUTUAL" },
      },
    },
  ];

  const recommendations: string[] = [];

  for (const policy of policies) {
    if (!policy.trafficPolicy.tls) {
      recommendations.push(`${policy.name}: Add TLS configuration for secure communication`);
    }
    if (!policy.trafficPolicy.connectionPool) {
      recommendations.push(
        `${policy.name}: Configure connection pool to prevent resource exhaustion`
      );
    }
  }

  return { policies, recommendations };
}

// Sidecar Version Check
export function checkSidecarVersions(namespace: string): SidecarInfo[] {
  const latestVersion = "1.20.0";

  // In production would query actual sidecar info
  return [
    {
      namespace,
      pod: "frontend-abc123",
      proxyVersion: "1.20.0",
      proxyStatus: "healthy",
      lastUpdated: new Date().toISOString(),
      needsUpgrade: false,
      latestVersion,
    },
    {
      namespace,
      pod: "backend-def456",
      proxyVersion: "1.18.0",
      proxyStatus: "healthy",
      lastUpdated: new Date().toISOString(),
      needsUpgrade: true,
      latestVersion,
    },
  ];
}

// CVE Checking
export function checkMeshCves(provider: MeshProvider, version: string): MeshCveInfo[] {
  // Store and check known CVEs
  const knownCves: MeshCveInfo[] = [
    {
      cveId: "CVE-2024-0001",
      severity: "HIGH",
      affectedVersions: ["1.17.0", "1.17.1", "1.17.2"],
      fixedVersion: "1.17.3",
      description: "Request smuggling vulnerability in proxy",
      published: "2024-01-15",
    },
    {
      cveId: "CVE-2024-0002",
      severity: "MEDIUM",
      affectedVersions: ["1.16.0", "1.16.1", "1.17.0"],
      fixedVersion: "1.17.1",
      description: "Information disclosure in control plane API",
      published: "2024-02-01",
    },
  ];

  return knownCves.filter((cve) => cve.affectedVersions.includes(version));
}

// Upgrade Path
export function getSecureUpgradePath(
  provider: MeshProvider,
  currentVersion: string,
  targetVersion: string
): UpgradePath {
  const steps: UpgradePath["steps"] = [];
  const securityFixes: string[] = [];

  // Parse versions
  const current = currentVersion.split(".").map(Number);
  const target = targetVersion.split(".").map(Number);

  // Generate upgrade path
  const ver = [...current];
  while (ver[0] < target[0] || ver[1] < target[1]) {
    ver[1]++;
    if (ver[1] > 20) {
      ver[0]++;
      ver[1] = 0;
    }

    const version = ver.join(".");
    steps.push({
      version,
      breaking: ver[1] === 0, // Minor version bump might have breaking changes
      notes: [`Upgrade to ${version}`],
    });

    // Check for security fixes in this version
    const cves = checkMeshCves(provider, version);
    for (const cve of cves) {
      if (cve.fixedVersion === version) {
        securityFixes.push(`${cve.cveId}: ${cve.description}`);
      }
    }

    if (ver[0] >= target[0] && ver[1] >= target[1]) break;
  }

  return {
    currentVersion,
    targetVersion,
    steps,
    securityFixes,
  };
}

// Summary
export function getMeshSecuritySummary(namespace: string): {
  mtlsStatus: MtlsStatus;
  expiringCerts: number;
  policyFindings: number;
  outdatedSidecars: number;
  overallScore: number;
} {
  const mtlsStatus = getMtlsStatus(namespace);
  const certs = checkCertExpiry(namespace);
  const policyAudit = auditAuthorizationPolicies(namespace);
  const sidecars = checkSidecarVersions(namespace);

  const expiringCerts = certs.filter((c) => c.isExpiringSoon || c.isExpired).length;
  const policyFindings = policyAudit.findings.length;
  const outdatedSidecars = sidecars.filter((s) => s.needsUpgrade).length;

  let score = 100;
  if (!mtlsStatus.enabled) score -= 30;
  if (mtlsStatus.coverage < 100) score -= (100 - mtlsStatus.coverage) * 0.2;
  score -= expiringCerts * 10;
  score -= policyFindings * 5;
  score -= outdatedSidecars * 5;

  return {
    mtlsStatus,
    expiringCerts,
    policyFindings,
    outdatedSidecars,
    overallScore: Math.max(0, Math.round(score)),
  };
}

export const serviceMesh = {
  initMeshDb,
  scanMeshConfig,
  getMtlsStatus,
  auditAuthorizationPolicies,
  createMeshPolicy,
  listPolicies,
  checkCertExpiry,
  analyzeTrafficPolicies,
  checkSidecarVersions,
  checkMeshCves,
  getSecureUpgradePath,
  getMeshSecuritySummary,
};
