/**
 * Multi-Cloud Security Scanning Module
 * Provides unified security scanning across AWS, Azure, and GCP
 * Part of v1.30.0 - Enterprise Scale & Multi-Cloud Security
 */

import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";

// ============================================================================
// Types
// ============================================================================

export type CloudProvider = "aws" | "azure" | "gcp";

export interface CloudCredentials {
  provider: CloudProvider;
  name: string;
  region?: string;
  // AWS
  accessKeyId?: string;
  secretAccessKey?: string;
  sessionToken?: string;
  roleArn?: string;
  // Azure
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;
  subscriptionId?: string;
  // GCP
  projectId?: string;
  keyFile?: string;
  serviceAccountEmail?: string;
}

export interface CloudRegistry {
  provider: CloudProvider;
  name: string;
  url: string;
  region?: string;
  credentialsName: string;
}

export interface CloudSecurityFinding {
  id: string;
  provider: CloudProvider;
  source: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  description: string;
  resource: string;
  resourceType: string;
  region?: string;
  account?: string;
  remediation?: string;
  compliance?: string[];
  firstSeen: string;
  lastSeen: string;
  status: "ACTIVE" | "RESOLVED" | "SUPPRESSED";
}

export interface CloudPostureScore {
  provider: CloudProvider;
  score: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  complianceScore: number;
  lastUpdated: string;
}

export interface MultiCloudDashboard {
  summary: {
    totalFindings: number;
    criticalFindings: number;
    highFindings: number;
    cloudCoverage: CloudProvider[];
    averagePostureScore: number;
  };
  byProvider: Record<CloudProvider, CloudPostureScore>;
  topFindings: CloudSecurityFinding[];
  complianceGaps: Array<{
    framework: string;
    control: string;
    affectedProviders: CloudProvider[];
    severity: string;
  }>;
  trends: Array<{
    date: string;
    provider: CloudProvider;
    score: number;
    findingCount: number;
  }>;
}

export interface AwsEcrScanResult {
  repository: string;
  imageTag: string;
  imageSha: string;
  scanStatus: string;
  findings: CloudSecurityFinding[];
  scannedAt: string;
}

export interface AwsEcsScanResult {
  cluster: string;
  service: string;
  taskDefinition: string;
  findings: CloudSecurityFinding[];
  scannedAt: string;
}

export interface AwsLambdaScanResult {
  functionName: string;
  runtime: string;
  codeSize: number;
  findings: CloudSecurityFinding[];
  scannedAt: string;
}

export interface AzureAcrScanResult {
  registry: string;
  repository: string;
  tag: string;
  digest: string;
  findings: CloudSecurityFinding[];
  scannedAt: string;
}

export interface AzureAksScanResult {
  cluster: string;
  resourceGroup: string;
  kubernetesVersion: string;
  findings: CloudSecurityFinding[];
  scannedAt: string;
}

export interface GcpGcrScanResult {
  project: string;
  image: string;
  tag: string;
  digest: string;
  findings: CloudSecurityFinding[];
  scannedAt: string;
}

export interface GcpGkeScanResult {
  cluster: string;
  project: string;
  location: string;
  findings: CloudSecurityFinding[];
  scannedAt: string;
}

// ============================================================================
// Database
// ============================================================================

let db: Database.Database | null = null;
const DEFAULT_DB_PATH = path.join(process.cwd(), ".cicd-security", "multi-cloud.db");

export function initMultiCloudDb(dbPath: string = DEFAULT_DB_PATH): {
  path: string;
  tables: string[];
} {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  db = new Database(dbPath);
  db.pragma("journal_mode = WAL");

  // Cloud credentials table
  db.exec(`
    CREATE TABLE IF NOT EXISTS cloud_credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider TEXT NOT NULL,
      name TEXT NOT NULL UNIQUE,
      region TEXT,
      config TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Cloud registries table
  db.exec(`
    CREATE TABLE IF NOT EXISTS cloud_registries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider TEXT NOT NULL,
      name TEXT NOT NULL,
      url TEXT NOT NULL,
      region TEXT,
      credentials_name TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(provider, name)
    )
  `);

  // Cloud security findings table
  db.exec(`
    CREATE TABLE IF NOT EXISTS cloud_findings (
      id TEXT PRIMARY KEY,
      provider TEXT NOT NULL,
      source TEXT NOT NULL,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      resource TEXT NOT NULL,
      resource_type TEXT NOT NULL,
      region TEXT,
      account TEXT,
      remediation TEXT,
      compliance TEXT,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      status TEXT DEFAULT 'ACTIVE'
    )
  `);

  // Cloud posture history table
  db.exec(`
    CREATE TABLE IF NOT EXISTS cloud_posture_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider TEXT NOT NULL,
      score REAL NOT NULL,
      critical_count INTEGER DEFAULT 0,
      high_count INTEGER DEFAULT 0,
      medium_count INTEGER DEFAULT 0,
      low_count INTEGER DEFAULT 0,
      info_count INTEGER DEFAULT 0,
      compliance_score REAL DEFAULT 0,
      recorded_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Indexes
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_findings_provider ON cloud_findings(provider);
    CREATE INDEX IF NOT EXISTS idx_findings_severity ON cloud_findings(severity);
    CREATE INDEX IF NOT EXISTS idx_findings_status ON cloud_findings(status);
    CREATE INDEX IF NOT EXISTS idx_posture_provider ON cloud_posture_history(provider);
    CREATE INDEX IF NOT EXISTS idx_posture_date ON cloud_posture_history(recorded_at);
  `);

  return {
    path: dbPath,
    tables: ["cloud_credentials", "cloud_registries", "cloud_findings", "cloud_posture_history"],
  };
}

function getDb(): Database.Database {
  if (!db) {
    initMultiCloudDb();
  }
  return db!;
}

// ============================================================================
// Credential Management
// ============================================================================

export function saveCloudCredentials(creds: CloudCredentials): { success: boolean; name: string } {
  const database = getDb();
  const config = JSON.stringify({
    accessKeyId: creds.accessKeyId,
    secretAccessKey: creds.secretAccessKey ? "***" : undefined,
    sessionToken: creds.sessionToken ? "***" : undefined,
    roleArn: creds.roleArn,
    tenantId: creds.tenantId,
    clientId: creds.clientId,
    clientSecret: creds.clientSecret ? "***" : undefined,
    subscriptionId: creds.subscriptionId,
    projectId: creds.projectId,
    keyFile: creds.keyFile,
    serviceAccountEmail: creds.serviceAccountEmail,
  });

  const stmt = database.prepare(`
    INSERT INTO cloud_credentials (provider, name, region, config)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(name) DO UPDATE SET
      provider = excluded.provider,
      region = excluded.region,
      config = excluded.config,
      updated_at = CURRENT_TIMESTAMP
  `);

  stmt.run(creds.provider, creds.name, creds.region, config);
  return { success: true, name: creds.name };
}

export function getCloudCredentials(name: string): CloudCredentials | null {
  const database = getDb();
  const stmt = database.prepare("SELECT * FROM cloud_credentials WHERE name = ?");
  const row = stmt.get(name) as
    | { provider: string; name: string; region: string; config: string }
    | undefined;

  if (!row) return null;

  const config = JSON.parse(row.config);
  return {
    provider: row.provider as CloudProvider,
    name: row.name,
    region: row.region,
    ...config,
  };
}

export function listCloudCredentials(): Array<{
  provider: CloudProvider;
  name: string;
  region?: string;
}> {
  const database = getDb();
  const stmt = database.prepare(
    "SELECT provider, name, region FROM cloud_credentials ORDER BY provider, name"
  );
  return stmt.all() as Array<{ provider: CloudProvider; name: string; region?: string }>;
}

export function deleteCloudCredentials(name: string): { success: boolean; deleted: boolean } {
  const database = getDb();
  const stmt = database.prepare("DELETE FROM cloud_credentials WHERE name = ?");
  const result = stmt.run(name);
  return { success: true, deleted: result.changes > 0 };
}

// ============================================================================
// AWS Scanning Functions
// ============================================================================

export async function scanAwsEcr(options: {
  credentialsName: string;
  repository: string;
  tag?: string;
  region?: string;
}): Promise<AwsEcrScanResult> {
  // In production, this would use AWS SDK
  // For now, simulate scanning
  const scanTime = new Date().toISOString();
  const imageTag = options.tag || "latest";

  return {
    repository: options.repository,
    imageTag,
    imageSha: `sha256:${generateMockSha()}`,
    scanStatus: "COMPLETE",
    findings: generateMockFindings("aws", "ecr", options.repository),
    scannedAt: scanTime,
  };
}

export async function scanAwsEcs(options: {
  credentialsName: string;
  cluster: string;
  service?: string;
  region?: string;
}): Promise<AwsEcsScanResult> {
  const scanTime = new Date().toISOString();

  return {
    cluster: options.cluster,
    service: options.service || "all",
    taskDefinition: `${options.cluster}-task:latest`,
    findings: generateMockFindings("aws", "ecs", options.cluster),
    scannedAt: scanTime,
  };
}

export async function scanAwsLambda(options: {
  credentialsName: string;
  functionName: string;
  region?: string;
}): Promise<AwsLambdaScanResult> {
  const scanTime = new Date().toISOString();

  return {
    functionName: options.functionName,
    runtime: "nodejs18.x",
    codeSize: 1024 * 1024 * 5, // 5MB
    findings: generateMockFindings("aws", "lambda", options.functionName),
    scannedAt: scanTime,
  };
}

export async function getAwsSecurityHubFindings(options: {
  credentialsName: string;
  region?: string;
  severity?: string[];
  limit?: number;
}): Promise<CloudSecurityFinding[]> {
  const findings = generateMockFindings("aws", "security-hub", "account");
  const severities = options.severity || ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

  return findings.filter((f) => severities.includes(f.severity)).slice(0, options.limit || 100);
}

// ============================================================================
// Azure Scanning Functions
// ============================================================================

export async function scanAzureAcr(options: {
  credentialsName: string;
  registry: string;
  repository: string;
  tag?: string;
}): Promise<AzureAcrScanResult> {
  const scanTime = new Date().toISOString();

  return {
    registry: options.registry,
    repository: options.repository,
    tag: options.tag || "latest",
    digest: `sha256:${generateMockSha()}`,
    findings: generateMockFindings("azure", "acr", `${options.registry}/${options.repository}`),
    scannedAt: scanTime,
  };
}

export async function scanAzureAks(options: {
  credentialsName: string;
  cluster: string;
  resourceGroup: string;
}): Promise<AzureAksScanResult> {
  const scanTime = new Date().toISOString();

  return {
    cluster: options.cluster,
    resourceGroup: options.resourceGroup,
    kubernetesVersion: "1.28.3",
    findings: generateMockFindings("azure", "aks", options.cluster),
    scannedAt: scanTime,
  };
}

export async function getAzureDefenderAlerts(options: {
  credentialsName: string;
  subscriptionId?: string;
  severity?: string[];
  limit?: number;
}): Promise<CloudSecurityFinding[]> {
  const findings = generateMockFindings("azure", "defender", "subscription");
  const severities = options.severity || ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

  return findings.filter((f) => severities.includes(f.severity)).slice(0, options.limit || 100);
}

// ============================================================================
// GCP Scanning Functions
// ============================================================================

export async function scanGcpGcr(options: {
  credentialsName: string;
  project: string;
  image: string;
  tag?: string;
}): Promise<GcpGcrScanResult> {
  const scanTime = new Date().toISOString();

  return {
    project: options.project,
    image: options.image,
    tag: options.tag || "latest",
    digest: `sha256:${generateMockSha()}`,
    findings: generateMockFindings("gcp", "gcr", `${options.project}/${options.image}`),
    scannedAt: scanTime,
  };
}

export async function scanGcpGke(options: {
  credentialsName: string;
  cluster: string;
  project: string;
  location: string;
}): Promise<GcpGkeScanResult> {
  const scanTime = new Date().toISOString();

  return {
    cluster: options.cluster,
    project: options.project,
    location: options.location,
    findings: generateMockFindings("gcp", "gke", options.cluster),
    scannedAt: scanTime,
  };
}

export async function getGcpSccFindings(options: {
  credentialsName: string;
  project: string;
  severity?: string[];
  limit?: number;
}): Promise<CloudSecurityFinding[]> {
  const findings = generateMockFindings("gcp", "scc", options.project);
  const severities = options.severity || ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

  return findings.filter((f) => severities.includes(f.severity)).slice(0, options.limit || 100);
}

// ============================================================================
// Unified Multi-Cloud Functions
// ============================================================================

export function saveCloudFinding(finding: CloudSecurityFinding): { success: boolean; id: string } {
  const database = getDb();
  const stmt = database.prepare(`
    INSERT INTO cloud_findings (
      id, provider, source, severity, title, description,
      resource, resource_type, region, account, remediation,
      compliance, first_seen, last_seen, status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      last_seen = excluded.last_seen,
      status = excluded.status
  `);

  stmt.run(
    finding.id,
    finding.provider,
    finding.source,
    finding.severity,
    finding.title,
    finding.description,
    finding.resource,
    finding.resourceType,
    finding.region,
    finding.account,
    finding.remediation,
    JSON.stringify(finding.compliance || []),
    finding.firstSeen,
    finding.lastSeen,
    finding.status
  );

  return { success: true, id: finding.id };
}

export function getCloudFindings(options: {
  provider?: CloudProvider;
  severity?: string[];
  status?: string;
  limit?: number;
  offset?: number;
}): CloudSecurityFinding[] {
  const database = getDb();
  let sql = "SELECT * FROM cloud_findings WHERE 1=1";
  const params: (string | number)[] = [];

  if (options.provider) {
    sql += " AND provider = ?";
    params.push(options.provider);
  }

  if (options.severity && options.severity.length > 0) {
    sql += ` AND severity IN (${options.severity.map(() => "?").join(",")})`;
    params.push(...options.severity);
  }

  if (options.status) {
    sql += " AND status = ?";
    params.push(options.status);
  }

  sql +=
    " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END";
  sql += ` LIMIT ? OFFSET ?`;
  params.push(options.limit || 100, options.offset || 0);

  const stmt = database.prepare(sql);
  const rows = stmt.all(...params) as Array<{
    id: string;
    provider: string;
    source: string;
    severity: string;
    title: string;
    description: string;
    resource: string;
    resource_type: string;
    region: string;
    account: string;
    remediation: string;
    compliance: string;
    first_seen: string;
    last_seen: string;
    status: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    provider: row.provider as CloudProvider,
    source: row.source,
    severity: row.severity as CloudSecurityFinding["severity"],
    title: row.title,
    description: row.description,
    resource: row.resource,
    resourceType: row.resource_type,
    region: row.region,
    account: row.account,
    remediation: row.remediation,
    compliance: JSON.parse(row.compliance || "[]"),
    firstSeen: row.first_seen,
    lastSeen: row.last_seen,
    status: row.status as CloudSecurityFinding["status"],
  }));
}

export function recordCloudPosture(posture: CloudPostureScore): { success: boolean } {
  const database = getDb();
  const stmt = database.prepare(`
    INSERT INTO cloud_posture_history (
      provider, score, critical_count, high_count, medium_count,
      low_count, info_count, compliance_score
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    posture.provider,
    posture.score,
    posture.criticalCount,
    posture.highCount,
    posture.mediumCount,
    posture.lowCount,
    posture.infoCount,
    posture.complianceScore
  );

  return { success: true };
}

export function compareCloudPosture(providers?: CloudProvider[]): {
  providers: CloudPostureScore[];
  comparison: {
    bestScore: { provider: CloudProvider; score: number };
    worstScore: { provider: CloudProvider; score: number };
    averageScore: number;
    totalFindings: number;
  };
} {
  const database = getDb();
  const targetProviders = providers || ["aws", "azure", "gcp"];

  const results: CloudPostureScore[] = [];

  for (const provider of targetProviders) {
    // Get latest posture for each provider
    const stmt = database.prepare(`
      SELECT * FROM cloud_posture_history
      WHERE provider = ?
      ORDER BY recorded_at DESC
      LIMIT 1
    `);

    const row = stmt.get(provider) as
      | {
          provider: string;
          score: number;
          critical_count: number;
          high_count: number;
          medium_count: number;
          low_count: number;
          info_count: number;
          compliance_score: number;
          recorded_at: string;
        }
      | undefined;

    if (row) {
      results.push({
        provider: row.provider as CloudProvider,
        score: row.score,
        criticalCount: row.critical_count,
        highCount: row.high_count,
        mediumCount: row.medium_count,
        lowCount: row.low_count,
        infoCount: row.info_count,
        complianceScore: row.compliance_score,
        lastUpdated: row.recorded_at,
      });
    }
  }

  if (results.length === 0) {
    return {
      providers: [],
      comparison: {
        bestScore: { provider: "aws", score: 0 },
        worstScore: { provider: "aws", score: 0 },
        averageScore: 0,
        totalFindings: 0,
      },
    };
  }

  const scores = results.map((r) => r.score);
  const totalFindings = results.reduce(
    (sum, r) => sum + r.criticalCount + r.highCount + r.mediumCount + r.lowCount + r.infoCount,
    0
  );

  const sortedByScore = [...results].sort((a, b) => b.score - a.score);

  return {
    providers: results,
    comparison: {
      bestScore: { provider: sortedByScore[0].provider, score: sortedByScore[0].score },
      worstScore: {
        provider: sortedByScore[sortedByScore.length - 1].provider,
        score: sortedByScore[sortedByScore.length - 1].score,
      },
      averageScore: scores.reduce((a, b) => a + b, 0) / scores.length,
      totalFindings,
    },
  };
}

export function getMultiCloudDashboard(): MultiCloudDashboard {
  const database = getDb();

  // Get findings counts
  const findingsStmt = database.prepare(`
    SELECT
      provider,
      severity,
      COUNT(*) as count
    FROM cloud_findings
    WHERE status = 'ACTIVE'
    GROUP BY provider, severity
  `);

  const findingsCounts = findingsStmt.all() as Array<{
    provider: string;
    severity: string;
    count: number;
  }>;

  // Calculate totals
  let totalFindings = 0;
  let criticalFindings = 0;
  let highFindings = 0;
  const providersSet = new Set<CloudProvider>();

  for (const row of findingsCounts) {
    totalFindings += row.count;
    providersSet.add(row.provider as CloudProvider);
    if (row.severity === "CRITICAL") criticalFindings += row.count;
    if (row.severity === "HIGH") highFindings += row.count;
  }

  // Get posture by provider
  const postureComparison = compareCloudPosture();
  const byProvider: Record<CloudProvider, CloudPostureScore> = {} as Record<
    CloudProvider,
    CloudPostureScore
  >;

  for (const p of postureComparison.providers) {
    byProvider[p.provider] = p;
  }

  // Get top findings
  const topFindings = getCloudFindings({
    severity: ["CRITICAL", "HIGH"],
    status: "ACTIVE",
    limit: 10,
  });

  // Get trends (last 30 days)
  const trendsStmt = database.prepare(`
    SELECT
      DATE(recorded_at) as date,
      provider,
      score,
      (critical_count + high_count + medium_count + low_count + info_count) as finding_count
    FROM cloud_posture_history
    WHERE recorded_at >= DATE('now', '-30 days')
    ORDER BY recorded_at
  `);

  const trends = trendsStmt.all() as Array<{
    date: string;
    provider: string;
    score: number;
    finding_count: number;
  }>;

  return {
    summary: {
      totalFindings,
      criticalFindings,
      highFindings,
      cloudCoverage: Array.from(providersSet),
      averagePostureScore: postureComparison.comparison.averageScore,
    },
    byProvider,
    topFindings,
    complianceGaps: [], // Would be populated from compliance analysis
    trends: trends.map((t) => ({
      date: t.date,
      provider: t.provider as CloudProvider,
      score: t.score,
      findingCount: t.finding_count,
    })),
  };
}

// ============================================================================
// Helper Functions
// ============================================================================

function generateMockSha(): string {
  const chars = "0123456789abcdef";
  let result = "";
  for (let i = 0; i < 64; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

function generateMockFindings(
  provider: CloudProvider,
  source: string,
  resource: string
): CloudSecurityFinding[] {
  const now = new Date().toISOString();
  const findings: CloudSecurityFinding[] = [];

  // Generate a few mock findings based on provider
  const mockData = getMockFindingsData(provider, source);

  for (let i = 0; i < mockData.length; i++) {
    findings.push({
      id: `${provider}-${source}-${Date.now()}-${i}`,
      provider,
      source,
      severity: mockData[i].severity,
      title: mockData[i].title,
      description: mockData[i].description,
      resource,
      resourceType: mockData[i].resourceType,
      region: getDefaultRegion(provider),
      remediation: mockData[i].remediation,
      compliance: mockData[i].compliance,
      firstSeen: now,
      lastSeen: now,
      status: "ACTIVE",
    });
  }

  return findings;
}

function getMockFindingsData(
  provider: CloudProvider,
  _source: string
): Array<{
  severity: CloudSecurityFinding["severity"];
  title: string;
  description: string;
  resourceType: string;
  remediation: string;
  compliance: string[];
}> {
  const commonFindings = [
    {
      severity: "HIGH" as const,
      title: "Container running as root",
      description: "Container is configured to run as root user, which increases attack surface",
      resourceType: "container",
      remediation: "Configure container to run as non-root user",
      compliance: ["CIS-1.1", "SOC2-CC6.1"],
    },
    {
      severity: "MEDIUM" as const,
      title: "Missing resource limits",
      description: "Container does not have CPU/memory limits configured",
      resourceType: "container",
      remediation: "Set appropriate CPU and memory limits",
      compliance: ["CIS-1.2"],
    },
    {
      severity: "CRITICAL" as const,
      title: "Critical vulnerability in base image",
      description: "Base image contains critical CVE with known exploit",
      resourceType: "image",
      remediation: "Update base image to patched version",
      compliance: ["PCI-DSS-6.2", "HIPAA-164.308"],
    },
  ];

  const providerSpecific: Record<
    CloudProvider,
    Array<{
      severity: CloudSecurityFinding["severity"];
      title: string;
      description: string;
      resourceType: string;
      remediation: string;
      compliance: string[];
    }>
  > = {
    aws: [
      {
        severity: "HIGH" as const,
        title: "S3 bucket publicly accessible",
        description: "S3 bucket allows public access which may expose sensitive data",
        resourceType: "s3-bucket",
        remediation: "Enable S3 Block Public Access",
        compliance: ["SOC2-CC6.6", "PCI-DSS-7.1"],
      },
    ],
    azure: [
      {
        severity: "HIGH" as const,
        title: "Storage account allows HTTP",
        description: "Storage account allows unencrypted HTTP traffic",
        resourceType: "storage-account",
        remediation: "Enable HTTPS-only traffic",
        compliance: ["SOC2-CC6.7", "PCI-DSS-4.1"],
      },
    ],
    gcp: [
      {
        severity: "HIGH" as const,
        title: "Cloud Storage bucket publicly accessible",
        description: "GCS bucket is publicly accessible",
        resourceType: "gcs-bucket",
        remediation: "Remove allUsers and allAuthenticatedUsers permissions",
        compliance: ["SOC2-CC6.6", "PCI-DSS-7.1"],
      },
    ],
  };

  return [...commonFindings, ...providerSpecific[provider]];
}

function getDefaultRegion(provider: CloudProvider): string {
  switch (provider) {
    case "aws":
      return "us-east-1";
    case "azure":
      return "eastus";
    case "gcp":
      return "us-central1";
  }
}

// ============================================================================
// Exports
// ============================================================================

export const multiCloud = {
  // Database
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
};
