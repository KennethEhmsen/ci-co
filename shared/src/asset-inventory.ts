/**
 * Asset Inventory Module (v1.28.0)
 *
 * Track scanned targets (container images, repositories, projects) and
 * their security posture over time:
 * - Asset registration and metadata management
 * - Security posture tracking per asset
 * - Last scan tracking with stale detection
 * - Asset criticality and ownership
 */

import Database from "better-sqlite3";
import { randomUUID } from "crypto";

// =============================================================================
// Types
// =============================================================================

export type AssetType = "container_image" | "repository" | "project" | "filesystem" | "sbom";

export type AssetCriticality = "critical" | "high" | "medium" | "low";

export type ComplianceStatus = "compliant" | "non_compliant" | "unknown" | "partial";

export interface Asset {
  id: string;
  type: AssetType;
  identifier: string; // e.g., "nginx:1.25", "org/repo", "project-name"
  name: string;
  description?: string;
  criticality: AssetCriticality;
  owner?: string;
  team?: string;
  tags: string[];
  metadata: Record<string, unknown>;
  lastScanAt?: string;
  lastScanId?: string;
  createdAt: string;
  updatedAt: string;
}

export interface AssetPosture {
  id: string;
  assetId: string;
  scanId: string;
  scanType: string;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  unknownCount: number;
  totalVulnerabilities: number;
  complianceStatus: ComplianceStatus;
  complianceScore?: number;
  findings: SecurityFinding[];
  scannedAt: string;
}

export interface SecurityFinding {
  id: string;
  severity: string;
  title: string;
  source: string;
  status?: string;
}

export interface RegisterAssetOptions {
  type: AssetType;
  identifier: string;
  name: string;
  description?: string;
  criticality?: AssetCriticality;
  owner?: string;
  team?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface UpdateAssetMetadataOptions {
  name?: string;
  description?: string;
  criticality?: AssetCriticality;
  owner?: string;
  team?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface AssetListOptions {
  type?: AssetType;
  criticality?: AssetCriticality;
  owner?: string;
  team?: string;
  tag?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface RecordPostureOptions {
  assetId: string;
  scanId: string;
  scanType: string;
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
  unknownCount?: number;
  complianceStatus?: ComplianceStatus;
  complianceScore?: number;
  findings?: SecurityFinding[];
}

export interface StaleAssetOptions {
  staleDays?: number;
  type?: AssetType;
  criticality?: AssetCriticality;
}

export interface AssetSummary {
  totalAssets: number;
  byType: Record<AssetType, number>;
  byCriticality: Record<AssetCriticality, number>;
  staleCount: number;
  recentlyScanned: number;
  averageVulnerabilities: number;
}

export interface AssetDbInitResult {
  path: string;
  created: boolean;
}

export interface AssetAuditEntry {
  id: string;
  eventType: string;
  assetId?: string;
  actorId?: string;
  details: Record<string, unknown>;
  timestamp: string;
}

// =============================================================================
// Database Management
// =============================================================================

let assetDb: Database.Database | null = null;
let assetDbPath: string | null = null;

const ASSET_SCHEMA = `
-- Assets table
CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  identifier TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  criticality TEXT DEFAULT 'medium',
  owner TEXT,
  team TEXT,
  tags_json TEXT DEFAULT '[]',
  metadata_json TEXT DEFAULT '{}',
  last_scan_at TEXT,
  last_scan_id TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(type, identifier)
);

-- Asset posture history
CREATE TABLE IF NOT EXISTS asset_posture (
  id TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL,
  scan_id TEXT NOT NULL,
  scan_type TEXT NOT NULL,
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  low_count INTEGER DEFAULT 0,
  unknown_count INTEGER DEFAULT 0,
  total_vulnerabilities INTEGER DEFAULT 0,
  compliance_status TEXT DEFAULT 'unknown',
  compliance_score REAL,
  findings_json TEXT DEFAULT '[]',
  scanned_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

-- Asset audit log
CREATE TABLE IF NOT EXISTS asset_audit (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  asset_id TEXT,
  actor_id TEXT,
  details_json TEXT DEFAULT '{}',
  timestamp TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);
CREATE INDEX IF NOT EXISTS idx_assets_owner ON assets(owner);
CREATE INDEX IF NOT EXISTS idx_assets_last_scan ON assets(last_scan_at);
CREATE INDEX IF NOT EXISTS idx_posture_asset ON asset_posture(asset_id);
CREATE INDEX IF NOT EXISTS idx_posture_scan_date ON asset_posture(scanned_at);
CREATE INDEX IF NOT EXISTS idx_audit_asset ON asset_audit(asset_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON asset_audit(timestamp);
`;

/**
 * Initialize asset inventory database
 */
export function initAssetDatabase(path?: string): AssetDbInitResult {
  const dbPath = path || "./asset-inventory.db";
  const isNew = !assetDb;

  if (assetDb && assetDbPath === dbPath) {
    return { path: dbPath, created: false };
  }

  if (assetDb) {
    assetDb.close();
  }

  assetDb = new Database(dbPath);
  assetDb.pragma("journal_mode = WAL");
  assetDb.pragma("foreign_keys = ON");
  assetDb.exec(ASSET_SCHEMA);
  assetDbPath = dbPath;

  return { path: dbPath, created: isNew };
}

/**
 * Get database instance
 */
export function getAssetDatabase(): Database.Database {
  if (!assetDb) {
    initAssetDatabase();
  }
  return assetDb!;
}

/**
 * Close database connection
 */
export function closeAssetDatabase(): void {
  if (assetDb) {
    assetDb.close();
    assetDb = null;
    assetDbPath = null;
  }
}

// =============================================================================
// Audit Logging
// =============================================================================

/**
 * Log asset audit event
 */
function logAudit(
  eventType: string,
  assetId?: string,
  actor?: string,
  details: Record<string, unknown> = {}
): void {
  const db = getAssetDatabase();
  const stmt = db.prepare(`
    INSERT INTO asset_audit (id, event_type, asset_id, actor_id, details_json, timestamp)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    randomUUID(),
    eventType,
    assetId || null,
    actor || null,
    JSON.stringify(details),
    new Date().toISOString()
  );
}

/**
 * Get audit log entries for an asset
 */
export function getAssetAuditLog(assetId?: string, limit: number = 100): AssetAuditEntry[] {
  const db = getAssetDatabase();
  let query = "SELECT * FROM asset_audit";
  const params: unknown[] = [];

  if (assetId) {
    query += " WHERE asset_id = ?";
    params.push(assetId);
  }
  query += " ORDER BY timestamp DESC LIMIT ?";
  params.push(limit);

  const rows = db.prepare(query).all(...params) as Array<{
    id: string;
    event_type: string;
    asset_id: string | null;
    actor_id: string | null;
    details_json: string;
    timestamp: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    eventType: row.event_type,
    assetId: row.asset_id || undefined,
    actorId: row.actor_id || undefined,
    details: JSON.parse(row.details_json || "{}"),
    timestamp: row.timestamp,
  }));
}

// =============================================================================
// Asset CRUD Operations
// =============================================================================

/**
 * Register a new asset
 */
export function registerAsset(options: RegisterAssetOptions, actor?: string): Asset {
  const db = getAssetDatabase();
  const id = randomUUID();
  const now = new Date().toISOString();

  const stmt = db.prepare(`
    INSERT INTO assets (id, type, identifier, name, description, criticality, owner, team, tags_json, metadata_json, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    id,
    options.type,
    options.identifier,
    options.name,
    options.description || null,
    options.criticality || "medium",
    options.owner || null,
    options.team || null,
    JSON.stringify(options.tags || []),
    JSON.stringify(options.metadata || {}),
    now,
    now
  );

  logAudit("asset_registered", id, actor, {
    type: options.type,
    identifier: options.identifier,
    name: options.name,
  });

  return getAsset(id)!;
}

/**
 * Get asset by ID
 */
export function getAsset(id: string): Asset | null {
  const db = getAssetDatabase();
  const row = db.prepare("SELECT * FROM assets WHERE id = ?").get(id) as
    | {
        id: string;
        type: AssetType;
        identifier: string;
        name: string;
        description: string | null;
        criticality: AssetCriticality;
        owner: string | null;
        team: string | null;
        tags_json: string;
        metadata_json: string;
        last_scan_at: string | null;
        last_scan_id: string | null;
        created_at: string;
        updated_at: string;
      }
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    type: row.type,
    identifier: row.identifier,
    name: row.name,
    description: row.description || undefined,
    criticality: row.criticality,
    owner: row.owner || undefined,
    team: row.team || undefined,
    tags: JSON.parse(row.tags_json || "[]"),
    metadata: JSON.parse(row.metadata_json || "{}"),
    lastScanAt: row.last_scan_at || undefined,
    lastScanId: row.last_scan_id || undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * Get asset by type and identifier
 */
export function getAssetByIdentifier(type: AssetType, identifier: string): Asset | null {
  const db = getAssetDatabase();
  const row = db
    .prepare("SELECT * FROM assets WHERE type = ? AND identifier = ?")
    .get(type, identifier) as
    | {
        id: string;
        type: AssetType;
        identifier: string;
        name: string;
        description: string | null;
        criticality: AssetCriticality;
        owner: string | null;
        team: string | null;
        tags_json: string;
        metadata_json: string;
        last_scan_at: string | null;
        last_scan_id: string | null;
        created_at: string;
        updated_at: string;
      }
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    type: row.type,
    identifier: row.identifier,
    name: row.name,
    description: row.description || undefined,
    criticality: row.criticality,
    owner: row.owner || undefined,
    team: row.team || undefined,
    tags: JSON.parse(row.tags_json || "[]"),
    metadata: JSON.parse(row.metadata_json || "{}"),
    lastScanAt: row.last_scan_at || undefined,
    lastScanId: row.last_scan_id || undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * List assets with filtering
 */
export function listAssets(options: AssetListOptions = {}): Asset[] {
  const db = getAssetDatabase();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options.type) {
    conditions.push("type = ?");
    params.push(options.type);
  }
  if (options.criticality) {
    conditions.push("criticality = ?");
    params.push(options.criticality);
  }
  if (options.owner) {
    conditions.push("owner = ?");
    params.push(options.owner);
  }
  if (options.team) {
    conditions.push("team = ?");
    params.push(options.team);
  }
  if (options.tag) {
    conditions.push("tags_json LIKE ?");
    params.push(`%"${options.tag}"%`);
  }
  if (options.search) {
    conditions.push("(name LIKE ? OR identifier LIKE ? OR description LIKE ?)");
    const searchTerm = `%${options.search}%`;
    params.push(searchTerm, searchTerm, searchTerm);
  }

  let query = "SELECT * FROM assets";
  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }
  query += " ORDER BY updated_at DESC";

  if (options.limit) {
    query += " LIMIT ?";
    params.push(options.limit);
  }
  if (options.offset) {
    query += " OFFSET ?";
    params.push(options.offset);
  }

  const rows = db.prepare(query).all(...params) as Array<{
    id: string;
    type: AssetType;
    identifier: string;
    name: string;
    description: string | null;
    criticality: AssetCriticality;
    owner: string | null;
    team: string | null;
    tags_json: string;
    metadata_json: string;
    last_scan_at: string | null;
    last_scan_id: string | null;
    created_at: string;
    updated_at: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    type: row.type,
    identifier: row.identifier,
    name: row.name,
    description: row.description || undefined,
    criticality: row.criticality,
    owner: row.owner || undefined,
    team: row.team || undefined,
    tags: JSON.parse(row.tags_json || "[]"),
    metadata: JSON.parse(row.metadata_json || "{}"),
    lastScanAt: row.last_scan_at || undefined,
    lastScanId: row.last_scan_id || undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

/**
 * Update asset metadata
 */
export function updateAssetMetadata(
  id: string,
  options: UpdateAssetMetadataOptions,
  actor?: string
): Asset | null {
  const db = getAssetDatabase();
  const asset = getAsset(id);
  if (!asset) return null;

  const updates: string[] = [];
  const params: unknown[] = [];

  if (options.name !== undefined) {
    updates.push("name = ?");
    params.push(options.name);
  }
  if (options.description !== undefined) {
    updates.push("description = ?");
    params.push(options.description);
  }
  if (options.criticality !== undefined) {
    updates.push("criticality = ?");
    params.push(options.criticality);
  }
  if (options.owner !== undefined) {
    updates.push("owner = ?");
    params.push(options.owner);
  }
  if (options.team !== undefined) {
    updates.push("team = ?");
    params.push(options.team);
  }
  if (options.tags !== undefined) {
    updates.push("tags_json = ?");
    params.push(JSON.stringify(options.tags));
  }
  if (options.metadata !== undefined) {
    updates.push("metadata_json = ?");
    params.push(JSON.stringify(options.metadata));
  }

  if (updates.length === 0) return asset;

  updates.push("updated_at = ?");
  params.push(new Date().toISOString());
  params.push(id);

  const stmt = db.prepare(`UPDATE assets SET ${updates.join(", ")} WHERE id = ?`);
  stmt.run(...params);

  logAudit("asset_updated", id, actor, { updates: Object.keys(options) });

  return getAsset(id);
}

/**
 * Delete asset
 */
export function deleteAsset(id: string, actor?: string): boolean {
  const db = getAssetDatabase();
  const asset = getAsset(id);
  if (!asset) return false;

  db.prepare("DELETE FROM assets WHERE id = ?").run(id);
  logAudit("asset_deleted", id, actor, {
    type: asset.type,
    identifier: asset.identifier,
  });

  return true;
}

// =============================================================================
// Security Posture Tracking
// =============================================================================

/**
 * Record security posture for an asset
 */
export function recordAssetPosture(options: RecordPostureOptions, actor?: string): AssetPosture {
  const db = getAssetDatabase();
  const id = randomUUID();
  const now = new Date().toISOString();

  const criticalCount = options.criticalCount || 0;
  const highCount = options.highCount || 0;
  const mediumCount = options.mediumCount || 0;
  const lowCount = options.lowCount || 0;
  const unknownCount = options.unknownCount || 0;
  const totalVulnerabilities = criticalCount + highCount + mediumCount + lowCount + unknownCount;

  const stmt = db.prepare(`
    INSERT INTO asset_posture (
      id, asset_id, scan_id, scan_type,
      critical_count, high_count, medium_count, low_count, unknown_count,
      total_vulnerabilities, compliance_status, compliance_score, findings_json, scanned_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    id,
    options.assetId,
    options.scanId,
    options.scanType,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    unknownCount,
    totalVulnerabilities,
    options.complianceStatus || "unknown",
    options.complianceScore || null,
    JSON.stringify(options.findings || []),
    now
  );

  // Update asset last scan info
  db.prepare(
    `
    UPDATE assets SET last_scan_at = ?, last_scan_id = ?, updated_at = ?
    WHERE id = ?
  `
  ).run(now, options.scanId, now, options.assetId);

  logAudit("posture_recorded", options.assetId, actor, {
    scanId: options.scanId,
    scanType: options.scanType,
    totalVulnerabilities,
  });

  return getAssetPosture(options.assetId)!;
}

/**
 * Get latest posture for an asset
 */
export function getAssetPosture(assetId: string): AssetPosture | null {
  const db = getAssetDatabase();
  const row = db
    .prepare("SELECT * FROM asset_posture WHERE asset_id = ? ORDER BY scanned_at DESC LIMIT 1")
    .get(assetId) as
    | {
        id: string;
        asset_id: string;
        scan_id: string;
        scan_type: string;
        critical_count: number;
        high_count: number;
        medium_count: number;
        low_count: number;
        unknown_count: number;
        total_vulnerabilities: number;
        compliance_status: ComplianceStatus;
        compliance_score: number | null;
        findings_json: string;
        scanned_at: string;
      }
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    assetId: row.asset_id,
    scanId: row.scan_id,
    scanType: row.scan_type,
    criticalCount: row.critical_count,
    highCount: row.high_count,
    mediumCount: row.medium_count,
    lowCount: row.low_count,
    unknownCount: row.unknown_count,
    totalVulnerabilities: row.total_vulnerabilities,
    complianceStatus: row.compliance_status,
    complianceScore: row.compliance_score || undefined,
    findings: JSON.parse(row.findings_json || "[]"),
    scannedAt: row.scanned_at,
  };
}

/**
 * Get posture history for an asset
 */
export function getAssetPostureHistory(assetId: string, limit: number = 30): AssetPosture[] {
  const db = getAssetDatabase();
  const rows = db
    .prepare("SELECT * FROM asset_posture WHERE asset_id = ? ORDER BY scanned_at DESC LIMIT ?")
    .all(assetId, limit) as Array<{
    id: string;
    asset_id: string;
    scan_id: string;
    scan_type: string;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    unknown_count: number;
    total_vulnerabilities: number;
    compliance_status: ComplianceStatus;
    compliance_score: number | null;
    findings_json: string;
    scanned_at: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    assetId: row.asset_id,
    scanId: row.scan_id,
    scanType: row.scan_type,
    criticalCount: row.critical_count,
    highCount: row.high_count,
    mediumCount: row.medium_count,
    lowCount: row.low_count,
    unknownCount: row.unknown_count,
    totalVulnerabilities: row.total_vulnerabilities,
    complianceStatus: row.compliance_status,
    complianceScore: row.compliance_score || undefined,
    findings: JSON.parse(row.findings_json || "[]"),
    scannedAt: row.scanned_at,
  }));
}

// =============================================================================
// Stale Asset Detection
// =============================================================================

/**
 * Find assets that haven't been scanned recently
 */
export function findStaleAssets(options: StaleAssetOptions = {}): Asset[] {
  const db = getAssetDatabase();
  const staleDays = options.staleDays || 7;
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - staleDays);
  const cutoffIso = cutoffDate.toISOString();

  const conditions: string[] = ["(last_scan_at IS NULL OR last_scan_at < ?)"];
  const params: unknown[] = [cutoffIso];

  if (options.type) {
    conditions.push("type = ?");
    params.push(options.type);
  }
  if (options.criticality) {
    conditions.push("criticality = ?");
    params.push(options.criticality);
  }

  const query = `SELECT * FROM assets WHERE ${conditions.join(" AND ")} ORDER BY criticality DESC, last_scan_at ASC`;
  const rows = db.prepare(query).all(...params) as Array<{
    id: string;
    type: AssetType;
    identifier: string;
    name: string;
    description: string | null;
    criticality: AssetCriticality;
    owner: string | null;
    team: string | null;
    tags_json: string;
    metadata_json: string;
    last_scan_at: string | null;
    last_scan_id: string | null;
    created_at: string;
    updated_at: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    type: row.type,
    identifier: row.identifier,
    name: row.name,
    description: row.description || undefined,
    criticality: row.criticality,
    owner: row.owner || undefined,
    team: row.team || undefined,
    tags: JSON.parse(row.tags_json || "[]"),
    metadata: JSON.parse(row.metadata_json || "{}"),
    lastScanAt: row.last_scan_at || undefined,
    lastScanId: row.last_scan_id || undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

/**
 * Get days since last scan for an asset
 */
export function getAssetScanAge(assetId: string): number | null {
  const asset = getAsset(assetId);
  if (!asset || !asset.lastScanAt) return null;

  const lastScan = new Date(asset.lastScanAt);
  const now = new Date();
  const diffMs = now.getTime() - lastScan.getTime();
  return Math.floor(diffMs / (1000 * 60 * 60 * 24));
}

// =============================================================================
// Statistics and Summary
// =============================================================================

/**
 * Get asset inventory summary
 */
export function getAssetSummary(staleDays: number = 7): AssetSummary {
  const db = getAssetDatabase();

  // Total count
  const totalRow = db.prepare("SELECT COUNT(*) as count FROM assets").get() as { count: number };

  // By type
  const typeRows = db
    .prepare("SELECT type, COUNT(*) as count FROM assets GROUP BY type")
    .all() as Array<{ type: AssetType; count: number }>;
  const byType: Record<AssetType, number> = {
    container_image: 0,
    repository: 0,
    project: 0,
    filesystem: 0,
    sbom: 0,
  };
  for (const row of typeRows) {
    byType[row.type] = row.count;
  }

  // By criticality
  const critRows = db
    .prepare("SELECT criticality, COUNT(*) as count FROM assets GROUP BY criticality")
    .all() as Array<{ criticality: AssetCriticality; count: number }>;
  const byCriticality: Record<AssetCriticality, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const row of critRows) {
    byCriticality[row.criticality] = row.count;
  }

  // Stale count
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - staleDays);
  const staleRow = db
    .prepare("SELECT COUNT(*) as count FROM assets WHERE last_scan_at IS NULL OR last_scan_at < ?")
    .get(cutoffDate.toISOString()) as { count: number };

  // Recently scanned (last 24 hours)
  const recentDate = new Date();
  recentDate.setDate(recentDate.getDate() - 1);
  const recentRow = db
    .prepare("SELECT COUNT(*) as count FROM assets WHERE last_scan_at > ?")
    .get(recentDate.toISOString()) as { count: number };

  // Average vulnerabilities from latest postures
  const avgRow = db
    .prepare(
      `
      SELECT AVG(total_vulnerabilities) as avg
      FROM (
        SELECT asset_id, total_vulnerabilities
        FROM asset_posture
        WHERE id IN (
          SELECT id FROM asset_posture p1
          WHERE scanned_at = (
            SELECT MAX(scanned_at) FROM asset_posture p2 WHERE p2.asset_id = p1.asset_id
          )
        )
      )
    `
    )
    .get() as { avg: number | null };

  return {
    totalAssets: totalRow.count,
    byType,
    byCriticality,
    staleCount: staleRow.count,
    recentlyScanned: recentRow.count,
    averageVulnerabilities: avgRow.avg || 0,
  };
}

// =============================================================================
// Bulk Operations
// =============================================================================

/**
 * Register multiple assets in a transaction
 */
export function bulkRegisterAssets(assets: RegisterAssetOptions[], actor?: string): Asset[] {
  const db = getAssetDatabase();
  const results: Asset[] = [];

  const insertStmt = db.prepare(`
    INSERT INTO assets (id, type, identifier, name, description, criticality, owner, team, tags_json, metadata_json, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const transaction = db.transaction(() => {
    const now = new Date().toISOString();
    for (const options of assets) {
      const id = randomUUID();
      insertStmt.run(
        id,
        options.type,
        options.identifier,
        options.name,
        options.description || null,
        options.criticality || "medium",
        options.owner || null,
        options.team || null,
        JSON.stringify(options.tags || []),
        JSON.stringify(options.metadata || {}),
        now,
        now
      );
      const asset = getAsset(id);
      if (asset) results.push(asset);
    }
  });

  transaction();

  logAudit("bulk_assets_registered", undefined, actor, {
    count: results.length,
  });

  return results;
}

/**
 * Bulk update asset criticality
 */
export function bulkUpdateCriticality(
  assetIds: string[],
  criticality: AssetCriticality,
  actor?: string
): number {
  const db = getAssetDatabase();
  const now = new Date().toISOString();

  const placeholders = assetIds.map(() => "?").join(",");
  const stmt = db.prepare(`
    UPDATE assets SET criticality = ?, updated_at = ?
    WHERE id IN (${placeholders})
  `);

  const result = stmt.run(criticality, now, ...assetIds);

  logAudit("bulk_criticality_updated", undefined, actor, {
    assetIds,
    criticality,
    affected: result.changes,
  });

  return result.changes;
}

/**
 * Get or create asset by identifier
 */
export function getOrCreateAsset(
  options: RegisterAssetOptions,
  actor?: string
): { asset: Asset; created: boolean } {
  const existing = getAssetByIdentifier(options.type, options.identifier);
  if (existing) {
    return { asset: existing, created: false };
  }
  const asset = registerAsset(options, actor);
  return { asset, created: true };
}

/**
 * Link scan result to asset and record posture
 */
export function linkScanToAsset(
  type: AssetType,
  identifier: string,
  scanId: string,
  scanType: string,
  vulnerabilityCounts: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    unknown?: number;
  },
  complianceStatus?: ComplianceStatus,
  actor?: string
): { asset: Asset; posture: AssetPosture } {
  // Get or create the asset
  const { asset } = getOrCreateAsset(
    {
      type,
      identifier,
      name: identifier,
    },
    actor
  );

  // Record the posture
  const posture = recordAssetPosture(
    {
      assetId: asset.id,
      scanId,
      scanType,
      criticalCount: vulnerabilityCounts.critical,
      highCount: vulnerabilityCounts.high,
      mediumCount: vulnerabilityCounts.medium,
      lowCount: vulnerabilityCounts.low,
      unknownCount: vulnerabilityCounts.unknown,
      complianceStatus,
    },
    actor
  );

  return { asset: getAsset(asset.id)!, posture };
}
