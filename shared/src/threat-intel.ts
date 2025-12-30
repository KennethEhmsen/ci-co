/**
 * Threat Intelligence Module
 *
 * Provides threat intelligence integration for enriching vulnerability
 * data with real-world threat context and indicators of compromise (IOCs).
 *
 * Features:
 * - CVE enrichment with exploit availability data
 * - EPSS (Exploit Prediction Scoring System) scores
 * - KEV (Known Exploited Vulnerabilities) catalog integration
 * - Threat feed aggregation
 * - IOC management
 * - Threat actor tracking
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import type { SeverityLevel } from "./types.js";

// =============================================================================
// Types
// =============================================================================

export interface ThreatIntelConfig {
  /** Database path (defaults to ~/.cicd-security/threat-intel.db) */
  dbPath?: string;
  /** Cache TTL in seconds (defaults to 3600) */
  cacheTtl?: number;
  /** Enable auto-refresh of feeds */
  autoRefresh?: boolean;
}

export interface CVEEnrichment {
  cveId: string;
  /** EPSS score (0-1, probability of exploitation in next 30 days) */
  epssScore?: number;
  /** EPSS percentile (0-100) */
  epssPercentile?: number;
  /** Is in CISA KEV catalog */
  isKev: boolean;
  /** KEV details if present */
  kevDetails?: {
    vendorProject: string;
    product: string;
    vulnerabilityName: string;
    dateAdded: string;
    shortDescription: string;
    requiredAction: string;
    dueDate?: string;
  };
  /** Known exploits */
  exploits: ExploitInfo[];
  /** Threat actors known to use this CVE */
  threatActors: string[];
  /** Malware families that exploit this CVE */
  malwareFamilies: string[];
  /** Attack patterns (MITRE ATT&CK) */
  attackPatterns: string[];
  /** Enrichment timestamp */
  lastUpdated: string;
}

export interface ExploitInfo {
  source: string;
  url?: string;
  description?: string;
  published?: string;
  verified: boolean;
}

export interface ThreatFeed {
  id: string;
  name: string;
  type: "CVE" | "IOC" | "MALWARE" | "ACTOR";
  url: string;
  format: "json" | "csv" | "stix" | "openioc";
  enabled: boolean;
  lastSync?: string;
  entryCount?: number;
}

export interface IOC {
  id: string;
  type: IOCType;
  value: string;
  confidence: number; // 0-100
  severity: SeverityLevel;
  source: string;
  firstSeen: string;
  lastSeen: string;
  tags: string[];
  relatedCves: string[];
  description?: string;
}

export type IOCType =
  | "ip"
  | "domain"
  | "url"
  | "hash_md5"
  | "hash_sha1"
  | "hash_sha256"
  | "email"
  | "file_name"
  | "registry_key"
  | "mutex"
  | "user_agent";

export interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  motivation: string[];
  sophistication: "LOW" | "MEDIUM" | "HIGH" | "EXPERT";
  targetedSectors: string[];
  targetedCountries: string[];
  tools: string[];
  techniques: string[]; // MITRE ATT&CK IDs
  associatedCves: string[];
  lastActivity?: string;
  references: string[];
}

export interface ThreatReport {
  id: string;
  title: string;
  summary: string;
  severity: SeverityLevel;
  publishedDate: string;
  source: string;
  tags: string[];
  iocs: IOC[];
  cves: string[];
  actors: string[];
  mitigations: string[];
  url?: string;
}

export interface VulnThreatContext {
  cveId: string;
  riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  exploitAvailable: boolean;
  activelyExploited: boolean;
  epssScore?: number;
  threatScore: number; // 0-100 composite score
  priorityRecommendation: string;
  context: {
    hasPublicExploit: boolean;
    inKevCatalog: boolean;
    usedByThreatActors: boolean;
    recentActivity: boolean;
  };
}

// =============================================================================
// Database
// =============================================================================

let threatDb: Database.Database | null = null;

/**
 * Run multiple SQL statements
 */
function runStatements(db: Database.Database, statements: string[]): void {
  for (const stmt of statements) {
    const trimmed = stmt.trim();
    if (trimmed) {
      db.prepare(trimmed).run();
    }
  }
}

/**
 * Initialize threat intelligence database
 */
export function initThreatIntelDb(config?: ThreatIntelConfig): { path: string; created: boolean } {
  const dbPath = config?.dbPath || join(homedir(), ".cicd-security", "threat-intel.db");

  // Ensure directory exists
  const dbDir = dirname(dbPath);
  if (!existsSync(dbDir)) {
    mkdirSync(dbDir, { recursive: true });
  }

  const exists = existsSync(dbPath);
  threatDb = new Database(dbPath);

  // Create tables using individual statements
  const statements = [
    `CREATE TABLE IF NOT EXISTS cve_enrichment (
      cve_id TEXT PRIMARY KEY,
      epss_score REAL,
      epss_percentile REAL,
      is_kev INTEGER DEFAULT 0,
      kev_details TEXT,
      exploits TEXT,
      threat_actors TEXT,
      malware_families TEXT,
      attack_patterns TEXT,
      last_updated TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS threat_feeds (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      url TEXT NOT NULL,
      format TEXT NOT NULL,
      enabled INTEGER DEFAULT 1,
      last_sync TEXT,
      entry_count INTEGER DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS iocs (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      value TEXT NOT NULL,
      confidence INTEGER DEFAULT 50,
      severity TEXT DEFAULT 'MEDIUM',
      source TEXT NOT NULL,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      tags TEXT,
      related_cves TEXT,
      description TEXT,
      UNIQUE(type, value)
    )`,
    `CREATE TABLE IF NOT EXISTS threat_actors (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      aliases TEXT,
      description TEXT,
      motivation TEXT,
      sophistication TEXT,
      targeted_sectors TEXT,
      targeted_countries TEXT,
      tools TEXT,
      techniques TEXT,
      associated_cves TEXT,
      last_activity TEXT,
      refs TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS threat_reports (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      summary TEXT,
      severity TEXT,
      published_date TEXT,
      source TEXT,
      tags TEXT,
      ioc_ids TEXT,
      cves TEXT,
      actors TEXT,
      mitigations TEXT,
      url TEXT
    )`,
    `CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type)`,
    `CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value)`,
    `CREATE INDEX IF NOT EXISTS idx_cve_enrichment_kev ON cve_enrichment(is_kev)`,
  ];

  runStatements(threatDb, statements);

  // Seed default threat feeds
  seedDefaultFeeds();

  return { path: dbPath, created: !exists };
}

/**
 * Close threat intel database
 */
export function closeThreatIntelDb(): void {
  if (threatDb) {
    threatDb.close();
    threatDb = null;
  }
}

/**
 * Get database instance
 */
function getDb(): Database.Database {
  if (!threatDb) {
    throw new Error("Threat intel database not initialized. Call initThreatIntelDb first.");
  }
  return threatDb;
}

/**
 * Seed default threat feeds
 */
function seedDefaultFeeds(): void {
  const db = getDb();
  const defaultFeeds: ThreatFeed[] = [
    {
      id: "cisa-kev",
      name: "CISA Known Exploited Vulnerabilities",
      type: "CVE",
      url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      format: "json",
      enabled: true,
    },
    {
      id: "first-epss",
      name: "FIRST EPSS Scores",
      type: "CVE",
      url: "https://epss.cyentia.com/epss_scores-current.csv.gz",
      format: "csv",
      enabled: true,
    },
  ];

  const stmt = db.prepare(`
    INSERT OR IGNORE INTO threat_feeds (id, name, type, url, format, enabled)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  for (const feed of defaultFeeds) {
    stmt.run(feed.id, feed.name, feed.type, feed.url, feed.format, feed.enabled ? 1 : 0);
  }
}

// =============================================================================
// CVE Enrichment
// =============================================================================

/**
 * Get CVE enrichment data
 */
export function getCveEnrichment(cveId: string): CVEEnrichment | null {
  const db = getDb();
  const row = db.prepare("SELECT * FROM cve_enrichment WHERE cve_id = ?").get(cveId) as
    | {
        cve_id: string;
        epss_score: number | null;
        epss_percentile: number | null;
        is_kev: number;
        kev_details: string | null;
        exploits: string | null;
        threat_actors: string | null;
        malware_families: string | null;
        attack_patterns: string | null;
        last_updated: string;
      }
    | undefined;

  if (!row) return null;

  return {
    cveId: row.cve_id,
    epssScore: row.epss_score ?? undefined,
    epssPercentile: row.epss_percentile ?? undefined,
    isKev: row.is_kev === 1,
    kevDetails: row.kev_details ? JSON.parse(row.kev_details) : undefined,
    exploits: row.exploits ? JSON.parse(row.exploits) : [],
    threatActors: row.threat_actors ? JSON.parse(row.threat_actors) : [],
    malwareFamilies: row.malware_families ? JSON.parse(row.malware_families) : [],
    attackPatterns: row.attack_patterns ? JSON.parse(row.attack_patterns) : [],
    lastUpdated: row.last_updated,
  };
}

/**
 * Save CVE enrichment data
 */
export function saveCveEnrichment(enrichment: CVEEnrichment): void {
  const db = getDb();
  db.prepare(
    `
    INSERT OR REPLACE INTO cve_enrichment
    (cve_id, epss_score, epss_percentile, is_kev, kev_details, exploits,
     threat_actors, malware_families, attack_patterns, last_updated)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
  ).run(
    enrichment.cveId,
    enrichment.epssScore ?? null,
    enrichment.epssPercentile ?? null,
    enrichment.isKev ? 1 : 0,
    enrichment.kevDetails ? JSON.stringify(enrichment.kevDetails) : null,
    JSON.stringify(enrichment.exploits),
    JSON.stringify(enrichment.threatActors),
    JSON.stringify(enrichment.malwareFamilies),
    JSON.stringify(enrichment.attackPatterns),
    enrichment.lastUpdated
  );
}

/**
 * Get threat context for a vulnerability
 */
export function getVulnThreatContext(cveId: string): VulnThreatContext | null {
  const enrichment = getCveEnrichment(cveId);
  if (!enrichment) return null;

  const hasPublicExploit = enrichment.exploits.length > 0;
  const inKevCatalog = enrichment.isKev;
  const usedByThreatActors = enrichment.threatActors.length > 0;

  // Calculate threat score (0-100)
  let threatScore = 0;
  if (inKevCatalog) threatScore += 40;
  if (hasPublicExploit) threatScore += 25;
  if (usedByThreatActors) threatScore += 20;
  if (enrichment.epssScore) threatScore += enrichment.epssScore * 15;

  // Determine risk level
  let riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  if (inKevCatalog || threatScore >= 70) {
    riskLevel = "CRITICAL";
  } else if (hasPublicExploit || threatScore >= 50) {
    riskLevel = "HIGH";
  } else if (threatScore >= 25) {
    riskLevel = "MEDIUM";
  } else {
    riskLevel = "LOW";
  }

  // Generate priority recommendation
  let recommendation: string;
  if (inKevCatalog) {
    recommendation =
      "IMMEDIATE: This vulnerability is actively exploited in the wild. Patch within 24-48 hours.";
  } else if (hasPublicExploit) {
    recommendation =
      "HIGH PRIORITY: Public exploits exist. Patch within 1 week or implement mitigations.";
  } else if (usedByThreatActors) {
    recommendation =
      "ELEVATED: Known threat actors target this vulnerability. Prioritize patching.";
  } else {
    recommendation = "STANDARD: Follow normal patch cycle based on severity.";
  }

  return {
    cveId,
    riskLevel,
    exploitAvailable: hasPublicExploit,
    activelyExploited: inKevCatalog,
    epssScore: enrichment.epssScore,
    threatScore: Math.min(100, Math.round(threatScore)),
    priorityRecommendation: recommendation,
    context: {
      hasPublicExploit,
      inKevCatalog,
      usedByThreatActors,
      recentActivity: false, // Would need recent activity tracking
    },
  };
}

/**
 * Batch get threat context for multiple CVEs
 */
export function getBatchThreatContext(cveIds: string[]): Map<string, VulnThreatContext> {
  const results = new Map<string, VulnThreatContext>();
  for (const cveId of cveIds) {
    const context = getVulnThreatContext(cveId);
    if (context) {
      results.set(cveId, context);
    }
  }
  return results;
}

// =============================================================================
// Threat Feeds
// =============================================================================

/**
 * List configured threat feeds
 */
export function listThreatFeeds(): ThreatFeed[] {
  const db = getDb();
  const rows = db.prepare("SELECT * FROM threat_feeds").all() as Array<{
    id: string;
    name: string;
    type: string;
    url: string;
    format: string;
    enabled: number;
    last_sync: string | null;
    entry_count: number;
  }>;

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    type: row.type as ThreatFeed["type"],
    url: row.url,
    format: row.format as ThreatFeed["format"],
    enabled: row.enabled === 1,
    lastSync: row.last_sync ?? undefined,
    entryCount: row.entry_count,
  }));
}

/**
 * Add a threat feed
 */
export function addThreatFeed(feed: Omit<ThreatFeed, "lastSync" | "entryCount">): void {
  const db = getDb();
  db.prepare(
    `
    INSERT OR REPLACE INTO threat_feeds (id, name, type, url, format, enabled)
    VALUES (?, ?, ?, ?, ?, ?)
  `
  ).run(feed.id, feed.name, feed.type, feed.url, feed.format, feed.enabled ? 1 : 0);
}

/**
 * Enable/disable a threat feed
 */
export function setThreatFeedEnabled(feedId: string, enabled: boolean): void {
  const db = getDb();
  db.prepare("UPDATE threat_feeds SET enabled = ? WHERE id = ?").run(enabled ? 1 : 0, feedId);
}

/**
 * Update feed sync status
 */
export function updateFeedSyncStatus(feedId: string, entryCount: number): void {
  const db = getDb();
  db.prepare(
    `
    UPDATE threat_feeds
    SET last_sync = ?, entry_count = ?
    WHERE id = ?
  `
  ).run(new Date().toISOString(), entryCount, feedId);
}

// =============================================================================
// IOC Management
// =============================================================================

/**
 * Add or update an IOC
 */
export function saveIOC(ioc: IOC): void {
  const db = getDb();
  db.prepare(
    `
    INSERT OR REPLACE INTO iocs
    (id, type, value, confidence, severity, source, first_seen, last_seen,
     tags, related_cves, description)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
  ).run(
    ioc.id,
    ioc.type,
    ioc.value,
    ioc.confidence,
    ioc.severity,
    ioc.source,
    ioc.firstSeen,
    ioc.lastSeen,
    JSON.stringify(ioc.tags),
    JSON.stringify(ioc.relatedCves),
    ioc.description ?? null
  );
}

/**
 * Search IOCs
 */
export function searchIOCs(query: {
  type?: IOCType;
  value?: string;
  minConfidence?: number;
  severity?: SeverityLevel;
  source?: string;
  limit?: number;
}): IOC[] {
  const db = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (query.type) {
    conditions.push("type = ?");
    params.push(query.type);
  }
  if (query.value) {
    conditions.push("value LIKE ?");
    params.push(`%${query.value}%`);
  }
  if (query.minConfidence !== undefined) {
    conditions.push("confidence >= ?");
    params.push(query.minConfidence);
  }
  if (query.severity) {
    conditions.push("severity = ?");
    params.push(query.severity);
  }
  if (query.source) {
    conditions.push("source = ?");
    params.push(query.source);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const limit = query.limit || 100;

  const rows = db.prepare(`SELECT * FROM iocs ${where} LIMIT ?`).all(...params, limit) as Array<{
    id: string;
    type: string;
    value: string;
    confidence: number;
    severity: string;
    source: string;
    first_seen: string;
    last_seen: string;
    tags: string | null;
    related_cves: string | null;
    description: string | null;
  }>;

  return rows.map((row) => ({
    id: row.id,
    type: row.type as IOCType,
    value: row.value,
    confidence: row.confidence,
    severity: row.severity as SeverityLevel,
    source: row.source,
    firstSeen: row.first_seen,
    lastSeen: row.last_seen,
    tags: row.tags ? JSON.parse(row.tags) : [],
    relatedCves: row.related_cves ? JSON.parse(row.related_cves) : [],
    description: row.description ?? undefined,
  }));
}

/**
 * Check if a value matches any IOC
 */
export function checkIOC(type: IOCType, value: string): IOC | null {
  const db = getDb();
  const row = db.prepare("SELECT * FROM iocs WHERE type = ? AND value = ?").get(type, value) as
    | {
        id: string;
        type: string;
        value: string;
        confidence: number;
        severity: string;
        source: string;
        first_seen: string;
        last_seen: string;
        tags: string | null;
        related_cves: string | null;
        description: string | null;
      }
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    type: row.type as IOCType,
    value: row.value,
    confidence: row.confidence,
    severity: row.severity as SeverityLevel,
    source: row.source,
    firstSeen: row.first_seen,
    lastSeen: row.last_seen,
    tags: row.tags ? JSON.parse(row.tags) : [],
    relatedCves: row.related_cves ? JSON.parse(row.related_cves) : [],
    description: row.description ?? undefined,
  };
}

/**
 * Delete an IOC
 */
export function deleteIOC(id: string): boolean {
  const db = getDb();
  const result = db.prepare("DELETE FROM iocs WHERE id = ?").run(id);
  return result.changes > 0;
}

// =============================================================================
// Threat Actors
// =============================================================================

/**
 * Save threat actor
 */
export function saveThreatActor(actor: ThreatActor): void {
  const db = getDb();
  db.prepare(
    `
    INSERT OR REPLACE INTO threat_actors
    (id, name, aliases, description, motivation, sophistication,
     targeted_sectors, targeted_countries, tools, techniques,
     associated_cves, last_activity, refs)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
  ).run(
    actor.id,
    actor.name,
    JSON.stringify(actor.aliases),
    actor.description,
    JSON.stringify(actor.motivation),
    actor.sophistication,
    JSON.stringify(actor.targetedSectors),
    JSON.stringify(actor.targetedCountries),
    JSON.stringify(actor.tools),
    JSON.stringify(actor.techniques),
    JSON.stringify(actor.associatedCves),
    actor.lastActivity ?? null,
    JSON.stringify(actor.references)
  );
}

/**
 * Get threat actor by name or ID
 */
export function getThreatActor(nameOrId: string): ThreatActor | null {
  const db = getDb();
  const row = db
    .prepare("SELECT * FROM threat_actors WHERE id = ? OR name = ?")
    .get(nameOrId, nameOrId) as
    | {
        id: string;
        name: string;
        aliases: string;
        description: string;
        motivation: string;
        sophistication: string;
        targeted_sectors: string;
        targeted_countries: string;
        tools: string;
        techniques: string;
        associated_cves: string;
        last_activity: string | null;
        refs: string;
      }
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    name: row.name,
    aliases: JSON.parse(row.aliases),
    description: row.description,
    motivation: JSON.parse(row.motivation),
    sophistication: row.sophistication as ThreatActor["sophistication"],
    targetedSectors: JSON.parse(row.targeted_sectors),
    targetedCountries: JSON.parse(row.targeted_countries),
    tools: JSON.parse(row.tools),
    techniques: JSON.parse(row.techniques),
    associatedCves: JSON.parse(row.associated_cves),
    lastActivity: row.last_activity ?? undefined,
    references: JSON.parse(row.refs),
  };
}

/**
 * Search threat actors
 */
export function searchThreatActors(query: {
  name?: string;
  technique?: string;
  cve?: string;
  sector?: string;
  limit?: number;
}): ThreatActor[] {
  const db = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (query.name) {
    conditions.push("(name LIKE ? OR aliases LIKE ?)");
    params.push(`%${query.name}%`, `%${query.name}%`);
  }
  if (query.technique) {
    conditions.push("techniques LIKE ?");
    params.push(`%${query.technique}%`);
  }
  if (query.cve) {
    conditions.push("associated_cves LIKE ?");
    params.push(`%${query.cve}%`);
  }
  if (query.sector) {
    conditions.push("targeted_sectors LIKE ?");
    params.push(`%${query.sector}%`);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const limit = query.limit || 50;

  const rows = db
    .prepare(`SELECT * FROM threat_actors ${where} LIMIT ?`)
    .all(...params, limit) as Array<{
    id: string;
    name: string;
    aliases: string;
    description: string;
    motivation: string;
    sophistication: string;
    targeted_sectors: string;
    targeted_countries: string;
    tools: string;
    techniques: string;
    associated_cves: string;
    last_activity: string | null;
    refs: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    aliases: JSON.parse(row.aliases),
    description: row.description,
    motivation: JSON.parse(row.motivation),
    sophistication: row.sophistication as ThreatActor["sophistication"],
    targetedSectors: JSON.parse(row.targeted_sectors),
    targetedCountries: JSON.parse(row.targeted_countries),
    tools: JSON.parse(row.tools),
    techniques: JSON.parse(row.techniques),
    associatedCves: JSON.parse(row.associated_cves),
    lastActivity: row.last_activity ?? undefined,
    references: JSON.parse(row.refs),
  }));
}

// =============================================================================
// Threat Reports
// =============================================================================

/**
 * Save threat report
 */
export function saveThreatReport(report: ThreatReport): void {
  const db = getDb();
  db.prepare(
    `
    INSERT OR REPLACE INTO threat_reports
    (id, title, summary, severity, published_date, source, tags,
     ioc_ids, cves, actors, mitigations, url)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
  ).run(
    report.id,
    report.title,
    report.summary,
    report.severity,
    report.publishedDate,
    report.source,
    JSON.stringify(report.tags),
    JSON.stringify(report.iocs.map((i) => i.id)),
    JSON.stringify(report.cves),
    JSON.stringify(report.actors),
    JSON.stringify(report.mitigations),
    report.url ?? null
  );
}

/**
 * Search threat reports
 */
export function searchThreatReports(query: {
  keyword?: string;
  severity?: SeverityLevel;
  cve?: string;
  actor?: string;
  since?: string;
  limit?: number;
}): Omit<ThreatReport, "iocs">[] {
  const db = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (query.keyword) {
    conditions.push("(title LIKE ? OR summary LIKE ?)");
    params.push(`%${query.keyword}%`, `%${query.keyword}%`);
  }
  if (query.severity) {
    conditions.push("severity = ?");
    params.push(query.severity);
  }
  if (query.cve) {
    conditions.push("cves LIKE ?");
    params.push(`%${query.cve}%`);
  }
  if (query.actor) {
    conditions.push("actors LIKE ?");
    params.push(`%${query.actor}%`);
  }
  if (query.since) {
    conditions.push("published_date >= ?");
    params.push(query.since);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const limit = query.limit || 50;

  const rows = db
    .prepare(`SELECT * FROM threat_reports ${where} ORDER BY published_date DESC LIMIT ?`)
    .all(...params, limit) as Array<{
    id: string;
    title: string;
    summary: string;
    severity: string;
    published_date: string;
    source: string;
    tags: string;
    ioc_ids: string;
    cves: string;
    actors: string;
    mitigations: string;
    url: string | null;
  }>;

  return rows.map((row) => ({
    id: row.id,
    title: row.title,
    summary: row.summary,
    severity: row.severity as SeverityLevel,
    publishedDate: row.published_date,
    source: row.source,
    tags: JSON.parse(row.tags),
    cves: JSON.parse(row.cves),
    actors: JSON.parse(row.actors),
    mitigations: JSON.parse(row.mitigations),
    url: row.url ?? undefined,
  }));
}

// =============================================================================
// Statistics
// =============================================================================

export interface ThreatIntelStats {
  totalCves: number;
  kevCount: number;
  totalIOCs: number;
  iocsByType: Record<IOCType, number>;
  totalActors: number;
  totalReports: number;
  feedStats: {
    total: number;
    enabled: number;
    lastSync?: string;
  };
}

/**
 * Get threat intelligence statistics
 */
export function getThreatIntelStats(): ThreatIntelStats {
  const db = getDb();

  const cveCount = (
    db.prepare("SELECT COUNT(*) as count FROM cve_enrichment").get() as { count: number }
  ).count;

  const kevCount = (
    db.prepare("SELECT COUNT(*) as count FROM cve_enrichment WHERE is_kev = 1").get() as {
      count: number;
    }
  ).count;

  const iocCount = (db.prepare("SELECT COUNT(*) as count FROM iocs").get() as { count: number })
    .count;

  const iocsByType = db
    .prepare("SELECT type, COUNT(*) as count FROM iocs GROUP BY type")
    .all() as Array<{ type: string; count: number }>;

  const actorCount = (
    db.prepare("SELECT COUNT(*) as count FROM threat_actors").get() as { count: number }
  ).count;

  const reportCount = (
    db.prepare("SELECT COUNT(*) as count FROM threat_reports").get() as { count: number }
  ).count;

  const feedStats = db
    .prepare(
      `
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as enabled,
      MAX(last_sync) as last_sync
    FROM threat_feeds
  `
    )
    .get() as { total: number; enabled: number; last_sync: string | null };

  const iocTypeMap: Record<IOCType, number> = {
    ip: 0,
    domain: 0,
    url: 0,
    hash_md5: 0,
    hash_sha1: 0,
    hash_sha256: 0,
    email: 0,
    file_name: 0,
    registry_key: 0,
    mutex: 0,
    user_agent: 0,
  };

  for (const row of iocsByType) {
    if (row.type in iocTypeMap) {
      iocTypeMap[row.type as IOCType] = row.count;
    }
  }

  return {
    totalCves: cveCount,
    kevCount,
    totalIOCs: iocCount,
    iocsByType: iocTypeMap,
    totalActors: actorCount,
    totalReports: reportCount,
    feedStats: {
      total: feedStats.total,
      enabled: feedStats.enabled,
      lastSync: feedStats.last_sync ?? undefined,
    },
  };
}

// =============================================================================
// Exports
// =============================================================================

export const threatIntelExports = {
  // Database
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
};
