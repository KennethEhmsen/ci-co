/**
 * Audit Preparation Module
 * Prepares audit packages, attestations, and compliance timelines
 */

import Database from "better-sqlite3";
import { randomUUID, createHash } from "crypto";

// Local type definitions for this module
export type AuditTypeLocal = "internal" | "external" | "certification" | "assessment";
export type AuditStatusLocal = "draft" | "final" | "archived";

export interface AuditPackageLocal {
  id: string;
  name: string;
  type: AuditTypeLocal;
  framework?: string;
  scope: Record<string, unknown>;
  preparedBy?: string;
  preparedAt: string;
  validFrom?: string;
  validUntil?: string;
  status: AuditStatusLocal;
  contents: {
    evidenceIds: string[];
    controlIds: string[];
    findings: unknown[];
    remediations: unknown[];
  };
  summary?: Record<string, unknown>;
  hash: string;
}

export interface AttestationRecordLocal {
  id: string;
  auditPackageId?: string;
  type: string;
  statement: string;
  attester: string;
  attesterRole?: string;
  attestedAt: string;
  validUntil?: string;
  scope?: Record<string, unknown>;
  evidenceIds: string[];
  signatureHash: string;
}

export interface ComplianceTimelineEventLocal {
  id: string;
  target: string;
  framework?: string;
  eventType: string;
  description: string;
  actor?: string;
  timestamp: string;
  details?: Record<string, unknown>;
  severity?: string;
}

export interface PrepareAuditOptionsLocal {
  name: string;
  type: AuditTypeLocal;
  framework?: string;
  preparedBy?: string;
  evidenceIds?: string[];
  controlIds?: string[];
  findings?: unknown[];
  remediations?: unknown[];
  scope?: Record<string, unknown>;
  validFrom?: string;
  validUntil?: string;
  summary?: Record<string, unknown>;
}

export interface GenerateAttestationOptionsLocal {
  type: string;
  statement: string;
  attester: string;
  attesterRole?: string;
  auditPackageId?: string;
  evidenceIds?: string[];
  scope?: Record<string, unknown>;
  validUntil?: string;
}

export interface TimelineOptionsLocal {
  target?: string;
  framework?: string;
  eventTypes?: string[];
  startDate?: string;
  endDate?: string;
  limit?: number;
}

let db: Database.Database | null = null;

const AUDIT_SCHEMA = `
  CREATE TABLE IF NOT EXISTS audit_packages (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    framework TEXT,
    scope_json TEXT NOT NULL DEFAULT '{}',
    prepared_by TEXT,
    prepared_at TEXT DEFAULT CURRENT_TIMESTAMP,
    valid_from TEXT,
    valid_until TEXT,
    status TEXT NOT NULL DEFAULT 'draft',
    contents_json TEXT NOT NULL DEFAULT '{}',
    summary_json TEXT,
    hash TEXT
  );

  CREATE TABLE IF NOT EXISTS attestations (
    id TEXT PRIMARY KEY,
    audit_package_id TEXT,
    type TEXT NOT NULL,
    statement TEXT NOT NULL,
    attester TEXT NOT NULL,
    attester_role TEXT,
    attested_at TEXT DEFAULT CURRENT_TIMESTAMP,
    valid_until TEXT,
    scope_json TEXT,
    evidence_ids_json TEXT DEFAULT '[]',
    signature_hash TEXT,
    FOREIGN KEY (audit_package_id) REFERENCES audit_packages(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS compliance_timeline (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    framework TEXT,
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    actor TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    details_json TEXT,
    severity TEXT
  );

  CREATE TABLE IF NOT EXISTS audit_prep_log (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    package_id TEXT,
    attestation_id TEXT,
    actor TEXT,
    details_json TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_packages_type ON audit_packages(type);
  CREATE INDEX IF NOT EXISTS idx_packages_framework ON audit_packages(framework);
  CREATE INDEX IF NOT EXISTS idx_attestations_package ON attestations(audit_package_id);
  CREATE INDEX IF NOT EXISTS idx_timeline_target ON compliance_timeline(target);
  CREATE INDEX IF NOT EXISTS idx_timeline_framework ON compliance_timeline(framework);
`;

export interface AuditPrepDbInitResult {
  path: string;
  initialized: boolean;
}

export function initAuditPrepDatabase(dbPath?: string): AuditPrepDbInitResult {
  const path = dbPath || ":memory:";
  db = new Database(path);
  db.exec(AUDIT_SCHEMA);
  return { path, initialized: true };
}

export function closeAuditPrepDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

function getDb(): Database.Database {
  if (!db) {
    throw new Error("Audit database not initialized. Call initAuditDatabase first.");
  }
  return db;
}

function logAudit(
  eventType: string,
  packageId: string | undefined,
  attestationId: string | undefined,
  actor: string | undefined,
  details?: Record<string, unknown>
): void {
  const database = getDb();
  database
    .prepare(
      `
    INSERT INTO audit_prep_log (id, event_type, package_id, attestation_id, actor, details_json)
    VALUES (?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      randomUUID(),
      eventType,
      packageId,
      attestationId,
      actor,
      details ? JSON.stringify(details) : null
    );
}

function computeHash(content: unknown): string {
  const str = typeof content === "string" ? content : JSON.stringify(content);
  return createHash("sha256").update(str).digest("hex");
}

export function prepareAuditPackage(options: PrepareAuditOptionsLocal): AuditPackageLocal {
  const database = getDb();
  const id = randomUUID();
  const now = new Date().toISOString();

  const contents = {
    evidenceIds: options.evidenceIds || [],
    controlIds: options.controlIds || [],
    findings: options.findings || [],
    remediations: options.remediations || [],
  };

  const hash = computeHash(contents);

  database
    .prepare(
      `
    INSERT INTO audit_packages (id, name, type, framework, scope_json, prepared_by, prepared_at, valid_from, valid_until, status, contents_json, summary_json, hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      id,
      options.name,
      options.type,
      options.framework || null,
      JSON.stringify(options.scope || {}),
      options.preparedBy || null,
      now,
      options.validFrom || null,
      options.validUntil || null,
      "draft",
      JSON.stringify(contents),
      options.summary ? JSON.stringify(options.summary) : null,
      hash
    );

  logAudit("package_prepared", id, undefined, options.preparedBy, {
    name: options.name,
    type: options.type,
  });
  return getAuditPackage(id)!;
}

export function getAuditPackage(id: string): AuditPackageLocal | null {
  const database = getDb();
  const row = database.prepare("SELECT * FROM audit_packages WHERE id = ?").get(id) as
    | Record<string, unknown>
    | undefined;

  if (!row) return null;

  return {
    id: row.id as string,
    name: row.name as string,
    type: row.type as AuditTypeLocal,
    framework: row.framework as string | undefined,
    scope: JSON.parse(row.scope_json as string),
    preparedBy: row.prepared_by as string | undefined,
    preparedAt: row.prepared_at as string,
    validFrom: row.valid_from as string | undefined,
    validUntil: row.valid_until as string | undefined,
    status: row.status as "draft" | "final" | "archived",
    contents: JSON.parse(row.contents_json as string),
    summary: row.summary_json ? JSON.parse(row.summary_json as string) : undefined,
    hash: row.hash as string,
  };
}

export function listAuditPackages(options?: {
  type?: AuditTypeLocal;
  framework?: string;
  status?: string;
}): AuditPackageLocal[] {
  const database = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options?.type) {
    conditions.push("type = ?");
    params.push(options.type);
  }
  if (options?.framework) {
    conditions.push("framework = ?");
    params.push(options.framework);
  }
  if (options?.status) {
    conditions.push("status = ?");
    params.push(options.status);
  }

  let query = "SELECT * FROM audit_packages";
  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }
  query += " ORDER BY prepared_at DESC";

  const rows = database.prepare(query).all(...params) as Record<string, unknown>[];
  return rows.map((row) => ({
    id: row.id as string,
    name: row.name as string,
    type: row.type as AuditTypeLocal,
    framework: row.framework as string | undefined,
    scope: JSON.parse(row.scope_json as string),
    preparedBy: row.prepared_by as string | undefined,
    preparedAt: row.prepared_at as string,
    validFrom: row.valid_from as string | undefined,
    validUntil: row.valid_until as string | undefined,
    status: row.status as "draft" | "final" | "archived",
    contents: JSON.parse(row.contents_json as string),
    summary: row.summary_json ? JSON.parse(row.summary_json as string) : undefined,
    hash: row.hash as string,
  }));
}

export function finalizeAuditPackage(id: string, actor?: string): AuditPackageLocal | null {
  const database = getDb();
  const existing = getAuditPackage(id);
  if (!existing || existing.status !== "draft") return null;

  database.prepare("UPDATE audit_packages SET status = ? WHERE id = ?").run("final", id);

  logAudit("package_finalized", id, undefined, actor);
  return getAuditPackage(id);
}

export function archiveAuditPackage(id: string, actor?: string): AuditPackageLocal | null {
  const database = getDb();
  const existing = getAuditPackage(id);
  if (!existing) return null;

  database.prepare("UPDATE audit_packages SET status = ? WHERE id = ?").run("archived", id);

  logAudit("package_archived", id, undefined, actor);
  return getAuditPackage(id);
}

export function generateAttestation(
  options: GenerateAttestationOptionsLocal
): AttestationRecordLocal {
  const database = getDb();
  const id = randomUUID();
  const now = new Date().toISOString();

  const signatureContent = {
    statement: options.statement,
    attester: options.attester,
    attestedAt: now,
    evidenceIds: options.evidenceIds || [],
  };
  const signatureHash = computeHash(signatureContent);

  database
    .prepare(
      `
    INSERT INTO attestations (id, audit_package_id, type, statement, attester, attester_role, attested_at, valid_until, scope_json, evidence_ids_json, signature_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      id,
      options.auditPackageId || null,
      options.type,
      options.statement,
      options.attester,
      options.attesterRole || null,
      now,
      options.validUntil || null,
      options.scope ? JSON.stringify(options.scope) : null,
      JSON.stringify(options.evidenceIds || []),
      signatureHash
    );

  logAudit("attestation_generated", options.auditPackageId, id, options.attester, {
    type: options.type,
  });
  return getAttestation(id)!;
}

export function getAttestation(id: string): AttestationRecordLocal | null {
  const database = getDb();
  const row = database.prepare("SELECT * FROM attestations WHERE id = ?").get(id) as
    | Record<string, unknown>
    | undefined;

  if (!row) return null;

  return {
    id: row.id as string,
    auditPackageId: row.audit_package_id as string | undefined,
    type: row.type as string,
    statement: row.statement as string,
    attester: row.attester as string,
    attesterRole: row.attester_role as string | undefined,
    attestedAt: row.attested_at as string,
    validUntil: row.valid_until as string | undefined,
    scope: row.scope_json ? JSON.parse(row.scope_json as string) : undefined,
    evidenceIds: JSON.parse(row.evidence_ids_json as string),
    signatureHash: row.signature_hash as string,
  };
}

export function listAttestations(options?: {
  auditPackageId?: string;
  type?: string;
  attester?: string;
}): AttestationRecordLocal[] {
  const database = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options?.auditPackageId) {
    conditions.push("audit_package_id = ?");
    params.push(options.auditPackageId);
  }
  if (options?.type) {
    conditions.push("type = ?");
    params.push(options.type);
  }
  if (options?.attester) {
    conditions.push("attester = ?");
    params.push(options.attester);
  }

  let query = "SELECT * FROM attestations";
  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }
  query += " ORDER BY attested_at DESC";

  const rows = database.prepare(query).all(...params) as Record<string, unknown>[];
  return rows.map((row) => ({
    id: row.id as string,
    auditPackageId: row.audit_package_id as string | undefined,
    type: row.type as string,
    statement: row.statement as string,
    attester: row.attester as string,
    attesterRole: row.attester_role as string | undefined,
    attestedAt: row.attested_at as string,
    validUntil: row.valid_until as string | undefined,
    scope: row.scope_json ? JSON.parse(row.scope_json as string) : undefined,
    evidenceIds: JSON.parse(row.evidence_ids_json as string),
    signatureHash: row.signature_hash as string,
  }));
}

export function recordTimelineEvent(
  event: Omit<ComplianceTimelineEventLocal, "id" | "timestamp">
): ComplianceTimelineEventLocal {
  const database = getDb();
  const id = randomUUID();
  const now = new Date().toISOString();

  database
    .prepare(
      `
    INSERT INTO compliance_timeline (id, target, framework, event_type, description, actor, timestamp, details_json, severity)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      id,
      event.target,
      event.framework || null,
      event.eventType,
      event.description,
      event.actor || null,
      now,
      event.details ? JSON.stringify(event.details) : null,
      event.severity || null
    );

  return {
    id,
    target: event.target,
    framework: event.framework,
    eventType: event.eventType,
    description: event.description,
    actor: event.actor,
    timestamp: now,
    details: event.details,
    severity: event.severity,
  };
}

export function getComplianceTimeline(
  options: TimelineOptionsLocal
): ComplianceTimelineEventLocal[] {
  const database = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options.target) {
    conditions.push("target = ?");
    params.push(options.target);
  }
  if (options.framework) {
    conditions.push("framework = ?");
    params.push(options.framework);
  }
  if (options.eventTypes && options.eventTypes.length > 0) {
    conditions.push(`event_type IN (${options.eventTypes.map(() => "?").join(", ")})`);
    params.push(...options.eventTypes);
  }
  if (options.startDate) {
    conditions.push("timestamp >= ?");
    params.push(options.startDate);
  }
  if (options.endDate) {
    conditions.push("timestamp <= ?");
    params.push(options.endDate);
  }

  let query = "SELECT * FROM compliance_timeline";
  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }
  query += " ORDER BY timestamp DESC";

  if (options.limit) {
    query += " LIMIT ?";
    params.push(options.limit);
  }

  const rows = database.prepare(query).all(...params) as Record<string, unknown>[];
  return rows.map((row) => ({
    id: row.id as string,
    target: row.target as string,
    framework: row.framework as string | undefined,
    eventType: row.event_type as string,
    description: row.description as string,
    actor: row.actor as string | undefined,
    timestamp: row.timestamp as string,
    details: row.details_json ? JSON.parse(row.details_json as string) : undefined,
    severity: row.severity as string | undefined,
  }));
}

export interface AuditPrepAuditEntry {
  id: string;
  eventType: string;
  packageId?: string;
  attestationId?: string;
  actor?: string;
  details?: Record<string, unknown>;
  timestamp: string;
}

export function getAuditPrepLog(options?: {
  packageId?: string;
  limit?: number;
}): AuditPrepAuditEntry[] {
  const database = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options?.packageId) {
    conditions.push("package_id = ?");
    params.push(options.packageId);
  }

  let query = "SELECT * FROM audit_prep_log";
  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }
  query += " ORDER BY timestamp DESC";

  if (options?.limit) {
    query += " LIMIT ?";
    params.push(options.limit);
  }

  const rows = database.prepare(query).all(...params) as Record<string, unknown>[];
  return rows.map((row) => ({
    id: row.id as string,
    eventType: row.event_type as string,
    packageId: row.package_id as string | undefined,
    attestationId: row.attestation_id as string | undefined,
    actor: row.actor as string | undefined,
    details: row.details_json ? JSON.parse(row.details_json as string) : undefined,
    timestamp: row.timestamp as string,
  }));
}
