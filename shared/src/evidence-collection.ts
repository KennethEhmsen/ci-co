/**
 * Evidence Collection Module
 * Collects and manages compliance evidence for audits
 */

import Database from "better-sqlite3";
import { randomUUID, createHash } from "crypto";

// Local type definitions for this module
export type EvidenceTypeLocal =
  | "scan_result"
  | "configuration"
  | "policy"
  | "attestation"
  | "log"
  | "screenshot"
  | "document";

export interface EvidenceRecordLocal {
  id: string;
  type: EvidenceTypeLocal;
  title: string;
  description?: string;
  framework?: string;
  controlId?: string;
  source: string;
  collectedBy?: string;
  collectedAt: string;
  validFrom?: string;
  validUntil?: string;
  contentHash?: string;
  content?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  tags: string[];
}

export interface EvidenceAttachmentLocal {
  id: string;
  evidenceId: string;
  filename: string;
  mimeType?: string;
  sizeBytes?: number;
  contentHash?: string;
  storagePath?: string;
  uploadedBy?: string;
  uploadedAt: string;
}

export interface CollectEvidenceOptionsLocal {
  type: EvidenceTypeLocal;
  title: string;
  description?: string;
  framework?: string;
  controlId?: string;
  source: string;
  collectedBy?: string;
  content?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  validFrom?: string;
  validUntil?: string;
  tags?: string[];
}

export interface EvidencePackageLocal {
  exportedAt: string;
  totalRecords: number;
  totalAttachments: number;
  frameworks: string[];
  records: EvidenceRecordLocal[];
  attachments?: EvidenceAttachmentLocal[];
  byFramework: Record<string, Record<string, EvidenceRecordLocal[]>>;
}

let db: Database.Database | null = null;

const EVIDENCE_SCHEMA = `
  CREATE TABLE IF NOT EXISTS evidence_records (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    framework TEXT,
    control_id TEXT,
    source TEXT NOT NULL,
    collected_by TEXT,
    collected_at TEXT DEFAULT CURRENT_TIMESTAMP,
    valid_from TEXT,
    valid_until TEXT,
    content_hash TEXT,
    content_json TEXT,
    metadata_json TEXT,
    tags_json TEXT DEFAULT '[]'
  );

  CREATE TABLE IF NOT EXISTS evidence_attachments (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    mime_type TEXT,
    size_bytes INTEGER,
    content_hash TEXT,
    storage_path TEXT,
    uploaded_by TEXT,
    uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence_records(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS evidence_audit (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    evidence_id TEXT,
    actor TEXT,
    details_json TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence_records(type);
  CREATE INDEX IF NOT EXISTS idx_evidence_framework ON evidence_records(framework);
  CREATE INDEX IF NOT EXISTS idx_evidence_control ON evidence_records(control_id);
  CREATE INDEX IF NOT EXISTS idx_attachments_evidence ON evidence_attachments(evidence_id);
`;

export interface EvidenceDbInitResult {
  path: string;
  initialized: boolean;
}

export function initEvidenceDatabase(dbPath?: string): EvidenceDbInitResult {
  const path = dbPath || ":memory:";
  db = new Database(path);
  db.exec(EVIDENCE_SCHEMA);
  return { path, initialized: true };
}

export function closeEvidenceDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

function getDb(): Database.Database {
  if (!db) {
    throw new Error("Evidence database not initialized. Call initEvidenceDatabase first.");
  }
  return db;
}

function logAudit(
  eventType: string,
  evidenceId: string | undefined,
  actor: string | undefined,
  details?: Record<string, unknown>
): void {
  const database = getDb();
  database
    .prepare(
      `
    INSERT INTO evidence_audit (id, event_type, evidence_id, actor, details_json)
    VALUES (?, ?, ?, ?, ?)
  `
    )
    .run(randomUUID(), eventType, evidenceId, actor, details ? JSON.stringify(details) : null);
}

function computeHash(content: unknown): string {
  const str = typeof content === "string" ? content : JSON.stringify(content);
  return createHash("sha256").update(str).digest("hex");
}

export function collectEvidence(options: CollectEvidenceOptionsLocal): EvidenceRecordLocal {
  const database = getDb();
  const id = randomUUID();
  const now = new Date().toISOString();
  const contentHash = options.content ? computeHash(options.content) : undefined;

  database
    .prepare(
      `
    INSERT INTO evidence_records (id, type, title, description, framework, control_id, source, collected_by, collected_at, valid_from, valid_until, content_hash, content_json, metadata_json, tags_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      id,
      options.type,
      options.title,
      options.description || null,
      options.framework || null,
      options.controlId || null,
      options.source,
      options.collectedBy || null,
      now,
      options.validFrom || null,
      options.validUntil || null,
      contentHash || null,
      options.content ? JSON.stringify(options.content) : null,
      options.metadata ? JSON.stringify(options.metadata) : null,
      JSON.stringify(options.tags || [])
    );

  logAudit("evidence_collected", id, options.collectedBy, {
    type: options.type,
    title: options.title,
  });
  return getEvidence(id)!;
}

export function getEvidence(id: string): EvidenceRecordLocal | null {
  const database = getDb();
  const row = database.prepare("SELECT * FROM evidence_records WHERE id = ?").get(id) as
    | Record<string, unknown>
    | undefined;

  if (!row) return null;

  return {
    id: row.id as string,
    type: row.type as EvidenceTypeLocal,
    title: row.title as string,
    description: row.description as string | undefined,
    framework: row.framework as string | undefined,
    controlId: row.control_id as string | undefined,
    source: row.source as string,
    collectedBy: row.collected_by as string | undefined,
    collectedAt: row.collected_at as string,
    validFrom: row.valid_from as string | undefined,
    validUntil: row.valid_until as string | undefined,
    contentHash: row.content_hash as string | undefined,
    content: row.content_json ? JSON.parse(row.content_json as string) : undefined,
    metadata: row.metadata_json ? JSON.parse(row.metadata_json as string) : undefined,
    tags: JSON.parse(row.tags_json as string),
  };
}

export interface ListEvidenceOptions {
  type?: EvidenceTypeLocal;
  framework?: string;
  controlId?: string;
  source?: string;
  tags?: string[];
  limit?: number;
}

export function listEvidence(options?: ListEvidenceOptions): EvidenceRecordLocal[] {
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
  if (options?.controlId) {
    conditions.push("control_id = ?");
    params.push(options.controlId);
  }
  if (options?.source) {
    conditions.push("source = ?");
    params.push(options.source);
  }

  let query = "SELECT * FROM evidence_records";
  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }
  query += " ORDER BY collected_at DESC";

  if (options?.limit) {
    query += " LIMIT ?";
    params.push(options.limit);
  }

  const rows = database.prepare(query).all(...params) as Record<string, unknown>[];
  let results = rows.map((row) => ({
    id: row.id as string,
    type: row.type as EvidenceTypeLocal,
    title: row.title as string,
    description: row.description as string | undefined,
    framework: row.framework as string | undefined,
    controlId: row.control_id as string | undefined,
    source: row.source as string,
    collectedBy: row.collected_by as string | undefined,
    collectedAt: row.collected_at as string,
    validFrom: row.valid_from as string | undefined,
    validUntil: row.valid_until as string | undefined,
    contentHash: row.content_hash as string | undefined,
    content: row.content_json ? JSON.parse(row.content_json as string) : undefined,
    metadata: row.metadata_json ? JSON.parse(row.metadata_json as string) : undefined,
    tags: JSON.parse(row.tags_json as string),
  }));

  if (options?.tags && options.tags.length > 0) {
    results = results.filter((r) => options.tags!.some((tag) => r.tags.includes(tag)));
  }

  return results;
}

export function deleteEvidence(id: string, actor?: string): boolean {
  const database = getDb();
  const existing = getEvidence(id);
  if (!existing) return false;

  database.prepare("DELETE FROM evidence_records WHERE id = ?").run(id);
  logAudit("evidence_deleted", id, actor, { title: existing.title });
  return true;
}

export function attachToEvidence(
  evidenceId: string,
  attachment: Omit<EvidenceAttachmentLocal, "id" | "evidenceId" | "uploadedAt">
): EvidenceAttachmentLocal {
  const database = getDb();
  const id = randomUUID();
  const now = new Date().toISOString();

  database
    .prepare(
      `
    INSERT INTO evidence_attachments (id, evidence_id, filename, mime_type, size_bytes, content_hash, storage_path, uploaded_by, uploaded_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      id,
      evidenceId,
      attachment.filename,
      attachment.mimeType || null,
      attachment.sizeBytes || null,
      attachment.contentHash || null,
      attachment.storagePath || null,
      attachment.uploadedBy || null,
      now
    );

  logAudit("attachment_added", evidenceId, attachment.uploadedBy, {
    filename: attachment.filename,
  });

  return {
    id,
    evidenceId,
    filename: attachment.filename,
    mimeType: attachment.mimeType,
    sizeBytes: attachment.sizeBytes,
    contentHash: attachment.contentHash,
    storagePath: attachment.storagePath,
    uploadedBy: attachment.uploadedBy,
    uploadedAt: now,
  };
}

export function getEvidenceAttachments(evidenceId: string): EvidenceAttachmentLocal[] {
  const database = getDb();
  const rows = database
    .prepare("SELECT * FROM evidence_attachments WHERE evidence_id = ?")
    .all(evidenceId) as Record<string, unknown>[];

  return rows.map((row) => ({
    id: row.id as string,
    evidenceId: row.evidence_id as string,
    filename: row.filename as string,
    mimeType: row.mime_type as string | undefined,
    sizeBytes: row.size_bytes as number | undefined,
    contentHash: row.content_hash as string | undefined,
    storagePath: row.storage_path as string | undefined,
    uploadedBy: row.uploaded_by as string | undefined,
    uploadedAt: row.uploaded_at as string,
  }));
}

export function deleteAttachment(attachmentId: string, actor?: string): boolean {
  const database = getDb();
  const row = database
    .prepare("SELECT * FROM evidence_attachments WHERE id = ?")
    .get(attachmentId) as Record<string, unknown> | undefined;
  if (!row) return false;

  database.prepare("DELETE FROM evidence_attachments WHERE id = ?").run(attachmentId);
  logAudit("attachment_deleted", row.evidence_id as string, actor, { filename: row.filename });
  return true;
}

export interface ExportEvidenceOptions {
  framework?: string;
  controlIds?: string[];
  includeContent?: boolean;
  includeAttachments?: boolean;
}

export function exportEvidencePackage(options?: ExportEvidenceOptions): EvidencePackageLocal {
  const database = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options?.framework) {
    conditions.push("framework = ?");
    params.push(options.framework);
  }
  if (options?.controlIds && options.controlIds.length > 0) {
    conditions.push(`control_id IN (${options.controlIds.map(() => "?").join(", ")})`);
    params.push(...options.controlIds);
  }

  let query = "SELECT * FROM evidence_records";
  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }
  query += " ORDER BY framework, control_id, collected_at";

  const rows = database.prepare(query).all(...params) as Record<string, unknown>[];

  const records: EvidenceRecordLocal[] = rows.map((row) => {
    const record: EvidenceRecordLocal = {
      id: row.id as string,
      type: row.type as EvidenceTypeLocal,
      title: row.title as string,
      description: row.description as string | undefined,
      framework: row.framework as string | undefined,
      controlId: row.control_id as string | undefined,
      source: row.source as string,
      collectedBy: row.collected_by as string | undefined,
      collectedAt: row.collected_at as string,
      validFrom: row.valid_from as string | undefined,
      validUntil: row.valid_until as string | undefined,
      contentHash: row.content_hash as string | undefined,
      tags: JSON.parse(row.tags_json as string),
    };

    if (options?.includeContent && row.content_json) {
      record.content = JSON.parse(row.content_json as string);
    }
    if (row.metadata_json) {
      record.metadata = JSON.parse(row.metadata_json as string);
    }

    return record;
  });

  const attachments: EvidenceAttachmentLocal[] = [];
  if (options?.includeAttachments) {
    for (const record of records) {
      const recordAttachments = getEvidenceAttachments(record.id);
      attachments.push(...recordAttachments);
    }
  }

  const byFramework: Record<string, Record<string, EvidenceRecordLocal[]>> = {};
  for (const record of records) {
    const fw = record.framework || "unassigned";
    const ctrl = record.controlId || "unassigned";
    if (!byFramework[fw]) byFramework[fw] = {};
    if (!byFramework[fw][ctrl]) byFramework[fw][ctrl] = [];
    byFramework[fw][ctrl].push(record);
  }

  return {
    exportedAt: new Date().toISOString(),
    totalRecords: records.length,
    totalAttachments: attachments.length,
    frameworks: Object.keys(byFramework),
    records,
    attachments: options?.includeAttachments ? attachments : undefined,
    byFramework,
  };
}

export interface EvidenceAuditEntry {
  id: string;
  eventType: string;
  evidenceId?: string;
  actor?: string;
  details?: Record<string, unknown>;
  timestamp: string;
}

export function getEvidenceAuditLog(options?: {
  evidenceId?: string;
  limit?: number;
}): EvidenceAuditEntry[] {
  const database = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options?.evidenceId) {
    conditions.push("evidence_id = ?");
    params.push(options.evidenceId);
  }

  let query = "SELECT * FROM evidence_audit";
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
    evidenceId: row.evidence_id as string | undefined,
    actor: row.actor as string | undefined,
    details: row.details_json ? JSON.parse(row.details_json as string) : undefined,
    timestamp: row.timestamp as string,
  }));
}
