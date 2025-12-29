/**
 * Governance Workflow Module
 * Manages security policies and exception workflows
 */

import Database from "better-sqlite3";
import { randomUUID } from "crypto";

// Local type definitions for this module
export type GovernancePolicyStatusLocal = "draft" | "active" | "deprecated";
export type ExceptionStatusLocal = "pending" | "approved" | "rejected" | "expired";
export type EnforcementLevel = "advisory" | "blocking";

export interface GovernancePolicyLocal {
  id: string;
  name: string;
  description?: string;
  version: string;
  status: GovernancePolicyStatusLocal;
  rules: GovernancePolicyRuleLocal[];
  enforcementLevel: EnforcementLevel;
  owner?: string;
  createdAt: string;
  updatedAt: string;
  activatedAt?: string;
  deprecatedAt?: string;
}

export interface GovernancePolicyRuleLocal {
  type: string;
  condition: string;
  action: string;
}

export interface PolicyExceptionLocal {
  id: string;
  policyId: string;
  requester: string;
  reason: string;
  scope: Record<string, unknown>;
  status: ExceptionStatusLocal;
  expiresAt?: string;
  approvedBy?: string;
  approvedAt?: string;
  rejectedBy?: string;
  rejectedAt?: string;
  rejectionReason?: string;
  createdAt: string;
}

export interface CreatePolicyOptionsLocal {
  name: string;
  description?: string;
  version?: string;
  enforcementLevel?: EnforcementLevel;
  owner?: string;
  rules?: GovernancePolicyRuleLocal[];
}

export interface RequestExceptionOptionsLocal {
  policyId: string;
  requester: string;
  reason: string;
  scope?: Record<string, unknown>;
  expiresAt?: string;
}

export interface GovernanceDbInitResult {
  path: string;
  initialized: boolean;
}

let db: Database.Database | null = null;

const GOVERNANCE_SCHEMA = `
  CREATE TABLE IF NOT EXISTS governance_policies (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    version TEXT NOT NULL DEFAULT '1.0',
    status TEXT NOT NULL DEFAULT 'draft',
    rules_json TEXT NOT NULL DEFAULT '[]',
    enforcement_level TEXT NOT NULL DEFAULT 'advisory',
    owner TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    activated_at TEXT,
    deprecated_at TEXT
  );

  CREATE TABLE IF NOT EXISTS policy_exceptions (
    id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    requester TEXT NOT NULL,
    reason TEXT NOT NULL,
    scope_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    expires_at TEXT,
    approved_by TEXT,
    approved_at TEXT,
    rejected_by TEXT,
    rejected_at TEXT,
    rejection_reason TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (policy_id) REFERENCES governance_policies(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS governance_audit (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    actor TEXT,
    policy_id TEXT,
    exception_id TEXT,
    details_json TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_policies_status ON governance_policies(status);
  CREATE INDEX IF NOT EXISTS idx_exceptions_policy ON policy_exceptions(policy_id);
  CREATE INDEX IF NOT EXISTS idx_exceptions_status ON policy_exceptions(status);
  CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON governance_audit(timestamp);
`;

export function initGovernanceDatabase(dbPath?: string): GovernanceDbInitResult {
  const path = dbPath || ":memory:";
  db = new Database(path);
  db.exec(GOVERNANCE_SCHEMA);
  return { path, initialized: true };
}

export function closeGovernanceDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

function getDb(): Database.Database {
  if (!db) {
    throw new Error("Governance database not initialized. Call initGovernanceDatabase first.");
  }
  return db;
}

function logAudit(
  eventType: string,
  actor: string | undefined,
  policyId?: string,
  exceptionId?: string,
  details?: Record<string, unknown>
): void {
  const database = getDb();
  database
    .prepare(
      `
    INSERT INTO governance_audit (id, event_type, actor, policy_id, exception_id, details_json)
    VALUES (?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      randomUUID(),
      eventType,
      actor,
      policyId,
      exceptionId,
      details ? JSON.stringify(details) : null
    );
}

export function createGovernancePolicy(options: CreatePolicyOptionsLocal): GovernancePolicyLocal {
  const database = getDb();
  const id = randomUUID();
  const now = new Date().toISOString();

  database
    .prepare(
      `
    INSERT INTO governance_policies (id, name, description, version, status, rules_json, enforcement_level, owner, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      id,
      options.name,
      options.description || null,
      options.version || "1.0",
      "draft",
      JSON.stringify(options.rules || []),
      options.enforcementLevel || "advisory",
      options.owner || null,
      now,
      now
    );

  logAudit("policy_created", options.owner, id, undefined, { name: options.name });

  return getGovernancePolicy(id)!;
}

export function getGovernancePolicy(id: string): GovernancePolicyLocal | null {
  const database = getDb();
  const row = database.prepare("SELECT * FROM governance_policies WHERE id = ?").get(id) as
    | Record<string, unknown>
    | undefined;

  if (!row) return null;

  return {
    id: row.id as string,
    name: row.name as string,
    description: row.description as string | undefined,
    version: row.version as string,
    status: row.status as GovernancePolicyStatusLocal,
    rules: JSON.parse(row.rules_json as string),
    enforcementLevel: row.enforcement_level as "advisory" | "blocking",
    owner: row.owner as string | undefined,
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
    activatedAt: row.activated_at as string | undefined,
    deprecatedAt: row.deprecated_at as string | undefined,
  };
}

export function listGovernancePolicies(
  status?: GovernancePolicyStatusLocal
): GovernancePolicyLocal[] {
  const database = getDb();
  let query = "SELECT * FROM governance_policies";
  const params: unknown[] = [];

  if (status) {
    query += " WHERE status = ?";
    params.push(status);
  }

  query += " ORDER BY created_at DESC";

  const rows = database.prepare(query).all(...params) as Record<string, unknown>[];
  return rows.map((row) => ({
    id: row.id as string,
    name: row.name as string,
    description: row.description as string | undefined,
    version: row.version as string,
    status: row.status as GovernancePolicyStatusLocal,
    rules: JSON.parse(row.rules_json as string),
    enforcementLevel: row.enforcement_level as "advisory" | "blocking",
    owner: row.owner as string | undefined,
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
    activatedAt: row.activated_at as string | undefined,
    deprecatedAt: row.deprecated_at as string | undefined,
  }));
}

export function updateGovernancePolicy(
  id: string,
  updates: Partial<CreatePolicyOptionsLocal>,
  actor?: string
): GovernancePolicyLocal | null {
  const database = getDb();
  const existing = getGovernancePolicy(id);
  if (!existing) return null;

  const now = new Date().toISOString();
  const setClauses: string[] = ["updated_at = ?"];
  const params: unknown[] = [now];

  if (updates.name !== undefined) {
    setClauses.push("name = ?");
    params.push(updates.name);
  }
  if (updates.description !== undefined) {
    setClauses.push("description = ?");
    params.push(updates.description);
  }
  if (updates.version !== undefined) {
    setClauses.push("version = ?");
    params.push(updates.version);
  }
  if (updates.rules !== undefined) {
    setClauses.push("rules_json = ?");
    params.push(JSON.stringify(updates.rules));
  }
  if (updates.enforcementLevel !== undefined) {
    setClauses.push("enforcement_level = ?");
    params.push(updates.enforcementLevel);
  }
  if (updates.owner !== undefined) {
    setClauses.push("owner = ?");
    params.push(updates.owner);
  }

  params.push(id);
  database
    .prepare(`UPDATE governance_policies SET ${setClauses.join(", ")} WHERE id = ?`)
    .run(...params);

  logAudit("policy_updated", actor, id, undefined, updates);
  return getGovernancePolicy(id);
}

export function activateGovernancePolicy(id: string, actor?: string): GovernancePolicyLocal | null {
  const database = getDb();
  const existing = getGovernancePolicy(id);
  if (!existing || existing.status !== "draft") return null;

  const now = new Date().toISOString();
  database
    .prepare(
      `
    UPDATE governance_policies SET status = 'active', activated_at = ?, updated_at = ? WHERE id = ?
  `
    )
    .run(now, now, id);

  logAudit("policy_activated", actor, id);
  return getGovernancePolicy(id);
}

export function deprecateGovernancePolicy(
  id: string,
  actor?: string
): GovernancePolicyLocal | null {
  const database = getDb();
  const existing = getGovernancePolicy(id);
  if (!existing || existing.status !== "active") return null;

  const now = new Date().toISOString();
  database
    .prepare(
      `
    UPDATE governance_policies SET status = 'deprecated', deprecated_at = ?, updated_at = ? WHERE id = ?
  `
    )
    .run(now, now, id);

  logAudit("policy_deprecated", actor, id);
  return getGovernancePolicy(id);
}

export function deleteGovernancePolicy(id: string, actor?: string): boolean {
  const database = getDb();
  const existing = getGovernancePolicy(id);
  if (!existing) return false;

  database.prepare("DELETE FROM governance_policies WHERE id = ?").run(id);
  logAudit("policy_deleted", actor, id, undefined, { name: existing.name });
  return true;
}

export function requestPolicyException(
  options: RequestExceptionOptionsLocal
): PolicyExceptionLocal {
  const database = getDb();
  const id = randomUUID();

  database
    .prepare(
      `
    INSERT INTO policy_exceptions (id, policy_id, requester, reason, scope_json, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      id,
      options.policyId,
      options.requester,
      options.reason,
      JSON.stringify(options.scope || {}),
      options.expiresAt || null
    );

  logAudit("exception_requested", options.requester, options.policyId, id, {
    reason: options.reason,
  });
  return getPolicyException(id)!;
}

export function getPolicyException(id: string): PolicyExceptionLocal | null {
  const database = getDb();
  const row = database.prepare("SELECT * FROM policy_exceptions WHERE id = ?").get(id) as
    | Record<string, unknown>
    | undefined;

  if (!row) return null;

  return {
    id: row.id as string,
    policyId: row.policy_id as string,
    requester: row.requester as string,
    reason: row.reason as string,
    scope: JSON.parse(row.scope_json as string),
    status: row.status as ExceptionStatusLocal,
    expiresAt: row.expires_at as string | undefined,
    approvedBy: row.approved_by as string | undefined,
    approvedAt: row.approved_at as string | undefined,
    rejectedBy: row.rejected_by as string | undefined,
    rejectedAt: row.rejected_at as string | undefined,
    rejectionReason: row.rejection_reason as string | undefined,
    createdAt: row.created_at as string,
  };
}

export function listPolicyExceptions(
  policyId?: string,
  status?: ExceptionStatusLocal
): PolicyExceptionLocal[] {
  const database = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (policyId) {
    conditions.push("policy_id = ?");
    params.push(policyId);
  }
  if (status) {
    conditions.push("status = ?");
    params.push(status);
  }

  let query = "SELECT * FROM policy_exceptions";
  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }
  query += " ORDER BY created_at DESC";

  const rows = database.prepare(query).all(...params) as Record<string, unknown>[];
  return rows.map((row) => ({
    id: row.id as string,
    policyId: row.policy_id as string,
    requester: row.requester as string,
    reason: row.reason as string,
    scope: JSON.parse(row.scope_json as string),
    status: row.status as ExceptionStatusLocal,
    expiresAt: row.expires_at as string | undefined,
    approvedBy: row.approved_by as string | undefined,
    approvedAt: row.approved_at as string | undefined,
    rejectedBy: row.rejected_by as string | undefined,
    rejectedAt: row.rejected_at as string | undefined,
    rejectionReason: row.rejection_reason as string | undefined,
    createdAt: row.created_at as string,
  }));
}

export function approvePolicyException(id: string, approver: string): PolicyExceptionLocal | null {
  const database = getDb();
  const existing = getPolicyException(id);
  if (!existing || existing.status !== "pending") return null;

  const now = new Date().toISOString();
  database
    .prepare(
      `
    UPDATE policy_exceptions SET status = 'approved', approved_by = ?, approved_at = ? WHERE id = ?
  `
    )
    .run(approver, now, id);

  logAudit("exception_approved", approver, existing.policyId, id);
  return getPolicyException(id);
}

export function rejectPolicyException(
  id: string,
  rejector: string,
  reason?: string
): PolicyExceptionLocal | null {
  const database = getDb();
  const existing = getPolicyException(id);
  if (!existing || existing.status !== "pending") return null;

  const now = new Date().toISOString();
  database
    .prepare(
      `
    UPDATE policy_exceptions SET status = 'rejected', rejected_by = ?, rejected_at = ?, rejection_reason = ? WHERE id = ?
  `
    )
    .run(rejector, now, reason || null, id);

  logAudit("exception_rejected", rejector, existing.policyId, id, { reason });
  return getPolicyException(id);
}

export interface GovernanceAuditEntry {
  id: string;
  eventType: string;
  actor?: string;
  policyId?: string;
  exceptionId?: string;
  details?: Record<string, unknown>;
  timestamp: string;
}

export function getGovernanceAuditLog(options?: {
  policyId?: string;
  limit?: number;
}): GovernanceAuditEntry[] {
  const database = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options?.policyId) {
    conditions.push("policy_id = ?");
    params.push(options.policyId);
  }

  let query = "SELECT * FROM governance_audit";
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
    actor: row.actor as string | undefined,
    policyId: row.policy_id as string | undefined,
    exceptionId: row.exception_id as string | undefined,
    details: row.details_json ? JSON.parse(row.details_json as string) : undefined,
    timestamp: row.timestamp as string,
  }));
}
