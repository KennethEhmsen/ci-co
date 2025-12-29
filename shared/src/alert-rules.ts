/**
 * Alert Rules Module
 * Manages threshold-based alert rules with conditions
 */

import Database from "better-sqlite3";
import { randomUUID } from "crypto";

// Local type definitions
export type AlertRuleSeverity = "critical" | "high" | "medium" | "low" | "info";
export type AlertRuleStatus = "active" | "inactive" | "muted";
export type AlertConditionOperator =
  | "gt"
  | "gte"
  | "lt"
  | "lte"
  | "eq"
  | "neq"
  | "contains"
  | "not_contains";
export type AlertMetricType =
  | "vulnerability_count"
  | "critical_count"
  | "high_count"
  | "new_vulnerabilities"
  | "sla_breach"
  | "scan_failure"
  | "custom";

export interface AlertCondition {
  metric: AlertMetricType;
  operator: AlertConditionOperator;
  threshold: number | string;
  timeWindowMinutes?: number;
}

export interface AlertRule {
  id: string;
  name: string;
  description?: string;
  severity: AlertRuleSeverity;
  status: AlertRuleStatus;
  conditions: AlertCondition[];
  conditionLogic: "and" | "or";
  channelIds: string[];
  escalationPolicyId?: string;
  cooldownMinutes: number;
  labels?: Record<string, string>;
  createdBy?: string;
  createdAt: string;
  updatedAt: string;
  lastTriggeredAt?: string;
  triggerCount: number;
}

export interface CreateAlertRuleOptions {
  name: string;
  description?: string;
  severity: AlertRuleSeverity;
  conditions: AlertCondition[];
  conditionLogic?: "and" | "or";
  channelIds: string[];
  escalationPolicyId?: string;
  cooldownMinutes?: number;
  labels?: Record<string, string>;
  createdBy?: string;
}

export interface UpdateAlertRuleOptions {
  name?: string;
  description?: string;
  severity?: AlertRuleSeverity;
  status?: AlertRuleStatus;
  conditions?: AlertCondition[];
  conditionLogic?: "and" | "or";
  channelIds?: string[];
  escalationPolicyId?: string;
  cooldownMinutes?: number;
  labels?: Record<string, string>;
}

export interface AlertEvent {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: AlertRuleSeverity;
  title: string;
  message: string;
  triggeredAt: string;
  resolvedAt?: string;
  acknowledgedAt?: string;
  acknowledgedBy?: string;
  metadata?: Record<string, unknown>;
  notificationsSent: number;
}

export interface EvaluateRuleContext {
  vulnerabilityCount?: number;
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
  newVulnerabilities?: number;
  slaBreaches?: number;
  scanFailures?: number;
  customMetrics?: Record<string, number | string>;
}

export interface EvaluateRuleResult {
  ruleId: string;
  ruleName: string;
  triggered: boolean;
  matchedConditions: AlertCondition[];
  severity: AlertRuleSeverity;
  message?: string;
}

let db: Database.Database | null = null;

const ALERT_RULES_SCHEMA = `
  CREATE TABLE IF NOT EXISTS alert_rules (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    conditions_json TEXT NOT NULL,
    condition_logic TEXT NOT NULL DEFAULT 'and',
    channel_ids_json TEXT NOT NULL DEFAULT '[]',
    escalation_policy_id TEXT,
    cooldown_minutes INTEGER NOT NULL DEFAULT 15,
    labels_json TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_triggered_at TEXT,
    trigger_count INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS alert_events (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    triggered_at TEXT DEFAULT CURRENT_TIMESTAMP,
    resolved_at TEXT,
    acknowledged_at TEXT,
    acknowledged_by TEXT,
    metadata_json TEXT,
    notifications_sent INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS alert_rules_audit (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    rule_id TEXT,
    actor TEXT,
    details_json TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_rules_status ON alert_rules(status);
  CREATE INDEX IF NOT EXISTS idx_rules_severity ON alert_rules(severity);
  CREATE INDEX IF NOT EXISTS idx_events_rule ON alert_events(rule_id);
  CREATE INDEX IF NOT EXISTS idx_events_triggered ON alert_events(triggered_at);
`;

export interface AlertRulesDbInitResult {
  path: string;
  initialized: boolean;
}

function runSchema(database: Database.Database): void {
  database.exec(ALERT_RULES_SCHEMA);
}

export function initAlertRulesDatabase(dbPath?: string): AlertRulesDbInitResult {
  const path = dbPath || ":memory:";
  db = new Database(path);
  runSchema(db);
  return { path, initialized: true };
}

export function closeAlertRulesDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

function getDb(): Database.Database {
  if (!db) {
    throw new Error("Alert rules database not initialized. Call initAlertRulesDatabase first.");
  }
  return db;
}

function logAudit(
  eventType: string,
  ruleId: string | undefined,
  actor: string | undefined,
  details?: Record<string, unknown>
): void {
  const database = getDb();
  database
    .prepare(
      `
    INSERT INTO alert_rules_audit (id, event_type, rule_id, actor, details_json)
    VALUES (?, ?, ?, ?, ?)
  `
    )
    .run(randomUUID(), eventType, ruleId, actor, details ? JSON.stringify(details) : null);
}

export function createAlertRule(options: CreateAlertRuleOptions): AlertRule {
  const database = getDb();
  const id = randomUUID();
  const now = new Date().toISOString();

  database
    .prepare(
      `
    INSERT INTO alert_rules (id, name, description, severity, status, conditions_json, condition_logic, channel_ids_json, escalation_policy_id, cooldown_minutes, labels_json, created_by, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      id,
      options.name,
      options.description || null,
      options.severity,
      "active",
      JSON.stringify(options.conditions),
      options.conditionLogic || "and",
      JSON.stringify(options.channelIds),
      options.escalationPolicyId || null,
      options.cooldownMinutes || 15,
      options.labels ? JSON.stringify(options.labels) : null,
      options.createdBy || null,
      now,
      now
    );

  logAudit("rule_created", id, options.createdBy, {
    name: options.name,
    severity: options.severity,
  });
  return getAlertRule(id)!;
}

export function getAlertRule(id: string): AlertRule | null {
  const database = getDb();
  const row = database.prepare("SELECT * FROM alert_rules WHERE id = ?").get(id) as
    | Record<string, unknown>
    | undefined;

  if (!row) return null;

  return {
    id: row.id as string,
    name: row.name as string,
    description: row.description as string | undefined,
    severity: row.severity as AlertRuleSeverity,
    status: row.status as AlertRuleStatus,
    conditions: JSON.parse(row.conditions_json as string),
    conditionLogic: row.condition_logic as "and" | "or",
    channelIds: JSON.parse(row.channel_ids_json as string),
    escalationPolicyId: row.escalation_policy_id as string | undefined,
    cooldownMinutes: row.cooldown_minutes as number,
    labels: row.labels_json ? JSON.parse(row.labels_json as string) : undefined,
    createdBy: row.created_by as string | undefined,
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
    lastTriggeredAt: row.last_triggered_at as string | undefined,
    triggerCount: row.trigger_count as number,
  };
}

export function getAlertRuleByName(name: string): AlertRule | null {
  const database = getDb();
  const row = database.prepare("SELECT * FROM alert_rules WHERE name = ?").get(name) as
    | Record<string, unknown>
    | undefined;

  if (!row) return null;

  return {
    id: row.id as string,
    name: row.name as string,
    description: row.description as string | undefined,
    severity: row.severity as AlertRuleSeverity,
    status: row.status as AlertRuleStatus,
    conditions: JSON.parse(row.conditions_json as string),
    conditionLogic: row.condition_logic as "and" | "or",
    channelIds: JSON.parse(row.channel_ids_json as string),
    escalationPolicyId: row.escalation_policy_id as string | undefined,
    cooldownMinutes: row.cooldown_minutes as number,
    labels: row.labels_json ? JSON.parse(row.labels_json as string) : undefined,
    createdBy: row.created_by as string | undefined,
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
    lastTriggeredAt: row.last_triggered_at as string | undefined,
    triggerCount: row.trigger_count as number,
  };
}

export function listAlertRules(options?: {
  status?: AlertRuleStatus;
  severity?: AlertRuleSeverity;
}): AlertRule[] {
  const database = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options?.status) {
    conditions.push("status = ?");
    params.push(options.status);
  }
  if (options?.severity) {
    conditions.push("severity = ?");
    params.push(options.severity);
  }

  let query = "SELECT * FROM alert_rules";
  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }
  query += " ORDER BY severity ASC, name ASC";

  const rows = database.prepare(query).all(...params) as Record<string, unknown>[];
  return rows.map((row) => ({
    id: row.id as string,
    name: row.name as string,
    description: row.description as string | undefined,
    severity: row.severity as AlertRuleSeverity,
    status: row.status as AlertRuleStatus,
    conditions: JSON.parse(row.conditions_json as string),
    conditionLogic: row.condition_logic as "and" | "or",
    channelIds: JSON.parse(row.channel_ids_json as string),
    escalationPolicyId: row.escalation_policy_id as string | undefined,
    cooldownMinutes: row.cooldown_minutes as number,
    labels: row.labels_json ? JSON.parse(row.labels_json as string) : undefined,
    createdBy: row.created_by as string | undefined,
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
    lastTriggeredAt: row.last_triggered_at as string | undefined,
    triggerCount: row.trigger_count as number,
  }));
}

export function updateAlertRule(
  id: string,
  updates: UpdateAlertRuleOptions,
  actor?: string
): AlertRule | null {
  const database = getDb();
  const existing = getAlertRule(id);
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
  if (updates.severity !== undefined) {
    setClauses.push("severity = ?");
    params.push(updates.severity);
  }
  if (updates.status !== undefined) {
    setClauses.push("status = ?");
    params.push(updates.status);
  }
  if (updates.conditions !== undefined) {
    setClauses.push("conditions_json = ?");
    params.push(JSON.stringify(updates.conditions));
  }
  if (updates.conditionLogic !== undefined) {
    setClauses.push("condition_logic = ?");
    params.push(updates.conditionLogic);
  }
  if (updates.channelIds !== undefined) {
    setClauses.push("channel_ids_json = ?");
    params.push(JSON.stringify(updates.channelIds));
  }
  if (updates.escalationPolicyId !== undefined) {
    setClauses.push("escalation_policy_id = ?");
    params.push(updates.escalationPolicyId);
  }
  if (updates.cooldownMinutes !== undefined) {
    setClauses.push("cooldown_minutes = ?");
    params.push(updates.cooldownMinutes);
  }
  if (updates.labels !== undefined) {
    setClauses.push("labels_json = ?");
    params.push(JSON.stringify(updates.labels));
  }

  params.push(id);
  database.prepare(`UPDATE alert_rules SET ${setClauses.join(", ")} WHERE id = ?`).run(...params);

  logAudit("rule_updated", id, actor, { ...updates });
  return getAlertRule(id);
}

export function deleteAlertRule(id: string, actor?: string): boolean {
  const database = getDb();
  const existing = getAlertRule(id);
  if (!existing) return false;

  database.prepare("DELETE FROM alert_rules WHERE id = ?").run(id);
  logAudit("rule_deleted", id, actor, { name: existing.name });
  return true;
}

function evaluateCondition(condition: AlertCondition, context: EvaluateRuleContext): boolean {
  let value: number | string | undefined;

  switch (condition.metric) {
    case "vulnerability_count":
      value = context.vulnerabilityCount;
      break;
    case "critical_count":
      value = context.criticalCount;
      break;
    case "high_count":
      value = context.highCount;
      break;
    case "new_vulnerabilities":
      value = context.newVulnerabilities;
      break;
    case "sla_breach":
      value = context.slaBreaches;
      break;
    case "scan_failure":
      value = context.scanFailures;
      break;
    case "custom":
      value = context.customMetrics?.[condition.metric];
      break;
    default:
      return false;
  }

  if (value === undefined) return false;

  const threshold = condition.threshold;

  switch (condition.operator) {
    case "gt":
      return typeof value === "number" && typeof threshold === "number" && value > threshold;
    case "gte":
      return typeof value === "number" && typeof threshold === "number" && value >= threshold;
    case "lt":
      return typeof value === "number" && typeof threshold === "number" && value < threshold;
    case "lte":
      return typeof value === "number" && typeof threshold === "number" && value <= threshold;
    case "eq":
      return value === threshold;
    case "neq":
      return value !== threshold;
    case "contains":
      return (
        typeof value === "string" && typeof threshold === "string" && value.includes(threshold)
      );
    case "not_contains":
      return (
        typeof value === "string" && typeof threshold === "string" && !value.includes(threshold)
      );
    default:
      return false;
  }
}

export function evaluateAlertRule(
  ruleId: string,
  context: EvaluateRuleContext
): EvaluateRuleResult {
  const rule = getAlertRule(ruleId);
  if (!rule) {
    return {
      ruleId,
      ruleName: "unknown",
      triggered: false,
      matchedConditions: [],
      severity: "info",
      message: "Rule not found",
    };
  }

  if (rule.status !== "active") {
    return {
      ruleId,
      ruleName: rule.name,
      triggered: false,
      matchedConditions: [],
      severity: rule.severity,
      message: "Rule is not active",
    };
  }

  const matchedConditions: AlertCondition[] = [];
  for (const condition of rule.conditions) {
    if (evaluateCondition(condition, context)) {
      matchedConditions.push(condition);
    }
  }

  let triggered: boolean;
  if (rule.conditionLogic === "and") {
    triggered = matchedConditions.length === rule.conditions.length;
  } else {
    triggered = matchedConditions.length > 0;
  }

  return {
    ruleId: rule.id,
    ruleName: rule.name,
    triggered,
    matchedConditions,
    severity: rule.severity,
    message: triggered
      ? `Alert triggered: ${matchedConditions.length} condition(s) matched`
      : "No alert triggered",
  };
}

export function evaluateAllRules(context: EvaluateRuleContext): EvaluateRuleResult[] {
  const rules = listAlertRules({ status: "active" });
  return rules.map((rule) => evaluateAlertRule(rule.id, context));
}

export function triggerAlert(
  ruleId: string,
  title: string,
  message: string,
  metadata?: Record<string, unknown>
): AlertEvent {
  const database = getDb();
  const rule = getAlertRule(ruleId);
  if (!rule) {
    throw new Error("Rule not found");
  }

  const id = randomUUID();
  const now = new Date().toISOString();

  database
    .prepare(
      `
    INSERT INTO alert_events (id, rule_id, rule_name, severity, title, message, triggered_at, metadata_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      id,
      ruleId,
      rule.name,
      rule.severity,
      title,
      message,
      now,
      metadata ? JSON.stringify(metadata) : null
    );

  database
    .prepare(
      `
    UPDATE alert_rules SET last_triggered_at = ?, trigger_count = trigger_count + 1 WHERE id = ?
  `
    )
    .run(now, ruleId);

  logAudit("alert_triggered", ruleId, undefined, { title, severity: rule.severity });

  return getAlertEvent(id)!;
}

export function getAlertEvent(id: string): AlertEvent | null {
  const database = getDb();
  const row = database.prepare("SELECT * FROM alert_events WHERE id = ?").get(id) as
    | Record<string, unknown>
    | undefined;

  if (!row) return null;

  return {
    id: row.id as string,
    ruleId: row.rule_id as string,
    ruleName: row.rule_name as string,
    severity: row.severity as AlertRuleSeverity,
    title: row.title as string,
    message: row.message as string,
    triggeredAt: row.triggered_at as string,
    resolvedAt: row.resolved_at as string | undefined,
    acknowledgedAt: row.acknowledged_at as string | undefined,
    acknowledgedBy: row.acknowledged_by as string | undefined,
    metadata: row.metadata_json ? JSON.parse(row.metadata_json as string) : undefined,
    notificationsSent: row.notifications_sent as number,
  };
}

export function listAlertEvents(options?: {
  ruleId?: string;
  resolved?: boolean;
  limit?: number;
}): AlertEvent[] {
  const database = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options?.ruleId) {
    conditions.push("rule_id = ?");
    params.push(options.ruleId);
  }
  if (options?.resolved !== undefined) {
    if (options.resolved) {
      conditions.push("resolved_at IS NOT NULL");
    } else {
      conditions.push("resolved_at IS NULL");
    }
  }

  let query = "SELECT * FROM alert_events";
  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }
  query += " ORDER BY triggered_at DESC";

  if (options?.limit) {
    query += " LIMIT ?";
    params.push(options.limit);
  }

  const rows = database.prepare(query).all(...params) as Record<string, unknown>[];
  return rows.map((row) => ({
    id: row.id as string,
    ruleId: row.rule_id as string,
    ruleName: row.rule_name as string,
    severity: row.severity as AlertRuleSeverity,
    title: row.title as string,
    message: row.message as string,
    triggeredAt: row.triggered_at as string,
    resolvedAt: row.resolved_at as string | undefined,
    acknowledgedAt: row.acknowledged_at as string | undefined,
    acknowledgedBy: row.acknowledged_by as string | undefined,
    metadata: row.metadata_json ? JSON.parse(row.metadata_json as string) : undefined,
    notificationsSent: row.notifications_sent as number,
  }));
}

export function acknowledgeAlertEvent(id: string, acknowledgedBy: string): AlertEvent | null {
  const database = getDb();
  const existing = getAlertEvent(id);
  if (!existing) return null;

  const now = new Date().toISOString();
  database
    .prepare(
      `
    UPDATE alert_events SET acknowledged_at = ?, acknowledged_by = ? WHERE id = ?
  `
    )
    .run(now, acknowledgedBy, id);

  logAudit("alert_acknowledged", existing.ruleId, acknowledgedBy, { eventId: id });
  return getAlertEvent(id);
}

export function resolveAlertEvent(id: string, actor?: string): AlertEvent | null {
  const database = getDb();
  const existing = getAlertEvent(id);
  if (!existing) return null;

  const now = new Date().toISOString();
  database
    .prepare(
      `
    UPDATE alert_events SET resolved_at = ? WHERE id = ?
  `
    )
    .run(now, id);

  logAudit("alert_resolved", existing.ruleId, actor, { eventId: id });
  return getAlertEvent(id);
}

export interface AlertRulesAuditEntry {
  id: string;
  eventType: string;
  ruleId?: string;
  actor?: string;
  details?: Record<string, unknown>;
  timestamp: string;
}

export function getAlertRulesAuditLog(options?: {
  ruleId?: string;
  limit?: number;
}): AlertRulesAuditEntry[] {
  const database = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options?.ruleId) {
    conditions.push("rule_id = ?");
    params.push(options.ruleId);
  }

  let query = "SELECT * FROM alert_rules_audit";
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
    ruleId: row.rule_id as string | undefined,
    actor: row.actor as string | undefined,
    details: row.details_json ? JSON.parse(row.details_json as string) : undefined,
    timestamp: row.timestamp as string,
  }));
}
