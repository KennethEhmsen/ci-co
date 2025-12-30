/**
 * Integration Webhooks Module (v1.28.0)
 *
 * Outbound webhooks to notify external systems of security events:
 * - Event-based triggers (scan completion, new vulnerabilities, etc.)
 * - Configurable payload templates
 * - Retry logic with exponential backoff
 * - HMAC signature verification
 */

import Database from "better-sqlite3";
import { randomUUID, createHmac } from "crypto";

// =============================================================================
// Types
// =============================================================================

export type WebhookEventType =
  | "scan.completed"
  | "scan.failed"
  | "vulnerability.new_critical"
  | "vulnerability.new_high"
  | "vulnerability.new_medium"
  | "threshold.exceeded"
  | "compliance.violation"
  | "policy.failed"
  | "baseline.exceeded";

export type WebhookStatus = "active" | "inactive" | "failing";

export interface Webhook {
  id: string;
  name: string;
  url: string;
  secret: string;
  events: WebhookEventType[];
  headers: Record<string, string>;
  payloadTemplate?: string;
  status: WebhookStatus;
  failureCount: number;
  lastTriggeredAt?: string;
  lastSuccessAt?: string;
  createdAt: string;
  createdBy?: string;
}

export interface WebhookDelivery {
  id: string;
  webhookId: string;
  eventType: WebhookEventType;
  payload: string;
  responseStatus?: number;
  responseBody?: string;
  attempts: number;
  success: boolean;
  deliveredAt?: string;
  createdAt: string;
}

export interface WebhookDbInitResult {
  success: boolean;
  path: string;
  created: boolean;
}

export interface CreateWebhookOptions {
  name: string;
  url: string;
  events: WebhookEventType[];
  secret?: string;
  headers?: Record<string, string>;
  payloadTemplate?: string;
  createdBy?: string;
}

export interface UpdateWebhookOptions {
  name?: string;
  url?: string;
  events?: WebhookEventType[];
  secret?: string;
  headers?: Record<string, string>;
  payloadTemplate?: string;
  status?: WebhookStatus;
}

export interface TriggerWebhookOptions {
  eventType: WebhookEventType;
  payload: Record<string, unknown>;
  target?: string;
}

export interface WebhookTestResult {
  success: boolean;
  statusCode?: number;
  responseTime?: number;
  error?: string;
}

export interface WebhookAuditEntry {
  id: string;
  eventType: string;
  webhookId: string;
  actor?: string;
  details: Record<string, unknown>;
  timestamp: string;
}

// =============================================================================
// Database Management
// =============================================================================

let db: Database.Database | null = null;
let dbPath: string = ":memory:";

function runSchema(database: Database.Database, sql: string): void {
  database.exec(sql);
}

export function initWebhooksDatabase(path?: string): WebhookDbInitResult {
  if (db) {
    return { success: true, path: dbPath, created: false };
  }

  dbPath = path || ":memory:";
  db = new Database(dbPath);

  const schema = `
    CREATE TABLE IF NOT EXISTS webhooks (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      url TEXT NOT NULL,
      secret TEXT NOT NULL,
      events_json TEXT NOT NULL,
      headers_json TEXT,
      payload_template TEXT,
      status TEXT DEFAULT 'active',
      failure_count INTEGER DEFAULT 0,
      last_triggered_at TEXT,
      last_success_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      created_by TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_webhooks_status ON webhooks(status);

    CREATE TABLE IF NOT EXISTS webhook_deliveries (
      id TEXT PRIMARY KEY,
      webhook_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      payload TEXT NOT NULL,
      response_status INTEGER,
      response_body TEXT,
      attempts INTEGER DEFAULT 1,
      success INTEGER DEFAULT 0,
      delivered_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_deliveries_webhook ON webhook_deliveries(webhook_id);
    CREATE INDEX IF NOT EXISTS idx_deliveries_created ON webhook_deliveries(created_at);

    CREATE TABLE IF NOT EXISTS webhooks_audit (
      id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      webhook_id TEXT,
      actor TEXT,
      details_json TEXT,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_webhooks_audit_timestamp ON webhooks_audit(timestamp);
  `;

  runSchema(db, schema);

  return { success: true, path: dbPath, created: true };
}

export function closeWebhooksDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

export function getWebhooksDatabase(): Database.Database | null {
  return db;
}

// =============================================================================
// Audit Logging
// =============================================================================

function logAudit(
  eventType: string,
  webhookId: string,
  actor?: string,
  details?: Record<string, unknown>
): void {
  if (!db) return;

  const stmt = db.prepare(`
    INSERT INTO webhooks_audit (id, event_type, webhook_id, actor, details_json, timestamp)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    randomUUID(),
    eventType,
    webhookId,
    actor || null,
    details ? JSON.stringify(details) : null,
    new Date().toISOString()
  );
}

export function getWebhooksAuditLog(limit: number = 100): WebhookAuditEntry[] {
  if (!db) return [];

  const stmt = db.prepare(`
    SELECT id, event_type, webhook_id, actor, details_json, timestamp
    FROM webhooks_audit
    ORDER BY timestamp DESC
    LIMIT ?
  `);

  const rows = stmt.all(limit) as Array<{
    id: string;
    event_type: string;
    webhook_id: string;
    actor: string | null;
    details_json: string | null;
    timestamp: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    eventType: row.event_type,
    webhookId: row.webhook_id,
    actor: row.actor || undefined,
    details: row.details_json ? JSON.parse(row.details_json) : {},
    timestamp: row.timestamp,
  }));
}

// =============================================================================
// Signature Generation
// =============================================================================

export function generateSignature(payload: string, secret: string): string {
  return createHmac("sha256", secret).update(payload).digest("hex");
}

export function verifySignature(payload: string, secret: string, signature: string): boolean {
  const expected = generateSignature(payload, secret);
  return expected === signature;
}

// =============================================================================
// Webhook CRUD Operations
// =============================================================================

function generateSecret(): string {
  return "whsec_" + randomUUID().replace(/-/g, "");
}

export function createWebhook(options: CreateWebhookOptions): Webhook {
  if (!db) {
    throw new Error("Database not initialized. Call initWebhooksDatabase first.");
  }

  const id = randomUUID();
  const secret = options.secret || generateSecret();
  const now = new Date().toISOString();

  const stmt = db.prepare(`
    INSERT INTO webhooks (id, name, url, secret, events_json, headers_json, payload_template, status, created_at, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
  `);

  stmt.run(
    id,
    options.name,
    options.url,
    secret,
    JSON.stringify(options.events),
    options.headers ? JSON.stringify(options.headers) : null,
    options.payloadTemplate || null,
    now,
    options.createdBy || null
  );

  logAudit("webhook_created", id, options.createdBy, {
    name: options.name,
    url: options.url,
    events: options.events,
  });

  return {
    id,
    name: options.name,
    url: options.url,
    secret,
    events: options.events,
    headers: options.headers || {},
    payloadTemplate: options.payloadTemplate,
    status: "active",
    failureCount: 0,
    createdAt: now,
    createdBy: options.createdBy,
  };
}

export function getWebhook(id: string): Webhook | null {
  if (!db) return null;

  const stmt = db.prepare(`
    SELECT id, name, url, secret, events_json, headers_json, payload_template,
           status, failure_count, last_triggered_at, last_success_at, created_at, created_by
    FROM webhooks
    WHERE id = ?
  `);

  const row = stmt.get(id) as
    | {
        id: string;
        name: string;
        url: string;
        secret: string;
        events_json: string;
        headers_json: string | null;
        payload_template: string | null;
        status: string;
        failure_count: number;
        last_triggered_at: string | null;
        last_success_at: string | null;
        created_at: string;
        created_by: string | null;
      }
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    name: row.name,
    url: row.url,
    secret: row.secret,
    events: JSON.parse(row.events_json),
    headers: row.headers_json ? JSON.parse(row.headers_json) : {},
    payloadTemplate: row.payload_template || undefined,
    status: row.status as WebhookStatus,
    failureCount: row.failure_count,
    lastTriggeredAt: row.last_triggered_at || undefined,
    lastSuccessAt: row.last_success_at || undefined,
    createdAt: row.created_at,
    createdBy: row.created_by || undefined,
  };
}

export function listWebhooks(status?: WebhookStatus): Webhook[] {
  if (!db) return [];

  let sql = `
    SELECT id, name, url, secret, events_json, headers_json, payload_template,
           status, failure_count, last_triggered_at, last_success_at, created_at, created_by
    FROM webhooks
  `;

  if (status) {
    sql += " WHERE status = ?";
  }

  sql += " ORDER BY created_at DESC";

  const stmt = db.prepare(sql);
  const rows = (status ? stmt.all(status) : stmt.all()) as Array<{
    id: string;
    name: string;
    url: string;
    secret: string;
    events_json: string;
    headers_json: string | null;
    payload_template: string | null;
    status: string;
    failure_count: number;
    last_triggered_at: string | null;
    last_success_at: string | null;
    created_at: string;
    created_by: string | null;
  }>;

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    url: row.url,
    secret: row.secret,
    events: JSON.parse(row.events_json),
    headers: row.headers_json ? JSON.parse(row.headers_json) : {},
    payloadTemplate: row.payload_template || undefined,
    status: row.status as WebhookStatus,
    failureCount: row.failure_count,
    lastTriggeredAt: row.last_triggered_at || undefined,
    lastSuccessAt: row.last_success_at || undefined,
    createdAt: row.created_at,
    createdBy: row.created_by || undefined,
  }));
}

export function updateWebhook(
  id: string,
  options: UpdateWebhookOptions,
  actor?: string
): Webhook | null {
  if (!db) return null;

  const existing = getWebhook(id);
  if (!existing) return null;

  const updates: string[] = [];
  const params: (string | number | null)[] = [];

  if (options.name !== undefined) {
    updates.push("name = ?");
    params.push(options.name);
  }
  if (options.url !== undefined) {
    updates.push("url = ?");
    params.push(options.url);
  }
  if (options.events !== undefined) {
    updates.push("events_json = ?");
    params.push(JSON.stringify(options.events));
  }
  if (options.secret !== undefined) {
    updates.push("secret = ?");
    params.push(options.secret);
  }
  if (options.headers !== undefined) {
    updates.push("headers_json = ?");
    params.push(JSON.stringify(options.headers));
  }
  if (options.payloadTemplate !== undefined) {
    updates.push("payload_template = ?");
    params.push(options.payloadTemplate);
  }
  if (options.status !== undefined) {
    updates.push("status = ?");
    params.push(options.status);
  }

  if (updates.length === 0) return existing;

  params.push(id);
  const sql = `UPDATE webhooks SET ${updates.join(", ")} WHERE id = ?`;
  db.prepare(sql).run(...params);

  logAudit("webhook_updated", id, actor, { ...options });

  return getWebhook(id);
}

export function deleteWebhook(id: string, actor?: string): boolean {
  if (!db) return false;

  const stmt = db.prepare("DELETE FROM webhooks WHERE id = ?");
  const result = stmt.run(id);

  if (result.changes > 0) {
    logAudit("webhook_deleted", id, actor, {});
    return true;
  }

  return false;
}

// =============================================================================
// Webhook Triggering
// =============================================================================

const MAX_RETRIES = 3;
const RETRY_DELAYS = [1000, 5000, 15000]; // Exponential backoff delays in ms

function applyTemplate(template: string, data: Record<string, unknown>): string {
  let result = template;
  for (const [key, value] of Object.entries(data)) {
    const placeholder = `{{${key}}}`;
    result = result.replace(new RegExp(placeholder, "g"), String(value));
  }
  return result;
}

function recordDelivery(
  webhookId: string,
  eventType: WebhookEventType,
  payload: string,
  responseStatus?: number,
  responseBody?: string,
  success: boolean = false,
  attempts: number = 1
): WebhookDelivery {
  if (!db) {
    throw new Error("Database not initialized");
  }

  const id = randomUUID();
  const now = new Date().toISOString();

  const stmt = db.prepare(`
    INSERT INTO webhook_deliveries (id, webhook_id, event_type, payload, response_status, response_body, attempts, success, delivered_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    id,
    webhookId,
    eventType,
    payload,
    responseStatus || null,
    responseBody || null,
    attempts,
    success ? 1 : 0,
    success ? now : null,
    now
  );

  return {
    id,
    webhookId,
    eventType,
    payload,
    responseStatus,
    responseBody,
    attempts,
    success,
    deliveredAt: success ? now : undefined,
    createdAt: now,
  };
}

function updateWebhookTriggerStatus(webhookId: string, success: boolean): void {
  if (!db) return;

  const now = new Date().toISOString();

  if (success) {
    db.prepare(
      `
      UPDATE webhooks
      SET last_triggered_at = ?, last_success_at = ?, failure_count = 0, status = 'active'
      WHERE id = ?
    `
    ).run(now, now, webhookId);
  } else {
    db.prepare(
      `
      UPDATE webhooks
      SET last_triggered_at = ?, failure_count = failure_count + 1
      WHERE id = ?
    `
    ).run(now, webhookId);

    // Check if we should mark as failing
    const webhook = getWebhook(webhookId);
    if (webhook && webhook.failureCount >= 5) {
      db.prepare("UPDATE webhooks SET status = 'failing' WHERE id = ?").run(webhookId);
    }
  }
}

async function deliverWebhook(
  webhook: Webhook,
  eventType: WebhookEventType,
  payload: Record<string, unknown>
): Promise<{ success: boolean; statusCode?: number; error?: string; attempts: number }> {
  let payloadString: string;

  if (webhook.payloadTemplate) {
    payloadString = applyTemplate(webhook.payloadTemplate, payload);
  } else {
    payloadString = JSON.stringify({
      event: eventType,
      timestamp: new Date().toISOString(),
      data: payload,
    });
  }

  const signature = generateSignature(payloadString, webhook.secret);

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Webhook-Signature": signature,
    "X-Webhook-Event": eventType,
    ...webhook.headers,
  };

  let lastError: string | undefined;
  let lastStatusCode: number | undefined;
  let attempts = 0;

  for (let i = 0; i <= MAX_RETRIES; i++) {
    attempts = i + 1;

    if (i > 0) {
      await new Promise((resolve) => setTimeout(resolve, RETRY_DELAYS[i - 1]));
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000);

      const response = await fetch(webhook.url, {
        method: "POST",
        headers,
        body: payloadString,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      lastStatusCode = response.status;

      const responseBody = await response.text();

      if (response.ok) {
        recordDelivery(
          webhook.id,
          eventType,
          payloadString,
          response.status,
          responseBody,
          true,
          attempts
        );
        updateWebhookTriggerStatus(webhook.id, true);
        return { success: true, statusCode: response.status, attempts };
      }

      lastError = `HTTP ${response.status}: ${responseBody.slice(0, 500)}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
  }

  // All retries failed
  recordDelivery(webhook.id, eventType, payloadString, lastStatusCode, lastError, false, attempts);
  updateWebhookTriggerStatus(webhook.id, false);

  return { success: false, statusCode: lastStatusCode, error: lastError, attempts };
}

export interface TriggerResult {
  triggered: number;
  successful: number;
  failed: number;
  results: Array<{
    webhookId: string;
    webhookName: string;
    success: boolean;
    statusCode?: number;
    error?: string;
    attempts: number;
  }>;
}

export async function triggerWebhooks(options: TriggerWebhookOptions): Promise<TriggerResult> {
  if (!db) {
    throw new Error("Database not initialized");
  }

  const webhooks = listWebhooks("active");
  const matchingWebhooks = webhooks.filter((w) => w.events.includes(options.eventType));

  const results: TriggerResult = {
    triggered: matchingWebhooks.length,
    successful: 0,
    failed: 0,
    results: [],
  };

  for (const webhook of matchingWebhooks) {
    const result = await deliverWebhook(webhook, options.eventType, options.payload);

    results.results.push({
      webhookId: webhook.id,
      webhookName: webhook.name,
      success: result.success,
      statusCode: result.statusCode,
      error: result.error,
      attempts: result.attempts,
    });

    if (result.success) {
      results.successful++;
    } else {
      results.failed++;
    }
  }

  logAudit("webhooks_triggered", "", undefined, {
    eventType: options.eventType,
    triggered: results.triggered,
    successful: results.successful,
    failed: results.failed,
  });

  return results;
}

// =============================================================================
// Test Webhook
// =============================================================================

export async function testWebhook(webhookId: string): Promise<WebhookTestResult> {
  const webhook = getWebhook(webhookId);
  if (!webhook) {
    return { success: false, error: "Webhook not found" };
  }

  const testPayload = {
    test: true,
    message: "This is a test webhook delivery",
    timestamp: new Date().toISOString(),
  };

  const startTime = Date.now();

  try {
    const payloadString = JSON.stringify({
      event: "test",
      timestamp: new Date().toISOString(),
      data: testPayload,
    });

    const signature = generateSignature(payloadString, webhook.secret);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(webhook.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Webhook-Signature": signature,
        "X-Webhook-Event": "test",
        ...webhook.headers,
      },
      body: payloadString,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    const responseTime = Date.now() - startTime;

    logAudit("webhook_tested", webhookId, undefined, {
      success: response.ok,
      statusCode: response.status,
      responseTime,
    });

    return {
      success: response.ok,
      statusCode: response.status,
      responseTime,
    };
  } catch (error) {
    const responseTime = Date.now() - startTime;
    const errorMessage = error instanceof Error ? error.message : String(error);

    logAudit("webhook_tested", webhookId, undefined, {
      success: false,
      error: errorMessage,
      responseTime,
    });

    return {
      success: false,
      error: errorMessage,
      responseTime,
    };
  }
}

// =============================================================================
// Delivery History
// =============================================================================

export interface DeliveryHistoryOptions {
  webhookId?: string;
  eventType?: WebhookEventType;
  successOnly?: boolean;
  limit?: number;
}

export function getDeliveryHistory(options: DeliveryHistoryOptions = {}): WebhookDelivery[] {
  if (!db) return [];

  const conditions: string[] = [];
  const params: (string | number)[] = [];

  if (options.webhookId) {
    conditions.push("webhook_id = ?");
    params.push(options.webhookId);
  }

  if (options.eventType) {
    conditions.push("event_type = ?");
    params.push(options.eventType);
  }

  if (options.successOnly) {
    conditions.push("success = 1");
  }

  let sql = `
    SELECT id, webhook_id, event_type, payload, response_status, response_body,
           attempts, success, delivered_at, created_at
    FROM webhook_deliveries
  `;

  if (conditions.length > 0) {
    sql += " WHERE " + conditions.join(" AND ");
  }

  sql += " ORDER BY created_at DESC LIMIT ?";
  params.push(options.limit || 100);

  const stmt = db.prepare(sql);
  const rows = stmt.all(...params) as Array<{
    id: string;
    webhook_id: string;
    event_type: string;
    payload: string;
    response_status: number | null;
    response_body: string | null;
    attempts: number;
    success: number;
    delivered_at: string | null;
    created_at: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    webhookId: row.webhook_id,
    eventType: row.event_type as WebhookEventType,
    payload: row.payload,
    responseStatus: row.response_status || undefined,
    responseBody: row.response_body || undefined,
    attempts: row.attempts,
    success: row.success === 1,
    deliveredAt: row.delivered_at || undefined,
    createdAt: row.created_at,
  }));
}

// =============================================================================
// Statistics
// =============================================================================

export interface WebhookStats {
  totalWebhooks: number;
  activeWebhooks: number;
  failingWebhooks: number;
  totalDeliveries: number;
  successfulDeliveries: number;
  failedDeliveries: number;
  successRate: number;
  averageAttempts: number;
}

export function getWebhookStats(): WebhookStats {
  if (!db) {
    return {
      totalWebhooks: 0,
      activeWebhooks: 0,
      failingWebhooks: 0,
      totalDeliveries: 0,
      successfulDeliveries: 0,
      failedDeliveries: 0,
      successRate: 0,
      averageAttempts: 0,
    };
  }

  const webhookCounts = db
    .prepare(
      `
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
      SUM(CASE WHEN status = 'failing' THEN 1 ELSE 0 END) as failing
    FROM webhooks
  `
    )
    .get() as { total: number; active: number; failing: number };

  const deliveryCounts = db
    .prepare(
      `
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
      AVG(attempts) as avg_attempts
    FROM webhook_deliveries
  `
    )
    .get() as { total: number; successful: number; avg_attempts: number | null };

  const totalDeliveries = deliveryCounts.total || 0;
  const successfulDeliveries = deliveryCounts.successful || 0;

  return {
    totalWebhooks: webhookCounts.total,
    activeWebhooks: webhookCounts.active,
    failingWebhooks: webhookCounts.failing,
    totalDeliveries,
    successfulDeliveries,
    failedDeliveries: totalDeliveries - successfulDeliveries,
    successRate: totalDeliveries > 0 ? (successfulDeliveries / totalDeliveries) * 100 : 0,
    averageAttempts: deliveryCounts.avg_attempts || 1,
  };
}

// =============================================================================
// Cleanup
// =============================================================================

export function cleanupOldDeliveries(olderThanDays: number = 30): number {
  if (!db) return 0;

  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

  const result = db
    .prepare(
      `
    DELETE FROM webhook_deliveries
    WHERE created_at < ?
  `
    )
    .run(cutoffDate.toISOString());

  return result.changes;
}
