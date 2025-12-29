/**
 * Notification Channels Module
 * Manages notification channel configurations for alerts
 */

import Database from "better-sqlite3";
import { randomUUID } from "crypto";

// Local type definitions
export type NotificationChannelType =
  | "slack"
  | "teams"
  | "email"
  | "pagerduty"
  | "webhook"
  | "opsgenie";
export type ChannelStatus = "active" | "inactive" | "error";

export interface SlackChannelConfig {
  webhookUrl: string;
  channel?: string;
  username?: string;
  iconEmoji?: string;
}

export interface TeamsChannelConfig {
  webhookUrl: string;
}

export interface EmailChannelConfig {
  smtpHost: string;
  smtpPort: number;
  smtpUser?: string;
  smtpPassword?: string;
  smtpSecure?: boolean;
  from: string;
  to: string[];
  cc?: string[];
}

export interface PagerDutyChannelConfig {
  routingKey: string;
  severity?: "critical" | "error" | "warning" | "info";
}

export interface WebhookChannelConfig {
  url: string;
  method?: "POST" | "PUT";
  headers?: Record<string, string>;
  authType?: "none" | "basic" | "bearer";
  authCredentials?: string;
}

export interface OpsGenieChannelConfig {
  apiKey: string;
  region?: "us" | "eu";
  priority?: "P1" | "P2" | "P3" | "P4" | "P5";
}

export type ChannelConfig =
  | SlackChannelConfig
  | TeamsChannelConfig
  | EmailChannelConfig
  | PagerDutyChannelConfig
  | WebhookChannelConfig
  | OpsGenieChannelConfig;

export interface NotificationChannel {
  id: string;
  name: string;
  type: NotificationChannelType;
  config: ChannelConfig;
  status: ChannelStatus;
  description?: string;
  createdBy?: string;
  createdAt: string;
  updatedAt: string;
  lastTestedAt?: string;
  lastError?: string;
}

export interface CreateChannelOptions {
  name: string;
  type: NotificationChannelType;
  config: ChannelConfig;
  description?: string;
  createdBy?: string;
}

export interface UpdateChannelOptions {
  name?: string;
  config?: ChannelConfig;
  description?: string;
  status?: ChannelStatus;
}

export interface TestChannelResult {
  success: boolean;
  message: string;
  responseTime?: number;
  error?: string;
}

export interface NotificationPayload {
  title: string;
  message: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  source?: string;
  timestamp?: string;
  details?: Record<string, unknown>;
  links?: { title: string; url: string }[];
}

export interface SendNotificationResult {
  channelId: string;
  channelName: string;
  success: boolean;
  error?: string;
  responseTime?: number;
}

let db: Database.Database | null = null;

const NOTIFICATION_SCHEMA = `
  CREATE TABLE IF NOT EXISTS notification_channels (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL,
    config_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    description TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_tested_at TEXT,
    last_error TEXT
  );

  CREATE TABLE IF NOT EXISTS notification_history (
    id TEXT PRIMARY KEY,
    channel_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    success INTEGER NOT NULL,
    error TEXT,
    response_time_ms INTEGER,
    sent_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (channel_id) REFERENCES notification_channels(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS notification_audit (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    channel_id TEXT,
    actor TEXT,
    details_json TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_channels_type ON notification_channels(type);
  CREATE INDEX IF NOT EXISTS idx_channels_status ON notification_channels(status);
  CREATE INDEX IF NOT EXISTS idx_history_channel ON notification_history(channel_id);
  CREATE INDEX IF NOT EXISTS idx_history_sent ON notification_history(sent_at);
`;

export interface NotificationDbInitResult {
  path: string;
  initialized: boolean;
}

export function initNotificationDatabase(dbPath?: string): NotificationDbInitResult {
  const path = dbPath || ":memory:";
  db = new Database(path);
  db.exec(NOTIFICATION_SCHEMA);
  return { path, initialized: true };
}

export function closeNotificationDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

function getDb(): Database.Database {
  if (!db) {
    throw new Error("Notification database not initialized. Call initNotificationDatabase first.");
  }
  return db;
}

function logAudit(
  eventType: string,
  channelId: string | undefined,
  actor: string | undefined,
  details?: Record<string, unknown>
): void {
  const database = getDb();
  database
    .prepare(
      `
    INSERT INTO notification_audit (id, event_type, channel_id, actor, details_json)
    VALUES (?, ?, ?, ?, ?)
  `
    )
    .run(randomUUID(), eventType, channelId, actor, details ? JSON.stringify(details) : null);
}

export function createNotificationChannel(options: CreateChannelOptions): NotificationChannel {
  const database = getDb();
  const id = randomUUID();
  const now = new Date().toISOString();

  database
    .prepare(
      `
    INSERT INTO notification_channels (id, name, type, config_json, status, description, created_by, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      id,
      options.name,
      options.type,
      JSON.stringify(options.config),
      "active",
      options.description || null,
      options.createdBy || null,
      now,
      now
    );

  logAudit("channel_created", id, options.createdBy, { name: options.name, type: options.type });
  return getNotificationChannel(id)!;
}

export function getNotificationChannel(id: string): NotificationChannel | null {
  const database = getDb();
  const row = database.prepare("SELECT * FROM notification_channels WHERE id = ?").get(id) as
    | Record<string, unknown>
    | undefined;

  if (!row) return null;

  return {
    id: row.id as string,
    name: row.name as string,
    type: row.type as NotificationChannelType,
    config: JSON.parse(row.config_json as string),
    status: row.status as ChannelStatus,
    description: row.description as string | undefined,
    createdBy: row.created_by as string | undefined,
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
    lastTestedAt: row.last_tested_at as string | undefined,
    lastError: row.last_error as string | undefined,
  };
}

export function getNotificationChannelByName(name: string): NotificationChannel | null {
  const database = getDb();
  const row = database.prepare("SELECT * FROM notification_channels WHERE name = ?").get(name) as
    | Record<string, unknown>
    | undefined;

  if (!row) return null;

  return {
    id: row.id as string,
    name: row.name as string,
    type: row.type as NotificationChannelType,
    config: JSON.parse(row.config_json as string),
    status: row.status as ChannelStatus,
    description: row.description as string | undefined,
    createdBy: row.created_by as string | undefined,
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
    lastTestedAt: row.last_tested_at as string | undefined,
    lastError: row.last_error as string | undefined,
  };
}

export function listNotificationChannels(options?: {
  type?: NotificationChannelType;
  status?: ChannelStatus;
}): NotificationChannel[] {
  const database = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options?.type) {
    conditions.push("type = ?");
    params.push(options.type);
  }
  if (options?.status) {
    conditions.push("status = ?");
    params.push(options.status);
  }

  let query = "SELECT * FROM notification_channels";
  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }
  query += " ORDER BY name ASC";

  const rows = database.prepare(query).all(...params) as Record<string, unknown>[];
  return rows.map((row) => ({
    id: row.id as string,
    name: row.name as string,
    type: row.type as NotificationChannelType,
    config: JSON.parse(row.config_json as string),
    status: row.status as ChannelStatus,
    description: row.description as string | undefined,
    createdBy: row.created_by as string | undefined,
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
    lastTestedAt: row.last_tested_at as string | undefined,
    lastError: row.last_error as string | undefined,
  }));
}

export function updateNotificationChannel(
  id: string,
  updates: UpdateChannelOptions,
  actor?: string
): NotificationChannel | null {
  const database = getDb();
  const existing = getNotificationChannel(id);
  if (!existing) return null;

  const now = new Date().toISOString();
  const setClauses: string[] = ["updated_at = ?"];
  const params: unknown[] = [now];

  if (updates.name !== undefined) {
    setClauses.push("name = ?");
    params.push(updates.name);
  }
  if (updates.config !== undefined) {
    setClauses.push("config_json = ?");
    params.push(JSON.stringify(updates.config));
  }
  if (updates.description !== undefined) {
    setClauses.push("description = ?");
    params.push(updates.description);
  }
  if (updates.status !== undefined) {
    setClauses.push("status = ?");
    params.push(updates.status);
  }

  params.push(id);
  database
    .prepare(`UPDATE notification_channels SET ${setClauses.join(", ")} WHERE id = ?`)
    .run(...params);

  logAudit("channel_updated", id, actor, { ...updates });
  return getNotificationChannel(id);
}

export function deleteNotificationChannel(id: string, actor?: string): boolean {
  const database = getDb();
  const existing = getNotificationChannel(id);
  if (!existing) return false;

  database.prepare("DELETE FROM notification_channels WHERE id = ?").run(id);
  logAudit("channel_deleted", id, actor, { name: existing.name });
  return true;
}

export async function testNotificationChannel(
  id: string,
  actor?: string
): Promise<TestChannelResult> {
  const channel = getNotificationChannel(id);
  if (!channel) {
    return { success: false, message: "Channel not found" };
  }

  const database = getDb();
  const now = new Date().toISOString();
  const startTime = Date.now();

  try {
    let testResult: TestChannelResult;

    switch (channel.type) {
      case "slack":
      case "teams":
      case "webhook": {
        const config = channel.config as
          | SlackChannelConfig
          | TeamsChannelConfig
          | WebhookChannelConfig;
        const url =
          "webhookUrl" in config ? config.webhookUrl : (config as WebhookChannelConfig).url;
        if (!url || !url.startsWith("http")) {
          throw new Error("Invalid webhook URL");
        }
        testResult = { success: true, message: "Webhook URL validated successfully" };
        break;
      }
      case "email": {
        const config = channel.config as EmailChannelConfig;
        if (!config.smtpHost || !config.from || !config.to?.length) {
          throw new Error("Missing required email configuration");
        }
        testResult = { success: true, message: "Email configuration validated successfully" };
        break;
      }
      case "pagerduty": {
        const config = channel.config as PagerDutyChannelConfig;
        if (!config.routingKey) {
          throw new Error("Missing PagerDuty routing key");
        }
        testResult = { success: true, message: "PagerDuty configuration validated successfully" };
        break;
      }
      case "opsgenie": {
        const config = channel.config as OpsGenieChannelConfig;
        if (!config.apiKey) {
          throw new Error("Missing OpsGenie API key");
        }
        testResult = { success: true, message: "OpsGenie configuration validated successfully" };
        break;
      }
      default:
        testResult = { success: false, message: "Unknown channel type" };
    }

    const responseTime = Date.now() - startTime;
    testResult.responseTime = responseTime;

    database
      .prepare(
        `
      UPDATE notification_channels SET last_tested_at = ?, last_error = NULL, status = 'active' WHERE id = ?
    `
      )
      .run(now, id);

    logAudit("channel_tested", id, actor, { success: true, responseTime });
    return testResult;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    const responseTime = Date.now() - startTime;

    database
      .prepare(
        `
      UPDATE notification_channels SET last_tested_at = ?, last_error = ?, status = 'error' WHERE id = ?
    `
      )
      .run(now, errorMessage, id);

    logAudit("channel_tested", id, actor, { success: false, error: errorMessage });
    return { success: false, message: "Test failed", error: errorMessage, responseTime };
  }
}

export async function sendNotification(
  channelId: string,
  payload: NotificationPayload
): Promise<SendNotificationResult> {
  const channel = getNotificationChannel(channelId);
  if (!channel) {
    return { channelId, channelName: "unknown", success: false, error: "Channel not found" };
  }

  if (channel.status !== "active") {
    return { channelId, channelName: channel.name, success: false, error: "Channel is not active" };
  }

  const database = getDb();
  const startTime = Date.now();
  const historyId = randomUUID();
  const finalPayload = {
    ...payload,
    timestamp: payload.timestamp || new Date().toISOString(),
  };

  try {
    const responseTime = Date.now() - startTime;

    database
      .prepare(
        `
      INSERT INTO notification_history (id, channel_id, payload_json, success, response_time_ms)
      VALUES (?, ?, ?, ?, ?)
    `
      )
      .run(historyId, channelId, JSON.stringify(finalPayload), 1, responseTime);

    return { channelId, channelName: channel.name, success: true, responseTime };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    const responseTime = Date.now() - startTime;

    database
      .prepare(
        `
      INSERT INTO notification_history (id, channel_id, payload_json, success, error, response_time_ms)
      VALUES (?, ?, ?, ?, ?, ?)
    `
      )
      .run(historyId, channelId, JSON.stringify(finalPayload), 0, errorMessage, responseTime);

    return {
      channelId,
      channelName: channel.name,
      success: false,
      error: errorMessage,
      responseTime,
    };
  }
}

export async function sendToMultipleChannels(
  channelIds: string[],
  payload: NotificationPayload
): Promise<SendNotificationResult[]> {
  const results: SendNotificationResult[] = [];
  for (const channelId of channelIds) {
    const result = await sendNotification(channelId, payload);
    results.push(result);
  }
  return results;
}

export interface NotificationHistoryEntry {
  id: string;
  channelId: string;
  payload: NotificationPayload;
  success: boolean;
  error?: string;
  responseTimeMs?: number;
  sentAt: string;
}

export function getNotificationHistory(options?: {
  channelId?: string;
  limit?: number;
}): NotificationHistoryEntry[] {
  const database = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options?.channelId) {
    conditions.push("channel_id = ?");
    params.push(options.channelId);
  }

  let query = "SELECT * FROM notification_history";
  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }
  query += " ORDER BY sent_at DESC";

  if (options?.limit) {
    query += " LIMIT ?";
    params.push(options.limit);
  }

  const rows = database.prepare(query).all(...params) as Record<string, unknown>[];
  return rows.map((row) => ({
    id: row.id as string,
    channelId: row.channel_id as string,
    payload: JSON.parse(row.payload_json as string),
    success: (row.success as number) === 1,
    error: row.error as string | undefined,
    responseTimeMs: row.response_time_ms as number | undefined,
    sentAt: row.sent_at as string,
  }));
}

export interface NotificationAuditEntry {
  id: string;
  eventType: string;
  channelId?: string;
  actor?: string;
  details?: Record<string, unknown>;
  timestamp: string;
}

export function getNotificationAuditLog(options?: {
  channelId?: string;
  limit?: number;
}): NotificationAuditEntry[] {
  const database = getDb();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options?.channelId) {
    conditions.push("channel_id = ?");
    params.push(options.channelId);
  }

  let query = "SELECT * FROM notification_audit";
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
    channelId: row.channel_id as string | undefined,
    actor: row.actor as string | undefined,
    details: row.details_json ? JSON.parse(row.details_json as string) : undefined,
    timestamp: row.timestamp as string,
  }));
}
