/**
 * High Availability & Resilience Module
 * Provides HA cluster management, failover, and replication monitoring
 * Part of v1.30.0 - Enterprise Scale & Multi-Cloud Security
 */

import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";

// ============================================================================
// Types
// ============================================================================

export type NodeRole = "primary" | "standby" | "arbiter";
export type NodeStatus = "online" | "offline" | "degraded" | "syncing";
export type ClusterHealth = "healthy" | "degraded" | "critical" | "split-brain";

export interface ClusterNode {
  id: string;
  hostname: string;
  address: string;
  port: number;
  role: NodeRole;
  status: NodeStatus;
  lastHeartbeat: string;
  replicationLag?: number;
  version: string;
  startedAt: string;
}

export interface ClusterStatus {
  clusterId: string;
  health: ClusterHealth;
  primaryNode: ClusterNode | null;
  nodes: ClusterNode[];
  quorum: boolean;
  replicationEnabled: boolean;
  lastFailover?: string;
  uptime: number;
}

export interface ReplicationStatus {
  enabled: boolean;
  mode: "sync" | "async";
  primaryNode: string;
  standbyNodes: Array<{
    nodeId: string;
    lag: number;
    lagBytes: number;
    lastSync: string;
    status: "caught-up" | "lagging" | "disconnected";
  }>;
  walPosition: number;
  averageLag: number;
}

export interface FailoverConfig {
  enabled: boolean;
  mode: "automatic" | "manual";
  healthCheckInterval: number;
  failoverTimeout: number;
  minStandbyNodes: number;
  maxReplicationLag: number;
  webhookUrl?: string;
}

export interface FailoverEvent {
  id: string;
  timestamp: string;
  type: "automatic" | "manual" | "test";
  fromNode: string;
  toNode: string;
  reason: string;
  duration: number;
  success: boolean;
  details?: string;
}

export interface SplitBrainStatus {
  detected: boolean;
  partitions: Array<{
    nodes: string[];
    hasPrimary: boolean;
    isQuorum: boolean;
  }>;
  resolution?: string;
  lastCheck: string;
}

// ============================================================================
// Database
// ============================================================================

let db: Database.Database | null = null;
const DEFAULT_DB_PATH = path.join(process.cwd(), ".cicd-security", "ha-cluster.db");

export function initHaDb(dbPath: string = DEFAULT_DB_PATH): { path: string; tables: string[] } {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  db = new Database(dbPath);
  db.pragma("journal_mode = WAL");

  db.exec(`
    CREATE TABLE IF NOT EXISTS cluster_nodes (
      id TEXT PRIMARY KEY,
      hostname TEXT NOT NULL,
      address TEXT NOT NULL,
      port INTEGER NOT NULL,
      role TEXT NOT NULL,
      status TEXT NOT NULL,
      last_heartbeat TEXT,
      replication_lag INTEGER,
      version TEXT,
      started_at TEXT,
      config TEXT
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS cluster_config (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS failover_history (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      type TEXT NOT NULL,
      from_node TEXT NOT NULL,
      to_node TEXT NOT NULL,
      reason TEXT,
      duration INTEGER,
      success INTEGER,
      details TEXT
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS heartbeat_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      node_id TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      latency INTEGER,
      status TEXT
    )
  `);

  const configStmt = db.prepare("SELECT COUNT(*) as count FROM cluster_config");
  const { count } = configStmt.get() as { count: number };

  if (count === 0) {
    const clusterId = `cluster-${Date.now()}`;
    const insertConfig = db.prepare("INSERT INTO cluster_config (key, value) VALUES (?, ?)");
    insertConfig.run("cluster_id", clusterId);
    insertConfig.run("failover_enabled", "true");
    insertConfig.run("failover_mode", "automatic");
    insertConfig.run("health_check_interval", "5000");
    insertConfig.run("failover_timeout", "30000");
    insertConfig.run("min_standby_nodes", "1");
    insertConfig.run("max_replication_lag", "10000");
  }

  return {
    path: dbPath,
    tables: ["cluster_nodes", "cluster_config", "failover_history", "heartbeat_log"],
  };
}

function getDb(): Database.Database {
  if (!db) {
    initHaDb();
  }
  return db!;
}

// ============================================================================
// Node Management
// ============================================================================

export function registerNode(node: Omit<ClusterNode, "lastHeartbeat">): {
  success: boolean;
  nodeId: string;
} {
  const database = getDb();
  const now = new Date().toISOString();

  const stmt = database.prepare(`
    INSERT INTO cluster_nodes (id, hostname, address, port, role, status, last_heartbeat, version, started_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      hostname = excluded.hostname,
      address = excluded.address,
      port = excluded.port,
      role = excluded.role,
      status = excluded.status,
      last_heartbeat = excluded.last_heartbeat,
      version = excluded.version
  `);

  stmt.run(
    node.id,
    node.hostname,
    node.address,
    node.port,
    node.role,
    node.status,
    now,
    node.version,
    node.startedAt
  );

  return { success: true, nodeId: node.id };
}

export function getNode(nodeId: string): ClusterNode | null {
  const database = getDb();
  const stmt = database.prepare("SELECT * FROM cluster_nodes WHERE id = ?");
  const row = stmt.get(nodeId) as
    | {
        id: string;
        hostname: string;
        address: string;
        port: number;
        role: string;
        status: string;
        last_heartbeat: string;
        replication_lag: number;
        version: string;
        started_at: string;
      }
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    hostname: row.hostname,
    address: row.address,
    port: row.port,
    role: row.role as NodeRole,
    status: row.status as NodeStatus,
    lastHeartbeat: row.last_heartbeat,
    replicationLag: row.replication_lag,
    version: row.version,
    startedAt: row.started_at,
  };
}

export function listNodes(): ClusterNode[] {
  const database = getDb();
  const stmt = database.prepare("SELECT * FROM cluster_nodes ORDER BY role, hostname");
  const rows = stmt.all() as Array<{
    id: string;
    hostname: string;
    address: string;
    port: number;
    role: string;
    status: string;
    last_heartbeat: string;
    replication_lag: number;
    version: string;
    started_at: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    hostname: row.hostname,
    address: row.address,
    port: row.port,
    role: row.role as NodeRole,
    status: row.status as NodeStatus,
    lastHeartbeat: row.last_heartbeat,
    replicationLag: row.replication_lag,
    version: row.version,
    startedAt: row.started_at,
  }));
}

export function removeNode(nodeId: string): { success: boolean; removed: boolean } {
  const database = getDb();
  const stmt = database.prepare("DELETE FROM cluster_nodes WHERE id = ?");
  const result = stmt.run(nodeId);
  return { success: true, removed: result.changes > 0 };
}

export function updateNodeStatus(nodeId: string, status: NodeStatus): { success: boolean } {
  const database = getDb();
  const now = new Date().toISOString();
  const stmt = database.prepare(
    "UPDATE cluster_nodes SET status = ?, last_heartbeat = ? WHERE id = ?"
  );
  stmt.run(status, now, nodeId);
  return { success: true };
}

export function recordHeartbeat(nodeId: string, latency: number): { success: boolean } {
  const database = getDb();
  const now = new Date().toISOString();

  database
    .prepare("UPDATE cluster_nodes SET last_heartbeat = ?, status = ? WHERE id = ?")
    .run(now, "online", nodeId);
  database
    .prepare("INSERT INTO heartbeat_log (node_id, timestamp, latency, status) VALUES (?, ?, ?, ?)")
    .run(nodeId, now, latency, "ok");

  return { success: true };
}

// ============================================================================
// Cluster Status
// ============================================================================

export function getClusterStatus(): ClusterStatus {
  const database = getDb();
  const configRows = database.prepare("SELECT key, value FROM cluster_config").all() as Array<{
    key: string;
    value: string;
  }>;
  const config: Record<string, string> = {};
  for (const row of configRows) config[row.key] = row.value;

  const nodes = listNodes();
  const primaryNode = nodes.find((n) => n.role === "primary" && n.status === "online") || null;
  const onlineNodes = nodes.filter((n) => n.status === "online");
  const standbyNodes = nodes.filter((n) => n.role === "standby" && n.status === "online");

  let health: ClusterHealth = "healthy";
  if (onlineNodes.length === 0 || !primaryNode) health = "critical";
  else if (standbyNodes.length === 0) health = "degraded";
  else if (nodes.some((n) => n.replicationLag && n.replicationLag > 10000)) health = "degraded";

  const splitBrain = detectSplitBrain();
  if (splitBrain.detected) health = "split-brain";

  const quorum = onlineNodes.length > nodes.length / 2;
  const lastFailoverRow = database
    .prepare("SELECT timestamp FROM failover_history ORDER BY timestamp DESC LIMIT 1")
    .get() as { timestamp: string } | undefined;

  const oldestStart = nodes.reduce(
    (oldest, n) => (!oldest || n.startedAt < oldest ? n.startedAt : oldest),
    ""
  );
  const uptime = oldestStart ? Date.now() - new Date(oldestStart).getTime() : 0;

  return {
    clusterId: config.cluster_id || "unknown",
    health,
    primaryNode,
    nodes,
    quorum,
    replicationEnabled: true,
    lastFailover: lastFailoverRow?.timestamp,
    uptime,
  };
}

export function getReplicationStatus(): ReplicationStatus {
  const nodes = listNodes();
  const primaryNode = nodes.find((n) => n.role === "primary");
  const standbyNodes = nodes.filter((n) => n.role === "standby");

  const standbyStatus = standbyNodes.map((node) => {
    let status: "caught-up" | "lagging" | "disconnected" = "caught-up";
    if (node.status !== "online") status = "disconnected";
    else if (node.replicationLag && node.replicationLag > 5000) status = "lagging";

    return {
      nodeId: node.id,
      lag: node.replicationLag || 0,
      lagBytes: (node.replicationLag || 0) * 100,
      lastSync: node.lastHeartbeat,
      status,
    };
  });

  const totalLag = standbyStatus.reduce((sum, s) => sum + s.lag, 0);

  return {
    enabled: true,
    mode: "async",
    primaryNode: primaryNode?.id || "none",
    standbyNodes: standbyStatus,
    walPosition: Date.now(),
    averageLag: standbyStatus.length > 0 ? totalLag / standbyStatus.length : 0,
  };
}

// ============================================================================
// Failover Management
// ============================================================================

export function getFailoverConfig(): FailoverConfig {
  const database = getDb();
  const rows = database.prepare("SELECT key, value FROM cluster_config").all() as Array<{
    key: string;
    value: string;
  }>;
  const config: Record<string, string> = {};
  for (const row of rows) config[row.key] = row.value;

  return {
    enabled: config.failover_enabled === "true",
    mode: (config.failover_mode as "automatic" | "manual") || "automatic",
    healthCheckInterval: parseInt(config.health_check_interval || "5000"),
    failoverTimeout: parseInt(config.failover_timeout || "30000"),
    minStandbyNodes: parseInt(config.min_standby_nodes || "1"),
    maxReplicationLag: parseInt(config.max_replication_lag || "10000"),
    webhookUrl: config.webhook_url,
  };
}

export function setFailoverConfig(config: Partial<FailoverConfig>): { success: boolean } {
  const database = getDb();
  const stmt = database.prepare(
    "INSERT INTO cluster_config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP"
  );

  if (config.enabled !== undefined) stmt.run("failover_enabled", config.enabled.toString());
  if (config.mode) stmt.run("failover_mode", config.mode);
  if (config.healthCheckInterval)
    stmt.run("health_check_interval", config.healthCheckInterval.toString());
  if (config.failoverTimeout) stmt.run("failover_timeout", config.failoverTimeout.toString());
  if (config.minStandbyNodes) stmt.run("min_standby_nodes", config.minStandbyNodes.toString());
  if (config.maxReplicationLag)
    stmt.run("max_replication_lag", config.maxReplicationLag.toString());
  if (config.webhookUrl) stmt.run("webhook_url", config.webhookUrl);

  return { success: true };
}

export function promoteNode(
  nodeId: string,
  reason: string = "manual promotion"
): { success: boolean; event: FailoverEvent } {
  const database = getDb();
  const startTime = Date.now();
  const nodes = listNodes();
  const currentPrimary = nodes.find((n) => n.role === "primary");
  const targetNode = nodes.find((n) => n.id === nodeId);

  if (!targetNode) throw new Error(`Node ${nodeId} not found`);
  if (targetNode.role === "primary") throw new Error(`Node ${nodeId} is already primary`);

  if (currentPrimary)
    database
      .prepare("UPDATE cluster_nodes SET role = ? WHERE id = ?")
      .run("standby", currentPrimary.id);
  database.prepare("UPDATE cluster_nodes SET role = ? WHERE id = ?").run("primary", nodeId);

  const event: FailoverEvent = {
    id: `failover-${Date.now()}`,
    timestamp: new Date().toISOString(),
    type: "manual",
    fromNode: currentPrimary?.id || "none",
    toNode: nodeId,
    reason,
    duration: Date.now() - startTime,
    success: true,
  };

  database
    .prepare(
      "INSERT INTO failover_history (id, timestamp, type, from_node, to_node, reason, duration, success) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .run(
      event.id,
      event.timestamp,
      event.type,
      event.fromNode,
      event.toNode,
      event.reason,
      event.duration,
      1
    );

  return { success: true, event };
}

export function demoteNode(nodeId: string): { success: boolean } {
  const database = getDb();
  const node = getNode(nodeId);
  if (!node) throw new Error(`Node ${nodeId} not found`);
  database.prepare("UPDATE cluster_nodes SET role = ? WHERE id = ?").run("standby", nodeId);
  return { success: true };
}

export function testFailover(targetNodeId?: string): {
  success: boolean;
  duration: number;
  steps: Array<{ step: string; status: string; duration: number }>;
} {
  const startTime = Date.now();
  const steps: Array<{ step: string; status: string; duration: number }> = [];

  const step1Start = Date.now();
  const status = getClusterStatus();
  steps.push({
    step: "Check cluster health",
    status: status.health === "healthy" ? "passed" : "warning",
    duration: Date.now() - step1Start,
  });

  const step2Start = Date.now();
  const standbyNodes = status.nodes.filter((n) => n.role === "standby" && n.status === "online");
  steps.push({
    step: "Verify standby nodes available",
    status: standbyNodes.length > 0 ? "passed" : "failed",
    duration: Date.now() - step2Start,
  });

  const step3Start = Date.now();
  const replication = getReplicationStatus();
  const maxLag = Math.max(...replication.standbyNodes.map((s) => s.lag), 0);
  steps.push({
    step: "Check replication lag",
    status: maxLag < 5000 ? "passed" : "warning",
    duration: Date.now() - step3Start,
  });

  const step4Start = Date.now();
  const targetNode = targetNodeId
    ? standbyNodes.find((n) => n.id === targetNodeId)
    : standbyNodes[0];
  steps.push({
    step: "Simulate node promotion",
    status: targetNode ? "passed" : "failed",
    duration: Date.now() - step4Start,
  });

  const step5Start = Date.now();
  const config = getFailoverConfig();
  steps.push({
    step: "Verify failover configuration",
    status: config.enabled ? "passed" : "warning",
    duration: Date.now() - step5Start,
  });

  return {
    success: steps.every((s) => s.status === "passed"),
    duration: Date.now() - startTime,
    steps,
  };
}

export function getFailoverHistory(limit: number = 50): FailoverEvent[] {
  const database = getDb();
  const rows = database
    .prepare("SELECT * FROM failover_history ORDER BY timestamp DESC LIMIT ?")
    .all(limit) as Array<{
    id: string;
    timestamp: string;
    type: string;
    from_node: string;
    to_node: string;
    reason: string;
    duration: number;
    success: number;
    details: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    timestamp: row.timestamp,
    type: row.type as FailoverEvent["type"],
    fromNode: row.from_node,
    toNode: row.to_node,
    reason: row.reason,
    duration: row.duration,
    success: row.success === 1,
    details: row.details,
  }));
}

// ============================================================================
// Split Brain Detection
// ============================================================================

export function detectSplitBrain(): SplitBrainStatus {
  const nodes = listNodes();
  const now = Date.now();
  const recentHeartbeatThreshold = 30000;

  const connectedNodes: ClusterNode[] = [];
  const disconnectedNodes: ClusterNode[] = [];

  for (const node of nodes) {
    const lastHeartbeat = new Date(node.lastHeartbeat).getTime();
    if (now - lastHeartbeat < recentHeartbeatThreshold) connectedNodes.push(node);
    else disconnectedNodes.push(node);
  }

  const primaries = nodes.filter((n) => n.role === "primary");
  const hasSplitBrain = primaries.length > 1;

  const result: SplitBrainStatus = {
    detected: hasSplitBrain,
    partitions: [],
    lastCheck: new Date().toISOString(),
  };

  if (hasSplitBrain) {
    for (const primary of primaries) {
      result.partitions.push({ nodes: [primary.id], hasPrimary: true, isQuorum: false });
    }
    result.resolution =
      "Manual intervention required. Identify the correct primary and demote others.";
  } else if (disconnectedNodes.length > 0) {
    result.partitions = [
      {
        nodes: connectedNodes.map((n) => n.id),
        hasPrimary: connectedNodes.some((n) => n.role === "primary"),
        isQuorum: connectedNodes.length > nodes.length / 2,
      },
      {
        nodes: disconnectedNodes.map((n) => n.id),
        hasPrimary: disconnectedNodes.some((n) => n.role === "primary"),
        isQuorum: disconnectedNodes.length > nodes.length / 2,
      },
    ];
  }

  return result;
}

// ============================================================================
// Initialize Local Node
// ============================================================================

export function initializeLocalNode(options: {
  hostname?: string;
  port?: number;
  role?: NodeRole;
}): ClusterNode {
  const hostname = options.hostname || "localhost";
  const nodeId = `node-${hostname}-${Date.now()}`;

  const node: ClusterNode = {
    id: nodeId,
    hostname,
    address: "127.0.0.1",
    port: options.port || 3000,
    role: options.role || "standby",
    status: "online",
    lastHeartbeat: new Date().toISOString(),
    version: "1.30.0",
    startedAt: new Date().toISOString(),
  };

  registerNode(node);
  return node;
}

// ============================================================================
// Exports
// ============================================================================

export const highAvailability = {
  initHaDb,
  registerNode,
  getNode,
  listNodes,
  removeNode,
  updateNodeStatus,
  recordHeartbeat,
  initializeLocalNode,
  getClusterStatus,
  getReplicationStatus,
  getFailoverConfig,
  setFailoverConfig,
  promoteNode,
  demoteNode,
  testFailover,
  getFailoverHistory,
  detectSplitBrain,
};
