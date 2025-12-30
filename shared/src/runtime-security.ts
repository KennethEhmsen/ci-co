/**
 * Container Runtime Security Module (v1.28.0)
 *
 * Provides container runtime security capabilities including:
 * - Runtime scanning of running containers
 * - Security profile generation (AppArmor, Seccomp)
 * - Runtime anomaly detection
 * - Container process monitoring
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID } from "crypto";
import Database from "better-sqlite3";

const execFileAsync = promisify(execFile);

// =============================================================================
// Types
// =============================================================================

export type RuntimeSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type AnomalyType =
  | "process_spawn"
  | "network_connection"
  | "file_access"
  | "capability_use"
  | "syscall"
  | "privilege_escalation"
  | "container_escape";

export type ProfileType = "apparmor" | "seccomp";

export interface ContainerInfo {
  id: string;
  name: string;
  image: string;
  imageId: string;
  status: string;
  created: string;
  ports: string[];
  labels: Record<string, string>;
  runtime: string;
}

export interface RuntimeVulnerability {
  id: string;
  containerId: string;
  containerName: string;
  vulnId: string;
  pkgName: string;
  installedVersion: string;
  fixedVersion?: string;
  severity: RuntimeSeverity;
  title: string;
  description: string;
  references: string[];
}

export interface RuntimeScanResult {
  scanId: string;
  scanDate: string;
  container: ContainerInfo;
  vulnerabilities: RuntimeVulnerability[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  riskScore: number;
}

export interface ProcessInfo {
  pid: number;
  ppid: number;
  user: string;
  command: string;
  args: string[];
  startTime: string;
}

export interface NetworkConnection {
  protocol: "tcp" | "udp";
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state: string;
}

export interface ContainerRuntimeState {
  containerId: string;
  containerName: string;
  timestamp: string;
  processes: ProcessInfo[];
  networkConnections: NetworkConnection[];
  openFiles: string[];
  capabilities: string[];
  seccompProfile?: string;
  apparmorProfile?: string;
}

export interface RuntimeAnomaly {
  id: string;
  containerId: string;
  containerName: string;
  type: AnomalyType;
  severity: RuntimeSeverity;
  timestamp: string;
  description: string;
  details: Record<string, unknown>;
  baseline?: string;
  actual?: string;
}

export interface AnomalyDetectionResult {
  containerId: string;
  containerName: string;
  scanDate: string;
  anomalies: RuntimeAnomaly[];
  riskLevel: "low" | "medium" | "high" | "critical";
  summary: {
    totalAnomalies: number;
    byType: Record<AnomalyType, number>;
    bySeverity: Record<RuntimeSeverity, number>;
  };
}

export interface SeccompProfile {
  defaultAction: "SCMP_ACT_ERRNO" | "SCMP_ACT_ALLOW" | "SCMP_ACT_LOG";
  architectures: string[];
  syscalls: {
    names: string[];
    action: "SCMP_ACT_ALLOW" | "SCMP_ACT_ERRNO" | "SCMP_ACT_LOG";
    args?: {
      index: number;
      value: number;
      op: string;
    }[];
  }[];
}

export interface AppArmorProfile {
  name: string;
  mode: "enforce" | "complain" | "unconfined";
  rules: {
    type: "file" | "network" | "capability" | "signal";
    access: string;
    path?: string;
    permission?: string;
  }[];
}

export interface SecurityProfile {
  containerId: string;
  containerName: string;
  generatedAt: string;
  profileType: ProfileType;
  seccompProfile?: SeccompProfile;
  apparmorProfile?: AppArmorProfile;
  recommendations: string[];
}

export interface ContainerBaseline {
  id: string;
  containerId: string;
  containerName: string;
  imageId: string;
  createdAt: string;
  processes: string[];
  networkPorts: number[];
  capabilities: string[];
  syscalls: string[];
  fileAccess: string[];
}

export interface RuntimeScanOptions {
  severity?: RuntimeSeverity[];
  includeBaseImage?: boolean;
  timeout?: number;
}

export interface ProfileGenerationOptions {
  profileType: ProfileType;
  mode?: "strict" | "permissive";
  learningPeriodSeconds?: number;
}

export interface AnomalyDetectionOptions {
  baselineId?: string;
  sensitivity?: "low" | "medium" | "high";
  types?: AnomalyType[];
}

// =============================================================================
// Database Management
// =============================================================================

let db: Database.Database | null = null;
let dbPath: string = ":memory:";

export interface RuntimeDbInitResult {
  success: boolean;
  path: string;
  created: boolean;
}

export function initRuntimeDatabase(path?: string): RuntimeDbInitResult {
  if (db) {
    return { success: true, path: dbPath, created: false };
  }

  dbPath = path || ":memory:";
  db = new Database(dbPath);

  db.exec(`
    CREATE TABLE IF NOT EXISTS container_baselines (
      id TEXT PRIMARY KEY,
      container_id TEXT NOT NULL,
      container_name TEXT NOT NULL,
      image_id TEXT NOT NULL,
      processes_json TEXT NOT NULL,
      network_ports_json TEXT NOT NULL,
      capabilities_json TEXT NOT NULL,
      syscalls_json TEXT NOT NULL,
      file_access_json TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_baselines_container
      ON container_baselines(container_id);

    CREATE TABLE IF NOT EXISTS runtime_anomalies (
      id TEXT PRIMARY KEY,
      container_id TEXT NOT NULL,
      container_name TEXT NOT NULL,
      anomaly_type TEXT NOT NULL,
      severity TEXT NOT NULL,
      description TEXT NOT NULL,
      details_json TEXT NOT NULL,
      baseline TEXT,
      actual TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_anomalies_container
      ON runtime_anomalies(container_id);
    CREATE INDEX IF NOT EXISTS idx_anomalies_type
      ON runtime_anomalies(anomaly_type);

    CREATE TABLE IF NOT EXISTS security_profiles (
      id TEXT PRIMARY KEY,
      container_id TEXT NOT NULL,
      container_name TEXT NOT NULL,
      profile_type TEXT NOT NULL,
      profile_json TEXT NOT NULL,
      recommendations_json TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_profiles_container
      ON security_profiles(container_id);

    CREATE TABLE IF NOT EXISTS runtime_audit (
      id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      target_id TEXT NOT NULL,
      actor TEXT,
      details_json TEXT NOT NULL,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  return { success: true, path: dbPath, created: true };
}

export function closeRuntimeDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

function getDb(): Database.Database {
  if (!db) {
    throw new Error("Runtime database not initialized. Call initRuntimeDatabase() first.");
  }
  return db;
}

// =============================================================================
// Docker Utilities
// =============================================================================

async function getRunningContainers(): Promise<ContainerInfo[]> {
  try {
    const { stdout } = await execFileAsync("docker", ["ps", "--format", "{{json .}}"], {
      maxBuffer: 10 * 1024 * 1024,
    });

    const containers: ContainerInfo[] = [];
    const lines = stdout.trim().split("\n").filter(Boolean);

    for (const line of lines) {
      try {
        const data = JSON.parse(line);
        containers.push({
          id: data.ID,
          name: data.Names,
          image: data.Image,
          imageId: data.ID,
          status: data.Status,
          created: data.CreatedAt,
          ports: data.Ports ? data.Ports.split(",").map((p: string) => p.trim()) : [],
          labels: {},
          runtime: "docker",
        });
      } catch {
        // Skip malformed lines
      }
    }

    return containers;
  } catch (error) {
    throw new Error(
      `Failed to list containers: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

async function getContainerInfo(containerId: string): Promise<ContainerInfo> {
  try {
    const { stdout } = await execFileAsync(
      "docker",
      ["inspect", "--format", "{{json .}}", containerId],
      { maxBuffer: 10 * 1024 * 1024 }
    );

    const data = JSON.parse(stdout);
    return {
      id: data.Id,
      name: data.Name.replace(/^\//, ""),
      image: data.Config.Image,
      imageId: data.Image,
      status: data.State.Status,
      created: data.Created,
      ports: Object.keys(data.NetworkSettings.Ports || {}),
      labels: data.Config.Labels || {},
      runtime: "docker",
    };
  } catch (error) {
    throw new Error(
      `Failed to get container info: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

async function getContainerProcesses(containerId: string): Promise<ProcessInfo[]> {
  try {
    const { stdout } = await execFileAsync(
      "docker",
      ["top", containerId, "-eo", "pid,ppid,user,comm,args"],
      { maxBuffer: 10 * 1024 * 1024 }
    );

    const lines = stdout.trim().split("\n");
    const processes: ProcessInfo[] = [];

    // Skip header line
    for (let i = 1; i < lines.length; i++) {
      const parts = lines[i].trim().split(/\s+/);
      if (parts.length >= 4) {
        processes.push({
          pid: parseInt(parts[0], 10),
          ppid: parseInt(parts[1], 10),
          user: parts[2],
          command: parts[3],
          args: parts.slice(4),
          startTime: new Date().toISOString(),
        });
      }
    }

    return processes;
  } catch {
    return [];
  }
}

// =============================================================================
// Core Functions
// =============================================================================

/**
 * Check if Docker is available
 */
export async function isDockerAvailable(): Promise<boolean> {
  try {
    await execFileAsync("docker", ["version"], { timeout: 10000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * List all running containers
 */
export async function listRunningContainers(): Promise<ContainerInfo[]> {
  return getRunningContainers();
}

/**
 * Scan a running container for vulnerabilities
 */
export async function scanRunningContainer(
  containerId: string,
  options?: RuntimeScanOptions
): Promise<RuntimeScanResult> {
  const container = await getContainerInfo(containerId);

  // Use Trivy to scan the running container
  const args = [
    "run",
    "--rm",
    "-v",
    "/var/run/docker.sock:/var/run/docker.sock",
    "aquasec/trivy:latest",
    "image",
    "--format",
    "json",
  ];

  if (options?.severity) {
    args.push("--severity", options.severity.join(","));
  } else {
    args.push("--severity", "HIGH,CRITICAL");
  }

  args.push(container.image);

  try {
    const { stdout } = await execFileAsync("docker", args, {
      maxBuffer: 50 * 1024 * 1024,
      timeout: options?.timeout || 300000,
    });

    const trivyResult = JSON.parse(stdout);
    const vulnerabilities: RuntimeVulnerability[] = [];

    for (const result of trivyResult.Results || []) {
      for (const vuln of result.Vulnerabilities || []) {
        vulnerabilities.push({
          id: randomUUID(),
          containerId: container.id,
          containerName: container.name,
          vulnId: vuln.VulnerabilityID,
          pkgName: vuln.PkgName,
          installedVersion: vuln.InstalledVersion,
          fixedVersion: vuln.FixedVersion,
          severity: vuln.Severity as RuntimeSeverity,
          title: vuln.Title || vuln.VulnerabilityID,
          description: vuln.Description || "",
          references: vuln.References || [],
        });
      }
    }

    const summary = {
      critical: vulnerabilities.filter((v) => v.severity === "CRITICAL").length,
      high: vulnerabilities.filter((v) => v.severity === "HIGH").length,
      medium: vulnerabilities.filter((v) => v.severity === "MEDIUM").length,
      low: vulnerabilities.filter((v) => v.severity === "LOW").length,
      total: vulnerabilities.length,
    };

    // Calculate risk score
    const riskScore = Math.min(
      100,
      summary.critical * 25 + summary.high * 10 + summary.medium * 5 + summary.low * 2
    );

    return {
      scanId: randomUUID(),
      scanDate: new Date().toISOString(),
      container,
      vulnerabilities,
      summary,
      riskScore,
    };
  } catch (error) {
    throw new Error(
      `Failed to scan container: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Get the current runtime state of a container
 */
export async function getContainerRuntimeState(
  containerId: string
): Promise<ContainerRuntimeState> {
  const container = await getContainerInfo(containerId);
  const processes = await getContainerProcesses(containerId);

  // Get container capabilities
  let capabilities: string[] = [];
  try {
    const { stdout } = await execFileAsync("docker", [
      "inspect",
      "--format",
      "{{json .HostConfig.CapAdd}}",
      containerId,
    ]);
    const caps = JSON.parse(stdout);
    if (Array.isArray(caps)) {
      capabilities = caps;
    }
  } catch {
    // Ignore errors
  }

  // Get security profiles
  let seccompProfile: string | undefined;
  let apparmorProfile: string | undefined;
  try {
    const { stdout } = await execFileAsync("docker", [
      "inspect",
      "--format",
      "{{json .HostConfig.SecurityOpt}}",
      containerId,
    ]);
    const secOpts = JSON.parse(stdout) || [];
    for (const opt of secOpts) {
      if (typeof opt === "string") {
        if (opt.startsWith("seccomp=")) {
          seccompProfile = opt.replace("seccomp=", "");
        }
        if (opt.startsWith("apparmor=")) {
          apparmorProfile = opt.replace("apparmor=", "");
        }
      }
    }
  } catch {
    // Ignore errors
  }

  return {
    containerId: container.id,
    containerName: container.name,
    timestamp: new Date().toISOString(),
    processes,
    networkConnections: [],
    openFiles: [],
    capabilities,
    seccompProfile,
    apparmorProfile,
  };
}

/**
 * Create a baseline for a container's normal behavior
 */
export async function createContainerBaseline(containerId: string): Promise<ContainerBaseline> {
  const database = getDb();
  const container = await getContainerInfo(containerId);
  const state = await getContainerRuntimeState(containerId);

  const baseline: ContainerBaseline = {
    id: randomUUID(),
    containerId: container.id,
    containerName: container.name,
    imageId: container.imageId,
    createdAt: new Date().toISOString(),
    processes: state.processes.map((p) => p.command),
    networkPorts: [],
    capabilities: state.capabilities,
    syscalls: [],
    fileAccess: [],
  };

  database
    .prepare(
      `
    INSERT INTO container_baselines (
      id, container_id, container_name, image_id,
      processes_json, network_ports_json, capabilities_json,
      syscalls_json, file_access_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      baseline.id,
      baseline.containerId,
      baseline.containerName,
      baseline.imageId,
      JSON.stringify(baseline.processes),
      JSON.stringify(baseline.networkPorts),
      JSON.stringify(baseline.capabilities),
      JSON.stringify(baseline.syscalls),
      JSON.stringify(baseline.fileAccess)
    );

  return baseline;
}

/**
 * Get a stored baseline for a container
 */
export function getContainerBaseline(containerId: string): ContainerBaseline | null {
  const database = getDb();
  const row = database
    .prepare(
      `
    SELECT * FROM container_baselines
    WHERE container_id = ?
    ORDER BY created_at DESC
    LIMIT 1
  `
    )
    .get(containerId) as
    | {
        id: string;
        container_id: string;
        container_name: string;
        image_id: string;
        processes_json: string;
        network_ports_json: string;
        capabilities_json: string;
        syscalls_json: string;
        file_access_json: string;
        created_at: string;
      }
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    containerId: row.container_id,
    containerName: row.container_name,
    imageId: row.image_id,
    createdAt: row.created_at,
    processes: JSON.parse(row.processes_json),
    networkPorts: JSON.parse(row.network_ports_json),
    capabilities: JSON.parse(row.capabilities_json),
    syscalls: JSON.parse(row.syscalls_json),
    fileAccess: JSON.parse(row.file_access_json),
  };
}

/**
 * Detect anomalies in a running container
 */
export async function detectAnomalies(
  containerId: string,
  options?: AnomalyDetectionOptions
): Promise<AnomalyDetectionResult> {
  const container = await getContainerInfo(containerId);
  const currentState = await getContainerRuntimeState(containerId);
  const anomalies: RuntimeAnomaly[] = [];

  // Get baseline if available
  let baseline: ContainerBaseline | null = null;
  if (options?.baselineId) {
    const database = getDb();
    const row = database
      .prepare(`SELECT * FROM container_baselines WHERE id = ?`)
      .get(options.baselineId);
    if (row) {
      baseline = {
        id: (row as { id: string }).id,
        containerId: (row as { container_id: string }).container_id,
        containerName: (row as { container_name: string }).container_name,
        imageId: (row as { image_id: string }).image_id,
        createdAt: (row as { created_at: string }).created_at,
        processes: JSON.parse((row as { processes_json: string }).processes_json),
        networkPorts: JSON.parse((row as { network_ports_json: string }).network_ports_json),
        capabilities: JSON.parse((row as { capabilities_json: string }).capabilities_json),
        syscalls: JSON.parse((row as { syscalls_json: string }).syscalls_json),
        fileAccess: JSON.parse((row as { file_access_json: string }).file_access_json),
      };
    }
  } else {
    baseline = getContainerBaseline(containerId);
  }

  // Detect process anomalies
  if (baseline) {
    const currentProcesses = currentState.processes.map((p) => p.command);
    const newProcesses = currentProcesses.filter((p) => !baseline!.processes.includes(p));

    for (const process of newProcesses) {
      const severity = getSeverityForProcess(process);
      anomalies.push({
        id: randomUUID(),
        containerId: container.id,
        containerName: container.name,
        type: "process_spawn",
        severity,
        timestamp: new Date().toISOString(),
        description: `New process detected: ${process}`,
        details: { process },
        baseline: baseline.processes.join(", "),
        actual: currentProcesses.join(", "),
      });
    }

    // Detect capability changes
    const newCapabilities = currentState.capabilities.filter(
      (c) => !baseline!.capabilities.includes(c)
    );

    for (const cap of newCapabilities) {
      anomalies.push({
        id: randomUUID(),
        containerId: container.id,
        containerName: container.name,
        type: "capability_use",
        severity: getCapabilitySeverity(cap),
        timestamp: new Date().toISOString(),
        description: `New capability detected: ${cap}`,
        details: { capability: cap },
        baseline: baseline.capabilities.join(", "),
        actual: currentState.capabilities.join(", "),
      });
    }
  }

  // Check for suspicious processes regardless of baseline
  for (const process of currentState.processes) {
    if (isSuspiciousProcess(process.command)) {
      anomalies.push({
        id: randomUUID(),
        containerId: container.id,
        containerName: container.name,
        type: "process_spawn",
        severity: "HIGH",
        timestamp: new Date().toISOString(),
        description: `Suspicious process detected: ${process.command}`,
        details: { process: process.command, args: process.args },
      });
    }
  }

  // Check for privilege escalation indicators
  const rootProcesses = currentState.processes.filter((p) => p.user === "root");
  if (rootProcesses.length > 0 && container.labels["run-as-nonroot"] === "true") {
    anomalies.push({
      id: randomUUID(),
      containerId: container.id,
      containerName: container.name,
      type: "privilege_escalation",
      severity: "CRITICAL",
      timestamp: new Date().toISOString(),
      description: "Root processes detected in container marked as non-root",
      details: { rootProcesses: rootProcesses.map((p) => p.command) },
    });
  }

  // Calculate risk level
  const criticalCount = anomalies.filter((a) => a.severity === "CRITICAL").length;
  const highCount = anomalies.filter((a) => a.severity === "HIGH").length;

  let riskLevel: "low" | "medium" | "high" | "critical" = "low";
  if (criticalCount > 0) {
    riskLevel = "critical";
  } else if (highCount > 2) {
    riskLevel = "high";
  } else if (highCount > 0 || anomalies.length > 5) {
    riskLevel = "medium";
  }

  // Build summary
  const byType: Record<AnomalyType, number> = {
    process_spawn: 0,
    network_connection: 0,
    file_access: 0,
    capability_use: 0,
    syscall: 0,
    privilege_escalation: 0,
    container_escape: 0,
  };
  const bySeverity: Record<RuntimeSeverity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };

  for (const anomaly of anomalies) {
    byType[anomaly.type]++;
    bySeverity[anomaly.severity]++;
  }

  // Store anomalies in database
  const database = getDb();
  for (const anomaly of anomalies) {
    database
      .prepare(
        `
      INSERT INTO runtime_anomalies (
        id, container_id, container_name, anomaly_type,
        severity, description, details_json, baseline, actual
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
      )
      .run(
        anomaly.id,
        anomaly.containerId,
        anomaly.containerName,
        anomaly.type,
        anomaly.severity,
        anomaly.description,
        JSON.stringify(anomaly.details),
        anomaly.baseline || null,
        anomaly.actual || null
      );
  }

  return {
    containerId: container.id,
    containerName: container.name,
    scanDate: new Date().toISOString(),
    anomalies,
    riskLevel,
    summary: {
      totalAnomalies: anomalies.length,
      byType,
      bySeverity,
    },
  };
}

/**
 * Generate a security profile for a container
 */
export async function generateSecurityProfile(
  containerId: string,
  options: ProfileGenerationOptions
): Promise<SecurityProfile> {
  const container = await getContainerInfo(containerId);
  const state = await getContainerRuntimeState(containerId);
  const recommendations: string[] = [];

  let seccompProfile: SeccompProfile | undefined;
  let apparmorProfile: AppArmorProfile | undefined;

  if (options.profileType === "seccomp") {
    // Generate seccomp profile based on observed syscalls
    const allowedSyscalls = getDefaultAllowedSyscalls();

    seccompProfile = {
      defaultAction: options.mode === "strict" ? "SCMP_ACT_ERRNO" : "SCMP_ACT_LOG",
      architectures: ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"],
      syscalls: [
        {
          names: allowedSyscalls,
          action: "SCMP_ACT_ALLOW",
        },
      ],
    };

    recommendations.push("Review and test the seccomp profile in complain mode before enforcing");
    recommendations.push("Monitor for blocked syscalls and adjust the profile as needed");
  }

  if (options.profileType === "apparmor") {
    // Generate AppArmor profile
    apparmorProfile = {
      name: `container-${container.name}`,
      mode: options.mode === "strict" ? "enforce" : "complain",
      rules: [
        { type: "file", access: "r", path: "/lib/**" },
        { type: "file", access: "r", path: "/usr/lib/**" },
        { type: "file", access: "r", path: "/etc/ld.so.cache" },
        { type: "network", access: "inet tcp", permission: "create,accept,connect" },
        { type: "capability", access: "net_bind_service", permission: "allow" },
      ],
    };

    // Add rules based on current state
    for (const cap of state.capabilities) {
      apparmorProfile.rules.push({
        type: "capability",
        access: cap.toLowerCase(),
        permission: "allow",
      });
    }

    recommendations.push("Review and test the AppArmor profile in complain mode before enforcing");
    recommendations.push("Use aa-logprof to refine the profile based on actual usage");
  }

  const profile: SecurityProfile = {
    containerId: container.id,
    containerName: container.name,
    generatedAt: new Date().toISOString(),
    profileType: options.profileType,
    seccompProfile,
    apparmorProfile,
    recommendations,
  };

  // Store profile
  const database = getDb();
  database
    .prepare(
      `
    INSERT INTO security_profiles (
      id, container_id, container_name, profile_type,
      profile_json, recommendations_json
    ) VALUES (?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      randomUUID(),
      profile.containerId,
      profile.containerName,
      profile.profileType,
      JSON.stringify(profile.seccompProfile || profile.apparmorProfile),
      JSON.stringify(profile.recommendations)
    );

  return profile;
}

/**
 * Get stored anomalies for a container
 */
export function getStoredAnomalies(
  containerId: string,
  options?: { limit?: number; type?: AnomalyType; severity?: RuntimeSeverity }
): RuntimeAnomaly[] {
  const database = getDb();

  let sql = "SELECT * FROM runtime_anomalies WHERE container_id = ?";
  const params: (string | number)[] = [containerId];

  if (options?.type) {
    sql += " AND anomaly_type = ?";
    params.push(options.type);
  }
  if (options?.severity) {
    sql += " AND severity = ?";
    params.push(options.severity);
  }

  sql += " ORDER BY created_at DESC";

  if (options?.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }

  const rows = database.prepare(sql).all(...params) as Array<{
    id: string;
    container_id: string;
    container_name: string;
    anomaly_type: string;
    severity: string;
    description: string;
    details_json: string;
    baseline: string | null;
    actual: string | null;
    created_at: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    containerId: row.container_id,
    containerName: row.container_name,
    type: row.anomaly_type as AnomalyType,
    severity: row.severity as RuntimeSeverity,
    timestamp: row.created_at,
    description: row.description,
    details: JSON.parse(row.details_json),
    baseline: row.baseline || undefined,
    actual: row.actual || undefined,
  }));
}

/**
 * Get runtime audit log
 */
export function getRuntimeAuditLog(options?: {
  containerId?: string;
  eventType?: string;
  limit?: number;
}): Array<{
  id: string;
  eventType: string;
  targetId: string;
  actor?: string;
  details: Record<string, unknown>;
  timestamp: string;
}> {
  const database = getDb();

  let sql = "SELECT * FROM runtime_audit WHERE 1=1";
  const params: (string | number)[] = [];

  if (options?.containerId) {
    sql += " AND target_id = ?";
    params.push(options.containerId);
  }
  if (options?.eventType) {
    sql += " AND event_type = ?";
    params.push(options.eventType);
  }

  sql += " ORDER BY timestamp DESC";

  if (options?.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }

  const rows = database.prepare(sql).all(...params) as Array<{
    id: string;
    event_type: string;
    target_id: string;
    actor: string | null;
    details_json: string;
    timestamp: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    eventType: row.event_type,
    targetId: row.target_id,
    actor: row.actor || undefined,
    details: JSON.parse(row.details_json),
    timestamp: row.timestamp,
  }));
}

// =============================================================================
// Helper Functions
// =============================================================================

function getSeverityForProcess(process: string): RuntimeSeverity {
  const criticalProcesses = ["nc", "ncat", "netcat", "socat", "nmap", "wget", "curl"];
  const highProcesses = ["sh", "bash", "zsh", "python", "perl", "ruby", "node"];

  const cmd = process.toLowerCase();

  if (criticalProcesses.some((p) => cmd.includes(p))) {
    return "CRITICAL";
  }
  if (highProcesses.some((p) => cmd === p)) {
    return "HIGH";
  }
  return "MEDIUM";
}

function getCapabilitySeverity(capability: string): RuntimeSeverity {
  const criticalCaps = ["SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE"];
  const highCaps = ["NET_ADMIN", "NET_RAW", "SYS_RAWIO", "MKNOD"];

  if (criticalCaps.includes(capability)) {
    return "CRITICAL";
  }
  if (highCaps.includes(capability)) {
    return "HIGH";
  }
  return "MEDIUM";
}

function isSuspiciousProcess(command: string): boolean {
  const suspiciousPatterns = [
    /^nc$/i,
    /^ncat$/i,
    /^netcat$/i,
    /^nmap$/i,
    /^socat$/i,
    /reverse.?shell/i,
    /meterpreter/i,
    /cryptominer/i,
    /xmrig/i,
  ];

  return suspiciousPatterns.some((pattern) => pattern.test(command));
}

function getDefaultAllowedSyscalls(): string[] {
  return [
    "read",
    "write",
    "open",
    "close",
    "stat",
    "fstat",
    "lstat",
    "poll",
    "lseek",
    "mmap",
    "mprotect",
    "munmap",
    "brk",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "ioctl",
    "pread64",
    "pwrite64",
    "readv",
    "writev",
    "access",
    "pipe",
    "select",
    "sched_yield",
    "mremap",
    "msync",
    "mincore",
    "madvise",
    "dup",
    "dup2",
    "pause",
    "nanosleep",
    "getitimer",
    "alarm",
    "setitimer",
    "getpid",
    "sendfile",
    "socket",
    "connect",
    "accept",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "shutdown",
    "bind",
    "listen",
    "getsockname",
    "getpeername",
    "socketpair",
    "setsockopt",
    "getsockopt",
    "clone",
    "fork",
    "vfork",
    "exit",
    "wait4",
    "uname",
    "fcntl",
    "flock",
    "fsync",
    "fdatasync",
    "truncate",
    "ftruncate",
    "getdents",
    "getcwd",
    "chdir",
    "fchdir",
    "rename",
    "mkdir",
    "rmdir",
    "creat",
    "link",
    "unlink",
    "symlink",
    "readlink",
    "chmod",
    "fchmod",
    "chown",
    "fchown",
    "lchown",
    "umask",
    "gettimeofday",
    "getrlimit",
    "getrusage",
    "sysinfo",
    "times",
    "getuid",
    "getgid",
    "geteuid",
    "getegid",
    "setpgid",
    "getppid",
    "getpgrp",
    "setsid",
    "getgroups",
    "setgroups",
    "getpgid",
    "getsid",
    "capget",
    "rt_sigpending",
    "rt_sigtimedwait",
    "rt_sigsuspend",
    "sigaltstack",
    "utime",
    "statfs",
    "fstatfs",
    "getpriority",
    "setpriority",
    "sched_setparam",
    "sched_getparam",
    "sched_setscheduler",
    "sched_getscheduler",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "sched_rr_get_interval",
    "mlock",
    "munlock",
    "mlockall",
    "munlockall",
    "prctl",
    "arch_prctl",
    "setrlimit",
    "sync",
    "gettid",
    "readahead",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "getxattr",
    "lgetxattr",
    "fgetxattr",
    "listxattr",
    "llistxattr",
    "flistxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "time",
    "futex",
    "sched_setaffinity",
    "sched_getaffinity",
    "set_thread_area",
    "get_thread_area",
    "epoll_create",
    "epoll_ctl",
    "epoll_wait",
    "getdents64",
    "set_tid_address",
    "restart_syscall",
    "fadvise64",
    "timer_create",
    "timer_settime",
    "timer_gettime",
    "timer_getoverrun",
    "timer_delete",
    "clock_settime",
    "clock_gettime",
    "clock_getres",
    "clock_nanosleep",
    "exit_group",
    "epoll_pwait",
    "utimensat",
    "signalfd",
    "timerfd_create",
    "eventfd",
    "fallocate",
    "timerfd_settime",
    "timerfd_gettime",
    "accept4",
    "signalfd4",
    "eventfd2",
    "epoll_create1",
    "dup3",
    "pipe2",
    "preadv",
    "pwritev",
    "prlimit64",
    "syncfs",
    "getrandom",
  ];
}
