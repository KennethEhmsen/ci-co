/**
 * Team Management Module
 * Provides SQLite storage for organizations, teams, memberships, and audit logging.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import Database from "better-sqlite3";
import type {
  Organization,
  OrganizationSettings,
  OrganizationWithStats,
  Team,
  TeamSettings,
  TeamWithStats,
  TeamMember,
  TeamMemberRole,
  TeamMembershipDetails,
  TeamEventType,
  TeamAuditEvent,
  TeamDbInitResult,
  TeamStats,
  CreateOrganizationOptions,
  CreateTeamOptions,
  AddTeamMemberOptions,
  ListTeamsOptions,
  ListTeamMembersOptions,
} from "./types.js";

let db: Database.Database | null = null;

function getDefaultDbPath(): string {
  const dir = process.env.TEAM_DB_PATH
    ? path.dirname(process.env.TEAM_DB_PATH)
    : path.join(os.homedir(), ".cicd", "team");
  return process.env.TEAM_DB_PATH || path.join(dir, "team.db");
}

function createSchema(database: Database.Database): void {
  database.exec(`
    CREATE TABLE IF NOT EXISTS organizations (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, display_name TEXT, description TEXT, owner_id TEXT NOT NULL, settings_json TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS teams (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, name TEXT NOT NULL, display_name TEXT, description TEXT, visibility TEXT DEFAULT 'private', settings_json TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE, UNIQUE(organization_id, name));
    CREATE TABLE IF NOT EXISTS team_members (user_id TEXT NOT NULL, team_id TEXT NOT NULL, role TEXT DEFAULT 'member', joined_at TEXT DEFAULT CURRENT_TIMESTAMP, added_by TEXT, expires_at TEXT, PRIMARY KEY (user_id, team_id), FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS team_audit (id TEXT PRIMARY KEY, event_type TEXT NOT NULL, actor_id TEXT, organization_id TEXT, team_id TEXT, target_user_id TEXT, status TEXT NOT NULL, details_json TEXT, timestamp TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE INDEX IF NOT EXISTS idx_teams_org ON teams(organization_id);
    CREATE INDEX IF NOT EXISTS idx_team_members_team ON team_members(team_id);
    CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);
    CREATE INDEX IF NOT EXISTS idx_team_audit_org ON team_audit(organization_id);
    CREATE INDEX IF NOT EXISTS idx_team_audit_team ON team_audit(team_id);
    CREATE INDEX IF NOT EXISTS idx_team_audit_timestamp ON team_audit(timestamp);
  `);
}

export function initTeamDatabase(customPath?: string): TeamDbInitResult {
  if (db) return { success: true, path: getDefaultDbPath(), created: false };
  const dbPath = customPath || getDefaultDbPath();
  try {
    const dbDir = path.dirname(dbPath);
    if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });
    const isNew = !fs.existsSync(dbPath);
    db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    db.pragma("foreign_keys = ON");
    createSchema(db);
    return { success: true, path: dbPath, created: isNew };
  } catch (error) {
    return {
      success: false,
      path: dbPath,
      created: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export function closeTeamDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}
export function isTeamDbInitialized(): boolean {
  return db !== null;
}
function getDb(): Database.Database {
  if (!db) throw new Error("Team database not initialized");
  return db;
}

// Organization Management
export function createOrganization(options: CreateOrganizationOptions): Organization {
  const database = getDb();
  const now = new Date().toISOString();
  const id = crypto.randomUUID();
  database
    .prepare(
      "INSERT INTO organizations (id, name, display_name, description, owner_id, settings_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .run(
      id,
      options.name,
      options.displayName || null,
      options.description || null,
      options.ownerId,
      options.settings ? JSON.stringify(options.settings) : null,
      now,
      now
    );
  logTeamAudit({
    eventType: "ORG_CREATED",
    actorId: options.ownerId,
    organizationId: id,
    status: "SUCCESS",
    details: { name: options.name },
  });
  return {
    id,
    name: options.name,
    displayName: options.displayName,
    description: options.description,
    ownerId: options.ownerId,
    settings: options.settings,
    createdAt: now,
    updatedAt: now,
  };
}

export function getOrganization(orgId: string): Organization | null {
  const row = getDb().prepare("SELECT * FROM organizations WHERE id = ?").get(orgId) as
    | Record<string, unknown>
    | undefined;
  return row ? rowToOrganization(row) : null;
}

export function getOrganizationByName(name: string): Organization | null {
  const row = getDb().prepare("SELECT * FROM organizations WHERE name = ?").get(name) as
    | Record<string, unknown>
    | undefined;
  return row ? rowToOrganization(row) : null;
}

export function listOrganizations(options?: {
  ownerId?: string;
  includeStats?: boolean;
  limit?: number;
  offset?: number;
}): Organization[] | OrganizationWithStats[] {
  const database = getDb();
  let sql = "SELECT * FROM organizations";
  const params: (string | number)[] = [];
  if (options?.ownerId) {
    sql += " WHERE owner_id = ?";
    params.push(options.ownerId);
  }
  sql += " ORDER BY name";
  if (options?.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }
  if (options?.offset) {
    sql += " OFFSET ?";
    params.push(options.offset);
  }
  const rows = database.prepare(sql).all(...params) as Array<Record<string, unknown>>;
  const orgs = rows.map(rowToOrganization);
  if (!options?.includeStats) return orgs;
  return orgs.map((org) => {
    const teamCount = (
      database
        .prepare("SELECT COUNT(*) as count FROM teams WHERE organization_id = ?")
        .get(org.id) as { count: number }
    ).count;
    const totalMembers = (
      database
        .prepare(
          "SELECT COUNT(DISTINCT tm.user_id) as count FROM team_members tm JOIN teams t ON tm.team_id = t.id WHERE t.organization_id = ?"
        )
        .get(org.id) as { count: number }
    ).count;
    return { ...org, teamCount, totalMembers };
  });
}

export function updateOrganization(
  orgId: string,
  updates: { displayName?: string; description?: string; settings?: OrganizationSettings },
  actorId?: string
): Organization | null {
  const org = getOrganization(orgId);
  if (!org) return null;
  const now = new Date().toISOString();
  const newDisplayName = updates.displayName ?? org.displayName;
  const newDescription = updates.description ?? org.description;
  const newSettings = updates.settings ?? org.settings;
  getDb()
    .prepare(
      "UPDATE organizations SET display_name = ?, description = ?, settings_json = ?, updated_at = ? WHERE id = ?"
    )
    .run(
      newDisplayName || null,
      newDescription || null,
      newSettings ? JSON.stringify(newSettings) : null,
      now,
      orgId
    );
  logTeamAudit({
    eventType: "ORG_UPDATED",
    actorId,
    organizationId: orgId,
    status: "SUCCESS",
    details: updates,
  });
  return {
    ...org,
    displayName: newDisplayName,
    description: newDescription,
    settings: newSettings,
    updatedAt: now,
  };
}

export function deleteOrganization(orgId: string, actorId?: string): boolean {
  const org = getOrganization(orgId);
  if (!org) return false;
  const result = getDb().prepare("DELETE FROM organizations WHERE id = ?").run(orgId);
  if (result.changes > 0) {
    logTeamAudit({
      eventType: "ORG_DELETED",
      actorId,
      organizationId: orgId,
      status: "SUCCESS",
      details: { name: org.name },
    });
    return true;
  }
  return false;
}

function rowToOrganization(row: Record<string, unknown>): Organization {
  return {
    id: row.id as string,
    name: row.name as string,
    displayName: row.display_name as string | undefined,
    description: row.description as string | undefined,
    ownerId: row.owner_id as string,
    settings: row.settings_json ? JSON.parse(row.settings_json as string) : undefined,
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
  };
}

// Team Management
export function createTeam(options: CreateTeamOptions): Team {
  const database = getDb();
  const now = new Date().toISOString();
  const id = crypto.randomUUID();
  const org = getOrganization(options.organizationId);
  if (!org) throw new Error("Organization not found: " + options.organizationId);
  if (org.settings?.maxTeams) {
    const count = (
      database
        .prepare("SELECT COUNT(*) as count FROM teams WHERE organization_id = ?")
        .get(options.organizationId) as { count: number }
    ).count;
    if (count >= org.settings.maxTeams) throw new Error("Maximum teams limit reached");
  }
  const visibility = options.visibility || org.settings?.defaultTeamVisibility || "private";
  database
    .prepare(
      "INSERT INTO teams (id, organization_id, name, display_name, description, visibility, settings_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .run(
      id,
      options.organizationId,
      options.name,
      options.displayName || null,
      options.description || null,
      visibility,
      options.settings ? JSON.stringify(options.settings) : null,
      now,
      now
    );
  logTeamAudit({
    eventType: "TEAM_CREATED",
    actorId: options.createdBy,
    organizationId: options.organizationId,
    teamId: id,
    status: "SUCCESS",
    details: { name: options.name, visibility },
  });
  return {
    id,
    organizationId: options.organizationId,
    name: options.name,
    displayName: options.displayName,
    description: options.description,
    visibility,
    settings: options.settings,
    createdAt: now,
    updatedAt: now,
  };
}

export function getTeam(teamId: string): Team | null {
  const row = getDb().prepare("SELECT * FROM teams WHERE id = ?").get(teamId) as
    | Record<string, unknown>
    | undefined;
  return row ? rowToTeam(row) : null;
}

export function getTeamByName(organizationId: string, name: string): Team | null {
  const row = getDb()
    .prepare("SELECT * FROM teams WHERE organization_id = ? AND name = ?")
    .get(organizationId, name) as Record<string, unknown> | undefined;
  return row ? rowToTeam(row) : null;
}

export function listTeams(options?: ListTeamsOptions): Team[] | TeamWithStats[] {
  const database = getDb();
  let sql = "SELECT t.* FROM teams t";
  const params: (string | number)[] = [];
  const conditions: string[] = [];
  if (options?.userId) {
    sql = "SELECT DISTINCT t.* FROM teams t JOIN team_members tm ON t.id = tm.team_id";
    conditions.push("tm.user_id = ?");
    params.push(options.userId);
  }
  if (options?.organizationId) {
    conditions.push("t.organization_id = ?");
    params.push(options.organizationId);
  }
  if (options?.visibility) {
    conditions.push("t.visibility = ?");
    params.push(options.visibility);
  }
  if (options?.search) {
    conditions.push("(t.name LIKE ? OR t.display_name LIKE ?)");
    params.push(`%${options.search}%`, `%${options.search}%`);
  }
  if (conditions.length > 0) sql += " WHERE " + conditions.join(" AND ");
  sql += " ORDER BY t.name";
  if (options?.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }
  if (options?.offset) {
    sql += " OFFSET ?";
    params.push(options.offset);
  }
  const rows = database.prepare(sql).all(...params) as Array<Record<string, unknown>>;
  const teams = rows.map(rowToTeam);
  if (!options?.includeStats) return teams;
  return teams.map((team) => {
    const memberCount = (
      database
        .prepare("SELECT COUNT(*) as count FROM team_members WHERE team_id = ?")
        .get(team.id) as { count: number }
    ).count;
    const orgRow = database
      .prepare("SELECT name FROM organizations WHERE id = ?")
      .get(team.organizationId) as { name: string } | undefined;
    return { ...team, memberCount, organizationName: orgRow?.name };
  });
}

export function updateTeam(
  teamId: string,
  updates: {
    displayName?: string;
    description?: string;
    visibility?: "public" | "private";
    settings?: TeamSettings;
  },
  actorId?: string
): Team | null {
  const team = getTeam(teamId);
  if (!team) return null;
  const now = new Date().toISOString();
  const newDisplayName = updates.displayName ?? team.displayName;
  const newDescription = updates.description ?? team.description;
  const newVisibility = updates.visibility ?? team.visibility;
  const newSettings = updates.settings ?? team.settings;
  getDb()
    .prepare(
      "UPDATE teams SET display_name = ?, description = ?, visibility = ?, settings_json = ?, updated_at = ? WHERE id = ?"
    )
    .run(
      newDisplayName || null,
      newDescription || null,
      newVisibility,
      newSettings ? JSON.stringify(newSettings) : null,
      now,
      teamId
    );
  logTeamAudit({
    eventType: "TEAM_UPDATED",
    actorId,
    organizationId: team.organizationId,
    teamId,
    status: "SUCCESS",
    details: updates,
  });
  return {
    ...team,
    displayName: newDisplayName,
    description: newDescription,
    visibility: newVisibility,
    settings: newSettings,
    updatedAt: now,
  };
}

export function deleteTeam(teamId: string, actorId?: string): boolean {
  const team = getTeam(teamId);
  if (!team) return false;
  const result = getDb().prepare("DELETE FROM teams WHERE id = ?").run(teamId);
  if (result.changes > 0) {
    logTeamAudit({
      eventType: "TEAM_DELETED",
      actorId,
      organizationId: team.organizationId,
      teamId,
      status: "SUCCESS",
      details: { name: team.name },
    });
    return true;
  }
  return false;
}

function rowToTeam(row: Record<string, unknown>): Team {
  return {
    id: row.id as string,
    organizationId: row.organization_id as string,
    name: row.name as string,
    displayName: row.display_name as string | undefined,
    description: row.description as string | undefined,
    visibility: row.visibility as "public" | "private",
    settings: row.settings_json ? JSON.parse(row.settings_json as string) : undefined,
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
  };
}

// Team Member Management
export function addTeamMember(options: AddTeamMemberOptions): TeamMember {
  const database = getDb();
  const now = new Date().toISOString();
  const team = getTeam(options.teamId);
  if (!team) throw new Error("Team not found: " + options.teamId);
  const org = getOrganization(team.organizationId);
  if (org?.settings?.maxMembersPerTeam) {
    const count = (
      database
        .prepare("SELECT COUNT(*) as count FROM team_members WHERE team_id = ?")
        .get(options.teamId) as { count: number }
    ).count;
    if (count >= org.settings.maxMembersPerTeam) throw new Error("Maximum members limit reached");
  }
  const role = options.role || "member";
  database
    .prepare(
      "INSERT OR REPLACE INTO team_members (user_id, team_id, role, joined_at, added_by, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .run(
      options.userId,
      options.teamId,
      role,
      now,
      options.addedBy || null,
      options.expiresAt || null
    );
  logTeamAudit({
    eventType: "MEMBER_ADDED",
    actorId: options.addedBy,
    organizationId: team.organizationId,
    teamId: options.teamId,
    targetUserId: options.userId,
    status: "SUCCESS",
    details: { role, expiresAt: options.expiresAt },
  });
  return {
    userId: options.userId,
    teamId: options.teamId,
    role,
    joinedAt: now,
    addedBy: options.addedBy,
    expiresAt: options.expiresAt,
  };
}

export function removeTeamMember(teamId: string, userId: string, actorId?: string): boolean {
  const team = getTeam(teamId);
  const result = getDb()
    .prepare("DELETE FROM team_members WHERE team_id = ? AND user_id = ?")
    .run(teamId, userId);
  if (result.changes > 0) {
    logTeamAudit({
      eventType: "MEMBER_REMOVED",
      actorId,
      organizationId: team?.organizationId,
      teamId,
      targetUserId: userId,
      status: "SUCCESS",
    });
    return true;
  }
  return false;
}

export function updateTeamMemberRole(
  teamId: string,
  userId: string,
  newRole: TeamMemberRole,
  actorId?: string
): TeamMember | null {
  const database = getDb();
  const team = getTeam(teamId);
  const memberRow = database
    .prepare("SELECT * FROM team_members WHERE team_id = ? AND user_id = ?")
    .get(teamId, userId) as Record<string, unknown> | undefined;
  if (!memberRow) return null;
  const oldRole = memberRow.role as string;
  database
    .prepare("UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ?")
    .run(newRole, teamId, userId);
  logTeamAudit({
    eventType: "MEMBER_ROLE_CHANGED",
    actorId,
    organizationId: team?.organizationId,
    teamId,
    targetUserId: userId,
    status: "SUCCESS",
    details: { oldRole, newRole },
  });
  return {
    userId: memberRow.user_id as string,
    teamId: memberRow.team_id as string,
    role: newRole,
    joinedAt: memberRow.joined_at as string,
    addedBy: memberRow.added_by as string | undefined,
    expiresAt: memberRow.expires_at as string | undefined,
  };
}

export function getTeamMember(teamId: string, userId: string): TeamMember | null {
  const row = getDb()
    .prepare("SELECT * FROM team_members WHERE team_id = ? AND user_id = ?")
    .get(teamId, userId) as Record<string, unknown> | undefined;
  return row ? rowToTeamMember(row) : null;
}

export function listTeamMembers(teamId: string, options?: ListTeamMembersOptions): TeamMember[] {
  const database = getDb();
  const now = new Date().toISOString();
  let sql = "SELECT * FROM team_members WHERE team_id = ?";
  const params: (string | number)[] = [teamId];
  if (!options?.includeExpired) {
    sql += " AND (expires_at IS NULL OR expires_at > ?)";
    params.push(now);
  }
  if (options?.role) {
    sql += " AND role = ?";
    params.push(options.role);
  }
  sql += " ORDER BY role, joined_at";
  if (options?.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }
  if (options?.offset) {
    sql += " OFFSET ?";
    params.push(options.offset);
  }
  return (database.prepare(sql).all(...params) as Array<Record<string, unknown>>).map(
    rowToTeamMember
  );
}

export function getUserTeamMemberships(userId: string): TeamMembershipDetails[] {
  const now = new Date().toISOString();
  const rows = getDb()
    .prepare(
      "SELECT tm.*, t.name as team_name, t.organization_id, o.name as org_name FROM team_members tm JOIN teams t ON tm.team_id = t.id JOIN organizations o ON t.organization_id = o.id WHERE tm.user_id = ? AND (tm.expires_at IS NULL OR tm.expires_at > ?) ORDER BY o.name, t.name"
    )
    .all(userId, now) as Array<Record<string, unknown>>;
  return rows.map((row) => ({
    userId: row.user_id as string,
    teamId: row.team_id as string,
    teamName: row.team_name as string,
    organizationId: row.organization_id as string,
    organizationName: row.org_name as string,
    role: row.role as TeamMemberRole,
    joinedAt: row.joined_at as string,
  }));
}

export function isTeamMember(teamId: string, userId: string): boolean {
  const member = getTeamMember(teamId, userId);
  if (!member) return false;
  if (member.expiresAt && new Date(member.expiresAt) <= new Date()) return false;
  return true;
}

export function hasTeamRole(teamId: string, userId: string, role: TeamMemberRole): boolean {
  const member = getTeamMember(teamId, userId);
  if (!member || !isTeamMember(teamId, userId)) return false;
  const hierarchy: Record<TeamMemberRole, number> = { owner: 4, admin: 3, member: 2, viewer: 1 };
  return hierarchy[member.role] >= hierarchy[role];
}

function rowToTeamMember(row: Record<string, unknown>): TeamMember {
  return {
    userId: row.user_id as string,
    teamId: row.team_id as string,
    role: row.role as TeamMemberRole,
    joinedAt: row.joined_at as string,
    addedBy: row.added_by as string | undefined,
    expiresAt: row.expires_at as string | undefined,
  };
}

// Audit Logging
export function logTeamAudit(event: Omit<TeamAuditEvent, "id" | "timestamp">): void {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  getDb()
    .prepare(
      "INSERT INTO team_audit (id, event_type, actor_id, organization_id, team_id, target_user_id, status, details_json, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .run(
      id,
      event.eventType,
      event.actorId || null,
      event.organizationId || null,
      event.teamId || null,
      event.targetUserId || null,
      event.status,
      event.details ? JSON.stringify(event.details) : null,
      now
    );
}

export function getTeamAuditEvents(options?: {
  actorId?: string;
  organizationId?: string;
  teamId?: string;
  targetUserId?: string;
  eventType?: TeamEventType;
  status?: "SUCCESS" | "FAILURE";
  limit?: number;
  offset?: number;
}): TeamAuditEvent[] {
  let sql = "SELECT * FROM team_audit WHERE 1=1";
  const params: (string | number)[] = [];
  if (options?.actorId) {
    sql += " AND actor_id = ?";
    params.push(options.actorId);
  }
  if (options?.organizationId) {
    sql += " AND organization_id = ?";
    params.push(options.organizationId);
  }
  if (options?.teamId) {
    sql += " AND team_id = ?";
    params.push(options.teamId);
  }
  if (options?.targetUserId) {
    sql += " AND target_user_id = ?";
    params.push(options.targetUserId);
  }
  if (options?.eventType) {
    sql += " AND event_type = ?";
    params.push(options.eventType);
  }
  if (options?.status) {
    sql += " AND status = ?";
    params.push(options.status);
  }
  sql += " ORDER BY timestamp DESC";
  if (options?.limit || options?.offset) {
    sql += " LIMIT ?";
    params.push(options?.limit ?? -1);
  }
  if (options?.offset) {
    sql += " OFFSET ?";
    params.push(options.offset);
  }
  return (
    getDb()
      .prepare(sql)
      .all(...params) as Array<Record<string, unknown>>
  ).map((row) => ({
    id: row.id as string,
    eventType: row.event_type as TeamEventType,
    actorId: row.actor_id as string | undefined,
    organizationId: row.organization_id as string | undefined,
    teamId: row.team_id as string | undefined,
    targetUserId: row.target_user_id as string | undefined,
    status: row.status as "SUCCESS" | "FAILURE",
    details: row.details_json ? JSON.parse(row.details_json as string) : undefined,
    timestamp: row.timestamp as string,
  }));
}

// Maintenance Functions
export function cleanupExpiredMemberships(): number {
  return getDb()
    .prepare("DELETE FROM team_members WHERE expires_at IS NOT NULL AND expires_at <= ?")
    .run(new Date().toISOString()).changes;
}

export function cleanupTeamAuditEvents(olderThanDays: number = 90): number {
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - olderThanDays);
  return getDb().prepare("DELETE FROM team_audit WHERE timestamp < ?").run(cutoff.toISOString())
    .changes;
}

export function getTeamStats(): TeamStats {
  const database = getDb();
  const totalOrganizations = (
    database.prepare("SELECT COUNT(*) as count FROM organizations").get() as { count: number }
  ).count;
  const totalTeams = (
    database.prepare("SELECT COUNT(*) as count FROM teams").get() as { count: number }
  ).count;
  const totalMemberships = (
    database.prepare("SELECT COUNT(*) as count FROM team_members").get() as { count: number }
  ).count;
  const roleRows = database
    .prepare("SELECT role, COUNT(*) as count FROM team_members GROUP BY role")
    .all() as Array<{ role: string; count: number }>;
  const membersByRole: Record<TeamMemberRole, number> = {
    owner: 0,
    admin: 0,
    member: 0,
    viewer: 0,
  };
  for (const row of roleRows) membersByRole[row.role as TeamMemberRole] = row.count;
  return { totalOrganizations, totalTeams, totalMemberships, membersByRole };
}
