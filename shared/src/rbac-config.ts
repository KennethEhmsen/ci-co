/**
 * RBAC (Role-Based Access Control) Configuration Module
 *
 * Provides SQLite database storage for roles, permissions,
 * user-role assignments, and audit logging.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import Database from "better-sqlite3";
import type {
  RbacRole,
  RbacPermission,
  RbacUserRole,
  RbacCheckResult,
  RbacAuditEvent,
  RbacEventType,
  RbacDbInitResult,
  RbacRoleWithPermissions,
} from "./types.js";

// =============================================================================
// Database Instance
// =============================================================================

let db: Database.Database | null = null;

/**
 * Get the default RBAC database path
 */
function getDefaultDbPath(): string {
  const rbacDir = process.env.RBAC_DB_PATH
    ? path.dirname(process.env.RBAC_DB_PATH)
    : path.join(os.homedir(), ".cicd", "rbac");
  return process.env.RBAC_DB_PATH || path.join(rbacDir, "rbac.db");
}

/**
 * Create RBAC database schema
 */
function createSchema(database: Database.Database): void {
  const schema = `
    -- Roles table
    CREATE TABLE IF NOT EXISTS rbac_roles (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      is_system INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Permissions table
    CREATE TABLE IF NOT EXISTS rbac_permissions (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      resource TEXT NOT NULL,
      action TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Role-Permission mapping
    CREATE TABLE IF NOT EXISTS rbac_role_permissions (
      role_id TEXT NOT NULL,
      permission_id TEXT NOT NULL,
      granted_at TEXT DEFAULT CURRENT_TIMESTAMP,
      granted_by TEXT,
      PRIMARY KEY (role_id, permission_id),
      FOREIGN KEY (role_id) REFERENCES rbac_roles(id) ON DELETE CASCADE,
      FOREIGN KEY (permission_id) REFERENCES rbac_permissions(id) ON DELETE CASCADE
    );

    -- User-Role mapping
    CREATE TABLE IF NOT EXISTS rbac_user_roles (
      user_id TEXT NOT NULL,
      role_id TEXT NOT NULL,
      assigned_at TEXT DEFAULT CURRENT_TIMESTAMP,
      assigned_by TEXT,
      expires_at TEXT,
      PRIMARY KEY (user_id, role_id),
      FOREIGN KEY (role_id) REFERENCES rbac_roles(id) ON DELETE CASCADE
    );

    -- RBAC Audit log
    CREATE TABLE IF NOT EXISTS rbac_audit (
      id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      actor_id TEXT,
      target_user_id TEXT,
      role_id TEXT,
      permission_id TEXT,
      status TEXT NOT NULL,
      details_json TEXT,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Indexes for performance
    CREATE INDEX IF NOT EXISTS idx_user_roles_user ON rbac_user_roles(user_id);
    CREATE INDEX IF NOT EXISTS idx_user_roles_role ON rbac_user_roles(role_id);
    CREATE INDEX IF NOT EXISTS idx_role_perms_role ON rbac_role_permissions(role_id);
    CREATE INDEX IF NOT EXISTS idx_rbac_audit_actor ON rbac_audit(actor_id);
    CREATE INDEX IF NOT EXISTS idx_rbac_audit_timestamp ON rbac_audit(timestamp);
  `;
  database.exec(schema);
}

// =============================================================================
// Default Roles and Permissions
// =============================================================================

const DEFAULT_PERMISSIONS: Array<Omit<RbacPermission, "id" | "createdAt">> = [
  { name: "scan:read", resource: "scan", action: "read", description: "View scan results" },
  { name: "scan:execute", resource: "scan", action: "execute", description: "Run scans" },
  { name: "scan:delete", resource: "scan", action: "delete", description: "Delete scan results" },
  { name: "config:read", resource: "config", action: "read", description: "View configuration" },
  {
    name: "config:write",
    resource: "config",
    action: "write",
    description: "Modify configuration",
  },
  { name: "report:read", resource: "report", action: "read", description: "View reports" },
  {
    name: "report:generate",
    resource: "report",
    action: "execute",
    description: "Generate reports",
  },
  { name: "audit:read", resource: "audit", action: "read", description: "View audit logs" },
  { name: "user:read", resource: "user", action: "read", description: "View user info" },
  { name: "user:manage", resource: "user", action: "write", description: "Manage users/roles" },
  { name: "system:admin", resource: "system", action: "admin", description: "Full system access" },
];

interface DefaultRoleConfig {
  name: string;
  description: string;
  permissions: string[];
}

const DEFAULT_ROLES: DefaultRoleConfig[] = [
  {
    name: "Admin",
    description: "Full system access - all permissions",
    permissions: ["system:admin"],
  },
  {
    name: "Auditor",
    description: "Read-only access to all resources and audit logs",
    permissions: ["scan:read", "report:read", "audit:read", "config:read"],
  },
  {
    name: "Developer",
    description: "Scan execution and report access",
    permissions: ["scan:read", "scan:execute", "report:read", "report:generate"],
  },
  {
    name: "Viewer",
    description: "Read-only access to scan results and reports",
    permissions: ["scan:read", "report:read"],
  },
];

/**
 * Seed default permissions and roles
 */
function seedDefaults(database: Database.Database): void {
  const now = new Date().toISOString();

  // Insert default permissions
  const permStmt = database.prepare(`
    INSERT OR IGNORE INTO rbac_permissions (id, name, description, resource, action, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  const permissionIds: Record<string, string> = {};
  for (const perm of DEFAULT_PERMISSIONS) {
    const id = crypto.randomUUID();
    permStmt.run(id, perm.name, perm.description, perm.resource, perm.action, now);
    permissionIds[perm.name] = id;
  }

  // Get actual permission IDs from database (in case they already existed)
  const getPermId = database.prepare("SELECT id FROM rbac_permissions WHERE name = ?");
  for (const perm of DEFAULT_PERMISSIONS) {
    const row = getPermId.get(perm.name) as { id: string } | undefined;
    if (row) {
      permissionIds[perm.name] = row.id;
    }
  }

  // Insert default roles
  const roleStmt = database.prepare(`
    INSERT OR IGNORE INTO rbac_roles (id, name, description, is_system, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `);

  const rolePermStmt = database.prepare(`
    INSERT OR IGNORE INTO rbac_role_permissions (role_id, permission_id, granted_at)
    VALUES (?, ?, ?)
  `);

  for (const role of DEFAULT_ROLES) {
    const roleId = crypto.randomUUID();
    roleStmt.run(roleId, role.name, role.description, now, now);

    // Get actual role ID (in case it already existed)
    const existingRole = database
      .prepare("SELECT id FROM rbac_roles WHERE name = ?")
      .get(role.name) as { id: string } | undefined;
    const actualRoleId = existingRole?.id || roleId;

    // Grant permissions to role
    for (const permName of role.permissions) {
      const permId = permissionIds[permName];
      if (permId) {
        rolePermStmt.run(actualRoleId, permId, now);
      }
    }
  }
}

// =============================================================================
// Database Lifecycle
// =============================================================================

/**
 * Initialize the RBAC database
 */
export function initRbacDatabase(customPath?: string): RbacDbInitResult {
  if (db) {
    return {
      success: true,
      path: getDefaultDbPath(),
      created: false,
    };
  }

  const dbPath = customPath || getDefaultDbPath();
  const dbDir = path.dirname(dbPath);

  try {
    // Create directory if it doesn't exist
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }

    const isNew = !fs.existsSync(dbPath);
    db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    db.pragma("foreign_keys = ON");
    createSchema(db);

    // Seed defaults on first creation
    if (isNew) {
      seedDefaults(db);
    }

    return {
      success: true,
      path: dbPath,
      created: isNew,
    };
  } catch (error) {
    return {
      success: false,
      path: dbPath,
      created: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Close the RBAC database
 */
export function closeRbacDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

/**
 * Check if RBAC database is initialized
 */
export function isRbacDbInitialized(): boolean {
  return db !== null;
}

/**
 * Get the database instance (for internal use)
 */
function getDb(): Database.Database {
  if (!db) {
    throw new Error("RBAC database not initialized. Call initRbacDatabase() first.");
  }
  return db;
}

// =============================================================================
// Role Management
// =============================================================================

/**
 * Create a new role
 */
export function createRole(
  name: string,
  description?: string,
  permissions?: string[],
  actorId?: string
): RbacRole {
  const database = getDb();
  const now = new Date().toISOString();
  const id = crypto.randomUUID();

  const stmt = database.prepare(`
    INSERT INTO rbac_roles (id, name, description, is_system, created_at, updated_at)
    VALUES (?, ?, ?, 0, ?, ?)
  `);

  stmt.run(id, name, description || null, now, now);

  // Grant permissions if specified
  if (permissions && permissions.length > 0) {
    for (const permName of permissions) {
      grantPermissionToRole(id, permName, actorId);
    }
  }

  logRbacAudit({
    eventType: "ROLE_CREATED",
    actorId,
    roleId: id,
    status: "SUCCESS",
    details: { name, permissions },
  });

  return {
    id,
    name,
    description,
    isSystem: false,
    createdAt: now,
    updatedAt: now,
  };
}

/**
 * Get a role by ID
 */
export function getRole(roleId: string): RbacRole | null {
  const database = getDb();
  const stmt = database.prepare("SELECT * FROM rbac_roles WHERE id = ?");
  const row = stmt.get(roleId) as Record<string, unknown> | undefined;

  if (!row) {
    return null;
  }

  return rowToRole(row);
}

/**
 * Get a role by name
 */
export function getRoleByName(name: string): RbacRole | null {
  const database = getDb();
  const stmt = database.prepare("SELECT * FROM rbac_roles WHERE name = ?");
  const row = stmt.get(name) as Record<string, unknown> | undefined;

  if (!row) {
    return null;
  }

  return rowToRole(row);
}

/**
 * List all roles
 */
export function listRoles(
  includePermissions: boolean = false
): RbacRole[] | RbacRoleWithPermissions[] {
  const database = getDb();
  const stmt = database.prepare("SELECT * FROM rbac_roles ORDER BY name");
  const rows = stmt.all() as Array<Record<string, unknown>>;

  const roles = rows.map(rowToRole);

  if (!includePermissions) {
    return roles;
  }

  // Include permissions for each role
  return roles.map((role) => ({
    ...role,
    permissions: getRolePermissions(role.id),
  }));
}

/**
 * Update a role
 */
export function updateRole(
  roleId: string,
  updates: { name?: string; description?: string },
  actorId?: string
): RbacRole | null {
  const database = getDb();
  const role = getRole(roleId);

  if (!role) {
    return null;
  }

  if (role.isSystem) {
    throw new Error("Cannot modify system roles");
  }

  const now = new Date().toISOString();
  const newName = updates.name ?? role.name;
  const newDescription = updates.description ?? role.description;

  const stmt = database.prepare(`
    UPDATE rbac_roles SET name = ?, description = ?, updated_at = ? WHERE id = ?
  `);

  stmt.run(newName, newDescription, now, roleId);

  logRbacAudit({
    eventType: "ROLE_UPDATED",
    actorId,
    roleId,
    status: "SUCCESS",
    details: updates,
  });

  return {
    ...role,
    name: newName,
    description: newDescription,
    updatedAt: now,
  };
}

/**
 * Delete a role
 */
export function deleteRole(roleId: string, actorId?: string): boolean {
  const database = getDb();
  const role = getRole(roleId);

  if (!role) {
    return false;
  }

  if (role.isSystem) {
    logRbacAudit({
      eventType: "ROLE_DELETED",
      actorId,
      roleId,
      status: "FAILURE",
      details: { error: "Cannot delete system role" },
    });
    throw new Error("Cannot delete system roles");
  }

  const stmt = database.prepare("DELETE FROM rbac_roles WHERE id = ?");
  const result = stmt.run(roleId);

  if (result.changes > 0) {
    logRbacAudit({
      eventType: "ROLE_DELETED",
      actorId,
      roleId,
      status: "SUCCESS",
      details: { name: role.name },
    });
    return true;
  }

  return false;
}

/**
 * Convert database row to RbacRole
 */
function rowToRole(row: Record<string, unknown>): RbacRole {
  return {
    id: row.id as string,
    name: row.name as string,
    description: row.description as string | undefined,
    isSystem: (row.is_system as number) === 1,
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
  };
}

// =============================================================================
// Permission Management
// =============================================================================

/**
 * Get a permission by ID
 */
export function getPermission(permissionId: string): RbacPermission | null {
  const database = getDb();
  const stmt = database.prepare("SELECT * FROM rbac_permissions WHERE id = ?");
  const row = stmt.get(permissionId) as Record<string, unknown> | undefined;

  if (!row) {
    return null;
  }

  return rowToPermission(row);
}

/**
 * Get a permission by name
 */
export function getPermissionByName(name: string): RbacPermission | null {
  const database = getDb();
  const stmt = database.prepare("SELECT * FROM rbac_permissions WHERE name = ?");
  const row = stmt.get(name) as Record<string, unknown> | undefined;

  if (!row) {
    return null;
  }

  return rowToPermission(row);
}

/**
 * List all permissions
 */
export function listPermissions(): RbacPermission[] {
  const database = getDb();
  const stmt = database.prepare("SELECT * FROM rbac_permissions ORDER BY resource, action");
  const rows = stmt.all() as Array<Record<string, unknown>>;
  return rows.map(rowToPermission);
}

/**
 * Grant a permission to a role
 */
export function grantPermissionToRole(
  roleId: string,
  permissionName: string,
  grantedBy?: string
): boolean {
  const database = getDb();
  const permission = getPermissionByName(permissionName);

  if (!permission) {
    return false;
  }

  const now = new Date().toISOString();
  const stmt = database.prepare(`
    INSERT OR IGNORE INTO rbac_role_permissions (role_id, permission_id, granted_at, granted_by)
    VALUES (?, ?, ?, ?)
  `);

  const result = stmt.run(roleId, permission.id, now, grantedBy || null);

  if (result.changes > 0) {
    logRbacAudit({
      eventType: "PERMISSION_GRANTED",
      actorId: grantedBy,
      roleId,
      permissionId: permission.id,
      status: "SUCCESS",
      details: { permissionName },
    });
    return true;
  }

  return false;
}

/**
 * Revoke a permission from a role
 */
export function revokePermissionFromRole(
  roleId: string,
  permissionName: string,
  actorId?: string
): boolean {
  const database = getDb();
  const permission = getPermissionByName(permissionName);

  if (!permission) {
    return false;
  }

  const stmt = database.prepare(`
    DELETE FROM rbac_role_permissions WHERE role_id = ? AND permission_id = ?
  `);

  const result = stmt.run(roleId, permission.id);

  if (result.changes > 0) {
    logRbacAudit({
      eventType: "PERMISSION_REVOKED",
      actorId,
      roleId,
      permissionId: permission.id,
      status: "SUCCESS",
      details: { permissionName },
    });
    return true;
  }

  return false;
}

/**
 * Get all permissions for a role
 */
export function getRolePermissions(roleId: string): RbacPermission[] {
  const database = getDb();
  const stmt = database.prepare(`
    SELECT p.* FROM rbac_permissions p
    JOIN rbac_role_permissions rp ON p.id = rp.permission_id
    WHERE rp.role_id = ?
    ORDER BY p.resource, p.action
  `);

  const rows = stmt.all(roleId) as Array<Record<string, unknown>>;
  return rows.map(rowToPermission);
}

/**
 * Convert database row to RbacPermission
 */
function rowToPermission(row: Record<string, unknown>): RbacPermission {
  return {
    id: row.id as string,
    name: row.name as string,
    description: row.description as string | undefined,
    resource: row.resource as string,
    action: row.action as string,
    createdAt: row.created_at as string,
  };
}

// =============================================================================
// User-Role Assignment
// =============================================================================

/**
 * Assign a role to a user
 */
export function assignRoleToUser(
  userId: string,
  roleId: string,
  assignedBy?: string,
  expiresAt?: string
): boolean {
  const database = getDb();
  const role = getRole(roleId);

  if (!role) {
    return false;
  }

  const now = new Date().toISOString();
  const stmt = database.prepare(`
    INSERT OR REPLACE INTO rbac_user_roles (user_id, role_id, assigned_at, assigned_by, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `);

  stmt.run(userId, roleId, now, assignedBy || null, expiresAt || null);

  logRbacAudit({
    eventType: "ROLE_ASSIGNED",
    actorId: assignedBy,
    targetUserId: userId,
    roleId,
    status: "SUCCESS",
    details: { roleName: role.name, expiresAt },
  });

  return true;
}

/**
 * Unassign a role from a user
 */
export function unassignRoleFromUser(userId: string, roleId: string, actorId?: string): boolean {
  const database = getDb();
  const role = getRole(roleId);

  const stmt = database.prepare("DELETE FROM rbac_user_roles WHERE user_id = ? AND role_id = ?");
  const result = stmt.run(userId, roleId);

  if (result.changes > 0) {
    logRbacAudit({
      eventType: "ROLE_UNASSIGNED",
      actorId,
      targetUserId: userId,
      roleId,
      status: "SUCCESS",
      details: { roleName: role?.name },
    });
    return true;
  }

  return false;
}

/**
 * Get all roles for a user
 */
export function getUserRoles(userId: string): RbacUserRole[] {
  const database = getDb();
  const now = new Date().toISOString();

  const stmt = database.prepare(`
    SELECT ur.*, r.name as role_name
    FROM rbac_user_roles ur
    JOIN rbac_roles r ON ur.role_id = r.id
    WHERE ur.user_id = ? AND (ur.expires_at IS NULL OR ur.expires_at > ?)
    ORDER BY r.name
  `);

  const rows = stmt.all(userId, now) as Array<Record<string, unknown>>;

  return rows.map((row) => ({
    userId: row.user_id as string,
    roleId: row.role_id as string,
    roleName: row.role_name as string,
    assignedAt: row.assigned_at as string,
    assignedBy: row.assigned_by as string | undefined,
    expiresAt: row.expires_at as string | undefined,
  }));
}

/**
 * Get all users with a specific role
 */
export function getUsersWithRole(roleId: string): string[] {
  const database = getDb();
  const now = new Date().toISOString();

  const stmt = database.prepare(`
    SELECT user_id FROM rbac_user_roles
    WHERE role_id = ? AND (expires_at IS NULL OR expires_at > ?)
  `);

  const rows = stmt.all(roleId, now) as Array<{ user_id: string }>;
  return rows.map((row) => row.user_id);
}

// =============================================================================
// Permission Checking
// =============================================================================

/**
 * Check if a user has a specific permission
 */
export function checkPermission(userId: string, permission: string): RbacCheckResult {
  // Get all active roles for the user
  const userRoles = getUserRoles(userId);

  if (userRoles.length === 0) {
    logRbacAudit({
      eventType: "PERMISSION_CHECK",
      targetUserId: userId,
      status: "FAILURE",
      details: { permission, reason: "No roles assigned" },
    });

    return {
      allowed: false,
      permission,
      reason: "User has no roles assigned",
    };
  }

  // Check if any role grants the permission or system:admin
  for (const userRole of userRoles) {
    const rolePermissions = getRolePermissions(userRole.roleId);

    // Check for exact permission match
    const hasPermission = rolePermissions.some((p) => p.name === permission);
    if (hasPermission) {
      logRbacAudit({
        eventType: "PERMISSION_CHECK",
        targetUserId: userId,
        roleId: userRole.roleId,
        status: "SUCCESS",
        details: { permission, matchedRole: userRole.roleName },
      });

      return {
        allowed: true,
        permission,
        matchedRole: userRole.roleName,
      };
    }

    // Check for system:admin (grants all permissions)
    const hasAdmin = rolePermissions.some((p) => p.name === "system:admin");
    if (hasAdmin) {
      logRbacAudit({
        eventType: "PERMISSION_CHECK",
        targetUserId: userId,
        roleId: userRole.roleId,
        status: "SUCCESS",
        details: { permission, matchedRole: userRole.roleName, grantedBy: "system:admin" },
      });

      return {
        allowed: true,
        permission,
        matchedRole: userRole.roleName,
      };
    }
  }

  logRbacAudit({
    eventType: "PERMISSION_CHECK",
    targetUserId: userId,
    status: "FAILURE",
    details: { permission, roles: userRoles.map((r) => r.roleName) },
  });

  return {
    allowed: false,
    permission,
    reason: "Permission not granted by any assigned role",
  };
}

/**
 * Get all effective permissions for a user
 */
export function listUserPermissions(userId: string): RbacPermission[] {
  const userRoles = getUserRoles(userId);
  const permissionMap = new Map<string, RbacPermission>();

  for (const userRole of userRoles) {
    const rolePermissions = getRolePermissions(userRole.roleId);
    for (const perm of rolePermissions) {
      permissionMap.set(perm.id, perm);
    }
  }

  return Array.from(permissionMap.values()).sort((a, b) => {
    if (a.resource !== b.resource) {
      return a.resource.localeCompare(b.resource);
    }
    return a.action.localeCompare(b.action);
  });
}

/**
 * Check if user has admin access
 */
export function isUserAdmin(userId: string): boolean {
  const result = checkPermission(userId, "system:admin");
  return result.allowed;
}

// =============================================================================
// Audit Logging
// =============================================================================

/**
 * Log an RBAC audit event
 */
export function logRbacAudit(event: Omit<RbacAuditEvent, "id" | "timestamp">): void {
  const database = getDb();
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  const stmt = database.prepare(`
    INSERT INTO rbac_audit (
      id, event_type, actor_id, target_user_id, role_id, permission_id,
      status, details_json, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    id,
    event.eventType,
    event.actorId || null,
    event.targetUserId || null,
    event.roleId || null,
    event.permissionId || null,
    event.status,
    event.details ? JSON.stringify(event.details) : null,
    now
  );
}

/**
 * Get RBAC audit events
 */
export function getRbacAuditEvents(options?: {
  actorId?: string;
  targetUserId?: string;
  roleId?: string;
  eventType?: RbacEventType;
  status?: "SUCCESS" | "FAILURE";
  limit?: number;
  offset?: number;
}): RbacAuditEvent[] {
  const database = getDb();
  let sql = "SELECT * FROM rbac_audit WHERE 1=1";
  const params: (string | number)[] = [];

  if (options?.actorId) {
    sql += " AND actor_id = ?";
    params.push(options.actorId);
  }

  if (options?.targetUserId) {
    sql += " AND target_user_id = ?";
    params.push(options.targetUserId);
  }

  if (options?.roleId) {
    sql += " AND role_id = ?";
    params.push(options.roleId);
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

  const stmt = database.prepare(sql);
  const rows = stmt.all(...params) as Array<Record<string, unknown>>;

  return rows.map((row) => ({
    id: row.id as string,
    eventType: row.event_type as RbacEventType,
    actorId: row.actor_id as string | undefined,
    targetUserId: row.target_user_id as string | undefined,
    roleId: row.role_id as string | undefined,
    permissionId: row.permission_id as string | undefined,
    status: row.status as "SUCCESS" | "FAILURE",
    details: row.details_json ? JSON.parse(row.details_json as string) : undefined,
    timestamp: row.timestamp as string,
  }));
}

/**
 * Cleanup old audit events
 */
export function cleanupOldRbacAuditEvents(olderThanDays: number = 90): number {
  const database = getDb();
  const stmt = database.prepare(`
    DELETE FROM rbac_audit
    WHERE timestamp < datetime('now', '-' || ? || ' days')
  `);
  const result = stmt.run(olderThanDays);
  return result.changes;
}

/**
 * Cleanup expired user-role assignments
 */
export function cleanupExpiredRoleAssignments(): number {
  const database = getDb();
  const now = new Date().toISOString();
  const stmt = database.prepare(
    "DELETE FROM rbac_user_roles WHERE expires_at IS NOT NULL AND expires_at <= ?"
  );
  const result = stmt.run(now);
  return result.changes;
}
