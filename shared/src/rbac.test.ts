/**
 * RBAC Configuration Tests
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  initRbacDatabase,
  closeRbacDatabase,
  isRbacDbInitialized,
  createRole,
  getRole,
  getRoleByName,
  listRoles,
  updateRole,
  deleteRole,
  listPermissions,
  grantPermissionToRole,
  revokePermissionFromRole,
  getRolePermissions,
  assignRoleToUser,
  unassignRoleFromUser,
  getUserRoles,
  getUsersWithRole,
  checkPermission,
  listUserPermissions,
  isUserAdmin,
  getRbacAuditEvents,
  cleanupExpiredRoleAssignments,
} from "./rbac-config.js";
import type { RbacRoleWithPermissions } from "./types.js";

describe("RBAC Configuration", () => {
  let testDbPath: string;

  beforeEach(() => {
    // Create a unique temp database for each test
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rbac-test-"));
    testDbPath = path.join(tempDir, "rbac.db");
  });

  afterEach(() => {
    closeRbacDatabase();
    // Clean up test database
    try {
      if (fs.existsSync(testDbPath)) {
        fs.unlinkSync(testDbPath);
      }
      const dir = path.dirname(testDbPath);
      if (fs.existsSync(dir)) {
        fs.rmdirSync(dir);
      }
    } catch {
      // Ignore cleanup errors
    }
  });

  describe("Database Lifecycle", () => {
    it("should initialize database successfully", () => {
      const result = initRbacDatabase(testDbPath);
      expect(result.success).toBe(true);
      expect(result.created).toBe(true);
      expect(result.path).toBe(testDbPath);
      expect(isRbacDbInitialized()).toBe(true);
    });

    it("should return existing database on re-initialization", () => {
      const first = initRbacDatabase(testDbPath);
      expect(first.created).toBe(true);

      const second = initRbacDatabase(testDbPath);
      expect(second.success).toBe(true);
      expect(second.created).toBe(false);
    });

    it("should close database", () => {
      initRbacDatabase(testDbPath);
      expect(isRbacDbInitialized()).toBe(true);

      closeRbacDatabase();
      expect(isRbacDbInitialized()).toBe(false);
    });
  });

  describe("Default Roles and Permissions", () => {
    beforeEach(() => {
      initRbacDatabase(testDbPath);
    });

    it("should seed default permissions", () => {
      const permissions = listPermissions();
      expect(permissions.length).toBeGreaterThanOrEqual(11);

      const permNames = permissions.map((p) => p.name);
      expect(permNames).toContain("scan:read");
      expect(permNames).toContain("scan:execute");
      expect(permNames).toContain("system:admin");
    });

    it("should seed default roles", () => {
      const roles = listRoles(false);
      expect(roles.length).toBeGreaterThanOrEqual(4);

      const roleNames = roles.map((r) => r.name);
      expect(roleNames).toContain("Admin");
      expect(roleNames).toContain("Auditor");
      expect(roleNames).toContain("Developer");
      expect(roleNames).toContain("Viewer");
    });

    it("should have correct permissions for Admin role", () => {
      const role = getRoleByName("Admin");
      expect(role).not.toBeNull();
      expect(role?.isSystem).toBe(true);

      const permissions = getRolePermissions(role!.id);
      expect(permissions.some((p) => p.name === "system:admin")).toBe(true);
    });

    it("should have correct permissions for Developer role", () => {
      const role = getRoleByName("Developer");
      expect(role).not.toBeNull();

      const permissions = getRolePermissions(role!.id);
      const permNames = permissions.map((p) => p.name);
      expect(permNames).toContain("scan:read");
      expect(permNames).toContain("scan:execute");
      expect(permNames).toContain("report:read");
      expect(permNames).toContain("report:generate");
    });
  });

  describe("Role Management", () => {
    beforeEach(() => {
      initRbacDatabase(testDbPath);
    });

    it("should create a custom role", () => {
      const role = createRole("CustomRole", "A test role");
      expect(role.name).toBe("CustomRole");
      expect(role.description).toBe("A test role");
      expect(role.isSystem).toBe(false);
    });

    it("should create a role with permissions", () => {
      const role = createRole("SecurityAnalyst", "Security team role", ["scan:read", "audit:read"]);

      const permissions = getRolePermissions(role.id);
      expect(permissions.length).toBe(2);
      expect(permissions.some((p) => p.name === "scan:read")).toBe(true);
      expect(permissions.some((p) => p.name === "audit:read")).toBe(true);
    });

    it("should get role by ID", () => {
      const created = createRole("TestRole");
      const retrieved = getRole(created.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.name).toBe("TestRole");
    });

    it("should get role by name", () => {
      createRole("UniqueRole");
      const role = getRoleByName("UniqueRole");
      expect(role).not.toBeNull();
      expect(role?.name).toBe("UniqueRole");
    });

    it("should list all roles with permissions", () => {
      const roles = listRoles(true) as RbacRoleWithPermissions[];
      expect(roles.length).toBeGreaterThan(0);
      expect(roles[0].permissions).toBeDefined();
      expect(Array.isArray(roles[0].permissions)).toBe(true);
    });

    it("should update a custom role", () => {
      const role = createRole("UpdateTest");
      const updated = updateRole(role.id, { description: "Updated description" });
      expect(updated).not.toBeNull();
      expect(updated?.description).toBe("Updated description");
    });

    it("should not allow updating system roles", () => {
      const adminRole = getRoleByName("Admin");
      expect(() => updateRole(adminRole!.id, { description: "Hacked" })).toThrow(
        "Cannot modify system roles"
      );
    });

    it("should delete a custom role", () => {
      const role = createRole("ToDelete");
      const deleted = deleteRole(role.id);
      expect(deleted).toBe(true);

      const retrieved = getRole(role.id);
      expect(retrieved).toBeNull();
    });

    it("should not allow deleting system roles", () => {
      const adminRole = getRoleByName("Admin");
      expect(() => deleteRole(adminRole!.id)).toThrow("Cannot delete system roles");
    });
  });

  describe("Permission Management", () => {
    beforeEach(() => {
      initRbacDatabase(testDbPath);
    });

    it("should grant permission to role", () => {
      const role = createRole("PermTest");
      const granted = grantPermissionToRole(role.id, "scan:delete");
      expect(granted).toBe(true);

      const permissions = getRolePermissions(role.id);
      expect(permissions.some((p) => p.name === "scan:delete")).toBe(true);
    });

    it("should revoke permission from role", () => {
      const role = createRole("RevokeTest", undefined, ["scan:read", "scan:execute"]);
      const revoked = revokePermissionFromRole(role.id, "scan:read");
      expect(revoked).toBe(true);

      const permissions = getRolePermissions(role.id);
      expect(permissions.some((p) => p.name === "scan:read")).toBe(false);
      expect(permissions.some((p) => p.name === "scan:execute")).toBe(true);
    });

    it("should return false when granting non-existent permission", () => {
      const role = createRole("NoPermTest");
      const granted = grantPermissionToRole(role.id, "nonexistent:permission");
      expect(granted).toBe(false);
    });
  });

  describe("User-Role Assignment", () => {
    beforeEach(() => {
      initRbacDatabase(testDbPath);
    });

    it("should assign role to user", () => {
      const developerRole = getRoleByName("Developer")!;
      const assigned = assignRoleToUser("user123", developerRole.id);
      expect(assigned).toBe(true);

      const roles = getUserRoles("user123");
      expect(roles.length).toBe(1);
      expect(roles[0].roleName).toBe("Developer");
    });

    it("should assign multiple roles to user", () => {
      const developerRole = getRoleByName("Developer")!;
      const auditorRole = getRoleByName("Auditor")!;

      assignRoleToUser("multiUser", developerRole.id);
      assignRoleToUser("multiUser", auditorRole.id);

      const roles = getUserRoles("multiUser");
      expect(roles.length).toBe(2);
    });

    it("should unassign role from user", () => {
      const viewerRole = getRoleByName("Viewer")!;
      assignRoleToUser("removeUser", viewerRole.id);

      const unassigned = unassignRoleFromUser("removeUser", viewerRole.id);
      expect(unassigned).toBe(true);

      const roles = getUserRoles("removeUser");
      expect(roles.length).toBe(0);
    });

    it("should get users with specific role", () => {
      const developerRole = getRoleByName("Developer")!;
      assignRoleToUser("dev1", developerRole.id);
      assignRoleToUser("dev2", developerRole.id);
      assignRoleToUser("dev3", developerRole.id);

      const users = getUsersWithRole(developerRole.id);
      expect(users.length).toBe(3);
      expect(users).toContain("dev1");
      expect(users).toContain("dev2");
      expect(users).toContain("dev3");
    });

    it("should handle role expiration", () => {
      const role = getRoleByName("Viewer")!;
      const expiredDate = new Date(Date.now() - 1000).toISOString(); // 1 second ago

      assignRoleToUser("expiredUser", role.id, undefined, expiredDate);

      // Expired roles should not be returned
      const roles = getUserRoles("expiredUser");
      expect(roles.length).toBe(0);
    });

    it("should cleanup expired role assignments", () => {
      const role = getRoleByName("Viewer")!;
      const expiredDate = new Date(Date.now() - 1000).toISOString();

      assignRoleToUser("cleanupUser", role.id, undefined, expiredDate);

      const cleaned = cleanupExpiredRoleAssignments();
      expect(cleaned).toBeGreaterThanOrEqual(1);
    });
  });

  describe("Permission Checking", () => {
    beforeEach(() => {
      initRbacDatabase(testDbPath);
    });

    it("should allow permission when user has it", () => {
      const developerRole = getRoleByName("Developer")!;
      assignRoleToUser("permUser", developerRole.id);

      const result = checkPermission("permUser", "scan:execute");
      expect(result.allowed).toBe(true);
      expect(result.matchedRole).toBe("Developer");
    });

    it("should deny permission when user doesn't have it", () => {
      const viewerRole = getRoleByName("Viewer")!;
      assignRoleToUser("viewerUser", viewerRole.id);

      const result = checkPermission("viewerUser", "scan:execute");
      expect(result.allowed).toBe(false);
      expect(result.reason).toBeDefined();
    });

    it("should allow any permission for admin users", () => {
      const adminRole = getRoleByName("Admin")!;
      assignRoleToUser("adminUser", adminRole.id);

      // Admin should have access to everything via system:admin
      expect(checkPermission("adminUser", "scan:execute").allowed).toBe(true);
      expect(checkPermission("adminUser", "config:write").allowed).toBe(true);
      expect(checkPermission("adminUser", "some:random:permission").allowed).toBe(true);
    });

    it("should deny permission for users with no roles", () => {
      const result = checkPermission("noRoleUser", "scan:read");
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("no roles");
    });

    it("should identify admin users", () => {
      const adminRole = getRoleByName("Admin")!;
      assignRoleToUser("isAdminUser", adminRole.id);

      expect(isUserAdmin("isAdminUser")).toBe(true);
      expect(isUserAdmin("randomUser")).toBe(false);
    });
  });

  describe("User Permissions", () => {
    beforeEach(() => {
      initRbacDatabase(testDbPath);
    });

    it("should list all effective permissions for user", () => {
      const developerRole = getRoleByName("Developer")!;
      assignRoleToUser("listPermUser", developerRole.id);

      const permissions = listUserPermissions("listPermUser");
      expect(permissions.length).toBeGreaterThan(0);

      const permNames = permissions.map((p) => p.name);
      expect(permNames).toContain("scan:read");
      expect(permNames).toContain("scan:execute");
    });

    it("should combine permissions from multiple roles", () => {
      const developerRole = getRoleByName("Developer")!;
      const auditorRole = getRoleByName("Auditor")!;

      assignRoleToUser("multiRoleUser", developerRole.id);
      assignRoleToUser("multiRoleUser", auditorRole.id);

      const permissions = listUserPermissions("multiRoleUser");
      const permNames = permissions.map((p) => p.name);

      // Should have permissions from both roles
      expect(permNames).toContain("scan:execute"); // Developer
      expect(permNames).toContain("audit:read"); // Auditor
    });

    it("should return empty array for users with no roles", () => {
      const permissions = listUserPermissions("noRoleUser");
      expect(permissions.length).toBe(0);
    });
  });

  describe("Audit Logging", () => {
    beforeEach(() => {
      initRbacDatabase(testDbPath);
    });

    it("should log role creation", () => {
      createRole("AuditTestRole", undefined, undefined, "testActor");

      const events = getRbacAuditEvents({ eventType: "ROLE_CREATED" });
      expect(events.length).toBeGreaterThan(0);

      const createEvent = events.find((e) => e.details?.name === "AuditTestRole");
      expect(createEvent).toBeDefined();
      expect(createEvent?.status).toBe("SUCCESS");
    });

    it("should log role assignment", () => {
      const role = getRoleByName("Viewer")!;
      assignRoleToUser("auditAssignUser", role.id, "adminActor");

      const events = getRbacAuditEvents({ eventType: "ROLE_ASSIGNED" });
      expect(events.length).toBeGreaterThan(0);

      const assignEvent = events.find((e) => e.targetUserId === "auditAssignUser");
      expect(assignEvent).toBeDefined();
      expect(assignEvent?.actorId).toBe("adminActor");
    });

    it("should log permission checks", () => {
      const role = getRoleByName("Developer")!;
      assignRoleToUser("permCheckUser", role.id);
      checkPermission("permCheckUser", "scan:execute");

      const events = getRbacAuditEvents({ eventType: "PERMISSION_CHECK" });
      expect(events.length).toBeGreaterThan(0);

      const checkEvent = events.find((e) => e.targetUserId === "permCheckUser");
      expect(checkEvent).toBeDefined();
    });

    it("should filter audit events by status", () => {
      const role = getRoleByName("Developer")!;
      assignRoleToUser("statusUser", role.id);
      checkPermission("statusUser", "scan:execute"); // SUCCESS
      checkPermission("noRoleUser", "scan:execute"); // FAILURE

      const successEvents = getRbacAuditEvents({ status: "SUCCESS" });
      const failureEvents = getRbacAuditEvents({ status: "FAILURE" });

      expect(successEvents.length).toBeGreaterThan(0);
      expect(failureEvents.length).toBeGreaterThan(0);
    });
  });
});
