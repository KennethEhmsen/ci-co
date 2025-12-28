/**
 * Team Management Tests
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  initTeamDatabase,
  closeTeamDatabase,
  isTeamDbInitialized,
  createOrganization,
  getOrganization,
  getOrganizationByName,
  listOrganizations,
  updateOrganization,
  deleteOrganization,
  createTeam,
  getTeam,
  getTeamByName,
  listTeams,
  updateTeam,
  deleteTeam,
  addTeamMember,
  removeTeamMember,
  updateTeamMemberRole,
  getTeamMember,
  listTeamMembers,
  getUserTeamMemberships,
  isTeamMember,
  hasTeamRole,
  getTeamAuditEvents,
  cleanupExpiredMemberships,
  cleanupTeamAuditEvents,
  getTeamStats,
} from "./team-manager.js";

describe("Team Management", () => {
  let testDbPath: string;

  beforeEach(() => {
    // Create a unique temp database for each test
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "team-test-"));
    testDbPath = path.join(tempDir, "teams.db");
  });

  afterEach(() => {
    closeTeamDatabase();
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
      const result = initTeamDatabase(testDbPath);
      expect(result.success).toBe(true);
      expect(result.created).toBe(true);
      expect(result.path).toBe(testDbPath);
      expect(isTeamDbInitialized()).toBe(true);
    });

    it("should return existing database on re-initialization", () => {
      const first = initTeamDatabase(testDbPath);
      expect(first.created).toBe(true);

      const second = initTeamDatabase(testDbPath);
      expect(second.success).toBe(true);
      expect(second.created).toBe(false);
    });

    it("should close database", () => {
      initTeamDatabase(testDbPath);
      expect(isTeamDbInitialized()).toBe(true);

      closeTeamDatabase();
      expect(isTeamDbInitialized()).toBe(false);
    });
  });

  describe("Organization Management", () => {
    beforeEach(() => {
      initTeamDatabase(testDbPath);
    });

    it("should create an organization", () => {
      const org = createOrganization({
        name: "test-org",
        displayName: "Test Organization",
        description: "A test organization",
        ownerId: "user-1",
      });

      expect(org.name).toBe("test-org");
      expect(org.displayName).toBe("Test Organization");
      expect(org.ownerId).toBe("user-1");
      expect(org.id).toBeDefined();
    });

    it("should get an organization by ID", () => {
      const created = createOrganization({
        name: "get-test-org",
        ownerId: "user-1",
      });

      const retrieved = getOrganization(created.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.name).toBe("get-test-org");
    });

    it("should get an organization by name", () => {
      createOrganization({
        name: "name-test-org",
        ownerId: "user-1",
      });

      const retrieved = getOrganizationByName("name-test-org");
      expect(retrieved).not.toBeNull();
      expect(retrieved?.name).toBe("name-test-org");
    });

    it("should return null for non-existent organization", () => {
      const retrieved = getOrganization("non-existent-id");
      expect(retrieved).toBeNull();
    });

    it("should list organizations", () => {
      createOrganization({ name: "org-1", ownerId: "user-1" });
      createOrganization({ name: "org-2", ownerId: "user-2" });
      createOrganization({ name: "org-3", ownerId: "user-1" });

      const allOrgs = listOrganizations();
      expect(allOrgs.length).toBe(3);
    });

    it("should filter organizations by owner", () => {
      createOrganization({ name: "org-1", ownerId: "user-1" });
      createOrganization({ name: "org-2", ownerId: "user-2" });
      createOrganization({ name: "org-3", ownerId: "user-1" });

      const user1Orgs = listOrganizations({ ownerId: "user-1" });
      expect(user1Orgs.length).toBe(2);
    });

    it("should update an organization", () => {
      const org = createOrganization({
        name: "update-test-org",
        ownerId: "user-1",
      });

      const updated = updateOrganization(org.id, {
        displayName: "Updated Display Name",
        description: "Updated description",
      });

      expect(updated?.displayName).toBe("Updated Display Name");
      expect(updated?.description).toBe("Updated description");
    });

    it("should delete an organization", () => {
      const org = createOrganization({
        name: "delete-test-org",
        ownerId: "user-1",
      });

      const deleted = deleteOrganization(org.id);
      expect(deleted).toBe(true);

      const retrieved = getOrganization(org.id);
      expect(retrieved).toBeNull();
    });

    it("should reject duplicate organization names", () => {
      createOrganization({ name: "unique-org", ownerId: "user-1" });

      expect(() => createOrganization({ name: "unique-org", ownerId: "user-2" })).toThrow();
    });
  });

  describe("Team Management", () => {
    let orgId: string;

    beforeEach(() => {
      initTeamDatabase(testDbPath);
      const org = createOrganization({
        name: "team-test-org",
        ownerId: "user-1",
      });
      orgId = org.id;
    });

    it("should create a team", () => {
      const team = createTeam({
        organizationId: orgId,
        name: "test-team",
        displayName: "Test Team",
        description: "A test team",
        visibility: "private",
        createdBy: "user-1",
      });

      expect(team.name).toBe("test-team");
      expect(team.displayName).toBe("Test Team");
      expect(team.organizationId).toBe(orgId);
      expect(team.visibility).toBe("private");
    });

    it("should get a team by ID", () => {
      const created = createTeam({
        organizationId: orgId,
        name: "get-test-team",
      });

      const retrieved = getTeam(created.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.name).toBe("get-test-team");
    });

    it("should get a team by name within org", () => {
      createTeam({
        organizationId: orgId,
        name: "name-test-team",
      });

      const retrieved = getTeamByName(orgId, "name-test-team");
      expect(retrieved).not.toBeNull();
      expect(retrieved?.name).toBe("name-test-team");
    });

    it("should list teams", () => {
      createTeam({ organizationId: orgId, name: "team-1" });
      createTeam({ organizationId: orgId, name: "team-2" });
      createTeam({ organizationId: orgId, name: "team-3" });

      const allTeams = listTeams({ organizationId: orgId });
      expect(allTeams.length).toBe(3);
    });

    it("should filter teams by visibility", () => {
      createTeam({ organizationId: orgId, name: "public-team", visibility: "public" });
      createTeam({ organizationId: orgId, name: "private-team-1", visibility: "private" });
      createTeam({ organizationId: orgId, name: "private-team-2", visibility: "private" });

      const publicTeams = listTeams({ organizationId: orgId, visibility: "public" });
      expect(publicTeams.length).toBe(1);

      const privateTeams = listTeams({ organizationId: orgId, visibility: "private" });
      expect(privateTeams.length).toBe(2);
    });

    it("should update a team", () => {
      const team = createTeam({
        organizationId: orgId,
        name: "update-test-team",
      });

      const updated = updateTeam(team.id, {
        displayName: "Updated Team Name",
        visibility: "public",
      });

      expect(updated?.displayName).toBe("Updated Team Name");
      expect(updated?.visibility).toBe("public");
    });

    it("should delete a team", () => {
      const team = createTeam({
        organizationId: orgId,
        name: "delete-test-team",
      });

      const deleted = deleteTeam(team.id);
      expect(deleted).toBe(true);

      const retrieved = getTeam(team.id);
      expect(retrieved).toBeNull();
    });

    it("should cascade delete teams when org is deleted", () => {
      const team = createTeam({
        organizationId: orgId,
        name: "cascade-test-team",
      });

      deleteOrganization(orgId);

      const retrieved = getTeam(team.id);
      expect(retrieved).toBeNull();
    });
  });

  describe("Team Membership", () => {
    let orgId: string;
    let teamId: string;

    beforeEach(() => {
      initTeamDatabase(testDbPath);
      const org = createOrganization({
        name: "member-test-org",
        ownerId: "user-1",
      });
      orgId = org.id;
      const team = createTeam({
        organizationId: orgId,
        name: "member-test-team",
      });
      teamId = team.id;
    });

    it("should add a member to a team", () => {
      const member = addTeamMember({
        teamId,
        userId: "user-2",
        role: "member",
        addedBy: "user-1",
      });

      expect(member.userId).toBe("user-2");
      expect(member.teamId).toBe(teamId);
      expect(member.role).toBe("member");
    });

    it("should check if user is a team member", () => {
      addTeamMember({
        teamId,
        userId: "user-2",
        role: "member",
      });

      expect(isTeamMember(teamId, "user-2")).toBe(true);
      expect(isTeamMember(teamId, "user-3")).toBe(false);
    });

    it("should check team role hierarchy", () => {
      addTeamMember({
        teamId,
        userId: "user-owner",
        role: "owner",
      });
      addTeamMember({
        teamId,
        userId: "user-admin",
        role: "admin",
      });
      addTeamMember({
        teamId,
        userId: "user-member",
        role: "member",
      });
      addTeamMember({
        teamId,
        userId: "user-viewer",
        role: "viewer",
      });

      // Owner has all roles
      expect(hasTeamRole(teamId, "user-owner", "owner")).toBe(true);
      expect(hasTeamRole(teamId, "user-owner", "admin")).toBe(true);
      expect(hasTeamRole(teamId, "user-owner", "member")).toBe(true);
      expect(hasTeamRole(teamId, "user-owner", "viewer")).toBe(true);

      // Admin has admin and below
      expect(hasTeamRole(teamId, "user-admin", "owner")).toBe(false);
      expect(hasTeamRole(teamId, "user-admin", "admin")).toBe(true);
      expect(hasTeamRole(teamId, "user-admin", "member")).toBe(true);
      expect(hasTeamRole(teamId, "user-admin", "viewer")).toBe(true);

      // Member has member and below
      expect(hasTeamRole(teamId, "user-member", "admin")).toBe(false);
      expect(hasTeamRole(teamId, "user-member", "member")).toBe(true);
      expect(hasTeamRole(teamId, "user-member", "viewer")).toBe(true);

      // Viewer has only viewer
      expect(hasTeamRole(teamId, "user-viewer", "member")).toBe(false);
      expect(hasTeamRole(teamId, "user-viewer", "viewer")).toBe(true);
    });

    it("should update team member role", () => {
      addTeamMember({
        teamId,
        userId: "user-2",
        role: "member",
      });

      const updated = updateTeamMemberRole(teamId, "user-2", "admin", "user-1");
      expect(updated?.role).toBe("admin");
    });

    it("should remove a team member", () => {
      addTeamMember({
        teamId,
        userId: "user-2",
        role: "member",
      });

      const removed = removeTeamMember(teamId, "user-2", "user-1");
      expect(removed).toBe(true);

      expect(isTeamMember(teamId, "user-2")).toBe(false);
    });

    it("should list team members", () => {
      addTeamMember({ teamId, userId: "user-2", role: "admin" });
      addTeamMember({ teamId, userId: "user-3", role: "member" });
      addTeamMember({ teamId, userId: "user-4", role: "viewer" });

      const members = listTeamMembers(teamId);
      expect(members.length).toBe(3);
    });

    it("should get user team memberships", () => {
      const team2 = createTeam({ organizationId: orgId, name: "team-2" });

      addTeamMember({ teamId, userId: "user-2", role: "member" });
      addTeamMember({ teamId: team2.id, userId: "user-2", role: "admin" });

      const memberships = getUserTeamMemberships("user-2");
      expect(memberships.length).toBe(2);
    });

    it("should add member with expiration", () => {
      const futureDate = new Date(Date.now() + 86400000).toISOString(); // 1 day from now

      const member = addTeamMember({
        teamId,
        userId: "user-temp",
        role: "member",
        expiresAt: futureDate,
      });

      expect(member.expiresAt).toBe(futureDate);
    });

    it("should cascade delete members when team is deleted", () => {
      addTeamMember({
        teamId,
        userId: "user-2",
        role: "member",
      });

      deleteTeam(teamId);

      const member = getTeamMember(teamId, "user-2");
      expect(member).toBeNull();
    });
  });

  describe("Audit Events", () => {
    let orgId: string;
    let teamId: string;

    beforeEach(() => {
      initTeamDatabase(testDbPath);
      const org = createOrganization({
        name: "audit-test-org",
        ownerId: "user-1",
      });
      orgId = org.id;
      const team = createTeam({
        organizationId: orgId,
        name: "audit-test-team",
        createdBy: "user-1",
      });
      teamId = team.id;
    });

    it("should log organization creation", () => {
      const events = getTeamAuditEvents({ eventType: "ORG_CREATED" });
      expect(events.length).toBeGreaterThan(0);
    });

    it("should log team creation", () => {
      const events = getTeamAuditEvents({ eventType: "TEAM_CREATED" });
      expect(events.length).toBeGreaterThan(0);
    });

    it("should log member addition", () => {
      addTeamMember({
        teamId,
        userId: "user-2",
        role: "member",
        addedBy: "user-1",
      });

      const events = getTeamAuditEvents({ eventType: "MEMBER_ADDED" });
      expect(events.length).toBeGreaterThan(0);
    });

    it("should log role changes", () => {
      addTeamMember({
        teamId,
        userId: "user-2",
        role: "member",
      });

      updateTeamMemberRole(teamId, "user-2", "admin", "user-1");

      const events = getTeamAuditEvents({ eventType: "MEMBER_ROLE_CHANGED" });
      expect(events.length).toBeGreaterThan(0);
    });
  });

  describe("Maintenance", () => {
    beforeEach(() => {
      initTeamDatabase(testDbPath);
    });

    it("should cleanup expired memberships", () => {
      const org = createOrganization({
        name: "cleanup-test-org",
        ownerId: "user-1",
      });
      const team = createTeam({
        organizationId: org.id,
        name: "cleanup-test-team",
      });

      const pastDate = new Date(Date.now() - 1000).toISOString();
      addTeamMember({
        teamId: team.id,
        userId: "user-expired",
        role: "member",
        expiresAt: pastDate,
      });

      const cleaned = cleanupExpiredMemberships();
      expect(cleaned).toBeGreaterThanOrEqual(1);

      expect(isTeamMember(team.id, "user-expired")).toBe(false);
    });

    it("should cleanup old audit events", () => {
      // Create an org to generate audit events
      createOrganization({
        name: "audit-cleanup-org",
        ownerId: "user-1",
      });

      // Cleanup with -1 days (future date) to remove all logs
      const cleaned = cleanupTeamAuditEvents(-1);
      expect(cleaned).toBeGreaterThan(0);
    });

    it("should get team stats", () => {
      const org = createOrganization({
        name: "stats-test-org",
        ownerId: "user-1",
      });
      const team1 = createTeam({ organizationId: org.id, name: "stats-team-1" });
      createTeam({ organizationId: org.id, name: "stats-team-2" });

      addTeamMember({ teamId: team1.id, userId: "user-2", role: "member" });
      addTeamMember({ teamId: team1.id, userId: "user-3", role: "admin" });

      const stats = getTeamStats();
      expect(stats.totalOrganizations).toBeGreaterThanOrEqual(1);
      expect(stats.totalTeams).toBeGreaterThanOrEqual(2);
      expect(stats.totalMemberships).toBeGreaterThanOrEqual(2);
    });
  });
});
