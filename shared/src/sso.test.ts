/**
 * SSO Module Tests
 *
 * Tests for SSO configuration, session management, and audit logging.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

import {
  initSsoDatabase,
  closeSsoDatabase,
  isSsoDbInitialized,
  configureSamlProvider,
  configureOidcProvider,
  getSsoProvider,
  getSamlProvider,
  getOidcProvider,
  listSsoProviders,
  deleteSsoProvider,
  setSsoProviderEnabled,
  getSsoProviderByIssuer,
  createSsoSession,
  getSsoSession,
  validateSsoSession,
  terminateSsoSession,
  terminateAllUserSessions,
  listUserSessions,
  listAllSessions,
  cleanupExpiredSessions,
  updateSessionTokens,
  logSsoAudit,
  getSsoAuditEvents,
  cleanupOldAuditEvents,
} from "./sso-config.js";

import { generateSpMetadata, clearSamlInstanceCache } from "./sso-saml.js";

import { discoverOidcProvider, clearJwksCache, clearDiscoveryCache } from "./sso-oidc.js";

// =============================================================================
// Test Fixtures
// =============================================================================

const testDbPath = path.join(os.tmpdir(), `sso-test-${Date.now()}.db`);

const testSamlConfig = {
  name: "Test SAML Provider",
  enabled: true,
  idpCertificate: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
  idpSsoUrl: "https://idp.example.com/sso",
  idpSloUrl: "https://idp.example.com/slo",
  spEntityId: "https://sp.example.com/metadata",
  spAcsUrl: "https://sp.example.com/acs",
  spSloUrl: "https://sp.example.com/slo",
  wantAssertionsSigned: true,
  wantResponseSigned: false,
  attributeMapping: {
    email: "email",
    name: "displayName",
    groups: "memberOf",
  },
};

const testOidcConfig = {
  name: "Test OIDC Provider",
  enabled: true,
  issuer: "https://idp.example.com",
  discoveryUrl: "https://idp.example.com/.well-known/openid-configuration",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  redirectUri: "https://sp.example.com/callback",
  scopes: ["openid", "profile", "email"],
  attributeMapping: {
    email: "email",
    name: "name",
    groups: "groups",
  },
};

// =============================================================================
// Database Lifecycle Tests
// =============================================================================

describe("SSO Database", () => {
  beforeEach(() => {
    closeSsoDatabase();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
  });

  afterEach(() => {
    closeSsoDatabase();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
  });

  describe("initSsoDatabase", () => {
    it("should initialize a new database", () => {
      const result = initSsoDatabase(testDbPath);

      expect(result.success).toBe(true);
      expect(result.path).toBe(testDbPath);
      expect(result.created).toBe(true);
      expect(isSsoDbInitialized()).toBe(true);
    });

    it("should return existing database if already initialized", () => {
      initSsoDatabase(testDbPath);
      const result = initSsoDatabase(testDbPath);

      expect(result.success).toBe(true);
      expect(result.created).toBe(false);
    });

    it("should create parent directories if they don't exist", () => {
      const nestedPath = path.join(os.tmpdir(), "sso-test-nested", "subdir", "sso.db");
      const result = initSsoDatabase(nestedPath);

      expect(result.success).toBe(true);
      expect(fs.existsSync(nestedPath)).toBe(true);

      // Cleanup
      closeSsoDatabase();
      fs.unlinkSync(nestedPath);
      fs.rmdirSync(path.dirname(nestedPath));
      fs.rmdirSync(path.dirname(path.dirname(nestedPath)));
    });
  });

  describe("closeSsoDatabase", () => {
    it("should close the database", () => {
      initSsoDatabase(testDbPath);
      expect(isSsoDbInitialized()).toBe(true);

      closeSsoDatabase();
      expect(isSsoDbInitialized()).toBe(false);
    });

    it("should handle closing when not initialized", () => {
      expect(() => closeSsoDatabase()).not.toThrow();
    });
  });

  describe("isSsoDbInitialized", () => {
    it("should return false when not initialized", () => {
      expect(isSsoDbInitialized()).toBe(false);
    });

    it("should return true when initialized", () => {
      initSsoDatabase(testDbPath);
      expect(isSsoDbInitialized()).toBe(true);
    });
  });
});

// =============================================================================
// Provider Configuration Tests
// =============================================================================

describe("SSO Provider Configuration", () => {
  beforeEach(() => {
    closeSsoDatabase();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
    initSsoDatabase(testDbPath);
  });

  afterEach(() => {
    closeSsoDatabase();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
    clearSamlInstanceCache();
  });

  describe("configureSamlProvider", () => {
    it("should create a new SAML provider", () => {
      const result = configureSamlProvider(testSamlConfig);

      expect(result.id).toBeDefined();
      expect(result.name).toBe(testSamlConfig.name);
      expect(result.enabled).toBe(true);
      expect(result.idpSsoUrl).toBe(testSamlConfig.idpSsoUrl);
      expect(result.createdAt).toBeDefined();
      expect(result.updatedAt).toBeDefined();
    });

    it("should use provided id", () => {
      const result = configureSamlProvider({ ...testSamlConfig, id: "custom-saml-id" });

      expect(result.id).toBe("custom-saml-id");
    });

    it("should update existing provider", () => {
      configureSamlProvider({ ...testSamlConfig, id: "update-test" });
      const second = configureSamlProvider({
        ...testSamlConfig,
        id: "update-test",
        name: "Updated Name",
      });

      expect(second.id).toBe("update-test");
      expect(second.name).toBe("Updated Name");
    });
  });

  describe("configureOidcProvider", () => {
    it("should create a new OIDC provider", () => {
      const result = configureOidcProvider(testOidcConfig);

      expect(result.id).toBeDefined();
      expect(result.name).toBe(testOidcConfig.name);
      expect(result.issuer).toBe(testOidcConfig.issuer);
      expect(result.clientId).toBe(testOidcConfig.clientId);
    });

    it("should use provided id", () => {
      const result = configureOidcProvider({ ...testOidcConfig, id: "custom-oidc-id" });

      expect(result.id).toBe("custom-oidc-id");
    });
  });

  describe("getSsoProvider", () => {
    it("should return SAML provider", () => {
      const created = configureSamlProvider(testSamlConfig);
      const result = getSsoProvider(created.id);

      expect(result).not.toBeNull();
      expect(result!.type).toBe("saml");
      expect(result!.config.id).toBe(created.id);
    });

    it("should return OIDC provider", () => {
      const created = configureOidcProvider(testOidcConfig);
      const result = getSsoProvider(created.id);

      expect(result).not.toBeNull();
      expect(result!.type).toBe("oidc");
      expect(result!.config.id).toBe(created.id);
    });

    it("should return null for non-existent provider", () => {
      const result = getSsoProvider("non-existent-id");

      expect(result).toBeNull();
    });
  });

  describe("getSamlProvider", () => {
    it("should return SAML provider", () => {
      const created = configureSamlProvider(testSamlConfig);
      const result = getSamlProvider(created.id);

      expect(result).not.toBeNull();
      expect(result!.id).toBe(created.id);
    });

    it("should return null for OIDC provider", () => {
      const created = configureOidcProvider(testOidcConfig);
      const result = getSamlProvider(created.id);

      expect(result).toBeNull();
    });
  });

  describe("getOidcProvider", () => {
    it("should return OIDC provider", () => {
      const created = configureOidcProvider(testOidcConfig);
      const result = getOidcProvider(created.id);

      expect(result).not.toBeNull();
      expect(result!.id).toBe(created.id);
    });

    it("should return null for SAML provider", () => {
      const created = configureSamlProvider(testSamlConfig);
      const result = getOidcProvider(created.id);

      expect(result).toBeNull();
    });
  });

  describe("listSsoProviders", () => {
    it("should return empty array when no providers", () => {
      const result = listSsoProviders();

      expect(result).toEqual([]);
    });

    it("should return all providers", () => {
      configureSamlProvider(testSamlConfig);
      configureOidcProvider(testOidcConfig);

      const result = listSsoProviders();

      expect(result.length).toBe(2);
      expect(result.some((p) => p.type === "saml")).toBe(true);
      expect(result.some((p) => p.type === "oidc")).toBe(true);
    });

    it("should include issuer for OIDC and spEntityId for SAML", () => {
      const saml = configureSamlProvider(testSamlConfig);
      const oidc = configureOidcProvider(testOidcConfig);

      const result = listSsoProviders();

      const samlProvider = result.find((p) => p.id === saml.id);
      const oidcProvider = result.find((p) => p.id === oidc.id);

      expect(samlProvider?.issuer).toBe(testSamlConfig.spEntityId);
      expect(oidcProvider?.issuer).toBe(testOidcConfig.issuer);
    });
  });

  describe("deleteSsoProvider", () => {
    it("should delete existing provider", () => {
      const created = configureSamlProvider(testSamlConfig);
      const result = deleteSsoProvider(created.id);

      expect(result).toBe(true);
      expect(getSsoProvider(created.id)).toBeNull();
    });

    it("should return false for non-existent provider", () => {
      const result = deleteSsoProvider("non-existent-id");

      expect(result).toBe(false);
    });
  });

  describe("setSsoProviderEnabled", () => {
    it("should disable provider", () => {
      const created = configureSamlProvider(testSamlConfig);
      const result = setSsoProviderEnabled(created.id, false);

      expect(result).toBe(true);

      const provider = getSamlProvider(created.id);
      expect(provider?.enabled).toBe(false);
    });

    it("should enable provider", () => {
      const created = configureSamlProvider({ ...testSamlConfig, enabled: false });
      const result = setSsoProviderEnabled(created.id, true);

      expect(result).toBe(true);

      const provider = getSamlProvider(created.id);
      expect(provider?.enabled).toBe(true);
    });

    it("should return false for non-existent provider", () => {
      const result = setSsoProviderEnabled("non-existent-id", true);

      expect(result).toBe(false);
    });
  });

  describe("getSsoProviderByIssuer", () => {
    it("should find OIDC provider by issuer", () => {
      configureOidcProvider(testOidcConfig);
      const result = getSsoProviderByIssuer(testOidcConfig.issuer);

      expect(result).not.toBeNull();
      expect(result!.issuer).toBe(testOidcConfig.issuer);
    });

    it("should return null for unknown issuer", () => {
      const result = getSsoProviderByIssuer("https://unknown.example.com");

      expect(result).toBeNull();
    });

    it("should not find disabled provider", () => {
      configureOidcProvider({ ...testOidcConfig, enabled: false });
      const result = getSsoProviderByIssuer(testOidcConfig.issuer);

      expect(result).toBeNull();
    });
  });
});

// =============================================================================
// Session Management Tests
// =============================================================================

describe("SSO Session Management", () => {
  beforeEach(() => {
    closeSsoDatabase();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
    initSsoDatabase(testDbPath);
    configureSamlProvider({ ...testSamlConfig, id: "test-saml-provider" });
    configureOidcProvider({ ...testOidcConfig, id: "test-oidc-provider" });
  });

  afterEach(() => {
    closeSsoDatabase();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
  });

  describe("createSsoSession", () => {
    it("should create a new session", () => {
      const session = createSsoSession({
        providerId: "test-saml-provider",
        providerType: "saml",
        userId: "user123",
        email: "user@example.com",
        name: "Test User",
        groups: ["admin", "users"],
        claims: { nameID: "user123" },
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      });

      expect(session.id).toBeDefined();
      expect(session.userId).toBe("user123");
      expect(session.email).toBe("user@example.com");
      expect(session.groups).toEqual(["admin", "users"]);
      expect(session.createdAt).toBeDefined();
      expect(session.lastActivityAt).toBeDefined();
    });

    it("should create session with tokens", () => {
      const session = createSsoSession({
        providerId: "test-oidc-provider",
        providerType: "oidc",
        userId: "user456",
        email: "user2@example.com",
        name: "Test User 2",
        groups: [],
        claims: { sub: "user456" },
        accessToken: "access-token-123",
        refreshToken: "refresh-token-456",
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      });

      expect(session.accessToken).toBe("access-token-123");
      expect(session.refreshToken).toBe("refresh-token-456");
    });
  });

  describe("getSsoSession", () => {
    it("should return existing session", () => {
      const created = createSsoSession({
        providerId: "test-saml-provider",
        providerType: "saml",
        userId: "user123",
        email: "user@example.com",
        name: "Test User",
        groups: [],
        claims: {},
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      });

      const session = getSsoSession(created.id);

      expect(session).not.toBeNull();
      expect(session!.id).toBe(created.id);
      expect(session!.userId).toBe("user123");
    });

    it("should return null for non-existent session", () => {
      const session = getSsoSession("non-existent-session-id");

      expect(session).toBeNull();
    });
  });

  describe("validateSsoSession", () => {
    it("should validate active session", () => {
      const created = createSsoSession({
        providerId: "test-saml-provider",
        providerType: "saml",
        userId: "user123",
        email: "user@example.com",
        name: "Test User",
        groups: [],
        claims: {},
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      });

      const result = validateSsoSession(created.id);

      expect(result.valid).toBe(true);
      expect(result.session).toBeDefined();
      expect(result.session!.id).toBe(created.id);
    });

    it("should reject expired session", () => {
      const created = createSsoSession({
        providerId: "test-saml-provider",
        providerType: "saml",
        userId: "user123",
        email: "user@example.com",
        name: "Test User",
        groups: [],
        claims: {},
        expiresAt: new Date(Date.now() - 1000).toISOString(), // Already expired
      });

      const result = validateSsoSession(created.id);

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Session expired");
    });

    it("should reject non-existent session", () => {
      const result = validateSsoSession("non-existent-session-id");

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Session not found");
    });
  });

  describe("terminateSsoSession", () => {
    it("should terminate existing session", () => {
      const created = createSsoSession({
        providerId: "test-saml-provider",
        providerType: "saml",
        userId: "user123",
        email: "user@example.com",
        name: "Test User",
        groups: [],
        claims: {},
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      });

      const result = terminateSsoSession(created.id);

      expect(result).toBe(true);
      expect(getSsoSession(created.id)).toBeNull();
    });

    it("should return false for non-existent session", () => {
      const result = terminateSsoSession("non-existent-session-id");

      expect(result).toBe(false);
    });
  });

  describe("terminateAllUserSessions", () => {
    it("should terminate all sessions for a user", () => {
      createSsoSession({
        providerId: "test-saml-provider",
        providerType: "saml",
        userId: "user123",
        email: "user@example.com",
        name: "Test User",
        groups: [],
        claims: {},
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      });

      createSsoSession({
        providerId: "test-oidc-provider",
        providerType: "oidc",
        userId: "user123",
        email: "user@example.com",
        name: "Test User",
        groups: [],
        claims: {},
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      });

      const count = terminateAllUserSessions("user123");

      expect(count).toBe(2);
      expect(listUserSessions("user123").length).toBe(0);
    });

    it("should return 0 when user has no sessions", () => {
      const count = terminateAllUserSessions("non-existent-user");

      expect(count).toBe(0);
    });
  });

  describe("listUserSessions", () => {
    it("should list user sessions", () => {
      createSsoSession({
        providerId: "test-saml-provider",
        providerType: "saml",
        userId: "user123",
        email: "user@example.com",
        name: "Test User",
        groups: [],
        claims: {},
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      });

      createSsoSession({
        providerId: "test-oidc-provider",
        providerType: "oidc",
        userId: "user456",
        email: "user2@example.com",
        name: "Test User 2",
        groups: [],
        claims: {},
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      });

      const sessions = listUserSessions("user123");

      expect(sessions.length).toBe(1);
      expect(sessions[0].userId).toBe("user123");
    });

    it("should not include expired sessions", () => {
      createSsoSession({
        providerId: "test-saml-provider",
        providerType: "saml",
        userId: "user123",
        email: "user@example.com",
        name: "Test User",
        groups: [],
        claims: {},
        expiresAt: new Date(Date.now() - 1000).toISOString(), // Already expired
      });

      const sessions = listUserSessions("user123");

      expect(sessions.length).toBe(0);
    });
  });

  describe("listAllSessions", () => {
    it("should list all active sessions", () => {
      createSsoSession({
        providerId: "test-saml-provider",
        providerType: "saml",
        userId: "user123",
        email: "user@example.com",
        name: "Test User",
        groups: [],
        claims: {},
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      });

      createSsoSession({
        providerId: "test-oidc-provider",
        providerType: "oidc",
        userId: "user456",
        email: "user2@example.com",
        name: "Test User 2",
        groups: [],
        claims: {},
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      });

      const sessions = listAllSessions();

      expect(sessions.length).toBe(2);
    });
  });

  describe("cleanupExpiredSessions", () => {
    it("should remove expired sessions", () => {
      createSsoSession({
        providerId: "test-saml-provider",
        providerType: "saml",
        userId: "user123",
        email: "user@example.com",
        name: "Test User",
        groups: [],
        claims: {},
        expiresAt: new Date(Date.now() - 1000).toISOString(), // Already expired
      });

      createSsoSession({
        providerId: "test-oidc-provider",
        providerType: "oidc",
        userId: "user456",
        email: "user2@example.com",
        name: "Test User 2",
        groups: [],
        claims: {},
        expiresAt: new Date(Date.now() + 3600000).toISOString(), // Still valid
      });

      const removed = cleanupExpiredSessions();

      expect(removed).toBe(1);
    });
  });

  describe("updateSessionTokens", () => {
    it("should update session tokens", () => {
      const created = createSsoSession({
        providerId: "test-oidc-provider",
        providerType: "oidc",
        userId: "user123",
        email: "user@example.com",
        name: "Test User",
        groups: [],
        claims: {},
        accessToken: "old-access-token",
        refreshToken: "old-refresh-token",
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      });

      const result = updateSessionTokens(created.id, "new-access-token", "new-refresh-token");

      expect(result).toBe(true);

      const session = getSsoSession(created.id);
      expect(session!.accessToken).toBe("new-access-token");
      expect(session!.refreshToken).toBe("new-refresh-token");
    });

    it("should update only access token", () => {
      const created = createSsoSession({
        providerId: "test-oidc-provider",
        providerType: "oidc",
        userId: "user123",
        email: "user@example.com",
        name: "Test User",
        groups: [],
        claims: {},
        accessToken: "old-access-token",
        refreshToken: "old-refresh-token",
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      });

      const result = updateSessionTokens(created.id, "new-access-token");

      expect(result).toBe(true);

      const session = getSsoSession(created.id);
      expect(session!.accessToken).toBe("new-access-token");
      expect(session!.refreshToken).toBe("old-refresh-token");
    });

    it("should return false for non-existent session", () => {
      const result = updateSessionTokens("non-existent-session", "token");

      expect(result).toBe(false);
    });
  });
});

// =============================================================================
// Audit Logging Tests
// =============================================================================

describe("SSO Audit Logging", () => {
  beforeEach(() => {
    closeSsoDatabase();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
    initSsoDatabase(testDbPath);
  });

  afterEach(() => {
    closeSsoDatabase();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
  });

  describe("logSsoAudit", () => {
    it("should log audit event", () => {
      logSsoAudit({
        eventType: "LOGIN",
        providerId: "test-provider",
        userId: "user123",
        email: "user@example.com",
        status: "SUCCESS",
      });

      const events = getSsoAuditEvents();

      expect(events.length).toBe(1);
      expect(events[0].eventType).toBe("LOGIN");
      expect(events[0].userId).toBe("user123");
      expect(events[0].status).toBe("SUCCESS");
    });

    it("should log audit event with details", () => {
      logSsoAudit({
        eventType: "TOKEN_VALIDATION",
        providerId: "test-provider",
        status: "FAILURE",
        errorMessage: "Invalid token",
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla/5.0",
        details: { reason: "expired" },
      });

      const events = getSsoAuditEvents();

      expect(events[0].errorMessage).toBe("Invalid token");
      expect(events[0].ipAddress).toBe("192.168.1.1");
      expect(events[0].details).toEqual({ reason: "expired" });
    });
  });

  describe("getSsoAuditEvents", () => {
    beforeEach(() => {
      // Create some audit events
      logSsoAudit({
        eventType: "LOGIN",
        providerId: "provider1",
        userId: "user123",
        status: "SUCCESS",
      });
      logSsoAudit({
        eventType: "LOGIN",
        providerId: "provider2",
        userId: "user456",
        status: "SUCCESS",
      });
      logSsoAudit({
        eventType: "LOGOUT",
        providerId: "provider1",
        userId: "user123",
        status: "SUCCESS",
      });
      logSsoAudit({
        eventType: "TOKEN_VALIDATION",
        providerId: "provider1",
        userId: "user789",
        status: "FAILURE",
        errorMessage: "Invalid token",
      });
    });

    it("should return all events", () => {
      const events = getSsoAuditEvents();

      expect(events.length).toBe(4);
    });

    it("should filter by userId", () => {
      const events = getSsoAuditEvents({ userId: "user123" });

      expect(events.length).toBe(2);
      expect(events.every((e) => e.userId === "user123")).toBe(true);
    });

    it("should filter by providerId", () => {
      const events = getSsoAuditEvents({ providerId: "provider1" });

      expect(events.length).toBe(3);
      expect(events.every((e) => e.providerId === "provider1")).toBe(true);
    });

    it("should filter by eventType", () => {
      const events = getSsoAuditEvents({ eventType: "LOGIN" });

      expect(events.length).toBe(2);
      expect(events.every((e) => e.eventType === "LOGIN")).toBe(true);
    });

    it("should filter by status", () => {
      const events = getSsoAuditEvents({ status: "FAILURE" });

      expect(events.length).toBe(1);
      expect(events[0].status).toBe("FAILURE");
    });

    it("should limit results", () => {
      const events = getSsoAuditEvents({ limit: 2 });

      expect(events.length).toBe(2);
    });

    it("should support offset", () => {
      const allEvents = getSsoAuditEvents();
      const offsetEvents = getSsoAuditEvents({ offset: 2 });

      expect(offsetEvents.length).toBe(2);
      expect(offsetEvents[0].id).toBe(allEvents[2].id);
    });
  });

  describe("cleanupOldAuditEvents", () => {
    it("should not delete recent events", () => {
      logSsoAudit({
        eventType: "LOGIN",
        providerId: "test-provider",
        userId: "user123",
        status: "SUCCESS",
      });

      const deleted = cleanupOldAuditEvents(90);

      expect(deleted).toBe(0);
      expect(getSsoAuditEvents().length).toBe(1);
    });
  });
});

// =============================================================================
// SAML Metadata Tests
// =============================================================================

describe("SAML SP Metadata", () => {
  beforeEach(() => {
    closeSsoDatabase();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
    initSsoDatabase(testDbPath);
    clearSamlInstanceCache();
  });

  afterEach(() => {
    closeSsoDatabase();
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
    clearSamlInstanceCache();
  });

  describe("generateSpMetadata", () => {
    it("should generate valid metadata XML", () => {
      const provider = configureSamlProvider(testSamlConfig);
      const result = generateSpMetadata(provider.id);

      expect(result).not.toBeNull();
      expect(result!.xml).toContain("<?xml version");
      expect(result!.xml).toContain("md:EntityDescriptor");
      expect(result!.xml).toContain(testSamlConfig.spEntityId);
      expect(result!.entityId).toBe(testSamlConfig.spEntityId);
      expect(result!.acsUrl).toBe(testSamlConfig.spAcsUrl);
    });

    it("should include ACS URL in metadata", () => {
      const provider = configureSamlProvider(testSamlConfig);
      const result = generateSpMetadata(provider.id);

      expect(result!.xml).toContain("AssertionConsumerService");
      expect(result!.xml).toContain(testSamlConfig.spAcsUrl);
    });

    it("should include SLO URL when configured", () => {
      const provider = configureSamlProvider(testSamlConfig);
      const result = generateSpMetadata(provider.id);

      expect(result!.xml).toContain("SingleLogoutService");
      expect(result!.xml).toContain(testSamlConfig.spSloUrl);
    });

    it("should return null for non-existent provider", () => {
      const result = generateSpMetadata("non-existent-id");

      expect(result).toBeNull();
    });
  });
});

// =============================================================================
// OIDC Discovery Tests
// =============================================================================

describe("OIDC Discovery", () => {
  beforeEach(() => {
    clearDiscoveryCache();
  });

  afterEach(() => {
    clearJwksCache();
    clearDiscoveryCache();
    vi.restoreAllMocks();
  });

  describe("discoverOidcProvider", () => {
    it("should fetch discovery document", async () => {
      const mockDiscovery = {
        issuer: "https://idp1.example.com",
        authorization_endpoint: "https://idp1.example.com/authorize",
        token_endpoint: "https://idp1.example.com/token",
        jwks_uri: "https://idp1.example.com/.well-known/jwks.json",
      };

      vi.spyOn(global, "fetch").mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockDiscovery),
      } as Response);

      const result = await discoverOidcProvider(
        "https://idp1.example.com/.well-known/openid-configuration"
      );

      expect(result).not.toBeNull();
      expect(result!.issuer).toBe("https://idp1.example.com");
      expect(result!.jwks_uri).toBe("https://idp1.example.com/.well-known/jwks.json");
    });

    it("should return null on fetch error", async () => {
      vi.spyOn(global, "fetch").mockRejectedValueOnce(new Error("Network error"));

      const result = await discoverOidcProvider(
        "https://error.example.com/.well-known/openid-configuration"
      );

      expect(result).toBeNull();
    });

    it("should return null on non-ok response", async () => {
      vi.spyOn(global, "fetch").mockResolvedValueOnce({
        ok: false,
        status: 404,
      } as Response);

      const result = await discoverOidcProvider(
        "https://notfound.example.com/.well-known/openid-configuration"
      );

      expect(result).toBeNull();
    });

    it("should cache discovery results", async () => {
      const mockDiscovery = {
        issuer: "https://cached.example.com",
        authorization_endpoint: "https://cached.example.com/authorize",
        token_endpoint: "https://cached.example.com/token",
        jwks_uri: "https://cached.example.com/.well-known/jwks.json",
      };

      const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockDiscovery),
      } as Response);

      // First call
      await discoverOidcProvider("https://cached.example.com/.well-known/openid-configuration");
      // Second call (should use cache)
      await discoverOidcProvider("https://cached.example.com/.well-known/openid-configuration");

      expect(fetchSpy).toHaveBeenCalledTimes(1);
    });
  });

  describe("clearJwksCache", () => {
    it("should not throw when clearing empty cache", () => {
      expect(() => clearJwksCache()).not.toThrow();
    });

    it("should not throw when clearing specific URI", () => {
      expect(() => clearJwksCache("https://example.com/jwks")).not.toThrow();
    });
  });
});

// =============================================================================
// Error Handling Tests
// =============================================================================

describe("SSO Error Handling", () => {
  describe("Database not initialized", () => {
    beforeEach(() => {
      closeSsoDatabase();
    });

    it("should throw when configuring SAML provider without database", () => {
      expect(() => configureSamlProvider(testSamlConfig)).toThrow("SSO database not initialized");
    });

    it("should throw when configuring OIDC provider without database", () => {
      expect(() => configureOidcProvider(testOidcConfig)).toThrow("SSO database not initialized");
    });

    it("should throw when getting provider without database", () => {
      expect(() => getSsoProvider("some-id")).toThrow("SSO database not initialized");
    });

    it("should throw when listing providers without database", () => {
      expect(() => listSsoProviders()).toThrow("SSO database not initialized");
    });

    it("should throw when creating session without database", () => {
      expect(() =>
        createSsoSession({
          providerId: "test",
          providerType: "saml",
          userId: "user",
          email: "user@example.com",
          name: "Test",
          groups: [],
          claims: {},
          expiresAt: new Date().toISOString(),
        })
      ).toThrow("SSO database not initialized");
    });
  });
});
