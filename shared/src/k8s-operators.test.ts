/**
 * Tests for Kubernetes Operators Security Module
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import {
  initOperatorsDb,
  registerOperator,
  listOperators,
  getOperator,
  scanOperator,
  registerCrd,
  listCrds,
  validateCrd,
  analyzeOperatorRbac,
  checkOperatorCompatibility,
  registerWebhook,
  auditWebhooks,
  getOperatorSecuritySummary,
} from "./k8s-operators.js";

// Use unique DB path per test run to avoid locking issues
const getTestDbPath = () =>
  path.join(
    process.cwd(),
    `.test-k8s-operators-${Date.now()}-${Math.random().toString(36).slice(2)}.db`
  );
let testDbPath: string;

describe("K8s Operators Security", () => {
  beforeEach(() => {
    testDbPath = getTestDbPath();
  });

  afterEach(() => {
    // Clean up after each test - ignore errors on Windows
    try {
      if (fs.existsSync(testDbPath)) {
        fs.unlinkSync(testDbPath);
      }
    } catch {
      // Ignore cleanup errors on Windows
    }
  });

  describe("initOperatorsDb", () => {
    it("should initialize database with required tables", () => {
      const result = initOperatorsDb(testDbPath);
      expect(result.path).toBe(testDbPath);
      expect(result.tables).toContain("operators");
      expect(result.tables).toContain("crds");
      expect(result.tables).toContain("operator_scans");
      expect(result.tables).toContain("webhooks");
    });
  });

  describe("registerOperator", () => {
    it("should register a new operator", () => {
      initOperatorsDb(testDbPath);
      const operator = registerOperator({
        name: "cert-manager",
        namespace: "cert-manager",
        version: "1.13.0",
        type: "helm",
        crdCount: 6,
        permissions: ["secrets", "certificates"],
      });

      expect(operator.id).toMatch(/^op-\d+-[a-z0-9]+$/);
      expect(operator.name).toBe("cert-manager");
      expect(operator.namespace).toBe("cert-manager");
      expect(operator.version).toBe("1.13.0");
      expect(operator.type).toBe("helm");
      expect(operator.status).toBe("unknown");
    });
  });

  describe("listOperators", () => {
    it("should list all operators", () => {
      initOperatorsDb(testDbPath);
      registerOperator({
        name: "operator1",
        namespace: "ns1",
        version: "1.0.0",
        type: "go",
        crdCount: 2,
        permissions: [],
      });
      registerOperator({
        name: "operator2",
        namespace: "ns2",
        version: "2.0.0",
        type: "helm",
        crdCount: 3,
        permissions: [],
      });

      const operators = listOperators();
      expect(operators.length).toBe(2);
    });

    it("should filter operators by namespace", () => {
      initOperatorsDb(testDbPath);
      registerOperator({
        name: "operator1",
        namespace: "ns1",
        version: "1.0.0",
        type: "go",
        crdCount: 2,
        permissions: [],
      });
      registerOperator({
        name: "operator2",
        namespace: "ns2",
        version: "2.0.0",
        type: "helm",
        crdCount: 3,
        permissions: [],
      });

      const operators = listOperators("ns1");
      expect(operators.length).toBe(1);
      expect(operators[0].name).toBe("operator1");
    });
  });

  describe("getOperator", () => {
    it("should get operator by ID", () => {
      initOperatorsDb(testDbPath);
      const created = registerOperator({
        name: "test-operator",
        namespace: "default",
        version: "1.0.0",
        type: "ansible",
        crdCount: 1,
        permissions: ["pods"],
      });

      const operator = getOperator(created.id);
      expect(operator).not.toBeNull();
      expect(operator?.name).toBe("test-operator");
    });

    it("should return null for non-existent operator", () => {
      initOperatorsDb(testDbPath);
      const operator = getOperator("non-existent");
      expect(operator).toBeNull();
    });
  });

  describe("scanOperator", () => {
    it("should scan operator and detect issues", () => {
      initOperatorsDb(testDbPath);
      const operator = registerOperator({
        name: "risky-operator",
        namespace: "default",
        version: "1.0.0",
        type: "go",
        crdCount: 1,
        permissions: ["*", "secrets"],
      });

      const result = scanOperator(operator.id);
      expect(result.operatorId).toBe(operator.id);
      expect(result.issues.length).toBeGreaterThan(0);
      expect(result.issues.some((i) => i.id === "rbac-wildcard")).toBe(true);
      expect(result.passed).toBe(false);
    });

    it("should pass for operator with minimal permissions", () => {
      initOperatorsDb(testDbPath);
      const operator = registerOperator({
        name: "safe-operator",
        namespace: "default",
        version: "1.0.0",
        type: "go",
        crdCount: 1,
        permissions: ["pods:get", "pods:list"],
      });

      const result = scanOperator(operator.id);
      expect(result.passed).toBe(true);
      expect(result.score).toBe(100);
    });
  });

  describe("CRD Management", () => {
    it("should register and list CRDs", () => {
      initOperatorsDb(testDbPath);
      const operator = registerOperator({
        name: "test-operator",
        namespace: "default",
        version: "1.0.0",
        type: "go",
        crdCount: 0,
        permissions: [],
      });

      const crd = registerCrd({
        name: "certificates.cert-manager.io",
        group: "cert-manager.io",
        version: "v1",
        kind: "Certificate",
        scope: "Namespaced",
        operatorId: operator.id,
      });

      expect(crd.id).toMatch(/^crd-\d+-[a-z0-9]+$/);
      expect(crd.name).toBe("certificates.cert-manager.io");

      const crds = listCrds(operator.id);
      expect(crds.length).toBe(1);
    });

    it("should validate CRD", () => {
      initOperatorsDb(testDbPath);
      const operator = registerOperator({
        name: "test-operator",
        namespace: "default",
        version: "1.0.0",
        type: "go",
        crdCount: 0,
        permissions: [],
      });

      const crd = registerCrd({
        name: "test-crd",
        group: "example.com",
        version: "v1alpha1",
        kind: "Test",
        scope: "Namespaced",
        operatorId: operator.id,
      });

      const result = validateCrd(crd.id, "warn");
      expect(result.crdId).toBe(crd.id);
      expect(result.warnings.length).toBeGreaterThan(0);
    });
  });

  describe("RBAC Analysis", () => {
    it("should analyze operator RBAC", () => {
      initOperatorsDb(testDbPath);
      const operator = registerOperator({
        name: "test-operator",
        namespace: "default",
        version: "1.0.0",
        type: "go",
        crdCount: 0,
        permissions: ["*"],
      });

      const result = analyzeOperatorRbac(operator.id);
      expect(result.operatorId).toBe(operator.id);
      expect(result.roles.length).toBeGreaterThan(0);
      expect(result.analyzedAt).toBeDefined();
    });
  });

  describe("Compatibility Check", () => {
    it("should check K8s version compatibility", () => {
      initOperatorsDb(testDbPath);
      const operator = registerOperator({
        name: "test-operator",
        namespace: "default",
        version: "1.0.0",
        type: "go",
        crdCount: 0,
        permissions: [],
      });

      const result = checkOperatorCompatibility(operator.id, "v1.28");
      expect(result.operatorId).toBe(operator.id);
      expect(result.k8sVersions).toContain("1.28");
      expect(result.checkedAt).toBeDefined();
    });
  });

  describe("Webhook Management", () => {
    it("should register and audit webhooks", () => {
      initOperatorsDb(testDbPath);
      const operator = registerOperator({
        name: "test-operator",
        namespace: "default",
        version: "1.0.0",
        type: "go",
        crdCount: 0,
        permissions: [],
      });

      const webhook = registerWebhook({
        operatorId: operator.id,
        name: "validate-pods",
        type: "validating",
        failurePolicy: "Ignore",
        timeoutSeconds: 15,
        rules: [
          {
            operations: ["CREATE", "UPDATE"],
            apiGroups: [""],
            apiVersions: ["v1"],
            resources: ["pods"],
          },
        ],
      });

      expect(webhook.id).toMatch(/^wh-\d+-[a-z0-9]+$/);

      const audit = auditWebhooks(operator.id);
      expect(audit.webhooks.length).toBe(1);
      expect(audit.findings.length).toBeGreaterThan(0);
    });
  });

  describe("Security Summary", () => {
    it("should get operator security summary", () => {
      initOperatorsDb(testDbPath);
      registerOperator({
        name: "operator1",
        namespace: "default",
        version: "1.0.0",
        type: "go",
        crdCount: 0,
        permissions: [],
      });

      const summary = getOperatorSecuritySummary();
      expect(summary.totalOperators).toBe(1);
      expect(summary.overallScore).toBeDefined();
    });
  });
});
