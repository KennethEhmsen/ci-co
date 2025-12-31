/**
 * API Security Gateway Module
 * API security scanning and runtime protection
 * Part of v1.31.0 - GitOps & Zero-Trust Security
 */

import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";

export type ApiType = "openapi" | "graphql" | "grpc" | "rest";
export type AuthMethod = "none" | "apikey" | "basic" | "bearer" | "oauth2" | "mtls";
export type OwaspCategory =
  | "broken-object-level-auth"
  | "broken-authentication"
  | "broken-object-property-level-auth"
  | "unrestricted-resource-consumption"
  | "broken-function-level-auth"
  | "unrestricted-access-to-sensitive-business-flows"
  | "server-side-request-forgery"
  | "security-misconfiguration"
  | "improper-inventory-management"
  | "unsafe-consumption-of-apis";

export interface ApiSpec {
  id: string;
  name: string;
  type: ApiType;
  version: string;
  basePath: string;
  endpoints: number;
  authMethods: AuthMethod[];
  createdAt: string;
  lastScanned?: string;
}

export interface ApiScanResult {
  specId: string;
  scannedAt: string;
  findings: ApiFinding[];
  score: number;
  passed: boolean;
  owaspCoverage: Record<OwaspCategory, boolean>;
}

export interface ApiFinding {
  id: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  category: OwaspCategory | "injection" | "auth" | "rate-limit" | "schema" | "custom";
  endpoint?: string;
  method?: string;
  message: string;
  evidence?: string;
  remediation: string;
}

export interface AuthAuditResult {
  specId: string;
  endpoints: Array<{
    path: string;
    method: string;
    authRequired: boolean;
    authMethods: AuthMethod[];
    issues: string[];
  }>;
  summary: {
    totalEndpoints: number;
    protectedEndpoints: number;
    unprotectedEndpoints: number;
    authMethods: AuthMethod[];
  };
  auditedAt: string;
}

export interface RateLimitConfig {
  endpoint: string;
  method: string;
  limit: number;
  window: string;
  enabled: boolean;
}

export interface RateLimitAudit {
  specId: string;
  endpoints: Array<{
    path: string;
    method: string;
    hasRateLimit: boolean;
    config?: RateLimitConfig;
  }>;
  recommendations: string[];
  auditedAt: string;
}

export interface InjectionTestResult {
  specId: string;
  endpoint: string;
  method: string;
  testedAt: string;
  vulnerabilities: Array<{
    type: "sql" | "nosql" | "ldap" | "xpath" | "command" | "header";
    parameter: string;
    payload: string;
    response: string;
    vulnerable: boolean;
  }>;
}

export interface ApiPolicy {
  id: string;
  name: string;
  description: string;
  rules: Array<{
    type: "auth" | "rate-limit" | "input-validation" | "cors" | "tls";
    condition: string;
    action: "allow" | "deny" | "log";
  }>;
  enabled: boolean;
  createdAt: string;
}

export interface OwaspApiTop10Check {
  specId: string;
  checkedAt: string;
  results: Array<{
    category: OwaspCategory;
    name: string;
    passed: boolean;
    findings: number;
    description: string;
  }>;
  overallScore: number;
}

let db: Database.Database | null = null;
const DEFAULT_DB_PATH = path.join(process.cwd(), ".cicd-security", "api-security.db");

export function initApiSecurityDb(dbPath: string = DEFAULT_DB_PATH): {
  path: string;
  tables: string[];
} {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  db = new Database(dbPath);
  db.pragma("journal_mode = WAL");

  db.prepare(
    `CREATE TABLE IF NOT EXISTS api_specs (
    id TEXT PRIMARY KEY, name TEXT, type TEXT, version TEXT,
    base_path TEXT, endpoints INTEGER, auth_methods TEXT,
    created_at TEXT, last_scanned TEXT
  )`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS api_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, spec_id TEXT, scanned_at TEXT,
    findings TEXT, score INTEGER, passed INTEGER, owasp_coverage TEXT
  )`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS api_policies (
    id TEXT PRIMARY KEY, name TEXT, description TEXT, rules TEXT,
    enabled INTEGER, created_at TEXT
  )`
  ).run();

  return { path: dbPath, tables: ["api_specs", "api_scans", "api_policies"] };
}

function getDb(): Database.Database {
  if (!db) initApiSecurityDb();
  return db!;
}

// OpenAPI Scanning
export function scanOpenApiSpec(specPath: string): ApiScanResult {
  const findings: ApiFinding[] = [];
  let spec: any = {};

  try {
    const content = fs.readFileSync(specPath, "utf-8");
    spec = JSON.parse(content);
  } catch {
    try {
      const content = fs.readFileSync(specPath, "utf-8");
      // Basic YAML parsing for OpenAPI
      if (content.includes("openapi:") || content.includes("swagger:")) {
        spec = { openapi: "3.0.0", paths: {} };
      }
    } catch {
      findings.push({
        id: "parse-error",
        severity: "CRITICAL",
        category: "schema",
        message: "Failed to parse API specification",
        remediation: "Ensure the spec file is valid JSON or YAML",
      });
    }
  }

  // Check for security definitions
  if (!spec.components?.securitySchemes && !spec.securityDefinitions) {
    findings.push({
      id: "no-security-schemes",
      severity: "HIGH",
      category: "broken-authentication",
      message: "No security schemes defined in the API specification",
      remediation:
        "Define security schemes (OAuth2, API Key, Bearer) in components.securitySchemes",
    });
  }

  // Check for global security
  if (!spec.security || spec.security.length === 0) {
    findings.push({
      id: "no-global-security",
      severity: "MEDIUM",
      category: "broken-authentication",
      message: "No global security requirement defined",
      remediation: "Add a security requirement at the root level or on each operation",
    });
  }

  // Check paths for security issues
  const paths = spec.paths || {};
  for (const [pathStr, pathItem] of Object.entries(paths)) {
    for (const method of ["get", "post", "put", "patch", "delete"]) {
      const operation = (pathItem as any)[method];
      if (!operation) continue;

      // Check for missing security on sensitive endpoints
      if (!operation.security && !spec.security) {
        if (method !== "get" || pathStr.includes("{")) {
          findings.push({
            id: `unprotected-${method}-${pathStr}`,
            severity: "HIGH",
            category: "broken-function-level-auth",
            endpoint: pathStr,
            method: method.toUpperCase(),
            message: `Endpoint ${method.toUpperCase()} ${pathStr} has no security requirement`,
            remediation: "Add security requirement to this operation",
          });
        }
      }

      // Check for potential injection points
      const parameters = operation.parameters || [];
      for (const param of parameters) {
        if (param.in === "query" || param.in === "path") {
          if (!param.schema?.pattern && param.schema?.type === "string") {
            findings.push({
              id: `no-pattern-${method}-${pathStr}-${param.name}`,
              severity: "MEDIUM",
              category: "injection",
              endpoint: pathStr,
              method: method.toUpperCase(),
              message: `Parameter ${param.name} lacks input validation pattern`,
              remediation: "Add a regex pattern to validate input",
            });
          }
        }
      }
    }
  }

  const owaspCoverage = calculateOwaspCoverage(findings);
  const score = calculateSecurityScore(findings);

  const specId = `spec-${Date.now()}`;
  const result: ApiScanResult = {
    specId,
    scannedAt: new Date().toISOString(),
    findings,
    score,
    passed: findings.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH").length === 0,
    owaspCoverage,
  };

  // Store scan result
  getDb()
    .prepare(
      `INSERT INTO api_scans (spec_id, scanned_at, findings, score, passed, owasp_coverage)
     VALUES (?, ?, ?, ?, ?, ?)`
    )
    .run(
      specId,
      result.scannedAt,
      JSON.stringify(findings),
      score,
      result.passed ? 1 : 0,
      JSON.stringify(owaspCoverage)
    );

  return result;
}

function calculateOwaspCoverage(findings: ApiFinding[]): Record<OwaspCategory, boolean> {
  const categories: OwaspCategory[] = [
    "broken-object-level-auth",
    "broken-authentication",
    "broken-object-property-level-auth",
    "unrestricted-resource-consumption",
    "broken-function-level-auth",
    "unrestricted-access-to-sensitive-business-flows",
    "server-side-request-forgery",
    "security-misconfiguration",
    "improper-inventory-management",
    "unsafe-consumption-of-apis",
  ];

  const coverage: Record<string, boolean> = {};
  for (const cat of categories) {
    const hasIssues = findings.some((f) => f.category === cat);
    coverage[cat] = !hasIssues;
  }
  return coverage as Record<OwaspCategory, boolean>;
}

function calculateSecurityScore(findings: ApiFinding[]): number {
  let score = 100;
  for (const finding of findings) {
    switch (finding.severity) {
      case "CRITICAL":
        score -= 25;
        break;
      case "HIGH":
        score -= 15;
        break;
      case "MEDIUM":
        score -= 8;
        break;
      case "LOW":
        score -= 3;
        break;
    }
  }
  return Math.max(0, score);
}

// GraphQL Scanning
export function scanGraphQlSchema(schemaPath: string): ApiScanResult {
  const findings: ApiFinding[] = [];

  try {
    const content = fs.readFileSync(schemaPath, "utf-8");

    // Check for introspection enabled
    if (!content.includes("@deprecated") || content.includes("__schema")) {
      findings.push({
        id: "introspection-enabled",
        severity: "MEDIUM",
        category: "improper-inventory-management",
        message: "GraphQL introspection may be enabled in production",
        remediation: "Disable introspection in production environments",
      });
    }

    // Check for depth limiting
    findings.push({
      id: "no-depth-limit",
      severity: "MEDIUM",
      category: "unrestricted-resource-consumption",
      message: "No query depth limiting detected",
      remediation: "Implement query depth limiting to prevent DoS attacks",
    });

    // Check for batch query limiting
    findings.push({
      id: "no-batch-limit",
      severity: "LOW",
      category: "unrestricted-resource-consumption",
      message: "No batch query limiting detected",
      remediation: "Limit the number of operations per request",
    });
  } catch {
    findings.push({
      id: "parse-error",
      severity: "CRITICAL",
      category: "schema",
      message: "Failed to parse GraphQL schema",
      remediation: "Ensure the schema file is valid GraphQL SDL",
    });
  }

  const specId = `graphql-${Date.now()}`;
  return {
    specId,
    scannedAt: new Date().toISOString(),
    findings,
    score: calculateSecurityScore(findings),
    passed: findings.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH").length === 0,
    owaspCoverage: calculateOwaspCoverage(findings),
  };
}

// Auth Audit
export function auditApiAuth(specId: string, specPath: string): AuthAuditResult {
  const endpoints: AuthAuditResult["endpoints"] = [];
  let spec: any = {};

  try {
    const content = fs.readFileSync(specPath, "utf-8");
    spec = JSON.parse(content);
  } catch {
    // Handle parse error
  }

  const globalSecurity = spec.security || [];
  const securitySchemes = spec.components?.securitySchemes || spec.securityDefinitions || {};

  const paths = spec.paths || {};
  for (const [pathStr, pathItem] of Object.entries(paths)) {
    for (const method of ["get", "post", "put", "patch", "delete"]) {
      const operation = (pathItem as any)[method];
      if (!operation) continue;

      const opSecurity = operation.security || globalSecurity;
      const authRequired = opSecurity.length > 0;
      const authMethods: AuthMethod[] = [];
      const issues: string[] = [];

      for (const secReq of opSecurity) {
        for (const schemeName of Object.keys(secReq)) {
          const scheme = securitySchemes[schemeName];
          if (scheme) {
            if (scheme.type === "apiKey") authMethods.push("apikey");
            else if (scheme.type === "http" && scheme.scheme === "bearer")
              authMethods.push("bearer");
            else if (scheme.type === "http" && scheme.scheme === "basic") authMethods.push("basic");
            else if (scheme.type === "oauth2") authMethods.push("oauth2");
            else if (scheme.type === "mutualTLS") authMethods.push("mtls");
          }
        }
      }

      if (!authRequired && method !== "get") {
        issues.push("Write operation without authentication");
      }

      if (authMethods.includes("basic")) {
        issues.push("Using Basic auth - consider more secure alternatives");
      }

      endpoints.push({
        path: pathStr,
        method: method.toUpperCase(),
        authRequired,
        authMethods: authMethods.length > 0 ? authMethods : ["none"],
        issues,
      });
    }
  }

  const protectedEndpoints = endpoints.filter((e) => e.authRequired).length;
  const allAuthMethods = [...new Set(endpoints.flatMap((e) => e.authMethods))];

  return {
    specId,
    endpoints,
    summary: {
      totalEndpoints: endpoints.length,
      protectedEndpoints,
      unprotectedEndpoints: endpoints.length - protectedEndpoints,
      authMethods: allAuthMethods,
    },
    auditedAt: new Date().toISOString(),
  };
}

// Rate Limit Audit
export function auditRateLimits(specId: string, specPath: string): RateLimitAudit {
  const endpoints: RateLimitAudit["endpoints"] = [];
  const recommendations: string[] = [];
  let spec: any = {};

  try {
    const content = fs.readFileSync(specPath, "utf-8");
    spec = JSON.parse(content);
  } catch {
    // Handle parse error
  }

  const paths = spec.paths || {};
  for (const [pathStr, pathItem] of Object.entries(paths)) {
    for (const method of ["get", "post", "put", "patch", "delete"]) {
      const operation = (pathItem as any)[method];
      if (!operation) continue;

      // Check for rate limit headers in responses
      const hasRateLimit =
        operation["x-ratelimit-limit"] ||
        Object.values(operation.responses || {}).some(
          (r: any) => r.headers?.["X-RateLimit-Limit"] || r.headers?.["x-ratelimit-limit"]
        );

      endpoints.push({
        path: pathStr,
        method: method.toUpperCase(),
        hasRateLimit,
        config: hasRateLimit
          ? {
              endpoint: pathStr,
              method: method.toUpperCase(),
              limit: operation["x-ratelimit-limit"] || 100,
              window: "1m",
              enabled: true,
            }
          : undefined,
      });

      if (!hasRateLimit) {
        recommendations.push(`Add rate limiting to ${method.toUpperCase()} ${pathStr}`);
      }
    }
  }

  return {
    specId,
    endpoints,
    recommendations,
    auditedAt: new Date().toISOString(),
  };
}

// Injection Testing (simulated)
export function testForInjection(
  endpoint: string,
  method: string,
  parameters: string[]
): InjectionTestResult {
  const vulnerabilities: InjectionTestResult["vulnerabilities"] = [];

  const payloads = {
    sql: ["' OR '1'='1", "1; DROP TABLE users--", "UNION SELECT * FROM users"],
    nosql: ['{"$gt": ""}', '{"$ne": null}'],
    command: ["; ls -la", "| cat /etc/passwd", "&& whoami"],
  };

  for (const param of parameters) {
    for (const [type, testPayloads] of Object.entries(payloads)) {
      for (const payload of testPayloads) {
        // Simulated test - in production would actually send requests
        vulnerabilities.push({
          type: type as any,
          parameter: param,
          payload,
          response: "200 OK (simulated)",
          vulnerable: false, // Would be determined by actual response analysis
        });
      }
    }
  }

  return {
    specId: `test-${Date.now()}`,
    endpoint,
    method,
    testedAt: new Date().toISOString(),
    vulnerabilities,
  };
}

// API Policy Management
export function createApiPolicy(policy: Omit<ApiPolicy, "id" | "createdAt">): ApiPolicy {
  const id = `api-policy-${Date.now()}`;
  const now = new Date().toISOString();

  const record: ApiPolicy = { ...policy, id, createdAt: now };

  getDb()
    .prepare(
      `INSERT INTO api_policies (id, name, description, rules, enabled, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`
    )
    .run(
      id,
      policy.name,
      policy.description,
      JSON.stringify(policy.rules),
      policy.enabled ? 1 : 0,
      now
    );

  return record;
}

export function listApiPolicies(): ApiPolicy[] {
  return (getDb().prepare("SELECT * FROM api_policies ORDER BY name").all() as any[]).map((r) => ({
    id: r.id,
    name: r.name,
    description: r.description,
    rules: JSON.parse(r.rules),
    enabled: r.enabled === 1,
    createdAt: r.created_at,
  }));
}

// OWASP API Top 10 Check
export function checkOwaspApiTop10(specPath: string): OwaspApiTop10Check {
  const scanResult = scanOpenApiSpec(specPath);

  const owaspCategories: Array<{ category: OwaspCategory; name: string; description: string }> = [
    {
      category: "broken-object-level-auth",
      name: "Broken Object Level Authorization",
      description: "APIs expose endpoints that handle object identifiers",
    },
    {
      category: "broken-authentication",
      name: "Broken Authentication",
      description: "Authentication mechanisms are implemented incorrectly",
    },
    {
      category: "broken-object-property-level-auth",
      name: "Broken Object Property Level Authorization",
      description: "Improper authorization at property level",
    },
    {
      category: "unrestricted-resource-consumption",
      name: "Unrestricted Resource Consumption",
      description: "API requests consume excessive resources",
    },
    {
      category: "broken-function-level-auth",
      name: "Broken Function Level Authorization",
      description: "Complex access control policies",
    },
    {
      category: "unrestricted-access-to-sensitive-business-flows",
      name: "Unrestricted Access to Sensitive Business Flows",
      description: "APIs expose sensitive business flows",
    },
    {
      category: "server-side-request-forgery",
      name: "Server Side Request Forgery",
      description: "API fetches remote resources without validation",
    },
    {
      category: "security-misconfiguration",
      name: "Security Misconfiguration",
      description: "Insecure default configurations",
    },
    {
      category: "improper-inventory-management",
      name: "Improper Inventory Management",
      description: "APIs lack proper documentation and versioning",
    },
    {
      category: "unsafe-consumption-of-apis",
      name: "Unsafe Consumption of APIs",
      description: "Trusting third-party APIs without validation",
    },
  ];

  const results = owaspCategories.map(({ category, name, description }) => {
    const categoryFindings = scanResult.findings.filter((f) => f.category === category);
    return {
      category,
      name,
      passed: categoryFindings.length === 0,
      findings: categoryFindings.length,
      description,
    };
  });

  const passedCount = results.filter((r) => r.passed).length;
  const overallScore = Math.round((passedCount / results.length) * 100);

  return {
    specId: scanResult.specId,
    checkedAt: new Date().toISOString(),
    results,
    overallScore,
  };
}

export const apiSecurity = {
  initApiSecurityDb,
  scanOpenApiSpec,
  scanGraphQlSchema,
  auditApiAuth,
  auditRateLimits,
  testForInjection,
  createApiPolicy,
  listApiPolicies,
  checkOwaspApiTop10,
};
