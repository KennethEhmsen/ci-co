/**
 * Supply Chain Security Module (v1.28.0)
 *
 * Provides supply chain security verification using:
 * - SLSA (Supply-chain Levels for Software Artifacts) provenance
 * - in-toto attestation framework
 * - SBOM attestation verification
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, readFileSync } from "node:fs";
import { randomUUID } from "crypto";
import Database from "better-sqlite3";

const runCommand = promisify(execFile);

// =============================================================================
// Types
// =============================================================================

export type SlsaLevel = 0 | 1 | 2 | 3 | 4;
export type ProvenanceStatus = "verified" | "failed" | "missing" | "partial";
export type AttestationFormat = "in-toto" | "slsa" | "sigstore" | "custom";
export type BuilderTrust = "trusted" | "verified" | "unknown" | "untrusted";

export interface SlsaProvenance {
  buildType: string;
  builder: {
    id: string;
    version?: string;
    builderDependencies?: Array<{ uri: string; digest?: Record<string, string> }>;
  };
  invocation: {
    configSource: {
      uri: string;
      digest: Record<string, string>;
      entryPoint?: string;
    };
    parameters?: Record<string, unknown>;
    environment?: Record<string, string>;
  };
  buildConfig?: Record<string, unknown>;
  metadata: {
    buildInvocationId?: string;
    buildStartedOn?: string;
    buildFinishedOn?: string;
    completeness?: {
      parameters?: boolean;
      environment?: boolean;
      materials?: boolean;
    };
    reproducible?: boolean;
  };
  materials: Array<{
    uri: string;
    digest: Record<string, string>;
  }>;
}

export interface SlsaVerificationResult {
  verified: boolean;
  status: ProvenanceStatus;
  level: SlsaLevel;
  artifact: string;
  provenance?: SlsaProvenance;
  builder: {
    id: string;
    trust: BuilderTrust;
    verified: boolean;
  };
  source: {
    uri?: string;
    digest?: Record<string, string>;
    verified: boolean;
  };
  materials: {
    count: number;
    verified: number;
    failed: number;
  };
  errors: string[];
  verifiedAt: string;
}

export interface InTotoStatement {
  _type: string;
  subject: Array<{
    name: string;
    digest: Record<string, string>;
  }>;
  predicateType: string;
  predicate: Record<string, unknown>;
}

export interface InTotoLink {
  _type: string;
  name: string;
  materials: Record<string, Record<string, string>>;
  products: Record<string, Record<string, string>>;
  byproducts?: {
    returnValue?: number;
    stdout?: string;
    stderr?: string;
  };
  command?: string[];
  environment?: Record<string, string>;
}

export interface InTotoLayout {
  _type: string;
  expires: string;
  readme?: string;
  keys: Record<string, InTotoKey>;
  steps: InTotoStep[];
  inspect: InTotoInspection[];
}

export interface InTotoKey {
  keytype: string;
  scheme: string;
  keyval: {
    public: string;
    private?: string;
  };
}

export interface InTotoStep {
  name: string;
  expectedMaterials: string[][];
  expectedProducts: string[][];
  pubkeys: string[];
  expectedCommand?: string[];
  threshold?: number;
}

export interface InTotoInspection {
  name: string;
  expectedMaterials: string[][];
  expectedProducts: string[][];
  run: string[];
}

export interface InTotoVerificationResult {
  verified: boolean;
  layout: string;
  artifact: string;
  stepsVerified: number;
  stepsFailed: number;
  inspectionsPassed: number;
  inspectionsFailed: number;
  errors: string[];
  verifiedAt: string;
}

export interface SbomAttestation {
  format: "spdx" | "cyclonedx";
  version: string;
  artifact: string;
  digest: string;
  components: number;
  vulnerabilities?: number;
  licenses?: string[];
  signedBy?: string;
  createdAt: string;
}

export interface SbomVerificationResult {
  verified: boolean;
  artifact: string;
  sbom?: SbomAttestation;
  signatureValid: boolean;
  contentValid: boolean;
  errors: string[];
  verifiedAt: string;
}

export interface SupplyChainPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  rules: SupplyChainRule[];
  createdAt: string;
  updatedAt: string;
}

export interface SupplyChainRule {
  id: string;
  type: "slsa_level" | "builder" | "source" | "materials" | "sbom" | "signature" | "custom";
  condition: string;
  value: string | number | string[];
  action: "require" | "deny" | "warn";
}

export interface SupplyChainPolicyResult {
  passed: boolean;
  policyId: string;
  policyName: string;
  artifact: string;
  rulesEvaluated: number;
  rulesPassed: number;
  rulesFailed: number;
  rulesWarned: number;
  violations: Array<{
    ruleId: string;
    ruleType: string;
    message: string;
    severity: "error" | "warning";
  }>;
  evaluatedAt: string;
}

export interface TrustedBuilder {
  id: string;
  name: string;
  uri: string;
  publicKey?: string;
  minSlsaLevel: SlsaLevel;
  enabled: boolean;
  addedAt: string;
}

// =============================================================================
// Database Schema
// =============================================================================

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS slsa_verifications (
    id TEXT PRIMARY KEY,
    artifact TEXT NOT NULL,
    status TEXT NOT NULL,
    level INTEGER NOT NULL,
    builder_id TEXT,
    builder_trust TEXT,
    source_uri TEXT,
    source_verified INTEGER,
    materials_count INTEGER,
    materials_verified INTEGER,
    provenance_json TEXT,
    errors_json TEXT,
    verified_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS intoto_verifications (
    id TEXT PRIMARY KEY,
    artifact TEXT NOT NULL,
    layout TEXT NOT NULL,
    verified INTEGER NOT NULL,
    steps_verified INTEGER,
    steps_failed INTEGER,
    inspections_passed INTEGER,
    inspections_failed INTEGER,
    errors_json TEXT,
    verified_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sbom_attestations (
    id TEXT PRIMARY KEY,
    artifact TEXT NOT NULL,
    format TEXT NOT NULL,
    version TEXT NOT NULL,
    digest TEXT NOT NULL,
    components INTEGER,
    vulnerabilities INTEGER,
    licenses_json TEXT,
    signed_by TEXT,
    verified INTEGER NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS supply_chain_policies (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    enabled INTEGER DEFAULT 1,
    rules_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS trusted_builders (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    uri TEXT NOT NULL,
    public_key TEXT,
    min_slsa_level INTEGER DEFAULT 1,
    enabled INTEGER DEFAULT 1,
    added_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS supply_chain_audit (
    id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    artifact TEXT,
    policy_id TEXT,
    result TEXT,
    details_json TEXT,
    timestamp TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_slsa_artifact ON slsa_verifications(artifact);
  CREATE INDEX IF NOT EXISTS idx_slsa_status ON slsa_verifications(status);
  CREATE INDEX IF NOT EXISTS idx_intoto_artifact ON intoto_verifications(artifact);
  CREATE INDEX IF NOT EXISTS idx_sbom_artifact ON sbom_attestations(artifact);
  CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON supply_chain_audit(timestamp);
`;

// =============================================================================
// Database Helpers
// =============================================================================

let dbInstance: Database.Database | null = null;

export function initSupplyChainDb(dbPath: string): { path: string; created: boolean } {
  const created = !existsSync(dbPath);
  dbInstance = new Database(dbPath);
  dbInstance.exec(SCHEMA);
  return { path: dbPath, created };
}

export function getSupplyChainDb(): Database.Database {
  if (!dbInstance) {
    throw new Error("Supply chain database not initialized. Call initSupplyChainDb first.");
  }
  return dbInstance;
}

export function closeSupplyChainDb(): void {
  if (dbInstance) {
    dbInstance.close();
    dbInstance = null;
  }
}

// =============================================================================
// SLSA Provenance Verification
// =============================================================================

export async function verifySlsaProvenance(
  artifact: string,
  options: {
    provenancePath?: string;
    sourceUri?: string;
    builderUri?: string;
    minLevel?: SlsaLevel;
  } = {}
): Promise<SlsaVerificationResult> {
  const verificationId = randomUUID();
  const verifiedAt = new Date().toISOString();
  const errors: string[] = [];

  try {
    // Check if slsa-verifier is available
    try {
      await runCommand("slsa-verifier", ["version"]);
    } catch {
      return createFailedSlsaResult(artifact, verifiedAt, [
        "slsa-verifier not found. Install from: https://github.com/slsa-framework/slsa-verifier",
      ]);
    }

    // Build verification arguments
    const args = ["verify-artifact", artifact];

    if (options.provenancePath) {
      args.push("--provenance-path", options.provenancePath);
    }

    if (options.sourceUri) {
      args.push("--source-uri", options.sourceUri);
    }

    if (options.builderUri) {
      args.push("--builder-id", options.builderUri);
    }

    args.push("--print-provenance");

    const { stdout } = await runCommand("slsa-verifier", args);

    // Parse provenance output
    let provenance: SlsaProvenance | undefined;
    try {
      provenance = JSON.parse(stdout);
    } catch {
      // Provenance may be printed separately
    }

    // Determine SLSA level from provenance
    const level = determineSlsaLevel(provenance);

    // Verify against minimum level
    const minLevel = options.minLevel ?? 1;
    if (level < minLevel) {
      errors.push(`SLSA level ${level} is below required minimum ${minLevel}`);
    }

    const result: SlsaVerificationResult = {
      verified: errors.length === 0,
      status: errors.length === 0 ? "verified" : "partial",
      level,
      artifact,
      provenance,
      builder: {
        id: provenance?.builder.id ?? "unknown",
        trust: await getBuilderTrust(provenance?.builder.id),
        verified: true,
      },
      source: {
        uri: provenance?.invocation.configSource.uri,
        digest: provenance?.invocation.configSource.digest,
        verified: !!provenance?.invocation.configSource.uri,
      },
      materials: {
        count: provenance?.materials.length ?? 0,
        verified: provenance?.materials.length ?? 0,
        failed: 0,
      },
      errors,
      verifiedAt,
    };

    // Store verification result
    storeSlsaVerification(verificationId, result);

    return result;
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    return createFailedSlsaResult(artifact, verifiedAt, [`Verification failed: ${errMsg}`]);
  }
}

function createFailedSlsaResult(
  artifact: string,
  verifiedAt: string,
  errors: string[]
): SlsaVerificationResult {
  return {
    verified: false,
    status: "failed",
    level: 0,
    artifact,
    builder: { id: "unknown", trust: "unknown", verified: false },
    source: { verified: false },
    materials: { count: 0, verified: 0, failed: 0 },
    errors,
    verifiedAt,
  };
}

function determineSlsaLevel(provenance?: SlsaProvenance): SlsaLevel {
  if (!provenance) return 0;

  // SLSA level determination based on provenance completeness
  let level: SlsaLevel = 1;

  // Level 2: Authenticated provenance
  if (provenance.builder?.id && provenance.invocation?.configSource) {
    level = 2;
  }

  // Level 3: Hardened builds with non-falsifiable provenance
  if (
    provenance.metadata?.completeness?.parameters &&
    provenance.metadata?.completeness?.environment &&
    provenance.metadata?.completeness?.materials
  ) {
    level = 3;
  }

  // Level 4: Two-party review and hermetic builds (requires additional checks)
  if (provenance.metadata?.reproducible) {
    level = 4;
  }

  return level;
}

async function getBuilderTrust(builderId?: string): Promise<BuilderTrust> {
  if (!builderId) return "unknown";

  if (!dbInstance) return "unknown";

  const builder = dbInstance
    .prepare("SELECT * FROM trusted_builders WHERE uri = ? AND enabled = 1")
    .get(builderId) as { id: string } | undefined;

  if (builder) return "trusted";

  // Check for known trusted builders
  const knownTrustedBuilders = [
    "https://github.com/slsa-framework/slsa-github-generator",
    "https://cloudbuild.googleapis.com/GoogleHostedWorker",
  ];

  if (knownTrustedBuilders.some((b) => builderId.includes(b))) {
    return "verified";
  }

  return "unknown";
}

function storeSlsaVerification(id: string, result: SlsaVerificationResult): void {
  if (!dbInstance) return;

  dbInstance
    .prepare(
      `
    INSERT INTO slsa_verifications (
      id, artifact, status, level, builder_id, builder_trust,
      source_uri, source_verified, materials_count, materials_verified,
      provenance_json, errors_json, verified_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      id,
      result.artifact,
      result.status,
      result.level,
      result.builder.id,
      result.builder.trust,
      result.source.uri ?? null,
      result.source.verified ? 1 : 0,
      result.materials.count,
      result.materials.verified,
      result.provenance ? JSON.stringify(result.provenance) : null,
      JSON.stringify(result.errors),
      result.verifiedAt
    );
}

// =============================================================================
// in-toto Verification
// =============================================================================

export async function verifyInToto(
  artifact: string,
  layoutPath: string,
  options: {
    linkDir?: string;
    keyPaths?: string[];
  } = {}
): Promise<InTotoVerificationResult> {
  const verifiedAt = new Date().toISOString();
  const errors: string[] = [];

  try {
    // Check if in-toto-verify is available
    try {
      await runCommand("in-toto-verify", ["--version"]);
    } catch {
      return createFailedInTotoResult(artifact, layoutPath, verifiedAt, [
        "in-toto-verify not found. Install from: https://github.com/in-toto/in-toto",
      ]);
    }

    // Build verification arguments
    const args = ["--layout", layoutPath];

    if (options.linkDir) {
      args.push("--link-dir", options.linkDir);
    }

    if (options.keyPaths && options.keyPaths.length > 0) {
      for (const keyPath of options.keyPaths) {
        args.push("--layout-key", keyPath);
      }
    }

    await runCommand("in-toto-verify", args);

    // Parse layout to count steps and inspections
    const layoutContent = readFileSync(layoutPath, "utf-8");
    const layout = JSON.parse(layoutContent) as InTotoLayout;

    const result: InTotoVerificationResult = {
      verified: true,
      layout: layoutPath,
      artifact,
      stepsVerified: layout.steps?.length ?? 0,
      stepsFailed: 0,
      inspectionsPassed: layout.inspect?.length ?? 0,
      inspectionsFailed: 0,
      errors: [],
      verifiedAt,
    };

    storeInTotoVerification(result);

    return result;
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    errors.push(`in-toto verification failed: ${errMsg}`);
    return createFailedInTotoResult(artifact, layoutPath, verifiedAt, errors);
  }
}

function createFailedInTotoResult(
  artifact: string,
  layout: string,
  verifiedAt: string,
  errors: string[]
): InTotoVerificationResult {
  return {
    verified: false,
    layout,
    artifact,
    stepsVerified: 0,
    stepsFailed: 0,
    inspectionsPassed: 0,
    inspectionsFailed: 0,
    errors,
    verifiedAt,
  };
}

function storeInTotoVerification(result: InTotoVerificationResult): void {
  if (!dbInstance) return;

  const id = randomUUID();
  dbInstance
    .prepare(
      `
    INSERT INTO intoto_verifications (
      id, artifact, layout, verified, steps_verified, steps_failed,
      inspections_passed, inspections_failed, errors_json, verified_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      id,
      result.artifact,
      result.layout,
      result.verified ? 1 : 0,
      result.stepsVerified,
      result.stepsFailed,
      result.inspectionsPassed,
      result.inspectionsFailed,
      JSON.stringify(result.errors),
      result.verifiedAt
    );
}

// =============================================================================
// SBOM Attestation Verification
// =============================================================================

export async function verifySbomAttestation(
  artifact: string,
  options: {
    attestationPath?: string;
    expectedFormat?: "spdx" | "cyclonedx";
    verifySignature?: boolean;
    keyPath?: string;
  } = {}
): Promise<SbomVerificationResult> {
  const verifiedAt = new Date().toISOString();
  const errors: string[] = [];

  try {
    // Use cosign to verify SBOM attestation if signature verification requested
    if (options.verifySignature) {
      const args = ["verify-attestation", artifact, "--type", "spdxjson"];

      if (options.keyPath) {
        args.push("--key", options.keyPath);
      }

      try {
        await runCommand("cosign", args);
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : String(error);
        errors.push(`SBOM signature verification failed: ${errMsg}`);
      }
    }

    // Parse SBOM attestation
    let sbom: SbomAttestation | undefined;
    if (options.attestationPath) {
      const content = readFileSync(options.attestationPath, "utf-8");
      const parsed = JSON.parse(content);

      // Detect format
      const format = detectSbomFormat(parsed);
      if (options.expectedFormat && format !== options.expectedFormat) {
        errors.push(`Expected ${options.expectedFormat} format but got ${format}`);
      }

      sbom = {
        format,
        version: getSbomVersion(parsed, format),
        artifact,
        digest: parsed.digest ?? "",
        components: countSbomComponents(parsed, format),
        licenses: extractSbomLicenses(parsed, format),
        createdAt: parsed.creationInfo?.created ?? verifiedAt,
      };

      storeSbomAttestation(sbom, errors.length === 0);
    }

    return {
      verified: errors.length === 0,
      artifact,
      sbom,
      signatureValid: options.verifySignature ? errors.length === 0 : true,
      contentValid: !!sbom,
      errors,
      verifiedAt,
    };
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    return {
      verified: false,
      artifact,
      signatureValid: false,
      contentValid: false,
      errors: [`SBOM verification failed: ${errMsg}`],
      verifiedAt,
    };
  }
}

function detectSbomFormat(sbom: Record<string, unknown>): "spdx" | "cyclonedx" {
  if (sbom.spdxVersion || sbom.SPDXID) return "spdx";
  if (sbom.bomFormat === "CycloneDX") return "cyclonedx";
  return "spdx"; // Default
}

function getSbomVersion(sbom: Record<string, unknown>, format: "spdx" | "cyclonedx"): string {
  if (format === "spdx") {
    return (sbom.spdxVersion as string) ?? "unknown";
  }
  return (sbom.specVersion as string) ?? "unknown";
}

function countSbomComponents(sbom: Record<string, unknown>, format: "spdx" | "cyclonedx"): number {
  if (format === "spdx") {
    return (sbom.packages as unknown[])?.length ?? 0;
  }
  return (sbom.components as unknown[])?.length ?? 0;
}

function extractSbomLicenses(
  sbom: Record<string, unknown>,
  format: "spdx" | "cyclonedx"
): string[] {
  const licenses = new Set<string>();

  if (format === "spdx") {
    const packages =
      (sbom.packages as Array<{ licenseConcluded?: string; licenseDeclared?: string }>) ?? [];
    for (const pkg of packages) {
      if (pkg.licenseConcluded && pkg.licenseConcluded !== "NOASSERTION") {
        licenses.add(pkg.licenseConcluded);
      }
      if (pkg.licenseDeclared && pkg.licenseDeclared !== "NOASSERTION") {
        licenses.add(pkg.licenseDeclared);
      }
    }
  } else {
    const components =
      (sbom.components as Array<{ licenses?: Array<{ license?: { id?: string } }> }>) ?? [];
    for (const comp of components) {
      for (const lic of comp.licenses ?? []) {
        if (lic.license?.id) {
          licenses.add(lic.license.id);
        }
      }
    }
  }

  return Array.from(licenses);
}

function storeSbomAttestation(sbom: SbomAttestation, verified: boolean): void {
  if (!dbInstance) return;

  const id = randomUUID();
  dbInstance
    .prepare(
      `
    INSERT INTO sbom_attestations (
      id, artifact, format, version, digest, components,
      vulnerabilities, licenses_json, signed_by, verified, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      id,
      sbom.artifact,
      sbom.format,
      sbom.version,
      sbom.digest,
      sbom.components,
      sbom.vulnerabilities ?? null,
      JSON.stringify(sbom.licenses ?? []),
      sbom.signedBy ?? null,
      verified ? 1 : 0,
      sbom.createdAt
    );
}

// =============================================================================
// Supply Chain Policy Management
// =============================================================================

export function createSupplyChainPolicy(
  name: string,
  description: string,
  rules: SupplyChainRule[]
): SupplyChainPolicy {
  if (!dbInstance) {
    throw new Error("Database not initialized");
  }

  const id = randomUUID();
  const now = new Date().toISOString();

  // Add IDs to rules if not present
  const rulesWithIds = rules.map((rule) => ({
    ...rule,
    id: rule.id ?? randomUUID(),
  }));

  dbInstance
    .prepare(
      `
    INSERT INTO supply_chain_policies (
      id, name, description, enabled, rules_json, created_at, updated_at
    ) VALUES (?, ?, ?, 1, ?, ?, ?)
  `
    )
    .run(id, name, description, JSON.stringify(rulesWithIds), now, now);

  return {
    id,
    name,
    description,
    enabled: true,
    rules: rulesWithIds,
    createdAt: now,
    updatedAt: now,
  };
}

export function getSupplyChainPolicy(nameOrId: string): SupplyChainPolicy | null {
  if (!dbInstance) return null;

  const row = dbInstance
    .prepare("SELECT * FROM supply_chain_policies WHERE id = ? OR name = ?")
    .get(nameOrId, nameOrId) as
    | {
        id: string;
        name: string;
        description: string;
        enabled: number;
        rules_json: string;
        created_at: string;
        updated_at: string;
      }
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    name: row.name,
    description: row.description,
    enabled: row.enabled === 1,
    rules: JSON.parse(row.rules_json),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function listSupplyChainPolicies(): SupplyChainPolicy[] {
  if (!dbInstance) return [];

  const rows = dbInstance
    .prepare("SELECT * FROM supply_chain_policies ORDER BY name")
    .all() as Array<{
    id: string;
    name: string;
    description: string;
    enabled: number;
    rules_json: string;
    created_at: string;
    updated_at: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    description: row.description,
    enabled: row.enabled === 1,
    rules: JSON.parse(row.rules_json),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

export async function evaluateSupplyChainPolicy(
  policyNameOrId: string,
  artifact: string,
  context: {
    slsaResult?: SlsaVerificationResult;
    inTotoResult?: InTotoVerificationResult;
    sbomResult?: SbomVerificationResult;
  } = {}
): Promise<SupplyChainPolicyResult> {
  const policy = getSupplyChainPolicy(policyNameOrId);
  if (!policy) {
    throw new Error(`Policy not found: ${policyNameOrId}`);
  }

  const evaluatedAt = new Date().toISOString();
  const violations: SupplyChainPolicyResult["violations"] = [];
  let rulesPassed = 0;
  let rulesWarned = 0;

  for (const rule of policy.rules) {
    const evaluation = evaluateRule(rule, context);

    if (evaluation.passed) {
      rulesPassed++;
    } else if (rule.action === "warn") {
      rulesWarned++;
      violations.push({
        ruleId: rule.id,
        ruleType: rule.type,
        message: evaluation.message,
        severity: "warning",
      });
    } else {
      violations.push({
        ruleId: rule.id,
        ruleType: rule.type,
        message: evaluation.message,
        severity: "error",
      });
    }
  }

  const rulesFailed = violations.filter((v) => v.severity === "error").length;
  const passed = rulesFailed === 0;

  // Audit log
  storeAuditEntry("policy_evaluation", artifact, policy.id, passed ? "passed" : "failed", {
    violations,
    rulesPassed,
    rulesWarned,
    rulesFailed,
  });

  return {
    passed,
    policyId: policy.id,
    policyName: policy.name,
    artifact,
    rulesEvaluated: policy.rules.length,
    rulesPassed,
    rulesFailed,
    rulesWarned,
    violations,
    evaluatedAt,
  };
}

function evaluateRule(
  rule: SupplyChainRule,
  context: {
    slsaResult?: SlsaVerificationResult;
    inTotoResult?: InTotoVerificationResult;
    sbomResult?: SbomVerificationResult;
  }
): { passed: boolean; message: string } {
  switch (rule.type) {
    case "slsa_level": {
      const requiredLevel = Number(rule.value);
      const actualLevel = context.slsaResult?.level ?? 0;
      if (rule.condition === "min" && actualLevel < requiredLevel) {
        return {
          passed: false,
          message: `SLSA level ${actualLevel} is below required minimum ${requiredLevel}`,
        };
      }
      return { passed: true, message: "" };
    }

    case "builder": {
      const allowedBuilders = Array.isArray(rule.value) ? rule.value : [rule.value];
      const builderId = context.slsaResult?.builder.id ?? "";
      if (rule.condition === "allow") {
        const matched = allowedBuilders.some((b) => builderId.includes(String(b)));
        if (!matched) {
          return {
            passed: false,
            message: `Builder ${builderId} not in allowed list`,
          };
        }
      } else if (rule.condition === "deny") {
        const matched = allowedBuilders.some((b) => builderId.includes(String(b)));
        if (matched) {
          return {
            passed: false,
            message: `Builder ${builderId} is in denied list`,
          };
        }
      }
      return { passed: true, message: "" };
    }

    case "source": {
      const sourceUri = context.slsaResult?.source.uri ?? "";
      if (rule.condition === "match") {
        const pattern = new RegExp(String(rule.value));
        if (!pattern.test(sourceUri)) {
          return {
            passed: false,
            message: `Source ${sourceUri} does not match required pattern ${rule.value}`,
          };
        }
      }
      return { passed: true, message: "" };
    }

    case "materials": {
      const materialsCount = context.slsaResult?.materials.count ?? 0;
      if (rule.condition === "min" && materialsCount < Number(rule.value)) {
        return {
          passed: false,
          message: `Materials count ${materialsCount} is below required minimum ${rule.value}`,
        };
      }
      return { passed: true, message: "" };
    }

    case "sbom": {
      if (rule.condition === "required") {
        if (!context.sbomResult?.verified) {
          return {
            passed: false,
            message: "SBOM attestation is required but not verified",
          };
        }
      }
      if (rule.condition === "format") {
        if (context.sbomResult?.sbom?.format !== rule.value) {
          return {
            passed: false,
            message: `SBOM format ${context.sbomResult?.sbom?.format} does not match required ${rule.value}`,
          };
        }
      }
      return { passed: true, message: "" };
    }

    case "signature": {
      if (rule.condition === "required") {
        const verified = context.slsaResult?.verified || context.inTotoResult?.verified;
        if (!verified) {
          return {
            passed: false,
            message: "Signature verification is required but not verified",
          };
        }
      }
      return { passed: true, message: "" };
    }

    default:
      return { passed: true, message: "" };
  }
}

// =============================================================================
// Trusted Builder Management
// =============================================================================

export function addTrustedBuilder(
  name: string,
  uri: string,
  options: { publicKey?: string; minSlsaLevel?: SlsaLevel } = {}
): TrustedBuilder {
  if (!dbInstance) {
    throw new Error("Database not initialized");
  }

  const id = randomUUID();
  const addedAt = new Date().toISOString();

  dbInstance
    .prepare(
      `
    INSERT INTO trusted_builders (
      id, name, uri, public_key, min_slsa_level, enabled, added_at
    ) VALUES (?, ?, ?, ?, ?, 1, ?)
  `
    )
    .run(id, name, uri, options.publicKey ?? null, options.minSlsaLevel ?? 1, addedAt);

  return {
    id,
    name,
    uri,
    publicKey: options.publicKey,
    minSlsaLevel: options.minSlsaLevel ?? 1,
    enabled: true,
    addedAt,
  };
}

export function listTrustedBuilders(): TrustedBuilder[] {
  if (!dbInstance) return [];

  const rows = dbInstance
    .prepare("SELECT * FROM trusted_builders WHERE enabled = 1 ORDER BY name")
    .all() as Array<{
    id: string;
    name: string;
    uri: string;
    public_key: string | null;
    min_slsa_level: number;
    enabled: number;
    added_at: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    uri: row.uri,
    publicKey: row.public_key ?? undefined,
    minSlsaLevel: row.min_slsa_level as SlsaLevel,
    enabled: row.enabled === 1,
    addedAt: row.added_at,
  }));
}

export function removeTrustedBuilder(nameOrId: string): boolean {
  if (!dbInstance) return false;

  const result = dbInstance
    .prepare("UPDATE trusted_builders SET enabled = 0 WHERE id = ? OR name = ?")
    .run(nameOrId, nameOrId);

  return result.changes > 0;
}

// =============================================================================
// Audit Logging
// =============================================================================

function storeAuditEntry(
  action: string,
  artifact: string | null,
  policyId: string | null,
  result: string,
  details: Record<string, unknown>
): void {
  if (!dbInstance) return;

  const id = randomUUID();
  dbInstance
    .prepare(
      `
    INSERT INTO supply_chain_audit (
      id, action, artifact, policy_id, result, details_json, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `
    )
    .run(id, action, artifact, policyId, result, JSON.stringify(details), new Date().toISOString());
}

export function getSupplyChainAuditLog(
  options: {
    artifact?: string;
    policyId?: string;
    limit?: number;
  } = {}
): Array<{
  id: string;
  action: string;
  artifact: string | null;
  policyId: string | null;
  result: string;
  details: Record<string, unknown>;
  timestamp: string;
}> {
  if (!dbInstance) return [];

  let sql = "SELECT * FROM supply_chain_audit WHERE 1=1";
  const params: (string | number)[] = [];

  if (options.artifact) {
    sql += " AND artifact = ?";
    params.push(options.artifact);
  }

  if (options.policyId) {
    sql += " AND policy_id = ?";
    params.push(options.policyId);
  }

  sql += " ORDER BY timestamp DESC";

  if (options.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }

  const rows = dbInstance.prepare(sql).all(...params) as Array<{
    id: string;
    action: string;
    artifact: string | null;
    policy_id: string | null;
    result: string;
    details_json: string;
    timestamp: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    action: row.action,
    artifact: row.artifact,
    policyId: row.policy_id,
    result: row.result,
    details: JSON.parse(row.details_json),
    timestamp: row.timestamp,
  }));
}

// =============================================================================
// Utility Functions
// =============================================================================

export function getSupplyChainSummary(): {
  slsaVerifications: {
    total: number;
    verified: number;
    failed: number;
    byLevel: Record<number, number>;
  };
  inTotoVerifications: { total: number; verified: number; failed: number };
  sbomAttestations: { total: number; verified: number; byFormat: Record<string, number> };
  policies: { total: number; enabled: number };
  trustedBuilders: number;
} {
  if (!dbInstance) {
    return {
      slsaVerifications: { total: 0, verified: 0, failed: 0, byLevel: {} },
      inTotoVerifications: { total: 0, verified: 0, failed: 0 },
      sbomAttestations: { total: 0, verified: 0, byFormat: {} },
      policies: { total: 0, enabled: 0 },
      trustedBuilders: 0,
    };
  }

  // SLSA stats
  const slsaStats = dbInstance
    .prepare(
      `
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN status = 'verified' THEN 1 ELSE 0 END) as verified,
      SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
    FROM slsa_verifications
  `
    )
    .get() as { total: number; verified: number; failed: number };

  const slsaByLevel = dbInstance
    .prepare(
      `
    SELECT level, COUNT(*) as count FROM slsa_verifications GROUP BY level
  `
    )
    .all() as Array<{ level: number; count: number }>;

  // in-toto stats
  const inTotoStats = dbInstance
    .prepare(
      `
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN verified = 1 THEN 1 ELSE 0 END) as verified,
      SUM(CASE WHEN verified = 0 THEN 1 ELSE 0 END) as failed
    FROM intoto_verifications
  `
    )
    .get() as { total: number; verified: number; failed: number };

  // SBOM stats
  const sbomStats = dbInstance
    .prepare(
      `
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN verified = 1 THEN 1 ELSE 0 END) as verified
    FROM sbom_attestations
  `
    )
    .get() as { total: number; verified: number };

  const sbomByFormat = dbInstance
    .prepare(
      `
    SELECT format, COUNT(*) as count FROM sbom_attestations GROUP BY format
  `
    )
    .all() as Array<{ format: string; count: number }>;

  // Policy stats
  const policyStats = dbInstance
    .prepare(
      `
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as enabled
    FROM supply_chain_policies
  `
    )
    .get() as { total: number; enabled: number };

  // Trusted builders
  const builderCount = dbInstance
    .prepare("SELECT COUNT(*) as count FROM trusted_builders WHERE enabled = 1")
    .get() as { count: number };

  return {
    slsaVerifications: {
      ...slsaStats,
      byLevel: Object.fromEntries(slsaByLevel.map((r) => [r.level, r.count])),
    },
    inTotoVerifications: inTotoStats,
    sbomAttestations: {
      ...sbomStats,
      byFormat: Object.fromEntries(sbomByFormat.map((r) => [r.format, r.count])),
    },
    policies: policyStats,
    trustedBuilders: builderCount.count,
  };
}
