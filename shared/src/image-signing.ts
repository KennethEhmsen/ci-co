/**
 * Image Signing & Verification Module (v1.28.0)
 *
 * Provides container image signing and verification capabilities using:
 * - Cosign (sigstore)
 * - Notary v2
 * - In-toto attestations
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID } from "crypto";
import Database from "better-sqlite3";

const runCommand = promisify(execFile);

// =============================================================================
// Types
// =============================================================================

export type SignatureType = "cosign" | "notary" | "gpg";
export type VerificationStatus = "verified" | "failed" | "unsigned" | "unknown";
export type AttestationType = "provenance" | "sbom" | "vuln-scan" | "custom";

export interface ImageReference {
  registry: string;
  repository: string;
  tag?: string;
  digest?: string;
  fullRef: string;
}

export interface SignatureInfo {
  id: string;
  type: SignatureType;
  imageRef: string;
  digest: string;
  signedAt: string;
  signer?: string;
  issuer?: string;
  keyId?: string;
  payload?: Record<string, unknown>;
}

export interface VerificationResult {
  verified: boolean;
  status: VerificationStatus;
  imageRef: string;
  digest?: string;
  signatures: SignatureInfo[];
  attestations: AttestationInfo[];
  errors: string[];
  verifiedAt: string;
  trustChain?: TrustChainInfo;
}

export interface AttestationInfo {
  id: string;
  type: AttestationType;
  predicateType: string;
  imageRef: string;
  digest: string;
  createdAt: string;
  signer?: string;
  payload: Record<string, unknown>;
}

export interface TrustChainInfo {
  root: string;
  intermediates: string[];
  leaf?: string;
  valid: boolean;
  expiresAt?: string;
}

export interface SigningOptions {
  keyPath?: string;
  keylessEnabled?: boolean;
  fulcioUrl?: string;
  rekorUrl?: string;
  annotations?: Record<string, string>;
  recursive?: boolean;
}

export interface VerifyOptions {
  keyPath?: string;
  keylessEnabled?: boolean;
  rekorUrl?: string;
  certIdentity?: string;
  certOidcIssuer?: string;
  allowInsecure?: boolean;
}

export interface AttestOptions {
  keyPath?: string;
  predicateType: string;
  predicatePath?: string;
  predicateData?: Record<string, unknown>;
  keylessEnabled?: boolean;
}

export interface CosignKeyPair {
  publicKey: string;
  privateKeyPath: string;
  createdAt: string;
}

export interface SigningPolicy {
  id: string;
  name: string;
  description: string;
  requiredSignatures: number;
  trustedKeys: string[];
  trustedIssuers: string[];
  requiredAttestations: AttestationType[];
  enabled: boolean;
  createdAt: string;
}

export interface PolicyCheckResult {
  policyId: string;
  policyName: string;
  imageRef: string;
  passed: boolean;
  checks: {
    name: string;
    passed: boolean;
    message: string;
  }[];
  checkedAt: string;
}

export interface SigningDbInitResult {
  success: boolean;
  path: string;
  created: boolean;
}

// =============================================================================
// Database Management
// =============================================================================

let db: Database.Database | null = null;
let dbPath: string = ":memory:";

export function initSigningDatabase(path?: string): SigningDbInitResult {
  if (db) {
    return { success: true, path: dbPath, created: false };
  }

  dbPath = path || ":memory:";
  db = new Database(dbPath);

  db.exec(`
    CREATE TABLE IF NOT EXISTS signing_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      description TEXT,
      required_signatures INTEGER DEFAULT 1,
      trusted_keys_json TEXT NOT NULL,
      trusted_issuers_json TEXT NOT NULL,
      required_attestations_json TEXT NOT NULL,
      enabled INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS verification_history (
      id TEXT PRIMARY KEY,
      image_ref TEXT NOT NULL,
      digest TEXT,
      status TEXT NOT NULL,
      signatures_count INTEGER DEFAULT 0,
      attestations_count INTEGER DEFAULT 0,
      policy_id TEXT,
      policy_passed INTEGER,
      errors_json TEXT,
      verified_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_verification_image
      ON verification_history(image_ref);
    CREATE INDEX IF NOT EXISTS idx_verification_date
      ON verification_history(verified_at);

    CREATE TABLE IF NOT EXISTS trusted_keys (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      key_type TEXT NOT NULL,
      public_key TEXT NOT NULL,
      fingerprint TEXT,
      issuer TEXT,
      subject TEXT,
      expires_at TEXT,
      enabled INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_trusted_keys_fingerprint
      ON trusted_keys(fingerprint);

    CREATE TABLE IF NOT EXISTS signing_audit (
      id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      image_ref TEXT,
      actor TEXT,
      details_json TEXT NOT NULL,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  return { success: true, path: dbPath, created: true };
}

export function closeSigningDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

function getDb(): Database.Database {
  if (!db) {
    throw new Error("Signing database not initialized. Call initSigningDatabase() first.");
  }
  return db;
}

// =============================================================================
// Utility Functions
// =============================================================================

function parseImageReference(ref: string): ImageReference {
  let registry = "docker.io";
  let repository = ref;
  let tag: string | undefined;
  let digest: string | undefined;

  const digestMatch = repository.match(/@(sha256:[a-f0-9]{64})$/);
  if (digestMatch) {
    digest = digestMatch[1];
    repository = repository.replace(/@sha256:[a-f0-9]{64}$/, "");
  }

  const tagMatch = repository.match(/:([^:/]+)$/);
  if (tagMatch) {
    tag = tagMatch[1];
    repository = repository.replace(/:[^:/]+$/, "");
  }

  const parts = repository.split("/");
  if (parts.length > 1 && (parts[0].includes(".") || parts[0].includes(":"))) {
    registry = parts[0];
    repository = parts.slice(1).join("/");
  }

  if (registry === "docker.io" && !repository.includes("/")) {
    repository = `library/${repository}`;
  }

  const fullRef = digest
    ? `${registry}/${repository}@${digest}`
    : tag
      ? `${registry}/${repository}:${tag}`
      : `${registry}/${repository}:latest`;

  return { registry, repository, tag, digest, fullRef };
}

function logAudit(
  eventType: string,
  imageRef: string | null,
  actor: string | null,
  details: Record<string, unknown>
): void {
  const database = getDb();
  database
    .prepare(
      `
    INSERT INTO signing_audit (id, event_type, image_ref, actor, details_json)
    VALUES (?, ?, ?, ?, ?)
  `
    )
    .run(randomUUID(), eventType, imageRef, actor, JSON.stringify(details));
}

// =============================================================================
// Cosign Functions
// =============================================================================

export async function isCosignInstalled(): Promise<boolean> {
  try {
    await runCommand("cosign", ["version"], { timeout: 10000 });
    return true;
  } catch {
    return false;
  }
}

export async function getCosignVersion(): Promise<string | null> {
  try {
    const { stdout } = await runCommand("cosign", ["version"], { timeout: 10000 });
    const match = stdout.match(/cosign\s+version\s+(\S+)/i);
    return match ? match[1] : stdout.trim().split("\n")[0];
  } catch {
    return null;
  }
}

export async function generateCosignKeyPair(
  outputPath: string,
  password?: string
): Promise<CosignKeyPair> {
  const args = ["generate-key-pair", "--output-key-prefix", outputPath];

  const env = { ...process.env };
  if (password) {
    env.COSIGN_PASSWORD = password;
  }

  try {
    await runCommand("cosign", args, { timeout: 30000, env });

    const { readFile } = await import("node:fs/promises");
    const publicKey = await readFile(`${outputPath}.pub`, "utf-8");

    return {
      publicKey,
      privateKeyPath: `${outputPath}.key`,
      createdAt: new Date().toISOString(),
    };
  } catch (error) {
    throw new Error(
      `Failed to generate key pair: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

export async function cosignSign(
  imageRef: string,
  options: SigningOptions
): Promise<SignatureInfo> {
  const ref = parseImageReference(imageRef);
  const args = ["sign"];

  if (options.keyPath) {
    args.push("--key", options.keyPath);
  } else if (options.keylessEnabled) {
    args.push("--yes");
    if (options.fulcioUrl) {
      args.push("--fulcio-url", options.fulcioUrl);
    }
    if (options.rekorUrl) {
      args.push("--rekor-url", options.rekorUrl);
    }
  }

  if (options.annotations) {
    for (const [key, value] of Object.entries(options.annotations)) {
      args.push("-a", `${key}=${value}`);
    }
  }

  if (options.recursive) {
    args.push("--recursive");
  }

  args.push(ref.fullRef);

  try {
    const { stdout, stderr } = await runCommand("cosign", args, {
      timeout: 120000,
      maxBuffer: 10 * 1024 * 1024,
    });

    const digestMatch = (stdout + stderr).match(/sha256:[a-f0-9]{64}/);

    const signature: SignatureInfo = {
      id: randomUUID(),
      type: "cosign",
      imageRef: ref.fullRef,
      digest: digestMatch ? digestMatch[0] : "",
      signedAt: new Date().toISOString(),
      signer: options.keylessEnabled ? "keyless" : "key-based",
    };

    logAudit("image_signed", ref.fullRef, null, {
      signatureType: "cosign",
      keyless: options.keylessEnabled,
    });

    return signature;
  } catch (error) {
    throw new Error(
      `Failed to sign image: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

export async function cosignVerify(
  imageRef: string,
  options: VerifyOptions
): Promise<VerificationResult> {
  const ref = parseImageReference(imageRef);
  const args = ["verify"];

  if (options.keyPath) {
    args.push("--key", options.keyPath);
  } else if (options.keylessEnabled) {
    if (options.certIdentity) {
      args.push("--certificate-identity", options.certIdentity);
    }
    if (options.certOidcIssuer) {
      args.push("--certificate-oidc-issuer", options.certOidcIssuer);
    }
    if (options.rekorUrl) {
      args.push("--rekor-url", options.rekorUrl);
    }
  }

  if (options.allowInsecure) {
    args.push("--insecure-ignore-tlog");
  }

  args.push("--output", "json");
  args.push(ref.fullRef);

  const result: VerificationResult = {
    verified: false,
    status: "unknown",
    imageRef: ref.fullRef,
    signatures: [],
    attestations: [],
    errors: [],
    verifiedAt: new Date().toISOString(),
  };

  try {
    const { stdout } = await runCommand("cosign", args, {
      timeout: 60000,
      maxBuffer: 10 * 1024 * 1024,
    });

    try {
      const verifyOutput = JSON.parse(stdout);

      if (Array.isArray(verifyOutput)) {
        for (const sig of verifyOutput) {
          result.signatures.push({
            id: randomUUID(),
            type: "cosign",
            imageRef: ref.fullRef,
            digest: sig.critical?.image?.["docker-manifest-digest"] || "",
            signedAt: sig.optional?.timestamp || new Date().toISOString(),
            issuer: sig.optional?.Issuer,
            signer: sig.optional?.Subject,
            payload: sig,
          });
        }
      }
    } catch {
      // Output might not be valid JSON
    }

    result.verified = true;
    result.status = "verified";
    result.digest = ref.digest;

    const database = getDb();
    database
      .prepare(
        `
      INSERT INTO verification_history (
        id, image_ref, digest, status, signatures_count, attestations_count, verified_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `
      )
      .run(
        randomUUID(),
        ref.fullRef,
        ref.digest || null,
        result.status,
        result.signatures.length,
        result.attestations.length,
        result.verifiedAt
      );

    logAudit("image_verified", ref.fullRef, null, {
      status: result.status,
      signaturesCount: result.signatures.length,
    });

    return result;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);

    if (errorMsg.includes("no matching signatures")) {
      result.status = "unsigned";
      result.errors.push("No signatures found for image");
    } else {
      result.status = "failed";
      result.errors.push(errorMsg);
    }

    const database = getDb();
    database
      .prepare(
        `
      INSERT INTO verification_history (
        id, image_ref, digest, status, signatures_count, errors_json, verified_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `
      )
      .run(
        randomUUID(),
        ref.fullRef,
        ref.digest || null,
        result.status,
        0,
        JSON.stringify(result.errors),
        result.verifiedAt
      );

    return result;
  }
}

export async function cosignAttest(
  imageRef: string,
  options: AttestOptions
): Promise<AttestationInfo> {
  const ref = parseImageReference(imageRef);
  const args = ["attest"];

  if (options.keyPath) {
    args.push("--key", options.keyPath);
  } else if (options.keylessEnabled) {
    args.push("--yes");
  }

  args.push("--type", options.predicateType);

  if (options.predicatePath) {
    args.push("--predicate", options.predicatePath);
  }

  args.push(ref.fullRef);

  try {
    const { stdout, stderr } = await runCommand("cosign", args, {
      timeout: 120000,
      maxBuffer: 10 * 1024 * 1024,
    });

    const digestMatch = (stdout + stderr).match(/sha256:[a-f0-9]{64}/);

    const attestation: AttestationInfo = {
      id: randomUUID(),
      type: mapPredicateToType(options.predicateType),
      predicateType: options.predicateType,
      imageRef: ref.fullRef,
      digest: digestMatch ? digestMatch[0] : "",
      createdAt: new Date().toISOString(),
      payload: options.predicateData || {},
    };

    logAudit("attestation_created", ref.fullRef, null, {
      predicateType: options.predicateType,
    });

    return attestation;
  } catch (error) {
    throw new Error(
      `Failed to create attestation: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

export async function cosignVerifyAttestation(
  imageRef: string,
  predicateType: string,
  options: VerifyOptions
): Promise<AttestationInfo[]> {
  const ref = parseImageReference(imageRef);
  const args = ["verify-attestation"];

  if (options.keyPath) {
    args.push("--key", options.keyPath);
  } else if (options.keylessEnabled) {
    if (options.certIdentity) {
      args.push("--certificate-identity", options.certIdentity);
    }
    if (options.certOidcIssuer) {
      args.push("--certificate-oidc-issuer", options.certOidcIssuer);
    }
  }

  args.push("--type", predicateType);
  args.push("--output", "json");
  args.push(ref.fullRef);

  try {
    const { stdout } = await runCommand("cosign", args, {
      timeout: 60000,
      maxBuffer: 10 * 1024 * 1024,
    });

    const attestations: AttestationInfo[] = [];

    try {
      const output = JSON.parse(stdout);
      const items = Array.isArray(output) ? output : [output];

      for (const item of items) {
        attestations.push({
          id: randomUUID(),
          type: mapPredicateToType(predicateType),
          predicateType,
          imageRef: ref.fullRef,
          digest: item.critical?.image?.["docker-manifest-digest"] || "",
          createdAt: new Date().toISOString(),
          payload: item.payload || item,
        });
      }
    } catch {
      // Parse failed
    }

    return attestations;
  } catch (error) {
    throw new Error(
      `Failed to verify attestation: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

// =============================================================================
// Notary Functions
// =============================================================================

export async function isNotaryInstalled(): Promise<boolean> {
  try {
    await runCommand("notation", ["version"], { timeout: 10000 });
    return true;
  } catch {
    return false;
  }
}

export async function notaryVerify(
  imageRef: string,
  trustPolicy?: string
): Promise<VerificationResult> {
  const ref = parseImageReference(imageRef);
  const args = ["verify"];

  if (trustPolicy) {
    args.push("--trust-policy", trustPolicy);
  }

  args.push(ref.fullRef);

  const result: VerificationResult = {
    verified: false,
    status: "unknown",
    imageRef: ref.fullRef,
    signatures: [],
    attestations: [],
    errors: [],
    verifiedAt: new Date().toISOString(),
  };

  try {
    const { stdout } = await runCommand("notation", args, {
      timeout: 60000,
      maxBuffer: 10 * 1024 * 1024,
    });

    result.verified = true;
    result.status = "verified";

    if (stdout.includes("Successfully verified")) {
      result.signatures.push({
        id: randomUUID(),
        type: "notary",
        imageRef: ref.fullRef,
        digest: ref.digest || "",
        signedAt: new Date().toISOString(),
      });
    }

    return result;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    result.status = "failed";
    result.errors.push(errorMsg);
    return result;
  }
}

// =============================================================================
// Policy Management
// =============================================================================

export function createSigningPolicy(
  policy: Omit<SigningPolicy, "id" | "createdAt">
): SigningPolicy {
  const database = getDb();

  const newPolicy: SigningPolicy = {
    ...policy,
    id: randomUUID(),
    createdAt: new Date().toISOString(),
  };

  database
    .prepare(
      `
    INSERT INTO signing_policies (
      id, name, description, required_signatures,
      trusted_keys_json, trusted_issuers_json,
      required_attestations_json, enabled
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `
    )
    .run(
      newPolicy.id,
      newPolicy.name,
      newPolicy.description,
      newPolicy.requiredSignatures,
      JSON.stringify(newPolicy.trustedKeys),
      JSON.stringify(newPolicy.trustedIssuers),
      JSON.stringify(newPolicy.requiredAttestations),
      newPolicy.enabled ? 1 : 0
    );

  logAudit("policy_created", null, null, { policyId: newPolicy.id, name: newPolicy.name });

  return newPolicy;
}

export function getSigningPolicy(policyId: string): SigningPolicy | null {
  const database = getDb();
  const row = database.prepare(`SELECT * FROM signing_policies WHERE id = ?`).get(policyId) as
    | {
        id: string;
        name: string;
        description: string;
        required_signatures: number;
        trusted_keys_json: string;
        trusted_issuers_json: string;
        required_attestations_json: string;
        enabled: number;
        created_at: string;
      }
    | undefined;

  if (!row) return null;

  return {
    id: row.id,
    name: row.name,
    description: row.description,
    requiredSignatures: row.required_signatures,
    trustedKeys: JSON.parse(row.trusted_keys_json),
    trustedIssuers: JSON.parse(row.trusted_issuers_json),
    requiredAttestations: JSON.parse(row.required_attestations_json),
    enabled: row.enabled === 1,
    createdAt: row.created_at,
  };
}

export function listSigningPolicies(): SigningPolicy[] {
  const database = getDb();
  const rows = database
    .prepare(`SELECT * FROM signing_policies ORDER BY created_at DESC`)
    .all() as Array<{
    id: string;
    name: string;
    description: string;
    required_signatures: number;
    trusted_keys_json: string;
    trusted_issuers_json: string;
    required_attestations_json: string;
    enabled: number;
    created_at: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    description: row.description,
    requiredSignatures: row.required_signatures,
    trustedKeys: JSON.parse(row.trusted_keys_json),
    trustedIssuers: JSON.parse(row.trusted_issuers_json),
    requiredAttestations: JSON.parse(row.required_attestations_json),
    enabled: row.enabled === 1,
    createdAt: row.created_at,
  }));
}

export function deleteSigningPolicy(policyId: string): boolean {
  const database = getDb();
  const result = database.prepare(`DELETE FROM signing_policies WHERE id = ?`).run(policyId);
  if (result.changes > 0) {
    logAudit("policy_deleted", null, null, { policyId });
    return true;
  }
  return false;
}

export async function checkPolicy(
  imageRef: string,
  policyId: string,
  options?: VerifyOptions
): Promise<PolicyCheckResult> {
  const policy = getSigningPolicy(policyId);
  if (!policy) {
    throw new Error(`Policy not found: ${policyId}`);
  }

  const checks: { name: string; passed: boolean; message: string }[] = [];
  let allPassed = true;

  const verifyResult = await cosignVerify(imageRef, options || {});

  const sigCheck = verifyResult.signatures.length >= policy.requiredSignatures;
  checks.push({
    name: "required_signatures",
    passed: sigCheck,
    message: sigCheck
      ? `Found ${verifyResult.signatures.length} signatures (required: ${policy.requiredSignatures})`
      : `Only ${verifyResult.signatures.length} signatures found (required: ${policy.requiredSignatures})`,
  });
  if (!sigCheck) allPassed = false;

  if (policy.trustedIssuers.length > 0 && verifyResult.signatures.length > 0) {
    const hasValidIssuer = verifyResult.signatures.some(
      (sig) => sig.issuer && policy.trustedIssuers.includes(sig.issuer)
    );
    checks.push({
      name: "trusted_issuer",
      passed: hasValidIssuer,
      message: hasValidIssuer
        ? "Signature from trusted issuer found"
        : "No signature from trusted issuer",
    });
    if (!hasValidIssuer) allPassed = false;
  }

  for (const attestationType of policy.requiredAttestations) {
    const predicateType = mapTypeToPredicateType(attestationType);
    try {
      const attestations = await cosignVerifyAttestation(imageRef, predicateType, options || {});
      const hasAttestation = attestations.length > 0;
      checks.push({
        name: `attestation_${attestationType}`,
        passed: hasAttestation,
        message: hasAttestation
          ? `${attestationType} attestation found`
          : `Missing ${attestationType} attestation`,
      });
      if (!hasAttestation) allPassed = false;
    } catch {
      checks.push({
        name: `attestation_${attestationType}`,
        passed: false,
        message: `Failed to verify ${attestationType} attestation`,
      });
      allPassed = false;
    }
  }

  const result: PolicyCheckResult = {
    policyId: policy.id,
    policyName: policy.name,
    imageRef,
    passed: allPassed,
    checks,
    checkedAt: new Date().toISOString(),
  };

  const database = getDb();
  database
    .prepare(
      `
    UPDATE verification_history
    SET policy_id = ?, policy_passed = ?
    WHERE image_ref = ?
    ORDER BY verified_at DESC
    LIMIT 1
  `
    )
    .run(policyId, allPassed ? 1 : 0, imageRef);

  logAudit("policy_checked", imageRef, null, {
    policyId,
    passed: allPassed,
  });

  return result;
}

export function getVerificationHistory(
  imageRef: string,
  limit?: number
): Array<{
  id: string;
  imageRef: string;
  status: VerificationStatus;
  signaturesCount: number;
  attestationsCount: number;
  policyId?: string;
  policyPassed?: boolean;
  verifiedAt: string;
}> {
  const database = getDb();

  let sql = `SELECT * FROM verification_history WHERE image_ref = ? ORDER BY verified_at DESC`;
  const params: (string | number)[] = [imageRef];

  if (limit) {
    sql += " LIMIT ?";
    params.push(limit);
  }

  const rows = database.prepare(sql).all(...params) as Array<{
    id: string;
    image_ref: string;
    status: string;
    signatures_count: number;
    attestations_count: number;
    policy_id: string | null;
    policy_passed: number | null;
    verified_at: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    imageRef: row.image_ref,
    status: row.status as VerificationStatus,
    signaturesCount: row.signatures_count,
    attestationsCount: row.attestations_count,
    policyId: row.policy_id || undefined,
    policyPassed: row.policy_passed !== null ? row.policy_passed === 1 : undefined,
    verifiedAt: row.verified_at,
  }));
}

export function getSigningAuditLog(options?: {
  imageRef?: string;
  eventType?: string;
  limit?: number;
}): Array<{
  id: string;
  eventType: string;
  imageRef?: string;
  actor?: string;
  details: Record<string, unknown>;
  timestamp: string;
}> {
  const database = getDb();

  let sql = "SELECT * FROM signing_audit WHERE 1=1";
  const params: (string | number)[] = [];

  if (options?.imageRef) {
    sql += " AND image_ref = ?";
    params.push(options.imageRef);
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
    image_ref: string | null;
    actor: string | null;
    details_json: string;
    timestamp: string;
  }>;

  return rows.map((row) => ({
    id: row.id,
    eventType: row.event_type,
    imageRef: row.image_ref || undefined,
    actor: row.actor || undefined,
    details: JSON.parse(row.details_json),
    timestamp: row.timestamp,
  }));
}

// =============================================================================
// Helper Functions
// =============================================================================

function mapPredicateToType(predicateType: string): AttestationType {
  const mapping: Record<string, AttestationType> = {
    slsaprovenance: "provenance",
    spdx: "sbom",
    cyclonedx: "sbom",
    vuln: "vuln-scan",
  };

  for (const [key, type] of Object.entries(mapping)) {
    if (predicateType.toLowerCase().includes(key)) {
      return type;
    }
  }

  return "custom";
}

function mapTypeToPredicateType(type: AttestationType): string {
  const mapping: Record<AttestationType, string> = {
    provenance: "slsaprovenance",
    sbom: "cyclonedx",
    "vuln-scan": "vuln",
    custom: "custom",
  };

  return mapping[type] || type;
}
