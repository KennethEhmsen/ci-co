/**
 * Multi-Registry Configuration Module
 *
 * Manages multiple container registry configurations with
 * cloud-specific authentication and auto-detection.
 */

import type {
  CloudRegistryType,
  RegistryConfig,
  RegistryDetectionResult,
  RegistryAuthResult,
  MultiRegistryScanOptions,
  MultiRegistryScanResult,
  VulnerabilityCounts,
} from "./types.js";
import { scanRegistry } from "./registry-scanner.js";

// =============================================================================
// Constants
// =============================================================================

/** ECR URL pattern: {account}.dkr.ecr.{region}.amazonaws.com */
const ECR_PATTERN = /^(\d{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com$/i;

/** ACR URL pattern: {name}.azurecr.io */
const ACR_PATTERN = /^([a-z0-9]+)\.azurecr\.io$/i;

/** GCR URL patterns */
const GCR_PATTERNS = [
  /^gcr\.io$/i,
  /^([a-z]+\.)?gcr\.io$/i,
  /^([a-z0-9-]+)-docker\.pkg\.dev$/i, // Artifact Registry
];

/** GHCR URL pattern */
const GHCR_PATTERN = /^ghcr\.io$/i;

/** GitLab registry pattern */
const GITLAB_PATTERN = /registry\.gitlab\.(com|io)/i;

// =============================================================================
// Registry Storage
// =============================================================================

/** In-memory registry configuration storage */
const registryStore: Map<string, RegistryConfig> = new Map();

/** Cached auth tokens with expiration */
const authCache: Map<string, { result: RegistryAuthResult; expiresAt: number }> = new Map();

// =============================================================================
// Registry Type Detection
// =============================================================================

/**
 * Detect registry type from URL
 *
 * @param url - Registry URL or hostname
 * @returns Detection result with type and confidence
 *
 * @example
 * ```typescript
 * detectRegistryType("123456789012.dkr.ecr.us-east-1.amazonaws.com");
 * // { type: "ecr", confidence: 1.0, details: { region: "us-east-1" } }
 *
 * detectRegistryType("ghcr.io");
 * // { type: "ghcr", confidence: 1.0 }
 *
 * detectRegistryType("registry.example.com");
 * // { type: "docker-registry", confidence: 0.5 }
 * ```
 */
export function detectRegistryType(url: string): RegistryDetectionResult {
  // Normalize URL - remove protocol if present
  const hostname = url.replace(/^https?:\/\//, "").split("/")[0];

  // Check ECR
  const ecrMatch = hostname.match(ECR_PATTERN);
  if (ecrMatch) {
    return {
      type: "ecr",
      confidence: 1.0,
      details: {
        region: ecrMatch[2],
      },
      authSuggestions: [
        "Use AWS credentials (access key + secret key)",
        "Use IAM role (for EC2/ECS/Lambda)",
        "Use aws ecr get-login-password",
      ],
    };
  }

  // Check ACR
  const acrMatch = hostname.match(ACR_PATTERN);
  if (acrMatch) {
    return {
      type: "acr",
      confidence: 1.0,
      details: {
        registry: acrMatch[1],
      },
      authSuggestions: [
        "Use Azure service principal",
        "Use managed identity",
        "Use ACR admin credentials",
      ],
    };
  }

  // Check GCR/Artifact Registry
  for (const pattern of GCR_PATTERNS) {
    if (pattern.test(hostname)) {
      const isArtifactRegistry = hostname.includes("-docker.pkg.dev");
      return {
        type: isArtifactRegistry ? "gar" : "gcr",
        confidence: 1.0,
        authSuggestions: [
          "Use service account JSON key",
          "Use gcloud auth configure-docker",
          "Use default credentials (ADC)",
        ],
      };
    }
  }

  // Check GHCR
  if (GHCR_PATTERN.test(hostname)) {
    return {
      type: "ghcr",
      confidence: 1.0,
      authSuggestions: ["Use GitHub personal access token", "Use GITHUB_TOKEN in GitHub Actions"],
    };
  }

  // Check GitLab
  if (GITLAB_PATTERN.test(hostname)) {
    return {
      type: "gitlab",
      confidence: 1.0,
      authSuggestions: ["Use GitLab personal access token", "Use CI job token", "Use deploy token"],
    };
  }

  // Default to docker-registry with low confidence
  return {
    type: "docker-registry",
    confidence: 0.5,
    authSuggestions: ["Use username and password", "Use Docker credential helper"],
  };
}

/**
 * Check if a registry URL appears to be Harbor
 *
 * This requires an HTTP request to check for Harbor-specific endpoints
 */
export async function isHarborRegistry(url: string): Promise<boolean> {
  try {
    const baseUrl = url.startsWith("http") ? url : `https://${url}`;
    const response = await fetch(`${baseUrl}/api/v2.0/health`, {
      method: "HEAD",
      signal: AbortSignal.timeout(5000),
    });
    return response.ok;
  } catch {
    return false;
  }
}

// =============================================================================
// Registry Configuration Management
// =============================================================================

/**
 * Add or update a registry configuration
 */
export function configureRegistry(config: RegistryConfig): void {
  // Validate required fields
  if (!config.id) {
    throw new Error("Registry configuration must have an id");
  }
  if (!config.url) {
    throw new Error("Registry configuration must have a url");
  }

  // Auto-detect type if not provided
  if (!config.type) {
    const detected = detectRegistryType(config.url);
    config.type = detected.type;
  }

  // Set defaults
  config.enabled = config.enabled ?? true;

  registryStore.set(config.id, config);

  // If this is the default, unset default on others
  if (config.isDefault) {
    for (const [id, reg] of registryStore.entries()) {
      if (id !== config.id) {
        reg.isDefault = false;
      }
    }
  }
}

/**
 * Get a registry configuration by ID
 */
export function getRegistryConfig(id: string): RegistryConfig | undefined {
  return registryStore.get(id);
}

/**
 * List all configured registries
 */
export function listRegistryConfigs(
  options: {
    enabled?: boolean;
    type?: CloudRegistryType;
  } = {}
): RegistryConfig[] {
  let configs = Array.from(registryStore.values());

  if (options.enabled !== undefined) {
    configs = configs.filter((c) => c.enabled === options.enabled);
  }

  if (options.type) {
    configs = configs.filter((c) => c.type === options.type);
  }

  return configs;
}

/**
 * Remove a registry configuration
 */
export function removeRegistryConfig(id: string): boolean {
  // Also clear auth cache for this registry
  authCache.delete(id);
  return registryStore.delete(id);
}

/**
 * Get the default registry configuration
 */
export function getDefaultRegistry(): RegistryConfig | undefined {
  for (const config of registryStore.values()) {
    if (config.isDefault) {
      return config;
    }
  }
  // Return first enabled registry if no default
  for (const config of registryStore.values()) {
    if (config.enabled) {
      return config;
    }
  }
  return undefined;
}

/**
 * Clear all registry configurations
 */
export function clearRegistryConfigs(): void {
  registryStore.clear();
  authCache.clear();
}

// =============================================================================
// Cloud Authentication Handlers
// =============================================================================

/**
 * Get authentication token/credentials for a registry
 *
 * Handles cloud-specific auth flows:
 * - ECR: Uses AWS SDK to get auth token
 * - ACR: Uses Azure identity/admin credentials
 * - GCR: Uses service account or default credentials
 * - GHCR: Uses provided token
 * - Basic: Returns username/password
 */
export async function getRegistryAuth(registryConfig: RegistryConfig): Promise<RegistryAuthResult> {
  const cacheKey = registryConfig.id;

  // Check cache
  const cached = authCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.result;
  }

  const auth = registryConfig.auth;
  if (!auth) {
    return { success: true }; // Anonymous
  }

  let result: RegistryAuthResult;

  switch (auth.type) {
    case "basic":
      result = {
        success: true,
        username: auth.username,
        password: auth.password,
      };
      break;

    case "ecr":
      result = await getEcrAuth(registryConfig.url, auth);
      break;

    case "acr":
      result = await getAcrAuth(registryConfig.url, auth);
      break;

    case "gcr":
      result = await getGcrAuth(auth);
      break;

    case "ghcr":
      result = {
        success: true,
        username: auth.username || "token",
        password: auth.token,
      };
      break;

    case "anonymous":
      result = { success: true };
      break;

    default:
      result = { success: false, error: "Unknown auth type" };
  }

  // Cache successful results (with 11 hour expiry for 12-hour tokens)
  if (result.success) {
    const expiresAt = result.expiresAt
      ? new Date(result.expiresAt).getTime()
      : Date.now() + 11 * 60 * 60 * 1000;
    authCache.set(cacheKey, { result, expiresAt });
  }

  return result;
}

/**
 * Get AWS ECR authentication token
 *
 * In a full implementation, this would use the AWS SDK.
 * For now, it expects the user to provide credentials or use
 * the aws ecr get-login-password command externally.
 */
async function getEcrAuth(
  registryUrl: string,
  auth: { type: "ecr"; region: string; accessKeyId?: string; secretAccessKey?: string }
): Promise<RegistryAuthResult> {
  // Extract account ID from URL
  const match = registryUrl.match(/^(\d{12})\.dkr\.ecr\./);
  if (!match) {
    return { success: false, error: "Invalid ECR URL format" };
  }

  // If credentials provided, attempt to get auth token
  if (auth.accessKeyId && auth.secretAccessKey) {
    try {
      // This is a simplified implementation
      // In production, use @aws-sdk/client-ecr
      const endpoint = `https://api.ecr.${auth.region}.amazonaws.com`;
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-amz-json-1.1",
          "X-Amz-Target": "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken",
        },
        body: JSON.stringify({}),
      });

      if (!response.ok) {
        return {
          success: false,
          error: `ECR auth failed: ${response.status}`,
        };
      }

      const data = (await response.json()) as {
        authorizationData?: Array<{
          authorizationToken: string;
          expiresAt: string;
        }>;
      };
      const authData = data.authorizationData?.[0];
      if (authData) {
        const decoded = Buffer.from(authData.authorizationToken, "base64").toString();
        const [username, password] = decoded.split(":");
        return {
          success: true,
          username,
          password,
          expiresAt: authData.expiresAt,
        };
      }
    } catch (error) {
      return {
        success: false,
        error: `ECR auth error: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  return {
    success: false,
    error:
      "ECR requires AWS credentials. Use aws ecr get-login-password or provide accessKeyId/secretAccessKey",
  };
}

/**
 * Get Azure ACR authentication
 */
async function getAcrAuth(
  registryUrl: string,
  auth: {
    type: "acr";
    username?: string;
    password?: string;
    clientId?: string;
    clientSecret?: string;
    tenantId?: string;
  }
): Promise<RegistryAuthResult> {
  // If admin credentials provided
  if (auth.username && auth.password) {
    return {
      success: true,
      username: auth.username,
      password: auth.password,
    };
  }

  // If service principal credentials provided
  if (auth.clientId && auth.clientSecret && auth.tenantId) {
    try {
      // Get Azure AD token
      const tokenUrl = `https://login.microsoftonline.com/${auth.tenantId}/oauth2/v2.0/token`;
      const tokenResponse = await fetch(tokenUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id: auth.clientId,
          client_secret: auth.clientSecret,
          scope: `https://${registryUrl}/.default`,
        }),
      });

      if (!tokenResponse.ok) {
        return {
          success: false,
          error: `Azure AD auth failed: ${tokenResponse.status}`,
        };
      }

      const tokenData = (await tokenResponse.json()) as {
        access_token: string;
        expires_in: number;
      };
      return {
        success: true,
        username: "00000000-0000-0000-0000-000000000000",
        password: tokenData.access_token,
        expiresAt: new Date(Date.now() + tokenData.expires_in * 1000).toISOString(),
      };
    } catch (error) {
      return {
        success: false,
        error: `ACR auth error: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  return {
    success: false,
    error: "ACR requires admin credentials or service principal",
  };
}

/**
 * Get Google GCR/Artifact Registry authentication
 */
async function getGcrAuth(auth: {
  type: "gcr";
  serviceAccountKey?: string | object;
}): Promise<RegistryAuthResult> {
  if (auth.serviceAccountKey) {
    try {
      // Parse service account key if string
      const key =
        typeof auth.serviceAccountKey === "string"
          ? JSON.parse(
              auth.serviceAccountKey.startsWith("{")
                ? auth.serviceAccountKey
                : Buffer.from(auth.serviceAccountKey, "base64").toString()
            )
          : auth.serviceAccountKey;

      // Use service account email as username, key as password
      return {
        success: true,
        username: "_json_key",
        password: JSON.stringify(key),
      };
    } catch (error) {
      return {
        success: false,
        error: `GCR auth error: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  return {
    success: false,
    error: "GCR requires service account key or default credentials",
  };
}

// =============================================================================
// Multi-Registry Scanning
// =============================================================================

/**
 * Create empty vulnerability counts
 */
function createEmptyCounts(): VulnerabilityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: 0 };
}

/**
 * Add vulnerability counts
 */
function addCounts(a: VulnerabilityCounts, b: VulnerabilityCounts): VulnerabilityCounts {
  return {
    critical: a.critical + b.critical,
    high: a.high + b.high,
    medium: a.medium + b.medium,
    low: a.low + b.low,
    unknown: a.unknown + b.unknown,
    total: a.total + b.total,
  };
}

/**
 * Scan multiple registries
 *
 * @param options - Multi-registry scan options
 * @returns Aggregated results from all registries
 *
 * @example
 * ```typescript
 * const result = await scanMultipleRegistries({
 *   registries: ["ecr-prod", "ghcr-dev"],
 *   concurrency: 5,
 *   severity: "HIGH,CRITICAL",
 * });
 * ```
 */
export async function scanMultipleRegistries(
  options: MultiRegistryScanOptions
): Promise<MultiRegistryScanResult> {
  const {
    registries: registryIds,
    repositories,
    tagFilter,
    concurrency = 3,
    severity = "HIGH,CRITICAL",
    limitPerRegistry,
    latestOnly = false,
    continueOnError = true,
  } = options;

  const startedAt = new Date().toISOString();
  const startTime = Date.now();
  const results: MultiRegistryScanResult["registries"] = [];
  let totalVulnerabilities = createEmptyCounts();
  let totalImagesScanned = 0;
  let totalFailedScans = 0;

  for (const registryId of registryIds) {
    // Look up registry config
    let registryConfig = getRegistryConfig(registryId);

    // If not found by ID, treat as URL and auto-detect
    if (!registryConfig) {
      const detected = detectRegistryType(registryId);
      registryConfig = {
        id: registryId,
        name: registryId,
        type: detected.type,
        url: registryId,
        enabled: true,
      };
    }

    try {
      // Get auth credentials
      const authResult = await getRegistryAuth(registryConfig);
      if (!authResult.success) {
        throw new Error(authResult.error || "Authentication failed");
      }

      // Scan the registry
      const scanResult = await scanRegistry({
        registry: registryConfig.url,
        repositories,
        tagFilter,
        concurrency,
        severity,
        limit: limitPerRegistry,
        allTags: !latestOnly,
      });

      results.push({
        registry: registryConfig.id,
        type: registryConfig.type,
        success: true,
        result: scanResult,
      });

      totalVulnerabilities = addCounts(totalVulnerabilities, scanResult.vulnerabilities);
      totalImagesScanned += scanResult.discovery.imagesScanned;
      totalFailedScans += scanResult.failedImages.length;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      results.push({
        registry: registryConfig.id,
        type: registryConfig.type,
        success: false,
        error: errorMessage,
      });

      if (!continueOnError) {
        break;
      }
    }
  }

  return {
    startedAt,
    completedAt: new Date().toISOString(),
    durationMs: Date.now() - startTime,
    registries: results,
    totalVulnerabilities,
    totalImagesScanned,
    totalFailedScans,
  };
}

/**
 * Test connectivity to a registry
 */
export async function testRegistryConnection(
  registryConfig: RegistryConfig
): Promise<{ success: boolean; error?: string; latencyMs?: number }> {
  const startTime = Date.now();

  try {
    // Get auth credentials
    const authResult = await getRegistryAuth(registryConfig);
    if (!authResult.success) {
      return { success: false, error: authResult.error };
    }

    // Try to access the registry's v2 API
    const baseUrl = registryConfig.url.startsWith("http")
      ? registryConfig.url
      : `https://${registryConfig.url}`;

    const headers: Record<string, string> = {};
    if (authResult.username && authResult.password) {
      headers["Authorization"] = `Basic ${Buffer.from(
        `${authResult.username}:${authResult.password}`
      ).toString("base64")}`;
    }

    const response = await fetch(`${baseUrl}/v2/`, {
      headers,
      signal: AbortSignal.timeout(10000),
    });

    if (response.ok || response.status === 401) {
      // 401 is expected for unauthenticated but valid registries
      return {
        success: response.ok,
        latencyMs: Date.now() - startTime,
        error: response.status === 401 ? "Authentication required" : undefined,
      };
    }

    return {
      success: false,
      error: `Registry returned ${response.status}`,
      latencyMs: Date.now() - startTime,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : String(error),
      latencyMs: Date.now() - startTime,
    };
  }
}
