/**
 * OIDC (OpenID Connect) Validation Module
 *
 * Provides OIDC token validation, discovery, and token refresh
 * using jsonwebtoken and jwks-rsa libraries.
 */

import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import type { OidcProviderConfig, SsoValidationResult } from "./types.js";
import {
  getOidcProvider,
  getSsoProviderByIssuer,
  createSsoSession,
  logSsoAudit,
} from "./sso-config.js";

// =============================================================================
// Types
// =============================================================================

interface OidcDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  id_token_signing_alg_values_supported?: string[];
  end_session_endpoint?: string;
  introspection_endpoint?: string;
}

interface OidcTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  nonce?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  groups?: string[];
  [key: string]: unknown;
}

interface OidcValidationOptions {
  /** Token type being validated */
  tokenType?: "id_token" | "access_token";
  /** Expected nonce (for id_token validation) */
  nonce?: string;
  /** IP address of the requester */
  ipAddress?: string;
  /** User agent string */
  userAgent?: string;
}

// =============================================================================
// JWKS Client Cache
// =============================================================================

const jwksClients = new Map<string, jwksClient.JwksClient>();
const discoveryCache = new Map<string, { doc: OidcDiscoveryDocument; expires: number }>();

/**
 * Get or create a JWKS client for a provider
 */
function getJwksClient(jwksUri: string): jwksClient.JwksClient {
  const cached = jwksClients.get(jwksUri);
  if (cached) {
    return cached;
  }

  const client = jwksClient({
    jwksUri,
    cache: true,
    cacheMaxAge: 600000, // 10 minutes
    rateLimit: true,
    jwksRequestsPerMinute: 10,
  });

  jwksClients.set(jwksUri, client);
  return client;
}

/**
 * Clear JWKS client cache
 */
export function clearJwksCache(jwksUri?: string): void {
  if (jwksUri) {
    jwksClients.delete(jwksUri);
  } else {
    jwksClients.clear();
  }
}

/**
 * Clear discovery document cache
 */
export function clearDiscoveryCache(discoveryUrl?: string): void {
  if (discoveryUrl) {
    discoveryCache.delete(discoveryUrl);
  } else {
    discoveryCache.clear();
  }
}

// =============================================================================
// OIDC Discovery
// =============================================================================

/**
 * Fetch OIDC discovery document
 */
export async function discoverOidcProvider(
  discoveryUrl: string
): Promise<OidcDiscoveryDocument | null> {
  // Check cache (5 minute TTL)
  const cached = discoveryCache.get(discoveryUrl);
  if (cached && cached.expires > Date.now()) {
    return cached.doc;
  }

  try {
    const response = await fetch(discoveryUrl);
    if (!response.ok) {
      throw new Error(`Failed to fetch discovery document: ${response.status}`);
    }

    const doc = (await response.json()) as OidcDiscoveryDocument;

    // Cache for 5 minutes
    discoveryCache.set(discoveryUrl, {
      doc,
      expires: Date.now() + 300000,
    });

    return doc;
  } catch (error) {
    console.error("OIDC discovery failed:", error);
    return null;
  }
}

/**
 * Get JWKS URI for a provider (via discovery or config)
 */
async function getJwksUri(config: OidcProviderConfig): Promise<string | null> {
  if (config.jwksUri) {
    return config.jwksUri;
  }

  if (config.discoveryUrl) {
    const doc = await discoverOidcProvider(config.discoveryUrl);
    return doc?.jwks_uri || null;
  }

  // Try standard discovery URL
  const standardDiscoveryUrl = `${config.issuer}/.well-known/openid-configuration`;
  const doc = await discoverOidcProvider(standardDiscoveryUrl);
  return doc?.jwks_uri || null;
}

// =============================================================================
// Token Validation
// =============================================================================

/**
 * Validate an OIDC token (ID token or access token)
 */
export async function validateOidcToken(
  providerId: string,
  token: string,
  options?: OidcValidationOptions
): Promise<SsoValidationResult> {
  const config = getOidcProvider(providerId);

  if (!config) {
    logSsoAudit({
      eventType: "TOKEN_VALIDATION",
      providerId,
      status: "FAILURE",
      errorMessage: "Provider not found",
      ipAddress: options?.ipAddress,
      userAgent: options?.userAgent,
    });

    return {
      valid: false,
      error: "Provider not found",
      errorCode: "PROVIDER_NOT_FOUND",
    };
  }

  if (!config.enabled) {
    logSsoAudit({
      eventType: "TOKEN_VALIDATION",
      providerId,
      status: "FAILURE",
      errorMessage: "Provider is disabled",
      ipAddress: options?.ipAddress,
      userAgent: options?.userAgent,
    });

    return {
      valid: false,
      error: "Provider is disabled",
      errorCode: "PROVIDER_DISABLED",
    };
  }

  try {
    // Get JWKS URI
    const jwksUri = await getJwksUri(config);
    if (!jwksUri) {
      throw new Error("Could not determine JWKS URI for token validation");
    }

    // Decode token header to get key ID
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded === "string") {
      throw new Error("Invalid token format");
    }

    const kid = decoded.header.kid;
    if (!kid) {
      throw new Error("Token missing key ID (kid)");
    }

    // Get signing key from JWKS
    const client = getJwksClient(jwksUri);
    const key = await client.getSigningKey(kid);
    const signingKey = key.getPublicKey();

    // Verify token
    const claims = jwt.verify(token, signingKey, {
      issuer: config.issuer,
      audience: config.clientId,
      algorithms: ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
    }) as OidcTokenClaims;

    // Validate nonce if provided
    if (options?.nonce && claims.nonce !== options.nonce) {
      throw new Error("Token nonce does not match");
    }

    // Extract user attributes using attribute mapping
    const email =
      extractClaim(claims, config.attributeMapping.email) ||
      claims.email ||
      claims.preferred_username ||
      claims.sub;
    const name = extractClaim(claims, config.attributeMapping.name) || claims.name || email;
    const groups = extractGroupsClaim(claims, config.attributeMapping.groups);
    const userId = config.attributeMapping.userId
      ? extractClaim(claims, config.attributeMapping.userId) || claims.sub
      : claims.sub;

    // Calculate session expiration based on token exp
    const tokenExp = new Date(claims.exp * 1000);
    const sessionMaxAge = parseInt(process.env.SSO_SESSION_MAX_AGE || "3600", 10) * 1000;
    const maxSessionExp = new Date(Date.now() + sessionMaxAge);
    const expiresAt = tokenExp < maxSessionExp ? tokenExp : maxSessionExp;

    // Create session
    const session = createSsoSession({
      providerId,
      providerType: "oidc",
      userId,
      email,
      name,
      groups,
      claims: claims as unknown as Record<string, unknown>,
      accessToken: options?.tokenType === "access_token" ? token : undefined,
      expiresAt: expiresAt.toISOString(),
    });

    logSsoAudit({
      eventType: "LOGIN",
      providerId,
      sessionId: session.id,
      userId: session.userId,
      email: session.email,
      status: "SUCCESS",
      ipAddress: options?.ipAddress,
      userAgent: options?.userAgent,
      details: { tokenType: options?.tokenType || "id_token" },
    });

    return {
      valid: true,
      session,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);

    logSsoAudit({
      eventType: "TOKEN_VALIDATION",
      providerId,
      status: "FAILURE",
      errorMessage,
      ipAddress: options?.ipAddress,
      userAgent: options?.userAgent,
    });

    // Determine error code
    let errorCode: SsoValidationResult["errorCode"] = "INVALID_TOKEN";
    if (errorMessage.includes("signature") || errorMessage.includes("verify")) {
      errorCode = "INVALID_SIGNATURE";
    } else if (errorMessage.includes("expired") || errorMessage.includes("exp")) {
      errorCode = "EXPIRED";
    } else if (errorMessage.includes("audience") || errorMessage.includes("aud")) {
      errorCode = "INVALID_AUDIENCE";
    } else if (errorMessage.includes("issuer") || errorMessage.includes("iss")) {
      errorCode = "INVALID_ISSUER";
    }

    return {
      valid: false,
      error: errorMessage,
      errorCode,
    };
  }
}

/**
 * Validate a token and find the provider by issuer
 */
export async function validateOidcTokenByIssuer(
  token: string,
  options?: OidcValidationOptions
): Promise<SsoValidationResult> {
  // Decode token to get issuer
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || typeof decoded === "string") {
    return {
      valid: false,
      error: "Invalid token format",
      errorCode: "INVALID_TOKEN",
    };
  }

  const claims = decoded.payload as OidcTokenClaims;
  if (!claims.iss) {
    return {
      valid: false,
      error: "Token missing issuer claim",
      errorCode: "INVALID_TOKEN",
    };
  }

  // Find provider by issuer
  const config = getSsoProviderByIssuer(claims.iss);
  if (!config) {
    return {
      valid: false,
      error: `No provider configured for issuer: ${claims.iss}`,
      errorCode: "PROVIDER_NOT_FOUND",
    };
  }

  return validateOidcToken(config.id, token, options);
}

/**
 * Extract a claim value
 */
function extractClaim(claims: OidcTokenClaims, claimName?: string): string | undefined {
  if (!claimName) {
    return undefined;
  }

  const value = claims[claimName];
  if (value === undefined || value === null) {
    return undefined;
  }

  return String(value);
}

/**
 * Extract groups from claims
 */
function extractGroupsClaim(claims: OidcTokenClaims, claimName?: string): string[] {
  if (!claimName) {
    return claims.groups || [];
  }

  const value = claims[claimName];
  if (!value) {
    return [];
  }

  if (Array.isArray(value)) {
    return value.map(String);
  }

  return [String(value)];
}

// =============================================================================
// Token Introspection
// =============================================================================

/**
 * Introspect an access token (check if active)
 */
export async function introspectOidcToken(
  providerId: string,
  token: string
): Promise<{ active: boolean; claims?: Record<string, unknown>; error?: string }> {
  const config = getOidcProvider(providerId);
  if (!config) {
    return { active: false, error: "Provider not found" };
  }

  // Get introspection endpoint from discovery
  let introspectionEndpoint: string | undefined;

  if (config.discoveryUrl) {
    const doc = await discoverOidcProvider(config.discoveryUrl);
    introspectionEndpoint = doc?.introspection_endpoint;
  }

  if (!introspectionEndpoint) {
    // Try standard introspection endpoint
    introspectionEndpoint = `${config.issuer}/oauth2/introspect`;
  }

  try {
    const auth = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString("base64");

    const response = await fetch(introspectionEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${auth}`,
      },
      body: new URLSearchParams({ token }).toString(),
    });

    if (!response.ok) {
      throw new Error(`Introspection failed: ${response.status}`);
    }

    const result = (await response.json()) as { active: boolean; [key: string]: unknown };

    return {
      active: result.active,
      claims: result.active ? result : undefined,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return { active: false, error: errorMessage };
  }
}

// =============================================================================
// Token Refresh
// =============================================================================

/**
 * Refresh an OIDC access token using a refresh token
 */
export async function refreshOidcToken(
  providerId: string,
  refreshToken: string
): Promise<{
  success: boolean;
  accessToken?: string;
  refreshToken?: string;
  expiresIn?: number;
  error?: string;
}> {
  const config = getOidcProvider(providerId);
  if (!config) {
    return { success: false, error: "Provider not found" };
  }

  // Get token endpoint from discovery
  let tokenEndpoint: string | undefined;

  if (config.discoveryUrl) {
    const doc = await discoverOidcProvider(config.discoveryUrl);
    tokenEndpoint = doc?.token_endpoint;
  }

  if (!tokenEndpoint) {
    // Try standard token endpoint
    tokenEndpoint = `${config.issuer}/oauth2/token`;
  }

  try {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: config.clientId,
      client_secret: config.clientSecret,
    });

    const response = await fetch(tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`Token refresh failed: ${response.status} - ${errorBody}`);
    }

    const result = (await response.json()) as {
      access_token: string;
      refresh_token?: string;
      expires_in?: number;
      token_type: string;
    };

    logSsoAudit({
      eventType: "TOKEN_REFRESH",
      providerId,
      status: "SUCCESS",
    });

    return {
      success: true,
      accessToken: result.access_token,
      refreshToken: result.refresh_token,
      expiresIn: result.expires_in,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);

    logSsoAudit({
      eventType: "TOKEN_REFRESH",
      providerId,
      status: "FAILURE",
      errorMessage,
    });

    return { success: false, error: errorMessage };
  }
}

// =============================================================================
// User Info
// =============================================================================

/**
 * Get user info from the userinfo endpoint
 */
export async function getOidcUserInfo(
  providerId: string,
  accessToken: string
): Promise<{ success: boolean; userInfo?: Record<string, unknown>; error?: string }> {
  const config = getOidcProvider(providerId);
  if (!config) {
    return { success: false, error: "Provider not found" };
  }

  // Get userinfo endpoint from discovery
  let userinfoEndpoint: string | undefined;

  if (config.discoveryUrl) {
    const doc = await discoverOidcProvider(config.discoveryUrl);
    userinfoEndpoint = doc?.userinfo_endpoint;
  }

  if (!userinfoEndpoint) {
    // Try standard userinfo endpoint
    userinfoEndpoint = `${config.issuer}/userinfo`;
  }

  try {
    const response = await fetch(userinfoEndpoint, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(`UserInfo request failed: ${response.status}`);
    }

    const userInfo = (await response.json()) as Record<string, unknown>;

    return {
      success: true,
      userInfo,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return { success: false, error: errorMessage };
  }
}
