/**
 * SAML 2.0 Validation Module
 *
 * Provides SAML assertion validation and SP metadata generation
 * using the @node-saml/node-saml library.
 */

import { SAML } from "@node-saml/node-saml";
import type {
  SamlProviderConfig,
  SsoSession,
  SsoValidationResult,
  SsoMetadataResult,
} from "./types.js";
import { getSamlProvider, createSsoSession, logSsoAudit } from "./sso-config.js";

// =============================================================================
// Types
// =============================================================================

interface SamlValidationOptions {
  /** IP address of the requester */
  ipAddress?: string;
  /** User agent string */
  userAgent?: string;
}

// =============================================================================
// SAML Instance Cache
// =============================================================================

const samlInstances = new Map<string, SAML>();

/**
 * Get or create a SAML instance for a provider
 */
function getSamlInstance(config: SamlProviderConfig): SAML {
  const cached = samlInstances.get(config.id);
  if (cached) {
    return cached;
  }

  const saml = new SAML({
    callbackUrl: config.spAcsUrl,
    entryPoint: config.idpSsoUrl,
    issuer: config.spEntityId,
    idpCert: config.idpCertificate,
    logoutUrl: config.idpSloUrl,
    wantAssertionsSigned: config.wantAssertionsSigned ?? true,
    wantAuthnResponseSigned: config.wantResponseSigned ?? false,
    signatureAlgorithm: "sha256",
    digestAlgorithm: "sha256",
  });

  samlInstances.set(config.id, saml);
  return saml;
}

/**
 * Clear cached SAML instance for a provider
 */
export function clearSamlInstanceCache(providerId?: string): void {
  if (providerId) {
    samlInstances.delete(providerId);
  } else {
    samlInstances.clear();
  }
}

// =============================================================================
// SP Metadata Generation
// =============================================================================

/**
 * Generate SAML Service Provider metadata XML
 */
export function generateSpMetadata(providerId: string): SsoMetadataResult | null {
  const config = getSamlProvider(providerId);
  if (!config) {
    return null;
  }

  const entityId = config.spEntityId;
  const acsUrl = config.spAcsUrl;
  const sloUrl = config.spSloUrl;

  // Generate SP metadata XML
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="${escapeXml(entityId)}">
  <md:SPSSODescriptor AuthnRequestsSigned="false"
                      WantAssertionsSigned="${config.wantAssertionsSigned ? "true" : "false"}"
                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                 Location="${escapeXml(acsUrl)}"
                                 index="0"
                                 isDefault="true"/>
${
  sloUrl
    ? `    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="${escapeXml(sloUrl)}"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="${escapeXml(sloUrl)}"/>`
    : ""
}
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;

  return {
    xml,
    entityId,
    acsUrl,
  };
}

/**
 * Escape special XML characters
 */
function escapeXml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

// =============================================================================
// SAML Assertion Validation
// =============================================================================

/**
 * Validate a SAML assertion and create a session
 */
export async function validateSamlAssertion(
  providerId: string,
  samlResponse: string,
  options?: SamlValidationOptions
): Promise<SsoValidationResult> {
  const config = getSamlProvider(providerId);

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
    const saml = getSamlInstance(config);

    // Validate the SAML response
    const result = await saml.validatePostResponseAsync({
      SAMLResponse: samlResponse,
    });

    if (!result || !result.profile) {
      throw new Error("Invalid SAML response: no profile returned");
    }

    const profile = result.profile;
    // Profile can contain nameID, nameIDFormat, sessionIndex, and arbitrary SAML attributes
    const attributes = profile as unknown as Record<string, string | string[]>;

    // Extract user attributes using attribute mapping
    const email = extractAttribute(attributes, config.attributeMapping.email) || profile.nameID;
    const name = extractAttribute(attributes, config.attributeMapping.name) || email;
    const groups = extractGroupsAttribute(attributes, config.attributeMapping.groups);
    const userId = config.attributeMapping.userId
      ? extractAttribute(attributes, config.attributeMapping.userId) || profile.nameID
      : profile.nameID;

    // Calculate session expiration (default 1 hour)
    const sessionMaxAge = parseInt(process.env.SSO_SESSION_MAX_AGE || "3600", 10) * 1000;
    const expiresAt = new Date(Date.now() + sessionMaxAge).toISOString();

    // Create session
    const session = createSsoSession({
      providerId,
      providerType: "saml",
      userId,
      email,
      name,
      groups,
      claims: {
        nameID: profile.nameID,
        nameIDFormat: profile.nameIDFormat,
        sessionIndex: profile.sessionIndex,
        ...attributes,
      },
      expiresAt,
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
      details: { nameIDFormat: profile.nameIDFormat },
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
    if (errorMessage.includes("signature")) {
      errorCode = "INVALID_SIGNATURE";
    } else if (errorMessage.includes("expired") || errorMessage.includes("NotOnOrAfter")) {
      errorCode = "EXPIRED";
    } else if (errorMessage.includes("audience") || errorMessage.includes("Audience")) {
      errorCode = "INVALID_AUDIENCE";
    } else if (errorMessage.includes("issuer") || errorMessage.includes("Issuer")) {
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
 * Extract a single attribute value from SAML attributes
 */
function extractAttribute(
  attributes: Record<string, string | string[]>,
  attributeName?: string
): string | undefined {
  if (!attributeName) {
    return undefined;
  }

  const value = attributes[attributeName];
  if (!value) {
    return undefined;
  }

  return Array.isArray(value) ? value[0] : value;
}

/**
 * Extract groups from SAML attributes
 */
function extractGroupsAttribute(
  attributes: Record<string, string | string[]>,
  attributeName?: string
): string[] {
  if (!attributeName) {
    return [];
  }

  const value = attributes[attributeName];
  if (!value) {
    return [];
  }

  return Array.isArray(value) ? value : [value];
}

// =============================================================================
// SAML Logout
// =============================================================================

/**
 * Generate a SAML logout request
 */
export async function generateSamlLogoutRequest(
  providerId: string,
  session: SsoSession
): Promise<{ url: string; request: string } | null> {
  const config = getSamlProvider(providerId);
  if (!config || !config.idpSloUrl) {
    return null;
  }

  const saml = getSamlInstance(config);

  try {
    // Get nameID and sessionIndex from session claims
    const nameID = session.claims.nameID as string;
    const nameIDFormat = session.claims.nameIDFormat as string | undefined;
    const sessionIndex = session.claims.sessionIndex as string | undefined;

    // Generate logout URL - construct user object compatible with SAML library Profile type
    const user = {
      nameID,
      nameIDFormat,
      sessionIndex,
    } as Parameters<typeof saml.getLogoutUrlAsync>[0];
    const logoutUrl = await saml.getLogoutUrlAsync(user, "", {});

    return {
      url: logoutUrl,
      request: logoutUrl, // The request is embedded in the URL
    };
  } catch (error) {
    console.error("Failed to generate SAML logout request:", error);
    return null;
  }
}

/**
 * Validate a SAML logout response
 */
export async function validateSamlLogoutResponse(
  providerId: string,
  samlResponse: string
): Promise<{ success: boolean; error?: string }> {
  const config = getSamlProvider(providerId);
  if (!config) {
    return { success: false, error: "Provider not found" };
  }

  const saml = getSamlInstance(config);

  try {
    await saml.validatePostResponseAsync({
      SAMLResponse: samlResponse,
    });

    return { success: true };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return { success: false, error: errorMessage };
  }
}

// =============================================================================
// SAML Request Generation
// =============================================================================

/**
 * Generate a SAML authentication request URL
 * (for initiating SSO - typically used by external auth proxies)
 */
export async function generateSamlAuthRequest(
  providerId: string,
  relayState?: string
): Promise<{ url: string; request: string } | null> {
  const config = getSamlProvider(providerId);
  if (!config) {
    return null;
  }

  const saml = getSamlInstance(config);

  try {
    // getAuthorizeUrlAsync takes (RelayState, host, options)
    const authRequest = await saml.getAuthorizeUrlAsync(relayState || "", undefined, {});

    return {
      url: authRequest,
      request: authRequest,
    };
  } catch (error) {
    console.error("Failed to generate SAML auth request:", error);
    return null;
  }
}
