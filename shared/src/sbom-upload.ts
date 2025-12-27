/**
 * SBOM Upload Module
 *
 * Automates the workflow of generating SBOMs with Trivy and uploading
 * them to Dependency-Track for vulnerability tracking.
 */

import { config } from "./config.js";
import { fetchJson } from "./http.js";
import { trivyGenerateSbom, trivyGenerateSbomImage } from "./handlers.js";
import { auditOperation } from "./audit.js";
import type {
  SbomUploadOptions,
  SbomUploadResult,
  DTrackProjectCreateOptions,
  DTrackProjectCreateResult,
  DTrackProject,
  TrivySbomResult,
} from "./types.js";

// =============================================================================
// Constants
// =============================================================================

const DEFAULT_PROJECT_VERSION = "latest";
const DEFAULT_PROCESSING_TIMEOUT = 30000; // 30 seconds

// =============================================================================
// Project Management
// =============================================================================

/**
 * Look up a project by name and version in Dependency-Track
 *
 * @param name - Project name to search for
 * @param version - Project version (optional, defaults to "latest")
 * @returns Promise resolving to project if found, null otherwise
 */
export async function dtrackLookupProject(
  name: string,
  version: string = DEFAULT_PROJECT_VERSION
): Promise<DTrackProject | null> {
  if (!config.dependencyTrack.apiKey) {
    throw new Error(
      "Dependency-Track API key not configured. Set DTRACK_API_KEY environment variable."
    );
  }

  try {
    // Use the lookup endpoint to find by name and version
    const project = await fetchJson<DTrackProject>(
      `${config.dependencyTrack.url}/api/v1/project/lookup?name=${encodeURIComponent(name)}&version=${encodeURIComponent(version)}`,
      {
        headers: { "X-Api-Key": config.dependencyTrack.apiKey },
      }
    );
    return project;
  } catch (error) {
    // 404 means project not found
    const err = error as { message?: string };
    if (err.message?.includes("404") || err.message?.includes("Not Found")) {
      return null;
    }
    throw error;
  }
}

/**
 * Create a new project in Dependency-Track
 *
 * @param options - Project creation options
 * @returns Promise resolving to created project details
 */
export async function dtrackCreateProject(
  options: DTrackProjectCreateOptions
): Promise<DTrackProjectCreateResult> {
  if (!config.dependencyTrack.apiKey) {
    throw new Error(
      "Dependency-Track API key not configured. Set DTRACK_API_KEY environment variable."
    );
  }

  const { name, version = DEFAULT_PROJECT_VERSION, description, tags, parent } = options;

  const body: Record<string, unknown> = {
    name,
    version,
    active: true,
  };

  if (description) {
    body.description = description;
  }

  if (tags && tags.length > 0) {
    body.tags = tags.map((tag) => ({ name: tag }));
  }

  if (parent) {
    body.parent = { uuid: parent };
  }

  const result = await fetchJson<DTrackProjectCreateResult>(
    `${config.dependencyTrack.url}/api/v1/project`,
    {
      method: "PUT",
      headers: {
        "X-Api-Key": config.dependencyTrack.apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    }
  );

  const audit = auditOperation("dtrack_create_project", "sbom-upload", name);
  audit.start();
  audit.complete({ projectVersion: version, projectUuid: result.uuid, tags, parent });

  return result;
}

/**
 * Get or create a project in Dependency-Track
 *
 * @param name - Project name
 * @param version - Project version
 * @param createOptions - Additional options for project creation if needed
 * @returns Promise resolving to project details and whether it was created
 */
export async function dtrackGetOrCreateProject(
  name: string,
  version: string = DEFAULT_PROJECT_VERSION,
  createOptions?: Partial<DTrackProjectCreateOptions>
): Promise<{ project: DTrackProject | DTrackProjectCreateResult; created: boolean }> {
  // Try to find existing project
  const existing = await dtrackLookupProject(name, version);
  if (existing) {
    return { project: existing, created: false };
  }

  // Create new project
  const created = await dtrackCreateProject({
    name,
    version,
    ...createOptions,
  });

  return { project: created, created: true };
}

/**
 * Upload an SBOM to Dependency-Track with base64 encoding
 *
 * @param projectUuid - Target project UUID
 * @param sbomContent - SBOM content as string (JSON)
 * @returns Promise resolving to upload token
 */
export async function dtrackUploadSbomToProject(
  projectUuid: string,
  sbomContent: string
): Promise<{ token: string }> {
  if (!config.dependencyTrack.apiKey) {
    throw new Error(
      "Dependency-Track API key not configured. Set DTRACK_API_KEY environment variable."
    );
  }

  // Encode SBOM as base64
  const sbomBase64 = Buffer.from(sbomContent).toString("base64");

  const result = await fetchJson<{ token: string }>(`${config.dependencyTrack.url}/api/v1/bom`, {
    method: "PUT",
    headers: {
      "X-Api-Key": config.dependencyTrack.apiKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      project: projectUuid,
      bom: sbomBase64,
    }),
  });

  return result;
}

/**
 * Check if SBOM processing is complete
 *
 * @param token - Upload token from SBOM upload
 * @returns Promise resolving to processing status
 */
export async function dtrackCheckBomProcessing(token: string): Promise<{ processing: boolean }> {
  if (!config.dependencyTrack.apiKey) {
    throw new Error(
      "Dependency-Track API key not configured. Set DTRACK_API_KEY environment variable."
    );
  }

  try {
    const result = await fetchJson<{ processing: boolean }>(
      `${config.dependencyTrack.url}/api/v1/bom/token/${token}`,
      {
        headers: { "X-Api-Key": config.dependencyTrack.apiKey },
      }
    );
    return result;
  } catch {
    // If token endpoint fails, assume processing is complete
    return { processing: false };
  }
}

/**
 * Wait for SBOM processing to complete
 *
 * @param token - Upload token
 * @param timeout - Maximum wait time in milliseconds
 * @returns Promise resolving when processing is complete
 */
export async function dtrackWaitForProcessing(
  token: string,
  timeout: number = DEFAULT_PROCESSING_TIMEOUT
): Promise<void> {
  const startTime = Date.now();
  const pollInterval = 1000; // 1 second

  while (Date.now() - startTime < timeout) {
    const status = await dtrackCheckBomProcessing(token);
    if (!status.processing) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, pollInterval));
  }

  throw new Error(`SBOM processing timed out after ${timeout}ms`);
}

// =============================================================================
// Main Upload Function
// =============================================================================

/**
 * Generate SBOM and upload to Dependency-Track
 *
 * This function orchestrates the complete workflow:
 * 1. Generate SBOM using Trivy
 * 2. Look up or create project in Dependency-Track
 * 3. Upload SBOM to the project
 * 4. Optionally wait for processing to complete
 *
 * @param options - Upload options
 * @returns Promise resolving to upload result with project details
 *
 * @example
 * ```typescript
 * // Upload SBOM for a Docker image
 * const result = await uploadSbomToDtrack({
 *   target: 'nginx:latest',
 *   targetType: 'image',
 *   projectName: 'nginx',
 *   projectVersion: 'latest',
 *   autoCreateProject: true,
 * });
 * console.log(result.projectUuid); // Use for vulnerability tracking
 *
 * // Upload SBOM for a local path
 * const result = await uploadSbomToDtrack({
 *   target: '/path/to/project',
 *   targetType: 'path',
 *   projectName: 'my-project',
 *   projectVersion: '1.0.0',
 * });
 * ```
 */
export async function uploadSbomToDtrack(options: SbomUploadOptions): Promise<SbomUploadResult> {
  const {
    target,
    targetType = "image",
    projectName,
    projectVersion = DEFAULT_PROJECT_VERSION,
    autoCreateProject = true,
    tags,
    parentUuid,
    sbomFormat = "cyclonedx",
    waitForProcessing = false,
    processingTimeout = DEFAULT_PROCESSING_TIMEOUT,
  } = options;

  // Determine project name from target if not provided
  const resolvedProjectName = projectName || deriveProjectName(target, targetType);

  try {
    // Step 1: Generate SBOM using Trivy
    let sbomResult: TrivySbomResult | { error: string; output?: string };

    if (targetType === "image") {
      sbomResult = await trivyGenerateSbomImage(target, sbomFormat);
    } else {
      sbomResult = await trivyGenerateSbom(target, sbomFormat);
    }

    // Check for error response
    if ("error" in sbomResult) {
      return {
        success: false,
        projectUuid: "",
        projectName: resolvedProjectName,
        projectVersion,
        componentsCount: 0,
        token: "",
        projectCreated: false,
        uploadedAt: new Date().toISOString(),
        error: sbomResult.error,
      };
    }

    // Count components in SBOM
    const componentsCount = sbomResult.components?.length ?? 0;

    // Step 2: Get or create project in Dependency-Track
    let projectUuid: string;
    let projectCreated = false;

    if (autoCreateProject) {
      const { project, created } = await dtrackGetOrCreateProject(
        resolvedProjectName,
        projectVersion,
        { tags, parent: parentUuid }
      );
      projectUuid = project.uuid;
      projectCreated = created;
    } else {
      const existing = await dtrackLookupProject(resolvedProjectName, projectVersion);
      if (!existing) {
        return {
          success: false,
          projectUuid: "",
          projectName: resolvedProjectName,
          projectVersion,
          componentsCount,
          token: "",
          projectCreated: false,
          uploadedAt: new Date().toISOString(),
          error: `Project '${resolvedProjectName}:${projectVersion}' not found and autoCreateProject is disabled`,
        };
      }
      projectUuid = existing.uuid;
    }

    // Step 3: Upload SBOM to project
    const sbomJson = JSON.stringify(sbomResult);
    const uploadResult = await dtrackUploadSbomToProject(projectUuid, sbomJson);

    // Step 4: Optionally wait for processing
    if (waitForProcessing) {
      await dtrackWaitForProcessing(uploadResult.token, processingTimeout);
    }

    // Audit the successful upload
    const uploadAudit = auditOperation("sbom_upload", "sbom-upload", target);
    uploadAudit.start();
    uploadAudit.complete({
      targetType,
      projectName: resolvedProjectName,
      projectVersion,
      projectUuid,
      componentsCount,
      projectCreated,
    });

    return {
      success: true,
      projectUuid,
      projectName: resolvedProjectName,
      projectVersion,
      componentsCount,
      token: uploadResult.token,
      projectCreated,
      uploadedAt: new Date().toISOString(),
    };
  } catch (error) {
    const err = error as Error;
    return {
      success: false,
      projectUuid: "",
      projectName: resolvedProjectName,
      projectVersion,
      componentsCount: 0,
      token: "",
      projectCreated: false,
      uploadedAt: new Date().toISOString(),
      error: err.message,
    };
  }
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Derive a project name from target
 */
function deriveProjectName(target: string, targetType: string): string {
  if (targetType === "image") {
    // Extract image name without registry and tag
    // e.g., "docker.io/library/nginx:latest" -> "nginx"
    // e.g., "nginx:1.25" -> "nginx"
    const parts = target.split("/");
    const imageName = parts[parts.length - 1];
    return imageName.split(":")[0];
  } else {
    // Extract directory name from path
    const normalized = target.replace(/\\/g, "/").replace(/\/+$/, "");
    const parts = normalized.split("/");
    return parts[parts.length - 1] || "unknown";
  }
}

/**
 * Batch upload SBOMs for multiple targets
 *
 * @param targets - Array of upload options
 * @param concurrency - Maximum concurrent uploads (default: 3)
 * @returns Promise resolving to array of upload results
 */
export async function uploadSbomsBatch(
  targets: SbomUploadOptions[],
  concurrency: number = 3
): Promise<SbomUploadResult[]> {
  const results: SbomUploadResult[] = [];
  const queue = [...targets];

  // Process in batches
  while (queue.length > 0) {
    const batch = queue.splice(0, concurrency);
    const batchResults = await Promise.all(batch.map(uploadSbomToDtrack));
    results.push(...batchResults);
  }

  return results;
}
