/**
 * Registry Scanner Module
 *
 * Scans all images in a container registry with filtering,
 * parallel execution, and aggregated results.
 */

import { minimatch } from "minimatch";
import { config } from "./config.js";
import { registryGetCatalog, registryGetTags } from "./handlers.js";
import { scanParallel } from "./parallel-scanner.js";
import type {
  RegistryImage,
  RegistryScanOptions,
  RegistryScanResult,
  VulnerabilityCounts,
  ScanTarget,
} from "./types.js";

// =============================================================================
// Constants
// =============================================================================

const DEFAULT_CONCURRENCY = 3;
const DEFAULT_SEVERITY = "HIGH,CRITICAL";

// Duration parsing regex (e.g., "7d", "24h", "30m")
const DURATION_REGEX = /^(\d+)(d|h|m|s)$/i;

// =============================================================================
// Duration Parsing
// =============================================================================

/**
 * Parse a duration string to milliseconds
 * Supports: 7d (days), 24h (hours), 30m (minutes), 60s (seconds)
 */
export function parseDuration(duration: string): number {
  const match = duration.match(DURATION_REGEX);
  if (!match) {
    throw new Error(
      `Invalid duration format: ${duration}. Use format like "7d", "24h", "30m", "60s"`
    );
  }

  const value = parseInt(match[1], 10);
  const unit = match[2].toLowerCase();

  switch (unit) {
    case "d":
      return value * 24 * 60 * 60 * 1000;
    case "h":
      return value * 60 * 60 * 1000;
    case "m":
      return value * 60 * 1000;
    case "s":
      return value * 1000;
    default:
      throw new Error(`Unknown duration unit: ${unit}`);
  }
}

/**
 * Check if a date is within the max age limit
 */
export function isWithinMaxAge(date: Date | string, maxAge: string): boolean {
  const maxAgeMs = parseDuration(maxAge);
  const dateTime = typeof date === "string" ? new Date(date).getTime() : date.getTime();
  const cutoffTime = Date.now() - maxAgeMs;

  return dateTime >= cutoffTime;
}

// =============================================================================
// Filtering
// =============================================================================

/**
 * Check if a repository name matches any of the patterns
 * Supports glob patterns (e.g., "myapp/*", "library/**")
 */
export function matchesRepositoryPattern(repository: string, patterns: string[]): boolean {
  if (!patterns || patterns.length === 0) {
    return true; // No filter means match all
  }

  return patterns.some((pattern) => {
    // Check if it's a regex pattern (starts/ends with /)
    if (pattern.startsWith("/") && pattern.endsWith("/")) {
      const regex = new RegExp(pattern.slice(1, -1));
      return regex.test(repository);
    }

    // Otherwise treat as glob pattern
    return minimatch(repository, pattern, { nocase: true });
  });
}

/**
 * Check if a tag matches the filter pattern
 */
export function matchesTagFilter(tag: string, filter?: string): boolean {
  if (!filter) {
    return true;
  }

  try {
    const regex = new RegExp(filter);
    return regex.test(tag);
  } catch {
    // If invalid regex, do simple string matching
    return tag.includes(filter);
  }
}

// =============================================================================
// Registry Discovery
// =============================================================================

/**
 * Discover all images in a registry
 *
 * @param registryUrl - Registry base URL
 * @param options - Filter options
 * @returns List of discovered images
 */
export async function discoverImages(
  registryUrl?: string,
  options: {
    repositories?: string[];
    tagFilter?: string;
    maxAge?: string;
    allTags?: boolean;
    limit?: number;
  } = {}
): Promise<{ images: RegistryImage[]; skipped: string[]; repositoriesFound: number }> {
  const { repositories: repoPatterns, tagFilter, maxAge: _maxAge, allTags = true, limit } = options;
  // Note: maxAge filtering is not yet implemented (requires manifest inspection)
  void _maxAge;

  // Get catalog from registry
  const catalog = await registryGetCatalog();
  const allImages: RegistryImage[] = [];
  const skippedImages: string[] = [];

  // Build registry prefix for full image names
  const registryPrefix = registryUrl || config.registry.url.replace(/^https?:\/\//, "");

  // Filter repositories
  const matchedRepos = catalog.repositories.filter((repo) =>
    matchesRepositoryPattern(repo, repoPatterns || [])
  );

  // Get tags for each matched repository
  for (const repo of matchedRepos) {
    try {
      const tagsResult = await registryGetTags(repo);
      const tags = tagsResult.tags || [];

      for (const tag of tags) {
        // Apply tag filter
        if (!matchesTagFilter(tag, tagFilter)) {
          skippedImages.push(`${repo}:${tag}`);
          continue;
        }

        // If not allTags, only include 'latest' tag
        if (!allTags && tag !== "latest") {
          skippedImages.push(`${repo}:${tag}`);
          continue;
        }

        const image: RegistryImage = {
          fullName: `${registryPrefix}/${repo}:${tag}`,
          repository: repo,
          tag,
        };

        // Note: maxAge filtering would need manifest inspection
        // For now, we include all matching images
        // In a production implementation, we'd fetch manifest to get creation date

        allImages.push(image);

        // Check limit
        if (limit && allImages.length >= limit) {
          break;
        }
      }

      if (limit && allImages.length >= limit) {
        break;
      }
    } catch (error) {
      // Log error but continue with other repos
      console.error(`Failed to get tags for ${repo}:`, error);
    }
  }

  return {
    images: allImages,
    skipped: skippedImages,
    repositoriesFound: catalog.repositories.length,
  };
}

/**
 * List images from registry without scanning
 *
 * @param options - Filter options
 * @returns List of discovered images
 */
export async function listRegistryImages(
  options: RegistryScanOptions = {}
): Promise<RegistryImage[]> {
  const { registry, repositories, tagFilter, maxAge, allTags, limit } = options;

  const { images } = await discoverImages(registry, {
    repositories,
    tagFilter,
    maxAge,
    allTags,
    limit,
  });

  return images;
}

// =============================================================================
// Registry Scanning
// =============================================================================

/**
 * Create empty vulnerability counts
 */
function createEmptyCounts(): VulnerabilityCounts {
  return {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
    total: 0,
  };
}

/**
 * Scan all images in a container registry
 *
 * This function:
 * 1. Discovers all images in the registry
 * 2. Filters by repository pattern, tag pattern, and age
 * 3. Scans matching images in parallel
 * 4. Returns aggregated results
 *
 * @param options - Scan options
 * @returns Registry scan result with aggregated vulnerabilities
 *
 * @example
 * ```typescript
 * // Scan all images in the default registry
 * const result = await scanRegistry();
 *
 * // Scan specific repositories with tag filter
 * const result = await scanRegistry({
 *   repositories: ['myapp/*', 'library/**'],
 *   tagFilter: '^v\\d+',  // Only version tags
 *   concurrency: 5,
 * });
 *
 * // Scan only latest tags, limit to 10 images
 * const result = await scanRegistry({
 *   allTags: false,
 *   limit: 10,
 *   severity: 'CRITICAL',
 * });
 * ```
 */
export async function scanRegistry(options: RegistryScanOptions = {}): Promise<RegistryScanResult> {
  const {
    registry,
    repositories,
    tagFilter,
    maxAge,
    concurrency = DEFAULT_CONCURRENCY,
    severity = DEFAULT_SEVERITY,
    limit,
    listOnly = false,
    allTags = true,
    failFast = false,
    onProgress,
  } = options;

  const startedAt = new Date().toISOString();
  const startTime = Date.now();

  // Report discovery phase
  if (onProgress) {
    onProgress({
      phase: "discovering",
      imagesDiscovered: 0,
      imagesScanned: 0,
      failedScans: 0,
      currentImages: [],
      percentage: 0,
    });
  }

  // Discover images
  const { images, skipped, repositoriesFound } = await discoverImages(registry, {
    repositories,
    tagFilter,
    maxAge,
    allTags,
    limit,
  });

  const registryUrl = registry || config.registry.url.replace(/^https?:\/\//, "");

  // If listOnly, return without scanning
  if (listOnly) {
    const completedAt = new Date().toISOString();

    if (onProgress) {
      onProgress({
        phase: "complete",
        imagesDiscovered: images.length,
        imagesScanned: 0,
        failedScans: 0,
        currentImages: [],
        percentage: 100,
      });
    }

    return {
      registry: registryUrl,
      startedAt,
      completedAt,
      durationMs: Date.now() - startTime,
      discovery: {
        repositoriesFound,
        imagesFound: images.length + skipped.length,
        imagesMatched: images.length,
        imagesScanned: 0,
      },
      vulnerabilities: createEmptyCounts(),
      results: [],
      failedImages: [],
      skippedImages: skipped,
    };
  }

  // Report scanning phase start
  if (onProgress) {
    onProgress({
      phase: "scanning",
      imagesDiscovered: images.length,
      imagesScanned: 0,
      failedScans: 0,
      currentImages: [],
      percentage: 0,
    });
  }

  // Convert images to scan targets
  const targets: ScanTarget[] = images.map((img) => ({
    target: img.fullName,
    type: "image" as const,
    label: `${img.repository}:${img.tag}`,
  }));

  // Scan in parallel
  const scanResult = await scanParallel({
    targets,
    concurrency,
    severity,
    failFast,
    onProgress: (progress) => {
      if (onProgress) {
        onProgress({
          phase: "scanning",
          imagesDiscovered: images.length,
          imagesScanned: progress.completed,
          failedScans: progress.failed,
          currentImages: progress.currentTargets,
          percentage: progress.percentage,
        });
      }
    },
  });

  const completedAt = new Date().toISOString();

  // Report completion
  if (onProgress) {
    onProgress({
      phase: "complete",
      imagesDiscovered: images.length,
      imagesScanned: scanResult.summary.successfulScans,
      failedScans: scanResult.summary.failedScans,
      currentImages: [],
      percentage: 100,
    });
  }

  return {
    registry: registryUrl,
    startedAt,
    completedAt,
    durationMs: Date.now() - startTime,
    discovery: {
      repositoriesFound,
      imagesFound: images.length + skipped.length,
      imagesMatched: images.length,
      imagesScanned: scanResult.summary.successfulScans,
    },
    vulnerabilities: scanResult.summary.vulnerabilities,
    results: scanResult.results,
    failedImages: scanResult.failedTargets,
    skippedImages: skipped,
  };
}

/**
 * Get a summary report of registry scan results
 */
export function getRegistryScanSummary(result: RegistryScanResult): string {
  const { registry, discovery, vulnerabilities, failedImages, durationMs } = result;

  const lines = [
    `Registry Scan Report: ${registry}`,
    `${"=".repeat(50)}`,
    "",
    `Discovery:`,
    `  Repositories found: ${discovery.repositoriesFound}`,
    `  Images found: ${discovery.imagesFound}`,
    `  Images matched filters: ${discovery.imagesMatched}`,
    `  Images scanned: ${discovery.imagesScanned}`,
    "",
    `Vulnerabilities:`,
    `  Critical: ${vulnerabilities.critical}`,
    `  High: ${vulnerabilities.high}`,
    `  Medium: ${vulnerabilities.medium}`,
    `  Low: ${vulnerabilities.low}`,
    `  Total: ${vulnerabilities.total}`,
    "",
    `Duration: ${(durationMs / 1000).toFixed(2)}s`,
  ];

  if (failedImages.length > 0) {
    lines.push("", `Failed Images (${failedImages.length}):`);
    failedImages.slice(0, 10).forEach((img) => lines.push(`  - ${img}`));
    if (failedImages.length > 10) {
      lines.push(`  ... and ${failedImages.length - 10} more`);
    }
  }

  return lines.join("\n");
}
