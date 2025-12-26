/**
 * Parallel Scanner Module
 *
 * Enables scanning multiple targets (images/paths) in parallel with
 * configurable concurrency, fail-fast support, and progress reporting.
 */

import type {
  ScanTarget,
  ScanTargetType,
  ParallelScanOptions,
  ParallelScanResult,
  TargetScanResult,
  ScanProgress,
  VulnerabilityCounts,
  TrivyScanResult,
} from "./types.js";
import { trivyScanImage, trivyScanPath } from "./handlers.js";

// Default configuration
const DEFAULT_CONCURRENCY = 3;
const DEFAULT_SEVERITY = "HIGH,CRITICAL";

// =============================================================================
// Target Parsing
// =============================================================================

/**
 * Parse a comma-separated list of targets into ScanTarget array
 */
export function parseTargets(input: string, type: ScanTargetType = "image"): ScanTarget[] {
  return input
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean)
    .map((target) => ({
      target,
      type,
      label: target,
    }));
}

/**
 * Parse multiple image names into ScanTarget array
 */
export function parseImages(images: string | string[]): ScanTarget[] {
  if (Array.isArray(images)) {
    return images.map((img) => ({
      target: img,
      type: "image" as const,
      label: img,
    }));
  }
  return parseTargets(images, "image");
}

/**
 * Parse multiple paths into ScanTarget array
 */
export function parsePaths(paths: string | string[]): ScanTarget[] {
  if (Array.isArray(paths)) {
    return paths.map((p) => ({
      target: p,
      type: "path" as const,
      label: p,
    }));
  }
  return parseTargets(paths, "path");
}

// =============================================================================
// Worker Pool
// =============================================================================

/**
 * Simple async worker pool with concurrency limiting
 */
class WorkerPool<T, R> {
  private concurrency: number;
  private running: number = 0;
  private queue: Array<{
    item: T;
    resolve: (result: R) => void;
    reject: (error: Error) => void;
  }> = [];
  private aborted: boolean = false;

  constructor(
    private worker: (item: T) => Promise<R>,
    concurrency: number
  ) {
    this.concurrency = Math.max(1, concurrency);
  }

  /**
   * Add an item to the pool for processing
   */
  async add(item: T): Promise<R> {
    return new Promise((resolve, reject) => {
      if (this.aborted) {
        reject(new Error("Pool has been aborted"));
        return;
      }

      this.queue.push({ item, resolve, reject });
      this.processQueue();
    });
  }

  /**
   * Abort all pending work
   */
  abort(): void {
    this.aborted = true;
    // Reject all queued items
    while (this.queue.length > 0) {
      const queued = this.queue.shift();
      queued?.reject(new Error("Scan aborted due to fail-fast"));
    }
  }

  /**
   * Check if pool is aborted
   */
  isAborted(): boolean {
    return this.aborted;
  }

  /**
   * Get number of currently running workers
   */
  getRunning(): number {
    return this.running;
  }

  private async processQueue(): Promise<void> {
    if (this.running >= this.concurrency || this.queue.length === 0 || this.aborted) {
      return;
    }

    const queued = this.queue.shift();
    if (!queued) return;

    this.running++;

    try {
      const result = await this.worker(queued.item);
      queued.resolve(result);
    } catch (error) {
      queued.reject(error instanceof Error ? error : new Error(String(error)));
    } finally {
      this.running--;
      this.processQueue();
    }
  }
}

// =============================================================================
// Result Aggregation
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
 * Extract vulnerability counts from a Trivy scan result
 */
function extractVulnerabilityCounts(result: TrivyScanResult): VulnerabilityCounts {
  const counts = createEmptyCounts();

  if (!result.Results) {
    return counts;
  }

  for (const scanResult of result.Results) {
    if (!scanResult.Vulnerabilities) continue;

    for (const vuln of scanResult.Vulnerabilities) {
      const severity = vuln.Severity?.toUpperCase() || "UNKNOWN";
      switch (severity) {
        case "CRITICAL":
          counts.critical++;
          break;
        case "HIGH":
          counts.high++;
          break;
        case "MEDIUM":
          counts.medium++;
          break;
        case "LOW":
          counts.low++;
          break;
        default:
          counts.unknown++;
      }
      counts.total++;
    }
  }

  return counts;
}

/**
 * Aggregate vulnerability counts from multiple results
 */
function aggregateCounts(results: TargetScanResult[]): VulnerabilityCounts {
  const total = createEmptyCounts();

  for (const result of results) {
    if (!result.success || !result.result) continue;

    const counts = extractVulnerabilityCounts(result.result);
    total.critical += counts.critical;
    total.high += counts.high;
    total.medium += counts.medium;
    total.low += counts.low;
    total.unknown += counts.unknown;
    total.total += counts.total;
  }

  return total;
}

// =============================================================================
// Scanning Functions
// =============================================================================

/**
 * Scan a single target and return the result
 */
async function scanTarget(target: ScanTarget, severity: string): Promise<TargetScanResult> {
  const startedAt = new Date().toISOString();
  const startTime = Date.now();

  try {
    let result: TrivyScanResult;

    if (target.type === "image") {
      const scanResult = await trivyScanImage(target.target, severity);
      // Check if it's an error response
      if ("error" in scanResult && typeof scanResult.error === "string") {
        throw new Error(scanResult.error);
      }
      result = scanResult as TrivyScanResult;
    } else {
      const scanResult = await trivyScanPath(target.target, severity);
      if ("error" in scanResult && typeof scanResult.error === "string") {
        throw new Error(scanResult.error);
      }
      result = scanResult as TrivyScanResult;
    }

    const completedAt = new Date().toISOString();
    return {
      target,
      success: true,
      result,
      durationMs: Date.now() - startTime,
      startedAt,
      completedAt,
    };
  } catch (error) {
    const completedAt = new Date().toISOString();
    return {
      target,
      success: false,
      error: error instanceof Error ? error.message : String(error),
      durationMs: Date.now() - startTime,
      startedAt,
      completedAt,
    };
  }
}

/**
 * Create progress object
 */
function createProgress(
  total: number,
  completed: number,
  failed: number,
  running: number,
  currentTargets: string[]
): ScanProgress {
  return {
    total,
    completed,
    failed,
    running,
    currentTargets,
    percentage: total > 0 ? Math.round((completed / total) * 100) : 0,
  };
}

// =============================================================================
// Main API
// =============================================================================

/**
 * Scan multiple targets in parallel
 *
 * @example
 * ```typescript
 * const result = await scanParallel({
 *   targets: [
 *     { target: 'node:20', type: 'image' },
 *     { target: 'python:3.12', type: 'image' },
 *   ],
 *   concurrency: 3,
 *   failFast: false,
 *   onProgress: (p) => console.log(`${p.percentage}% complete`),
 * });
 * ```
 */
export async function scanParallel(options: ParallelScanOptions): Promise<ParallelScanResult> {
  const {
    targets,
    concurrency = DEFAULT_CONCURRENCY,
    failFast = false,
    severity = DEFAULT_SEVERITY,
    onProgress,
    onTargetComplete,
  } = options;

  const startedAt = new Date().toISOString();
  const startTime = Date.now();

  const results: TargetScanResult[] = [];
  const failedTargets: string[] = [];
  let aborted = false;
  let completed = 0;
  let failed = 0;
  const currentlyScanning: Set<string> = new Set();

  // Create worker pool
  const pool = new WorkerPool<ScanTarget, TargetScanResult>(
    (target) => scanTarget(target, severity),
    concurrency
  );

  // Report initial progress
  if (onProgress) {
    onProgress(createProgress(targets.length, 0, 0, 0, []));
  }

  // Process all targets
  const promises = targets.map(async (target) => {
    if (pool.isAborted()) {
      return null;
    }

    currentlyScanning.add(target.target);

    // Report progress with current targets
    if (onProgress) {
      onProgress(
        createProgress(
          targets.length,
          completed,
          failed,
          currentlyScanning.size,
          Array.from(currentlyScanning)
        )
      );
    }

    try {
      const result = await pool.add(target);
      results.push(result);

      currentlyScanning.delete(target.target);
      completed++;

      if (!result.success) {
        failed++;
        failedTargets.push(target.target);

        // Fail-fast: abort remaining scans on first failure
        if (failFast && !aborted) {
          aborted = true;
          pool.abort();
        }
      }

      // Report progress
      if (onProgress) {
        onProgress(
          createProgress(
            targets.length,
            completed,
            failed,
            currentlyScanning.size,
            Array.from(currentlyScanning)
          )
        );
      }

      // Notify per-target completion
      if (onTargetComplete) {
        onTargetComplete(result);
      }

      return result;
    } catch (error) {
      currentlyScanning.delete(target.target);
      completed++;
      failed++;
      failedTargets.push(target.target);

      const errorResult: TargetScanResult = {
        target,
        success: false,
        error: error instanceof Error ? error.message : String(error),
        durationMs: 0,
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
      };

      results.push(errorResult);

      if (onTargetComplete) {
        onTargetComplete(errorResult);
      }

      return errorResult;
    }
  });

  // Wait for all to complete
  await Promise.all(promises);

  const completedAt = new Date().toISOString();

  // Aggregate results
  const aggregatedVulns = aggregateCounts(results);

  return {
    startedAt,
    completedAt,
    durationMs: Date.now() - startTime,
    summary: {
      totalTargets: targets.length,
      successfulScans: results.filter((r) => r.success).length,
      failedScans: failed,
      aborted,
      vulnerabilities: aggregatedVulns,
    },
    results,
    failedTargets,
  };
}

/**
 * Convenience function to scan multiple images in parallel
 *
 * @example
 * ```typescript
 * const result = await scanImagesParallel(
 *   ['node:20', 'python:3.12', 'nginx:latest'],
 *   { concurrency: 2 }
 * );
 * ```
 */
export async function scanImagesParallel(
  images: string | string[],
  options?: Omit<ParallelScanOptions, "targets">
): Promise<ParallelScanResult> {
  const targets = parseImages(images);
  return scanParallel({ ...options, targets });
}

/**
 * Convenience function to scan multiple paths in parallel
 *
 * @example
 * ```typescript
 * const result = await scanPathsParallel(
 *   ['/app/service1', '/app/service2'],
 *   { concurrency: 2, failFast: true }
 * );
 * ```
 */
export async function scanPathsParallel(
  paths: string | string[],
  options?: Omit<ParallelScanOptions, "targets">
): Promise<ParallelScanResult> {
  const targets = parsePaths(paths);
  return scanParallel({ ...options, targets });
}

/**
 * Scan mixed targets (both images and paths) in parallel
 *
 * @example
 * ```typescript
 * const result = await scanMixedParallel({
 *   images: ['node:20', 'python:3.12'],
 *   paths: ['/app/backend', '/app/frontend'],
 *   concurrency: 4,
 * });
 * ```
 */
export async function scanMixedParallel(
  options: {
    images?: string | string[];
    paths?: string | string[];
  } & Omit<ParallelScanOptions, "targets">
): Promise<ParallelScanResult> {
  const { images, paths, ...scanOptions } = options;

  const targets: ScanTarget[] = [];

  if (images) {
    targets.push(...parseImages(images));
  }

  if (paths) {
    targets.push(...parsePaths(paths));
  }

  return scanParallel({ ...scanOptions, targets });
}
