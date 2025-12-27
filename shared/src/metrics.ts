/**
 * Prometheus Metrics Module
 *
 * Collects and exposes metrics in Prometheus format for monitoring
 * scan performance, system health, and resource usage.
 */

import type {
  MetricType,
  MetricLabels,
  MetricDefinition,
  CounterValue,
  GaugeValue,
  HistogramValue,
  HistogramBucket,
  CollectedMetric,
  MetricsSnapshot,
  ScanMetrics,
  PushgatewayConfig,
  PushgatewayResult,
} from "./types.js";
import { getAllCircuitStats } from "./circuit-breaker.js";

// =============================================================================
// Metric Definitions
// =============================================================================

const METRIC_PREFIX = "cicd_security_";

// Default histogram buckets for scan duration (in seconds)
const DURATION_BUCKETS = [0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300];

// Metric definitions
export const METRICS = {
  scanDuration: {
    name: `${METRIC_PREFIX}scan_duration_seconds`,
    help: "Duration of security scans in seconds",
    type: "histogram" as MetricType,
    labelNames: ["target_type", "status"],
  },
  scanTotal: {
    name: `${METRIC_PREFIX}scan_total`,
    help: "Total number of security scans",
    type: "counter" as MetricType,
    labelNames: ["target_type", "status"],
  },
  vulnerabilitiesTotal: {
    name: `${METRIC_PREFIX}vulnerabilities_total`,
    help: "Total vulnerabilities found by severity",
    type: "counter" as MetricType,
    labelNames: ["severity"],
  },
  scanErrorsTotal: {
    name: `${METRIC_PREFIX}scan_errors_total`,
    help: "Total number of scan errors",
    type: "counter" as MetricType,
    labelNames: ["target_type", "error_type"],
  },
  circuitBreakerState: {
    name: `${METRIC_PREFIX}circuit_breaker_state`,
    help: "Circuit breaker state (0=closed, 1=half-open, 2=open)",
    type: "gauge" as MetricType,
    labelNames: ["service"],
  },
  circuitBreakerFailures: {
    name: `${METRIC_PREFIX}circuit_breaker_failures_total`,
    help: "Total circuit breaker failures",
    type: "counter" as MetricType,
    labelNames: ["service"],
  },
  rateLimiterQueueSize: {
    name: `${METRIC_PREFIX}rate_limiter_queue_size`,
    help: "Current rate limiter queue size",
    type: "gauge" as MetricType,
    labelNames: ["service"],
  },
  cacheSize: {
    name: `${METRIC_PREFIX}cache_size`,
    help: "Number of entries in cache",
    type: "gauge" as MetricType,
    labelNames: ["cache"],
  },
  cacheHits: {
    name: `${METRIC_PREFIX}cache_hits_total`,
    help: "Total cache hits",
    type: "counter" as MetricType,
    labelNames: ["cache"],
  },
  cacheMisses: {
    name: `${METRIC_PREFIX}cache_misses_total`,
    help: "Total cache misses",
    type: "counter" as MetricType,
    labelNames: ["cache"],
  },
} as const;

// =============================================================================
// Metrics Collector
// =============================================================================

/**
 * Metrics collector for tracking scan and system metrics
 */
class MetricsCollector {
  // Counters
  private readonly scanCounts: Map<string, number> = new Map();
  private readonly vulnerabilityCounts: Map<string, number> = new Map();
  private readonly errorCounts: Map<string, number> = new Map();
  private readonly cacheHitCounts: Map<string, number> = new Map();
  private readonly cacheMissCounts: Map<string, number> = new Map();
  private readonly circuitBreakerFailureCounts: Map<string, number> = new Map();

  // Histograms (store individual observations)
  private durationObservations: Array<{
    targetType: string;
    status: string;
    value: number;
  }> = [];

  /**
   * Record a scan completion
   */
  recordScan(metrics: ScanMetrics): void {
    const targetType = metrics.type;
    const status = metrics.success ? "success" : "error";

    // Increment scan counter
    const scanKey = `${targetType}:${status}`;
    this.scanCounts.set(scanKey, (this.scanCounts.get(scanKey) || 0) + 1);

    // Record duration
    this.durationObservations.push({
      targetType,
      status,
      value: metrics.durationSeconds,
    });

    // Record vulnerabilities if successful
    if (metrics.success && metrics.vulnerabilities) {
      const vulns = metrics.vulnerabilities;
      this.addToCounter(this.vulnerabilityCounts, "critical", vulns.critical);
      this.addToCounter(this.vulnerabilityCounts, "high", vulns.high);
      this.addToCounter(this.vulnerabilityCounts, "medium", vulns.medium);
      this.addToCounter(this.vulnerabilityCounts, "low", vulns.low);
    }

    // Record error if failed
    if (!metrics.success) {
      const errorType = this.categorizeError(metrics.error);
      const errorKey = `${targetType}:${errorType}`;
      this.errorCounts.set(errorKey, (this.errorCounts.get(errorKey) || 0) + 1);
    }
  }

  /**
   * Record a cache hit
   */
  recordCacheHit(cacheName: string): void {
    this.cacheHitCounts.set(cacheName, (this.cacheHitCounts.get(cacheName) || 0) + 1);
  }

  /**
   * Record a cache miss
   */
  recordCacheMiss(cacheName: string): void {
    this.cacheMissCounts.set(cacheName, (this.cacheMissCounts.get(cacheName) || 0) + 1);
  }

  /**
   * Record a circuit breaker failure
   */
  recordCircuitBreakerFailure(service: string): void {
    this.circuitBreakerFailureCounts.set(
      service,
      (this.circuitBreakerFailureCounts.get(service) || 0) + 1
    );
  }

  /**
   * Collect all metrics
   */
  collect(options?: {
    cacheSizes?: Record<string, number>;
    rateLimiterQueues?: Record<string, number>;
  }): MetricsSnapshot {
    // Collect all core metrics
    const metrics: CollectedMetric[] = [
      // Scan total counter
      this.collectCounter(METRICS.scanTotal, this.scanCounts, (key) => {
        const [targetType, status] = key.split(":");
        return { target_type: targetType, status };
      }),
      // Scan duration histogram
      this.collectHistogram(),
      // Vulnerabilities counter
      this.collectCounter(METRICS.vulnerabilitiesTotal, this.vulnerabilityCounts, (key) => ({
        severity: key,
      })),
      // Scan errors counter
      this.collectCounter(METRICS.scanErrorsTotal, this.errorCounts, (key) => {
        const [targetType, errorType] = key.split(":");
        return { target_type: targetType, error_type: errorType };
      }),
      // Circuit breaker state gauge
      this.collectCircuitBreakerState(),
      // Circuit breaker failures counter
      this.collectCounter(
        METRICS.circuitBreakerFailures,
        this.circuitBreakerFailureCounts,
        (key) => ({ service: key })
      ),
      // Cache hits counter
      this.collectCounter(METRICS.cacheHits, this.cacheHitCounts, (key) => ({
        cache: key,
      })),
      // Cache misses counter
      this.collectCounter(METRICS.cacheMisses, this.cacheMissCounts, (key) => ({
        cache: key,
      })),
    ];

    // Cache size gauge (if provided)
    if (options?.cacheSizes) {
      metrics.push(
        this.collectGauge(METRICS.cacheSize, options.cacheSizes, (key) => ({
          cache: key,
        }))
      );
    }

    // Rate limiter queue size gauge (if provided)
    if (options?.rateLimiterQueues) {
      metrics.push(
        this.collectGauge(METRICS.rateLimiterQueueSize, options.rateLimiterQueues, (key) => ({
          service: key,
        }))
      );
    }

    return {
      timestamp: new Date().toISOString(),
      metrics,
    };
  }

  /**
   * Reset all metrics (useful for testing)
   */
  reset(): void {
    this.scanCounts.clear();
    this.vulnerabilityCounts.clear();
    this.errorCounts.clear();
    this.cacheHitCounts.clear();
    this.cacheMissCounts.clear();
    this.circuitBreakerFailureCounts.clear();
    this.durationObservations = [];
  }

  private addToCounter(map: Map<string, number>, key: string, value: number): void {
    map.set(key, (map.get(key) || 0) + value);
  }

  private categorizeError(error?: string): string {
    if (!error) return "unknown";
    const lowerError = error.toLowerCase();
    if (lowerError.includes("timeout")) return "timeout";
    if (lowerError.includes("not found") || lowerError.includes("404")) return "not_found";
    if (lowerError.includes("connection") || lowerError.includes("network")) return "connection";
    if (
      lowerError.includes("permission") ||
      lowerError.includes("401") ||
      lowerError.includes("403")
    ) {
      return "auth";
    }
    return "unknown";
  }

  private collectCounter(
    definition: MetricDefinition,
    data: Map<string, number>,
    labelParser: (key: string) => MetricLabels
  ): CollectedMetric {
    const values: CounterValue[] = [];
    for (const [key, value] of data.entries()) {
      values.push({ value, labels: labelParser(key) });
    }
    return { definition, values };
  }

  private collectGauge(
    definition: MetricDefinition,
    data: Record<string, number>,
    labelParser: (key: string) => MetricLabels
  ): CollectedMetric {
    const values: GaugeValue[] = [];
    for (const [key, value] of Object.entries(data)) {
      values.push({ value, labels: labelParser(key) });
    }
    return { definition, values };
  }

  private collectHistogram(): CollectedMetric {
    // Group observations by labels
    const grouped = new Map<string, number[]>();

    for (const obs of this.durationObservations) {
      const key = `${obs.targetType}:${obs.status}`;
      const values = grouped.get(key) || [];
      values.push(obs.value);
      grouped.set(key, values);
    }

    const values: HistogramValue[] = [];

    for (const [key, observations] of grouped.entries()) {
      const [targetType, status] = key.split(":");
      const buckets = this.computeBuckets(observations);
      const sum = observations.reduce((a, b) => a + b, 0);

      values.push({
        buckets,
        sum,
        count: observations.length,
        labels: { target_type: targetType, status },
      });
    }

    return { definition: METRICS.scanDuration, values };
  }

  private computeBuckets(observations: number[]): HistogramBucket[] {
    const buckets: HistogramBucket[] = [];

    for (const le of DURATION_BUCKETS) {
      const count = observations.filter((v) => v <= le).length;
      buckets.push({ le, count });
    }

    // +Inf bucket
    buckets.push({ le: "+Inf", count: observations.length });

    return buckets;
  }

  private collectCircuitBreakerState(): CollectedMetric {
    const stats = getAllCircuitStats();
    const values: GaugeValue[] = stats.map((stat) => ({
      value: this.circuitStateToNumber(stat.state),
      labels: { service: stat.serviceName },
    }));

    return { definition: METRICS.circuitBreakerState, values };
  }

  private circuitStateToNumber(state: string): number {
    switch (state) {
      case "closed":
        return 0;
      case "half-open":
        return 1;
      case "open":
        return 2;
      default:
        return -1;
    }
  }
}

// Singleton instance
export const metricsCollector = new MetricsCollector();

// =============================================================================
// Prometheus Format Export
// =============================================================================

/**
 * Format a metric value with labels
 */
function formatLabels(labels?: MetricLabels): string {
  if (!labels || Object.keys(labels).length === 0) {
    return "";
  }

  const pairs = Object.entries(labels)
    .map(([k, v]) => `${k}="${escapeLabel(v)}"`)
    .join(",");

  return `{${pairs}}`;
}

/**
 * Escape label value for Prometheus format
 */
function escapeLabel(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("\n", "\\n");
}

/**
 * Format a single metric in Prometheus exposition format
 */
function formatMetric(metric: CollectedMetric): string {
  const lines: string[] = [];
  const { definition, values } = metric;

  // HELP and TYPE lines
  lines.push(
    `# HELP ${definition.name} ${definition.help}`,
    `# TYPE ${definition.name} ${definition.type}`
  );

  // Value lines
  for (const value of values) {
    if (definition.type === "histogram") {
      const histValue = value as HistogramValue;
      const baseLabels = formatLabels(histValue.labels);
      const baseName = definition.name;

      // Bucket lines
      for (const bucket of histValue.buckets) {
        const leLabel = bucket.le === "+Inf" ? "+Inf" : bucket.le.toString();
        const bucketLabels = histValue.labels
          ? { ...histValue.labels, le: leLabel }
          : { le: leLabel };
        lines.push(`${baseName}_bucket${formatLabels(bucketLabels)} ${bucket.count}`);
      }

      // Sum and count
      const sumLabels = baseLabels || "";
      lines.push(
        `${baseName}_sum${sumLabels} ${histValue.sum}`,
        `${baseName}_count${sumLabels} ${histValue.count}`
      );
    } else {
      const simpleValue = value as CounterValue | GaugeValue;
      const labels = formatLabels(simpleValue.labels);
      lines.push(`${definition.name}${labels} ${simpleValue.value}`);
    }
  }

  return lines.join("\n");
}

/**
 * Export metrics in Prometheus exposition format
 */
export function toPrometheusFormat(snapshot: MetricsSnapshot): string {
  const sections: string[] = [];

  for (const metric of snapshot.metrics) {
    if (metric.values.length > 0) {
      sections.push(formatMetric(metric));
    }
  }

  return sections.join("\n\n") + "\n";
}

/**
 * Get metrics in Prometheus format
 */
export function getMetrics(options?: {
  cacheSizes?: Record<string, number>;
  rateLimiterQueues?: Record<string, number>;
}): string {
  const snapshot = metricsCollector.collect(options);
  return toPrometheusFormat(snapshot);
}

// =============================================================================
// Pushgateway Support
// =============================================================================

/**
 * Push metrics to a Prometheus Pushgateway
 */
export async function pushToGateway(
  config: PushgatewayConfig,
  options?: {
    cacheSizes?: Record<string, number>;
    rateLimiterQueues?: Record<string, number>;
  }
): Promise<PushgatewayResult> {
  const metricsData = getMetrics(options);

  // Build URL with job and instance
  let url = `${config.url}/metrics/job/${encodeURIComponent(config.job)}`;
  if (config.instance) {
    url += `/instance/${encodeURIComponent(config.instance)}`;
  }

  // Add additional labels to URL
  if (config.labels) {
    for (const [key, value] of Object.entries(config.labels)) {
      url += `/${encodeURIComponent(key)}/${encodeURIComponent(value)}`;
    }
  }

  try {
    const headers: Record<string, string> = {
      "Content-Type": "text/plain; charset=utf-8",
    };

    // Add basic auth if configured
    if (config.username && config.password) {
      const auth = Buffer.from(`${config.username}:${config.password}`).toString("base64");
      headers["Authorization"] = `Basic ${auth}`;
    }

    const response = await fetch(url, {
      method: "POST",
      headers,
      body: metricsData,
    });

    if (response.ok) {
      return { success: true, statusCode: response.status };
    }

    const errorText = await response.text();
    return {
      success: false,
      statusCode: response.status,
      error: errorText || `HTTP ${response.status}`,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Delete metrics from Pushgateway
 */
export async function deleteFromGateway(config: PushgatewayConfig): Promise<PushgatewayResult> {
  let url = `${config.url}/metrics/job/${encodeURIComponent(config.job)}`;
  if (config.instance) {
    url += `/instance/${encodeURIComponent(config.instance)}`;
  }

  try {
    const headers: Record<string, string> = {};

    if (config.username && config.password) {
      const auth = Buffer.from(`${config.username}:${config.password}`).toString("base64");
      headers["Authorization"] = `Basic ${auth}`;
    }

    const response = await fetch(url, {
      method: "DELETE",
      headers,
    });

    if (response.ok) {
      return { success: true, statusCode: response.status };
    }

    const errorText = await response.text();
    return {
      success: false,
      statusCode: response.status,
      error: errorText || `HTTP ${response.status}`,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

// =============================================================================
// Convenience Functions
// =============================================================================

/**
 * Record scan metrics from a scan result
 */
export function recordScanMetrics(metrics: ScanMetrics): void {
  metricsCollector.recordScan(metrics);
}

/**
 * Record cache hit
 */
export function recordCacheHit(cacheName: string): void {
  metricsCollector.recordCacheHit(cacheName);
}

/**
 * Record cache miss
 */
export function recordCacheMiss(cacheName: string): void {
  metricsCollector.recordCacheMiss(cacheName);
}

/**
 * Record circuit breaker failure
 */
export function recordCircuitBreakerFailure(service: string): void {
  metricsCollector.recordCircuitBreakerFailure(service);
}

/**
 * Reset all metrics (for testing)
 */
export function resetMetrics(): void {
  metricsCollector.reset();
}

/**
 * Get raw metrics snapshot
 */
export function getMetricsSnapshot(options?: {
  cacheSizes?: Record<string, number>;
  rateLimiterQueues?: Record<string, number>;
}): MetricsSnapshot {
  return metricsCollector.collect(options);
}
