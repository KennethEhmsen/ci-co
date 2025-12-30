/**
 * Performance Optimization Module
 * Advanced caching and performance tuning capabilities
 * Part of v1.30.0 - Enterprise Scale & Multi-Cloud Security
 */

import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";

export interface PerformanceMetrics {
  timestamp: string;
  scanDuration: { avg: number; p50: number; p95: number; p99: number; min: number; max: number };
  apiLatency: { avg: number; p50: number; p95: number; p99: number };
  cacheHitRate: number;
  concurrentScans: number;
  memoryUsageMb: number;
  cpuUsagePercent: number;
  dbQueryTime: { avg: number; slowestQueries: Array<{ query: string; duration: number }> };
}

export interface SlowQuery {
  id: string;
  query: string;
  duration: number;
  timestamp: string;
  table: string;
  rowsExamined: number;
  indexUsed: boolean;
  suggestion?: string;
}

export interface IndexSuggestion {
  table: string;
  columns: string[];
  type: "btree" | "hash";
  reason: string;
  estimatedImprovement: string;
  createStatement: string;
}

export interface CacheStats {
  type: string;
  hits: number;
  misses: number;
  hitRate: number;
  size: number;
  maxSize: number;
  evictions: number;
  avgLoadTime: number;
}

let db: Database.Database | null = null;
const DEFAULT_DB_PATH = path.join(process.cwd(), ".cicd-security", "performance.db");

// In-memory cache for performance metrics
const metricsCache: Map<string, { data: any; expires: number }> = new Map();
const queryStats: Map<string, { count: number; totalDuration: number; maxDuration: number }> =
  new Map();

export function initPerformanceDb(dbPath: string = DEFAULT_DB_PATH): {
  path: string;
  tables: string[];
} {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("cache_size = -64000"); // 64MB cache

  db.prepare(
    `CREATE TABLE IF NOT EXISTS metrics_history (id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT, scan_duration_avg REAL, scan_duration_p95 REAL, api_latency_avg REAL,
    cache_hit_rate REAL, concurrent_scans INTEGER, memory_mb REAL, cpu_percent REAL)`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS slow_queries (id TEXT PRIMARY KEY, query TEXT,
    duration INTEGER, timestamp TEXT, table_name TEXT, rows_examined INTEGER, index_used INTEGER,
    suggestion TEXT)`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS cache_stats (id INTEGER PRIMARY KEY AUTOINCREMENT,
    cache_type TEXT, hits INTEGER, misses INTEGER, size INTEGER, max_size INTEGER,
    evictions INTEGER, avg_load_time REAL, recorded_at TEXT)`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS index_suggestions (id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT, columns TEXT, index_type TEXT, reason TEXT, improvement TEXT,
    create_statement TEXT, created_at TEXT, applied INTEGER DEFAULT 0)`
  ).run();

  db.prepare(
    `CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics_history(timestamp)`
  ).run();
  db.prepare(
    `CREATE INDEX IF NOT EXISTS idx_slow_queries_duration ON slow_queries(duration DESC)`
  ).run();

  return {
    path: dbPath,
    tables: ["metrics_history", "slow_queries", "cache_stats", "index_suggestions"],
  };
}

function getDb(): Database.Database {
  if (!db) initPerformanceDb();
  return db!;
}

export function recordMetrics(metrics: Partial<PerformanceMetrics>): { success: boolean } {
  const now = new Date().toISOString();
  getDb()
    .prepare(
      `INSERT INTO metrics_history (timestamp, scan_duration_avg, scan_duration_p95,
    api_latency_avg, cache_hit_rate, concurrent_scans, memory_mb, cpu_percent)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      now,
      metrics.scanDuration?.avg || 0,
      metrics.scanDuration?.p95 || 0,
      metrics.apiLatency?.avg || 0,
      metrics.cacheHitRate || 0,
      metrics.concurrentScans || 0,
      metrics.memoryUsageMb || 0,
      metrics.cpuUsagePercent || 0
    );
  return { success: true };
}

export function getMetrics(options?: { hours?: number; limit?: number }): PerformanceMetrics[] {
  const hours = options?.hours || 24;
  const since = new Date(Date.now() - hours * 3600000).toISOString();

  let sql = "SELECT * FROM metrics_history WHERE timestamp > ? ORDER BY timestamp DESC";
  const params: (string | number)[] = [since];
  if (options?.limit) {
    sql += " LIMIT ?";
    params.push(options.limit);
  }

  return (
    getDb()
      .prepare(sql)
      .all(...params) as any[]
  ).map((r) => ({
    timestamp: r.timestamp,
    scanDuration: {
      avg: r.scan_duration_avg,
      p50: 0,
      p95: r.scan_duration_p95,
      p99: 0,
      min: 0,
      max: 0,
    },
    apiLatency: { avg: r.api_latency_avg, p50: 0, p95: 0, p99: 0 },
    cacheHitRate: r.cache_hit_rate,
    concurrentScans: r.concurrent_scans,
    memoryUsageMb: r.memory_mb,
    cpuUsagePercent: r.cpu_percent,
    dbQueryTime: { avg: 0, slowestQueries: [] },
  }));
}

export function getAggregatedMetrics(hours: number = 24): {
  scanDuration: { avg: number; p95: number; trend: "improving" | "stable" | "degrading" };
  apiLatency: { avg: number; trend: "improving" | "stable" | "degrading" };
  cacheHitRate: { current: number; trend: "improving" | "stable" | "degrading" };
  recommendations: string[];
} {
  const since = new Date(Date.now() - hours * 3600000).toISOString();
  const halfwaySince = new Date(Date.now() - (hours / 2) * 3600000).toISOString();

  const all = getDb()
    .prepare(
      "SELECT AVG(scan_duration_avg) as scan_avg, AVG(scan_duration_p95) as scan_p95, AVG(api_latency_avg) as api_avg, AVG(cache_hit_rate) as cache_rate FROM metrics_history WHERE timestamp > ?"
    )
    .get(since) as any;
  const recent = getDb()
    .prepare(
      "SELECT AVG(scan_duration_avg) as scan_avg, AVG(api_latency_avg) as api_avg, AVG(cache_hit_rate) as cache_rate FROM metrics_history WHERE timestamp > ?"
    )
    .get(halfwaySince) as any;

  const getTrend = (allVal: number, recentVal: number): "improving" | "stable" | "degrading" => {
    const diff = recentVal - allVal;
    const threshold = allVal * 0.1;
    if (diff < -threshold) return "improving";
    if (diff > threshold) return "degrading";
    return "stable";
  };

  const recommendations: string[] = [];
  if ((all?.cache_rate || 0) < 0.7)
    recommendations.push("Cache hit rate is below 70%. Consider increasing cache size or TTL.");
  if ((all?.scan_avg || 0) > 30000)
    recommendations.push(
      "Average scan duration exceeds 30s. Consider parallel scanning or incremental scans."
    );
  if ((all?.api_avg || 0) > 500)
    recommendations.push(
      "API latency exceeds 500ms. Check database indexes and query optimization."
    );

  return {
    scanDuration: {
      avg: all?.scan_avg || 0,
      p95: all?.scan_p95 || 0,
      trend: getTrend(all?.scan_avg || 0, recent?.scan_avg || 0),
    },
    apiLatency: {
      avg: all?.api_avg || 0,
      trend: getTrend(all?.api_avg || 0, recent?.api_avg || 0),
    },
    cacheHitRate: {
      current: all?.cache_rate || 0,
      trend: getTrend(1 - (all?.cache_rate || 0), 1 - (recent?.cache_rate || 0)),
    },
    recommendations,
  };
}

export function recordSlowQuery(query: SlowQuery): { success: boolean } {
  getDb()
    .prepare(`INSERT OR REPLACE INTO slow_queries VALUES (?,?,?,?,?,?,?,?)`)
    .run(
      query.id,
      query.query,
      query.duration,
      query.timestamp,
      query.table,
      query.rowsExamined,
      query.indexUsed ? 1 : 0,
      query.suggestion || null
    );

  // Track query stats
  const key = query.query.substring(0, 100);
  const existing = queryStats.get(key) || { count: 0, totalDuration: 0, maxDuration: 0 };
  queryStats.set(key, {
    count: existing.count + 1,
    totalDuration: existing.totalDuration + query.duration,
    maxDuration: Math.max(existing.maxDuration, query.duration),
  });

  return { success: true };
}

export function analyzeSlowQueries(options?: { threshold?: number; limit?: number }): {
  queries: SlowQuery[];
  patterns: Array<{ pattern: string; count: number; avgDuration: number }>;
  suggestions: IndexSuggestion[];
} {
  const threshold = options?.threshold || 1000;
  const limit = options?.limit || 20;

  const queries = (
    getDb()
      .prepare("SELECT * FROM slow_queries WHERE duration > ? ORDER BY duration DESC LIMIT ?")
      .all(threshold, limit) as any[]
  ).map((r) => ({
    id: r.id,
    query: r.query,
    duration: r.duration,
    timestamp: r.timestamp,
    table: r.table_name,
    rowsExamined: r.rows_examined,
    indexUsed: r.index_used === 1,
    suggestion: r.suggestion,
  }));

  const patterns: Array<{ pattern: string; count: number; avgDuration: number }> = [];
  for (const [pattern, stats] of queryStats) {
    if (stats.count >= 3) {
      patterns.push({
        pattern,
        count: stats.count,
        avgDuration: stats.totalDuration / stats.count,
      });
    }
  }
  patterns.sort((a, b) => b.avgDuration - a.avgDuration);

  const suggestions: IndexSuggestion[] = [];
  for (const q of queries) {
    if (!q.indexUsed && q.rowsExamined > 1000) {
      const columns = extractWhereColumns(q.query);
      if (columns.length > 0) {
        suggestions.push({
          table: q.table,
          columns,
          type: "btree",
          reason: `Query scans ${q.rowsExamined} rows without index`,
          estimatedImprovement: "50-90% faster",
          createStatement: `CREATE INDEX idx_${q.table}_${columns.join("_")} ON ${q.table}(${columns.join(", ")})`,
        });
      }
    }
  }

  return {
    queries,
    patterns: patterns.slice(0, 10),
    suggestions: [...new Map(suggestions.map((s) => [s.createStatement, s])).values()],
  };
}

function extractWhereColumns(query: string): string[] {
  const whereMatch = query.match(/WHERE\s+(.+?)(?:ORDER|GROUP|LIMIT|$)/i);
  if (!whereMatch) return [];
  const columns: string[] = [];
  const colMatches = whereMatch[1].matchAll(/(\w+)\s*[=<>]/g);
  for (const match of colMatches) columns.push(match[1]);
  return [...new Set(columns)];
}

export function suggestIndexes(): IndexSuggestion[] {
  const analysis = analyzeSlowQueries({ threshold: 500, limit: 50 });
  return analysis.suggestions;
}

export function applyIndexSuggestion(suggestion: IndexSuggestion): {
  success: boolean;
  applied: boolean;
} {
  try {
    getDb().prepare(suggestion.createStatement).run();
    getDb()
      .prepare(
        `INSERT INTO index_suggestions (table_name, columns, index_type, reason, improvement, create_statement, created_at, applied) VALUES (?,?,?,?,?,?,?,1)`
      )
      .run(
        suggestion.table,
        JSON.stringify(suggestion.columns),
        suggestion.type,
        suggestion.reason,
        suggestion.estimatedImprovement,
        suggestion.createStatement,
        new Date().toISOString()
      );
    return { success: true, applied: true };
  } catch {
    return { success: false, applied: false };
  }
}

export function recordCacheStats(stats: CacheStats): { success: boolean } {
  getDb()
    .prepare(
      `INSERT INTO cache_stats (cache_type, hits, misses, size, max_size, evictions, avg_load_time, recorded_at) VALUES (?,?,?,?,?,?,?,?)`
    )
    .run(
      stats.type,
      stats.hits,
      stats.misses,
      stats.size,
      stats.maxSize,
      stats.evictions,
      stats.avgLoadTime,
      new Date().toISOString()
    );
  return { success: true };
}

export function getCacheStats(cacheType?: string): CacheStats[] {
  let sql =
    "SELECT cache_type, SUM(hits) as hits, SUM(misses) as misses, MAX(size) as size, MAX(max_size) as max_size, SUM(evictions) as evictions, AVG(avg_load_time) as avg_load FROM cache_stats";
  const params: string[] = [];
  if (cacheType) {
    sql += " WHERE cache_type = ?";
    params.push(cacheType);
  }
  sql += " GROUP BY cache_type ORDER BY cache_type";

  return (
    getDb()
      .prepare(sql)
      .all(...params) as any[]
  ).map((r) => ({
    type: r.cache_type,
    hits: r.hits,
    misses: r.misses,
    hitRate: r.hits + r.misses > 0 ? r.hits / (r.hits + r.misses) : 0,
    size: r.size,
    maxSize: r.max_size,
    evictions: r.evictions,
    avgLoadTime: r.avg_load,
  }));
}

export function warmupCache(targets: string[]): {
  warmed: number;
  failed: number;
  duration: number;
} {
  const start = Date.now();
  let warmed = 0;
  let failed = 0;

  for (const target of targets) {
    try {
      metricsCache.set(`warmup:${target}`, {
        data: { target, warmedAt: new Date().toISOString() },
        expires: Date.now() + 3600000,
      });
      warmed++;
    } catch {
      failed++;
    }
  }

  return { warmed, failed, duration: Date.now() - start };
}

export function getPerformanceSummary(): {
  status: "healthy" | "degraded" | "critical";
  metrics: { scanAvg: number; apiAvg: number; cacheHitRate: number };
  issues: string[];
  score: number;
} {
  const agg = getAggregatedMetrics(24);
  const issues: string[] = [];
  let score = 100;

  if (agg.scanDuration.avg > 30000) {
    issues.push("Slow scan times");
    score -= 20;
  } else if (agg.scanDuration.avg > 15000) {
    issues.push("Moderate scan times");
    score -= 10;
  }

  if (agg.apiLatency.avg > 500) {
    issues.push("High API latency");
    score -= 20;
  } else if (agg.apiLatency.avg > 200) {
    issues.push("Elevated API latency");
    score -= 10;
  }

  if (agg.cacheHitRate.current < 0.5) {
    issues.push("Low cache hit rate");
    score -= 20;
  } else if (agg.cacheHitRate.current < 0.7) {
    issues.push("Moderate cache hit rate");
    score -= 10;
  }

  if (agg.scanDuration.trend === "degrading") {
    issues.push("Scan performance degrading");
    score -= 10;
  }
  if (agg.apiLatency.trend === "degrading") {
    issues.push("API latency degrading");
    score -= 10;
  }

  let status: "healthy" | "degraded" | "critical" = "healthy";
  if (score < 50) status = "critical";
  else if (score < 75) status = "degraded";

  return {
    status,
    score: Math.max(0, score),
    metrics: {
      scanAvg: agg.scanDuration.avg,
      apiAvg: agg.apiLatency.avg,
      cacheHitRate: agg.cacheHitRate.current,
    },
    issues,
  };
}

export const performance = {
  initPerformanceDb,
  recordMetrics,
  getMetrics,
  getAggregatedMetrics,
  recordSlowQuery,
  analyzeSlowQueries,
  suggestIndexes,
  applyIndexSuggestion,
  recordCacheStats,
  getCacheStats,
  warmupCache,
  getPerformanceSummary,
};
