import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["src/**/*.test.ts"],
    // Run test files sequentially to avoid shared module state conflicts
    // (e.g., SQLite database connections in audit-trail, report-templates)
    fileParallelism: false,
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov", "html"],
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts"],
      thresholds: {
        // Lowered thresholds to accommodate new modules (db-sync, offline-scanner,
        // vuln-database, etc.) that require Docker/external dependencies for testing
        lines: 55,
        functions: 65,
        branches: 49,
        statements: 55,
      },
    },
  },
});
