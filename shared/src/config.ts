// =============================================================================
// Configuration
// =============================================================================

/**
 * Platform configuration loaded from environment variables.
 * Provides connection details for all CI/CD platform services.
 *
 * Environment variables (with defaults):
 * - `GITEA_URL` - Gitea server URL (default: http://localhost:3000)
 * - `GITEA_USER` - Gitea username (default: localadmin)
 * - `GITEA_PASSWORD` - Gitea password (default: admin123)
 * - `DRONE_URL` - Drone CI URL (default: http://localhost:8085)
 * - `DRONE_TOKEN` - Drone API token (required for write operations)
 * - `SONARQUBE_URL` - SonarQube URL (default: http://localhost:9000)
 * - `SONARQUBE_USER` - SonarQube username (default: admin)
 * - `SONARQUBE_PASSWORD` - SonarQube password (default: admin)
 * - `DTRACK_URL` - Dependency-Track API URL (default: http://localhost:8081)
 * - `DTRACK_API_KEY` - Dependency-Track API key (required)
 * - `TRIVY_URL` - Trivy server URL (default: http://localhost:4954)
 * - `REGISTRY_URL` - Docker registry URL (default: http://localhost:5000)
 *
 * @example
 * ```typescript
 * import { config } from '@cicd/shared';
 *
 * console.log(config.gitea.url); // "http://localhost:3000"
 * console.log(config.drone.token); // Value from DRONE_TOKEN env var
 * ```
 */
export const config = {
  gitea: {
    url: process.env.GITEA_URL || "http://localhost:3000",
    user: process.env.GITEA_USER || "localadmin",
    password: process.env.GITEA_PASSWORD || "admin123",
  },
  drone: {
    url: process.env.DRONE_URL || "http://localhost:8085",
    token: process.env.DRONE_TOKEN || "",
  },
  sonarqube: {
    url: process.env.SONARQUBE_URL || "http://localhost:9000",
    user: process.env.SONARQUBE_USER || "admin",
    password: process.env.SONARQUBE_PASSWORD || "admin",
  },
  dependencyTrack: {
    url: process.env.DTRACK_URL || "http://localhost:8081",
    apiKey: process.env.DTRACK_API_KEY || "",
  },
  trivy: {
    url: process.env.TRIVY_URL || "http://localhost:4954",
  },
  registry: {
    url: process.env.REGISTRY_URL || "http://localhost:5000",
  },
};

/**
 * TypeScript type representing the platform configuration structure.
 * Inferred from the config object for type-safe access to configuration values.
 *
 * @example
 * ```typescript
 * import { Config, config } from '@cicd/shared';
 *
 * function getServiceUrl(cfg: Config, service: keyof Config): string {
 *   return cfg[service].url;
 * }
 * ```
 */
export type Config = typeof config;
