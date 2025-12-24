// =============================================================================
// Configuration
// =============================================================================
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

export type Config = typeof config;
