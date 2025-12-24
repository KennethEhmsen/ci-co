# Local CI/CD System Architecture

## Overview

This document describes a complete local CI/CD system that replicates GitHub-like functionality on your local machine using Docker Desktop.

## System Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           LOCAL CI/CD PLATFORM                               │
│                                                                              │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐          │
│  │                 │    │                 │    │                 │          │
│  │    Gitea        │◄──►│    Drone CI     │◄──►│  Docker Registry│          │
│  │  (Git Server)   │    │   (CI/CD)       │    │   (Images)      │          │
│  │                 │    │                 │    │                 │          │
│  │  Port: 3000     │    │  Port: 8085     │    │  Port: 5000     │          │
│  │  SSH: 2222      │    │                 │    │  UI: 5001       │          │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘          │
│           │                      │                      │                    │
│           ▼                      ▼                      ▼                    │
│  ┌─────────────────────────────────────────────────────────────────┐        │
│  │                     Docker Network: ci-cd-network                │        │
│  └─────────────────────────────────────────────────────────────────┘        │
│           │                      │                      │                    │
│           ▼                      ▼                      ▼                    │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐          │
│  │   PostgreSQL    │    │  Drone Runner   │    │   SonarQube     │          │
│  │   (Database)    │    │   (Docker)      │    │  (Code Quality) │          │
│  │                 │    │                 │    │                 │          │
│  │  Port: 5432     │    │                 │    │  Port: 9000     │          │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘          │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────┐        │
│  │                     Persistent Volumes                           │        │
│  │  • gitea-data     • drone-data      • registry-data             │        │
│  │  • postgres-data  • runner-data                                  │        │
│  └─────────────────────────────────────────────────────────────────┘        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Gitea (Git Server)
- **Purpose**: Self-hosted Git service (GitHub alternative)
- **Features**:
  - Repository management
  - Pull requests and code review
  - Issue tracking
  - Wiki
  - Webhooks for CI/CD integration
  - User/organization management
- **URL**: http://localhost:3000
- **SSH**: localhost:2222

### 2. Drone CI (CI/CD Engine)
- **Purpose**: Continuous Integration and Continuous Deployment
- **Features**:
  - Pipeline as code (.drone.yml)
  - Docker-native builds
  - Parallel execution
  - Secret management
  - Multi-platform builds
- **URL**: http://localhost:8085

### 3. Drone Runner (Docker)
- **Purpose**: Executes CI/CD pipelines
- **Features**:
  - Runs pipelines in Docker containers
  - Automatic scaling
  - Resource management
  - Build isolation

### 4. Docker Registry
- **Purpose**: Private container image storage
- **Features**:
  - Store built Docker images
  - Push/pull images locally
  - Image versioning
- **URL**: http://localhost:5000

### 5. PostgreSQL Database
- **Purpose**: Data persistence for Gitea
- **Features**:
  - Reliable data storage
  - Backup support
  - High performance

### 6. Security Scanning Tools
- **Trivy**: Container and dependency vulnerability scanning (Port: 4954)
- **SonarQube**: Code quality and security analysis (Port: 9000)
- **Dependency-Track**: Software composition analysis and SBOM (Ports: 8081, 8082)

### 7. Traefik (Optional - Not Included by Default)
- **Purpose**: Route traffic and SSL termination
- **Note**: Can be added for production deployments requiring HTTPS
- **Features**:
  - Automatic HTTPS
  - Load balancing
  - Dashboard

## Data Flow

```
Developer Workflow:

  ┌──────────┐      git push       ┌──────────┐
  │Developer │ ──────────────────► │  Gitea   │
  │   PC     │                     │          │
  └──────────┘                     └────┬─────┘
                                        │
                                        │ Webhook
                                        ▼
                                   ┌──────────┐
                                   │ Drone CI │
                                   │          │
                                   └────┬─────┘
                                        │
                                        │ Trigger
                                        ▼
                                   ┌──────────┐
                                   │  Drone   │
                                   │  Runner  │
                                   └────┬─────┘
                                        │
        ┌───────────────────────────────┼───────────────────┐
        │                               │                   │
        ▼                               ▼                   ▼
   ┌─────────┐                    ┌─────────┐         ┌─────────┐
   │  Build  │                    │  Test   │         │ Deploy  │
   │Container│                    │Container│         │Container│
   └────┬────┘                    └─────────┘         └────┬────┘
        │                                                  │
        │ Push Image                                       │
        ▼                                                  ▼
   ┌─────────┐                                       ┌─────────┐
   │ Docker  │                                       │ Target  │
   │Registry │                                       │  Env    │
   └─────────┘                                       └─────────┘
```

## Network Architecture

```
Docker Network: ci-cd-network (bridge)

┌────────────────────────────────────────────────────────────┐
│                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │    gitea     │  │    drone     │  │   registry   │     │
│  │              │  │              │  │              │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   postgres   │  │drone-runner  │  │  sonarqube   │     │
│  │              │  │              │  │              │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │    trivy     │  │ dep-track-api│  │ dep-track-ui │     │
│  │              │  │              │  │              │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                            │
└────────────────────────────────────────────────────────────┘
                            │
                            │ Port Mapping
                            ▼
┌────────────────────────────────────────────────────────────┐
│  Host Machine (localhost)                                  │
│  • 3000  → Gitea Web UI                                   │
│  • 2222  → Gitea SSH                                      │
│  • 8085  → Drone CI Web UI                                │
│  • 5000  → Docker Registry API                            │
│  • 5001  → Docker Registry UI                             │
│  • 9000  → SonarQube                                      │
│  • 4954  → Trivy Server                                   │
│  • 8081  → Dependency-Track API                           │
│  • 8082  → Dependency-Track UI                            │
└────────────────────────────────────────────────────────────┘
```

## Security Considerations

1. **Network Isolation**: All services run in a dedicated Docker network
2. **Secret Management**: Drone secrets stored encrypted
3. **Access Control**: Gitea provides user authentication
4. **OAuth Integration**: Drone authenticates via Gitea OAuth
5. **Registry Security**: Private registry with optional authentication

## Scalability

- **Horizontal Scaling**: Add more Drone runners for parallel builds
- **Storage**: Volumes can be migrated to external storage
- **Database**: PostgreSQL can be upgraded or clustered

## Backup Strategy

| Component | Data Location | Backup Method |
|-----------|--------------|---------------|
| Gitea | gitea-data volume | Volume backup |
| PostgreSQL | postgres-data volume | pg_dump |
| Registry | registry-data volume | Volume backup |
| Drone | drone-data volume | Volume backup |

## Resource Requirements

| Component | CPU | Memory | Storage |
|-----------|-----|--------|---------|
| Gitea | 0.5 cores | 512 MB | 1 GB+ |
| PostgreSQL | 0.5 cores | 256 MB | 500 MB+ |
| Drone Server | 0.5 cores | 256 MB | 100 MB |
| Drone Runner | 1+ cores | 512 MB+ | Varies |
| Registry | 0.25 cores | 256 MB | 5 GB+ |
| **Total Minimum** | **2.75 cores** | **1.8 GB** | **7 GB** |

## Alternative Component Options

| Function | Primary Choice | Alternatives |
|----------|---------------|--------------|
| Git Server | Gitea | GitLab CE, Gogs, Forgejo |
| CI/CD | Drone CI | Jenkins, Woodpecker CI, Concourse |
| Registry | Docker Registry | Harbor, Nexus |
| Database | PostgreSQL | MySQL, SQLite |
| Proxy | Traefik | Nginx, Caddy |
