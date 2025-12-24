# Configuration Guide - Local CI/CD Platform

## Table of Contents

1. [Gitea Advanced Configuration](#gitea-advanced-configuration)
2. [Drone CI Configuration](#drone-ci-configuration)
3. [Docker Registry Configuration](#docker-registry-configuration)
4. [SSH Configuration](#ssh-configuration)
5. [Network Configuration](#network-configuration)
6. [Security Hardening](#security-hardening)
7. [Backup Configuration](#backup-configuration)
8. [Monitoring Setup](#monitoring-setup)

---

## Gitea Advanced Configuration

### Custom app.ini Configuration

Create a custom `app.ini` to override Gitea defaults:

```powershell
# Create config directory
mkdir -p config/gitea

# Create custom app.ini
notepad config/gitea/app.ini
```

Add this content to `config/gitea/app.ini`:

```ini
[server]
DOMAIN = localhost
ROOT_URL = http://localhost:3000/
SSH_PORT = 2222
START_SSH_SERVER = true
OFFLINE_MODE = true

[repository]
ROOT = /data/git/repositories
DEFAULT_BRANCH = main
DEFAULT_PRIVATE = true
ENABLE_PUSH_CREATE_USER = true
ENABLE_PUSH_CREATE_ORG = true

[repository.upload]
ENABLED = true
TEMP_PATH = /data/gitea/uploads
ALLOWED_TYPES =
FILE_MAX_SIZE = 100
MAX_FILES = 10

[lfs]
START_SERVER = true
PATH = /data/git/lfs
HTTP_AUTH_EXPIRY = 24h

[security]
INSTALL_LOCK = true
SECRET_KEY = ${GITEA_SECRET_KEY}
PASSWORD_COMPLEXITY = lower,upper,digit
MIN_PASSWORD_LENGTH = 10

[service]
DISABLE_REGISTRATION = false
REQUIRE_SIGNIN_VIEW = false
REGISTER_EMAIL_CONFIRM = false
ENABLE_NOTIFY_MAIL = false
ENABLE_CAPTCHA = false
DEFAULT_ALLOW_CREATE_ORGANIZATION = true
DEFAULT_ENABLE_TIMETRACKING = true

[webhook]
ALLOWED_HOST_LIST = *
SKIP_TLS_VERIFY = true
DELIVER_TIMEOUT = 30
PAGING_NUM = 10

[mailer]
ENABLED = false

[session]
PROVIDER = file
PROVIDER_CONFIG = /data/gitea/sessions
COOKIE_NAME = i_like_gitea
GC_INTERVAL_TIME = 86400
SESSION_LIFE_TIME = 86400
COOKIE_SECURE = false

[log]
MODE = console
LEVEL = Info
ROOT_PATH = /data/gitea/log

[cache]
ENABLED = true
ADAPTER = memory
INTERVAL = 60
HOST =

[database]
DB_TYPE = postgres
HOST = postgres:5432
NAME = gitea
USER = gitea
PASSWD = ${POSTGRES_PASSWORD}
LOG_SQL = false
SCHEMA =
SSL_MODE = disable

[indexer]
ISSUE_INDEXER_TYPE = bleve
ISSUE_INDEXER_PATH = /data/gitea/indexers/issues.bleve
REPO_INDEXER_ENABLED = true
REPO_INDEXER_PATH = /data/gitea/indexers/repos.bleve
REPO_INDEXER_INCLUDE =
REPO_INDEXER_EXCLUDE = resources/bin/**

[admin]
DISABLE_REGULAR_ORG_CREATION = false

[openid]
ENABLE_OPENID_SIGNIN = true
ENABLE_OPENID_SIGNUP = false

[oauth2]
ENABLE = true
ACCESS_TOKEN_EXPIRATION_TIME = 3600
REFRESH_TOKEN_EXPIRATION_TIME = 730
JWT_SECRET =

[metrics]
ENABLED = true
TOKEN =

[api]
ENABLE_SWAGGER = true
MAX_RESPONSE_ITEMS = 50

[ui]
EXPLORE_PAGING_NUM = 20
ISSUE_PAGING_NUM = 10
MEMBERS_PAGING_NUM = 20
```

Update `docker-compose.yml` to mount the config:

```yaml
gitea:
  volumes:
    - gitea-data:/data
    - ./config/gitea/app.ini:/data/gitea/conf/app.ini:ro
```

---

## Drone CI Configuration

### Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `DRONE_GITEA_SERVER` | Gitea server URL | - |
| `DRONE_GITEA_CLIENT_ID` | OAuth Client ID | - |
| `DRONE_GITEA_CLIENT_SECRET` | OAuth Client Secret | - |
| `DRONE_RPC_SECRET` | Shared secret with runners | - |
| `DRONE_SERVER_HOST` | Server hostname | - |
| `DRONE_SERVER_PROTO` | HTTP or HTTPS | http |
| `DRONE_DATABASE_DRIVER` | sqlite3 or postgres | sqlite3 |
| `DRONE_USER_CREATE` | Create admin user | - |
| `DRONE_USER_FILTER` | Limit user access | - |
| `DRONE_REPOSITORY_FILTER` | Limit repo access | - |

### Advanced Drone Configuration

Add to `docker-compose.yml` under `drone-server`:

```yaml
drone-server:
  environment:
    # Performance
    - DRONE_JSONNET_ENABLED=true
    - DRONE_STARLARK_ENABLED=true

    # Timeouts
    - DRONE_RUNNER_TIMEOUT=60m
    - DRONE_HTTP_TIMEOUT=30s

    # Limits
    - DRONE_LIMIT_REPOS=0
    - DRONE_LIMIT_EVENTS=0

    # Cron jobs
    - DRONE_CRON_DISABLED=false
    - DRONE_CRON_INTERVAL=1h

    # Secrets encryption
    - DRONE_SECRET_SECRET=${DRONE_SECRET_ENCRYPTION_KEY}
```

### Drone Runner Configuration

```yaml
drone-runner:
  environment:
    # Capacity
    - DRONE_RUNNER_CAPACITY=4
    - DRONE_RUNNER_MAX_PROCS=4

    # Resources
    - DRONE_MEMORY_LIMIT=2147483648
    - DRONE_CPU_QUOTA=400000

    # Volumes (mount host paths into build containers)
    - DRONE_RUNNER_VOLUMES=/var/run/docker.sock:/var/run/docker.sock

    # Environment variables for all builds
    - DRONE_RUNNER_ENVIRON=DOCKER_REGISTRY:localhost:5000

    # Clone configuration
    - DRONE_CLONE_DISABLE=false
    - DRONE_CLONE_RETRY=5

    # Labels (for runner selection)
    - DRONE_RUNNER_LABELS=platform:docker,os:linux
```

---

## Docker Registry Configuration

### Enable Authentication

Create `config/registry/config.yml`:

```yaml
version: 0.1
log:
  fields:
    service: registry
storage:
  cache:
    blobdescriptor: inmemory
  filesystem:
    rootdirectory: /var/lib/registry
  delete:
    enabled: true
  maintenance:
    uploadpurging:
      enabled: true
      age: 168h
      interval: 24h
      dryrun: false
http:
  addr: :5000
  headers:
    X-Content-Type-Options: [nosniff]
    Access-Control-Allow-Origin: ['*']
    Access-Control-Allow-Methods: ['HEAD', 'GET', 'OPTIONS', 'DELETE']
    Access-Control-Allow-Headers: ['Authorization', 'Accept']
    Access-Control-Max-Age: [1728000]
    Access-Control-Allow-Credentials: [true]
    Access-Control-Expose-Headers: ['Docker-Content-Digest']
auth:
  htpasswd:
    realm: basic-realm
    path: /auth/htpasswd
```

### Create Registry Users

```powershell
# Create auth directory
mkdir -p config/registry/auth

# Create htpasswd file (install apache2-utils if needed)
docker run --rm --entrypoint htpasswd httpd:2 -Bbn admin adminpassword > config/registry/auth/htpasswd
docker run --rm --entrypoint htpasswd httpd:2 -Bbn drone dronepassword >> config/registry/auth/htpasswd
```

### Update docker-compose.yml

```yaml
registry:
  volumes:
    - registry-data:/var/lib/registry
    - ./config/registry/config.yml:/etc/docker/registry/config.yml:ro
    - ./config/registry/auth:/auth:ro
```

---

## SSH Configuration

### Configure Git SSH Access

1. **Generate SSH Key** (if you don't have one):

```powershell
ssh-keygen -t ed25519 -C "your-email@example.com"
```

2. **Add SSH Key to Gitea**:
   - Go to Gitea → Settings → SSH / GPG Keys
   - Click "Add Key"
   - Paste your public key (`~/.ssh/id_ed25519.pub`)

3. **Configure SSH Config** (create/edit `~/.ssh/config`):

```
Host gitea-local
    HostName localhost
    Port 2222
    User git
    IdentityFile ~/.ssh/id_ed25519
    StrictHostKeyChecking no
```

4. **Test SSH Connection**:

```powershell
ssh -T git@localhost -p 2222
```

5. **Clone via SSH**:

```powershell
git clone ssh://git@localhost:2222/username/repository.git
# Or using the config alias
git clone git@gitea-local:username/repository.git
```

---

## Network Configuration

### Custom DNS with Traefik

Create `config/traefik/traefik.yml`:

```yaml
api:
  dashboard: true
  insecure: true

entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

providers:
  docker:
    exposedByDefault: false
    network: ci-cd-network

log:
  level: INFO

accessLog: {}
```

Create `config/traefik/dynamic.yml`:

```yaml
http:
  routers:
    gitea:
      rule: "Host(`git.localhost`)"
      service: gitea
      entryPoints:
        - web

    drone:
      rule: "Host(`ci.localhost`)"
      service: drone
      entryPoints:
        - web

    registry:
      rule: "Host(`registry.localhost`)"
      service: registry
      entryPoints:
        - web

  services:
    gitea:
      loadBalancer:
        servers:
          - url: "http://gitea:3000"

    drone:
      loadBalancer:
        servers:
          - url: "http://drone-server:80"

    registry:
      loadBalancer:
        servers:
          - url: "http://registry:5000"
```

### Add Hosts File Entries (Windows)

Run PowerShell as Administrator:

```powershell
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "`n127.0.0.1 git.localhost ci.localhost registry.localhost"
```

---

## Security Hardening

### 1. Enable HTTPS with Self-Signed Certificates

```powershell
# Create certs directory
mkdir -p config/certs

# Generate self-signed certificate
docker run --rm -v ${PWD}/config/certs:/certs alpine/openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /certs/server.key -out /certs/server.crt -subj "/CN=localhost"
```

### 2. Secure Docker Socket

Create `config/docker-socket-proxy/docker-compose.override.yml`:

```yaml
services:
  docker-socket-proxy:
    image: tecnativa/docker-socket-proxy
    container_name: ci-docker-socket-proxy
    restart: unless-stopped
    environment:
      - CONTAINERS=1
      - IMAGES=1
      - NETWORKS=1
      - VOLUMES=1
      - POST=1
      - BUILD=1
      - EXEC=1
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - ci-cd-network

  drone-runner:
    environment:
      - DOCKER_HOST=tcp://docker-socket-proxy:2375
    depends_on:
      - docker-socket-proxy
```

### 3. Network Policies

Add network segmentation:

```yaml
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # No external access

services:
  postgres:
    networks:
      - backend  # Only backend access

  gitea:
    networks:
      - frontend
      - backend
```

---

## Backup Configuration

### Automated Backup Script

Create `scripts/backup.ps1`:

```powershell
# Backup script for CI/CD platform
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupDir = "backups/$timestamp"

# Create backup directory
New-Item -ItemType Directory -Force -Path $backupDir

Write-Host "Creating backup at $backupDir..."

# Backup PostgreSQL
Write-Host "Backing up PostgreSQL..."
docker compose exec -T postgres pg_dump -U gitea gitea > "$backupDir/gitea-db.sql"

# Backup Gitea data
Write-Host "Backing up Gitea data..."
docker run --rm -v gitea-data:/data -v ${PWD}/${backupDir}:/backup alpine tar czf /backup/gitea-data.tar.gz -C /data .

# Backup Drone data
Write-Host "Backing up Drone data..."
docker run --rm -v drone-data:/data -v ${PWD}/${backupDir}:/backup alpine tar czf /backup/drone-data.tar.gz -C /data .

# Backup Registry data
Write-Host "Backing up Registry data..."
docker run --rm -v registry-data:/data -v ${PWD}/${backupDir}:/backup alpine tar czf /backup/registry-data.tar.gz -C /data .

# Backup configuration files
Write-Host "Backing up configuration..."
Copy-Item -Path ".env" -Destination "$backupDir/"
Copy-Item -Path "docker-compose.yml" -Destination "$backupDir/"
if (Test-Path "config") {
    Copy-Item -Path "config" -Destination "$backupDir/" -Recurse
}

Write-Host "Backup completed: $backupDir"
Get-ChildItem $backupDir
```

### Restore Script

Create `scripts/restore.ps1`:

```powershell
param(
    [Parameter(Mandatory=$true)]
    [string]$BackupDir
)

if (-not (Test-Path $BackupDir)) {
    Write-Error "Backup directory not found: $BackupDir"
    exit 1
}

Write-Host "Restoring from $BackupDir..."

# Stop services
docker compose down

# Restore PostgreSQL
Write-Host "Restoring PostgreSQL..."
docker compose up -d postgres
Start-Sleep -Seconds 10
Get-Content "$BackupDir/gitea-db.sql" | docker compose exec -T postgres psql -U gitea gitea

# Restore Gitea data
Write-Host "Restoring Gitea data..."
docker run --rm -v gitea-data:/data -v ${PWD}/${BackupDir}:/backup alpine sh -c "rm -rf /data/* && tar xzf /backup/gitea-data.tar.gz -C /data"

# Restore Drone data
Write-Host "Restoring Drone data..."
docker run --rm -v drone-data:/data -v ${PWD}/${BackupDir}:/backup alpine sh -c "rm -rf /data/* && tar xzf /backup/drone-data.tar.gz -C /data"

# Restore Registry data
Write-Host "Restoring Registry data..."
docker run --rm -v registry-data:/data -v ${PWD}/${BackupDir}:/backup alpine sh -c "rm -rf /data/* && tar xzf /backup/registry-data.tar.gz -C /data"

# Start all services
docker compose up -d

Write-Host "Restore completed!"
```

---

## Monitoring Setup

### Add Prometheus and Grafana

Create `docker-compose.monitoring.yml`:

```yaml
version: "3.8"

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: ci-prometheus
    restart: unless-stopped
    volumes:
      - ./config/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    ports:
      - "9090:9090"
    networks:
      - ci-cd-network
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.enable-lifecycle'

  grafana:
    image: grafana/grafana:latest
    container_name: ci-grafana
    restart: unless-stopped
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana-data:/var/lib/grafana
      - ./config/grafana/provisioning:/etc/grafana/provisioning:ro
    ports:
      - "3001:3000"
    networks:
      - ci-cd-network
    depends_on:
      - prometheus

volumes:
  prometheus-data:
  grafana-data:
```

Create `config/prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'gitea'
    static_configs:
      - targets: ['gitea:3000']
    metrics_path: /metrics

  - job_name: 'drone'
    static_configs:
      - targets: ['drone-server:80']
    metrics_path: /metrics

  - job_name: 'docker'
    static_configs:
      - targets: ['host.docker.internal:9323']
```

### Start Monitoring Stack

```powershell
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d
```

Access:
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3001 (admin/admin)

---

## Environment-Specific Configurations

### Development

```env
# .env.development
GITEA__service__DISABLE_REGISTRATION=false
GITEA__log__LEVEL=Debug
DRONE_LOGS_DEBUG=true
```

### Production

```env
# .env.production
GITEA__service__DISABLE_REGISTRATION=true
GITEA__log__LEVEL=Warn
DRONE_LOGS_DEBUG=false
DRONE_LOGS_TRACE=false
```

Use with:
```powershell
docker compose --env-file .env.production up -d
```
