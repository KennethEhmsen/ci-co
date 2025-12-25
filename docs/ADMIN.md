# Administrator Guide

This guide covers operational aspects of running and maintaining the CI/CD Security Platform.

## Table of Contents

- [Deployment](#deployment)
- [Service Management](#service-management)
- [Monitoring](#monitoring)
- [Backup and Recovery](#backup-and-recovery)
- [Scaling](#scaling)
- [Security Hardening](#security-hardening)
- [Maintenance](#maintenance)
- [Logging](#logging)

---

## Deployment

### Initial Deployment

```powershell
# Clone the repository
git clone https://github.com/KennethEhmsen/ci-co.git
cd ci-co

# Start all services
docker compose up -d

# Wait for services to initialize (~90 seconds)
# Check status
docker compose ps
```

### Production Deployment Checklist

- [ ] Change all default passwords (see [Security Hardening](#security-hardening))
- [ ] Configure proper hostnames in `.env`
- [ ] Set up SSL/TLS certificates
- [ ] Configure firewall rules
- [ ] Set up monitoring and alerting
- [ ] Configure backup schedules
- [ ] Review resource allocations

### Environment Configuration

Create `.env` file from template:

```bash
cp .env.example .env
```

Key production settings:

```bash
# Service URLs (change for production)
GITEA_URL=https://git.yourdomain.com
DRONE_URL=https://ci.yourdomain.com
SONARQUBE_URL=https://sonar.yourdomain.com
DTRACK_URL=https://dtrack.yourdomain.com

# Credentials (CHANGE THESE!)
GITEA_PASSWORD=<strong-password>
SONARQUBE_PASSWORD=<strong-password>
DRONE_TOKEN=<generated-token>
DTRACK_API_KEY=<generated-key>
```

---

## Service Management

### Starting Services

```powershell
# Start all services
docker compose up -d

# Start specific service
docker compose up -d gitea

# Start with rebuild
docker compose up -d --build
```

### Stopping Services

```powershell
# Stop all services (preserve data)
docker compose down

# Stop and remove volumes (DESTROYS DATA)
docker compose down -v

# Stop specific service
docker compose stop sonarqube
```

### Restarting Services

```powershell
# Restart all services
docker compose restart

# Restart specific service
docker compose restart drone

# Recreate containers (picks up config changes)
docker compose up -d --force-recreate
```

### Service Status

```powershell
# View all container status
docker compose ps

# View resource usage
docker stats

# Check service health
docker compose exec gitea curl -s localhost:3000/api/healthz
```

### Service Dependencies

```
gitea ─────────► drone-server ─────────► drone-runner
   │                                          │
   │                                          ▼
   ▼                                     ┌─────────┐
postgres                                 │ registry│
                                         └─────────┘
sonarqube ◄──────── sonarqube-db

dependency-track-api ◄──── dependency-track-db
        │
        ▼
dependency-track-frontend
```

---

## Monitoring

### Health Checks

Use the platform status tool:

```powershell
# Via CI/CD Agent
cicd-agent status

# Via scripts
.\scripts\status.ps1
```

### Manual Health Endpoints

| Service | Health Endpoint |
|---------|----------------|
| Gitea | `http://localhost:3000/api/healthz` |
| Drone | `http://localhost:8085/healthz` |
| SonarQube | `http://localhost:9000/api/system/health` |
| D-Track | `http://localhost:8082/api/version` |
| Trivy | `http://localhost:4954/healthz` |
| Registry | `http://localhost:5000/v2/` |

### Container Logs

```powershell
# View all logs
docker compose logs

# Follow logs in real-time
docker compose logs -f

# View specific service logs
docker compose logs -f gitea

# View last 100 lines
docker compose logs --tail=100 drone

# View logs with timestamps
docker compose logs -t sonarqube
```

### Resource Monitoring

```powershell
# Real-time resource usage
docker stats

# Single snapshot
docker stats --no-stream

# Specific containers
docker stats gitea drone-server
```

### Setting Up Prometheus (Optional)

Add to `docker-compose.yml`:

```yaml
prometheus:
  image: prom/prometheus:latest
  ports:
    - "9090:9090"
  volumes:
    - ./prometheus.yml:/etc/prometheus/prometheus.yml
  networks:
    - ci-cd-network

grafana:
  image: grafana/grafana:latest
  ports:
    - "3001:3000"
  environment:
    - GF_SECURITY_ADMIN_PASSWORD=admin
  networks:
    - ci-cd-network
```

---

## Backup and Recovery

### Backup Strategy

| Component | Data Location | Backup Method | Frequency |
|-----------|--------------|---------------|-----------|
| Gitea | `gitea-data` volume | Volume backup | Daily |
| PostgreSQL | `postgres-data` volume | pg_dump | Daily |
| SonarQube | `sonarqube-data` volume | Volume backup | Weekly |
| D-Track | `dtrack-data` volume | Volume backup | Weekly |
| Registry | `registry-data` volume | Volume backup | Weekly |
| Drone | `drone-data` volume | Volume backup | Daily |

### Using Backup Script

```powershell
# Run full backup
.\scripts\backup.ps1

# Backup to specific location
.\scripts\backup.ps1 -BackupPath "D:\Backups\cicd"

# Backup specific services only
.\scripts\backup.ps1 -Services "gitea,postgres"
```

### Manual Backup

```powershell
# Create backup directory
$BackupDir = "C:\Backups\cicd-$(Get-Date -Format 'yyyyMMdd')"
New-Item -ItemType Directory -Force -Path $BackupDir

# Backup Docker volumes
docker run --rm -v gitea-data:/data -v ${BackupDir}:/backup alpine `
    tar czf /backup/gitea-data.tar.gz -C /data .

docker run --rm -v postgres-data:/data -v ${BackupDir}:/backup alpine `
    tar czf /backup/postgres-data.tar.gz -C /data .

# Backup PostgreSQL database
docker compose exec -T postgres pg_dumpall -U gitea > "$BackupDir\postgres-dump.sql"
```

### Recovery

```powershell
# Restore from backup
.\scripts\restore.ps1 -BackupPath "C:\Backups\cicd-20241220"

# Manual volume restore
docker compose down
docker run --rm -v gitea-data:/data -v C:\Backups:/backup alpine `
    sh -c "rm -rf /data/* && tar xzf /backup/gitea-data.tar.gz -C /data"
docker compose up -d
```

### Disaster Recovery

1. **Stop services**: `docker compose down`
2. **Remove corrupted volumes**: `docker volume rm ci-co_gitea-data`
3. **Restore from backup**: Use restore script
4. **Start services**: `docker compose up -d`
5. **Verify data**: Check repositories, builds, and scans

---

## Scaling

### Horizontal Scaling

#### Adding More Drone Runners

Edit `docker-compose.yml`:

```yaml
drone-runner-2:
  image: drone/drone-runner-docker:1
  environment:
    - DRONE_RPC_PROTO=http
    - DRONE_RPC_HOST=drone-server
    - DRONE_RPC_SECRET=${DRONE_RPC_SECRET}
    - DRONE_RUNNER_CAPACITY=4
    - DRONE_RUNNER_NAME=runner-2
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
  networks:
    - ci-cd-network
```

### Vertical Scaling

#### Increasing Runner Capacity

```yaml
drone-runner:
  environment:
    - DRONE_RUNNER_CAPACITY=8  # Increase from default 2
```

#### SonarQube Memory

```yaml
sonarqube:
  environment:
    - SONAR_WEB_JAVAOPTS=-Xmx2g -Xms1g
    - SONAR_CE_JAVAOPTS=-Xmx2g -Xms1g
```

### Resource Limits

```yaml
gitea:
  deploy:
    resources:
      limits:
        cpus: '2'
        memory: 2G
      reservations:
        cpus: '0.5'
        memory: 512M
```

---

## Security Hardening

### Change Default Passwords

**Gitea:**
1. Login at http://localhost:3000
2. Settings → Security → Change Password

**SonarQube:**
1. Login at http://localhost:9000
2. My Account → Security → Change Password

**Dependency-Track:**
1. Login at http://localhost:8082
2. Administration → Users → Change Password

### Generate Secure Tokens

```powershell
# Generate random token
[System.Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

### Enable HTTPS (with Traefik)

Add Traefik to `docker-compose.yml`:

```yaml
traefik:
  image: traefik:v2.10
  command:
    - "--providers.docker=true"
    - "--entrypoints.websecure.address=:443"
    - "--certificatesresolvers.letsencrypt.acme.tlschallenge=true"
    - "--certificatesresolvers.letsencrypt.acme.email=admin@yourdomain.com"
  ports:
    - "443:443"
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
    - ./letsencrypt:/letsencrypt
  networks:
    - ci-cd-network
```

### Network Security

```powershell
# Restrict to localhost only
docker compose down
# Edit docker-compose.yml to bind to 127.0.0.1
# ports:
#   - "127.0.0.1:3000:3000"
docker compose up -d
```

### Secrets Management

Store secrets in environment:

```powershell
# Windows
$env:DRONE_TOKEN = "your-secret-token"

# Or use .env file (don't commit!)
echo "DRONE_TOKEN=your-secret-token" >> .env
```

---

## Maintenance

### Updates

```powershell
# Pull latest images
docker compose pull

# Recreate containers with new images
docker compose up -d

# Remove old images
docker image prune -f
```

### Cleanup

```powershell
# Remove unused Docker resources
docker system prune -f

# Remove unused volumes (CAREFUL!)
docker volume prune -f

# Remove old build cache
docker builder prune -f
```

### Database Maintenance

**PostgreSQL:**
```powershell
# Vacuum and analyze
docker compose exec postgres psql -U gitea -c "VACUUM ANALYZE;"

# Check database size
docker compose exec postgres psql -U gitea -c "SELECT pg_database_size('gitea');"
```

**SonarQube:**
```powershell
# Housekeeping (removes old data)
# Configure in Administration → Configuration → Housekeeping
```

### Log Rotation

Add to Docker daemon configuration:

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

---

## Logging

### Centralized Logging

Add Loki for log aggregation:

```yaml
loki:
  image: grafana/loki:latest
  ports:
    - "3100:3100"
  volumes:
    - loki-data:/loki
  networks:
    - ci-cd-network

promtail:
  image: grafana/promtail:latest
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
    - ./promtail-config.yml:/etc/promtail/config.yml
  networks:
    - ci-cd-network
```

### Log Levels

Configure service log levels:

**Gitea** (in `gitea/conf/app.ini`):
```ini
[log]
LEVEL = Info
```

**Drone** (environment variable):
```yaml
environment:
  - DRONE_LOGS_DEBUG=true
```

### Audit Logging

**Gitea** tracks:
- User logins
- Repository access
- Admin actions

**Drone** tracks:
- Build triggers
- Secret access
- Configuration changes

Access audit logs:
```powershell
docker compose logs gitea | Select-String "audit"
```

---

## Quick Reference

### Common Commands

| Action | Command |
|--------|---------|
| Start all | `docker compose up -d` |
| Stop all | `docker compose down` |
| View logs | `docker compose logs -f` |
| Check status | `docker compose ps` |
| Restart service | `docker compose restart <service>` |
| View resources | `docker stats` |
| Backup | `.\scripts\backup.ps1` |
| Restore | `.\scripts\restore.ps1` |

### Port Reference

| Port | Service |
|------|---------|
| 3000 | Gitea Web UI |
| 2222 | Gitea SSH |
| 8085 | Drone CI |
| 5000 | Docker Registry API |
| 5001 | Docker Registry UI |
| 9000 | SonarQube |
| 4954 | Trivy Server |
| 8081 | D-Track API |
| 8082 | D-Track UI |
| 5432 | PostgreSQL |

### Support

- [Troubleshooting Guide](TROUBLESHOOTING.md)
- [GitHub Issues](https://github.com/KennethEhmsen/ci-co/issues)
- [Security Policy](../SECURITY.md)
