# Troubleshooting Guide

This guide helps diagnose and resolve common issues with the CI/CD Security Platform.

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Service Issues](#service-issues)
  - [Gitea](#gitea-issues)
  - [Drone CI](#drone-ci-issues)
  - [SonarQube](#sonarqube-issues)
  - [Dependency-Track](#dependency-track-issues)
  - [Trivy](#trivy-issues)
  - [Docker Registry](#docker-registry-issues)
- [MCP Server Issues](#mcp-server-issues)
- [CI/CD Agent Issues](#cicd-agent-issues)
- [Build Issues](#build-issues)
- [Network Issues](#network-issues)
- [Performance Issues](#performance-issues)
- [Data Recovery](#data-recovery)

---

## Quick Diagnostics

### Check All Services

```powershell
# Check container status
docker compose ps

# Expected output: all services should show "running" or "Up"
```

### Check Logs for Errors

```powershell
# View recent errors across all services
docker compose logs --tail=50 | Select-String -Pattern "error|ERROR|fatal|FATAL"

# Or use grep on Linux/macOS
docker compose logs --tail=50 2>&1 | grep -i "error\|fatal"
```

### Platform Health Check

```powershell
# Using CI/CD Agent
cicd-agent status

# Using curl
curl http://localhost:3000/api/healthz  # Gitea
curl http://localhost:8085/healthz       # Drone
curl http://localhost:9000/api/system/health  # SonarQube
```

---

## Service Issues

### Gitea Issues

#### Gitea Won't Start

**Symptoms:** Container exits immediately or keeps restarting.

**Check logs:**
```powershell
docker compose logs gitea
```

**Common causes:**

1. **Database connection failed**
   ```
   Error: dial tcp postgres:5432: connection refused
   ```
   **Solution:** Ensure PostgreSQL is running first:
   ```powershell
   docker compose up -d postgres
   sleep 10
   docker compose up -d gitea
   ```

2. **Permission issues on volumes**
   ```
   Error: permission denied
   ```
   **Solution:**
   ```powershell
   docker compose down
   docker volume rm ci-co_gitea-data
   docker compose up -d
   ```

3. **Port already in use**
   ```
   Error: bind: address already in use
   ```
   **Solution:**
   ```powershell
   # Find what's using port 3000
   netstat -ano | findstr :3000
   # Kill the process or change Gitea's port in docker-compose.yml
   ```

#### Can't Login to Gitea

**Symptoms:** Login fails with correct credentials.

**Solutions:**

1. **Reset password via CLI:**
   ```powershell
   docker compose exec gitea gitea admin user change-password --username localadmin --password newpassword
   ```

2. **Check if user exists:**
   ```powershell
   docker compose exec gitea gitea admin user list
   ```

#### Gitea SSH Not Working

**Symptoms:** `ssh: connect to host localhost port 2222: Connection refused`

**Check:**
```powershell
# Verify SSH port is exposed
docker compose ps gitea
# Should show 0.0.0.0:2222->22/tcp
```

**Solution:** Ensure SSH is enabled in Gitea config:
```powershell
docker compose exec gitea cat /data/gitea/conf/app.ini | Select-String SSH
```

---

### Drone CI Issues

#### Drone Not Connecting to Gitea

**Symptoms:** "Failed to authenticate" when clicking Continue.

**Check OAuth settings:**
1. Go to Gitea → Settings → Applications
2. Verify OAuth2 application exists for Drone
3. Check redirect URL matches `http://localhost:8085/login`

**Solution:** Recreate OAuth app:
```powershell
# Remove and recreate Drone
docker compose down drone-server drone-runner
docker volume rm ci-co_drone-data
docker compose up -d drone-server drone-runner
```

#### Builds Not Starting

**Symptoms:** Pushed to Gitea but no build triggered.

**Checklist:**

1. **Repository activated in Drone?**
   - Go to http://localhost:8085
   - Find repository and check if "Active"

2. **Webhook configured?**
   - In Gitea repo → Settings → Webhooks
   - Should show `http://drone-server:8080/hook`

3. **`.drone.yml` exists?**
   ```powershell
   # Check if file exists in repo
   git ls-files | Select-String drone
   ```

4. **Check Drone logs:**
   ```powershell
   docker compose logs drone-server | Select-String -Pattern "hook|webhook"
   ```

#### Build Fails Immediately

**Symptoms:** Build shows "failure" within seconds.

**Check runner logs:**
```powershell
docker compose logs drone-runner
```

**Common causes:**

1. **Docker socket not accessible**
   ```
   Error: Cannot connect to the Docker daemon
   ```
   **Solution:** Verify Docker socket mount:
   ```powershell
   docker compose exec drone-runner ls -la /var/run/docker.sock
   ```

2. **Image pull failed**
   ```
   Error: pull access denied
   ```
   **Solution:** Check image name in `.drone.yml` or login to registry.

---

### SonarQube Issues

#### SonarQube Won't Start

**Symptoms:** Container keeps restarting.

**Most common cause:** Insufficient `vm.max_map_count`

**Solution (Windows with WSL2):**
```powershell
wsl -d docker-desktop
sysctl -w vm.max_map_count=262144
exit
docker compose restart sonarqube
```

**Make permanent:**
```powershell
wsl -d docker-desktop
echo "vm.max_map_count=262144" >> /etc/sysctl.conf
exit
```

#### SonarQube Out of Memory

**Symptoms:**
```
java.lang.OutOfMemoryError: Java heap space
```

**Solution:** Increase memory in `docker-compose.yml`:
```yaml
sonarqube:
  environment:
    - SONAR_WEB_JAVAOPTS=-Xmx2g -Xms1g
    - SONAR_CE_JAVAOPTS=-Xmx2g -Xms1g
```

#### SonarQube Database Error

**Symptoms:**
```
Unable to connect to database
```

**Solution:**
```powershell
# Check if SonarQube database is running
docker compose logs sonarqube-db

# Restart database
docker compose restart sonarqube-db
sleep 30
docker compose restart sonarqube
```

---

### Dependency-Track Issues

#### D-Track API Not Responding

**Symptoms:** 502 Bad Gateway or connection refused.

**Check:**
```powershell
docker compose logs dependency-track-api
```

**Common cause:** Not enough memory (needs 4GB+ for API server).

**Solution:**
```yaml
dependency-track-api:
  environment:
    - JAVA_OPTIONS=-Xmx4g -Xms2g
```

#### D-Track Frontend 404

**Symptoms:** Can access API but UI shows 404.

**Check:**
```powershell
docker compose logs dependency-track-frontend
```

**Solution:** Ensure frontend is connected to API:
```yaml
dependency-track-frontend:
  environment:
    - API_BASE_URL=http://dependency-track-api:8080
```

---

### Trivy Issues

#### Trivy Scan Times Out

**Symptoms:** Scan hangs or times out.

**Common cause:** First scan downloads vulnerability database.

**Solution:** Pre-download database:
```powershell
docker compose exec trivy trivy image --download-db-only
```

#### Trivy Server Not Responding

**Check:**
```powershell
curl http://localhost:4954/healthz
docker compose logs trivy
```

**Solution:**
```powershell
docker compose restart trivy
```

---

### Docker Registry Issues

#### Push to Registry Fails

**Symptoms:**
```
Error: server gave HTTP response to HTTPS client
```

**Solution:** Add insecure registry to Docker Desktop:

1. Docker Desktop → Settings → Docker Engine
2. Add:
   ```json
   {
     "insecure-registries": ["localhost:5000"]
   }
   ```
3. Apply & Restart

#### Registry Out of Space

**Symptoms:** Push fails with "no space left on device"

**Solution:** Clean up old images:
```powershell
# List images
curl http://localhost:5000/v2/_catalog

# Delete old tags (requires registry garbage collection)
docker compose exec registry bin/registry garbage-collect /etc/docker/registry/config.yml
```

---

## MCP Server Issues

### MCP Server Not Loading in Claude Code

**Symptoms:** Tools not available in Claude Code.

**Checklist:**

1. **Check configuration file:**
   ```powershell
   # Windows
   cat $env:APPDATA\Claude\claude_desktop_config.json

   # Or
   cat "$env:USERPROFILE\.claude\settings.json"
   ```

2. **Verify path is correct:**
   - Path should point to `mcp-server/dist/index.js`
   - Ensure forward slashes or escaped backslashes

3. **Check if built:**
   ```powershell
   ls mcp-server/dist/index.js
   # If not found:
   cd mcp-server && npm run build
   ```

4. **Restart Claude Code** after configuration changes.

### MCP Tools Return Errors

**Symptoms:** Tool calls fail with errors.

**Check environment variables:**
```powershell
# Ensure these are set in Claude config
$env:GITEA_URL
$env:DRONE_TOKEN
$env:DTRACK_API_KEY
```

**Test manually:**
```powershell
cd mcp-server
node dist/index.js
# Should output: CI/CD Security MCP Server running on stdio
```

---

## CI/CD Agent Issues

### Agent Can't Connect to Anthropic API

**Symptoms:**
```
Error: Invalid API key
```

**Solution:**
```powershell
# Set API key
$env:ANTHROPIC_API_KEY = "sk-ant-api03-..."

# Verify
echo $env:ANTHROPIC_API_KEY
```

### Agent Platform Status Shows Unreachable

**Symptoms:** All services show "unreachable"

**Check:**
1. Are Docker containers running?
   ```powershell
   docker compose ps
   ```

2. Can you reach services directly?
   ```powershell
   curl http://localhost:3000/api/healthz
   ```

3. Check `.env` file has correct URLs.

---

## Build Issues

### Build Can't Find Docker

**Symptoms in Drone:**
```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock
```

**Solution:** Ensure Docker socket is mounted in runner:
```yaml
drone-runner:
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
```

### Build Can't Pull Images

**Symptoms:**
```
Error: pull access denied for private-image
```

**Solutions:**

1. **For private registries:**
   ```yaml
   steps:
     - name: build
       image: plugins/docker
       settings:
         registry: localhost:5000
         insecure: true  # For local registry
   ```

2. **For Docker Hub rate limits:**
   Create Docker Hub credentials in Drone secrets.

### Build Succeeds but Image Not in Registry

**Check:**
```powershell
curl http://localhost:5000/v2/_catalog
```

**Common causes:**
- Wrong registry URL in `.drone.yml`
- Missing `insecure: true` for local registry
- Build step didn't push

---

## Network Issues

### Services Can't Communicate

**Symptoms:** "Connection refused" between services.

**Check network:**
```powershell
docker network inspect ci-co_ci-cd-network
```

**Verify containers are on same network:**
```powershell
docker compose exec gitea ping drone-server
```

**Solution:** Ensure all services use the same network:
```yaml
services:
  myservice:
    networks:
      - ci-cd-network
```

### Host Can't Access Services

**Symptoms:** "Connection refused" from host machine.

**Check port bindings:**
```powershell
docker compose ps
# Verify ports show as "0.0.0.0:3000->3000/tcp"
```

**Common cause:** Port bound to wrong interface.

**Solution:** Use `0.0.0.0` in port mapping:
```yaml
ports:
  - "0.0.0.0:3000:3000"
```

---

## Performance Issues

### Services Running Slow

**Diagnose:**
```powershell
docker stats
```

**Solutions:**

1. **Increase Docker resources:**
   - Docker Desktop → Settings → Resources
   - Allocate more CPU/Memory

2. **Disable unused services:**
   ```powershell
   docker compose stop sonarqube dependency-track-api
   ```

3. **Use minimal profile:**
   ```powershell
   docker compose -f docker-compose.yml -f docker-compose.minimal.yml up -d
   ```

### Scans Taking Too Long

**Trivy:**
- Pre-download database: `trivy image --download-db-only`
- Use server mode: Already configured in compose

**SonarQube:**
- Increase compute engine memory
- Reduce analysis scope in `sonar-project.properties`

---

## Data Recovery

### Corrupted Volume

**Symptoms:** Service won't start, data errors.

**Recovery steps:**

1. **Stop services:**
   ```powershell
   docker compose down
   ```

2. **Identify corrupted volume:**
   ```powershell
   docker volume ls
   ```

3. **Restore from backup:**
   ```powershell
   .\scripts\restore.ps1 -BackupPath "C:\Backups\cicd-latest"
   ```

4. **If no backup, recreate volume:**
   ```powershell
   docker volume rm ci-co_gitea-data
   docker compose up -d
   ```

### Lost Admin Password

**Gitea:**
```powershell
docker compose exec gitea gitea admin user change-password --username localadmin --password newpassword123
```

**SonarQube:**
```powershell
docker compose exec sonarqube-db psql -U sonar -c "UPDATE users SET crypted_password='$2a$12$uCkkXmhW5ThVK8mpBvnXOOJRLd64LJeHTeCkSuB3lfaR2N0AYBaSi', salt=null WHERE login='admin';"
# Sets password to "admin"
docker compose restart sonarqube
```

**Dependency-Track:**
```powershell
# Reset via API or recreate volume
docker volume rm ci-co_dtrack-data
docker compose up -d dependency-track-api
```

---

## Getting Help

### Collect Diagnostic Information

```powershell
# Create diagnostic bundle
$DiagDir = "cicd-diag-$(Get-Date -Format 'yyyyMMddHHmmss')"
New-Item -ItemType Directory -Path $DiagDir

# Collect info
docker compose ps > "$DiagDir\containers.txt"
docker compose logs > "$DiagDir\logs.txt" 2>&1
docker stats --no-stream > "$DiagDir\stats.txt"
docker version > "$DiagDir\docker-version.txt"
```

### Where to Get Help

1. **GitHub Issues:** https://github.com/KennethEhmsen/ci-co/issues
2. **Check existing issues** for similar problems
3. **Include diagnostic bundle** when reporting issues

### Useful Commands Reference

| Issue | Command |
|-------|---------|
| View all logs | `docker compose logs` |
| Restart everything | `docker compose restart` |
| Fresh start (keeps data) | `docker compose down && docker compose up -d` |
| Nuclear option | `docker compose down -v && docker compose up -d` |
| Check resources | `docker stats` |
| Network issues | `docker network inspect ci-co_ci-cd-network` |
