# Installation Guide - Local CI/CD Platform

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Step 1: Prepare Environment](#step-1-prepare-environment)
3. [Step 2: Configure Docker Desktop](#step-2-configure-docker-desktop)
4. [Step 3: Generate Secrets](#step-3-generate-secrets)
5. [Step 4: Start Core Services](#step-4-start-core-services)
6. [Step 5: Configure Gitea](#step-5-configure-gitea)
7. [Step 6: Create OAuth Application](#step-6-create-oauth-application)
8. [Step 7: Complete Drone Setup](#step-7-complete-drone-setup)
9. [Step 8: Verify Installation](#step-8-verify-installation)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software

| Software | Minimum Version | Download Link |
|----------|----------------|---------------|
| Docker Desktop | 4.0+ | https://www.docker.com/products/docker-desktop |
| Git | 2.30+ | https://git-scm.com/downloads |
| PowerShell | 5.1+ | Built into Windows |

### System Requirements

- **OS**: Windows 10/11 Pro or Enterprise (with WSL2)
- **RAM**: 8 GB minimum (16 GB recommended)
- **Disk**: 20 GB free space
- **CPU**: 4 cores minimum

### Verify Docker Desktop Installation

Open PowerShell and run:

```powershell
# Check Docker version
docker --version

# Check Docker Compose version
docker compose version

# Verify Docker is running
docker ps
```

Expected output:
```
Docker version 24.x.x, build xxxxxxx
Docker Compose version v2.x.x
CONTAINER ID   IMAGE   COMMAND   CREATED   STATUS   PORTS   NAMES
```

---

## Step 1: Prepare Environment

### 1.1 Create Project Directory

```powershell
# Navigate to your desired location
cd "C:\Users\keeh\OneDrive - Mansoft\Skrivebord\Mock Servers\ci-co"

# Verify files exist
Get-ChildItem
```

### 1.2 Create Environment File

```powershell
# Copy the example environment file
Copy-Item .env.example .env

# Open in notepad to edit
notepad .env
```

---

## Step 2: Configure Docker Desktop

### 2.1 Docker Desktop Settings

1. Open **Docker Desktop**
2. Go to **Settings** (gear icon)
3. Navigate to **Resources** > **Advanced**
4. Configure resources:
   - **CPUs**: 4 (or more)
   - **Memory**: 4 GB (or more)
   - **Swap**: 1 GB
   - **Disk image size**: 60 GB+

### 2.2 Enable WSL 2 Backend (Windows)

1. Go to **Settings** > **General**
2. Ensure **Use the WSL 2 based engine** is checked
3. Click **Apply & Restart**

### 2.3 Configure Docker for Insecure Registry

For the local registry to work without HTTPS:

1. Go to **Settings** > **Docker Engine**
2. Add the following to the JSON configuration:

```json
{
  "insecure-registries": ["localhost:5000", "127.0.0.1:5000"]
}
```

3. Click **Apply & Restart**

---

## Step 3: Generate Secrets

### 3.1 Generate Required Secrets

Open PowerShell and run:

```powershell
# Generate PostgreSQL password
$POSTGRES_PASSWORD = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
Write-Host "POSTGRES_PASSWORD=$POSTGRES_PASSWORD"

# Generate Gitea secret key
$GITEA_SECRET = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 64 | ForEach-Object {[char]$_})
Write-Host "GITEA_SECRET_KEY=$GITEA_SECRET"

# Generate Drone RPC secret
$DRONE_RPC = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
Write-Host "DRONE_RPC_SECRET=$DRONE_RPC"
```

### 3.2 Update .env File

Edit the `.env` file with the generated values:

```powershell
notepad .env
```

Update these values (leave DRONE_GITEA_CLIENT_ID and DRONE_GITEA_CLIENT_SECRET empty for now):

```env
POSTGRES_PASSWORD=<your_generated_postgres_password>
GITEA_SECRET_KEY=<your_generated_gitea_secret>
DRONE_RPC_SECRET=<your_generated_drone_rpc_secret>
DRONE_GITEA_CLIENT_ID=
DRONE_GITEA_CLIENT_SECRET=
DRONE_ADMIN_USER=admin
```

---

## Step 4: Start Core Services

### 4.1 Start Gitea and Database First

```powershell
# Navigate to the project directory
cd "C:\Users\keeh\OneDrive - Mansoft\Skrivebord\Mock Servers\ci-co"

# Start only Gitea and PostgreSQL first
docker compose up -d postgres gitea registry registry-ui

# Wait for services to be healthy
docker compose ps

# View logs if needed
docker compose logs -f gitea
```

### 4.2 Verify Gitea is Running

Open your browser and navigate to: **http://localhost:3000**

You should see the Gitea initial configuration page.

---

## Step 5: Configure Gitea

### 5.1 Initial Setup

When you first access http://localhost:3000, you'll see the installation page.

**Database Settings** (should be pre-filled):
- Database Type: `PostgreSQL`
- Host: `postgres:5432`
- Username: `gitea`
- Password: *(your POSTGRES_PASSWORD)*
- Database Name: `gitea`

**General Settings**:
- Site Title: `Local CI/CD`
- Repository Root Path: `/data/git/repositories`
- Git LFS Root Path: `/data/git/lfs`
- Run As Username: `git`
- SSH Server Domain: `localhost`
- SSH Server Port: `2222`
- Gitea HTTP Listen Port: `3000`
- Gitea Base URL: `http://localhost:3000/`

**Optional Settings**:
- Enable Local Mode
- Disable Gravatar
- Enable Open ID Sign-In (optional)

### 5.2 Create Administrator Account

On the same page, scroll down to **Administrator Account Settings**:

- Administrator Username: `admin` (or your preferred username)
- Password: `<strong_password>`
- Confirm Password: `<strong_password>`
- Email Address: `admin@localhost.local`

Click **Install Gitea**

### 5.3 Verify Admin Login

1. Click **Sign In**
2. Enter your admin credentials
3. Verify you can access the dashboard

---

## Step 6: Create OAuth Application

### 6.1 Create OAuth App for Drone

1. Log into Gitea as admin
2. Click your profile icon (top right) → **Settings**
3. Go to **Applications** tab
4. Under **Manage OAuth2 Applications**, click **Create a new OAuth2 Application**

Fill in:
- **Application Name**: `Drone CI`
- **Redirect URIs**: `http://localhost:8080/login`

Click **Create Application**

### 6.2 Save OAuth Credentials

**IMPORTANT**: Copy the **Client ID** and **Client Secret** immediately. The secret is only shown once!

```
Client ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Client Secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### 6.3 Update .env File

```powershell
notepad .env
```

Add the OAuth credentials:

```env
DRONE_GITEA_CLIENT_ID=<your_client_id>
DRONE_GITEA_CLIENT_SECRET=<your_client_secret>
DRONE_ADMIN_USER=admin
```

---

## Step 7: Complete Drone Setup

### 7.1 Start Drone Services

```powershell
# Stop current services
docker compose down

# Start all services
docker compose up -d

# Verify all services are running
docker compose ps
```

Expected output:
```
NAME                IMAGE                           STATUS          PORTS
ci-drone-runner     drone/drone-runner-docker:1     Up
ci-drone-server     drone/drone:2                   Up              0.0.0.0:8080->80/tcp
ci-gitea            gitea/gitea:latest              Up (healthy)    0.0.0.0:2222->22/tcp, 0.0.0.0:3000->3000/tcp
ci-postgres         postgres:15-alpine              Up (healthy)    5432/tcp
ci-registry         registry:2                      Up              0.0.0.0:5000->5000/tcp
ci-registry-ui      joxit/docker-registry-ui:latest Up              0.0.0.0:5001->80/tcp
```

### 7.2 Authenticate Drone with Gitea

1. Open **http://localhost:8080** in your browser
2. Click **Continue** to authenticate with Gitea
3. You'll be redirected to Gitea's authorization page
4. Click **Authorize Application**
5. You'll be redirected back to Drone CI dashboard

### 7.3 Activate Your First Repository

1. In Drone, click **Sync** to fetch repositories from Gitea
2. Find a repository and click **Activate**
3. Configure repository settings as needed

---

## Step 8: Verify Installation

### 8.1 Check All Services

Run the verification script:

```powershell
# Check service status
docker compose ps

# Check service health
docker compose exec gitea curl -s http://localhost:3000/api/healthz
docker compose exec drone-server wget -qO- http://localhost/healthz

# Check registry
curl http://localhost:5000/v2/_catalog
```

### 8.2 Service URLs

| Service | URL | Purpose |
|---------|-----|---------|
| Gitea | http://localhost:3000 | Git repository management |
| Drone CI | http://localhost:8080 | CI/CD pipelines |
| Registry | http://localhost:5000 | Docker image storage |
| Registry UI | http://localhost:5001 | Browse stored images |

### 8.3 Test Docker Registry

```powershell
# Pull a test image
docker pull hello-world

# Tag it for local registry
docker tag hello-world localhost:5000/hello-world:latest

# Push to local registry
docker push localhost:5000/hello-world:latest

# Verify it's in the registry
curl http://localhost:5000/v2/_catalog
```

Expected output:
```json
{"repositories":["hello-world"]}
```

---

## Troubleshooting

### Common Issues

#### Issue: Gitea can't connect to PostgreSQL

```powershell
# Check PostgreSQL logs
docker compose logs postgres

# Verify PostgreSQL is healthy
docker compose exec postgres pg_isready -U gitea
```

#### Issue: Drone can't connect to Gitea

```powershell
# Check Drone server logs
docker compose logs drone-server

# Verify Gitea is accessible from Drone container
docker compose exec drone-server wget -qO- http://gitea:3000/api/healthz
```

#### Issue: Drone runner not connecting

```powershell
# Check runner logs
docker compose logs drone-runner

# Verify RPC secret matches
docker compose exec drone-runner env | grep DRONE_RPC
docker compose exec drone-server env | grep DRONE_RPC
```

#### Issue: Registry push fails with "server gave HTTP response to HTTPS client"

1. Ensure Docker Desktop has `localhost:5000` in insecure registries
2. Restart Docker Desktop after adding the insecure registry

#### Issue: Port already in use

```powershell
# Find what's using the port (e.g., 3000)
netstat -ano | findstr :3000

# Kill the process if needed
taskkill /PID <process_id> /F
```

### Reset Everything

To completely reset and start fresh:

```powershell
# Stop all services
docker compose down

# Remove all volumes (WARNING: This deletes all data!)
docker compose down -v

# Remove all images
docker compose down --rmi all

# Start fresh
docker compose up -d
```

### View Logs

```powershell
# All services
docker compose logs -f

# Specific service
docker compose logs -f gitea
docker compose logs -f drone-server
docker compose logs -f drone-runner
```

---

## Next Steps

After successful installation:

1. Read the [CONFIGURATION.md](CONFIGURATION.md) for advanced setup
2. Read the [USAGE.md](USAGE.md) for workflows and examples
3. Create your first repository in Gitea
4. Add a `.drone.yml` to enable CI/CD
