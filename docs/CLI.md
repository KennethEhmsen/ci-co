# CLI Reference

The CI/CD Security Agent (`cicd-agent`) is a command-line interface powered by Claude that provides intelligent security scanning and DevOps automation.

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Commands](#commands)
  - [chat](#chat)
  - [scan](#scan)
  - [scan-image](#scan-image)
  - [status](#status)
  - [repos](#repos)
  - [builds](#builds)
  - [security-report](#security-report)
  - [migrate](#migrate)
  - [ask](#ask)
- [Interactive Mode](#interactive-mode)
- [Examples](#examples)
- [Environment Variables](#environment-variables)

---

## Installation

The CI/CD Agent is part of the monorepo. To install:

```bash
# From the repository root
npm install
npm run build

# Run the agent
cd cicd-agent
node dist/index.js
```

Or install globally (after building):

```bash
npm link
cicd-agent --help
```

---

## Configuration

The agent requires the `ANTHROPIC_API_KEY` environment variable:

```bash
# Linux/macOS
export ANTHROPIC_API_KEY="your-api-key"

# Windows PowerShell
$env:ANTHROPIC_API_KEY = "your-api-key"

# Windows Command Prompt
set ANTHROPIC_API_KEY=your-api-key
```

Additional environment variables for platform integration are loaded from `.env` file. See [Environment Variables](#environment-variables).

---

## Commands

### chat

Start an interactive chat session with the agent.

```bash
cicd-agent chat
```

**Description:** Opens an interactive REPL where you can have a conversation with the agent. The agent maintains conversation context across messages.

**Interactive Commands:**
- `exit` or `quit` - End the session
- `clear` - Reset the conversation history

**Example:**
```
$ cicd-agent chat

🔒 CI/CD Security Agent
========================
I can help you with:
  • Security scanning (Trivy, SonarQube, Dependency-Track)
  • Git repository management (Gitea)
  • CI/CD pipeline operations (Drone CI)
  • Docker registry management

📝 You: What repositories do we have?

🤖 Agent: Thinking...
🔧 Using tool: gitea_list_repos

🤖 Agent:
Here are the repositories in your Gitea instance:
1. **localadmin/my-app** - Main application repository
2. **localadmin/api-server** - Backend API service
...
```

---

### scan

Scan a directory for security vulnerabilities using Trivy.

```bash
cicd-agent scan <path> [options]
```

**Arguments:**
- `<path>` - Absolute path to the directory to scan

**Options:**
- `-s, --severity <levels>` - Severity levels to report (default: `HIGH,CRITICAL`)

**Example:**
```bash
# Scan current directory for high and critical vulnerabilities
cicd-agent scan /home/user/myproject

# Scan with all severity levels
cicd-agent scan /home/user/myproject --severity "LOW,MEDIUM,HIGH,CRITICAL"
```

**Output:** The agent analyzes Trivy results and provides:
- Summary of vulnerabilities found
- Breakdown by severity
- Affected dependencies
- Remediation recommendations

---

### scan-image

Scan a Docker image for vulnerabilities.

```bash
cicd-agent scan-image <image>
```

**Arguments:**
- `<image>` - Docker image to scan (e.g., `nginx:latest`, `localhost:5000/myapp:v1`)

**Example:**
```bash
# Scan an official image
cicd-agent scan-image nginx:1.25

# Scan a local registry image
cicd-agent scan-image localhost:5000/myapp:latest
```

---

### status

Check the health status of all CI/CD platform services.

```bash
cicd-agent status
```

**Output:** Reports the status of:
- Gitea (Git hosting)
- Drone CI (CI/CD)
- SonarQube (SAST)
- Dependency-Track (SCA)
- Trivy Server
- Docker Registry

---

### repos

List all repositories in Gitea.

```bash
cicd-agent repos
```

**Output:** Displays all repositories with:
- Repository name and owner
- Description
- Visibility (public/private)
- Clone URL
- Star and fork counts

---

### builds

Show recent CI/CD builds for a repository.

```bash
cicd-agent builds <owner> <repo>
```

**Arguments:**
- `<owner>` - Repository owner username
- `<repo>` - Repository name

**Example:**
```bash
cicd-agent builds localadmin my-app
```

**Output:** Displays build history with:
- Build number and status
- Trigger event (push, PR, etc.)
- Duration
- Failed steps (if any)
- Commit message

---

### security-report

Generate a comprehensive security report for a project.

```bash
cicd-agent security-report [path]
```

**Arguments:**
- `[path]` - Path to scan (optional, defaults to current directory)

**Example:**
```bash
# Report for current directory
cicd-agent security-report

# Report for specific path
cicd-agent security-report /home/user/myproject
```

**Output:** Comprehensive report including:
1. Trivy dependency vulnerabilities
2. SonarQube code issues (if project exists)
3. Dependency-Track findings (if project exists)
4. Executive summary with:
   - Total vulnerabilities by severity
   - Top 5 critical issues
   - Prioritized remediation recommendations

---

### migrate

Migrate a repository from GitHub to Gitea.

```bash
cicd-agent migrate <github-url> <repo-name> [options]
```

**Arguments:**
- `<github-url>` - GitHub clone URL (e.g., `https://github.com/user/repo.git`)
- `<repo-name>` - Name for the new repository in Gitea

**Options:**
- `-t, --token <token>` - GitHub personal access token (required for private repos)

**Example:**
```bash
# Migrate a public repository
cicd-agent migrate https://github.com/facebook/react.git react-mirror

# Migrate a private repository
cicd-agent migrate https://github.com/myorg/private-repo.git private-repo --token ghp_xxxx
```

**Output:** After migration, displays:
- New repository URL in Gitea
- Migration status (issues, PRs, releases)
- Next steps for setting up CI/CD

---

### ask

Ask a single question and get a response.

```bash
cicd-agent ask <question...>
```

**Arguments:**
- `<question...>` - Your question (multiple words supported)

**Example:**
```bash
cicd-agent ask How do I set up a CI pipeline for a Node.js project?

cicd-agent ask "What are the security best practices for Docker images?"
```

---

## Interactive Mode

Running `cicd-agent` without any command starts interactive mode (same as `cicd-agent chat`).

### Conversation Features

The agent maintains conversation context, allowing for follow-up questions:

```
📝 You: Scan my project at /home/user/app

🤖 Agent: I found 3 high severity vulnerabilities...

📝 You: Tell me more about the first one

🤖 Agent: The first vulnerability is CVE-2024-1234...

📝 You: How do I fix it?

🤖 Agent: To fix this vulnerability, update lodash to version 4.17.21...
```

### Clearing Context

Use the `clear` command to reset the conversation:

```
📝 You: clear

🔄 Conversation cleared.
```

---

## Examples

### Security Workflow

```bash
# 1. Check platform is running
cicd-agent status

# 2. Scan your project
cicd-agent scan /path/to/project

# 3. Generate full security report
cicd-agent security-report /path/to/project
```

### CI/CD Workflow

```bash
# 1. List repositories
cicd-agent repos

# 2. Check recent builds
cicd-agent builds localadmin my-app

# 3. Interactive troubleshooting
cicd-agent chat
> Why did build #42 fail?
> Show me the logs for the test step
```

### Migration Workflow

```bash
# Migrate from GitHub
cicd-agent migrate https://github.com/myorg/legacy-app.git legacy-app

# Then ask about setting up CI
cicd-agent ask How do I create a Drone pipeline for legacy-app?
```

---

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude | Yes |
| `GITEA_URL` | Gitea server URL | No (default: `http://localhost:3000`) |
| `GITEA_USER` | Gitea username | No (default: `localadmin`) |
| `GITEA_PASSWORD` | Gitea password | No (default: `admin123`) |
| `DRONE_URL` | Drone CI server URL | No (default: `http://localhost:8085`) |
| `DRONE_TOKEN` | Drone API token | No (required for triggering builds) |
| `SONARQUBE_URL` | SonarQube server URL | No (default: `http://localhost:9000`) |
| `SONARQUBE_USER` | SonarQube username | No (default: `admin`) |
| `SONARQUBE_PASSWORD` | SonarQube password | No (default: `admin`) |
| `DTRACK_URL` | Dependency-Track URL | No (default: `http://localhost:8082`) |
| `DTRACK_API_KEY` | Dependency-Track API key | No (required for D-Track features) |
| `REGISTRY_URL` | Docker registry URL | No (default: `http://localhost:5000`) |

### Example .env file

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-api03-xxxxx

# Optional - Platform URLs
GITEA_URL=http://localhost:3000
DRONE_URL=http://localhost:8085
SONARQUBE_URL=http://localhost:9000
DTRACK_URL=http://localhost:8082

# Optional - Credentials
GITEA_USER=localadmin
GITEA_PASSWORD=admin123
DRONE_TOKEN=your-drone-token
DTRACK_API_KEY=your-dtrack-api-key
```

---

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Error (API error, invalid input, etc.) |

---

## Troubleshooting

### "ANTHROPIC_API_KEY not set"

Ensure you have set the `ANTHROPIC_API_KEY` environment variable:

```bash
export ANTHROPIC_API_KEY="your-api-key"
```

### "Platform service unreachable"

Check that Docker containers are running:

```bash
docker compose ps
docker compose up -d
```

### "Invalid path provided"

Ensure you're using an absolute path:

```bash
# Correct
cicd-agent scan /home/user/project

# Incorrect
cicd-agent scan ./project
```

### Rate Limiting

If you see rate limiting errors, wait a moment and try again. The agent uses Claude's API which has rate limits.
