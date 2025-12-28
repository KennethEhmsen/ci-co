# Milestone: v1.22.0

**Release Date:** December 28, 2024

## Summary

Version 1.22.0 introduces **2 major feature areas** with **6 new MCP tools**, bringing the platform total to **82 tools** across **14 functional categories**. This release focuses on performance optimization with distributed caching and GitHub Marketplace integration.

## Features Implemented

### Issue #19: Redis Caching Backend (6 tools)
Distributed caching with Redis backend and automatic in-memory fallback.
- **Hybrid architecture:** Redis for distributed deployments, memory for single-node
- **Configurable TTL:** Per scan type (trivy: 5m, sonarqube: 10m, dtrack: 10m, registry: 30m)
- **Pattern-based invalidation:** Granular cache control
- **Cache statistics:** Hit/miss rates and performance metrics

**Tools:** `cache_init`, `cache_status`, `cache_stats`, `cache_clear`, `cache_invalidate`, `cache_config`

**Environment Variables:**
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `REDIS_DB`
- `REDIS_KEY_PREFIX`, `REDIS_CONNECT_TIMEOUT`
- `CACHE_TTL_TRIVY`, `CACHE_TTL_SONARQUBE`, `CACHE_TTL_DTRACK`, `CACHE_TTL_REGISTRY`

### Issue #20: GitHub Actions Marketplace
Official GitHub Action for CI/CD security scanning integration.
- **SARIF upload:** Automatic upload to GitHub Code Scanning
- **PR comments:** Scan summary posted to pull requests
- **Badge generation:** Dynamic security status badges (SVG)
- **Configurable thresholds:** fail-on severity levels

**Action Features:**
- Path and container image scanning with Trivy
- 20+ configuration inputs
- 9 outputs (vulnerability counts, pass/fail status, badge URL)
- Private registry authentication support
- Suppression file support

**Usage:**
```yaml
- uses: your-org/cicd-security-scanner@v1
  with:
    scan-type: path
    severity: 'CRITICAL,HIGH'
    fail-on: 'CRITICAL'
    upload-sarif: 'true'
    comment-on-pr: 'true'
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Technical Highlights

- **ioredis** integration with dynamic ESM import (optional dependency)
- Graceful degradation: Automatic fallback when Redis unavailable
- Docker-based GitHub Action with Node 20 runtime
- Comprehensive test coverage: 18 new tests for redis-cache module

## Platform Statistics

| Metric | Value |
|--------|-------|
| Total MCP Tools | 82 |
| New Tools (v1.22.0) | 6 |
| Tool Categories | 14 |
| Tests Added | 18+ |

## Breaking Changes

None - fully backward compatible.

## Dependencies Added

| Package | Version | Purpose |
|---------|---------|---------|
| `ioredis` | ^5.4.2 | Redis client (optional) |
| `@actions/core` | ^1.10.1 | GitHub Actions toolkit |
| `@actions/github` | ^6.0.0 | GitHub API client |
| `@actions/exec` | ^1.1.1 | Process execution |

## Documentation

- [Features Documentation](./FEATURES.md) - Updated with cache section
- [Cheat Sheet](./CHEAT-SHEET.md) - Quick reference for all 82 tools
- [API Reference](./API.md) - Complete API documentation
- [GitHub Action README](./.github/actions/security-scan/README.md) - Action usage guide

## CI/CD

- Build passing on Drone CI
- SonarQube analysis complete
- Coverage thresholds met across all modules

## Upgrade Notes

1. **Redis caching (optional):**
   - Install ioredis: `npm install ioredis`
   - Configure environment variables for Redis connection
   - Call `cache_init` with `useRedis: true`

2. **GitHub Action:**
   - Add workflow file using the action
   - Configure required permissions: `contents: read`, `security-events: write`, `pull-requests: write`
