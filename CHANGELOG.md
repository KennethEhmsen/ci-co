# Changelog

All notable changes to the CI/CD Security Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Trivy Server API** - Image-based Trivy functions now use the Trivy server API (`--server` flag) instead of local database sync:
  - `trivy_scan_image`
  - `trivy_generate_sbom_image`
  - `trivy_scan_secrets_image`
  - `trivy_scan_licenses_image`
  - Benefits: Faster scans, reduced bandwidth, centralized vulnerability database management
  - Path-based scans continue to use local Docker execution

## [1.16.0] - 2025-12-26

### Added

#### Developer Experience (Phase 4)
- **Configuration File Support**
  - Load settings from `.cicd-agent.yaml` or `.cicd-agent.json`
  - Platform URL overrides, default repository context
  - Simple YAML parser with nested object support
- **Multiple Output Formats**
  - JSON, table, markdown, and text output formats
  - `--format` flag for CLI output control
  - `--quiet` mode for scripting and automation
- **Formatter Module**
  - `setGlobalFormat()` and `setGlobalQuiet()` for programmatic control
  - `formatOutput()` with format-aware rendering
  - `log()` respects quiet mode

#### API Tools (Phase 2)
- **Pull Request Management**
  - `gitea_list_pull_requests` - List PRs with state filtering
  - `gitea_get_pull_request` - Get PR details by number
  - `gitea_create_pull_request` - Create new PRs
  - `gitea_merge_pull_request` - Merge PRs with strategy options
- **Issue Management**
  - `gitea_create_issue` - Create issues with labels and assignees
  - `gitea_list_issues` - List issues with state filtering
- **SBOM Generation**
  - `trivy_generate_sbom` - Generate SBOM for local paths
  - `trivy_generate_sbom_image` - Generate SBOM for container images
- **Quality Gates**
  - `sonar_get_quality_gate_status` - Check SonarQube quality gate status
- **Policy-Based Gating**
  - `evaluatePolicy()` - Evaluate scan results against security policies
  - Built-in policies: strict, standard, permissive
  - Configurable severity thresholds and license restrictions

#### Resilience & Performance (Phase 3)
- **Scan Result Caching**
  - `ScanCache` class with TTL-based expiration
  - `withCache()` decorator for async functions
  - Pre-configured caches for Trivy, SonarQube, Dependency-Track
- **Circuit Breaker Pattern**
  - `CircuitBreaker` class with CLOSED/OPEN/HALF_OPEN states
  - Automatic failure detection and recovery
  - Pre-configured breakers for all external services
- **Rate Limiting**
  - `RateLimiter` with token bucket algorithm
  - `QueuedRateLimiter` for request queuing
  - Service-specific rate limits (Trivy: 10/min, Gitea/Drone: 60/min)

#### Security & Compliance (Phase 1)
- **Audit Logging**
  - `AuditLogger` with structured log entries
  - `auditOperation()` for tracking tool executions
  - `auditSecurityEvent()` for security-relevant events
  - `getFailedOperations()` and `getSecurityEvents()` queries
- **Configuration Validation**
  - `validateConfig()` - Validate URL formats and credentials
  - `validateConnectivity()` - Check service reachability
  - `validateStartup()` - Full startup validation with health checks
  - `logValidationResults()` - Formatted validation output

### Changed
- Tool count increased to 41 (8 new tools)
- Test count: 538 tests across all packages
- Coverage: shared 84.2%, cicd-agent 65.82%

## [1.15.0] - 2025-12-25

### Added
- **SBOM Format Option** for combined scans
  - `trivy_scan_image_full` accepts `sbomFormat` parameter (cyclonedx or spdx-json)
  - `trivy_scan_path_full` accepts `sbomFormat` parameter (cyclonedx or spdx-json)
  - Default format is CycloneDX for backwards compatibility

## [1.14.0] - 2025-12-25

### Added
- **SBOM Generation** in combined scans
  - `trivy_scan_image_full` now includes SBOM (4 operations: vuln, secret, license, SBOM)
  - `trivy_scan_path_full` now includes SBOM (5 operations: vuln, secret, license, IaC, SBOM)

## [1.13.2] - 2025-12-25

### Fixed
- **Drone CI Pipeline** - Fixed build failures with multiple improvements:
  - Skip Husky prepare script in CI with `--ignore-scripts` flag
  - Switch from `node:20-alpine` to `node:20` for glibc compatibility with Rollup native bindings
  - Delete `package-lock.json` before install to ensure platform-native dependencies

## [1.13.1] - 2025-12-25

### Fixed
- Platform status health check now uses public endpoints for Drone (`/healthz`) and SonarQube (`/api/system/status`) to avoid authentication errors

## [1.13.0] - 2025-12-25

### Added
- **Combined Path Scan Tool** (`trivy_scan_path_full`)
  - Runs vulnerability, secret, license, IaC, and SBOM generation in one operation
  - Returns comprehensive results with individual error handling
- **SBOM Generation** in combined scans
  - `trivy_scan_image_full` now includes SBOM (4 operations: vuln, secret, license, SBOM)
  - `trivy_scan_path_full` now includes SBOM (5 operations: vuln, secret, license, IaC, SBOM)
- **SBOM Format Option** for combined scans
  - `trivy_scan_image_full` accepts `sbomFormat` parameter (cyclonedx or spdx-json)
  - `trivy_scan_path_full` accepts `sbomFormat` parameter (cyclonedx or spdx-json)
  - Default format is CycloneDX for backwards compatibility
- **CI Workflow SBOM Generation**
  - Generates CycloneDX and SPDX-JSON SBOMs in security job
  - Uploads both formats as artifacts with 90-day retention
- Tool count: 33

## [1.12.0] - 2025-12-25

### Added
- **Combined Image Scan Tool** (`trivy_scan_image_full`)
  - Runs vulnerability, secret, and license scanning in one operation
  - Returns combined results with timestamp and individual error handling
  - Tool count: 32

## [1.11.0] - 2025-12-25

### Added
- **Secret Scanning for Container Images** (`trivy_scan_secrets_image`)
  - Detects hardcoded secrets in Docker images
  - Supports custom severity filtering
  - Tool count: 31

## [1.10.0] - 2025-12-25

### Added
- **License Scanning for Container Images** (`trivy_scan_licenses_image`)
  - Detects licenses in Docker image dependencies
  - Flags problematic licenses (GPL, copyleft, etc.)
  - Tool count: 30

## [1.9.0] - 2025-12-25

### Added
- **License Scanning Tool** (`trivy_scan_licenses`)
  - Scans local paths for license information
  - Detects and categorizes dependency licenses
  - Tool count: 29

## [1.8.0] - 2025-12-25

### Added
- **Secret Scanning Tool** (`trivy_scan_secrets`)
  - Scans local paths for hardcoded secrets
  - Detects API keys, passwords, tokens, private keys
  - Tool count: 28

## [1.7.0] - 2025-12-25

### Added
- **IaC Scanning Tool** (`trivy_scan_iac`)
  - Scans Infrastructure as Code files for misconfigurations
  - Supports Terraform, Kubernetes, Docker, CloudFormation, and more
  - Tool count: 27

## [1.6.0] - 2025-12-25

### Added
- **SBOM Generation Tools**
  - `trivy_generate_sbom` - Generate SBOM for local paths
  - `trivy_generate_sbom_image` - Generate SBOM for Docker images
  - Supports CycloneDX and SPDX-JSON formats
  - Tool count: 26

## [1.5.1] - 2025-12-25

### Fixed
- Commitlint config converted to CommonJS format (eliminates Node.js module warning)

## [1.5.0] - 2025-12-25

### Added
- Semantic-release for automated versioning and releases
- Commitlint for conventional commit message validation
- Commit-msg hook to enforce conventional commits
- Automated CI release job (runs after all checks pass)

### Changed
- Releases are now fully automated based on conventional commits

## [1.4.1] - 2025-12-25

### Added
- Pre-commit hooks with Husky and lint-staged (auto-fix ESLint and Prettier)

## [1.4.0] - 2025-12-25

### Added
- Branch protection rules for GitHub (required CI checks, PR reviews)
- Branch protection rules for Gitea (push whitelist, stale review dismissal)
- CI Security Features section in README

## [1.3.4] - 2025-12-25

### Added
- Dependency caching in CI to speed up builds

## [1.3.3] - 2025-12-25

### Added
- Code coverage thresholds in CI (fails if coverage drops below configured minimums)

## [1.3.2] - 2025-12-25

### Added
- License compliance check in CI (fails on non-permissive licenses like GPL)

## [1.3.1] - 2025-12-25

### Added
- npm audit check in CI security job (fails on HIGH severity vulnerabilities)

## [1.3.0] - 2025-12-25

### Added
- **Trivy Security Scanning in CI** - Automated vulnerability, secret, and misconfiguration scanning
- **GitHub Security Integration** - SARIF results uploaded to GitHub Security tab
- **Security Badge** - Added security scan badge to README

## [1.2.2] - 2025-12-25

### Fixed
- Replaced all 109 explicit `any` types with proper TypeScript types
- Added generic type parameter to `fetchJson<T>()` for type-safe API responses
- Added typed return values for all handler functions
- Fixed `AuthHeaders` type compatibility with `HeadersInit`
- Fixed exec mock type casting for stricter TypeScript checks in tests

## [1.2.1] - 2025-12-25

### Fixed
- CI workflow now uses npm workspaces correctly
- Build order fixed: shared library builds first before dependent packages
- Removed `prepare` scripts that caused parallel build issues
- Cross-platform compatibility for rollup native bindings in CI

## [1.2.0] - 2025-12-25

### Added
- **Complete Documentation Suite**
  - `docs/API.md` - Full API reference for all 23 tools with input schemas and examples
  - `docs/CLI.md` - CI/CD Agent command-line reference
  - `docs/DEVELOPER.md` - Developer guide with extension patterns
  - `docs/ADMIN.md` - Administrator operations guide (deployment, monitoring, backup, scaling)
  - `docs/TROUBLESHOOTING.md` - Comprehensive troubleshooting for all services
- **Software Architecture** - Added software components section to `ARCHITECTURE.md`
- **Shared Types** - TypeScript interfaces for configuration, errors, and API responses
- **JSDoc Documentation** - Complete JSDoc comments for all public APIs
- Root workspace configuration with npm workspaces
- ESLint and Prettier for code quality

### Changed
- Updated `README.md` with comprehensive documentation links
- Aligned `@types/node` version to `^20.10.0` across all packages
- Enhanced `mcp-server/README.md` with development and architecture sections

### Fixed
- ESLint errors in test files (unused variables)
- Fixed placeholder email in `SECURITY.md`

## [1.1.0] - 2024-12-20

### Added
- Claude Code auto-installer script (`scripts/install-claude.ps1`)
- Claude Code uninstaller script (`scripts/uninstall-claude.ps1`)
- GitHub Actions CI/CD workflow for automated testing
- Contributing guidelines (`CONTRIBUTING.md`)
- Security policy with vulnerability reporting (`SECURITY.md`)
- Issue templates for bug reports
- Dependabot configuration for automated dependency updates
- MIT License

### Changed
- Updated README with Claude Code integration instructions
- Added build and coverage badges

## [1.0.0] - 2024-12-15

### Added
- Initial release of CI/CD Security Platform
- **MCP Server** for Claude Code integration
  - 23 security and DevOps tools
  - Platform configuration resource
  - Platform status resource
- **CI/CD Agent** with Anthropic SDK integration
  - Interactive CLI chat interface
  - Agentic tool execution loop
  - All security scanning tools
- **Shared Library** (`@cicd/shared`)
  - Common handlers for all integrations
  - Configuration management
  - Input validation and sanitization
  - HTTP utilities

### Security Tools
- **Trivy Integration**
  - File system vulnerability scanning
  - Docker image scanning
  - Secret detection
- **SonarQube Integration**
  - Project listing
  - Issue and vulnerability retrieval
  - Security hotspots
  - Quality metrics
- **Dependency-Track Integration**
  - Project management
  - Vulnerability tracking
  - Component analysis
  - Security findings

### DevOps Tools
- **Gitea Integration**
  - Repository listing and details
  - Branch management
  - Commit history
  - Repository creation
  - GitHub migration
- **Drone CI Integration**
  - Repository sync
  - Build history and details
  - Build logs
  - Build triggering
- **Docker Registry Integration**
  - Image catalog
  - Tag listing

### Infrastructure
- Docker Compose configuration for local deployment
- Pre-configured services:
  - Gitea (Git hosting)
  - Drone CI (CI/CD)
  - SonarQube (SAST)
  - Dependency-Track (SCA)
  - Trivy Server (vulnerability scanning)
  - Docker Registry (container storage)
  - PostgreSQL databases

### Documentation
- Comprehensive README with quick start guide
- Architecture documentation with diagrams
- Installation guide with troubleshooting
- Configuration reference
- Usage examples for multiple languages
- Security scanning guide

[Unreleased]: https://github.com/KennethEhmsen/ci-co/compare/v1.16.0...HEAD
[1.16.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.15.0...v1.16.0
[1.15.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.14.0...v1.15.0
[1.14.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.13.2...v1.14.0
[1.13.2]: https://github.com/KennethEhmsen/ci-co/compare/v1.13.1...v1.13.2
[1.13.1]: https://github.com/KennethEhmsen/ci-co/compare/v1.13.0...v1.13.1
[1.13.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.5.1...v1.6.0
[1.5.1]: https://github.com/KennethEhmsen/ci-co/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.4.1...v1.5.0
[1.4.1]: https://github.com/KennethEhmsen/ci-co/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.3.4...v1.4.0
[1.3.4]: https://github.com/KennethEhmsen/ci-co/compare/v1.3.3...v1.3.4
[1.3.3]: https://github.com/KennethEhmsen/ci-co/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/KennethEhmsen/ci-co/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/KennethEhmsen/ci-co/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.2.2...v1.3.0
[1.2.2]: https://github.com/KennethEhmsen/ci-co/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/KennethEhmsen/ci-co/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/KennethEhmsen/ci-co/releases/tag/v1.0.0
