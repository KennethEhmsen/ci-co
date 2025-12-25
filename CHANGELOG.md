# Changelog

All notable changes to the CI/CD Security Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/KennethEhmsen/ci-co/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.2.2...v1.3.0
[1.2.2]: https://github.com/KennethEhmsen/ci-co/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/KennethEhmsen/ci-co/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/KennethEhmsen/ci-co/releases/tag/v1.0.0
