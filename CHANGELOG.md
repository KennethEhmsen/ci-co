# Changelog

All notable changes to the CI/CD Security Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Root workspace configuration with npm workspaces
- ESLint and Prettier for code quality
- Shared TypeScript type definitions for all API responses

### Fixed
- ESLint errors in test files (unused variables)

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

[Unreleased]: https://github.com/KennethEhmsen/ci-co/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/KennethEhmsen/ci-co/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/KennethEhmsen/ci-co/releases/tag/v1.0.0
