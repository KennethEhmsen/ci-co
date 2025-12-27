# Milestone: v1.21.0

**Due Date:** April 30, 2025

## Features
- Compliance reporting (SOC2, HIPAA, PCI-DSS, CIS benchmarks)
- Security policy as code with OPA/Rego integration
- Vulnerability database caching with offline mode
- Container image signing verification (Cosign/Notary)

## Improvements
- Redis-backed caching for scan results
- Parallel scanning performance optimizations
- Enhanced webhook retry logic with exponential backoff
- CLI interactive mode for guided scanning

## Developer Experience
- VS Code extension for inline vulnerability display
- Pre-commit hooks for security scanning
- GitHub Actions marketplace action
- Improved error messages and troubleshooting guides

---

## Proposed Issues

### Issue #15: Compliance Reporting
Generate compliance reports for common frameworks (SOC2, HIPAA, PCI-DSS, CIS).
- Map vulnerabilities to compliance controls
- Generate audit-ready PDF/HTML reports
- Track compliance trends over time

### Issue #16: Policy as Code (OPA/Rego)
Define security policies using OPA/Rego for custom enforcement.
- Custom policy rules for vulnerability thresholds
- License compliance policies
- Container configuration policies

### Issue #17: Offline Vulnerability Database
Cache vulnerability databases for air-gapped environments.
- Download and cache NVD/OSV databases
- Offline scanning mode
- Database update scheduling

### Issue #18: Container Image Signing Verification
Verify container image signatures before scanning.
- Cosign signature verification
- Notary v2 support
- Policy enforcement for unsigned images

### Issue #19: Redis Caching Backend
Use Redis for distributed scan result caching.
- Shared cache across multiple instances
- Configurable TTL per scan type
- Cache invalidation API

### Issue #20: GitHub Actions Marketplace Action
Publish official GitHub Action for CI/CD integration.
- Easy YAML configuration
- SARIF upload integration
- PR comments with scan summaries
