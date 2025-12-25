# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security vulnerabilities by emailing:

**security@kennethehmsen.dk**

Or use GitHub's private vulnerability reporting:
1. Go to the [Security tab](https://github.com/KennethEhmsen/ci-co/security)
2. Click "Report a vulnerability"
3. Fill out the form with details

### What to Include

Please include the following in your report:

- **Description**: Clear description of the vulnerability
- **Impact**: Potential impact and severity
- **Steps to Reproduce**: Detailed steps to reproduce the issue
- **Affected Versions**: Which versions are affected
- **Possible Fix**: If you have suggestions for fixing the issue

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Target**: Within 30 days for critical issues

### What to Expect

1. **Acknowledgment**: We'll confirm receipt of your report
2. **Investigation**: We'll investigate and validate the issue
3. **Updates**: We'll keep you informed of our progress
4. **Fix**: We'll develop and test a fix
5. **Disclosure**: We'll coordinate disclosure timing with you
6. **Credit**: We'll credit you in the release notes (unless you prefer anonymity)

## Security Best Practices

When using this platform:

### Credentials

- **Change default passwords** immediately after first login
- Use strong, unique passwords for each service
- Store secrets in environment variables, not in code

### Network

- Run the platform on a trusted network
- Use a firewall to restrict access to service ports
- Consider using a VPN for remote access

### Docker

- Keep Docker Desktop updated
- Don't expose Docker socket unnecessarily
- Use the principle of least privilege

### API Tokens

- Rotate API tokens regularly
- Use minimal required permissions
- Never commit tokens to version control

## Default Credentials

**Change these immediately after installation:**

| Service | Default Username | Default Password |
|---------|-----------------|------------------|
| Gitea | `localadmin` | `admin123` |
| SonarQube | `admin` | `admin` |
| Dependency-Track | `admin` | `admin` |

## Security Features

This platform includes security scanning tools:

- **Trivy**: Vulnerability scanning for containers and dependencies
- **SonarQube**: Static Application Security Testing (SAST)
- **Dependency-Track**: Software Composition Analysis (SCA)

Use these tools to scan your own projects for vulnerabilities.

## Acknowledgments

We thank the security researchers who help keep this project secure.

*No vulnerabilities have been reported yet.*
