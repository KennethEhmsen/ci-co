# Integration Cookbook

This guide shows how to integrate the CI/CD Security Platform with various CI systems.

## Table of Contents

- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Jenkins](#jenkins)
- [Drone CI](#drone-ci)
- [Azure DevOps](#azure-devops)

---

## GitHub Actions

### Basic Security Scan

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy vulnerability scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          severity: 'HIGH,CRITICAL'
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'
```

### Using CI/CD Agent

```yaml
# .github/workflows/cicd-agent.yml
name: CI/CD Security Agent

on:
  push:
    branches: [main]

jobs:
  security-report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install CI/CD Agent
        run: npm install -g cicd-security-agent

      - name: Run Security Report
        run: cicd-agent security-report . --format json --quiet > report.json
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}

      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: report.json
```

---

## GitLab CI

### Basic Security Pipeline

```yaml
# .gitlab-ci.yml
stages:
  - test
  - security

variables:
  TRIVY_SEVERITY: "HIGH,CRITICAL"

trivy-scan:
  stage: security
  image: aquasec/trivy:latest
  script:
    - trivy fs --severity $TRIVY_SEVERITY --format json --output trivy-report.json .
  artifacts:
    reports:
      container_scanning: trivy-report.json
    paths:
      - trivy-report.json

sonarqube-scan:
  stage: security
  image: sonarsource/sonar-scanner-cli:latest
  variables:
    SONAR_HOST_URL: "http://sonarqube:9000"
  script:
    - sonar-scanner -Dsonar.projectKey=$CI_PROJECT_NAME
  only:
    - main
    - merge_requests
```

### SBOM Generation

```yaml
sbom-generate:
  stage: security
  image: aquasec/trivy:latest
  script:
    - trivy fs --format cyclonedx --output sbom-cyclonedx.json .
    - trivy fs --format spdx-json --output sbom-spdx.json .
  artifacts:
    paths:
      - sbom-cyclonedx.json
      - sbom-spdx.json
```

---

## Jenkins

### Jenkinsfile Example

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        TRIVY_SEVERITY = 'HIGH,CRITICAL'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Security Scan') {
            parallel {
                stage('Trivy Scan') {
                    steps {
                        sh '''
                            docker run --rm -v $(pwd):/src aquasec/trivy:latest \
                                fs --severity ${TRIVY_SEVERITY} \
                                --format json --output /src/trivy-report.json /src
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'trivy-report.json'
                        }
                    }
                }

                stage('SonarQube Scan') {
                    steps {
                        withSonarQubeEnv('SonarQube') {
                            sh 'sonar-scanner'
                        }
                    }
                }
            }
        }

        stage('Quality Gate') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        stage('SBOM Generation') {
            steps {
                sh '''
                    docker run --rm -v $(pwd):/src aquasec/trivy:latest \
                        fs --format cyclonedx --output /src/sbom.json /src
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'sbom.json'
                }
            }
        }
    }

    post {
        failure {
            // Send notification on security failures
            emailext (
                subject: "Security Scan Failed: ${env.JOB_NAME}",
                body: "Check console output at ${env.BUILD_URL}",
                recipientProviders: [[$class: 'DevelopersRecipientProvider']]
            )
        }
    }
}
```

---

## Drone CI

### Basic Pipeline

```yaml
# .drone.yml
kind: pipeline
type: docker
name: security

steps:
  - name: trivy-scan
    image: aquasec/trivy:latest
    commands:
      - trivy fs --severity HIGH,CRITICAL --format json --output trivy-report.json .
    volumes:
      - name: reports
        path: /reports

  - name: sbom-generate
    image: aquasec/trivy:latest
    commands:
      - trivy fs --format cyclonedx --output sbom-cyclonedx.json .
      - trivy fs --format spdx-json --output sbom-spdx.json .

  - name: upload-to-dtrack
    image: curlimages/curl:latest
    commands:
      - |
        curl -X PUT "http://dependency-track-api:8080/api/v1/bom" \
          -H "X-Api-Key: ${DTRACK_API_KEY}" \
          -H "Content-Type: application/json" \
          -d @sbom-cyclonedx.json
    environment:
      DTRACK_API_KEY:
        from_secret: dtrack_api_key
    when:
      branch:
        - main

volumes:
  - name: reports
    temp: {}

trigger:
  branch:
    - main
    - develop
  event:
    - push
    - pull_request
```

---

## Azure DevOps

### azure-pipelines.yml

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main
      - develop

pool:
  vmImage: 'ubuntu-latest'

stages:
  - stage: Security
    displayName: 'Security Scanning'
    jobs:
      - job: TrivyScan
        displayName: 'Trivy Vulnerability Scan'
        steps:
          - task: Docker@2
            displayName: 'Run Trivy Scan'
            inputs:
              command: run
              arguments: >
                --rm -v $(Build.SourcesDirectory):/src
                aquasec/trivy:latest fs
                --severity HIGH,CRITICAL
                --format json
                --output /src/trivy-report.json
                /src

          - task: PublishBuildArtifacts@1
            inputs:
              pathToPublish: 'trivy-report.json'
              artifactName: 'SecurityReports'

      - job: SBOMGeneration
        displayName: 'Generate SBOM'
        steps:
          - task: Docker@2
            displayName: 'Generate CycloneDX SBOM'
            inputs:
              command: run
              arguments: >
                --rm -v $(Build.SourcesDirectory):/src
                aquasec/trivy:latest fs
                --format cyclonedx
                --output /src/sbom.json
                /src

          - task: PublishBuildArtifacts@1
            inputs:
              pathToPublish: 'sbom.json'
              artifactName: 'SBOM'
```

---

## Common Patterns

### Exit Codes for CI

```bash
# Fail if HIGH or CRITICAL vulnerabilities found
trivy fs --severity HIGH,CRITICAL --exit-code 1 .

# Fail only on CRITICAL
trivy fs --severity CRITICAL --exit-code 1 .

# Always succeed (for reporting only)
trivy fs --exit-code 0 .
```

### Ignoring Known Vulnerabilities

Create `.trivyignore`:

```
# Ignore specific CVEs
CVE-2023-12345
CVE-2023-67890

# Ignore by package
pkg:npm/lodash@4.17.20
```

### Policy-Based Gating

```yaml
# trivy.yaml policy
severity:
  - CRITICAL
  - HIGH

ignore:
  - id: CVE-2023-12345
    reason: "Mitigated by network controls"
    expires: "2024-12-31"
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TRIVY_SEVERITY` | Severity filter | `HIGH,CRITICAL` |
| `SONAR_HOST_URL` | SonarQube server URL | `http://localhost:9000` |
| `DTRACK_API_KEY` | Dependency-Track API key | - |
| `ANTHROPIC_API_KEY` | For CI/CD Agent | - |

---

## Best Practices

1. **Fail Fast**: Use `--exit-code 1` to fail builds on vulnerabilities
2. **Cache Trivy DB**: Mount a persistent volume for the Trivy cache
3. **Parallel Scanning**: Run vulnerability, secret, and license scans in parallel
4. **SBOM Every Build**: Generate and store SBOMs for every release
5. **Quality Gates**: Require SonarQube quality gate to pass before merge
6. **Secrets Management**: Never commit API keys; use CI secrets
