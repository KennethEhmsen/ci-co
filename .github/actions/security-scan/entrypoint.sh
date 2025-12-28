#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Initialize counters
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
TOTAL_COUNT=0

# Parse severity threshold for fail-on
get_severity_level() {
    case "$1" in
        CRITICAL) echo 4 ;;
        HIGH) echo 3 ;;
        MEDIUM) echo 2 ;;
        LOW) echo 1 ;;
        *) echo 0 ;;
    esac
}

# Main scan function
run_scan() {
    local scan_target="$1"
    local scan_type="$2"
    local output_file="$3"

    log_info "Running Trivy scan on: $scan_target (type: $scan_type)"

    # Build Trivy command
    local trivy_cmd="trivy"

    if [ "$scan_type" = "image" ]; then
        trivy_cmd="$trivy_cmd image"
    else
        trivy_cmd="$trivy_cmd fs"
    fi

    # Add severity filter
    if [ -n "$SEVERITY" ]; then
        trivy_cmd="$trivy_cmd --severity $SEVERITY"
    fi

    # Add ignore unfixed option
    if [ "$IGNORE_UNFIXED" = "true" ]; then
        trivy_cmd="$trivy_cmd --ignore-unfixed"
    fi

    # Add skip directories
    if [ -n "$SKIP_DIRS" ]; then
        IFS=',' read -ra DIRS <<< "$SKIP_DIRS"
        for dir in "${DIRS[@]}"; do
            trivy_cmd="$trivy_cmd --skip-dirs $dir"
        done
    fi

    # Add skip files
    if [ -n "$SKIP_FILES" ]; then
        IFS=',' read -ra FILES <<< "$SKIP_FILES"
        for file in "${FILES[@]}"; do
            trivy_cmd="$trivy_cmd --skip-files $file"
        done
    fi

    # Add Trivy config if provided
    if [ -n "$TRIVY_CONFIG" ] && [ -f "$TRIVY_CONFIG" ]; then
        trivy_cmd="$trivy_cmd --config $TRIVY_CONFIG"
    fi

    # Output format
    if [ "$OUTPUT_FORMAT" = "sarif" ]; then
        trivy_cmd="$trivy_cmd --format sarif --output $output_file"
    elif [ "$OUTPUT_FORMAT" = "json" ]; then
        trivy_cmd="$trivy_cmd --format json --output $output_file"
    else
        trivy_cmd="$trivy_cmd --format table"
    fi

    # Add target
    trivy_cmd="$trivy_cmd $scan_target"

    log_info "Executing: $trivy_cmd"

    # Run scan and capture exit code
    set +e
    eval "$trivy_cmd"
    local exit_code=$?
    set -e

    if [ $exit_code -ne 0 ] && [ $exit_code -ne 1 ]; then
        log_error "Trivy scan failed with exit code: $exit_code"
        return $exit_code
    fi

    return 0
}

# Count vulnerabilities from SARIF
count_vulnerabilities_sarif() {
    local sarif_file="$1"

    if [ ! -f "$sarif_file" ]; then
        log_warning "SARIF file not found: $sarif_file"
        return
    fi

    # Extract counts using jq
    CRITICAL_COUNT=$(jq '[.runs[].results[] | select(.level == "error" and (.properties.security-severity // "0" | tonumber) >= 9.0)] | length' "$sarif_file" 2>/dev/null || echo "0")
    HIGH_COUNT=$(jq '[.runs[].results[] | select(.level == "error" and (.properties.security-severity // "0" | tonumber) >= 7.0 and (.properties.security-severity // "0" | tonumber) < 9.0)] | length' "$sarif_file" 2>/dev/null || echo "0")
    MEDIUM_COUNT=$(jq '[.runs[].results[] | select(.level == "warning")] | length' "$sarif_file" 2>/dev/null || echo "0")
    LOW_COUNT=$(jq '[.runs[].results[] | select(.level == "note")] | length' "$sarif_file" 2>/dev/null || echo "0")

    TOTAL_COUNT=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT))
}

# Count vulnerabilities from JSON
count_vulnerabilities_json() {
    local json_file="$1"

    if [ ! -f "$json_file" ]; then
        log_warning "JSON file not found: $json_file"
        return
    fi

    CRITICAL_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$json_file" 2>/dev/null || echo "0")
    HIGH_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$json_file" 2>/dev/null || echo "0")
    MEDIUM_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$json_file" 2>/dev/null || echo "0")
    LOW_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")] | length' "$json_file" 2>/dev/null || echo "0")

    TOTAL_COUNT=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT))
}

# Upload SARIF to GitHub Code Scanning
upload_sarif() {
    local sarif_file="$1"

    if [ ! -f "$sarif_file" ]; then
        log_error "SARIF file not found: $sarif_file"
        return 1
    fi

    log_info "Uploading SARIF to GitHub Code Scanning..."

    # Use GitHub CLI to upload SARIF
    gh api \
        --method POST \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "/repos/${GITHUB_REPOSITORY}/code-scanning/sarifs" \
        -f "commit_sha=${GITHUB_SHA}" \
        -f "ref=${GITHUB_REF}" \
        -f "sarif=$(gzip -c "$sarif_file" | base64 -w0)" \
        -f "tool_name=cicd-security-scanner" \
        -f "checkout_uri=file:///${GITHUB_WORKSPACE}"

    log_success "SARIF uploaded successfully"
}

# Post PR comment
post_pr_comment() {
    local comment_body="$1"

    # Only run on pull requests
    if [ -z "$GITHUB_EVENT_PATH" ]; then
        log_warning "Not in GitHub Actions environment, skipping PR comment"
        return
    fi

    # Get PR number from event
    local pr_number=$(jq -r '.pull_request.number // empty' "$GITHUB_EVENT_PATH" 2>/dev/null)

    if [ -z "$pr_number" ]; then
        log_info "Not a pull request event, skipping PR comment"
        return
    fi

    log_info "Posting comment to PR #$pr_number..."

    # Check for existing comment and update it
    local existing_comment_id=$(gh api \
        -H "Accept: application/vnd.github+json" \
        "/repos/${GITHUB_REPOSITORY}/issues/${pr_number}/comments" \
        --jq ".[] | select(.body | startswith(\"## ${COMMENT_TITLE}\")) | .id" 2>/dev/null | head -1)

    if [ -n "$existing_comment_id" ]; then
        # Update existing comment
        gh api \
            --method PATCH \
            -H "Accept: application/vnd.github+json" \
            "/repos/${GITHUB_REPOSITORY}/issues/comments/${existing_comment_id}" \
            -f body="$comment_body"
        log_success "Updated existing PR comment"
    else
        # Create new comment
        gh api \
            --method POST \
            -H "Accept: application/vnd.github+json" \
            "/repos/${GITHUB_REPOSITORY}/issues/${pr_number}/comments" \
            -f body="$comment_body"
        log_success "Posted new PR comment"
    fi
}

# Generate PR comment body
generate_comment_body() {
    local status_emoji="✅"
    local status_text="Passed"

    if [ "$SCAN_PASSED" = "false" ]; then
        status_emoji="❌"
        status_text="Failed"
    elif [ "$TOTAL_COUNT" -gt 0 ]; then
        status_emoji="⚠️"
        status_text="Warnings"
    fi

    cat << EOF
## ${COMMENT_TITLE}

${status_emoji} **Status: ${status_text}**

### Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | ${CRITICAL_COUNT} |
| 🟠 High | ${HIGH_COUNT} |
| 🟡 Medium | ${MEDIUM_COUNT} |
| 🟢 Low | ${LOW_COUNT} |
| **Total** | **${TOTAL_COUNT}** |

### Configuration

- **Scan Type:** ${SCAN_TYPE}
- **Severity Filter:** ${SEVERITY}
- **Fail Threshold:** ${FAIL_ON}

---
<sub>🛡️ Powered by [CI/CD Security Scanner](https://github.com/marketplace/actions/cicd-security-scanner)</sub>
EOF
}

# Generate badge SVG
generate_badge() {
    local badge_path="$1"
    local color="brightgreen"
    local status="passing"

    if [ "$CRITICAL_COUNT" -gt 0 ]; then
        color="red"
        status="${CRITICAL_COUNT}%20critical"
    elif [ "$HIGH_COUNT" -gt 0 ]; then
        color="orange"
        status="${HIGH_COUNT}%20high"
    elif [ "$MEDIUM_COUNT" -gt 0 ]; then
        color="yellow"
        status="${MEDIUM_COUNT}%20medium"
    elif [ "$TOTAL_COUNT" -gt 0 ]; then
        color="yellowgreen"
        status="${LOW_COUNT}%20low"
    fi

    # Create badge directory if needed
    mkdir -p "$(dirname "$badge_path")"

    # Download badge from shields.io
    curl -s "https://img.shields.io/badge/security-${status}-${color}" -o "$badge_path"

    log_success "Badge generated: $badge_path"
}

# Check if scan passed based on fail-on threshold
check_pass_fail() {
    local fail_level=$(get_severity_level "$FAIL_ON")
    SCAN_PASSED="true"

    if [ "$fail_level" -ge 4 ] && [ "$CRITICAL_COUNT" -gt 0 ]; then
        SCAN_PASSED="false"
    elif [ "$fail_level" -ge 3 ] && [ "$((CRITICAL_COUNT + HIGH_COUNT))" -gt 0 ]; then
        SCAN_PASSED="false"
    elif [ "$fail_level" -ge 2 ] && [ "$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT))" -gt 0 ]; then
        SCAN_PASSED="false"
    elif [ "$fail_level" -ge 1 ] && [ "$TOTAL_COUNT" -gt 0 ]; then
        SCAN_PASSED="false"
    fi
}

# Set GitHub Action outputs
set_outputs() {
    echo "vulnerabilities-count=${TOTAL_COUNT}" >> "$GITHUB_OUTPUT"
    echo "critical-count=${CRITICAL_COUNT}" >> "$GITHUB_OUTPUT"
    echo "high-count=${HIGH_COUNT}" >> "$GITHUB_OUTPUT"
    echo "medium-count=${MEDIUM_COUNT}" >> "$GITHUB_OUTPUT"
    echo "low-count=${LOW_COUNT}" >> "$GITHUB_OUTPUT"
    echo "sarif-file=${OUTPUT_FILE}" >> "$GITHUB_OUTPUT"
    echo "scan-passed=${SCAN_PASSED}" >> "$GITHUB_OUTPUT"

    # Generate summary JSON
    local summary=$(cat << EOF
{
    "total": ${TOTAL_COUNT},
    "critical": ${CRITICAL_COUNT},
    "high": ${HIGH_COUNT},
    "medium": ${MEDIUM_COUNT},
    "low": ${LOW_COUNT},
    "passed": ${SCAN_PASSED},
    "scanType": "${SCAN_TYPE}",
    "severity": "${SEVERITY}",
    "failOn": "${FAIL_ON}"
}
EOF
)
    echo "summary=${summary}" >> "$GITHUB_OUTPUT"

    if [ "$GENERATE_BADGE" = "true" ]; then
        echo "badge-url=https://raw.githubusercontent.com/${GITHUB_REPOSITORY}/${GITHUB_REF_NAME}/${BADGE_PATH}" >> "$GITHUB_OUTPUT"
    fi
}

# Main execution
main() {
    log_info "=== CI/CD Security Scanner ==="
    log_info "Scan Type: ${SCAN_TYPE}"
    log_info "Severity: ${SEVERITY}"
    log_info "Fail On: ${FAIL_ON}"

    # Determine scan target
    local scan_target=""
    local scan_mode=""

    case "$SCAN_TYPE" in
        image)
            if [ -z "$SCAN_IMAGE" ]; then
                log_error "Image name is required for image scans"
                exit 1
            fi
            scan_target="$SCAN_IMAGE"
            scan_mode="image"
            ;;
        path|*)
            scan_target="${SCAN_PATH:-.}"
            scan_mode="path"
            ;;
    esac

    # Run the scan
    run_scan "$scan_target" "$scan_mode" "$OUTPUT_FILE"

    # Count vulnerabilities
    if [ "$OUTPUT_FORMAT" = "sarif" ]; then
        count_vulnerabilities_sarif "$OUTPUT_FILE"
    elif [ "$OUTPUT_FORMAT" = "json" ]; then
        count_vulnerabilities_json "$OUTPUT_FILE"
    fi

    log_info "Scan complete: Found $TOTAL_COUNT vulnerabilities"
    log_info "  Critical: $CRITICAL_COUNT"
    log_info "  High: $HIGH_COUNT"
    log_info "  Medium: $MEDIUM_COUNT"
    log_info "  Low: $LOW_COUNT"

    # Check pass/fail
    check_pass_fail

    # Upload SARIF if enabled
    if [ "$UPLOAD_SARIF" = "true" ] && [ "$OUTPUT_FORMAT" = "sarif" ]; then
        upload_sarif "$OUTPUT_FILE" || log_warning "SARIF upload failed"
    fi

    # Post PR comment if enabled
    if [ "$COMMENT_ON_PR" = "true" ]; then
        local comment_body=$(generate_comment_body)
        post_pr_comment "$comment_body" || log_warning "PR comment failed"
    fi

    # Generate badge if enabled
    if [ "$GENERATE_BADGE" = "true" ]; then
        generate_badge "$BADGE_PATH"
    fi

    # Set outputs
    set_outputs

    # Exit with failure if scan didn't pass
    if [ "$SCAN_PASSED" = "false" ]; then
        log_error "Security scan failed: Found vulnerabilities exceeding threshold ($FAIL_ON)"
        exit 1
    fi

    log_success "Security scan completed successfully"
}

# Run main
main "$@"
