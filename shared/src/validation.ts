// =============================================================================
// Input Validation & Sanitization
// =============================================================================

/** Allowed Trivy severity levels */
const ALLOWED_SEVERITY_LEVELS = new Set(["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);

/**
 * Validate and sanitize severity level input.
 * Filters out invalid severity levels and returns only valid ones.
 *
 * @param severity - Comma-separated severity levels (e.g., "HIGH,CRITICAL")
 * @returns Validated severity string, defaults to "HIGH,CRITICAL" if none valid
 *
 * @example
 * ```typescript
 * validateSeverity("HIGH,CRITICAL,INVALID") // Returns "HIGH,CRITICAL"
 * validateSeverity("invalid") // Returns "HIGH,CRITICAL"
 * validateSeverity("low,medium") // Returns "LOW,MEDIUM"
 * ```
 */
export function validateSeverity(severity: string): string {
  const levels = severity.split(",").map((s) => s.trim().toUpperCase());
  const validLevels = levels.filter((l) => ALLOWED_SEVERITY_LEVELS.has(l));
  if (validLevels.length === 0) {
    return "HIGH,CRITICAL";
  }
  return validLevels.join(",");
}

/**
 * Sanitize a filesystem path to prevent path traversal attacks.
 * Removes dangerous characters and path traversal sequences.
 *
 * @param path - The path to sanitize
 * @returns Sanitized path with dangerous characters removed
 *
 * @example
 * ```typescript
 * sanitizePath("/home/user/../etc/passwd") // Returns "/home/user/etc/passwd"
 * sanitizePath("/path/with$special|chars") // Returns "/path/withspecialchars"
 * ```
 */
export function sanitizePath(path: string): string {
  const sanitized = path.replaceAll(/[^a-zA-Z0-9/\\.:\-_ ]/g, "");
  const normalized = sanitized.replaceAll("../", "").replaceAll("..\\", "");
  return normalized;
}

/**
 * Sanitize a Docker image name to prevent command injection.
 * Removes shell metacharacters and other dangerous characters.
 *
 * @param image - The Docker image name to sanitize
 * @returns Sanitized image name safe for use in shell commands
 *
 * @example
 * ```typescript
 * sanitizeImageName("nginx:1.25") // Returns "nginx:1.25"
 * sanitizeImageName("image$(rm -rf /)") // Returns "imagerm-rf"
 * sanitizeImageName("registry.io/org/image:v1.0.0") // Returns "registry.io/org/image:v1.0.0"
 * ```
 */
export function sanitizeImageName(image: string): string {
  const sanitized = image.replaceAll(/[^a-zA-Z0-9/:.@\-_]/g, "");
  return sanitized;
}
