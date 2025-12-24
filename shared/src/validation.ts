// =============================================================================
// Input Validation & Sanitization
// =============================================================================
const ALLOWED_SEVERITY_LEVELS = new Set(["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);

export function validateSeverity(severity: string): string {
  const levels = severity.split(",").map((s) => s.trim().toUpperCase());
  const validLevels = levels.filter((l) => ALLOWED_SEVERITY_LEVELS.has(l));
  if (validLevels.length === 0) {
    return "HIGH,CRITICAL";
  }
  return validLevels.join(",");
}

export function sanitizePath(path: string): string {
  const sanitized = path.replaceAll(/[^a-zA-Z0-9/\\.:\-_ ]/g, "");
  const normalized = sanitized.replaceAll("../", "").replaceAll("..\\", "");
  return normalized;
}

export function sanitizeImageName(image: string): string {
  const sanitized = image.replaceAll(/[^a-zA-Z0-9/:.@\-_]/g, "");
  return sanitized;
}
