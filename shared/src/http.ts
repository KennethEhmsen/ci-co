// =============================================================================
// HTTP Helper Functions
// =============================================================================

/**
 * Fetch JSON data from a URL with automatic timeout handling.
 * Provides a consistent interface for all HTTP API calls in the platform.
 *
 * @param url - The URL to fetch from
 * @param options - Standard fetch RequestInit options (headers, method, body, etc.)
 * @returns Promise resolving to parsed JSON response
 * @throws Error if response is not OK (non-2xx status) or request times out (30s)
 *
 * @example
 * ```typescript
 * // Simple GET request
 * const data = await fetchJson('http://localhost:3000/api/v1/version');
 *
 * // POST request with auth
 * const result = await fetchJson('http://localhost:3000/api/v1/repos', {
 *   method: 'POST',
 *   headers: { Authorization: 'Basic ...', 'Content-Type': 'application/json' },
 *   body: JSON.stringify({ name: 'my-repo' })
 * });
 * ```
 */
export async function fetchJson(url: string, options: RequestInit = {}): Promise<any> {
  const response = await fetch(url, {
    ...options,
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  return response.json();
}

/**
 * Generate a Basic Authentication header value.
 * Encodes username and password in base64 format for HTTP Basic Auth.
 *
 * @param user - Username for authentication
 * @param pass - Password for authentication
 * @returns The complete Authorization header value (e.g., "Basic dXNlcjpwYXNz")
 *
 * @example
 * ```typescript
 * const authHeader = basicAuth('admin', 'password123');
 * // Returns: "Basic YWRtaW46cGFzc3dvcmQxMjM="
 *
 * // Use in fetch request
 * await fetch(url, {
 *   headers: { Authorization: basicAuth('admin', 'password123') }
 * });
 * ```
 */
export function basicAuth(user: string, pass: string): string {
  return "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");
}
