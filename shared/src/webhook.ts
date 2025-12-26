/**
 * Webhook Notification Module
 *
 * Sends scan result notifications to configured webhook endpoints.
 * Supports Slack, Microsoft Teams, and generic webhook formats.
 */

import type {
  WebhookEndpoint,
  WebhookConfig,
  WebhookScanSummary,
  WebhookDeliveryResult,
  WebhookSeverityThreshold,
  SlackWebhookPayload,
  SlackBlock,
  TeamsWebhookPayload,
  TeamsAdaptiveCardElement,
  GenericWebhookPayload,
} from "./types.js";

// Default configuration values
const DEFAULT_RETRY_ATTEMPTS = 3;
const DEFAULT_RETRY_DELAY_MS = 1000;
const DEFAULT_SEVERITY_THRESHOLD: WebhookSeverityThreshold = "HIGH";

// Severity priority for threshold comparison
const SEVERITY_PRIORITY: Record<WebhookSeverityThreshold, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/**
 * Check if scan results meet the severity threshold for notification
 */
export function meetsSeverityThreshold(
  summary: WebhookScanSummary,
  threshold: WebhookSeverityThreshold
): boolean {
  const thresholdPriority = SEVERITY_PRIORITY[threshold];

  if (thresholdPriority <= SEVERITY_PRIORITY.CRITICAL && summary.vulnerabilities.critical > 0) {
    return true;
  }
  if (thresholdPriority <= SEVERITY_PRIORITY.HIGH && summary.vulnerabilities.high > 0) {
    return true;
  }
  if (thresholdPriority <= SEVERITY_PRIORITY.MEDIUM && summary.vulnerabilities.medium > 0) {
    return true;
  }
  if (thresholdPriority <= SEVERITY_PRIORITY.LOW && summary.vulnerabilities.low > 0) {
    return true;
  }

  return false;
}

/**
 * Get color based on vulnerability severity
 */
function getSeverityColor(summary: WebhookScanSummary): string {
  if (summary.vulnerabilities.critical > 0) return "#dc3545"; // Red
  if (summary.vulnerabilities.high > 0) return "#fd7e14"; // Orange
  if (summary.vulnerabilities.medium > 0) return "#ffc107"; // Yellow
  if (summary.vulnerabilities.low > 0) return "#17a2b8"; // Blue
  return "#28a745"; // Green
}

/**
 * Get status emoji based on vulnerability severity
 */
function getStatusEmoji(summary: WebhookScanSummary): string {
  if (summary.vulnerabilities.critical > 0) return ":rotating_light:";
  if (summary.vulnerabilities.high > 0) return ":warning:";
  if (summary.vulnerabilities.medium > 0) return ":large_yellow_circle:";
  if (summary.vulnerabilities.low > 0) return ":information_source:";
  return ":white_check_mark:";
}

/**
 * Get Teams color based on vulnerability severity
 */
function getTeamsColor(summary: WebhookScanSummary): "attention" | "warning" | "accent" | "good" {
  if (summary.vulnerabilities.critical > 0) return "attention";
  if (summary.vulnerabilities.high > 0) return "warning";
  if (summary.vulnerabilities.medium > 0) return "accent";
  return "good";
}

// =============================================================================
// Slack Formatter
// =============================================================================

/**
 * Format scan summary as Slack webhook payload
 */
export function formatSlackMessage(summary: WebhookScanSummary): SlackWebhookPayload {
  const emoji = getStatusEmoji(summary);
  const color = getSeverityColor(summary);

  const blocks: SlackBlock[] = [
    {
      type: "header",
      text: {
        type: "plain_text",
        text: `${emoji} Security Scan Complete`,
        emoji: true,
      },
    },
    {
      type: "section",
      fields: [
        {
          type: "mrkdwn",
          text: `*Target:*\n\`${summary.target}\``,
        },
        {
          type: "mrkdwn",
          text: `*Scan Type:*\n${summary.scanType}`,
        },
      ],
    },
    {
      type: "section",
      fields: [
        {
          type: "mrkdwn",
          text: `*Critical:*\n${summary.vulnerabilities.critical}`,
        },
        {
          type: "mrkdwn",
          text: `*High:*\n${summary.vulnerabilities.high}`,
        },
        {
          type: "mrkdwn",
          text: `*Medium:*\n${summary.vulnerabilities.medium}`,
        },
        {
          type: "mrkdwn",
          text: `*Low:*\n${summary.vulnerabilities.low}`,
        },
      ],
    },
  ];

  // Add policy status if available
  if (summary.policyPassed !== undefined) {
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: summary.policyPassed
          ? ":white_check_mark: *Policy Check:* Passed"
          : ":x: *Policy Check:* Failed",
      },
    });
  }

  // Add top findings if available
  if (summary.topFindings && summary.topFindings.length > 0) {
    blocks.push({ type: "divider" });
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: "*Top Findings:*",
      },
    });

    const findingsText = summary.topFindings
      .slice(0, 5)
      .map((f) => `• \`${f.id}\` [${f.severity}] ${f.title}${f.package ? ` (${f.package})` : ""}`)
      .join("\n");

    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: findingsText,
      },
    });
  }

  // Add details link if available
  if (summary.detailsUrl) {
    blocks.push({
      type: "actions",
      elements: [
        {
          type: "button",
          text: {
            type: "plain_text",
            text: "View Details",
            emoji: true,
          },
          url: summary.detailsUrl,
          action_id: "view_details",
        },
      ],
    });
  }

  // Add context with timestamp
  blocks.push({
    type: "context",
    elements: [
      {
        type: "mrkdwn",
        text: { type: "mrkdwn", text: `Scanned at ${summary.timestamp}` },
      },
    ],
  });

  return {
    text: `Security scan complete for ${summary.target}: ${summary.vulnerabilities.total} vulnerabilities found`,
    blocks,
    attachments: [
      {
        color,
        fields: [
          {
            title: "Total Vulnerabilities",
            value: summary.vulnerabilities.total.toString(),
            short: true,
          },
        ],
      },
    ],
  };
}

// =============================================================================
// Microsoft Teams Formatter
// =============================================================================

/**
 * Format scan summary as Microsoft Teams Adaptive Card payload
 */
export function formatTeamsMessage(summary: WebhookScanSummary): TeamsWebhookPayload {
  const color = getTeamsColor(summary);

  const body: TeamsAdaptiveCardElement[] = [
    {
      type: "TextBlock",
      text: "Security Scan Complete",
      size: "large",
      weight: "bolder",
      color,
    },
    {
      type: "FactSet",
      facts: [
        { title: "Target", value: summary.target },
        { title: "Scan Type", value: summary.scanType },
        { title: "Timestamp", value: summary.timestamp },
      ],
    },
    {
      type: "TextBlock",
      text: "Vulnerability Summary",
      weight: "bolder",
      size: "medium",
    },
    {
      type: "ColumnSet",
      columns: [
        {
          type: "Column",
          width: "auto",
          items: [
            {
              type: "TextBlock",
              text: "Critical",
              weight: "bolder",
              color: summary.vulnerabilities.critical > 0 ? "attention" : "default",
            },
            {
              type: "TextBlock",
              text: summary.vulnerabilities.critical.toString(),
              size: "extraLarge",
              color: summary.vulnerabilities.critical > 0 ? "attention" : "default",
            },
          ],
        },
        {
          type: "Column",
          width: "auto",
          items: [
            {
              type: "TextBlock",
              text: "High",
              weight: "bolder",
              color: summary.vulnerabilities.high > 0 ? "warning" : "default",
            },
            {
              type: "TextBlock",
              text: summary.vulnerabilities.high.toString(),
              size: "extraLarge",
              color: summary.vulnerabilities.high > 0 ? "warning" : "default",
            },
          ],
        },
        {
          type: "Column",
          width: "auto",
          items: [
            {
              type: "TextBlock",
              text: "Medium",
              weight: "bolder",
            },
            {
              type: "TextBlock",
              text: summary.vulnerabilities.medium.toString(),
              size: "extraLarge",
            },
          ],
        },
        {
          type: "Column",
          width: "auto",
          items: [
            {
              type: "TextBlock",
              text: "Low",
              weight: "bolder",
            },
            {
              type: "TextBlock",
              text: summary.vulnerabilities.low.toString(),
              size: "extraLarge",
            },
          ],
        },
      ],
    },
  ];

  // Add policy status if available
  if (summary.policyPassed !== undefined) {
    body.push({
      type: "TextBlock",
      text: summary.policyPassed ? "Policy Check: Passed" : "Policy Check: Failed",
      color: summary.policyPassed ? "good" : "attention",
      weight: "bolder",
    });
  }

  // Add top findings if available
  if (summary.topFindings && summary.topFindings.length > 0) {
    body.push({
      type: "TextBlock",
      text: "Top Findings",
      weight: "bolder",
      size: "medium",
    });

    body.push({
      type: "FactSet",
      facts: summary.topFindings.slice(0, 5).map((f) => ({
        title: `${f.id} [${f.severity}]`,
        value: `${f.title}${f.package ? ` (${f.package})` : ""}`,
      })),
    });
  }

  const actions: Array<{ type: string; title: string; url: string }> = [];
  if (summary.detailsUrl) {
    actions.push({
      type: "Action.OpenUrl",
      title: "View Details",
      url: summary.detailsUrl,
    });
  }

  return {
    type: "message",
    attachments: [
      {
        contentType: "application/vnd.microsoft.card.adaptive",
        content: {
          $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
          type: "AdaptiveCard",
          version: "1.4",
          body,
          actions: actions.length > 0 ? actions : undefined,
        },
      },
    ],
  };
}

// =============================================================================
// Generic Webhook Formatter
// =============================================================================

/**
 * Format scan summary as generic webhook payload
 */
export function formatGenericMessage(summary: WebhookScanSummary): GenericWebhookPayload {
  return {
    event: "scan_completed",
    timestamp: summary.timestamp,
    target: summary.target,
    scanType: summary.scanType,
    summary: summary.vulnerabilities,
    policyPassed: summary.policyPassed,
    topFindings: summary.topFindings,
    detailsUrl: summary.detailsUrl,
  };
}

// =============================================================================
// Webhook Delivery
// =============================================================================

/**
 * Sleep for a specified duration
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Send a webhook request with retry logic
 */
async function sendWithRetry(
  url: string,
  payload: unknown,
  headers: Record<string, string>,
  retryAttempts: number,
  retryDelayMs: number
): Promise<{ success: boolean; statusCode?: number; error?: string; attempts: number }> {
  let lastError: string | undefined;
  let lastStatusCode: number | undefined;

  for (let attempt = 1; attempt <= retryAttempts; attempt++) {
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...headers,
        },
        body: JSON.stringify(payload),
      });

      lastStatusCode = response.status;

      if (response.ok) {
        return { success: true, statusCode: response.status, attempts: attempt };
      }

      // Non-retryable errors (client errors except 429)
      if (response.status >= 400 && response.status < 500 && response.status !== 429) {
        const errorText = await response.text();
        return {
          success: false,
          statusCode: response.status,
          error: `HTTP ${response.status}: ${errorText.slice(0, 200)}`,
          attempts: attempt,
        };
      }

      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : "Unknown error";
    }

    // Wait before retry (with exponential backoff)
    if (attempt < retryAttempts) {
      await sleep(retryDelayMs * Math.pow(2, attempt - 1));
    }
  }

  return {
    success: false,
    statusCode: lastStatusCode,
    error: lastError,
    attempts: retryAttempts,
  };
}

/**
 * Send notification to a single webhook endpoint
 */
export async function sendWebhook(
  endpoint: WebhookEndpoint,
  summary: WebhookScanSummary,
  config?: Partial<WebhookConfig>
): Promise<WebhookDeliveryResult> {
  const retryAttempts = config?.retryAttempts ?? DEFAULT_RETRY_ATTEMPTS;
  const retryDelayMs = config?.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS;
  const threshold =
    endpoint.severityThreshold ?? config?.defaultSeverityThreshold ?? DEFAULT_SEVERITY_THRESHOLD;

  // Check if notification should be sent based on severity threshold
  if (!meetsSeverityThreshold(summary, threshold)) {
    return {
      endpointId: endpoint.id,
      success: true,
      attempts: 0,
      timestamp: new Date().toISOString(),
    };
  }

  // Format payload based on webhook format
  let payload: unknown;
  switch (endpoint.format) {
    case "slack":
      payload = formatSlackMessage(summary);
      break;
    case "teams":
      payload = formatTeamsMessage(summary);
      break;
    case "generic":
    default:
      payload = formatGenericMessage(summary);
      break;
  }

  // Send the webhook
  const result = await sendWithRetry(
    endpoint.url,
    payload,
    endpoint.headers ?? {},
    retryAttempts,
    retryDelayMs
  );

  return {
    endpointId: endpoint.id,
    success: result.success,
    statusCode: result.statusCode,
    error: result.error,
    attempts: result.attempts,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Send notifications to all configured webhook endpoints
 */
export async function sendWebhooks(
  config: WebhookConfig,
  summary: WebhookScanSummary
): Promise<WebhookDeliveryResult[]> {
  const enabledEndpoints = config.endpoints.filter((e) => e.enabled !== false);

  const results = await Promise.all(
    enabledEndpoints.map((endpoint) => sendWebhook(endpoint, summary, config))
  );

  return results;
}

/**
 * Create a WebhookScanSummary from scan results
 */
export function createScanSummary(
  target: string,
  scanType: WebhookScanSummary["scanType"],
  vulnerabilities: WebhookScanSummary["vulnerabilities"],
  options?: {
    policyPassed?: boolean;
    topFindings?: WebhookScanSummary["topFindings"];
    detailsUrl?: string;
  }
): WebhookScanSummary {
  return {
    target,
    scanType,
    timestamp: new Date().toISOString(),
    vulnerabilities,
    policyPassed: options?.policyPassed,
    topFindings: options?.topFindings,
    detailsUrl: options?.detailsUrl,
  };
}

/**
 * Parse webhook configuration from environment variable
 * Format: JSON string or comma-separated URL list
 */
export function parseWebhookConfig(envValue: string | undefined): WebhookConfig | null {
  if (!envValue) return null;

  try {
    // Try parsing as JSON first
    const parsed = JSON.parse(envValue) as WebhookConfig;
    return parsed;
  } catch {
    // Fall back to comma-separated URLs (generic format)
    const urls = envValue
      .split(",")
      .map((u) => u.trim())
      .filter(Boolean);
    if (urls.length === 0) return null;

    return {
      endpoints: urls.map((url, index) => ({
        id: `webhook-${index + 1}`,
        name: `Webhook ${index + 1}`,
        url,
        format: "generic" as const,
        enabled: true,
      })),
    };
  }
}
