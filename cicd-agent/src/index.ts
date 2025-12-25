#!/usr/bin/env node

import Anthropic from "@anthropic-ai/sdk";
import { program } from "commander";
import * as readline from "node:readline";
import { config as dotenvConfig } from "dotenv";
import { tools, executeTool } from "./tools.js";
import { OutputFormat, setGlobalFormat, setGlobalQuiet, log, isQuiet } from "./formatter.js";
import { loadConfigFile } from "./config-file.js";

// Load environment variables
dotenvConfig();

// Load configuration file
const fileConfig = loadConfigFile();
if (fileConfig) {
  // Apply file-based defaults (can be overridden by CLI)
  if (fileConfig.format) {
    setGlobalFormat(fileConfig.format);
  }
  if (fileConfig.quiet) {
    setGlobalQuiet(fileConfig.quiet);
  }
}

// Export for testing
export { tools, executeTool } from "./tools.js";

// =============================================================================
// Agent Configuration
// =============================================================================
export const SYSTEM_PROMPT = `You are a CI/CD Security Agent with access to a complete local development platform. You can help users with:

## Your Capabilities

### Security Scanning
- **Trivy**: Scan code and Docker images for vulnerabilities, misconfigurations, and secrets
- **SonarQube**: Analyze code quality, bugs, vulnerabilities, and security hotspots
- **Dependency-Track**: Track software bill of materials (SBOM) and CVE vulnerabilities

### Git Operations (Gitea)
- List, create, and manage repositories
- Migrate repositories from GitHub
- View branches and commit history

### CI/CD Pipelines (Drone CI)
- View build history and status
- Get build logs and diagnose failures
- Trigger new builds

### Docker Registry
- List images and tags in the local registry
- Check what's deployed

## Best Practices

1. **When asked to scan for vulnerabilities**: Use trivy_scan_path for code/dependencies, trivy_scan_image for containers
2. **When diagnosing CI failures**: Get the build details first, then fetch logs for failed steps
3. **When checking project security**: Combine Trivy, SonarQube, and Dependency-Track findings
4. **When migrating from GitHub**: Use gitea_migrate_repo to preserve issues and PRs

## Platform URLs (for user reference)
- Gitea: http://localhost:3000
- Drone CI: http://localhost:8085
- SonarQube: http://localhost:9000
- Dependency-Track: http://localhost:8082
- Registry UI: http://localhost:5001

Always provide actionable insights and recommendations based on the findings.`;

// =============================================================================
// Agent Class
// =============================================================================
export class CICDSecurityAgent {
  private readonly client: Anthropic;
  private conversationHistory: Anthropic.MessageParam[] = [];
  private readonly model = "claude-sonnet-4-20250514";

  constructor(client?: Anthropic) {
    this.client = client ?? new Anthropic();
  }

  // Expose for testing
  getConversationHistory(): Anthropic.MessageParam[] {
    return [...this.conversationHistory];
  }

  async chat(userMessage: string): Promise<string> {
    this.conversationHistory.push({
      role: "user",
      content: userMessage,
    });

    let response = await this.client.messages.create({
      model: this.model,
      max_tokens: 8096,
      system: SYSTEM_PROMPT,
      tools: tools,
      messages: this.conversationHistory,
    });

    // Agentic loop - keep processing until no more tool calls
    while (response.stop_reason === "tool_use") {
      const toolUseBlocks = response.content.filter(
        (block): block is Anthropic.ContentBlockParam & { type: "tool_use" } =>
          block.type === "tool_use"
      );

      const toolResults: Anthropic.ToolResultBlockParam[] = [];

      for (const toolUse of toolUseBlocks) {
        if (!isQuiet()) {
          console.log(`\n🔧 Using tool: ${toolUse.name}`);
        }

        const result = await executeTool(toolUse.name, toolUse.input as Record<string, unknown>);

        toolResults.push({
          type: "tool_result",
          tool_use_id: toolUse.id,
          content: result,
        });
      }

      // Add assistant's response and tool results to history
      this.conversationHistory.push(
        { role: "assistant", content: response.content },
        { role: "user", content: toolResults }
      );

      // Continue the conversation
      response = await this.client.messages.create({
        model: this.model,
        max_tokens: 8096,
        system: SYSTEM_PROMPT,
        tools: tools,
        messages: this.conversationHistory,
      });
    }

    // Extract text response
    const textContent = response.content.find(
      (block): block is Anthropic.TextBlock => block.type === "text"
    );

    const assistantMessage = textContent?.text || "No response generated.";

    this.conversationHistory.push({
      role: "assistant",
      content: response.content,
    });

    return assistantMessage;
  }

  async runSingleQuery(query: string): Promise<string> {
    return this.chat(query);
  }

  resetConversation(): void {
    this.conversationHistory = [];
  }
}

// =============================================================================
// Interactive CLI
// =============================================================================
async function interactiveMode() {
  const agent = new CICDSecurityAgent();

  console.log("\n🔒 CI/CD Security Agent");
  console.log("========================");
  console.log("I can help you with:");
  console.log("  • Security scanning (Trivy, SonarQube, Dependency-Track)");
  console.log("  • Git repository management (Gitea)");
  console.log("  • CI/CD pipeline operations (Drone CI)");
  console.log("  • Docker registry management");
  console.log("\nType 'exit' or 'quit' to end the session.");
  console.log("Type 'clear' to reset the conversation.\n");

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const prompt = () => {
    rl.question("\n📝 You: ", async (input) => {
      const trimmedInput = input.trim();

      if (!trimmedInput) {
        prompt();
        return;
      }

      if (trimmedInput.toLowerCase() === "exit" || trimmedInput.toLowerCase() === "quit") {
        console.log("\n👋 Goodbye!\n");
        rl.close();
        process.exit(0);
      }

      if (trimmedInput.toLowerCase() === "clear") {
        agent.resetConversation();
        console.log("\n🔄 Conversation cleared.\n");
        prompt();
        return;
      }

      try {
        console.log("\n🤖 Agent: Thinking...");
        const response = await agent.chat(trimmedInput);
        console.log(`\n🤖 Agent:\n${response}`);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.error(`\n❌ Error: ${errorMessage}`);
      }

      prompt();
    });
  };

  prompt();
}

// =============================================================================
// Command Handlers (exported for testing)
// =============================================================================
export async function handleScanCommand(
  path: string,
  severity: string,
  agent?: CICDSecurityAgent
): Promise<string> {
  const instance = agent ?? new CICDSecurityAgent();
  return instance.runSingleQuery(
    `Scan the directory "${path}" for security vulnerabilities. Report severity ${severity} and above. Provide a summary of findings with recommendations.`
  );
}

export async function handleScanImageCommand(
  image: string,
  agent?: CICDSecurityAgent
): Promise<string> {
  const instance = agent ?? new CICDSecurityAgent();
  return instance.runSingleQuery(
    `Scan the Docker image "${image}" for security vulnerabilities. Provide a summary of findings with severity levels and recommendations.`
  );
}

export async function handleStatusCommand(agent?: CICDSecurityAgent): Promise<string> {
  const instance = agent ?? new CICDSecurityAgent();
  return instance.runSingleQuery(
    "Check the health status of all CI/CD platform services and report which ones are available."
  );
}

export async function handleReposCommand(agent?: CICDSecurityAgent): Promise<string> {
  const instance = agent ?? new CICDSecurityAgent();
  return instance.runSingleQuery("List all repositories in Gitea with their details.");
}

export async function handleBuildsCommand(
  owner: string,
  repo: string,
  agent?: CICDSecurityAgent
): Promise<string> {
  const instance = agent ?? new CICDSecurityAgent();
  return instance.runSingleQuery(
    `Show the recent CI/CD builds for the repository ${owner}/${repo}. Include build status, duration, and any failures.`
  );
}

export async function handleSecurityReportCommand(
  path: string,
  agent?: CICDSecurityAgent
): Promise<string> {
  const instance = agent ?? new CICDSecurityAgent();
  return instance.runSingleQuery(
    `Generate a comprehensive security report for "${path}".
    1. First scan with Trivy for dependency vulnerabilities
    2. Check if there's a SonarQube project and get its issues
    3. Check Dependency-Track for any tracked vulnerabilities
    4. Provide an executive summary with:
       - Total vulnerabilities by severity
       - Top 5 critical issues to fix
       - Recommendations for remediation`
  );
}

export async function handleMigrateCommand(
  githubUrl: string,
  repoName: string,
  hasToken: boolean,
  agent?: CICDSecurityAgent
): Promise<string> {
  const instance = agent ?? new CICDSecurityAgent();
  const tokenInfo = hasToken ? " using the provided auth token" : "";
  return instance.runSingleQuery(
    `Migrate the GitHub repository "${githubUrl}" to Gitea with the name "${repoName}"${tokenInfo}. Preserve issues, PRs, and releases. After migration, report the new repository URL.`
  );
}

export async function handleAskCommand(
  question: string,
  agent?: CICDSecurityAgent
): Promise<string> {
  const instance = agent ?? new CICDSecurityAgent();
  return instance.runSingleQuery(question);
}

// =============================================================================
// CLI Commands
// =============================================================================
program
  .name("cicd-agent")
  .description("CI/CD Security Agent - powered by Claude")
  .version("1.15.0")
  .option("-f, --format <format>", "Output format: json, table, markdown, text", "text")
  .option("-q, --quiet", "Suppress progress output (for CI usage)")
  .hook("preAction", (thisCommand) => {
    const opts = thisCommand.opts();
    if (opts.format) {
      setGlobalFormat(opts.format as OutputFormat);
    }
    if (opts.quiet) {
      setGlobalQuiet(true);
    }
  });

program
  .command("chat")
  .description("Start an interactive chat session")
  .action(async () => {
    await interactiveMode();
  });

program
  .command("scan <path>")
  .description("Scan a directory for vulnerabilities")
  .option("-s, --severity <levels>", "Severity levels", "HIGH,CRITICAL")
  .action(async (path: string, options) => {
    log(`\n🔍 Scanning ${path} for vulnerabilities...\n`);
    const response = await handleScanCommand(path, options.severity);
    console.log(response);
  });

program
  .command("scan-image <image>")
  .description("Scan a Docker image for vulnerabilities")
  .action(async (image: string) => {
    log(`\n🐳 Scanning image ${image}...\n`);
    const response = await handleScanImageCommand(image);
    console.log(response);
  });

program
  .command("status")
  .description("Check CI/CD platform status")
  .action(async () => {
    log("\n🔍 Checking platform status...\n");
    const response = await handleStatusCommand();
    console.log(response);
  });

program
  .command("repos")
  .description("List all repositories")
  .action(async () => {
    log("\n📚 Fetching repositories...\n");
    const response = await handleReposCommand();
    console.log(response);
  });

program
  .command("builds <owner> <repo>")
  .description("Show recent builds for a repository")
  .action(async (owner: string, repo: string) => {
    log(`\n🏗️ Fetching builds for ${owner}/${repo}...\n`);
    const response = await handleBuildsCommand(owner, repo);
    console.log(response);
  });

program
  .command("security-report [path]")
  .description("Generate a comprehensive security report")
  .action(async (path?: string) => {
    const targetPath = path || process.cwd();
    log(`\n📊 Generating security report for ${targetPath}...\n`);
    const response = await handleSecurityReportCommand(targetPath);
    console.log(response);
  });

program
  .command("migrate <github-url> <repo-name>")
  .description("Migrate a repository from GitHub to Gitea")
  .option("-t, --token <token>", "GitHub personal access token (for private repos)")
  .action(async (githubUrl: string, repoName: string, options) => {
    log(`\n📦 Migrating ${githubUrl} to Gitea as ${repoName}...\n`);
    const response = await handleMigrateCommand(githubUrl, repoName, !!options.token);
    console.log(response);
  });

program
  .command("ask <question...>")
  .description("Ask a single question")
  .action(async (questionParts: string[]) => {
    const question = questionParts.join(" ");
    log("\n🤖 Processing...\n");
    const response = await handleAskCommand(question);
    console.log(response);
  });

// Default to interactive mode if no command specified
program.action(async () => {
  await interactiveMode();
});

// Only run CLI when executed directly (not when imported)
const isMainModule = process.argv[1]?.includes("index") && !process.argv[1]?.includes(".test.");
if (isMainModule) {
  program.parse();
}
