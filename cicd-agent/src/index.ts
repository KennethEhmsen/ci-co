#!/usr/bin/env node

import Anthropic from "@anthropic-ai/sdk";
import { program } from "commander";
import * as readline from "node:readline";
import { config as dotenvConfig } from "dotenv";
import { tools, executeTool } from "./tools.js";

// Load environment variables
dotenvConfig();

// =============================================================================
// Agent Configuration
// =============================================================================
const SYSTEM_PROMPT = `You are a CI/CD Security Agent with access to a complete local development platform. You can help users with:

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
class CICDSecurityAgent {
  private readonly client: Anthropic;
  private conversationHistory: Anthropic.MessageParam[] = [];
  private readonly model = "claude-sonnet-4-20250514";

  constructor() {
    this.client = new Anthropic();
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
        console.log(`\n🔧 Using tool: ${toolUse.name}`);

        const result = await executeTool(
          toolUse.name,
          toolUse.input as Record<string, unknown>
        );

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
      } catch (error: any) {
        console.error(`\n❌ Error: ${error.message}`);
      }

      prompt();
    });
  };

  prompt();
}

// =============================================================================
// CLI Commands
// =============================================================================
program
  .name("cicd-agent")
  .description("CI/CD Security Agent - powered by Claude")
  .version("1.0.0");

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
    const agent = new CICDSecurityAgent();
    console.log(`\n🔍 Scanning ${path} for vulnerabilities...\n`);
    const response = await agent.runSingleQuery(
      `Scan the directory "${path}" for security vulnerabilities. Report severity ${options.severity} and above. Provide a summary of findings with recommendations.`
    );
    console.log(response);
  });

program
  .command("scan-image <image>")
  .description("Scan a Docker image for vulnerabilities")
  .action(async (image: string) => {
    const agent = new CICDSecurityAgent();
    console.log(`\n🐳 Scanning image ${image}...\n`);
    const response = await agent.runSingleQuery(
      `Scan the Docker image "${image}" for security vulnerabilities. Provide a summary of findings with severity levels and recommendations.`
    );
    console.log(response);
  });

program
  .command("status")
  .description("Check CI/CD platform status")
  .action(async () => {
    const agent = new CICDSecurityAgent();
    console.log("\n🔍 Checking platform status...\n");
    const response = await agent.runSingleQuery(
      "Check the health status of all CI/CD platform services and report which ones are available."
    );
    console.log(response);
  });

program
  .command("repos")
  .description("List all repositories")
  .action(async () => {
    const agent = new CICDSecurityAgent();
    console.log("\n📚 Fetching repositories...\n");
    const response = await agent.runSingleQuery(
      "List all repositories in Gitea with their details."
    );
    console.log(response);
  });

program
  .command("builds <owner> <repo>")
  .description("Show recent builds for a repository")
  .action(async (owner: string, repo: string) => {
    const agent = new CICDSecurityAgent();
    console.log(`\n🏗️ Fetching builds for ${owner}/${repo}...\n`);
    const response = await agent.runSingleQuery(
      `Show the recent CI/CD builds for the repository ${owner}/${repo}. Include build status, duration, and any failures.`
    );
    console.log(response);
  });

program
  .command("security-report [path]")
  .description("Generate a comprehensive security report")
  .action(async (path?: string) => {
    const agent = new CICDSecurityAgent();
    const targetPath = path || process.cwd();
    console.log(`\n📊 Generating security report for ${targetPath}...\n`);
    const response = await agent.runSingleQuery(
      `Generate a comprehensive security report for "${targetPath}".
      1. First scan with Trivy for dependency vulnerabilities
      2. Check if there's a SonarQube project and get its issues
      3. Check Dependency-Track for any tracked vulnerabilities
      4. Provide an executive summary with:
         - Total vulnerabilities by severity
         - Top 5 critical issues to fix
         - Recommendations for remediation`
    );
    console.log(response);
  });

program
  .command("migrate <github-url> <repo-name>")
  .description("Migrate a repository from GitHub to Gitea")
  .option("-t, --token <token>", "GitHub personal access token (for private repos)")
  .action(async (githubUrl: string, repoName: string, options) => {
    const agent = new CICDSecurityAgent();
    console.log(`\n📦 Migrating ${githubUrl} to Gitea as ${repoName}...\n`);
    const tokenInfo = options.token ? ` using the provided auth token` : "";
    const response = await agent.runSingleQuery(
      `Migrate the GitHub repository "${githubUrl}" to Gitea with the name "${repoName}"${tokenInfo}. Preserve issues, PRs, and releases. After migration, report the new repository URL.`
    );
    console.log(response);
  });

program
  .command("ask <question...>")
  .description("Ask a single question")
  .action(async (questionParts: string[]) => {
    const agent = new CICDSecurityAgent();
    const question = questionParts.join(" ");
    console.log("\n🤖 Processing...\n");
    const response = await agent.runSingleQuery(question);
    console.log(response);
  });

// Default to interactive mode if no command specified
program.action(async () => {
  await interactiveMode();
});

program.parse();
