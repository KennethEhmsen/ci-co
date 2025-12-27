/**
 * OPA Compiler Utilities
 *
 * Provides utilities for working with the OPA CLI to compile Rego policies
 * to WASM format. The OPA CLI must be installed separately.
 *
 * @see https://www.openpolicyagent.org/docs/latest/#1-download-opa
 */

import { exec } from "node:child_process";
import { promisify } from "node:util";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import type { OpaCompileOptions, OpaCompileResult } from "./types.js";

const execAsync = promisify(exec);

// =============================================================================
// OPA CLI DETECTION
// =============================================================================

/**
 * Check if the OPA CLI is installed and available
 */
export async function isOpaInstalled(): Promise<boolean> {
  try {
    await execAsync("opa version");
    return true;
  } catch {
    return false;
  }
}

/**
 * Get the installed OPA CLI version
 */
export async function getOpaVersion(): Promise<string | null> {
  try {
    const { stdout } = await execAsync("opa version");
    // Parse version from output like "Version: 0.60.0\nBuild Commit: ..."
    const match = stdout.match(/Version:\s*(\S+)/);
    return match ? match[1] : null;
  } catch {
    return null;
  }
}

/**
 * Get OPA installation instructions based on platform
 */
export function getOpaInstallInstructions(): string {
  const platform = os.platform();

  switch (platform) {
    case "darwin":
      return `Install OPA on macOS:
  brew install opa

Or download from: https://github.com/open-policy-agent/opa/releases`;

    case "linux":
      return `Install OPA on Linux:
  curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
  chmod 755 opa
  sudo mv opa /usr/local/bin/

Or use your package manager if available.`;

    case "win32":
      return `Install OPA on Windows:
  Download from: https://github.com/open-policy-agent/opa/releases
  Extract opa.exe and add to PATH

Or use: winget install OpenPolicyAgent.OPA`;

    default:
      return `Download OPA from: https://github.com/open-policy-agent/opa/releases`;
  }
}

// =============================================================================
// REGO TO WASM COMPILATION
// =============================================================================

/**
 * Compile a Rego policy to WASM format
 *
 * Requires the OPA CLI to be installed.
 * The compiled WASM can be loaded using @open-policy-agent/opa-wasm.
 *
 * @param regoSource - The Rego policy source code
 * @param options - Compilation options
 * @returns Compilation result with path to WASM file
 */
export async function compileRegoToWasm(
  regoSource: string,
  options: OpaCompileOptions
): Promise<OpaCompileResult> {
  // Check if OPA is installed
  const installed = await isOpaInstalled();
  if (!installed) {
    return {
      success: false,
      error: `OPA CLI is not installed.\n\n${getOpaInstallInstructions()}`,
    };
  }

  // Create temporary directory for compilation
  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "opa-"));
  const regoPath = path.join(tmpDir, "policy.rego");
  const wasmPath = options.outputPath || path.join(tmpDir, "policy.wasm");

  try {
    // Write Rego source to temp file
    await fs.promises.writeFile(regoPath, regoSource);

    // Build OPA compile command
    const args = ["build", "-t", "wasm", "-e", options.entrypoint, "-o", wasmPath];

    if (options.optimize) {
      args.push("-O2");
    }

    args.push(regoPath);

    // Run OPA compile
    const command = `opa ${args.join(" ")}`;
    await execAsync(command);

    // Verify the WASM file was created
    const exists = await fs.promises
      .access(wasmPath)
      .then(() => true)
      .catch(() => false);

    if (!exists) {
      return {
        success: false,
        error: "WASM file was not created",
      };
    }

    return {
      success: true,
      wasmPath,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      error: `Compilation failed: ${message}`,
    };
  } finally {
    // Clean up temp files if output path was specified (we copied there)
    if (options.outputPath) {
      await fs.promises.rm(tmpDir, { recursive: true, force: true });
    }
  }
}

/**
 * Compile a Rego file to WASM format
 */
export async function compileRegoFileToWasm(
  regoFilePath: string,
  options: OpaCompileOptions
): Promise<OpaCompileResult> {
  // Check if OPA is installed
  const installed = await isOpaInstalled();
  if (!installed) {
    return {
      success: false,
      error: `OPA CLI is not installed.\n\n${getOpaInstallInstructions()}`,
    };
  }

  // Verify the Rego file exists
  const exists = await fs.promises
    .access(regoFilePath)
    .then(() => true)
    .catch(() => false);

  if (!exists) {
    return {
      success: false,
      error: `Rego file not found: ${regoFilePath}`,
    };
  }

  // Create output path if not specified
  const wasmPath = options.outputPath || regoFilePath.replace(/\.rego$/, ".wasm");

  try {
    // Build OPA compile command
    const args = ["build", "-t", "wasm", "-e", options.entrypoint, "-o", wasmPath];

    if (options.optimize) {
      args.push("-O2");
    }

    args.push(regoFilePath);

    // Run OPA compile
    const command = `opa ${args.join(" ")}`;
    await execAsync(command);

    return {
      success: true,
      wasmPath,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      error: `Compilation failed: ${message}`,
    };
  }
}

// =============================================================================
// WASM POLICY LOADING (placeholder for opa-wasm integration)
// =============================================================================

/**
 * Load a compiled WASM policy file
 *
 * Note: This requires @open-policy-agent/opa-wasm to be installed.
 * This function provides the interface but actual loading requires
 * the opa-wasm package.
 */
export async function loadWasmPolicy(wasmPath: string): Promise<{
  success: boolean;
  policy?: unknown;
  error?: string;
}> {
  // Verify the WASM file exists
  const exists = await fs.promises
    .access(wasmPath)
    .then(() => true)
    .catch(() => false);

  if (!exists) {
    return {
      success: false,
      error: `WASM file not found: ${wasmPath}`,
    };
  }

  try {
    // Try to dynamically import opa-wasm
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const opaWasm = await (async () => {
      try {
        // Dynamic require to avoid compile-time dependency
        return require("@open-policy-agent/opa-wasm");
      } catch {
        return null;
      }
    })();

    if (!opaWasm) {
      return {
        success: false,
        error: `@open-policy-agent/opa-wasm is not installed. Install it with: npm install @open-policy-agent/opa-wasm`,
      };
    }

    const wasmBuffer = await fs.promises.readFile(wasmPath);
    const policy = await opaWasm.loadPolicy(wasmBuffer);

    return {
      success: true,
      policy,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);

    return {
      success: false,
      error: `Failed to load WASM policy: ${message}`,
    };
  }
}

// =============================================================================
// POLICY BUNDLE UTILITIES
// =============================================================================

/**
 * Create an OPA policy bundle from multiple Rego files
 */
export async function createPolicyBundle(
  regoFiles: string[],
  outputPath: string
): Promise<OpaCompileResult> {
  // Check if OPA is installed
  const installed = await isOpaInstalled();
  if (!installed) {
    return {
      success: false,
      error: `OPA CLI is not installed.\n\n${getOpaInstallInstructions()}`,
    };
  }

  try {
    // Build OPA bundle command
    const args = ["build", "-b", "-o", outputPath, ...regoFiles];
    const command = `opa ${args.join(" ")}`;

    await execAsync(command);

    return {
      success: true,
      wasmPath: outputPath,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      error: `Bundle creation failed: ${message}`,
    };
  }
}

/**
 * Check a Rego file for syntax errors using OPA
 */
export async function checkRegoSyntax(
  regoSource: string
): Promise<{ valid: boolean; errors?: string[] }> {
  // Check if OPA is installed
  const installed = await isOpaInstalled();
  if (!installed) {
    // Fall back to basic validation without OPA
    const errors: string[] = [];

    if (!regoSource.includes("package ")) {
      errors.push("Missing package declaration");
    }

    const openBraces = (regoSource.match(/{/g) || []).length;
    const closeBraces = (regoSource.match(/}/g) || []).length;
    if (openBraces !== closeBraces) {
      errors.push("Unbalanced braces");
    }

    return {
      valid: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined,
    };
  }

  // Create temp file for OPA check
  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "opa-check-"));
  const regoPath = path.join(tmpDir, "policy.rego");

  try {
    await fs.promises.writeFile(regoPath, regoSource);

    const { stderr } = await execAsync(`opa check ${regoPath}`);

    if (stderr) {
      return {
        valid: false,
        errors: [stderr],
      };
    }

    return { valid: true };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      valid: false,
      errors: [message],
    };
  } finally {
    await fs.promises.rm(tmpDir, { recursive: true, force: true });
  }
}

/**
 * Format Rego source code using OPA
 */
export async function formatRego(regoSource: string): Promise<{
  success: boolean;
  formatted?: string;
  error?: string;
}> {
  // Check if OPA is installed
  const installed = await isOpaInstalled();
  if (!installed) {
    return {
      success: false,
      error: `OPA CLI is not installed.\n\n${getOpaInstallInstructions()}`,
    };
  }

  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "opa-fmt-"));
  const regoPath = path.join(tmpDir, "policy.rego");

  try {
    await fs.promises.writeFile(regoPath, regoSource);

    const { stdout } = await execAsync(`opa fmt ${regoPath}`);

    return {
      success: true,
      formatted: stdout,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      error: `Formatting failed: ${message}`,
    };
  } finally {
    await fs.promises.rm(tmpDir, { recursive: true, force: true });
  }
}
