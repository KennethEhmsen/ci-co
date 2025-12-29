/**
 * Dependency Updater Module
 *
 * Checks for available updates, previews impact, and applies dependency
 * updates across multiple package managers.
 */

import { execFile } from "child_process";
import { promisify } from "util";
import * as fs from "fs";
import * as path from "path";
import type { PackageManager } from "./types.js";

const execFileAsync = promisify(execFile);

// =============================================================================
// Types
// =============================================================================

/** Available update information */
export interface AvailableUpdate {
  package: string;
  currentVersion: string;
  latestVersion: string;
  wantedVersion: string;
  updateType: "major" | "minor" | "patch" | "prerelease";
  isBreaking: boolean;
  changelog?: string;
  releaseDate?: string;
  packageManager: PackageManager;
}

/** Update check result */
export interface UpdateCheckResult {
  packageManager: PackageManager;
  updates: AvailableUpdate[];
  totalUpdates: number;
  majorUpdates: number;
  minorUpdates: number;
  patchUpdates: number;
  error?: string;
}

/** Update preview */
export interface UpdatePreview {
  package: string;
  currentVersion: string;
  targetVersion: string;
  breakingChanges: string[];
  deprecations: string[];
  dependencies: string[];
  riskLevel: "low" | "medium" | "high";
  recommendedAction: "update" | "skip" | "manual-review";
}

/** Update apply result */
export interface UpdateApplyResult {
  success: boolean;
  package: string;
  previousVersion: string;
  newVersion: string;
  command: string;
  output: string;
  error?: string;
}

/** Batch update result */
export interface BatchUpdateResult {
  total: number;
  succeeded: number;
  failed: number;
  skipped: number;
  results: UpdateApplyResult[];
  rollbackAvailable: boolean;
}

// =============================================================================
// Version Utilities
// =============================================================================

/**
 * Parse semantic version
 */
function parseVersion(version: string): { major: number; minor: number; patch: number } | null {
  const match = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (!match) return null;
  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10),
  };
}

/**
 * Determine update type between versions
 */
export function getUpdateType(
  currentVersion: string,
  newVersion: string
): "major" | "minor" | "patch" | "prerelease" {
  const current = parseVersion(currentVersion);
  const next = parseVersion(newVersion);

  if (!current || !next) {
    return "patch";
  }

  if (next.major > current.major) {
    return "major";
  }
  if (next.minor > current.minor) {
    return "minor";
  }
  if (next.patch > current.patch) {
    return "patch";
  }

  // Check for prerelease
  if (newVersion.includes("-")) {
    return "prerelease";
  }

  return "patch";
}

/**
 * Check if update is breaking
 */
export function isBreakingUpdate(currentVersion: string, newVersion: string): boolean {
  return getUpdateType(currentVersion, newVersion) === "major";
}

// =============================================================================
// Package Manager Detection
// =============================================================================

/**
 * Detect package manager from project files
 */
export function detectPackageManager(projectPath: string): PackageManager {
  const checks: Array<[string, PackageManager]> = [
    ["pnpm-lock.yaml", "pnpm"],
    ["yarn.lock", "yarn"],
    ["package-lock.json", "npm"],
    ["Pipfile.lock", "pipenv"],
    ["poetry.lock", "poetry"],
    ["requirements.txt", "pip"],
    ["go.sum", "go"],
    ["Cargo.lock", "cargo"],
    ["Gemfile.lock", "gem"],
    ["pom.xml", "maven"],
    ["build.gradle", "gradle"],
  ];

  for (const [file, manager] of checks) {
    if (fs.existsSync(path.join(projectPath, file))) {
      return manager;
    }
  }

  return "npm"; // Default
}

// =============================================================================
// Update Checking
// =============================================================================

/**
 * Check for available npm updates using execFile (safe from injection)
 */
async function checkNpmUpdates(projectPath: string): Promise<AvailableUpdate[]> {
  try {
    const { stdout } = await execFileAsync("npm", ["outdated", "--json"], {
      cwd: projectPath,
    });

    const data = JSON.parse(stdout || "{}") as Record<
      string,
      { current: string; wanted: string; latest: string }
    >;
    const updates: AvailableUpdate[] = [];

    for (const [pkg, info] of Object.entries(data)) {
      updates.push({
        package: pkg,
        currentVersion: info.current,
        wantedVersion: info.wanted,
        latestVersion: info.latest,
        updateType: getUpdateType(info.current, info.latest),
        isBreaking: isBreakingUpdate(info.current, info.latest),
        packageManager: "npm",
      });
    }

    return updates;
  } catch (error) {
    // npm outdated exits with code 1 when there are outdated packages
    if (error instanceof Error && "stdout" in error) {
      try {
        const data = JSON.parse((error as { stdout: string }).stdout || "{}") as Record<
          string,
          { current: string; wanted: string; latest: string }
        >;
        const updates: AvailableUpdate[] = [];

        for (const [pkg, info] of Object.entries(data)) {
          updates.push({
            package: pkg,
            currentVersion: info.current,
            wantedVersion: info.wanted,
            latestVersion: info.latest,
            updateType: getUpdateType(info.current, info.latest),
            isBreaking: isBreakingUpdate(info.current, info.latest),
            packageManager: "npm",
          });
        }

        return updates;
      } catch {
        return [];
      }
    }
    return [];
  }
}

/**
 * Check for available pip updates using execFile (safe from injection)
 */
async function checkPipUpdates(projectPath: string): Promise<AvailableUpdate[]> {
  try {
    const { stdout } = await execFileAsync("pip", ["list", "--outdated", "--format=json"], {
      cwd: projectPath,
    });

    const data = JSON.parse(stdout) as Array<{
      name: string;
      version: string;
      latest_version: string;
    }>;

    return data.map((pkg) => ({
      package: pkg.name,
      currentVersion: pkg.version,
      wantedVersion: pkg.latest_version,
      latestVersion: pkg.latest_version,
      updateType: getUpdateType(pkg.version, pkg.latest_version),
      isBreaking: isBreakingUpdate(pkg.version, pkg.latest_version),
      packageManager: "pip" as PackageManager,
    }));
  } catch {
    return [];
  }
}

/**
 * Check for available Go module updates using execFile (safe from injection)
 */
async function checkGoUpdates(projectPath: string): Promise<AvailableUpdate[]> {
  try {
    const { stdout } = await execFileAsync("go", ["list", "-m", "-u", "-json", "all"], {
      cwd: projectPath,
    });

    const updates: AvailableUpdate[] = [];
    const lines = stdout.trim().split("\n");
    let buffer = "";

    for (const line of lines) {
      buffer += line;
      try {
        const mod = JSON.parse(buffer) as {
          Path: string;
          Version: string;
          Update?: { Version: string };
        };
        buffer = "";

        if (mod.Update) {
          updates.push({
            package: mod.Path,
            currentVersion: mod.Version,
            wantedVersion: mod.Update.Version,
            latestVersion: mod.Update.Version,
            updateType: getUpdateType(mod.Version, mod.Update.Version),
            isBreaking: isBreakingUpdate(mod.Version, mod.Update.Version),
            packageManager: "go",
          });
        }
      } catch {
        // Continue accumulating buffer for multi-line JSON
      }
    }

    return updates;
  } catch {
    return [];
  }
}

/**
 * Check for available updates
 */
export async function checkUpdates(
  projectPath: string,
  options: { packageManager?: PackageManager } = {}
): Promise<UpdateCheckResult> {
  const packageManager = options.packageManager || detectPackageManager(projectPath);
  let updates: AvailableUpdate[] = [];
  let error: string | undefined;

  try {
    switch (packageManager) {
      case "npm":
      case "yarn":
      case "pnpm":
        updates = await checkNpmUpdates(projectPath);
        break;
      case "pip":
      case "pipenv":
      case "poetry":
        updates = await checkPipUpdates(projectPath);
        break;
      case "go":
        updates = await checkGoUpdates(projectPath);
        break;
      default:
        error = `Package manager ${packageManager} not yet supported for update checking`;
    }
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  const majorUpdates = updates.filter((u) => u.updateType === "major").length;
  const minorUpdates = updates.filter((u) => u.updateType === "minor").length;
  const patchUpdates = updates.filter((u) => u.updateType === "patch").length;

  return {
    packageManager,
    updates,
    totalUpdates: updates.length,
    majorUpdates,
    minorUpdates,
    patchUpdates,
    error,
  };
}

// =============================================================================
// Update Preview
// =============================================================================

/**
 * Preview an update with risk assessment
 */
export async function previewUpdate(
  packageName: string,
  targetVersion: string,
  options: {
    projectPath?: string;
    packageManager?: PackageManager;
    currentVersion?: string;
  } = {}
): Promise<UpdatePreview> {
  const currentVersion = options.currentVersion || "0.0.0";
  const updateType = getUpdateType(currentVersion, targetVersion);

  // Determine risk level
  let riskLevel: "low" | "medium" | "high" = "low";
  let recommendedAction: "update" | "skip" | "manual-review" = "update";

  if (updateType === "major") {
    riskLevel = "high";
    recommendedAction = "manual-review";
  } else if (updateType === "minor") {
    riskLevel = "medium";
  }

  // Basic preview - in a full implementation, this would fetch changelog
  return {
    package: packageName,
    currentVersion,
    targetVersion,
    breakingChanges:
      updateType === "major" ? ["Major version update - may have breaking changes"] : [],
    deprecations: [],
    dependencies: [],
    riskLevel,
    recommendedAction,
  };
}

// =============================================================================
// Update Application
// =============================================================================

/**
 * Get command and args for package update (uses execFile for safety)
 */
function getUpdateCommand(
  packageName: string,
  targetVersion: string,
  packageManager: PackageManager
): { cmd: string; args: string[] } | null {
  // Validate package name and version to prevent injection
  if (!/^[@a-zA-Z0-9/_.-]+$/.test(packageName)) {
    return null;
  }
  if (!/^[a-zA-Z0-9._-]+$/.test(targetVersion)) {
    return null;
  }

  switch (packageManager) {
    case "npm":
      return { cmd: "npm", args: ["install", `${packageName}@${targetVersion}`] };
    case "yarn":
      return { cmd: "yarn", args: ["add", `${packageName}@${targetVersion}`] };
    case "pnpm":
      return { cmd: "pnpm", args: ["add", `${packageName}@${targetVersion}`] };
    case "pip":
      return { cmd: "pip", args: ["install", `${packageName}==${targetVersion}`] };
    case "go":
      return { cmd: "go", args: ["get", `${packageName}@${targetVersion}`] };
    case "cargo":
      return { cmd: "cargo", args: ["update", "-p", packageName, "--precise", targetVersion] };
    default:
      return null;
  }
}

/**
 * Apply a single update using execFile (safe from injection)
 */
export async function applyUpdate(
  packageName: string,
  targetVersion: string,
  options: {
    projectPath?: string;
    packageManager?: PackageManager;
    dryRun?: boolean;
  } = {}
): Promise<UpdateApplyResult> {
  const { projectPath = ".", packageManager = "npm", dryRun = false } = options;

  const cmdInfo = getUpdateCommand(packageName, targetVersion, packageManager);

  if (!cmdInfo) {
    return {
      success: false,
      package: packageName,
      previousVersion: "",
      newVersion: targetVersion,
      command: "",
      output: "",
      error: `Package manager ${packageManager} not supported or invalid package name`,
    };
  }

  const command = `${cmdInfo.cmd} ${cmdInfo.args.join(" ")}`;

  if (dryRun) {
    return {
      success: true,
      package: packageName,
      previousVersion: "",
      newVersion: targetVersion,
      command,
      output: "(dry run - no changes made)",
    };
  }

  try {
    const { stdout, stderr } = await execFileAsync(cmdInfo.cmd, cmdInfo.args, {
      cwd: projectPath,
    });

    return {
      success: true,
      package: packageName,
      previousVersion: "",
      newVersion: targetVersion,
      command,
      output: stdout + (stderr ? `\n${stderr}` : ""),
    };
  } catch (error) {
    return {
      success: false,
      package: packageName,
      previousVersion: "",
      newVersion: targetVersion,
      command,
      output: "",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Apply multiple updates
 */
export async function applyUpdates(
  updates: Array<{ package: string; version: string }>,
  options: {
    projectPath?: string;
    packageManager?: PackageManager;
    dryRun?: boolean;
    stopOnError?: boolean;
  } = {}
): Promise<BatchUpdateResult> {
  const {
    projectPath = ".",
    stopOnError = false,
    dryRun = false,
    packageManager = "npm",
  } = options;
  const result: BatchUpdateResult = {
    total: updates.length,
    succeeded: 0,
    failed: 0,
    skipped: 0,
    results: [],
    rollbackAvailable: false,
  };

  // Save rollback state (lockfile)
  try {
    let lockfile = "";

    switch (packageManager) {
      case "npm":
        lockfile = path.join(projectPath, "package-lock.json");
        break;
      case "yarn":
        lockfile = path.join(projectPath, "yarn.lock");
        break;
      case "pnpm":
        lockfile = path.join(projectPath, "pnpm-lock.yaml");
        break;
    }

    if (lockfile && fs.existsSync(lockfile) && !dryRun) {
      const backupPath = `${lockfile}.backup-${Date.now()}`;
      fs.copyFileSync(lockfile, backupPath);
      result.rollbackAvailable = true;
    }
  } catch {
    // Continue without rollback capability
  }

  for (const update of updates) {
    const updateResult = await applyUpdate(update.package, update.version, {
      projectPath,
      packageManager,
      dryRun,
    });

    result.results.push(updateResult);

    if (updateResult.success) {
      result.succeeded++;
    } else {
      result.failed++;
      if (stopOnError) {
        result.skipped = updates.length - result.succeeded - result.failed;
        break;
      }
    }
  }

  return result;
}

/**
 * Rollback to previous state using execFile (safe from injection)
 */
export async function rollbackUpdates(
  options: {
    projectPath?: string;
    packageManager?: PackageManager;
  } = {}
): Promise<{ success: boolean; message: string }> {
  const { projectPath = ".", packageManager = "npm" } = options;

  let lockfile = "";
  switch (packageManager) {
    case "npm":
      lockfile = path.join(projectPath, "package-lock.json");
      break;
    case "yarn":
      lockfile = path.join(projectPath, "yarn.lock");
      break;
    case "pnpm":
      lockfile = path.join(projectPath, "pnpm-lock.yaml");
      break;
  }

  if (!lockfile) {
    return {
      success: false,
      message: `Rollback not supported for ${packageManager}`,
    };
  }

  // Find backup file
  const dir = path.dirname(lockfile);
  const basename = path.basename(lockfile);
  const files = fs.readdirSync(dir) as string[];
  const backups = files
    .filter((f: string) => f.startsWith(`${basename}.backup-`))
    .sort()
    .reverse();

  if (backups.length === 0) {
    return {
      success: false,
      message: "No backup file found",
    };
  }

  const backupFile = path.join(dir, backups[0]);

  try {
    fs.copyFileSync(backupFile, lockfile);

    // Reinstall from lockfile using execFile (safe)
    let cmd = "";
    let args: string[] = [];
    switch (packageManager) {
      case "npm":
        cmd = "npm";
        args = ["ci"];
        break;
      case "yarn":
        cmd = "yarn";
        args = ["install", "--frozen-lockfile"];
        break;
      case "pnpm":
        cmd = "pnpm";
        args = ["install", "--frozen-lockfile"];
        break;
    }

    if (cmd) {
      await execFileAsync(cmd, args, { cwd: projectPath });
    }

    // Remove backup
    fs.unlinkSync(backupFile);

    return {
      success: true,
      message: `Rolled back to ${backupFile}`,
    };
  } catch (error) {
    return {
      success: false,
      message: error instanceof Error ? error.message : String(error),
    };
  }
}
