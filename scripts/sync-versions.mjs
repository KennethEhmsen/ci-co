#!/usr/bin/env node
/**
 * Sync version across all workspace package.json files
 * Used by semantic-release to keep versions in sync
 */

import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');

const version = process.argv[2];

if (!version) {
  console.error('Usage: sync-versions.mjs <version>');
  process.exit(1);
}

const packages = ['shared', 'mcp-server', 'cicd-agent'];

for (const pkg of packages) {
  const pkgPath = join(rootDir, pkg, 'package.json');
  const pkgJson = JSON.parse(readFileSync(pkgPath, 'utf8'));
  pkgJson.version = version;
  writeFileSync(pkgPath, JSON.stringify(pkgJson, null, 2) + '\n');
  console.log(`Updated ${pkg}/package.json to version ${version}`);
}

console.log('All package versions synced successfully');
