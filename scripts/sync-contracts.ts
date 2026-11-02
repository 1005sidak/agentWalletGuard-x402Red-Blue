import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

const ROOT_DIR = path.resolve(__dirname, '..');
const SOURCE_DIR = path.join(ROOT_DIR, 'contracts');
const BLUE_TARGET_DIR = path.join(ROOT_DIR, 'blue', 'src', 'contracts');
const RED_TARGET_DIR = path.join(ROOT_DIR, 'red', 'src', 'contracts');

function getFilesRecursively(dir: string): string[] {
  let results: string[] = [];
  const list = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of list) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results = results.concat(getFilesRecursively(fullPath));
    } else if (entry.isFile() && !entry.name.endsWith('.hash.json')) {
      results.push(fullPath);
    }
  }
  return results;
}

export function computeContractsHash(): { hash: string; version: string; fileHashes: Record<string, string> } {
  const files = getFilesRecursively(SOURCE_DIR).sort();
  const hasher = crypto.createHash('sha256');
  const fileHashes: Record<string, string> = {};

  for (const file of files) {
    const rel = path.relative(SOURCE_DIR, file).replace(/\\/g, '/');
    const content = fs.readFileSync(file);
    const fileHash = crypto.createHash('sha256').update(content).digest('hex');
    fileHashes[rel] = fileHash;
    hasher.update(`${rel}:${fileHash}\n`);
  }

  const hash = `sha256:${hasher.digest('hex')}`;
  const versionFile = path.join(SOURCE_DIR, 'CONTRACTS_VERSION');
  const version = fs.existsSync(versionFile) ? fs.readFileSync(versionFile, 'utf8').trim() : '1.0.0';

  return { hash, version, fileHashes };
}

export function copyDirectory(src: string, dest: string) {
  fs.mkdirSync(dest, { recursive: true });
  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDirectory(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

export function syncContracts(): { hash: string; version: string } {
  if (!fs.existsSync(SOURCE_DIR)) {
    throw new Error(`Contracts source directory not found: ${SOURCE_DIR}`);
  }

  const { hash, version, fileHashes } = computeContractsHash();
  const manifest = {
    version,
    contracts_hash: hash,
    synced_at: new Date().toISOString(),
    files: fileHashes,
  };

  const manifestContent = JSON.stringify(manifest, null, 2) + '\n';
  fs.writeFileSync(path.join(SOURCE_DIR, 'contracts.hash.json'), manifestContent);

  // Sync to blue
  fs.rmSync(BLUE_TARGET_DIR, { recursive: true, force: true });
  copyDirectory(SOURCE_DIR, BLUE_TARGET_DIR);

  // Sync to red
  fs.rmSync(RED_TARGET_DIR, { recursive: true, force: true });
  copyDirectory(SOURCE_DIR, RED_TARGET_DIR);

  console.log(`[contracts-sync] Successfully synchronized contracts v${version}`);
  console.log(`[contracts-sync] Canonical Hash: ${hash}`);
  console.log(`[contracts-sync] Vendored targets:`);
  console.log(`  - ${path.relative(ROOT_DIR, BLUE_TARGET_DIR)}`);
  console.log(`  - ${path.relative(ROOT_DIR, RED_TARGET_DIR)}`);

  return { hash, version };
}

// Execute directly if run as CLI
if (require.main === module || (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename))) {
  syncContracts();
}
