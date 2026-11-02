import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { execSync } from 'node:child_process';
import { syncContracts } from './sync-contracts';

const ROOT_DIR = path.resolve(__dirname, '..');
const BLUE_DIR = path.join(ROOT_DIR, 'blue');
const RED_DIR = path.join(ROOT_DIR, 'red');
const DIST_DIR = path.join(ROOT_DIR, 'dist');

interface SeparabilityViolation {
  file: string;
  line: number;
  content: string;
  targetNode: 'blue' | 'red';
  forbiddenReference: string;
}

/**
 * Scans a directory recursively for cross-node imports.
 */
function scanForCrossImports(dir: string, fromNode: 'blue' | 'red'): SeparabilityViolation[] {
  const violations: SeparabilityViolation[] = [];
  const forbidden = fromNode === 'blue' ? 'red' : 'blue';
  const forbiddenPatterns = [
    new RegExp(`from\\s+['"][^'"]*\\/${forbidden}\\/`, 'i'),
    new RegExp(`from\\s+['"][^'"]*\\.\\.\\/${forbidden}`, 'i'),
    new RegExp(`require\\(['"][^'"]*\\/${forbidden}\\/`, 'i'),
    new RegExp(`require\\(['"][^'"]*\\.\\.\\/${forbidden}`, 'i'),
  ];

  function walk(currentDir: string) {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '.git') {
        continue;
      }
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile() && (entry.name.endsWith('.ts') || entry.name.endsWith('.js'))) {
        const content = fs.readFileSync(fullPath, 'utf8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          for (const pattern of forbiddenPatterns) {
            if (pattern.test(line)) {
              violations.push({
                file: path.relative(ROOT_DIR, fullPath).replace(/\\/g, '/'),
                line: i + 1,
                content: line.trim(),
                targetNode: fromNode,
                forbiddenReference: forbidden,
              });
            }
          }
        }
      }
    }
  }

  walk(dir);
  return violations;
}

/**
 * Computes SHA256 of a file.
 */
function getFileSha256(filePath: string): string {
  const fileBuffer = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(fileBuffer).digest('hex');
}

/**
 * Creates a zip archive using tar (built into Windows 10/11 and Linux/macOS)
 * or falls back to PowerShell Compress-Archive.
 */
function createZip(sourceDir: string, zipPath: string) {
  if (fs.existsSync(zipPath)) {
    fs.unlinkSync(zipPath);
  }

  try {
    // bsdtar with -a flag automatically determines zip format from extension
    execSync(`tar -a -c -f "${zipPath}" --exclude="node_modules" --exclude=".git" --exclude="*.db*" -C "${sourceDir}" .`, {
      stdio: 'pipe',
    });
  } catch {
    // Fallback: PowerShell Compress-Archive
    execSync(
      `powershell -Command "Get-ChildItem -Path '${sourceDir}' -Exclude 'node_modules','.git','*.db*' | Compress-Archive -DestinationPath '${zipPath}' -Force"`,
      { stdio: 'pipe' }
    );
  }
}

export function runSplit(): {
  success: boolean;
  blueZip: string;
  redZip: string;
  blueSha256: string;
  redSha256: string;
  contractsHash: string;
} {
  console.log('=================================================================');
  console.log(' [SPLIT] x402 RED-BLUE PACKAGING & SEPARABILITY AUDIT');
  console.log('=================================================================\n');

  // Step 1: Sync contracts first
  console.log('[1/4] Syncing contracts source of truth...');
  const contractsInfo = syncContracts();
  console.log(`      Contracts Version: ${contractsInfo.version}`);
  console.log(`      Contracts Hash:    ${contractsInfo.hash}\n`);

  // Step 2: Perform strict separability audit
  console.log('[2/4] Auditing cross-node runtime separability...');
  const blueViolations = scanForCrossImports(path.join(BLUE_DIR, 'src'), 'blue');
  const redViolations = scanForCrossImports(path.join(RED_DIR, 'src'), 'red');

  const totalViolations = [...blueViolations, ...redViolations];
  if (totalViolations.length > 0) {
    console.error(`\n❌ SEPARABILITY VIOLATION DETECTED: Found ${totalViolations.length} cross-node references!`);
    for (const v of totalViolations) {
      console.error(`   - [${v.targetNode.toUpperCase()}] ${v.file}:${v.line} -> ${v.content}`);
    }
    throw new Error(`Separability check failed with ${totalViolations.length} violations.`);
  }
  console.log('      ✓ ZERO cross-node runtime imports detected.');
  console.log('      ✓ Both nodes are 100% independent and deployable across separate laptops.\n');

  // Step 3: Prepare dist/ directory
  console.log('[3/4] Packaging deployable distribution zips in dist/...');
  if (!fs.existsSync(DIST_DIR)) {
    fs.mkdirSync(DIST_DIR, { recursive: true });
  }

  const blueZipPath = path.join(DIST_DIR, 'blue.zip');
  const redZipPath = path.join(DIST_DIR, 'red.zip');

  createZip(BLUE_DIR, blueZipPath);
  console.log(`      ✓ Created: dist/blue.zip (${(fs.statSync(blueZipPath).size / 1024).toFixed(1)} KB)`);

  createZip(RED_DIR, redZipPath);
  console.log(`      ✓ Created: dist/red.zip (${(fs.statSync(redZipPath).size / 1024).toFixed(1)} KB)\n`);

  // Step 4: Generate Manifest
  console.log('[4/4] Generating deployment manifest...');
  const blueSha256 = getFileSha256(blueZipPath);
  const redSha256 = getFileSha256(redZipPath);

  const manifest = {
    system: 'x402-red-blue',
    version: contractsInfo.version,
    contracts_hash: contractsInfo.hash,
    created_at: new Date().toISOString(),
    nodes: {
      blue: {
        node: 'DEFENDER (Laptop 1)',
        file: 'blue.zip',
        sha256: blueSha256,
        size_bytes: fs.statSync(blueZipPath).size,
        services: ['agent:4010', 'chain:4040', 'collector:4050'],
      },
      red: {
        node: 'ATTACKER (Laptop 2)',
        file: 'red.zip',
        sha256: redSha256,
        size_bytes: fs.statSync(redZipPath).size,
        services: ['merchant:4020', 'facilitator:4030', 'console:4060'],
      },
    },
  };

  const manifestPath = path.join(DIST_DIR, 'MANIFEST.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');
  console.log(`      ✓ Written: dist/MANIFEST.json`);

  console.log('\n=================================================================');
  console.log(' ✅ DISTRIBUTION PACKAGING COMPLETE');
  console.log(' Copy dist/blue.zip to Laptop 1 and dist/red.zip to Laptop 2.');
  console.log(' Run `npm install && npm start` on each machine over LAN.');
  console.log('=================================================================\n');

  return {
    success: true,
    blueZip: blueZipPath,
    redZip: redZipPath,
    blueSha256,
    redSha256,
    contractsHash: contractsInfo.hash,
  };
}

if (require.main === module || (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename))) {
  runSplit();
}
