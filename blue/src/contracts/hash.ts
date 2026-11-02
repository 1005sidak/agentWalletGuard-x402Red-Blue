import * as path from 'node:path';
import * as fs from 'node:fs';

/**
 * Returns the SHA256 canonical hash of the shared contracts package.
 * Returns an object with { hash, version } that also coerces to string (hash).
 */
export function getContractsHash(): { hash: string; version: string; toString(): string } {
  let hash = 'sha256:default';
  let version = '1.0.0';
  try {
    const hashFile = path.resolve(__dirname, 'contracts.hash.json');
    if (fs.existsSync(hashFile)) {
      const data = JSON.parse(fs.readFileSync(hashFile, 'utf8'));
      hash = data.contracts_hash || hash;
      version = data.version || version;
    }
  } catch {}

  return {
    hash,
    version,
    toString() {
      return hash;
    },
  };
}

/**
 * Returns the semantic version of the shared contracts package.
 */
export function getContractsVersion(): string {
  try {
    const versionFile = path.resolve(__dirname, 'CONTRACTS_VERSION');
    if (fs.existsSync(versionFile)) {
      return fs.readFileSync(versionFile, 'utf8').trim();
    }
  } catch {}
  return '1.0.0';
}
