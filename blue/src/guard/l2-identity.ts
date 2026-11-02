import { getAddress } from 'viem';
import { GuardBlockError } from '../contracts/x402-types';
import { EndpointsRegistry, RegistryEndpoint } from '../contracts/registry.schema';

export interface IdentityCheckParams {
  url: string;
  method: string;
  payTo: string;
  asset: string;
  network?: string;
  chainId?: number;
  registry: EndpointsRegistry;
}

export interface MatchedEndpoint {
  merchantId: string;
  endpoint: RegistryEndpoint;
}

/**
 * L2 Merchant & Asset Identity Verification Layer:
 * - Validates endpoint against registered endpoints
 * - Validates payTo is within allowlist for this endpoint (checksummed)
 * - Validates asset contract matches registered asset
 * - Validates network / chainId matches registered configuration
 */
export function checkIdentity(params: IdentityCheckParams): MatchedEndpoint {
  const { url, method, payTo, asset, network, chainId, registry } = params;

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new GuardBlockError('ENDPOINT_UNKNOWN', 'L2', `Invalid URL: ${url}`);
  }

  const origin = parsed.origin;
  const path = parsed.pathname;

  // 1. Match endpoint in registry
  let matchedMerchant: string | null = null;
  let matchedConfig: RegistryEndpoint | null = null;

  for (const [mId, mConfig] of Object.entries(registry.merchants)) {
    const configOrigin = new URL(mConfig.origin).origin;
    if (
      configOrigin === origin &&
      mConfig.method.toUpperCase() === method.toUpperCase() &&
      (mConfig.path === path || path.startsWith(mConfig.path))
    ) {
      matchedMerchant = mId;
      matchedConfig = mConfig;
      break;
    }
  }

  if (!matchedMerchant || !matchedConfig) {
    throw new GuardBlockError(
      'ENDPOINT_UNKNOWN',
      'L2',
      `Endpoint not registered in policy: ${method} ${origin}${path}`
    );
  }

  // 2. Validate PayTo address against allowedPayTos
  let checksummedPayTo: string;
  try {
    checksummedPayTo = getAddress(payTo);
  } catch {
    throw new GuardBlockError('PAYTO_MISMATCH', 'L2', `Malformed payTo address: ${payTo}`);
  }

  const allowedPayTosChecksummed = matchedConfig.allowedPayTos.map((addr) => {
    try {
      return getAddress(addr);
    } catch {
      return addr;
    }
  });

  if (!allowedPayTosChecksummed.includes(checksummedPayTo)) {
    throw new GuardBlockError(
      'PAYTO_MISMATCH',
      'L2',
      `payTo address ${payTo} is not in registered allowedPayTos for merchant ${matchedMerchant}`
    );
  }

  // 3. Validate Asset contract address
  let checksummedAsset: string;
  try {
    checksummedAsset = getAddress(asset);
  } catch {
    throw new GuardBlockError('ASSET_NOT_ALLOWED', 'L2', `Malformed asset address: ${asset}`);
  }

  let checksummedAllowedAsset: string;
  try {
    checksummedAllowedAsset = getAddress(matchedConfig.asset);
  } catch {
    checksummedAllowedAsset = matchedConfig.asset;
  }

  if (checksummedAsset !== checksummedAllowedAsset) {
    throw new GuardBlockError(
      'ASSET_NOT_ALLOWED',
      'L2',
      `Asset ${asset} does not match registered asset ${matchedConfig.asset}`
    );
  }

  // 4. Validate Network / ChainId
  if (chainId !== undefined && chainId !== matchedConfig.chainId) {
    throw new GuardBlockError(
      'NETWORK_NOT_ALLOWED',
      'L2',
      `ChainId ${chainId} does not match registered chainId ${matchedConfig.chainId}`
    );
  }

  if (network !== undefined) {
    const isBaseSepolia = network === 'base-sepolia' && (matchedConfig.chainId === 84532 || matchedConfig.chainId === 31337);
    const isLocal = network === 'hardhat' || network === 'local' || network === 'mock';
    if (!isBaseSepolia && !isLocal && matchedConfig.chainId !== 31337) {
      throw new GuardBlockError(
        'NETWORK_NOT_ALLOWED',
        'L2',
        `Network ${network} does not match registered network for chain ${matchedConfig.chainId}`
      );
    }
  }

  return {
    merchantId: matchedMerchant,
    endpoint: matchedConfig,
  };
}
