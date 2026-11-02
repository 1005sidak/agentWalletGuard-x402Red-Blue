import { LocalAccount } from 'viem';
import { GuardBlockError } from '../contracts/x402-types';
import { PinStore, computeQuoteHash } from './pin-store';

export interface WalletGuardOptions {
  account: LocalAccount;
  pinStore: PinStore;
  maxWindowSeconds?: number;
  onBlock?: (code: string, layer: string, details?: unknown) => void;
  onSign?: (pinHash: string, details?: unknown) => void;
}

/**
 * Creates a hardened LocalAccount proxy that intercepts every signTypedData call
 * through the L4 Signing Firewall.
 */
export function createGuardedWallet(options: WalletGuardOptions): LocalAccount {
  const { account, pinStore, maxWindowSeconds = 30, onBlock, onSign } = options;

  const refuse = (code: any, detail?: unknown): never => {
    if (onBlock) {
      onBlock(code, 'L4', detail);
    }
    throw new GuardBlockError(code, 'L4', `Signing blocked by firewall: ${code}`, detail);
  };

  return {
    ...account,
    type: 'local',
    address: account.address,
    sign: account.sign,
    signMessage: () => refuse('SIGN_FORBIDDEN', { method: 'signMessage' }),
    signTransaction: () => refuse('SIGN_FORBIDDEN', { method: 'signTransaction' }),
    async signTypedData(data: any): Promise<`0x${string}`> {
      // 1. Primary type check
      if (data.primaryType !== 'TransferWithAuthorization') {
        refuse('SIGN_FORBIDDEN', { primaryType: data.primaryType });
      }

      const domain = data.domain || {};
      const message = data.message || {};

      // 2. Validity Window validation
      // Note: x402-fetch sets validAfter = now - 600s (for clock drift tolerance) and
      // validBefore = now + maxTimeoutSeconds. The active spendable window is measured from now to validBefore.
      const validBefore = BigInt(message.validBefore || 0);
      const nowSeconds = Math.floor(Date.now() / 1000);
      const remainingSeconds = Number(validBefore) - nowSeconds;

      // Allow 5s buffer for execution jitter, but strictly reject anything exceeding maxWindowSeconds + 5 (e.g. A9 attacks)
      if (remainingSeconds > maxWindowSeconds + 5 || remainingSeconds < -5) {
        refuse('WINDOW_TOO_LONG', { remainingSeconds, maxWindowSeconds, validBefore: Number(validBefore), nowSeconds });
      }

      // 3. Reconstruct quote hash
      const quoteHash = computeQuoteHash({
        payTo: message.to,
        asset: domain.verifyingContract,
        amountAtomic: message.value.toString(),
        chainId: Number(domain.chainId),
        assetName: domain.name,
        assetVersion: domain.version,
      });

      // 4. Pin validation
      const pinned = pinStore.get(quoteHash);
      if (!pinned) {
        refuse('SIGN_UNPINNED', { quoteHash, targetPayTo: message.to });
      }

      if (pinStore.isConsumed(quoteHash)) {
        refuse('PIN_CONSUMED', { quoteHash });
      }

      // 5. Verify fields match pinned authorization
      if (pinned.payTo.toLowerCase() !== message.to.toLowerCase()) {
        refuse('QUOTE_CHANGED', { expectedPayTo: pinned.payTo, actualPayTo: message.to });
      }
      if (pinned.amountAtomic !== message.value.toString()) {
        refuse('QUOTE_CHANGED', { expectedAmount: pinned.amountAtomic, actualAmount: message.value.toString() });
      }
      if (pinned.asset.toLowerCase() !== domain.verifyingContract.toLowerCase()) {
        refuse('QUOTE_CHANGED', { expectedAsset: pinned.asset, actualAsset: domain.verifyingContract });
      }
      if (pinned.chainId !== Number(domain.chainId)) {
        refuse('QUOTE_CHANGED', { expectedChainId: pinned.chainId, actualChainId: Number(domain.chainId) });
      }

      // 6. Atomically consume pin
      const consumed = pinStore.consume(quoteHash);
      if (!consumed) {
        refuse('PIN_CONSUMED', { quoteHash });
      }

      // 7. Perform genuine signature
      const signature = await account.signTypedData(data);
      if (onSign) {
        onSign(quoteHash, { to: message.to, value: message.value.toString() });
      }

      return signature;
    },
  };
}
