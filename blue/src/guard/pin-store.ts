import * as crypto from 'node:crypto';

export interface PinnedQuote {
  pin_id: string;
  intent_id: string;
  payTo: `0x${string}`;
  asset: `0x${string}`;
  amountAtomic: string;
  chainId: number;
  assetName: string;
  assetVersion: string;
  resource: string;
  expiresAt: number; // Unix timestamp ms
  consumed: boolean;
  consumedAt?: number;
}

export function computeQuoteHash(params: {
  payTo: string;
  asset: string;
  amountAtomic: string;
  chainId: number;
  assetName: string;
  assetVersion: string;
}): string {
  const normalized = {
    payTo: params.payTo.toLowerCase(),
    asset: params.asset.toLowerCase(),
    amountAtomic: params.amountAtomic,
    chainId: params.chainId,
    assetName: params.assetName,
    assetVersion: params.assetVersion,
  };
  const canonicalJson = JSON.stringify(normalized);
  return 'sha256:' + crypto.createHash('sha256').update(canonicalJson).digest('hex');
}

export class PinStore {
  private pins = new Map<string, PinnedQuote>();
  private consumedHashes = new Set<string>();

  /**
   * Pins an approved quote into the store.
   */
  pin(quote: Partial<PinnedQuote> & {
    payTo: string;
    asset: string;
    amountAtomic: string;
    chainId: number;
    assetName: string;
    assetVersion: string;
    maxWindowSeconds?: number;
  }): string {
    const hash = computeQuoteHash({
      payTo: quote.payTo,
      asset: quote.asset,
      amountAtomic: quote.amountAtomic,
      chainId: quote.chainId,
      assetName: quote.assetName,
      assetVersion: quote.assetVersion,
    });

    const now = Date.now();
    const expiresAt = quote.expiresAt || now + (quote.maxWindowSeconds || 30) * 1000;

    this.consumedHashes.delete(hash);
    this.pins.set(hash, {
      pin_id: quote.pin_id || crypto.randomUUID(),
      intent_id: quote.intent_id || crypto.randomUUID(),
      payTo: quote.payTo as `0x${string}`,
      asset: quote.asset as `0x${string}`,
      amountAtomic: quote.amountAtomic,
      chainId: quote.chainId,
      assetName: quote.assetName,
      assetVersion: quote.assetVersion,
      resource: quote.resource || '',
      expiresAt,
      consumed: false,
    });

    return hash;
  }

  /**
   * Retrieves a pinned quote by its hash.
   */
  get(hash: string): PinnedQuote | undefined {
    return this.pins.get(hash);
  }

  /**
   * Checks whether a hash has already been consumed.
   */
  isConsumed(hash: string): boolean {
    if (this.consumedHashes.has(hash)) {
      return true;
    }
    const quote = this.pins.get(hash);
    return quote ? quote.consumed : false;
  }

  /**
   * Atomically takes/consumes the pin. Returns null if not pinned or already consumed.
   */
  consume(hash: string): PinnedQuote | null {
    if (this.consumedHashes.has(hash)) {
      return null;
    }
    const quote = this.pins.get(hash);
    if (!quote || quote.consumed) {
      return null;
    }
    // Check expiry
    if (Date.now() > quote.expiresAt) {
      return null;
    }
    quote.consumed = true;
    quote.consumedAt = Date.now();
    this.consumedHashes.add(hash);
    return quote;
  }

  /**
   * Clears all pins (for testing / reset)
   */
  clear(): void {
    this.pins.clear();
    this.consumedHashes.clear();
  }
}
