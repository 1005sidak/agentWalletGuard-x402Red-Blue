/**
 * Shared constants for the x402 Red-Blue payment security system.
 */

export const TOKEN_DECIMALS = 6;
export const TOKEN_SYMBOL = 'TUSD';
export const TOKEN_NAME = 'Test USD';
export const TOKEN_VERSION = '1';
export const CHAIN_ID = 31337;

export const DEFAULT_PORTS = {
  BLUE_AGENT: 4010,
  RED_MERCHANT: 4020,
  RED_FACILITATOR: 4030,
  BLUE_CHAIN: 4040,
  BLUE_COLLECTOR: 4050,
  RED_CONSOLE: 4060,
} as const;

export const MAX_PAYMENT_WINDOW_SECONDS = 30;

/**
 * Converts decimal token amount (e.g. 1.5 or "1.5") to atomic unit integer string (e.g. "1500000").
 */
export function toAtomicUnits(amount: number | string, decimals = TOKEN_DECIMALS): string {
  const str = String(amount).trim();
  if (!str) return '0';
  if (!/^[0-9]+(\.[0-9]+)?$/.test(str)) {
    throw new Error(`Invalid decimal amount format: ${amount}`);
  }
  const [whole, frac = ''] = str.split('.');
  const paddedFrac = frac.padEnd(decimals, '0').slice(0, decimals);
  const combined = (whole === '0' ? '' : whole) + paddedFrac;
  const result = combined.replace(/^0+/, '');
  return result === '' ? '0' : result;
}

/**
 * Converts atomic unit integer string (e.g. "1500000") to formatted decimal string (e.g. "1.500000").
 */
export function fromAtomicUnits(atomic: string, decimals = TOKEN_DECIMALS): string {
  if (!/^[0-9]+$/.test(atomic)) {
    return '0.000000';
  }
  const padded = atomic.padStart(decimals + 1, '0');
  const whole = padded.slice(0, -decimals);
  const frac = padded.slice(-decimals);
  return `${whole}.${frac}`;
}

/**
 * Converts atomic units to INR display value using fixed conversion rate.
 */
export function inrFromAtomic(atomic: string, inrPerTusd: number, decimals = TOKEN_DECIMALS): string {
  const tusd = Number(fromAtomicUnits(atomic, decimals));
  const inr = tusd * inrPerTusd;
  return `₹${inr.toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}
