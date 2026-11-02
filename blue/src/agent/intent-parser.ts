import { PurchaseIntent, PurchaseIntentSchema } from '../contracts/api';
import { toAtomicUnits } from '../contracts/constants';

const NUMBER_WORDS: Record<string, number> = {
  one: 1,
  two: 2,
  three: 3,
  four: 4,
  five: 5,
  six: 6,
  seven: 7,
  eight: 8,
  nine: 9,
  ten: 10,
};

/**
 * Deterministic local rule/regex based intent parser.
 * Operates offline with zero external dependencies, satisfying the prompt requirement
 * for 100% predictable automated test runs.
 */
export function parseShoppingIntent(input: string, inrPerTusd = 85): PurchaseIntent {
  const text = input.trim();
  const lower = text.toLowerCase();

  // 1. Extract Quantity
  let quantity = 1;
  const numMatch = lower.match(/\b(buy|purchase|get|order)?\s*([0-9]+)\s*(items?|pieces?|units?)?\b/);
  if (numMatch && numMatch[2]) {
    quantity = parseInt(numMatch[2], 10);
  } else {
    for (const [word, val] of Object.entries(NUMBER_WORDS)) {
      if (new RegExp(`\\b${word}\\b`).test(lower)) {
        quantity = val;
        break;
      }
    }
  }

  // 2. Extract Product Query
  let productQuery = 'mouse';
  if (lower.includes('mouse')) productQuery = 'mouse';
  else if (lower.includes('keyboard')) productQuery = 'keyboard';
  else if (lower.includes('cable') || lower.includes('usb')) productQuery = 'cable';
  else if (lower.includes('stand')) productQuery = 'stand';
  else if (lower.includes('headphone') || lower.includes('earphone')) productQuery = 'headphones';
  else if (lower.includes('monitor') || lower.includes('screen') || lower.includes('display')) productQuery = 'monitor';
  else {
    // Fallback: extract main noun phrase
    const cleaned = lower.replace(/buy|me|a|an|the|for|under|budget|of|total|inr|₹|[0-9]+/g, '').trim();
    if (cleaned) {
      productQuery = cleaned.split(/\s+/)[0];
    }
  }

  // 3. Extract Budget Cap (INR or TUSD)
  let maxTotalAtomic = '100000000'; // Default 100 TUSD
  const inrMatch = text.match(/(?:₹|inr|rs\.?)\s*([0-9]+(?:,[0-9]+)*(?:\.[0-9]+)?)/i);
  const tusdMatch = text.match(/(?:usd|tusd|\$)\s*([0-9]+(?:,[0-9]+)*(?:\.[0-9]+)?)/i);

  if (inrMatch && inrMatch[1]) {
    const inrVal = parseFloat(inrMatch[1].replace(/,/g, ''));
    const tusdVal = inrVal / inrPerTusd;
    maxTotalAtomic = toAtomicUnits(tusdVal.toFixed(6));
  } else if (tusdMatch && tusdMatch[1]) {
    const tusdVal = parseFloat(tusdMatch[1].replace(/,/g, ''));
    maxTotalAtomic = toAtomicUnits(tusdVal.toFixed(6));
  } else {
    // Generous default based on known product prices * quantity
    const defaultLimits: Record<string, number> = {
      mouse: 35,
      keyboard: 80,
      cable: 10,
      stand: 40,
      headphones: 100,
      monitor: 300,
    };
    const unitLimit = defaultLimits[productQuery] || 50;
    maxTotalAtomic = toAtomicUnits((unitLimit * quantity).toFixed(6));
  }

  return PurchaseIntentSchema.parse({
    product_query: productQuery,
    quantity,
    max_total_atomic: maxTotalAtomic,
    currency: 'TUSD',
  });
}
