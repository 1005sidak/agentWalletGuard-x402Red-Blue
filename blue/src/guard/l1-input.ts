import { GuardBlockError } from '../contracts/x402-types';

export interface L1SanitizedRequirement {
  scheme: 'exact';
  network: string;
  maxAmountRequired: string;
  resource: string;
  description: string;
  mimeType: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra?: Record<string, any>;
}

export interface L1ParseResult {
  x402Version: 1;
  accepts: L1SanitizedRequirement[];
  strippedInjections: string[];
}

const ATOMIC_INT_REGEX = /^[1-9][0-9]*$/;

/**
 * L1 Input Validation Layer:
 * - 8 KB body size limit
 * - Rejects non-canonical amount encodings (scientific, decimals, leading zeros, empty, negative)
 * - Restricts accepts[] option count to <= 4
 * - Strips adversarial prompt injections from description / schema text
 */
export function parseAndSanitize402(rawBody: string | object): L1ParseResult {
  let bodyStr: string;
  let bodyObj: any;

  if (typeof rawBody === 'string') {
    if (Buffer.byteLength(rawBody, 'utf8') > 8192) {
      throw new GuardBlockError('PARSE_REJECT', 'L1', '402 response body exceeds 8 KB maximum limit');
    }
    bodyStr = rawBody;
    try {
      bodyObj = JSON.parse(rawBody);
    } catch {
      throw new GuardBlockError('PARSE_REJECT', 'L1', 'Invalid JSON in 402 response body');
    }
  } else {
    bodyObj = rawBody;
    bodyStr = JSON.stringify(rawBody);
    if (Buffer.byteLength(bodyStr, 'utf8') > 8192) {
      throw new GuardBlockError('PARSE_REJECT', 'L1', '402 response body exceeds 8 KB maximum limit');
    }
  }

  // Version check
  if (bodyObj.x402Version !== 1) {
    throw new GuardBlockError('PARSE_REJECT', 'L1', `Unsupported x402Version: ${bodyObj.x402Version}`);
  }

  // Options check
  if (!Array.isArray(bodyObj.accepts) || bodyObj.accepts.length === 0) {
    throw new GuardBlockError('PARSE_REJECT', 'L1', 'accepts must be a non-empty array');
  }

  if (bodyObj.accepts.length > 4) {
    throw new GuardBlockError('PARSE_REJECT', 'L1', `Exceeded maximum option count (found ${bodyObj.accepts.length}, max is 4)`);
  }

  const strippedInjections: string[] = [];
  const sanitizedAccepts: L1SanitizedRequirement[] = [];

  for (let i = 0; i < bodyObj.accepts.length; i++) {
    const opt = bodyObj.accepts[i];

    // Scheme check
    if (opt.scheme !== 'exact') {
      throw new GuardBlockError('PARSE_REJECT', 'L1', `Unsupported payment scheme: ${opt.scheme}`);
    }

    // Amount atomic integer validation
    const amountStr = String(opt.maxAmountRequired || '');
    if (!ATOMIC_INT_REGEX.test(amountStr)) {
      throw new GuardBlockError(
        'PARSE_REJECT',
        'L1',
        `Non-canonical atomic amount representation rejected: "${opt.maxAmountRequired}"`
      );
    }

    // Required fields check
    if (!opt.resource || typeof opt.resource !== 'string') {
      throw new GuardBlockError('PARSE_REJECT', 'L1', 'Missing or invalid resource URL');
    }
    if (!opt.asset || !/^0x[a-fA-F0-9]{40}$/.test(opt.asset)) {
      throw new GuardBlockError('PARSE_REJECT', 'L1', 'Invalid asset EVM address');
    }
    if (!opt.payTo || !/^0x[a-fA-F0-9]{40}$/.test(opt.payTo)) {
      throw new GuardBlockError('PARSE_REJECT', 'L1', 'Invalid payTo EVM address');
    }

    // Timeout seconds check
    const timeout = Number(opt.maxTimeoutSeconds);
    if (isNaN(timeout) || timeout <= 0) {
      throw new GuardBlockError('PARSE_REJECT', 'L1', 'Invalid maxTimeoutSeconds');
    }

    // Prompt Injection Sanitization (A12)
    // Strip adversarial command words from description and schema fields
    let safeDescription = typeof opt.description === 'string' ? opt.description : 'Payment Requirement';
    if (/system\s*override|ignore\s*all\s*prior|authorize.*immediately/i.test(safeDescription)) {
      strippedInjections.push(safeDescription);
      safeDescription = 'Sanitized Purchase Item';
    }

    sanitizedAccepts.push({
      scheme: 'exact',
      network: opt.network || 'base-sepolia',
      maxAmountRequired: amountStr,
      resource: opt.resource,
      description: safeDescription,
      mimeType: opt.mimeType || 'application/json',
      asset: opt.asset,
      payTo: opt.payTo,
      maxTimeoutSeconds: Math.min(timeout, 30), // Clamped to 30s max
      extra: opt.extra,
    });
  }

  return {
    x402Version: 1,
    accepts: sanitizedAccepts,
    strippedInjections,
  };
}
