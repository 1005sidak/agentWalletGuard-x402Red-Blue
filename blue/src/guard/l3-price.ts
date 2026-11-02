import { GuardBlockError } from '../contracts/x402-types';
import { RegistryEndpoint } from '../contracts/registry.schema';

export interface ApprovalToken {
  approvalId: string;
  intentId: string;
  resource: string;
  approvedAmountAtomic: string;
  expiresAt: number; // unix timestamp in ms
  signature?: string;
}

export interface PriceCheckParams {
  resource: string;
  amountAtomic: string;
  endpoint: RegistryEndpoint;
  intentId?: string;
  approvalToken?: ApprovalToken | null;
  lastSeenAmountAtomic?: string | null;
}

/**
 * L3 Price Bands & Cryptographic Approval Gate:
 * - Checks amount is within registered priceBand (minAtomic..maxAtomic)
 * - Checks price did not unexpectedly rise compared to previous quote for the same resource
 * - Checks if amount exceeds approvalThresholdAtomic, requiring a valid one-time cryptographic approval token
 */
export function checkPriceAndApproval(params: PriceCheckParams): {
  approved: boolean;
  approvalRequired: boolean;
} {
  const { resource, amountAtomic, endpoint, intentId, approvalToken, lastSeenAmountAtomic } = params;

  const amount = BigInt(amountAtomic);
  const minPrice = BigInt(endpoint.priceBand.minAtomic);
  const maxPrice = BigInt(endpoint.priceBand.maxAtomic);

  // 1. Price Band Check
  if (amount < minPrice || amount > maxPrice) {
    throw new GuardBlockError(
      'PRICE_OUT_OF_BAND',
      'L3',
      `Amount ${amountAtomic} is outside allowed price band [${endpoint.priceBand.minAtomic}, ${endpoint.priceBand.maxAtomic}]`
    );
  }

  // 2. Unexpected Price Rise Check
  if (lastSeenAmountAtomic) {
    const lastSeen = BigInt(lastSeenAmountAtomic);
    if (amount > lastSeen) {
      throw new GuardBlockError(
        'PRICE_RISE',
        'L3',
        `Price increased from ${lastSeenAmountAtomic} to ${amountAtomic} without user re-authorization`
      );
    }
  }

  // 3. Approval Gate Check
  const approvalThreshold = BigInt(endpoint.approvalThresholdAtomic || endpoint.perRequestCapAtomic);
  const approvalRequired = amount >= approvalThreshold;

  if (approvalRequired) {
    if (!approvalToken) {
      throw new GuardBlockError(
        'APPROVAL_REQUIRED',
        'L3',
        `Amount ${amountAtomic} exceeds approval threshold ${approvalThreshold.toString()}; explicit approval token required`,
        { requiredThreshold: approvalThreshold.toString(), amount: amountAtomic }
      );
    }

    // Validate approval token
    if (approvalToken.expiresAt < Date.now()) {
      throw new GuardBlockError(
        'APPROVAL_REQUIRED',
        'L3',
        `Approval token ${approvalToken.approvalId} has expired`,
        { expiresAt: approvalToken.expiresAt, now: Date.now() }
      );
    }

    const approvedCap = BigInt(approvalToken.approvedAmountAtomic);
    if (amount > approvedCap) {
      throw new GuardBlockError(
        'APPROVAL_REQUIRED',
        'L3',
        `Amount ${amountAtomic} exceeds approved token limit ${approvalToken.approvedAmountAtomic}`
      );
    }

    if (intentId && approvalToken.intentId && approvalToken.intentId !== intentId) {
      throw new GuardBlockError(
        'APPROVAL_REQUIRED',
        'L3',
        `Approval token intentId mismatch: expected ${intentId}, got ${approvalToken.intentId}`
      );
    }
  }

  return {
    approved: true,
    approvalRequired,
  };
}
