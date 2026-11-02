/**
 * Canonical reason codes, security layers, and severity classifications.
 */

export const REASON_CODES = [
  'ORIGIN_NOT_ALLOWED',
  'REDIRECT_HOST',
  'PARSE_REJECT',
  'ENDPOINT_UNKNOWN',
  'PAYTO_MISMATCH',
  'ASSET_NOT_ALLOWED',
  'NETWORK_NOT_ALLOWED',
  'PRICE_OUT_OF_BAND',
  'PRICE_RISE',
  'APPROVAL_REQUIRED',
  'QUOTE_CHANGED',
  'WINDOW_TOO_LONG',
  'PIN_CONSUMED',
  'SIGN_UNPINNED',
  'SIGN_FORBIDDEN',
  'BUDGET_RESERVED',
  'BUDGET_EXHAUSTED',
  'DUPLICATE_INTENT',
  'LOOP_DETECTED',
  'VELOCITY',
  'SETTLEMENT_MISMATCH',
  'GUARD_ERROR',
  'OK',
] as const;

export type ReasonCode = (typeof REASON_CODES)[number];

export const SECURITY_LAYERS = ['L0', 'L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7', 'L8'] as const;
export type SecurityLayer = (typeof SECURITY_LAYERS)[number];

export const LAYER_DESCRIPTIONS: Record<SecurityLayer, string> = {
  L0: 'Transport & Origin Allowlist',
  L1: 'Strict Input Parsing & Sanitization',
  L2: 'Merchant & Asset Identity Verification',
  L3: 'Price Bands & Cryptographic Approval Gate',
  L4: 'Wallet Signing Firewall & Quote Pinning',
  L5: 'Atomic WAL Budget & Intent Reservation',
  L6: 'Behavioral Loop & Velocity Protection',
  L7: 'Independent On-Chain Reconciliation',
  L8: 'Append-Only Audit Log & Fail-Closed Handler',
};

export const REASON_TO_LAYER: Record<ReasonCode, SecurityLayer> = {
  ORIGIN_NOT_ALLOWED: 'L0',
  REDIRECT_HOST: 'L0',
  PARSE_REJECT: 'L1',
  ENDPOINT_UNKNOWN: 'L2',
  PAYTO_MISMATCH: 'L2',
  ASSET_NOT_ALLOWED: 'L2',
  NETWORK_NOT_ALLOWED: 'L2',
  PRICE_OUT_OF_BAND: 'L3',
  PRICE_RISE: 'L3',
  APPROVAL_REQUIRED: 'L3',
  QUOTE_CHANGED: 'L4',
  WINDOW_TOO_LONG: 'L4',
  PIN_CONSUMED: 'L4',
  SIGN_UNPINNED: 'L4',
  SIGN_FORBIDDEN: 'L4',
  BUDGET_RESERVED: 'L5',
  BUDGET_EXHAUSTED: 'L5',
  DUPLICATE_INTENT: 'L5',
  LOOP_DETECTED: 'L6',
  VELOCITY: 'L6',
  SETTLEMENT_MISMATCH: 'L7',
  GUARD_ERROR: 'L8',
  OK: 'L8',
};

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export const REASON_TO_SEVERITY: Record<ReasonCode, Severity> = {
  ORIGIN_NOT_ALLOWED: 'HIGH',
  REDIRECT_HOST: 'HIGH',
  PARSE_REJECT: 'MEDIUM',
  ENDPOINT_UNKNOWN: 'HIGH',
  PAYTO_MISMATCH: 'CRITICAL',
  ASSET_NOT_ALLOWED: 'CRITICAL',
  NETWORK_NOT_ALLOWED: 'CRITICAL',
  PRICE_OUT_OF_BAND: 'HIGH',
  PRICE_RISE: 'HIGH',
  APPROVAL_REQUIRED: 'MEDIUM',
  QUOTE_CHANGED: 'CRITICAL',
  WINDOW_TOO_LONG: 'HIGH',
  PIN_CONSUMED: 'CRITICAL',
  SIGN_UNPINNED: 'CRITICAL',
  SIGN_FORBIDDEN: 'CRITICAL',
  BUDGET_RESERVED: 'MEDIUM',
  BUDGET_EXHAUSTED: 'MEDIUM',
  DUPLICATE_INTENT: 'HIGH',
  LOOP_DETECTED: 'HIGH',
  VELOCITY: 'HIGH',
  SETTLEMENT_MISMATCH: 'CRITICAL',
  GUARD_ERROR: 'CRITICAL',
  OK: 'INFO',
};
