import { z } from 'zod';
import { ReasonCode } from './reason-codes';

/**
 * Standard x402 PaymentRequirements matching x402 / x402-fetch 1.2.0
 */
export const PaymentRequirementsSchema = z
  .object({
    scheme: z.literal('exact'),
    network: z.string(),
    maxAmountRequired: z.string().regex(/^[1-9][0-9]*$/, 'Amount must be non-zero atomic integer string'),
    resource: z.string().url(),
    description: z.string(),
    mimeType: z.string(),
    outputSchema: z.record(z.any()).optional(),
    asset: z.string().regex(/^0x[a-fA-F0-9]{40}$/, 'Asset must be valid EVM address'),
    payTo: z.string().regex(/^0x[a-fA-F0-9]{40}$/, 'PayTo must be valid EVM address'),
    maxTimeoutSeconds: z.number().int().positive().max(30),
    extra: z.object({
      name: z.string(),
      version: z.string(),
    }).passthrough().optional(),
  })
  .strict();

export type PaymentRequirements = z.infer<typeof PaymentRequirementsSchema>;

/**
 * EIP-712 TransferWithAuthorization payload structure
 */
export interface TransferWithAuthorizationData {
  types: {
    EIP712Domain: Array<{ name: string; type: string }>;
    TransferWithAuthorization: Array<{ name: string; type: string }>;
  };
  primaryType: 'TransferWithAuthorization';
  domain: {
    name: string;
    version: string;
    chainId: number;
    verifyingContract: `0x${string}`;
  };
  message: {
    from: `0x${string}`;
    to: `0x${string}`;
    value: string | bigint;
    validAfter: number | bigint;
    validBefore: number | bigint;
    nonce: `0x${string}`;
  };
}

export interface PaymentPayload {
  x402Version: 1;
  scheme: 'exact';
  network: string;
  authorization: {
    from: `0x${string}`;
    to: `0x${string}`;
    value: string;
    validAfter: number;
    validBefore: number;
    nonce: `0x${string}`;
    v: number;
    r: `0x${string}`;
    s: `0x${string}`;
  };
}

export interface PaymentResponse {
  x402Version: 1;
  success: boolean;
  txHash?: string;
  receipt?: {
    from: string;
    to: string;
    amountAtomic: string;
    timestamp: number;
  };
  error?: string;
}

export class GuardBlockError extends Error {
  public readonly code: ReasonCode;
  public readonly layer: string;
  public readonly details?: unknown;

  constructor(code: ReasonCode, layer: string, message?: string, details?: unknown) {
    super(message || `Guard blocked at layer ${layer}: ${code}`);
    this.name = 'GuardBlockError';
    this.code = code;
    this.layer = layer;
    this.details = details;
  }
}
