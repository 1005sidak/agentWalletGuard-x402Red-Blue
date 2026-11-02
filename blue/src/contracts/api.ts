import { z } from 'zod';
import { TargetModeSchema } from './events';
import { PaymentRequirementsSchema } from './x402-types';

/**
 * Health check response schema
 */
export const HealthResponseSchema = z
  .object({
    status: z.literal('ok'),
    service: z.string(),
    mode: TargetModeSchema.optional(),
    contracts_hash: z.string(),
    policy_digest: z.string().optional(),
    uptime_seconds: z.number().nonnegative(),
  })
  .strict();

export type HealthResponse = z.infer<typeof HealthResponseSchema>;

/**
 * Product schema for merchant catalogue
 */
export const ProductSchema = z
  .object({
    id: z.string(),
    name: z.string(),
    category: z.string(),
    description: z.string(),
    price_atomic: z.string().regex(/^[1-9][0-9]*$/),
    price_display_inr: z.string(),
    currency: z.literal('TUSD'),
    stock: z.number().int().nonnegative(),
    image_url: z.string(),
  })
  .strict();

export type Product = z.infer<typeof ProductSchema>;

/**
 * Checkout request schema
 */
export const CheckoutRequestSchema = z
  .object({
    product_id: z.string(),
    quantity: z.number().int().positive(),
    intent_id: z.string().uuid(),
    approval_token: z.string().optional(),
  })
  .strict();

export type CheckoutRequest = z.infer<typeof CheckoutRequestSchema>;

/**
 * Facilitator verify request and response
 */
export const FacilitatorVerifyRequestSchema = z
  .object({
    x402Version: z.literal(1),
    paymentPayload: z.object({
      scheme: z.literal('exact'),
      network: z.string(),
      authorization: z.object({
        from: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
        to: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
        value: z.string(),
        validAfter: z.number().int(),
        validBefore: z.number().int(),
        nonce: z.string().regex(/^0x[a-fA-F0-9]{64}$/),
        v: z.number().int(),
        r: z.string().regex(/^0x[a-fA-F0-9]{64}$/),
        s: z.string().regex(/^0x[a-fA-F0-9]{64}$/),
      }),
    }),
    paymentRequirements: PaymentRequirementsSchema,
  })
  .strict();

export type FacilitatorVerifyRequest = z.infer<typeof FacilitatorVerifyRequestSchema>;

export const FacilitatorVerifyResponseSchema = z
  .object({
    valid: z.boolean(),
    reason: z.string().optional(),
  })
  .strict();

/**
 * Facilitator settle request and response
 */
export const FacilitatorSettleRequestSchema = FacilitatorVerifyRequestSchema;
export type FacilitatorSettleRequest = FacilitatorVerifyRequest;

export const FacilitatorSettleResponseSchema = z
  .object({
    success: z.boolean(),
    txHash: z.string().optional(),
    receipt: z
      .object({
        from: z.string(),
        to: z.string(),
        amountAtomic: z.string(),
        timestamp: z.number(),
      })
      .optional(),
    error: z.string().optional(),
  })
  .strict();

export type FacilitatorSettleResponse = z.infer<typeof FacilitatorSettleResponseSchema>;

/**
 * Agent Control API Schemas (RED -> BLUE Agent)
 */
export const ControlModeRequestSchema = z
  .object({
    mode: TargetModeSchema,
  })
  .strict();

export const PurchaseIntentSchema = z
  .object({
    product_query: z.string().min(1),
    category: z.string().optional(),
    quantity: z.number().int().positive().default(1),
    max_total_atomic: z.string().regex(/^[1-9][0-9]*$/),
    currency: z.literal('TUSD').default('TUSD'),
    preferences: z.array(z.string()).optional(),
  })
  .strict();

export type PurchaseIntent = z.infer<typeof PurchaseIntentSchema>;

export const ControlPurchaseRequestSchema = z
  .object({
    run_id: z.string().min(1),
    trace_id: z.string().min(1),
    seed: z.number().int().nullable().default(null),
    intent: PurchaseIntentSchema,
    auto_confirm: z.boolean().default(false),
    attack_id: z.string().optional(),
  })
  .strict();

export type ControlPurchaseRequest = z.infer<typeof ControlPurchaseRequestSchema>;

export const ControlPurchaseResponseSchema = z
  .object({
    decision: z.enum(['ALLOW', 'BLOCK']),
    reason: z.string().nullable(),
    layer: z.string().nullable(),
    signed: z.boolean(),
    order_result: z.unknown().nullable(),
    tx_hash: z.string().nullable(),
    chain_delta_atomic: z.string().nullable(),
    funds_lost_atomic: z.string(),
    latency_ms: z.number(),
  })
  .strict();

export type ControlPurchaseResponse = z.infer<typeof ControlPurchaseResponseSchema>;

export const QuoteMutationHookSchema = z
  .object({
    enabled: z.boolean(),
    mutatedAmountAtomic: z.string().optional(),
  })
  .strict();
