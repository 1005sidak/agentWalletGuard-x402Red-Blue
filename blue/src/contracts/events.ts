import { z } from 'zod';
import { REASON_CODES, SECURITY_LAYERS } from './reason-codes';

export const WorkerTypeSchema = z.enum([
  'blue-agent',
  'blue-guard',
  'blue-chain',
  'red-orchestrator',
  'red-merchant',
  'red-facilitator',
  'red-fuzzer',
  'red-learner',
]);
export type WorkerType = z.infer<typeof WorkerTypeSchema>;

export const TargetModeSchema = z.enum(['NAIVE', 'BLUE_V0', 'BLUE_V1']);
export type TargetMode = z.infer<typeof TargetModeSchema>;

export const DecisionSchema = z.enum([
  'ALLOW',
  'BLOCK',
  'SIGN',
  'SETTLE',
  'RECONCILE',
  'ATTACK_START',
  'ATTACK_END',
  'INFO',
]);
export type Decision = z.infer<typeof DecisionSchema>;

export const ReasonCodeSchema = z.enum(REASON_CODES);
export const SecurityLayerSchema = z.enum(SECURITY_LAYERS);

export const SecurityEventSchema = z
  .object({
    event_id: z.string().uuid(),
    run_id: z.string().min(1),
    trace_id: z.string().min(1),
    worker: WorkerTypeSchema,
    attack: z.string().nullable(),
    seed: z.number().int().nullable(),
    target: TargetModeSchema,
    decision: DecisionSchema,
    reason: ReasonCodeSchema.nullable(),
    layer: SecurityLayerSchema.nullable(),
    pin_hash: z.string().nullable(),
    amount_atomic: z.string().nullable(),
    chain_delta_atomic: z.string().nullable(),
    funds_lost_atomic: z.string(),
    latency_ms: z.number().nonnegative(),
    policy_digest: z.string().nullable(),
    ts: z.string().datetime(), // ISO-8601 UTC
    details: z.record(z.unknown()).optional(),
  })
  .strict();

export type SecurityEvent = z.infer<typeof SecurityEventSchema>;

/**
 * Validates that an incoming event strictly satisfies the schema.
 */
export function validateSecurityEvent(data: unknown): SecurityEvent {
  return SecurityEventSchema.parse(data);
}
