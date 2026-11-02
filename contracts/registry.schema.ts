import { z } from 'zod';

export const PriceBandSchema = z
  .object({
    minAtomic: z.string().regex(/^[0-9]+$/),
    maxAtomic: z.string().regex(/^[0-9]+$/),
  })
  .strict();

export const RegistryEndpointSchema = z
  .object({
    origin: z.string().url(),
    method: z.enum(['GET', 'POST', 'PUT', 'DELETE']),
    path: z.string().startsWith('/'),
    allowedPayTos: z.array(z.string().regex(/^0x[a-fA-F0-9]{40}$/)),
    asset: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
    assetName: z.string(),
    assetVersion: z.string(),
    chainId: z.number().int().positive(),
    priceBand: PriceBandSchema,
    maxWindowSeconds: z.number().int().positive().max(30),
    perRequestCapAtomic: z.string().regex(/^[0-9]+$/),
    approvalThresholdAtomic: z.string().regex(/^[0-9]+$/),
  })
  .strict();

export const EndpointsRegistrySchema = z
  .object({
    version: z.number().int().positive(),
    rails: z.array(z.string()),
    merchants: z.record(z.string(), RegistryEndpointSchema),
    globalCaps: z
      .object({
        dailyAtomic: z.string().regex(/^[0-9]+$/),
        perCallAtomic: z.string().regex(/^[0-9]+$/),
        approvalAtomic: z.string().regex(/^[0-9]+$/),
        velocityPerMin: z.number().int().positive(),
      })
      .strict(),
  })
  .strict();

export type RegistryEndpoint = z.infer<typeof RegistryEndpointSchema>;
export type EndpointsRegistry = z.infer<typeof EndpointsRegistrySchema>;
