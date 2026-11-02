import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  REASON_CODES,
  REASON_TO_LAYER,
  REASON_TO_SEVERITY,
  SECURITY_LAYERS,
  ATTACKS_CATALOG,
  ATTACK_IDS,
  SecurityEventSchema,
  toAtomicUnits,
  fromAtomicUnits,
  inrFromAtomic,
} from '../contracts';

describe('Contracts — Reason Codes & Layers', () => {
  it('defines 23 canonical reason codes', () => {
    expect(REASON_CODES.length).toBe(23);
    for (const code of REASON_CODES) {
      expect(REASON_TO_LAYER[code]).toBeDefined();
      expect(SECURITY_LAYERS).toContain(REASON_TO_LAYER[code]);
      expect(REASON_TO_SEVERITY[code]).toBeDefined();
    }
  });

  it('maps critical failure reasons correctly', () => {
    expect(REASON_TO_LAYER['ORIGIN_NOT_ALLOWED']).toBe('L0');
    expect(REASON_TO_LAYER['PARSE_REJECT']).toBe('L1');
    expect(REASON_TO_LAYER['PAYTO_MISMATCH']).toBe('L2');
    expect(REASON_TO_LAYER['APPROVAL_REQUIRED']).toBe('L3');
    expect(REASON_TO_LAYER['QUOTE_CHANGED']).toBe('L4');
    expect(REASON_TO_LAYER['BUDGET_RESERVED']).toBe('L5');
    expect(REASON_TO_LAYER['VELOCITY']).toBe('L6');
    expect(REASON_TO_LAYER['SETTLEMENT_MISMATCH']).toBe('L7');
    expect(REASON_TO_LAYER['GUARD_ERROR']).toBe('L8');
  });
});

describe('Contracts — Attack Catalog A1-A18', () => {
  it('contains exactly 18 attack definitions A1 through A18', () => {
    expect(ATTACK_IDS.length).toBe(18);
    for (let i = 1; i <= 18; i++) {
      const id = `A${i}`;
      expect(ATTACKS_CATALOG[id]).toBeDefined();
      expect(ATTACKS_CATALOG[id].id).toBe(id);
      expect(ATTACKS_CATALOG[id].name.length).toBeGreaterThan(0);
      expect(ATTACKS_CATALOG[id].expectedLayer).toBeDefined();
      expect(ATTACKS_CATALOG[id].expectedReason).toBeDefined();
    }
  });
});

describe('Contracts — Atomic Conversion Utilities', () => {
  it('converts decimal amounts to atomic strings', () => {
    expect(toAtomicUnits('1')).toBe('1000000');
    expect(toAtomicUnits('1.5')).toBe('1500000');
    expect(toAtomicUnits('0.000001')).toBe('1');
    expect(toAtomicUnits('0.10')).toBe('100000');
  });

  it('converts atomic units to decimal strings', () => {
    expect(fromAtomicUnits('1000000')).toBe('1.000000');
    expect(fromAtomicUnits('1500000')).toBe('1.500000');
    expect(fromAtomicUnits('1')).toBe('0.000001');
  });

  it('converts atomic units to INR display strings', () => {
    const inr = inrFromAtomic('1000000', 85);
    expect(inr).toBe('₹85.00');
  });
});

describe('Contracts — Event Schema Validation', () => {
  it('validates a valid SecurityEvent object', () => {
    const validEvent = {
      event_id: '11111111-2222-3333-4444-555555555555',
      run_id: 'run-test-1',
      trace_id: 'trace-test-1',
      worker: 'blue-guard',
      attack: 'A1',
      seed: 42,
      target: 'BLUE_V1',
      decision: 'BLOCK',
      reason: 'PAYTO_MISMATCH',
      layer: 'L2',
      pin_hash: 'sha256:abcd',
      amount_atomic: '1000000',
      chain_delta_atomic: '0',
      funds_lost_atomic: '0',
      latency_ms: 2.5,
      policy_digest: 'sha256:1234',
      ts: new Date().toISOString(),
      details: { note: 'blocked payee swap' },
    };

    const parsed = SecurityEventSchema.safeParse(validEvent);
    expect(parsed.success).toBe(true);
  });

  it('rejects extra unknown keys (strict mode)', () => {
    const invalidEvent = {
      event_id: '11111111-2222-3333-4444-555555555555',
      run_id: 'run-test-1',
      trace_id: 'trace-test-1',
      worker: 'blue-guard',
      attack: null,
      seed: null,
      target: 'BLUE_V1',
      decision: 'ALLOW',
      reason: null,
      layer: null,
      pin_hash: null,
      amount_atomic: null,
      chain_delta_atomic: null,
      funds_lost_atomic: '0',
      latency_ms: 1.0,
      policy_digest: null,
      ts: new Date().toISOString(),
      unauthorized_field: 'should fail',
    };

    const parsed = SecurityEventSchema.safeParse(invalidEvent);
    expect(parsed.success).toBe(false);
  });
});

describe('Contracts — Vendored Synchronization Parity', () => {
  it('verifies blue/ and red/ vendored hashes match root contracts.hash.json', () => {
    const rootHashFile = path.resolve(__dirname, '../contracts/contracts.hash.json');
    const blueHashFile = path.resolve(__dirname, '../blue/src/contracts/contracts.hash.json');
    const redHashFile = path.resolve(__dirname, '../red/src/contracts/contracts.hash.json');

    expect(fs.existsSync(rootHashFile)).toBe(true);
    expect(fs.existsSync(blueHashFile)).toBe(true);
    expect(fs.existsSync(redHashFile)).toBe(true);

    const rootHash = JSON.parse(fs.readFileSync(rootHashFile, 'utf8')).contracts_hash;
    const blueHash = JSON.parse(fs.readFileSync(blueHashFile, 'utf8')).contracts_hash;
    const redHash = JSON.parse(fs.readFileSync(redHashFile, 'utf8')).contracts_hash;

    expect(blueHash).toBe(rootHash);
    expect(redHash).toBe(rootHash);
  });
});
