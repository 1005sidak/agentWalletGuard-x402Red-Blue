import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createBudgetManager } from '../src/guard/l5-budget';
import { PinStore } from '../src/guard/pin-store';
import { createGuardedWallet } from '../src/guard/wallet-guard';
import { GuardBlockError } from '../src/contracts/x402-types';

const BURST_TEST_DIR = path.resolve(__dirname, 'test-temp-burst');

describe('Phase 4 — Concurrency & Firewall Hardening (100-Parallel Burst)', () => {
  beforeEach(() => {
    if (fs.existsSync(BURST_TEST_DIR)) {
      fs.rmSync(BURST_TEST_DIR, { recursive: true, force: true });
    }
    fs.mkdirSync(BURST_TEST_DIR, { recursive: true });
  });

  afterEach(() => {
    if (fs.existsSync(BURST_TEST_DIR)) {
      fs.rmSync(BURST_TEST_DIR, { recursive: true, force: true });
    }
  });

  it('proves zero overspending under a 100-request parallel burst race against L5 budget', async () => {
    const dbPath = path.resolve(BURST_TEST_DIR, 'burst-budget.db');
    // Daily cap: 10,000,000 atomic (10 USD). Per-call cap: 1,000,000 atomic (1 USD).
    const bm = createBudgetManager(dbPath, {
      dailyAtomic: '10000000',
      perCallAtomic: '1000000',
    });

    const burstCount = 100;
    const requestAmount = '500000'; // 0.50 USD each. Exactly 20 can succeed before 10M cap is reached.
    const promises: Promise<{ index: number; success: boolean; error?: string }>[] = [];

    // Blast 100 simultaneous concurrent reservation requests
    for (let i = 0; i < burstCount; i++) {
      const intentId = `burst-intent-${i}`;
      promises.push(
        new Promise((resolve) => {
          try {
            bm.reserve({
              intentId,
              resource: 'http://localhost:4020/checkout',
              amountAtomic: requestAmount,
            });
            resolve({ index: i, success: true });
          } catch (err: any) {
            resolve({ index: i, success: false, error: err.code || err.message });
          }
        })
      );
    }

    const results = await Promise.all(promises);

    const succeeded = results.filter((r) => r.success);
    const failed = results.filter((r) => !r.success);

    // Exactly 20 reservations must succeed
    expect(succeeded.length).toBe(20);
    // Exactly 80 reservations must be blocked with BUDGET_EXHAUSTED
    expect(failed.length).toBe(80);
    for (const f of failed) {
      expect(f.error).toBe('BUDGET_EXHAUSTED');
    }

    // Measure exact database balance to prove zero overspending
    const totalReserved = bm.getReservedToday();
    expect(totalReserved).toBe(10000000n);

    bm.close();
  });

  it('guarantees single-use pin consumption under 100 parallel concurrent consumes', async () => {
    const pinStore = new PinStore();
    const quoteHash = pinStore.pin({
      payTo: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      asset: '0x0000000000000000000000000000000000001010',
      amountAtomic: '1500000',
      chainId: 31337,
      assetName: 'Test USD',
      assetVersion: '1',
      maxWindowSeconds: 30,
    });

    const consumes = await Promise.all(
      Array.from({ length: 100 }, async () => {
        return pinStore.consume(quoteHash);
      })
    );

    const trueCount = consumes.filter((c) => c !== null).length;
    const falseCount = consumes.filter((c) => c === null).length;

    expect(trueCount).toBe(1);
    expect(falseCount).toBe(99);
    expect(pinStore.isConsumed(quoteHash)).toBe(true);
  });

  it('guarantees only one signature succeeds when 50 concurrent sign attempts target a single pin', async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const pinStore = new PinStore();
    const wallet = createGuardedWallet({
      account,
      pinStore,
      maxWindowSeconds: 30,
    });

    const nowSeconds = Math.floor(Date.now() / 1000);
    const quoteHash = pinStore.pin({
      payTo: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      asset: '0x0000000000000000000000000000000000001010',
      amountAtomic: '1500000',
      chainId: 84532,
      assetName: 'Test USD',
      assetVersion: '1',
      maxWindowSeconds: 30,
    });

    const typedDataPayload = {
      domain: {
        name: 'Test USD',
        version: '1',
        chainId: 84532,
        verifyingContract: '0x0000000000000000000000000000000000001010',
      },
      types: {
        TransferWithAuthorization: [
          { name: 'from', type: 'address' },
          { name: 'to', type: 'address' },
          { name: 'value', type: 'uint256' },
          { name: 'validAfter', type: 'uint256' },
          { name: 'validBefore', type: 'uint256' },
          { name: 'nonce', type: 'bytes32' },
        ],
      },
      primaryType: 'TransferWithAuthorization',
      message: {
        from: account.address,
        to: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
        value: 1500000n,
        validAfter: BigInt(nowSeconds - 10),
        validBefore: BigInt(nowSeconds + 20),
        nonce: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      },
    };

    const results = await Promise.all(
      Array.from({ length: 50 }, async () => {
        try {
          const sig = await wallet.signTypedData(typedDataPayload as any);
          return { success: true, sig };
        } catch (err: any) {
          return { success: false, error: err.code || err.message };
        }
      })
    );

    const successfulSigs = results.filter((r) => r.success);
    const blockedAttempts = results.filter((r) => !r.success);

    expect(successfulSigs.length).toBe(1);
    expect(blockedAttempts.length).toBe(49);
    for (const b of blockedAttempts) {
      expect(b.error).toBe('PIN_CONSUMED');
    }
  });
});
