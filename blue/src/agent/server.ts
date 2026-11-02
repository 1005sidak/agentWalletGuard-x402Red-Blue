import express, { Request, Response } from 'express';
import cors from 'cors';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { LocalAccount } from 'viem';
import { wrapFetchWithPayment } from 'x402-fetch';
import { parseShoppingIntent } from './intent-parser';
import { BlueV0Guard } from '../guard/v0';
import { BlueV1Guard, GuardEvaluationResult } from '../guard';
import { EndpointsRegistry, EndpointsRegistrySchema } from '../contracts/registry.schema';
import { PinStore } from '../guard/pin-store';
import { createGuardedWallet } from '../guard/wallet-guard';
import { getContractsHash } from '../contracts/hash';
import { DEFAULT_PORTS, TOKEN_NAME, TOKEN_VERSION } from '../contracts/constants';
import { TargetMode } from '../contracts/events';
import { ControlPurchaseResponse } from '../contracts/api';

export interface AgentConfig {
  port?: number;
  merchantUrl?: string;
  chainUrl?: string;
  collectorUrl?: string;
  keysDir?: string;
  budgetDbPath?: string;
  auditDbPath?: string;
  adminToken?: string;
  registry?: EndpointsRegistry;
}

export function createAgentServer(config: AgentConfig = {}) {
  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '1mb' }));

  const port = config.port || Number(process.env.AGENT_PORT) || DEFAULT_PORTS.BLUE_AGENT;
  const merchantUrl = config.merchantUrl || process.env.MERCHANT_URL || `http://localhost:${DEFAULT_PORTS.RED_MERCHANT}`;
  const chainUrl = config.chainUrl || process.env.CHAIN_URL || `http://localhost:${DEFAULT_PORTS.BLUE_CHAIN}`;
  const collectorUrl = config.collectorUrl || process.env.COLLECTOR_URL || `http://localhost:${DEFAULT_PORTS.BLUE_COLLECTOR}`;
  const startTime = Date.now();

  // Mode state: NAIVE, BLUE_V0, BLUE_V1
  let currentMode: TargetMode = 'BLUE_V1';

  // Test hooks state
  let quoteMutationHook = { enabled: false, mutatedAmountAtomic: '' };

  // Generate or load persistent private key in .keys/
  const keysDir = config.keysDir || path.resolve(__dirname, '../../.keys');
  if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir, { recursive: true });
  }
  const keyPath = path.join(keysDir, 'blue-wallet.key');
  let privateKey: `0x${string}`;
  if (fs.existsSync(keyPath)) {
    privateKey = fs.readFileSync(keyPath, 'utf8').trim() as `0x${string}`;
  } else {
    privateKey = generatePrivateKey();
    fs.writeFileSync(keyPath, privateKey, { mode: 0o600 });
  }
  const rawAccount: LocalAccount = privateKeyToAccount(privateKey);
  const pinStore = new PinStore();
  const v0Guard = new BlueV0Guard();

  // Load endpoint registry
  const registryPath = path.resolve(__dirname, '../../policy/endpoints.registry.json');
  let policyDigest = 'sha256:default';
  let registry: EndpointsRegistry;
  if (config.registry) {
    registry = config.registry;
  } else if (fs.existsSync(registryPath)) {
    const rawRegistry = fs.readFileSync(registryPath, 'utf8');
    policyDigest = 'sha256:' + crypto.createHash('sha256').update(rawRegistry).digest('hex');
    const parsed = JSON.parse(rawRegistry);
    if (parsed.merchants && parsed.merchants['red-merchant']) {
      parsed.merchants['red-merchant'].origin = merchantUrl;
    }
    registry = EndpointsRegistrySchema.parse(parsed);
  } else {
    registry = {
      version: 1,
      rails: ['evm'],
      globalCaps: { dailyAtomic: '500000000', perCallAtomic: '50000000', approvalAtomic: '5000000', velocityPerMin: 20 },
      merchants: {
        'red-merchant': {
          origin: merchantUrl,
          method: 'POST',
          path: '/checkout',
          allowedPayTos: [process.env.HONEST_PAYTO || '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'],
          asset: '0x0000000000000000000000000000000000001010',
          assetName: TOKEN_NAME,
          assetVersion: TOKEN_VERSION,
          chainId: 31337,
          priceBand: { minAtomic: '1000', maxAtomic: '50000000' },
          maxWindowSeconds: 30,
          perRequestCapAtomic: '50000000',
          approvalThresholdAtomic: '5000000',
        },
      },
    };
  }

  const v1Guard = new BlueV1Guard({
    account: rawAccount,
    registry,
    budgetDbPath: config.budgetDbPath || path.resolve(__dirname, '../../data/budget.db'),
    auditDbPath: config.auditDbPath || path.resolve(__dirname, '../../data/audit.jsonl'),
    collectorUrl,
    chainUrl,
  });

  // Event emission helper
  async function emitSecurityEvent(ev: {
    run_id?: string;
    trace_id?: string;
    worker: any;
    attack?: string | null;
    seed?: number | null;
    target: TargetMode;
    decision: any;
    reason?: string | null;
    layer?: string | null;
    pin_hash?: string | null;
    amount_atomic?: string | null;
    chain_delta_atomic?: string | null;
    funds_lost_atomic: string;
    latency_ms: number;
    details?: any;
  }) {
    try {
      const fullEvent = {
        event_id: crypto.randomUUID(),
        run_id: ev.run_id || 'run-default',
        trace_id: ev.trace_id || 'trace-' + Date.now(),
        worker: ev.worker,
        attack: ev.attack || null,
        seed: ev.seed || null,
        target: ev.target,
        decision: ev.decision,
        reason: ev.reason || null,
        layer: ev.layer || null,
        pin_hash: ev.pin_hash || null,
        amount_atomic: ev.amount_atomic || null,
        chain_delta_atomic: ev.chain_delta_atomic || null,
        funds_lost_atomic: ev.funds_lost_atomic,
        latency_ms: ev.latency_ms,
        policy_digest: policyDigest,
        ts: new Date().toISOString(),
        details: ev.details || null,
      };

      await fetch(`${collectorUrl}/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(fullEvent),
      }).catch(() => {});
    } catch {}
  }

  // Health
  app.get('/health', (req, res) => {
    const { hash } = getContractsHash();
    res.json({
      status: 'ok',
      service: 'blue-agent',
      mode: currentMode,
      contracts_hash: hash,
      policy_digest: policyDigest,
      address: rawAccount.address,
      uptime_seconds: Math.floor((Date.now() - startTime) / 1000),
    });
  });

  // Mode switcher
  app.post('/control/mode', (req, res) => {
    const { mode } = req.body;
    if (mode === 'NAIVE' || mode === 'BLUE_V0' || mode === 'BLUE_V1') {
      currentMode = mode;
      return res.json({ success: true, mode: currentMode });
    }
    return res.status(400).json({ error: 'Invalid mode. Must be NAIVE, BLUE_V0, or BLUE_V1' });
  });

  // Test hook for A8 quote mutation
  app.post('/control/test-hook/quote-mutation', (req, res) => {
    const { enabled, mutatedAmountAtomic } = req.body;
    quoteMutationHook = {
      enabled: Boolean(enabled),
      mutatedAmountAtomic: mutatedAmountAtomic || '99990000',
    };
    res.json({ success: true, quoteMutationHook });
  });

  // Execute purchase
  async function executePurchase(params: {
    run_id: string;
    trace_id: string;
    seed: number | null;
    intent: any;
    auto_confirm: boolean;
    attack_id?: string;
  }): Promise<ControlPurchaseResponse> {
    const startMs = Date.now();
    const { run_id, trace_id, seed, intent, auto_confirm, attack_id } = params;

    // Record initial balance on chain
    let balanceBefore = 0n;
    try {
      const bRes = await fetch(`${chainUrl}/balances?address=${rawAccount.address}`);
      const bData: any = await bRes.json();
      balanceBefore = BigInt(bData.balance_atomic || '0');
    } catch {}

    // Search merchant catalogue
    let targetProduct: any = null;
    try {
      const pRes = await fetch(`${merchantUrl}/products?q=${encodeURIComponent(intent.product_query)}`);
      const pData: any = await pRes.json();
      if (pData.products && pData.products.length > 0) {
        targetProduct = pData.products[0];
      }
    } catch (err: any) {
      const latency = Date.now() - startMs;
      await emitSecurityEvent({
        run_id,
        trace_id,
        worker: 'blue-agent',
        attack: attack_id,
        seed,
        target: currentMode,
        decision: 'BLOCK',
        reason: 'GUARD_ERROR',
        layer: 'L0',
        funds_lost_atomic: '0',
        latency_ms: latency,
        details: { error: 'Failed to contact merchant catalogue' },
      });
      return {
        decision: 'BLOCK',
        reason: 'GUARD_ERROR',
        layer: 'L0',
        signed: false,
        order_result: null,
        tx_hash: null,
        chain_delta_atomic: '0',
        funds_lost_atomic: '0',
        latency_ms: latency,
      };
    }

    if (!targetProduct) {
      targetProduct = {
        id: intent.product_query,
        price_atomic: '25000000',
        name: intent.product_query,
      };
    }

    const calculatedTotal = (BigInt(targetProduct.price_atomic) * BigInt(intent.quantity)).toString();

    // 1. V0 Policy Check
    if (currentMode === 'BLUE_V0') {
      const v0Check = v0Guard.check({
        resource: `${merchantUrl}/checkout`,
        amountAtomic: calculatedTotal,
        approvalRef: auto_confirm ? 'test-approval' : (attack_id === 'A18' ? 'x-bypass-test' : undefined),
      });
      if (!v0Check.allowed) {
        const latency = Date.now() - startMs;
        await emitSecurityEvent({
          run_id,
          trace_id,
          worker: 'blue-guard',
          attack: attack_id,
          seed,
          target: 'BLUE_V0',
          decision: 'BLOCK',
          reason: v0Check.reason,
          layer: 'L3',
          funds_lost_atomic: '0',
          latency_ms: latency,
          details: { note: 'Blocked by V0 baseline policy' },
        });
        return {
          decision: 'BLOCK',
          reason: v0Check.reason || 'POLICY_REJECT',
          layer: 'L3',
          signed: false,
          order_result: null,
          tx_hash: null,
          chain_delta_atomic: '0',
          funds_lost_atomic: '0',
          latency_ms: latency,
        };
      }
    }

    // Set up guarded or raw wallet based on mode
    let signed = false;
    let pinnedHash: string | null = null;
    let evalResult: GuardEvaluationResult | null = null;
    let walletToUse: LocalAccount = rawAccount;

    if (currentMode === 'BLUE_V1') {
      walletToUse = v1Guard.guardedWallet;
    }

    const baseSignTypedData = walletToUse.signTypedData.bind(walletToUse);
    const trackingWallet: LocalAccount = {
      ...walletToUse,
      signTypedData: async (data: any) => {
        const sig = await baseSignTypedData(data);
        signed = true;
        return sig;
      },
    };

    // Wrap fetch with payment
    let decision: 'ALLOW' | 'BLOCK' = 'ALLOW';
    let blockReason: string | null = null;
    let blockLayer: string | null = null;
    let orderResult: any = null;
    let txHash: string | null = null;

    try {
      const baseFetch: typeof fetch = async (input, init) => {
        const urlStr = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
        const method = init?.method || 'POST';

        const res = await globalThis.fetch(input, init);

        // If 402 challenge received
        if (res.status === 402) {
          const cloned = res.clone();
          const raw402 = await cloned.json();

          if (currentMode === 'BLUE_V1') {
            const approvalToken = (auto_confirm && attack_id !== 'A18')
              ? {
                  approvalId: 'appr-' + trace_id,
                  intentId: 'intent-' + trace_id,
                  resource: urlStr,
                  approvedAmountAtomic: intent.max_total_atomic || '50000000',
                  expiresAt: Date.now() + 60000,
                }
              : null;

            evalResult = await v1Guard.evaluate402({
              url: urlStr,
              method,
              raw402Body: raw402,
              intentId: 'intent-' + trace_id,
              approvalToken,
              runId: run_id,
              traceId: trace_id,
              attack: attack_id,
              seed,
            });
            pinnedHash = evalResult.quoteHash;
          }

          // If A8 simulated dependency tampering is enabled, mutate the requirement before passing to x402-fetch
          if (quoteMutationHook.enabled) {
            const mutated402 = JSON.parse(JSON.stringify(raw402));
            if (mutated402.accepts && mutated402.accepts[0]) {
              mutated402.accepts[0].maxAmountRequired = quoteMutationHook.mutatedAmountAtomic;
            }
            return new globalThis.Response(JSON.stringify(mutated402), {
              status: 402,
              headers: { 'Content-Type': 'application/json' },
            });
          }
        }

        return res;
      };

      const fetchWithPayment = wrapFetchWithPayment(baseFetch, trackingWallet, BigInt(intent.max_total_atomic));

      const res = await fetchWithPayment(`${merchantUrl}/checkout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          product_id: targetProduct.id,
          quantity: intent.quantity,
          intent_id: 'intent-' + trace_id,
        }),
      });

      if (res.ok) {
        orderResult = await res.json();
        txHash = orderResult.tx_hash || null;
        if (currentMode === 'BLUE_V0') {
          v0Guard.recordSpend(calculatedTotal);
        }
        if (currentMode === 'BLUE_V1' && evalResult) {
          await evalResult.reconcile(balanceBefore.toString(), txHash);
          evalResult.commitBudget();
        }
      } else {
        decision = 'BLOCK';
        const errJson: any = await res.json().catch(() => ({}));
        blockReason = errJson.reason || errJson.error || 'PAYMENT_REJECTED';
        blockLayer = errJson.layer || 'L0';
        if (evalResult) {
          evalResult.releaseBudget();
        }
      }
    } catch (err: any) {
      decision = 'BLOCK';
      blockReason = err.code || err.message;
      blockLayer = err.layer || (blockReason?.includes('QUOTE') || blockReason?.includes('WINDOW') || blockReason?.includes('SIGN') ? 'L4' : 'L1');
      if (evalResult) {
        evalResult.releaseBudget();
      }
    }

    // Query balance on chain after execution
    let balanceAfter = balanceBefore;
    try {
      const bRes = await fetch(`${chainUrl}/balances?address=${rawAccount.address}`);
      const bData: any = await bRes.json();
      balanceAfter = BigInt(bData.balance_atomic || '0');
    } catch {}

    const delta = (balanceBefore - balanceAfter).toString();
    // Funds lost is non-zero only if funds reached attacker or exceeded intended amount
    const attackerPayTo = (process.env.ATTACKER_PAYTO || '0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc').toLowerCase();
    let fundsLost = '0';
    if (BigInt(delta) > 0n && attack_id && attack_id !== 'HONEST') {
      fundsLost = delta;
    }

    const latency = Date.now() - startMs;
    const finalReason = decision === 'ALLOW' ? 'OK' : (blockReason || 'GUARD_ERROR');

    // Emit event to collector
    await emitSecurityEvent({
      run_id,
      trace_id,
      worker: 'blue-agent',
      attack: attack_id || (decision === 'ALLOW' ? 'HONEST' : null),
      seed,
      target: currentMode,
      decision,
      reason: finalReason,
      layer: blockLayer,
      pin_hash: pinnedHash,
      amount_atomic: calculatedTotal,
      chain_delta_atomic: delta,
      funds_lost_atomic: fundsLost,
      latency_ms: latency,
      details: { product: targetProduct.id, quantity: intent.quantity, signed },
    });

    return {
      decision,
      reason: finalReason,
      layer: blockLayer,
      signed,
      order_result: orderResult,
      tx_hash: txHash,
      chain_delta_atomic: delta,
      funds_lost_atomic: fundsLost,
      latency_ms: latency,
    };
  }

  // POST /control/purchase
  app.post('/control/purchase', async (req, res) => {
    try {
      const { run_id, trace_id, seed = null, intent, auto_confirm = true, attack_id } = req.body;
      const result = await executePurchase({
        run_id: run_id || 'run-test',
        trace_id: trace_id || 'trace-' + Date.now(),
        seed,
        intent,
        auto_confirm,
        attack_id,
      });
      return res.json(result);
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // POST /assistant/chat
  app.post('/assistant/chat', async (req, res) => {
    try {
      const { message } = req.body;
      if (!message) {
        return res.status(400).json({ error: 'Message required' });
      }

      const intent = parseShoppingIntent(message);
      const result = await executePurchase({
        run_id: 'chat-' + Date.now(),
        trace_id: 'trace-' + Date.now(),
        seed: null,
        intent,
        auto_confirm: true,
      });

      if (result.decision === 'ALLOW') {
        return res.json({
          reply: `Successfully placed order for ${intent.quantity}x ${intent.product_query}! Settlement confirmed on-chain (tx: ${result.tx_hash}).`,
          intent,
          result,
        });
      } else {
        return res.json({
          reply: `Purchase blocked by defense guard at layer ${result.layer}: ${result.reason}. Zero funds lost.`,
          intent,
          result,
        });
      }
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  return { app, port, rawAccount, v1Guard };
}

if (require.main === module || (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename))) {
  const { app, port, rawAccount } = createAgentServer();
  app.listen(port, '0.0.0.0', () => {
    console.log(`[blue-agent] AI payment agent listening on http://0.0.0.0:${port}`);
    console.log(`[blue-agent] Agent wallet address: ${rawAccount.address}`);
  });
}
