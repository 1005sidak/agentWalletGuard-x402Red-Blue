import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as http from 'node:http';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { createChainServer } from '../blue/src/chain/server';
import { createCollectorServer } from '../blue/src/collector/server';
import { createFacilitatorServer } from '../red/src/facilitator/server';
import { createMerchantServer } from '../red/src/merchant/server';
import { createAgentServer } from '../blue/src/agent/server';

describe('Phase 1 — Honest Payment End-to-End Flow', () => {
  let chainServer: http.Server;
  let collectorServer: http.Server;
  let facilitatorServer: http.Server;
  let merchantServer: http.Server;
  let agentServer: http.Server;
  let agentWalletAddress: string;

  let chainDb: any;
  let collectorDb: any;

  const chainPort = 4440;
  const collectorPort = 4450;
  const facilitatorPort = 4430;
  const merchantPort = 4420;
  const agentPort = 4410;

  const testDbDir = path.resolve(__dirname, '../data/test-phase1');
  const chainDbPath = path.join(testDbDir, 'chain.db');
  const collectorDbPath = path.join(testDbDir, 'collector.db');
  const keysDir = path.join(testDbDir, '.keys');

  beforeAll(async () => {
    if (fs.existsSync(testDbDir)) {
      try { fs.rmSync(testDbDir, { recursive: true, force: true }); } catch {}
    }
    fs.mkdirSync(testDbDir, { recursive: true });

    // 1. Start Blue Mock Chain
    const chainApp = createChainServer({
      port: chainPort,
      dbPath: chainDbPath,
      collectorUrl: `http://localhost:${collectorPort}`,
    });
    chainDb = chainApp.db;
    await new Promise<void>((resolve) => {
      chainServer = chainApp.app.listen(chainPort, () => resolve());
    });

    // 2. Start Blue Collector
    const collectorApp = createCollectorServer({
      port: collectorPort,
      dbPath: collectorDbPath,
    });
    collectorDb = collectorApp.db;
    await new Promise<void>((resolve) => {
      collectorServer = collectorApp.app.listen(collectorPort, () => resolve());
    });

    // 3. Start Red Facilitator
    const facApp = createFacilitatorServer({
      port: facilitatorPort,
      chainUrl: `http://localhost:${chainPort}`,
    });
    await new Promise<void>((resolve) => {
      facilitatorServer = facApp.app.listen(facilitatorPort, () => resolve());
    });

    // 4. Start Red Merchant
    const merchantApp = createMerchantServer({
      port: merchantPort,
      facilitatorUrl: `http://localhost:${facilitatorPort}`,
      honestPayTo: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    });
    await new Promise<void>((resolve) => {
      merchantServer = merchantApp.app.listen(merchantPort, () => resolve());
    });

    // 5. Start Blue Agent
    const agentApp = createAgentServer({
      port: agentPort,
      merchantUrl: `http://localhost:${merchantPort}`,
      chainUrl: `http://localhost:${chainPort}`,
      collectorUrl: `http://localhost:${collectorPort}`,
      keysDir,
      budgetDbPath: path.join(testDbDir, 'budget.db'),
      auditDbPath: path.join(testDbDir, 'audit.jsonl'),
    });
    agentWalletAddress = agentApp.rawAccount.address;
    await new Promise<void>((resolve) => {
      agentServer = agentApp.app.listen(agentPort, () => resolve());
    });

    // 6. Fund the agent wallet on the mock chain
    await fetch(`http://localhost:${chainPort}/fund`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        address: agentWalletAddress,
        amount_atomic: '1000000000', // 1,000 TUSD
      }),
    });
  });

  afterAll(async () => {
    agentServer?.close();
    merchantServer?.close();
    facilitatorServer?.close();
    collectorServer?.close();
    chainServer?.close();
    try { chainDb?.close(); } catch {}
    try { collectorDb?.close(); } catch {}
    try {
      if (fs.existsSync(testDbDir)) {
        fs.rmSync(testDbDir, { recursive: true, force: true });
      }
    } catch {}
  });

  it('reports health and valid contract hashes on all services', async () => {
    const endpoints = [
      `http://localhost:${chainPort}/health`,
      `http://localhost:${collectorPort}/health`,
      `http://localhost:${facilitatorPort}/health`,
      `http://localhost:${merchantPort}/health`,
      `http://localhost:${agentPort}/health`,
    ];

    for (const ep of endpoints) {
      const res = await fetch(ep);
      expect(res.status).toBe(200);
      const data: any = await res.json();
      expect(data.status).toBe('ok');
      expect(data.contracts_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    }
  });

  it('completes one honest purchase and settles on-chain with zero funds lost', async () => {
    // Check balance before
    const preBalRes = await fetch(`http://localhost:${chainPort}/balances?address=${agentWalletAddress}`);
    const preBal = await preBalRes.json();
    expect(preBal.balance_atomic).toBe('1000000000');

    // Switch agent to NAIVE mode as specified in Phase 1 ("agent in NAIVE mode")
    await fetch(`http://localhost:${agentPort}/control/mode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'NAIVE' }),
    });

    // Execute honest purchase through agent control API
    const purchaseRes = await fetch(`http://localhost:${agentPort}/control/purchase`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        run_id: 'phase1-honest-run',
        trace_id: 'trace-honest-1',
        intent: {
          product_query: 'mouse',
          quantity: 1,
          max_total_atomic: '30000000',
          currency: 'TUSD',
        },
        auto_confirm: true,
      }),
    });

    expect(purchaseRes.status).toBe(200);
    const purchaseData: any = await purchaseRes.json();
    if (purchaseData.decision !== 'ALLOW') {
      console.log('Purchase failed with details:', JSON.stringify(purchaseData, null, 2));
    }

    expect(purchaseData.decision).toBe('ALLOW');
    expect(purchaseData.order_result).toBeDefined();
    expect(purchaseData.order_result.status).toBe('confirmed');
    expect(purchaseData.order_result.product_id).toBe('mouse');
    expect(purchaseData.chain_delta_atomic).toBe('25000000'); // 25.00 TUSD for mouse
    expect(purchaseData.funds_lost_atomic).toBe('0');

    // Verify on-chain balances independently
    const postBalRes = await fetch(`http://localhost:${chainPort}/balances?address=${agentWalletAddress}`);
    const postBal = await postBalRes.json();
    expect(postBal.balance_atomic).toBe('975000000'); // 1,000,000,000 - 25,000,000

    const merchantBalRes = await fetch(`http://localhost:${chainPort}/balances?address=0x70997970c51812dc3a010c7d01b50e0d17dc79c8`);
    const merchantBal = await merchantBalRes.json();
    expect(merchantBal.balance_atomic).toBe('25000000');

    // Verify events arrived at the collector
    const eventsRes = await fetch(`http://localhost:${collectorPort}/events?run_id=phase1-honest-run`);
    const eventsData = await eventsRes.json();
    expect(eventsData.events.length).toBeGreaterThan(0);

    const metricsRes = await fetch(`http://localhost:${collectorPort}/metrics`);
    const metrics = await metricsRes.json();
    expect(metrics.totalRequests).toBeGreaterThanOrEqual(1);
    expect(metrics.fundsLostAtomic).toBe('0');
  });
});
