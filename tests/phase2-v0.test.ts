import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as http from 'node:http';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { createChainServer } from '../blue/src/chain/server';
import { createCollectorServer } from '../blue/src/collector/server';
import { createFacilitatorServer } from '../red/src/facilitator/server';
import { createMerchantServer } from '../red/src/merchant/server';
import { createAgentServer } from '../blue/src/agent/server';

describe('Phase 2 — Facilitator + V0 Module & Mode Switching', () => {
  let chainServer: http.Server;
  let collectorServer: http.Server;
  let facilitatorServer: http.Server;
  let merchantServer: http.Server;
  let agentServer: http.Server;
  let agentWalletAddress: string;

  let chainDb: any;
  let collectorDb: any;

  const chainPort = 4540;
  const collectorPort = 4550;
  const facilitatorPort = 4530;
  const merchantPort = 4520;
  const agentPort = 4510;

  const testDbDir = path.resolve(__dirname, '../data/test-phase2');
  const chainDbPath = path.join(testDbDir, 'chain.db');
  const collectorDbPath = path.join(testDbDir, 'collector.db');
  const keysDir = path.join(testDbDir, '.keys');

  beforeAll(async () => {
    if (fs.existsSync(testDbDir)) {
      try { fs.rmSync(testDbDir, { recursive: true, force: true }); } catch {}
    }
    fs.mkdirSync(testDbDir, { recursive: true });

    // 1. Mock Chain
    const chainApp = createChainServer({
      port: chainPort,
      dbPath: chainDbPath,
      collectorUrl: `http://localhost:${collectorPort}`,
    });
    chainDb = chainApp.db;
    await new Promise<void>((r) => { chainServer = chainApp.app.listen(chainPort, () => r()); });

    // 2. Collector
    const collectorApp = createCollectorServer({
      port: collectorPort,
      dbPath: collectorDbPath,
    });
    collectorDb = collectorApp.db;
    await new Promise<void>((r) => { collectorServer = collectorApp.app.listen(collectorPort, () => r()); });

    // 3. Facilitator
    const facApp = createFacilitatorServer({
      port: facilitatorPort,
      chainUrl: `http://localhost:${chainPort}`,
    });
    await new Promise<void>((r) => { facilitatorServer = facApp.app.listen(facilitatorPort, () => r()); });

    // 4. Merchant
    const merchantApp = createMerchantServer({
      port: merchantPort,
      facilitatorUrl: `http://localhost:${facilitatorPort}`,
      honestPayTo: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    });
    await new Promise<void>((r) => { merchantServer = merchantApp.app.listen(merchantPort, () => r()); });

    // 5. Agent
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
    await new Promise<void>((r) => { agentServer = agentApp.app.listen(agentPort, () => r()); });

    // Fund agent wallet with 1,000 TUSD
    await fetch(`http://localhost:${chainPort}/fund`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        address: agentWalletAddress,
        amount_atomic: '1000000000',
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

  it('executes honest purchase under NAIVE mode', async () => {
    await fetch(`http://localhost:${agentPort}/control/mode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'NAIVE' }),
    });

    const res = await fetch(`http://localhost:${agentPort}/control/purchase`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        run_id: 'naive-honest-test',
        trace_id: 'trace-naive-1',
        intent: { product_query: 'mouse', quantity: 1, max_total_atomic: '30000000', currency: 'TUSD' },
        auto_confirm: true,
      }),
    });

    expect(res.status).toBe(200);
    const data: any = await res.json();
    expect(data.decision).toBe('ALLOW');
    expect(data.order_result?.status).toBe('confirmed');
    expect(data.chain_delta_atomic).toBe('25000000');
  });

  it('executes honest purchase under BLUE_V0 mode', async () => {
    await fetch(`http://localhost:${agentPort}/control/mode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'BLUE_V0' }),
    });

    const res = await fetch(`http://localhost:${agentPort}/control/purchase`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        run_id: 'v0-honest-test',
        trace_id: 'trace-v0-1',
        intent: { product_query: 'cable', quantity: 1, max_total_atomic: '10000000', currency: 'TUSD' },
        auto_confirm: true,
      }),
    });

    expect(res.status).toBe(200);
    const data: any = await res.json();
    expect(data.decision).toBe('ALLOW');
    expect(data.order_result?.status).toBe('confirmed');
    expect(data.chain_delta_atomic).toBe('5000000'); // 5.00 TUSD for cable
  });

  it('executes honest purchase under BLUE_V1 mode', async () => {
    await fetch(`http://localhost:${agentPort}/control/mode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'BLUE_V1' }),
    });

    const res = await fetch(`http://localhost:${agentPort}/control/purchase`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        run_id: 'v1-honest-test',
        trace_id: 'trace-v1-' + Date.now(),
        intent: { product_query: 'mouse', quantity: 1, max_total_atomic: '30000000', currency: 'TUSD' },
        auto_confirm: true,
      }),
    });

    expect(res.status).toBe(200);
    const data: any = await res.json();
    expect(data.reason).toBe('OK');
    expect(data.decision).toBe('ALLOW');
    expect(data.order_result?.status).toBe('confirmed');
    expect(data.chain_delta_atomic).toBe('25000000');
    expect(data.signed).toBe(true);
  });
});
