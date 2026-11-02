import * as http from 'node:http';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { createChainServer } from '../blue/src/chain/server';
import { createCollectorServer } from '../blue/src/collector/server';
import { createAgentServer } from '../blue/src/agent/server';
import { createFacilitatorServer } from '../red/src/facilitator/server';
import { createMerchantServer } from '../red/src/merchant/server';
import { createConsoleServer } from '../red/src/console/server';
import { getContractsHash } from '../contracts/hash';
import { DEFAULT_PORTS } from '../contracts/constants';

const DATA_DIR = path.resolve(__dirname, '../data/solo');

async function main() {
  console.log('\n=================================================================');
  console.log(' 🚀 x402 RED-BLUE PAYMENT SECURITY LAB — SOLO RUNNER');
  console.log('=================================================================');

  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  const contractsHash = getContractsHash();
  console.log(`Contracts Hash: ${contractsHash.slice(0, 16)}...`);

  const servers: { name: string; port: number; server: http.Server; db?: any }[] = [];

  const cleanup = () => {
    console.log('\n[solo] Shutting down services cleanly...');
    for (const s of servers) {
      try {
        s.server.close();
        if (s.db) s.db.close();
        console.log(`  ✓ Stopped ${s.name} (:${s.port})`);
      } catch {}
    }
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  // 1. Mock Blockchain (:4040)
  const chainApp = createChainServer({
    port: DEFAULT_PORTS.BLUE_CHAIN,
    dbPath: path.join(DATA_DIR, 'chain.db'),
    collectorUrl: `http://localhost:${DEFAULT_PORTS.BLUE_COLLECTOR}`,
  });
  await new Promise<void>((r) => {
    const s = chainApp.app.listen(DEFAULT_PORTS.BLUE_CHAIN, '0.0.0.0', () => r());
    servers.push({ name: 'blue-chain', port: DEFAULT_PORTS.BLUE_CHAIN, server: s, db: (chainApp as any).db });
  });
  console.log(`[1/6] Blue Mock Blockchain active on      http://localhost:${DEFAULT_PORTS.BLUE_CHAIN}`);

  // 2. Collector (:4050)
  const collectorApp = createCollectorServer({
    port: DEFAULT_PORTS.BLUE_COLLECTOR,
    dbPath: path.join(DATA_DIR, 'collector.db'),
  });
  await new Promise<void>((r) => {
    const s = collectorApp.app.listen(DEFAULT_PORTS.BLUE_COLLECTOR, '0.0.0.0', () => r());
    servers.push({ name: 'blue-collector', port: DEFAULT_PORTS.BLUE_COLLECTOR, server: s, db: collectorApp.db });
  });
  console.log(`[2/6] Blue Event Collector active on      http://localhost:${DEFAULT_PORTS.BLUE_COLLECTOR}`);

  // 3. Facilitator (:4030)
  const facApp = createFacilitatorServer({
    port: DEFAULT_PORTS.RED_FACILITATOR,
    chainUrl: `http://localhost:${DEFAULT_PORTS.BLUE_CHAIN}`,
  });
  await new Promise<void>((r) => {
    const s = facApp.app.listen(DEFAULT_PORTS.RED_FACILITATOR, '0.0.0.0', () => r());
    servers.push({ name: 'red-facilitator', port: DEFAULT_PORTS.RED_FACILITATOR, server: s });
  });
  console.log(`[3/6] Red Mock Facilitator active on      http://localhost:${DEFAULT_PORTS.RED_FACILITATOR}`);

  // 4. Hostile Merchant (:4020)
  const merchantApp = createMerchantServer({
    port: DEFAULT_PORTS.RED_MERCHANT,
    facilitatorUrl: `http://localhost:${DEFAULT_PORTS.RED_FACILITATOR}`,
    chainUrl: `http://localhost:${DEFAULT_PORTS.BLUE_CHAIN}`,
  });
  await new Promise<void>((r) => {
    const s = merchantApp.app.listen(DEFAULT_PORTS.RED_MERCHANT, '0.0.0.0', () => r());
    servers.push({ name: 'red-merchant', port: DEFAULT_PORTS.RED_MERCHANT, server: s });
  });
  console.log(`[4/6] Red Hostile Merchant active on      http://localhost:${DEFAULT_PORTS.RED_MERCHANT}`);

  // 5. AI Shopping Agent (:4010)
  const agentApp = createAgentServer({
    port: DEFAULT_PORTS.BLUE_AGENT,
    merchantUrl: `http://localhost:${DEFAULT_PORTS.RED_MERCHANT}`,
    chainUrl: `http://localhost:${DEFAULT_PORTS.BLUE_CHAIN}`,
    collectorUrl: `http://localhost:${DEFAULT_PORTS.BLUE_COLLECTOR}`,
    keysDir: path.join(DATA_DIR, '.keys'),
  });
  await new Promise<void>((r) => {
    const s = agentApp.app.listen(DEFAULT_PORTS.BLUE_AGENT, '0.0.0.0', () => r());
    servers.push({ name: 'blue-agent', port: DEFAULT_PORTS.BLUE_AGENT, server: s });
  });
  console.log(`[5/6] Blue AI Shopping Agent active on    http://localhost:${DEFAULT_PORTS.BLUE_AGENT}`);

  // 6. Red Attacker Console (:4060)
  const consoleApp = createConsoleServer({
    port: DEFAULT_PORTS.RED_CONSOLE,
    dbPath: path.join(DATA_DIR, 'console.db'),
    merchantUrl: `http://localhost:${DEFAULT_PORTS.RED_MERCHANT}`,
    facilitatorUrl: `http://localhost:${DEFAULT_PORTS.RED_FACILITATOR}`,
    chainUrl: `http://localhost:${DEFAULT_PORTS.BLUE_CHAIN}`,
    agentUrl: `http://localhost:${DEFAULT_PORTS.BLUE_AGENT}`,
    collectorUrl: `http://localhost:${DEFAULT_PORTS.BLUE_COLLECTOR}`,
  });
  await new Promise<void>((r) => {
    const s = consoleApp.app.listen(DEFAULT_PORTS.RED_CONSOLE, '0.0.0.0', () => r());
    servers.push({ name: 'red-console', port: DEFAULT_PORTS.RED_CONSOLE, server: s, db: consoleApp.db });
  });
  console.log(`[6/6] Red Attacker Console active on      http://localhost:${DEFAULT_PORTS.RED_CONSOLE}`);

  // Seed funds to agent
  const agentWallet = agentApp.rawAccount.address;
  await fetch(`http://localhost:${DEFAULT_PORTS.BLUE_CHAIN}/fund`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      address: agentWallet,
      amount_atomic: '1000000000', // 1,000 TUSD
    }),
  });
  console.log(`\n  💰 Funded Blue Agent wallet with 1,000.00 TUSD (${agentWallet})`);

  console.log('\n=================================================================');
  console.log(' 🎉 ALL SERVICES ONLINE & SYNCHRONIZED');
  console.log('-----------------------------------------------------------------');
  console.log(` 🛡️  BLUE DEFENDER DASHBOARD:   http://localhost:${DEFAULT_PORTS.BLUE_COLLECTOR}`);
  console.log(` ⚔️  RED ATTACKER CONSOLE:      http://localhost:${DEFAULT_PORTS.RED_CONSOLE}`);
  console.log('-----------------------------------------------------------------');
  console.log(' Press Ctrl+C to terminate all services.');
  console.log('=================================================================\n');
}

if (require.main === module || (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename))) {
  main().catch((err) => {
    console.error('Fatal solo startup error:', err);
    process.exit(1);
  });
}
