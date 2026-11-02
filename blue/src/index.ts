import * as http from 'node:http';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { createChainServer } from './chain/server';
import { createCollectorServer } from './collector/server';
import { createAgentServer } from './agent/server';
import { DEFAULT_PORTS } from './contracts/constants';
import { getContractsHash } from './contracts/hash';

const DATA_DIR = path.resolve(__dirname, '../data');

async function main() {
  console.log('\n=================================================================');
  console.log(' 🛡️  BLUE DEFENDER NODE (LAPTOP 1)');
  console.log('=================================================================');

  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  const contractsHash = getContractsHash().hash;
  console.log(`Contracts Hash: ${contractsHash.slice(0, 16)}...`);

  // Target Red host (can be set to LAN IP e.g. RED_HOST=192.168.1.50)
  const redHost = process.env.RED_HOST || 'localhost';
  const merchantUrl = process.env.MERCHANT_URL || `http://${redHost}:${DEFAULT_PORTS.RED_MERCHANT}`;

  const chainPort = Number(process.env.CHAIN_PORT) || DEFAULT_PORTS.BLUE_CHAIN;
  const collectorPort = Number(process.env.COLLECTOR_PORT) || DEFAULT_PORTS.BLUE_COLLECTOR;
  const agentPort = Number(process.env.AGENT_PORT) || DEFAULT_PORTS.BLUE_AGENT;

  const servers: { name: string; port: number; server: http.Server; db?: any }[] = [];

  const cleanup = () => {
    console.log('\n[blue] Shutting down Blue Defender services cleanly...');
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
    port: chainPort,
    dbPath: path.join(DATA_DIR, 'chain.db'),
    collectorUrl: `http://localhost:${collectorPort}`,
  });
  await new Promise<void>((r) => {
    const s = chainApp.app.listen(chainPort, '0.0.0.0', () => r());
    servers.push({ name: 'blue-chain', port: chainPort, server: s, db: (chainApp as any).db });
  });
  console.log(`[1/3] Blue Blockchain Ledger:  http://localhost:${chainPort}`);

  // 2. Collector & Dashboard (:4050)
  const collectorApp = createCollectorServer({
    port: collectorPort,
    dbPath: path.join(DATA_DIR, 'collector.db'),
  });
  await new Promise<void>((r) => {
    const s = collectorApp.app.listen(collectorPort, '0.0.0.0', () => r());
    servers.push({ name: 'blue-collector', port: collectorPort, server: s, db: collectorApp.db });
  });
  console.log(`[2/3] Blue Defender Dashboard: http://localhost:${collectorPort}`);

  // 3. AI Shopping Agent (:4010)
  const agentApp = createAgentServer({
    port: agentPort,
    merchantUrl,
    chainUrl: `http://localhost:${chainPort}`,
    collectorUrl: `http://localhost:${collectorPort}`,
    keysDir: path.join(DATA_DIR, '.keys'),
    budgetDbPath: path.join(DATA_DIR, 'budget.db'),
    auditDbPath: path.join(DATA_DIR, 'audit.jsonl'),
  });
  await new Promise<void>((r) => {
    const s = agentApp.app.listen(agentPort, '0.0.0.0', () => r());
    servers.push({ name: 'blue-agent', port: agentPort, server: s });
  });
  console.log(`[3/3] Blue AI Shopping Agent:  http://localhost:${agentPort}`);

  // Fund Agent Wallet with 1,000 TUSD
  const agentWallet = agentApp.rawAccount.address;
  await fetch(`http://localhost:${chainPort}/fund`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      address: agentWallet,
      amount_atomic: '1000000000',
    }),
  }).catch(() => {});

  console.log(`\n  💰 Funded Blue Agent wallet with 1,000.00 TUSD (${agentWallet})`);
  console.log(`  🔗 Target Merchant: ${merchantUrl}`);
  console.log('\n=================================================================');
  console.log(` 🛡️  DEFENDER DASHBOARD READY: http://localhost:${collectorPort}`);
  console.log(' Press Ctrl+C to stop.');
  console.log('=================================================================\n');
}

if (require.main === module || (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename))) {
  main().catch((err) => {
    console.error('Fatal Blue Node startup error:', err);
    process.exit(1);
  });
}
