import express, { Request, Response } from 'express';
import cors from 'cors';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { openSqliteDatabase, DatabaseAdapter } from '../storage/db';
import { KillSwitch, globalKillSwitch } from '../orchestrator/kill-switch';
import { AttackOrchestrator, AttackExecutionResult } from '../orchestrator/runner';
import { ATTACKS_CATALOG, ATTACK_IDS } from '../contracts/attacks';
import { TargetMode } from '../contracts/events';
import { DEFAULT_PORTS, fromAtomicUnits } from '../contracts/constants';
import { getContractsHash } from '../contracts/hash';

export interface ConsoleConfig {
  port?: number;
  dbPath?: string;
  orchestrator?: AttackOrchestrator;
  killSwitch?: KillSwitch;
  merchantUrl?: string;
  facilitatorUrl?: string;
  chainUrl?: string;
  agentUrl?: string;
  collectorUrl?: string;
}

export function createConsoleServer(config: ConsoleConfig = {}) {
  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '2mb' }));

  const port = config.port || Number(process.env.CONSOLE_PORT) || DEFAULT_PORTS.RED_CONSOLE;
  const dbPath = config.dbPath || path.resolve(__dirname, '../../data/console.db');
  const db: DatabaseAdapter = openSqliteDatabase(dbPath);

  const killSwitch = config.killSwitch || globalKillSwitch;
  const orchestrator =
    config.orchestrator ||
    new AttackOrchestrator({
      merchantUrl: config.merchantUrl,
      facilitatorUrl: config.facilitatorUrl,
      chainUrl: config.chainUrl,
      agentUrl: config.agentUrl,
      collectorUrl: config.collectorUrl,
      killSwitch,
    });

  // Create table for console attack runs
  db.exec(`
    CREATE TABLE IF NOT EXISTS attack_runs (
      id TEXT PRIMARY KEY,
      attack_id TEXT NOT NULL,
      target TEXT NOT NULL,
      seed INTEGER,
      run_id TEXT NOT NULL,
      trace_id TEXT NOT NULL,
      decision TEXT NOT NULL,
      reason TEXT,
      layer TEXT,
      funds_lost_atomic TEXT NOT NULL,
      chain_delta_atomic TEXT NOT NULL,
      latency_ms REAL NOT NULL,
      attacker_won INTEGER NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  // SSE clients
  const sseClients = new Set<Response>();

  function broadcastSSE(type: string, data: unknown) {
    const payload = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const client of sseClients) {
      try {
        client.write(payload);
      } catch {
        sseClients.delete(client);
      }
    }
  }

  function logTerminal(message: string, level: 'info' | 'warn' | 'error' | 'success' = 'info') {
    broadcastSSE('log', {
      timestamp: new Date().toISOString(),
      message,
      level,
    });
  }

  // Continuous Attack Loop State
  let continuousInterval: NodeJS.Timeout | null = null;
  let continuousRunning = false;

  // SSE Stream Endpoint
  app.get('/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    sseClients.add(res);

    // Initial greeting and status
    res.write(
      `event: status\ndata: ${JSON.stringify({
        armed: !killSwitch.isKilled(),
        killed: killSwitch.isKilled(),
        continuousRunning,
        contractsHash: getContractsHash().hash,
      })}\n\n`
    );

    req.on('close', () => {
      sseClients.delete(res);
    });
  });

  // GET /status
  app.get('/status', (req, res) => {
    res.json({
      armed: !killSwitch.isKilled(),
      killed: killSwitch.isKilled(),
      reason: killSwitch.getReason(),
      continuousRunning,
      contractsHash: getContractsHash().hash,
      activeAttacksCount: ATTACK_IDS.length,
    });
  });

  // POST /kill
  app.post('/kill', (req, res) => {
    const reason = req.body.reason || 'Emergency Stop triggered via Red Console UI';
    killSwitch.trip(reason);
    if (continuousInterval) {
      clearInterval(continuousInterval);
      continuousInterval = null;
      continuousRunning = false;
    }
    logTerminal(`[KILL SWITCH TRIPPED] All offensive operations halted: ${reason}`, 'error');
    broadcastSSE('kill', { killed: true, reason });
    res.json({ success: true, killed: true, reason });
  });

  // POST /reset
  app.post('/reset', (req, res) => {
    killSwitch.reset();
    logTerminal('[KILL SWITCH RESET] Offensive engine armed and ready.', 'success');
    broadcastSSE('reset', { killed: false });
    res.json({ success: true, killed: false });
  });

  // Helper to record an attack result in DB
  function recordResult(result: AttackExecutionResult) {
    const id = 'run-' + crypto.randomUUID();
    db.prepare(`
      INSERT INTO attack_runs (
        id, attack_id, target, seed, run_id, trace_id,
        decision, reason, layer, funds_lost_atomic, chain_delta_atomic,
        latency_ms, attacker_won, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      result.attackId,
      result.target,
      result.seed,
      result.runId,
      result.traceId,
      result.decision,
      result.reason,
      result.layer,
      result.funds_lost_atomic,
      result.chain_delta_atomic,
      result.latency_ms,
      result.attackerWon ? 1 : 0,
      new Date().toISOString()
    );
  }

  // POST /attack/run
  app.post('/attack/run', async (req, res) => {
    try {
      killSwitch.assertNotKilled();

      const { attack_id, target = 'BLUE_V1', seed = Date.now(), customParams, productQuery, quantity } = req.body;
      if (!attack_id) {
        return res.status(400).json({ error: 'attack_id is required' });
      }

      logTerminal(`[LAUNCH] Executing ${attack_id} against target ${target} (seed: ${seed})...`, 'info');

      const result = await orchestrator.runAttack({
        attackId: attack_id,
        target: target as TargetMode,
        seed: Number(seed),
        customParams,
        productQuery,
        quantity,
      });

      recordResult(result);

      const msg = `[RESULT] ${result.attackId} vs ${result.target} => ${result.decision} (Reason: ${result.reason || 'None'}, Layer: ${result.layer || 'N/A'}, Funds Lost: ${result.funds_lost_atomic} atomic, Latency: ${result.latency_ms.toFixed(1)}ms)`;
      logTerminal(msg, result.attackerWon ? 'warn' : 'success');

      broadcastSSE('attack_completed', result);
      res.json({ success: true, result });
    } catch (err: any) {
      logTerminal(`[ERROR] Attack launch failed: ${err.message}`, 'error');
      res.status(500).json({ error: err.message, killed: killSwitch.isKilled() });
    }
  });

  // POST /attack/matrix
  app.post('/attack/matrix', async (req, res) => {
    try {
      killSwitch.assertNotKilled();
      const targets: TargetMode[] = req.body.targets || ['NAIVE', 'BLUE_V0', 'BLUE_V1'];
      const attackIds: string[] = req.body.attack_ids || ATTACK_IDS;

      logTerminal(`[MATRIX START] Launching 18-attack matrix across [${targets.join(', ')}] (${attackIds.length * targets.length} total operations)...`, 'info');

      // Run asynchronously so response returns immediately, streaming results over SSE
      (async () => {
        let completed = 0;
        const total = attackIds.length * targets.length;

        for (const attackId of attackIds) {
          for (const target of targets) {
            if (killSwitch.isKilled()) {
              logTerminal('[MATRIX ABORTED] Kill switch tripped during matrix execution.', 'error');
              return;
            }

            try {
              const result = await orchestrator.runAttack({
                attackId,
                target,
                seed: 1337 + completed,
              });
              recordResult(result);
              completed++;
              broadcastSSE('attack_completed', result);
              broadcastSSE('matrix_progress', { completed, total, current: `${attackId} vs ${target}` });
              logTerminal(`[MATRIX] (${completed}/${total}) ${attackId} vs ${target} => ${result.attackerWon ? 'ATTACKER WON' : 'DEFENDER BLOCKED'}`, result.attackerWon ? 'warn' : 'info');
            } catch (err: any) {
              logTerminal(`[MATRIX ERROR] ${attackId} vs ${target}: ${err.message}`, 'error');
            }
          }
        }
        logTerminal(`[MATRIX FINISHED] Completed ${completed}/${total} attacks successfully.`, 'success');
      })();

      res.json({ success: true, message: 'Matrix execution started', totalAttacks: attackIds.length * targets.length });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /attack/continuous
  app.post('/attack/continuous', (req, res) => {
    try {
      killSwitch.assertNotKilled();
      if (continuousRunning) {
        return res.json({ success: true, message: 'Continuous runner already active' });
      }

      const intervalMs = Number(req.body.interval_ms) || 2000;
      continuousRunning = true;
      logTerminal(`[CONTINUOUS START] Continuous offensive loop initialized (Interval: ${intervalMs}ms)`, 'info');
      broadcastSSE('continuous_state', { running: true });

      continuousInterval = setInterval(async () => {
        if (killSwitch.isKilled()) {
          clearInterval(continuousInterval!);
          continuousInterval = null;
          continuousRunning = false;
          broadcastSSE('continuous_state', { running: false });
          return;
        }

        const randomAttack = ATTACK_IDS[Math.floor(Math.random() * ATTACK_IDS.length)];
        const targets: TargetMode[] = ['NAIVE', 'BLUE_V0', 'BLUE_V1'];
        const randomTarget = targets[Math.floor(Math.random() * targets.length)];

        try {
          const result = await orchestrator.runAttack({
            attackId: randomAttack,
            target: randomTarget,
            seed: Date.now(),
          });
          recordResult(result);
          broadcastSSE('attack_completed', result);
          logTerminal(`[CONTINUOUS] ${randomAttack} vs ${randomTarget} => ${result.attackerWon ? 'WON' : 'BLOCKED'}`, result.attackerWon ? 'warn' : 'info');
        } catch (err: any) {
          logTerminal(`[CONTINUOUS ERROR] ${err.message}`, 'error');
        }
      }, intervalMs);

      res.json({ success: true, message: 'Continuous attack runner started' });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /attack/stop
  app.post('/attack/stop', (req, res) => {
    if (continuousInterval) {
      clearInterval(continuousInterval);
      continuousInterval = null;
    }
    continuousRunning = false;
    logTerminal('[CONTINUOUS STOP] Continuous offensive loop terminated.', 'info');
    broadcastSSE('continuous_state', { running: false });
    res.json({ success: true, message: 'Continuous runner stopped' });
  });

  // GET /matrix - Aggregated matrix data
  app.get('/matrix', (req, res) => {
    const rows = db.prepare('SELECT * FROM attack_runs ORDER BY rowid ASC').all();
    const matrix: Record<
      string,
      Record<
        TargetMode,
        { attempts: number; won: number; blocked: number; fundsLostAtomic: string; avgLatencyMs: number }
      >
    > = {};

    for (const aId of ATTACK_IDS) {
      matrix[aId] = {
        NAIVE: { attempts: 0, won: 0, blocked: 0, fundsLostAtomic: '0', avgLatencyMs: 0 },
        BLUE_V0: { attempts: 0, won: 0, blocked: 0, fundsLostAtomic: '0', avgLatencyMs: 0 },
        BLUE_V1: { attempts: 0, won: 0, blocked: 0, fundsLostAtomic: '0', avgLatencyMs: 0 },
      };
    }

    const latencies: Record<string, number[]> = {};

    for (const row of rows) {
      const aId = row.attack_id;
      const target = row.target as TargetMode;
      if (!matrix[aId] || !matrix[aId][target]) continue;

      const cell = matrix[aId][target];
      cell.attempts++;
      if (row.attacker_won === 1) cell.won++;
      else cell.blocked++;

      cell.fundsLostAtomic = (BigInt(cell.fundsLostAtomic) + BigInt(row.funds_lost_atomic || '0')).toString();

      const key = `${aId}:${target}`;
      if (!latencies[key]) latencies[key] = [];
      latencies[key].push(row.latency_ms);
    }

    for (const aId of ATTACK_IDS) {
      for (const t of ['NAIVE', 'BLUE_V0', 'BLUE_V1'] as TargetMode[]) {
        const key = `${aId}:${t}`;
        const arr = latencies[key] || [];
        if (arr.length > 0) {
          matrix[aId][t].avgLatencyMs = Number((arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(1));
        }
      }
    }

    res.json({ matrix, catalog: ATTACKS_CATALOG });
  });

  // GET /export/json
  app.get('/export/json', (req, res) => {
    const rows = db.prepare('SELECT * FROM attack_runs ORDER BY rowid ASC').all();
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="red_attack_results.json"');
    res.send(JSON.stringify(rows, null, 2));
  });

  // GET /export/csv
  app.get('/export/csv', (req, res) => {
    const rows = db.prepare('SELECT * FROM attack_runs ORDER BY rowid ASC').all();
    const headers = [
      'id',
      'attack_id',
      'target',
      'seed',
      'run_id',
      'trace_id',
      'decision',
      'reason',
      'layer',
      'funds_lost_atomic',
      'chain_delta_atomic',
      'latency_ms',
      'attacker_won',
      'created_at',
    ];
    let csv = headers.join(',') + '\n';
    for (const r of rows) {
      const line = headers.map((h) => JSON.stringify(r[h] ?? '')).join(',');
      csv += line + '\n';
    }
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="red_attack_results.csv"');
    res.send(csv);
  });

  // POST /results/reset
  app.post('/results/reset', (req, res) => {
    db.exec('DELETE FROM attack_runs;');
    logTerminal('[DATABASE RESET] All attack history cleared from Red console store.', 'info');
    broadcastSSE('reset_results', {});
    res.json({ success: true, message: 'Attack runs database cleared' });
  });

  // Serve Red Console HTML
  app.get('/', (req, res) => {
    res.send(renderRedConsoleHtml());
  });
  app.get('/console', (req, res) => {
    res.send(renderRedConsoleHtml());
  });

  return { app, port, db, killSwitch };
}

function renderRedConsoleHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Attacker Console // Red Node — x402 Security System</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background-color: #0A0507; color: #FEE2E2; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    .crimson-glow { box-shadow: 0 0 25px rgba(225, 29, 72, 0.4); }
    .kill-active { animation: pulse-kill 1.5s infinite; }
    @keyframes pulse-kill {
      0%, 100% { box-shadow: 0 0 20px rgba(225, 29, 72, 0.8); }
      50% { box-shadow: 0 0 40px rgba(225, 29, 72, 1); }
    }
  </style>
</head>
<body class="p-6">
  <div class="max-w-7xl mx-auto space-y-6">

    <!-- Top Navigation Header -->
    <header class="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-rose-950 pb-4 gap-4">
      <div>
        <div class="flex items-center space-x-3">
          <span class="inline-block w-3 h-3 rounded-full bg-rose-500 animate-ping"></span>
          <h1 class="text-2xl font-black text-rose-500 tracking-wider">ATTACK CONSOLE // RED NODE</h1>
        </div>
        <p class="text-xs text-rose-300/70 mt-1">Autonomous Hostile Protocol Simulator, Exploitation Matrix & Mutation Engine</p>
      </div>

      <div class="flex items-center space-x-4">
        <span id="contracts-hash" class="text-xs px-3 py-1.5 bg-rose-950/40 rounded border border-rose-900/60 text-rose-300">Hash: Loading...</span>

        <!-- LIVE KILL SWITCH BUTTON -->
        <button id="kill-toggle-btn" onclick="toggleKillSwitch()" class="px-5 py-2.5 rounded font-black text-xs tracking-wider transition-all duration-200 border bg-rose-950 border-rose-500 text-rose-400 hover:bg-rose-900">
          KILL SWITCH: ARMED
        </button>
      </div>
    </header>

    <!-- Top Command Ribbon -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
      <div class="bg-rose-950/20 border border-rose-900/40 p-4 rounded-lg">
        <div class="text-xs text-rose-400/80 font-bold">TOTAL ATTACKS LAUNCHED</div>
        <div id="stat-total-attacks" class="text-2xl font-black text-white mt-1">0</div>
      </div>
      <div class="bg-rose-950/20 border border-rose-900/40 p-4 rounded-lg">
        <div class="text-xs text-rose-400/80 font-bold">DRAINED / WON (ALL TARGETS)</div>
        <div id="stat-total-drained" class="text-2xl font-black text-rose-500 mt-1">0 TUSD</div>
      </div>
      <div class="bg-rose-950/20 border border-rose-900/40 p-4 rounded-lg">
        <div class="text-xs text-rose-400/80 font-bold">BLUE_V1 BLOCKED RATE</div>
        <div id="stat-v1-rate" class="text-2xl font-black text-emerald-400 mt-1">100.0%</div>
      </div>
      <div class="bg-rose-950/20 border border-rose-900/40 p-4 rounded-lg">
        <div class="text-xs text-rose-400/80 font-bold">ACTIVE TEST ARMS</div>
        <div class="text-2xl font-black text-amber-400 mt-1">18 Attacks</div>
      </div>
    </div>

    <!-- Attack Launcher & Control Bar -->
    <div class="bg-stone-950 border border-rose-900/40 p-5 rounded-lg space-y-4">
      <div class="flex items-center justify-between border-b border-rose-950 pb-3">
        <h2 class="text-sm font-bold text-rose-400 tracking-wider">OFFENSIVE LAUNCH CONTROLLER</h2>
        <div class="flex items-center space-x-2 text-xs">
          <button onclick="exportData('csv')" class="px-3 py-1 bg-stone-900 hover:bg-stone-800 border border-rose-900/40 rounded text-rose-300">Export CSV</button>
          <button onclick="exportData('json')" class="px-3 py-1 bg-stone-900 hover:bg-stone-800 border border-rose-900/40 rounded text-rose-300">Export JSON</button>
          <button onclick="resetResults()" class="px-3 py-1 bg-rose-950/60 hover:bg-rose-900 border border-rose-800 rounded text-rose-200">Reset Data</button>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
        <div>
          <label class="block text-xs text-rose-300/80 mb-1">Select Attack Vector</label>
          <select id="select-attack" class="w-full bg-stone-900 border border-rose-900/60 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-rose-500">
            <option value="A1">A1: Payee Swap (Single)</option>
            <option value="A2">A2: Payee Swap on Request N</option>
            <option value="A3">A3: Price Creep</option>
            <option value="A4">A4: Wallet Drain</option>
            <option value="A5">A5: Fake Asset / Network</option>
            <option value="A6">A6: Amount Parsing Manipulation</option>
            <option value="A7">A7: Parallel Burst Race</option>
            <option value="A8">A8: Quote Mutation Tampering</option>
            <option value="A9">A9: Long Authorization Window</option>
            <option value="A10">A10: Redirect / Lookalike Host</option>
            <option value="A11">A11: Slow Drain Velocity Loop</option>
            <option value="A12">A12: Prompt Injection in Desc</option>
            <option value="A13">A13: Binding Hygiene Mismatch</option>
            <option value="A14">A14: Multi-Option Confusion</option>
            <option value="A15">A15: Header & Version Confusion</option>
            <option value="A16">A16: Facilitator Settlement Lies</option>
            <option value="A17">A17: Settle and Fail Double-Debit</option>
            <option value="A18">A18: Approval Bypass Dummy Token</option>
          </select>
        </div>

        <div>
          <label class="block text-xs text-rose-300/80 mb-1">Target Mode</label>
          <select id="select-target" class="w-full bg-stone-900 border border-rose-900/60 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-rose-500">
            <option value="BLUE_V1">BLUE_V1 (Hardened 9-Layer)</option>
            <option value="BLUE_V0">BLUE_V0 (Baseline Caps)</option>
            <option value="NAIVE">NAIVE (No Guard)</option>
          </select>
        </div>

        <div>
          <label class="block text-xs text-rose-300/80 mb-1">PRNG Seed</label>
          <input id="input-seed" type="number" value="1337" class="w-full bg-stone-900 border border-rose-900/60 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-rose-500">
        </div>

        <div class="flex space-x-2">
          <button id="btn-launch-single" onclick="launchSingleAttack()" class="flex-1 bg-rose-600 hover:bg-rose-500 text-white font-bold py-2 px-3 rounded text-xs transition duration-150">
            Launch Attack
          </button>
          <button id="btn-launch-matrix" onclick="launchMatrix()" class="flex-1 bg-amber-600 hover:bg-amber-500 text-white font-bold py-2 px-3 rounded text-xs transition duration-150">
            Run 18 Matrix
          </button>
          <button id="btn-continuous" onclick="toggleContinuous()" class="px-3 bg-purple-900 hover:bg-purple-800 border border-purple-700 text-purple-200 font-bold py-2 rounded text-xs">
            Loop
          </button>
        </div>
      </div>
    </div>

    <!-- Main Comparison Matrix & Terminal -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">

      <!-- 18 Attack Comparison Matrix Table (2 cols) -->
      <div class="lg:col-span-2 bg-stone-950 border border-rose-900/40 rounded-lg p-4 space-y-3">
        <div class="flex justify-between items-center border-b border-rose-950 pb-2">
          <h2 class="text-sm font-bold text-rose-400">18-ATTACK CROSS-TARGET COMPARISON MATRIX</h2>
          <span class="text-xs text-rose-400/60">Live Updates via SSE</span>
        </div>

        <div class="overflow-x-auto max-h-[520px] overflow-y-auto">
          <table class="w-full text-left text-xs border-collapse">
            <thead>
              <tr class="border-b border-rose-900/60 text-rose-400 bg-rose-950/30">
                <th class="p-2">ID</th>
                <th class="p-2">Attack Name</th>
                <th class="p-2 text-center">Layer</th>
                <th class="p-2 text-center">NAIVE</th>
                <th class="p-2 text-center">BLUE_V0</th>
                <th class="p-2 text-center">BLUE_V1</th>
              </tr>
            </thead>
            <tbody id="matrix-tbody" class="divide-y divide-rose-950/40">
              <!-- Dynamically populated via JS -->
            </tbody>
          </table>
        </div>
      </div>

      <!-- Live Terminal Stream (1 col) -->
      <div class="bg-stone-950 border border-rose-900/40 rounded-lg p-4 flex flex-col h-[580px]">
        <div class="flex justify-between items-center border-b border-rose-950 pb-2 mb-3">
          <div class="flex items-center space-x-2">
            <span class="w-2 h-2 rounded-full bg-rose-500"></span>
            <h2 class="text-sm font-bold text-rose-400">OFFENSIVE LOG TERMINAL</h2>
          </div>
          <button onclick="clearTerminal()" class="text-xs text-rose-400/60 hover:text-rose-200">Clear</button>
        </div>

        <div id="terminal-logs" class="flex-1 overflow-y-auto space-y-1.5 text-[11px] font-mono pr-2">
          <div class="text-rose-400/60">[SYSTEM] Terminal initialized. Waiting for stream connection...</div>
        </div>
      </div>

    </div>

  </div>

  <script>
    let isKilled = false;
    let isContinuous = false;
    let eventSource = null;

    function initSSE() {
      if (eventSource) eventSource.close();
      eventSource = new EventSource('/stream');

      eventSource.addEventListener('status', (e) => {
        const data = JSON.parse(e.data);
        updateKillState(data.killed);
        isContinuous = data.continuousRunning;
        document.getElementById('contracts-hash').textContent = 'Hash: ' + (data.contractsHash ? data.contractsHash.slice(0, 10) + '...' : 'OK');
        updateContinuousBtn();
      });

      eventSource.addEventListener('kill', (e) => {
        const data = JSON.parse(e.data);
        updateKillState(data.killed);
      });

      eventSource.addEventListener('reset', (e) => {
        const data = JSON.parse(e.data);
        updateKillState(data.killed);
      });

      eventSource.addEventListener('continuous_state', (e) => {
        const data = JSON.parse(e.data);
        isContinuous = data.running;
        updateContinuousBtn();
      });

      eventSource.addEventListener('log', (e) => {
        const data = JSON.parse(e.data);
        appendTerminal(data.message, data.level);
      });

      eventSource.addEventListener('attack_completed', (e) => {
        loadMatrix();
      });

      eventSource.addEventListener('reset_results', () => {
        loadMatrix();
      });

      eventSource.onerror = () => {
        appendTerminal('[DISCONNECTED] SSE stream lost, reconnecting...', 'warn');
      };
    }

    function appendTerminal(msg, level = 'info') {
      const container = document.getElementById('terminal-logs');
      const div = document.createElement('div');
      const time = new Date().toLocaleTimeString();

      let color = 'text-slate-300';
      if (level === 'error') color = 'text-rose-400 font-bold';
      else if (level === 'warn') color = 'text-amber-400 font-bold';
      else if (level === 'success') color = 'text-emerald-400';

      div.className = color;
      div.textContent = '[' + time + '] ' + msg;
      container.appendChild(div);
      container.scrollTop = container.scrollHeight;
    }

    function clearTerminal() {
      document.getElementById('terminal-logs').innerHTML = '';
    }

    function updateKillState(killed) {
      isKilled = killed;
      const btn = document.getElementById('kill-toggle-btn');
      if (isKilled) {
        btn.textContent = 'EMERGENCY STOP (CLICK TO RESET)';
        btn.className = 'px-5 py-2.5 rounded font-black text-xs tracking-wider transition-all duration-200 border bg-rose-600 text-white kill-active border-rose-400';
      } else {
        btn.textContent = 'KILL SWITCH: ARMED';
        btn.className = 'px-5 py-2.5 rounded font-black text-xs tracking-wider transition-all duration-200 border bg-rose-950 border-rose-500 text-rose-400 hover:bg-rose-900';
      }
    }

    async function toggleKillSwitch() {
      if (isKilled) {
        await fetch('/reset', { method: 'POST' });
      } else {
        await fetch('/kill', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: 'Operator pressed Big Red Button' })
        });
      }
    }

    function updateContinuousBtn() {
      const btn = document.getElementById('btn-continuous');
      if (isContinuous) {
        btn.textContent = 'Stop Loop';
        btn.className = 'px-3 bg-rose-800 hover:bg-rose-700 border border-rose-600 text-white font-bold py-2 rounded text-xs';
      } else {
        btn.textContent = 'Loop';
        btn.className = 'px-3 bg-purple-900 hover:bg-purple-800 border border-purple-700 text-purple-200 font-bold py-2 rounded text-xs';
      }
    }

    async function toggleContinuous() {
      if (isContinuous) {
        await fetch('/attack/stop', { method: 'POST' });
      } else {
        await fetch('/attack/continuous', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ interval_ms: 1500 })
        });
      }
    }

    async function launchSingleAttack() {
      const attackId = document.getElementById('select-attack').value;
      const target = document.getElementById('select-target').value;
      const seed = Number(document.getElementById('input-seed').value);

      await fetch('/attack/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_id: attackId, target, seed })
      });
    }

    async function launchMatrix() {
      await fetch('/attack/matrix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
    }

    async function resetResults() {
      if (confirm('Are you sure you want to clear all attack history?')) {
        await fetch('/results/reset', { method: 'POST' });
      }
    }

    function exportData(format) {
      window.location.href = '/export/' + format;
    }

    async function loadMatrix() {
      try {
        const res = await fetch('/matrix');
        const data = await res.json();
        const matrix = data.matrix || {};
        const catalog = data.catalog || {};

        const tbody = document.getElementById('matrix-tbody');
        tbody.innerHTML = '';

        let totalAttacks = 0;
        let totalDrainedBigInt = 0n;
        let v1Attempts = 0;
        let v1Blocked = 0;

        for (const [id, meta] of Object.entries(catalog)) {
          const m = matrix[id] || {};
          const tr = document.createElement('tr');
          tr.className = 'hover:bg-rose-950/20';

          const renderCell = (cell) => {
            if (!cell || cell.attempts === 0) {
              return '<span class="text-stone-600 font-mono">—</span>';
            }
            totalAttacks += cell.attempts;
            totalDrainedBigInt += BigInt(cell.fundsLostAtomic || '0');

            if (cell.won > 0) {
              return '<span class="px-2 py-0.5 rounded text-[10px] bg-rose-950 text-rose-300 border border-rose-700 font-bold">DRAINED (' + (Number(cell.fundsLostAtomic) / 1e6).toFixed(1) + 'T)</span>';
            } else {
              return '<span class="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-700 font-bold">BLOCKED (' + cell.avgLatencyMs + 'ms)</span>';
            }
          };

          const naiveHtml = renderCell(m.NAIVE);
          const v0Html = renderCell(m.BLUE_V0);
          const v1Html = renderCell(m.BLUE_V1);

          if (m.BLUE_V1 && m.BLUE_V1.attempts > 0) {
            v1Attempts += m.BLUE_V1.attempts;
            v1Blocked += m.BLUE_V1.blocked;
          }

          tr.innerHTML =
            '<td class="p-2 font-bold text-rose-300">' + id + '</td>' +
            '<td class="p-2 text-stone-300">' + meta.name + '</td>' +
            '<td class="p-2 text-center text-amber-400 font-mono">' + meta.expectedLayer + '</td>' +
            '<td class="p-2 text-center">' + naiveHtml + '</td>' +
            '<td class="p-2 text-center">' + v0Html + '</td>' +
            '<td class="p-2 text-center">' + v1Html + '</td>';
          tbody.appendChild(tr);
        }

        document.getElementById('stat-total-attacks').textContent = totalAttacks;
        document.getElementById('stat-total-drained').textContent = (Number(totalDrainedBigInt) / 1e6).toFixed(2) + ' TUSD';
        const v1Rate = v1Attempts > 0 ? ((v1Blocked / v1Attempts) * 100).toFixed(1) + '%' : '100.0%';
        document.getElementById('stat-v1-rate').textContent = v1Rate;

      } catch (err) {
        console.error('Failed to load matrix:', err);
      }
    }

    window.onload = () => {
      initSSE();
      loadMatrix();
    };
  </script>
</body>
</html>`;
}

if (require.main === module || (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename))) {
  const { app, port } = createConsoleServer();
  app.listen(port, '0.0.0.0', () => {
    console.log(`[red-console] Red Attacker Console listening on http://0.0.0.0:${port}`);
  });
}
