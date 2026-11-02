import express, { Request, Response } from 'express';
import cors from 'cors';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { openSqliteDatabase, DatabaseAdapter } from '../storage/db';
import { SecurityEventSchema, SecurityEvent } from '../contracts/events';
import { getContractsHash } from '../contracts/hash';
import { DEFAULT_PORTS } from '../contracts/constants';

export interface CollectorConfig {
  port?: number;
  dbPath?: string;
  eventToken?: string;
}

export function createCollectorServer(config: CollectorConfig = {}) {
  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '2mb' }));

  const port = config.port || Number(process.env.COLLECTOR_PORT) || DEFAULT_PORTS.BLUE_COLLECTOR;
  const dbPath = config.dbPath || path.resolve(__dirname, '../../data/collector.db');
  const db: DatabaseAdapter = openSqliteDatabase(dbPath);
  const startTime = Date.now();

  // Create tables
  db.exec(`
    CREATE TABLE IF NOT EXISTS events (
      event_id TEXT PRIMARY KEY,
      run_id TEXT NOT NULL,
      trace_id TEXT NOT NULL,
      worker TEXT NOT NULL,
      attack TEXT,
      seed INTEGER,
      target TEXT NOT NULL,
      decision TEXT NOT NULL,
      reason TEXT,
      layer TEXT,
      pin_hash TEXT,
      amount_atomic TEXT,
      chain_delta_atomic TEXT,
      funds_lost_atomic TEXT NOT NULL,
      latency_ms REAL NOT NULL,
      policy_digest TEXT,
      ts TEXT NOT NULL,
      details TEXT
    );

    CREATE TABLE IF NOT EXISTS alarms (
      alarm_id TEXT PRIMARY KEY,
      severity TEXT NOT NULL,
      alarm_type TEXT NOT NULL,
      message TEXT NOT NULL,
      event_id TEXT,
      acknowledged INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );
  `);

  // SSE Clients
  const sseClients = new Set<Response>();

  function broadcastSSE(type: string, data: unknown) {
    const message = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const client of sseClients) {
      try {
        client.write(message);
      } catch {
        sseClients.delete(client);
      }
    }
  }

  // Health
  app.get('/health', (req, res) => {
    const { hash } = getContractsHash();
    res.json({
      status: 'ok',
      service: 'blue-collector',
      contracts_hash: hash,
      uptime_seconds: Math.floor((Date.now() - startTime) / 1000),
    });
  });

  // SSE Stream
  app.get('/events/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    sseClients.add(res);
    res.write(`event: connected\ndata: ${JSON.stringify({ status: 'connected', ts: new Date().toISOString() })}\n\n`);

    req.on('close', () => {
      sseClients.delete(res);
    });
  });

  // POST /events
  app.post('/events', (req, res) => {
    try {
      const parsed: SecurityEvent = SecurityEventSchema.parse(req.body);

      // Insert event into SQLite
      db.prepare(`
        INSERT INTO events (
          event_id, run_id, trace_id, worker, attack, seed, target,
          decision, reason, layer, pin_hash, amount_atomic,
          chain_delta_atomic, funds_lost_atomic, latency_ms,
          policy_digest, ts, details
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        parsed.event_id,
        parsed.run_id,
        parsed.trace_id,
        parsed.worker,
        parsed.attack,
        parsed.seed,
        parsed.target,
        parsed.decision,
        parsed.reason,
        parsed.layer,
        parsed.pin_hash,
        parsed.amount_atomic,
        parsed.chain_delta_atomic,
        parsed.funds_lost_atomic,
        parsed.latency_ms,
        parsed.policy_digest,
        parsed.ts,
        parsed.details ? JSON.stringify(parsed.details) : null
      );

      // Check for Discrepancy & Security Alarms
      const fundsLostBigInt = BigInt(parsed.funds_lost_atomic || '0');
      const chainDeltaBigInt = BigInt(parsed.chain_delta_atomic || '0');

      // 1. Guard blocked but chain moved funds
      if (parsed.decision === 'BLOCK' && chainDeltaBigInt > 0n) {
        createAlarm('CRITICAL', 'GUARD_CHAIN_DISAGREEMENT', `Guard rendered BLOCK but chain moved ${parsed.chain_delta_atomic} atomic units!`, parsed.event_id);
      }

      // 2. Unauthorized funds lost
      if (fundsLostBigInt > 0n) {
        createAlarm('CRITICAL', 'UNAUTHORIZED_RECEIVER', `Unauthorized funds reached attacker wallet: ${parsed.funds_lost_atomic} atomic units!`, parsed.event_id);
      }

      // 3. Prompt injection detection
      if (parsed.details && JSON.stringify(parsed.details).includes('SYSTEM OVERRIDE')) {
        createAlarm('HIGH', 'PROMPT_INJECTION', 'Adversarial system prompt injection attempt detected in merchant response', parsed.event_id);
      }

      // Broadcast to live dashboard via SSE
      broadcastSSE('security_event', parsed);

      res.status(201).json({ success: true, event_id: parsed.event_id });
    } catch (err: any) {
      res.status(400).json({ error: 'Invalid event schema', details: err.errors || err.message });
    }
  });

  function createAlarm(severity: string, alarmType: string, message: string, eventId: string) {
    const alarmId = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    db.prepare(`
      INSERT INTO alarms (alarm_id, severity, alarm_type, message, event_id, acknowledged, created_at)
      VALUES (?, ?, ?, ?, ?, 0, ?)
    `).run(alarmId, severity, alarmType, message, eventId, createdAt);

    broadcastSSE('security_alarm', {
      alarm_id: alarmId,
      severity,
      alarm_type: alarmType,
      message,
      event_id: eventId,
      created_at: createdAt,
    });
  }

  // GET /events
  app.get('/events', (req, res) => {
    const limit = Math.min(Number(req.query.limit || 100), 1000);
    const runId = req.query.run_id as string | undefined;
    const target = req.query.target as string | undefined;

    let query = 'SELECT * FROM events';
    const params: any[] = [];
    const conditions: string[] = [];

    if (runId) {
      conditions.push('run_id = ?');
      params.push(runId);
    }
    if (target) {
      conditions.push('target = ?');
      params.push(target);
    }
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    query += ' ORDER BY rowid DESC LIMIT ?';
    params.push(limit);

    const rows = db.prepare(query).all(...params);
    res.json({ events: rows });
  });

  // GET /alarms
  app.get('/alarms', (req, res) => {
    const rows = db.prepare('SELECT * FROM alarms ORDER BY rowid DESC LIMIT 100').all();
    res.json({ alarms: rows });
  });

  // POST /alarms/:id/ack
  app.post('/alarms/:id/ack', (req, res) => {
    db.prepare('UPDATE alarms SET acknowledged = 1 WHERE alarm_id = ?').run(req.params.id);
    res.json({ success: true });
  });

  // GET /metrics
  app.get('/metrics', (req, res) => {
    const events = db.prepare('SELECT * FROM events').all();
    let totalRequests = 0;
    let totalAllowed = 0;
    let totalBlocked = 0;
    let fundsProtectedBigInt = 0n;
    let fundsLostBigInt = 0n;
    let honestAttempts = 0;
    let honestSuccess = 0;
    const latencies: number[] = [];

    const byTarget: Record<string, { requests: number; allowed: number; blocked: number; fundsLost: string }> = {
      NAIVE: { requests: 0, allowed: 0, blocked: 0, fundsLost: '0' },
      BLUE_V0: { requests: 0, allowed: 0, blocked: 0, fundsLost: '0' },
      BLUE_V1: { requests: 0, allowed: 0, blocked: 0, fundsLost: '0' },
    };

    for (const ev of events) {
      totalRequests++;
      if (ev.decision === 'ALLOW' || ev.decision === 'SIGN') totalAllowed++;
      if (ev.decision === 'BLOCK') {
        totalBlocked++;
        if (ev.amount_atomic) {
          fundsProtectedBigInt += BigInt(ev.amount_atomic);
        }
      }

      if (ev.funds_lost_atomic) {
        fundsLostBigInt += BigInt(ev.funds_lost_atomic);
      }

      if (ev.latency_ms) {
        latencies.push(ev.latency_ms);
      }

      if (ev.attack === 'HONEST') {
        honestAttempts++;
        if (ev.decision === 'ALLOW' || ev.decision === 'SIGN') honestSuccess++;
      }

      const tgt = ev.target;
      if (tgt && byTarget[tgt]) {
        byTarget[tgt].requests++;
        if (ev.decision === 'ALLOW') byTarget[tgt].allowed++;
        if (ev.decision === 'BLOCK') byTarget[tgt].blocked++;
        if (ev.funds_lost_atomic) {
          byTarget[tgt].fundsLost = (BigInt(byTarget[tgt].fundsLost) + BigInt(ev.funds_lost_atomic)).toString();
        }
      }
    }

    latencies.sort((a, b) => a - b);
    const avgLatency = latencies.length ? latencies.reduce((a, b) => a + b, 0) / latencies.length : 0;
    const p95Latency = latencies.length ? latencies[Math.floor(latencies.length * 0.95)] : 0;
    const honestRate = honestAttempts > 0 ? (honestSuccess / honestAttempts) * 100 : 100;

    res.json({
      totalRequests,
      totalAllowed,
      totalBlocked,
      fundsProtectedAtomic: fundsProtectedBigInt.toString(),
      fundsLostAtomic: fundsLostBigInt.toString(),
      honestSuccessRatePercent: honestRate,
      latency: {
        avg_ms: Number(avgLatency.toFixed(2)),
        p95_ms: Number(p95Latency.toFixed(2)),
      },
      byTarget,
    });
  });

  // POST /runs/reset
  app.post('/runs/reset', (req, res) => {
    db.exec('DELETE FROM events; DELETE FROM alarms;');
    res.json({ success: true, message: 'Collector event and alarm store cleared' });
  });

  // Serve Blue Dashboard UI
  app.get('/', (req, res) => {
    res.send(renderDashboardHtml());
  });
  app.get('/dashboard', (req, res) => {
    res.send(renderDashboardHtml());
  });

  return { app, port, db };
}

function renderDashboardHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Blue Defender Console — x402 Security System</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background-color: #0B0F19; color: #E2E8F0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
  </style>
</head>
<body class="p-6">
  <div class="max-w-7xl mx-auto space-y-6">
    <!-- Header -->
    <header class="flex justify-between items-center border-b border-slate-800 pb-4">
      <div>
        <h1 class="text-2xl font-bold text-sky-400 tracking-wider">DEFENDER CONSOLE // BLUE NODE</h1>
        <p class="text-xs text-slate-400">Autonomous AI Shopping Guard & Multi-Layer Payment Firewall</p>
      </div>
      <div class="flex items-center space-x-4">
        <span id="contracts-hash" class="text-xs px-2 py-1 bg-slate-800 rounded border border-slate-700 text-slate-300">Hash: Loading...</span>
        <span id="active-mode" class="text-xs px-3 py-1 bg-sky-950 border border-sky-500 text-sky-300 font-bold rounded">MODE: BLUE_V1</span>
      </div>
    </header>

    <!-- Key Metrics Ribbon -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-lg">
        <div class="text-xs text-slate-400">FUNDS PROTECTED (ATOMIC)</div>
        <div id="metric-protected" class="text-2xl font-bold text-emerald-400 mt-1">0 TUSD</div>
      </div>
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-lg">
        <div class="text-xs text-slate-400">FUNDS LOST (CHAIN PROVEN)</div>
        <div id="metric-lost" class="text-2xl font-bold text-rose-500 mt-1">0 TUSD</div>
      </div>
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-lg">
        <div class="text-xs text-slate-400">TOTAL REQUESTS / BLOCKS</div>
        <div id="metric-reqs" class="text-2xl font-bold text-sky-400 mt-1">0 / 0</div>
      </div>
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-lg">
        <div class="text-xs text-slate-400">GUARD LATENCY (P95)</div>
        <div id="metric-latency" class="text-2xl font-bold text-indigo-400 mt-1">0.0 ms</div>
      </div>
    </div>

    <!-- Live Alarms Banner -->
    <div id="alarms-container" class="space-y-2"></div>

    <!-- Main Content Grid -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- 9 Layer Defense Overview & AI Assistant -->
      <div class="lg:col-span-1 space-y-4">
        <div class="bg-slate-900 border border-slate-800 p-5 rounded-lg space-y-3">
          <h2 class="text-sm font-bold text-slate-300 border-b border-slate-800 pb-2">9-LAYER DEFENSE ARCHITECTURE</h2>
          <div id="layers-list" class="space-y-2 text-xs">
            <div class="p-2 rounded bg-slate-800/60 flex justify-between items-center"><span class="font-bold text-sky-400">L0 Transport</span><span class="text-emerald-400">ACTIVE</span></div>
            <div class="p-2 rounded bg-slate-800/60 flex justify-between items-center"><span class="font-bold text-sky-400">L1 Input Validation</span><span class="text-emerald-400">ACTIVE</span></div>
            <div class="p-2 rounded bg-slate-800/60 flex justify-between items-center"><span class="font-bold text-sky-400">L2 Identity Verification</span><span class="text-emerald-400">ACTIVE</span></div>
            <div class="p-2 rounded bg-slate-800/60 flex justify-between items-center"><span class="font-bold text-sky-400">L3 Price & Approval</span><span class="text-emerald-400">ACTIVE</span></div>
            <div class="p-2 rounded bg-slate-800/60 flex justify-between items-center"><span class="font-bold text-sky-400">L4 Wallet Signing Firewall</span><span class="text-emerald-400">ACTIVE</span></div>
            <div class="p-2 rounded bg-slate-800/60 flex justify-between items-center"><span class="font-bold text-sky-400">L5 Atomic WAL Budget</span><span class="text-emerald-400">ACTIVE</span></div>
            <div class="p-2 rounded bg-slate-800/60 flex justify-between items-center"><span class="font-bold text-sky-400">L6 Behavioral Guard</span><span class="text-emerald-400">ACTIVE</span></div>
            <div class="p-2 rounded bg-slate-800/60 flex justify-between items-center"><span class="font-bold text-sky-400">L7 On-Chain Reconciliation</span><span class="text-emerald-400">ACTIVE</span></div>
            <div class="p-2 rounded bg-slate-800/60 flex justify-between items-center"><span class="font-bold text-sky-400">L8 Audit Log & Fail Closed</span><span class="text-emerald-400">ACTIVE</span></div>
          </div>
        </div>

        <!-- Interactive AI Shopping Assistant -->
        <div class="bg-slate-900 border border-slate-800 p-5 rounded-lg space-y-3">
          <div class="flex justify-between items-center border-b border-slate-800 pb-2">
            <h2 class="text-sm font-bold text-sky-400">🤖 AI SHOPPING ASSISTANT</h2>
            <span class="text-[10px] text-emerald-400 font-bold bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800">AGENT :4010</span>
          </div>
          <p class="text-xs text-slate-400">Ask the autonomous AI shopping agent to order tech items using x402 EIP-3009 authorization.</p>
          <div class="space-y-2">
            <input id="chat-input" type="text" placeholder="e.g. Buy 1 USB-C cable for 10 TUSD" class="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500 font-mono" value="Buy 1 USB-C cable for 10 TUSD" />
            <div class="flex flex-wrap gap-2">
              <button onclick="sendChatMessage()" id="chat-btn" class="w-full py-2 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-bold transition shadow-lg shadow-sky-900/40">Ask Agent To Pay</button>
              <button onclick="fillPrompt('Buy 1 USB-C cable for 10 TUSD')" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px]">Cable ($5)</button>
              <button onclick="fillPrompt('Order 1 ergonomic mouse under 30 USD')" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px]">Mouse ($25)</button>
              <button onclick="fillPrompt('Buy 1 mechanical keyboard for 60 USD')" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px]">Keyboard ($50)</button>
            </div>
          </div>
          <div id="chat-result" class="hidden p-3 rounded text-xs space-y-1 font-mono"></div>
        </div>
      </div>

      <!-- Live Event Feed -->
      <div class="lg:col-span-2 bg-slate-900 border border-slate-800 p-5 rounded-lg flex flex-col h-[640px]">
        <div class="flex justify-between items-center border-b border-slate-800 pb-2 mb-3">
          <h2 class="text-sm font-bold text-slate-300">LIVE SECURITY EVENT STREAM (SSE)</h2>
          <span class="text-xs text-emerald-400 animate-pulse">● CONNECTED</span>
        </div>
        <div id="events-log" class="flex-1 overflow-y-auto space-y-2 text-xs font-mono pr-2">
          <div class="text-slate-500 italic">Awaiting security events...</div>
        </div>
      </div>
    </div>
  </div>

  <script>
    function fillPrompt(text) {
      document.getElementById('chat-input').value = text;
    }

    async function sendChatMessage() {
      const input = document.getElementById('chat-input');
      const btn = document.getElementById('chat-btn');
      const resultBox = document.getElementById('chat-result');
      const msg = input.value.trim();
      if (!msg) return;

      btn.disabled = true;
      btn.innerText = 'Agent Negotiating Payment...';
      resultBox.className = 'p-3 rounded text-xs space-y-1 font-mono bg-slate-800 border border-slate-700 text-slate-300';
      resultBox.classList.remove('hidden');
      resultBox.innerHTML = '<span class="text-sky-400 animate-pulse">Consulting 9-layer firewall and negotiating with merchant...</span>';

      try {
        const res = await fetch('http://localhost:4010/assistant/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: msg })
        });
        const data = await res.json();
        btn.disabled = false;
        btn.innerText = 'Ask Agent To Pay';

        if (data.result && data.result.decision === 'ALLOW') {
          resultBox.className = 'p-3 rounded text-xs space-y-1 font-mono bg-emerald-950/40 border border-emerald-600 text-emerald-300';
          resultBox.innerHTML = '<div class="font-bold text-emerald-400">✅ PAYMENT AUTHORIZED & SETTLED</div>' +
            '<div>' + data.reply + '</div>' +
            '<div class="text-[10px] text-slate-400 mt-1">Tx: ' + (data.result.tx_hash || 'N/A') + ' | Delta: ' + data.result.chain_delta_atomic + ' | Latency: ' + data.result.latency_ms + 'ms</div>';
        } else if (data.result) {
          resultBox.className = 'p-3 rounded text-xs space-y-1 font-mono bg-rose-950/40 border border-rose-600 text-rose-300';
          resultBox.innerHTML = '<div class="font-bold text-rose-400">🛡️ PAYMENT BLOCKED BY GUARD</div>' +
            '<div>' + data.reply + '</div>' +
            '<div class="text-[10px] text-slate-400 mt-1">Layer: ' + data.result.layer + ' | Reason: ' + data.result.reason + ' | Funds Lost: 0</div>';
        } else {
          resultBox.className = 'p-3 rounded text-xs space-y-1 font-mono bg-rose-950/40 border border-rose-600 text-rose-300';
          resultBox.innerHTML = '<div>' + (data.error || 'Unknown error') + '</div>';
        }
      } catch (err) {
        btn.disabled = false;
        btn.innerText = 'Ask Agent To Pay';
        resultBox.className = 'p-3 rounded text-xs space-y-1 font-mono bg-rose-950/40 border border-rose-600 text-rose-300';
        resultBox.innerHTML = '<div>Network error contacting agent: ' + err.message + '</div>';
      }
    }

    async function updateMetrics() {
      try {
        const res = await fetch('/metrics');
        const data = await res.json();
        document.getElementById('metric-protected').innerText = (Number(data.fundsProtectedAtomic) / 1e6).toFixed(2) + ' TUSD';
        document.getElementById('metric-lost').innerText = (Number(data.fundsLostAtomic) / 1e6).toFixed(2) + ' TUSD';
        document.getElementById('metric-reqs').innerText = data.totalRequests + ' / ' + data.totalBlocked;
        document.getElementById('metric-latency').innerText = data.latency.p95_ms + ' ms';
      } catch (e) {}
    }

    async function loadHealth() {
      try {
        const res = await fetch('/health');
        const data = await res.json();
        document.getElementById('contracts-hash').innerText = 'Hash: ' + data.contracts_hash.slice(0, 16) + '...';
      } catch (e) {}
    }

    const evtSource = new EventSource('/events/stream');
    evtSource.addEventListener('security_event', (e) => {
      const ev = JSON.parse(e.data);
      const container = document.getElementById('events-log');
      const item = document.createElement('div');
      item.className = 'p-2 rounded border ' + (ev.decision === 'BLOCK' ? 'bg-rose-950/30 border-rose-800 text-rose-300' : 'bg-slate-800 border-slate-700 text-slate-200');
      item.innerHTML = '<div class="flex justify-between"><span class="font-bold">[' + ev.decision + '] ' + ev.worker + (ev.attack ? ' (' + ev.attack + ')' : '') + '</span><span class="text-slate-400">' + new Date(ev.ts).toLocaleTimeString() + '</span></div>' +
        '<div class="text-[11px] text-slate-400 mt-1">Reason: ' + (ev.reason || 'None') + ' | Layer: ' + (ev.layer || 'None') + ' | Amount: ' + (ev.amount_atomic || '0') + '</div>';
      container.prepend(item);
      updateMetrics();
    });

    evtSource.addEventListener('security_alarm', (e) => {
      const alarm = JSON.parse(e.data);
      const container = document.getElementById('alarms-container');
      const banner = document.createElement('div');
      banner.className = 'p-3 rounded bg-rose-900 border border-rose-600 text-white text-xs flex justify-between items-center';
      banner.innerHTML = '<div><span class="font-bold underline">CRITICAL ALARM [' + alarm.alarm_type + ']:</span> ' + alarm.message + '</div>' +
        '<button onclick="this.parentElement.remove()" class="px-2 py-0.5 bg-rose-950 rounded text-xs border border-rose-700 hover:bg-rose-800">Acknowledge</button>';
      container.prepend(banner);
    });

    loadHealth();
    updateMetrics();
    setInterval(updateMetrics, 5000);
  </script>
</body>
</html>`;
}

if (require.main === module || (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename))) {
  const { app, port } = createCollectorServer();
  app.listen(port, '0.0.0.0', () => {
    console.log(`[blue-collector] Event collector & dashboard listening on http://0.0.0.0:${port}`);
  });
}
