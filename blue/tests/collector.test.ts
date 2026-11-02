import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as http from 'node:http';
import { createCollectorServer } from '../src/collector/server';
import { SecurityEvent } from '../src/contracts/events';
import { DatabaseAdapter } from '../src/storage/db';

const COLLECTOR_TEST_DIR = path.resolve(__dirname, 'test-temp-collector');

describe('Phase 5 — Collector, Alarms & Metrics Engine', () => {
  let server: http.Server;
  let collectorDb: DatabaseAdapter;
  let baseUrl: string;

  beforeAll(async () => {
    if (fs.existsSync(COLLECTOR_TEST_DIR)) {
      fs.rmSync(COLLECTOR_TEST_DIR, { recursive: true, force: true });
    }
    fs.mkdirSync(COLLECTOR_TEST_DIR, { recursive: true });

    const collector = createCollectorServer({
      port: 0,
      dbPath: path.resolve(COLLECTOR_TEST_DIR, 'collector.db'),
    });

    collectorDb = collector.db;

    await new Promise<void>((resolve) => {
      server = collector.app.listen(0, () => {
        const addr: any = server.address();
        baseUrl = `http://localhost:${addr.port}`;
        resolve();
      });
    });
  });

  beforeEach(async () => {
    await fetch(`${baseUrl}/runs/reset`, { method: 'POST' });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    }
    if (collectorDb) {
      collectorDb.close();
    }
    if (fs.existsSync(COLLECTOR_TEST_DIR)) {
      fs.rmSync(COLLECTOR_TEST_DIR, { recursive: true, force: true });
    }
  });

  it('receives security event, stores it and exposes it via GET /events', async () => {
    const event: SecurityEvent = {
      event_id: 'a0000000-0000-0000-0000-000000000001',
      run_id: 'test-run-1',
      trace_id: 'trace-1',
      worker: 'blue-agent',
      attack: null,
      seed: null,
      target: 'BLUE_V1',
      decision: 'ALLOW',
      reason: 'OK',
      layer: 'L8',
      pin_hash: 'sha256:abc',
      amount_atomic: '1500000',
      chain_delta_atomic: '1500000',
      funds_lost_atomic: '0',
      latency_ms: 45,
      policy_digest: 'sha256:policy',
      ts: new Date().toISOString(),
    };

    const postRes = await fetch(`${baseUrl}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event),
    });
    expect(postRes.status).toBe(201);

    const getRes = await fetch(`${baseUrl}/events?run_id=test-run-1`);
    const data: any = await getRes.json();
    expect(data.events).toHaveLength(1);
    expect(data.events[0].decision).toBe('ALLOW');
  });

  it('generates UNAUTHORIZED_RECEIVER critical alarm when funds_lost_atomic > 0', async () => {
    const maliciousEvent: SecurityEvent = {
      event_id: 'a0000000-0000-0000-0000-000000000002',
      run_id: 'test-run-leak',
      trace_id: 'trace-leak',
      worker: 'blue-guard',
      attack: 'A01',
      seed: 42,
      target: 'NAIVE',
      decision: 'ALLOW',
      reason: 'OK',
      layer: null,
      pin_hash: null,
      amount_atomic: '1500000',
      chain_delta_atomic: '1500000',
      funds_lost_atomic: '1500000', // Stolen funds!
      latency_ms: 12,
      policy_digest: null,
      ts: new Date().toISOString(),
    };

    await fetch(`${baseUrl}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(maliciousEvent),
    });

    const alarmsRes = await fetch(`${baseUrl}/alarms`);
    const alarmsData: any = await alarmsRes.json();

    expect(alarmsData.alarms.length).toBeGreaterThan(0);
    const alarm = alarmsData.alarms[0];
    expect(alarm.alarm_type).toBe('UNAUTHORIZED_RECEIVER');
    expect(alarm.severity).toBe('CRITICAL');
  });

  it('computes correct metrics across targets', async () => {
    const eventV1: SecurityEvent = {
      event_id: 'a0000000-0000-0000-0000-000000000003',
      run_id: 'test-run-metrics',
      trace_id: 'trace-v1',
      worker: 'blue-guard',
      attack: 'A01',
      seed: 1,
      target: 'BLUE_V1',
      decision: 'BLOCK',
      reason: 'PAYTO_MISMATCH',
      layer: 'L2',
      pin_hash: null,
      amount_atomic: '1500000',
      chain_delta_atomic: '0',
      funds_lost_atomic: '0',
      latency_ms: 15,
      policy_digest: null,
      ts: new Date().toISOString(),
    };

    const eventNaive: SecurityEvent = {
      event_id: 'a0000000-0000-0000-0000-000000000004',
      run_id: 'test-run-metrics',
      trace_id: 'trace-naive',
      worker: 'blue-agent',
      attack: 'A01',
      seed: 1,
      target: 'NAIVE',
      decision: 'ALLOW',
      reason: 'OK',
      layer: null,
      pin_hash: null,
      amount_atomic: '1500000',
      chain_delta_atomic: '1500000',
      funds_lost_atomic: '1500000',
      latency_ms: 20,
      policy_digest: null,
      ts: new Date().toISOString(),
    };

    await fetch(`${baseUrl}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(eventV1),
    });
    await fetch(`${baseUrl}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(eventNaive),
    });

    const metricsRes = await fetch(`${baseUrl}/metrics?run_id=test-run-metrics`);
    const metrics: any = await metricsRes.json();

    expect(metrics.totalRequests).toBe(2);
    expect(metrics.byTarget['BLUE_V1'].fundsLost).toBe('0');
    expect(metrics.byTarget['BLUE_V1'].blocked).toBe(1);
    expect(metrics.byTarget['NAIVE'].fundsLost).toBe('1500000');
    expect(metrics.byTarget['NAIVE'].allowed).toBe(1);
  });
});
