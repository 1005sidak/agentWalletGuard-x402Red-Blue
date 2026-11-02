import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { GuardBlockError } from '../contracts/x402-types';
import { SecurityEvent, SecurityEventSchema } from '../contracts/events';
import { ReasonCode, SecurityLayer } from '../contracts/reason-codes';

export interface AuditConfig {
  logFilePath?: string;
  collectorUrl?: string;
  eventToken?: string;
  runId?: string;
  worker?: 'blue-guard' | 'blue-agent';
}

export interface AuditLogger {
  logEvent(event: Partial<SecurityEvent>): void;
  close(): void;
}

export function createAuditLogger(config: AuditConfig = {}): AuditLogger {
  const logPath = config.logFilePath || path.resolve(process.cwd(), 'data/audit.jsonl');
  const dir = path.dirname(logPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  return {
    logEvent(eventInput: Partial<SecurityEvent>) {
      const fullEvent: SecurityEvent = {
        event_id: eventInput.event_id || crypto.randomUUID(),
        run_id: eventInput.run_id || config.runId || 'blue-run-default',
        trace_id: eventInput.trace_id || crypto.randomUUID(),
        worker: eventInput.worker || config.worker || 'blue-guard',
        attack: eventInput.attack !== undefined ? eventInput.attack : null,
        seed: eventInput.seed !== undefined ? eventInput.seed : null,
        target: eventInput.target || 'BLUE_V1',
        decision: eventInput.decision || 'INFO',
        reason: (eventInput.reason as ReasonCode) || null,
        layer: (eventInput.layer as SecurityLayer) || null,
        pin_hash: eventInput.pin_hash !== undefined ? eventInput.pin_hash : null,
        amount_atomic: eventInput.amount_atomic !== undefined ? eventInput.amount_atomic : null,
        chain_delta_atomic: eventInput.chain_delta_atomic !== undefined ? eventInput.chain_delta_atomic : null,
        funds_lost_atomic: eventInput.funds_lost_atomic || '0',
        latency_ms: eventInput.latency_ms || 0,
        policy_digest: eventInput.policy_digest !== undefined ? eventInput.policy_digest : null,
        ts: eventInput.ts || new Date().toISOString(),
        details: eventInput.details,
      };

      // 1. Write to local append-only log synchronously
      try {
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        fs.appendFileSync(logPath, JSON.stringify(fullEvent) + '\n', 'utf8');
      } catch (err) {
        console.error('Failed writing to local audit log:', err);
      }

      // 2. Asynchronously forward to Collector if configured
      if (config.collectorUrl) {
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (config.eventToken) {
          headers['Authorization'] = `Bearer ${config.eventToken}`;
        }

        fetch(`${config.collectorUrl}/events`, {
          method: 'POST',
          headers,
          body: JSON.stringify(fullEvent),
        }).catch(() => {
          // Fire-and-forget; do not block guard pipeline on collector network errors
        });
      }
    },

    close() {
      // Synchronous file handles are auto-closed after each append
    },
  };
}

export interface FailClosedContext {
  logger?: AuditLogger;
  runId?: string;
  traceId?: string;
  attack?: string | null;
  seed?: number | null;
  amountAtomic?: string | null;
}

/**
 * Fail-Closed Handler:
 * Catches any unhandled error, logs GUARD_ERROR to audit log and collector,
 * and ensures the system aborts execution without spending or signing.
 */
export async function wrapFailClosed<T>(
  fn: () => Promise<T> | T,
  ctx: FailClosedContext = {}
): Promise<T> {
  const start = Date.now();
  try {
    return await fn();
  } catch (err: any) {
    const latency = Date.now() - start;

    if (err instanceof GuardBlockError) {
      if (ctx.logger) {
        ctx.logger.logEvent({
          run_id: ctx.runId,
          trace_id: ctx.traceId,
          attack: ctx.attack,
          seed: ctx.seed,
          target: 'BLUE_V1',
          decision: 'BLOCK',
          reason: err.code as ReasonCode,
          layer: err.layer as SecurityLayer,
          amount_atomic: ctx.amountAtomic,
          latency_ms: latency,
          details: { message: err.message, details: err.details },
        });
      }
      throw err;
    }

    // Unhandled / unexpected exception: FAIL CLOSED with GUARD_ERROR
    if (ctx.logger) {
      ctx.logger.logEvent({
        run_id: ctx.runId,
        trace_id: ctx.traceId,
        attack: ctx.attack,
        seed: ctx.seed,
        target: 'BLUE_V1',
        decision: 'BLOCK',
        reason: 'GUARD_ERROR',
        layer: 'L8',
        amount_atomic: ctx.amountAtomic,
        latency_ms: latency,
        details: {
          originalError: err.message || String(err),
          stack: err.stack,
        },
      });
    }

    throw new GuardBlockError('GUARD_ERROR', 'L8', `Unexpected guard failure: ${err.message}`, {
      originalError: err.message,
    });
  }
}
