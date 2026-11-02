import { DatabaseAdapter, openSqliteDatabase } from '../storage/db';
import { GuardBlockError } from '../contracts/x402-types';

export interface BudgetConfig {
  dailyAtomic: string;
  perCallAtomic: string;
}

export interface BudgetReservationParams {
  intentId: string;
  resource: string;
  amountAtomic: string;
}

export interface BudgetManager {
  reserve(params: BudgetReservationParams): void;
  commit(intentId: string, actualAmountAtomic?: string): void;
  release(intentId: string): void;
  getSpentToday(): bigint;
  getReservedToday(): bigint;
  close(): void;
}

export function createBudgetManager(dbPath: string, config: BudgetConfig): BudgetManager {
  const db: DatabaseAdapter = openSqliteDatabase(dbPath);

  // Initialize schema
  db.exec(`
    CREATE TABLE IF NOT EXISTS budget_reservations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      intent_id TEXT NOT NULL UNIQUE,
      resource TEXT NOT NULL,
      amount_atomic TEXT NOT NULL,
      status TEXT NOT NULL, -- 'RESERVED' | 'COMMITTED' | 'RELEASED'
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_budget_intent ON budget_reservations (intent_id);
    CREATE INDEX IF NOT EXISTS idx_budget_status_created ON budget_reservations (status, created_at);
  `);

  const dailyCap = BigInt(config.dailyAtomic);
  const perCallCap = BigInt(config.perCallAtomic);

  return {
    reserve(params: BudgetReservationParams) {
      const { intentId, resource, amountAtomic } = params;
      const amount = BigInt(amountAtomic);

      // 1. Per-call cap check
      if (amount > perCallCap) {
        throw new GuardBlockError(
          'BUDGET_EXHAUSTED',
          'L5',
          `Amount ${amountAtomic} exceeds per-call cap of ${config.perCallAtomic}`
        );
      }

      // Execute within an atomic immediate transaction
      db.transaction(() => {
        // 2. Duplicate Intent check (anti-replay)
        const existing = db
          .prepare('SELECT id, status FROM budget_reservations WHERE intent_id = ?')
          .get(intentId);

        if (existing) {
          throw new GuardBlockError(
            'DUPLICATE_INTENT',
            'L5',
            `Intent ${intentId} has already been processed or reserved (status: ${existing.status})`
          );
        }

        // 3. Compute active reservations + committed spends in the last 24h
        const windowStart = Date.now() - 24 * 60 * 60 * 1000;
        const activeRows = db
          .prepare(
            `SELECT amount_atomic FROM budget_reservations 
             WHERE status IN ('RESERVED', 'COMMITTED') AND created_at >= ?`
          )
          .all(windowStart);

        let currentActiveTotal = 0n;
        for (const row of activeRows) {
          currentActiveTotal += BigInt(row.amount_atomic);
        }

        // 4. Daily cap check
        if (currentActiveTotal + amount > dailyCap) {
          throw new GuardBlockError(
            'BUDGET_EXHAUSTED',
            'L5',
            `Transaction of ${amountAtomic} would exceed 24h budget cap (current: ${currentActiveTotal.toString()}, max: ${dailyCap.toString()})`
          );
        }

        // 5. Insert reservation
        const now = Date.now();
        db.prepare(
          `INSERT INTO budget_reservations (intent_id, resource, amount_atomic, status, created_at, updated_at)
           VALUES (?, ?, ?, 'RESERVED', ?, ?)`
        ).run(intentId, resource, amountAtomic, now, now);
      });
    },

    commit(intentId: string, actualAmountAtomic?: string) {
      db.transaction(() => {
        const row = db
          .prepare('SELECT id, status, amount_atomic FROM budget_reservations WHERE intent_id = ?')
          .get(intentId);

        if (!row) {
          return;
        }

        const now = Date.now();
        const finalAmount = actualAmountAtomic || row.amount_atomic;

        db.prepare(
          `UPDATE budget_reservations 
           SET status = 'COMMITTED', amount_atomic = ?, updated_at = ? 
           WHERE intent_id = ?`
        ).run(finalAmount, now, intentId);
      });
    },

    release(intentId: string) {
      db.transaction(() => {
        const now = Date.now();
        db.prepare(
          `UPDATE budget_reservations 
           SET status = 'RELEASED', updated_at = ? 
           WHERE intent_id = ? AND status = 'RESERVED'`
        ).run(now, intentId);
      });
    },

    getSpentToday(): bigint {
      const windowStart = Date.now() - 24 * 60 * 60 * 1000;
      const rows = db
        .prepare(
          `SELECT amount_atomic FROM budget_reservations 
           WHERE status = 'COMMITTED' AND created_at >= ?`
        )
        .all(windowStart);

      return rows.reduce((acc, row) => acc + BigInt(row.amount_atomic), 0n);
    },

    getReservedToday(): bigint {
      const windowStart = Date.now() - 24 * 60 * 60 * 1000;
      const rows = db
        .prepare(
          `SELECT amount_atomic FROM budget_reservations 
           WHERE status = 'RESERVED' AND created_at >= ?`
        )
        .all(windowStart);

      return rows.reduce((acc, row) => acc + BigInt(row.amount_atomic), 0n);
    },

    close() {
      db.close();
    },
  };
}
