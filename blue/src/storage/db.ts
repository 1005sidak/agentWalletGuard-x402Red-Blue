import { createRequire } from 'node:module';
import * as fs from 'node:fs';
import * as path from 'node:path';

const require = createRequire(import.meta.url);

function getDatabaseSyncClass(): any {
  try {
    const sqlite = require('node:sqlite');
    return sqlite.DatabaseSync;
  } catch (err: any) {
    throw new Error(`node:sqlite is not available in this Node runtime: ${err.message}`);
  }
}

export interface DatabaseAdapter {
  exec(sql: string): void;
  prepare(sql: string): {
    run(...params: any[]): { changes: number | bigint; lastInsertRowid: number | bigint };
    get(...params: any[]): any;
    all(...params: any[]): any[];
  };
  transaction<T>(fn: () => T): T;
  close(): void;
}

export function openSqliteDatabase(dbPath: string): DatabaseAdapter {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const DatabaseSync = getDatabaseSyncClass();
  const db = new DatabaseSync(dbPath);

  // Enable WAL mode and synchronous normal
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA synchronous = NORMAL;');
  db.exec('PRAGMA busy_timeout = 5000;');

  return {
    exec(sql: string) {
      db.exec(sql);
    },
    prepare(sql: string) {
      const stmt = db.prepare(sql);
      return {
        run(...params: any[]) {
          return stmt.run(...params);
        },
        get(...params: any[]) {
          return stmt.get(...params);
        },
        all(...params: any[]) {
          return stmt.all(...params);
        },
      };
    },
    transaction<T>(fn: () => T): T {
      db.exec('BEGIN IMMEDIATE;');
      try {
        const result = fn();
        db.exec('COMMIT;');
        return result;
      } catch (err) {
        db.exec('ROLLBACK;');
        throw err;
      }
    },
    close() {
      db.close();
    },
  };
}
