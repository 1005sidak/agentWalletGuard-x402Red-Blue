import express from 'express';
import cors from 'cors';
import { verifyTypedData, getAddress } from 'viem';
import * as crypto from 'node:crypto';
import * as path from 'node:path';
import { openSqliteDatabase, DatabaseAdapter } from '../storage/db';
import { getContractsHash } from '../contracts/hash';
import { TOKEN_NAME, TOKEN_VERSION, CHAIN_ID, DEFAULT_PORTS } from '../contracts/constants';

export interface ChainConfig {
  port?: number;
  dbPath?: string;
  collectorUrl?: string;
  eventToken?: string;
  initialAgentBalanceAtomic?: string;
  honestPayTo?: string;
  attackerPayTo?: string;
}

export function createChainServer(config: ChainConfig = {}) {
  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '1mb' }));

  const port = config.port || Number(process.env.CHAIN_PORT) || DEFAULT_PORTS.BLUE_CHAIN;
  const dbPath = config.dbPath || path.resolve(__dirname, '../../data/chain.db');
  const db: DatabaseAdapter = openSqliteDatabase(dbPath);
  const startTime = Date.now();

  // Initialize blockchain tables
  db.exec(`
    CREATE TABLE IF NOT EXISTS accounts (
      address TEXT PRIMARY KEY,
      balance_atomic TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS nonces (
      nonce TEXT PRIMARY KEY,
      used_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS transactions (
      tx_hash TEXT PRIMARY KEY,
      from_addr TEXT NOT NULL,
      to_addr TEXT NOT NULL,
      amount_atomic TEXT NOT NULL,
      nonce TEXT NOT NULL,
      block_number INTEGER NOT NULL,
      ts TEXT NOT NULL,
      raw_payload TEXT NOT NULL
    );
  `);

  // Seed genesis balances if empty
  const rowCount = db.prepare('SELECT count(*) as count FROM accounts').get();
  if (!rowCount || Number(rowCount.count) === 0) {
    const initBalance = config.initialAgentBalanceAtomic || '10000000000'; // 10,000 TUSD
    const honestMerchant = config.honestPayTo || process.env.HONEST_PAYTO || '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
    const attacker = config.attackerPayTo || process.env.ATTACKER_PAYTO || '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC';

    const insertAcc = db.prepare('INSERT OR REPLACE INTO accounts (address, balance_atomic) VALUES (?, ?)');
    insertAcc.run(honestMerchant.toLowerCase(), '0');
    insertAcc.run(attacker.toLowerCase(), '0');
  }

  // Health endpoint
  app.get('/health', (req, res) => {
    const { hash } = getContractsHash();
    res.json({
      status: 'ok',
      service: 'blue-chain',
      contracts_hash: hash,
      uptime_seconds: Math.floor((Date.now() - startTime) / 1000),
    });
  });

  // Get balance of specific or all accounts
  app.get('/balances', (req, res) => {
    const address = req.query.address as string | undefined;
    if (address) {
      const acc = db.prepare('SELECT address, balance_atomic FROM accounts WHERE address = ?').get(address.toLowerCase());
      return res.json({ address: address.toLowerCase(), balance_atomic: acc ? acc.balance_atomic : '0' });
    }
    const accounts = db.prepare('SELECT address, balance_atomic FROM accounts').all();
    res.json({ accounts });
  });

  // Fund an account (for testing/setup)
  app.post('/fund', (req, res) => {
    const { address, amount_atomic } = req.body;
    if (!address || !amount_atomic) {
      return res.status(400).json({ error: 'address and amount_atomic required' });
    }
    db.prepare('INSERT INTO accounts (address, balance_atomic) VALUES (?, ?) ON CONFLICT(address) DO UPDATE SET balance_atomic = ?').run(
      address.toLowerCase(),
      amount_atomic,
      amount_atomic
    );
    res.json({ success: true, address: address.toLowerCase(), balance_atomic: amount_atomic });
  });

  // Get transactions
  app.get('/transactions', (req, res) => {
    const limit = Math.min(Number(req.query.limit || 50), 200);
    const txs = db.prepare('SELECT * FROM transactions ORDER BY rowid DESC LIMIT ?').all(limit);
    res.json({ transactions: txs });
  });

  app.get('/transactions/:id', (req, res) => {
    const tx = db.prepare('SELECT * FROM transactions WHERE tx_hash = ?').get(req.params.id);
    if (!tx) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    res.json(tx);
  });

  // Settlement endpoint called by Facilitator
  app.post('/settle', async (req, res) => {
    try {
      const { paymentPayload, paymentRequirements } = req.body;
      if (!paymentPayload || !paymentRequirements) {
        return res.status(400).json({ success: false, error: 'Missing paymentPayload or paymentRequirements' });
      }

      const payloadObj = paymentPayload.payload || paymentPayload;
      const auth = payloadObj.authorization || payloadObj;
      const signature = payloadObj.signature || paymentPayload.signature;

      if (!auth || !auth.from || !auth.to) {
        return res.status(400).json({ success: false, error: 'Missing authorization fields in paymentPayload' });
      }

      const from = auth.from.toLowerCase();
      const to = auth.to.toLowerCase();
      const amountAtomic = auth.value;
      const nonce = auth.nonce;
      const validAfter = Number(auth.validAfter);
      const validBefore = Number(auth.validBefore);
      const nowSeconds = Math.floor(Date.now() / 1000);

      // 1. Check time window
      if (nowSeconds < validAfter || nowSeconds > validBefore) {
        return res.status(400).json({
          success: false,
          error: `Authorization expired or not yet valid (now: ${nowSeconds}, validAfter: ${validAfter}, validBefore: ${validBefore})`,
        });
      }

      // 2. Check nonce reuse
      const existingNonce = db.prepare('SELECT nonce FROM nonces WHERE nonce = ?').get(nonce);
      if (existingNonce) {
        return res.status(400).json({ success: false, error: 'Nonce already used (replay rejected)' });
      }

      // 3. Verify EIP-712 signature
      // Resolve chainId from paymentRequirements.chainId or network
      let targetChainId = Number(paymentRequirements.chainId || 0);
      if (!targetChainId) {
        if (paymentRequirements.network === 'base-sepolia') {
          targetChainId = 84532;
        } else {
          targetChainId = CHAIN_ID;
        }
      }

      const domain = {
        name: paymentRequirements.extra?.name || TOKEN_NAME,
        version: paymentRequirements.extra?.version || TOKEN_VERSION,
        chainId: targetChainId,
        verifyingContract: getAddress(paymentRequirements.asset),
      };

      const types = {
        TransferWithAuthorization: [
          { name: 'from', type: 'address' },
          { name: 'to', type: 'address' },
          { name: 'value', type: 'uint256' },
          { name: 'validAfter', type: 'uint256' },
          { name: 'validBefore', type: 'uint256' },
          { name: 'nonce', type: 'bytes32' },
        ],
      };

      const sigToVerify = signature || paymentPayload.signature || auth.signature || payloadObj.signature;
      if (!sigToVerify) {
        return res.status(400).json({ success: false, error: 'Signature required' });
      }

      let isValidSig = false;
      try {
        isValidSig = await verifyTypedData({
          address: getAddress(from),
          domain: domain as any,
          types,
          primaryType: 'TransferWithAuthorization',
          message: {
            from: getAddress(from),
            to: getAddress(to),
            value: BigInt(amountAtomic),
            validAfter: BigInt(validAfter),
            validBefore: BigInt(validBefore),
            nonce: nonce,
          },
          signature: sigToVerify,
        });
      } catch (err: any) {}

      // Fallback: If verification failed and targetChainId was not 84532, retry with 84532
      if (!isValidSig && targetChainId !== 84532) {
        try {
          isValidSig = await verifyTypedData({
            address: getAddress(from),
            domain: { ...domain, chainId: 84532 } as any,
            types,
            primaryType: 'TransferWithAuthorization',
            message: {
              from: getAddress(from),
              to: getAddress(to),
              value: BigInt(amountAtomic),
              validAfter: BigInt(validAfter),
              validBefore: BigInt(validBefore),
              nonce: nonce,
            },
            signature: sigToVerify,
          });
        } catch {}
      }

      // Fallback: If verification failed and targetChainId was not 31337, retry with 31337
      if (!isValidSig && targetChainId !== CHAIN_ID) {
        try {
          isValidSig = await verifyTypedData({
            address: getAddress(from),
            domain: { ...domain, chainId: CHAIN_ID } as any,
            types,
            primaryType: 'TransferWithAuthorization',
            message: {
              from: getAddress(from),
              to: getAddress(to),
              value: BigInt(amountAtomic),
              validAfter: BigInt(validAfter),
              validBefore: BigInt(validBefore),
              nonce: nonce,
            },
            signature: sigToVerify,
          });
        } catch {}
      }

      if (!isValidSig) {
        return res.status(400).json({ success: false, error: 'Cryptographic signature verification failed' });
      }

      // 4. Atomic balance transfer in SQLite WAL transaction
      const txHash = '0x' + crypto.randomBytes(32).toString('hex');
      const ts = new Date().toISOString();

      const receipt = db.transaction(() => {
        const sender = db.prepare('SELECT balance_atomic FROM accounts WHERE address = ?').get(from);
        const senderBalance = BigInt(sender ? sender.balance_atomic : '0');
        const transferAmount = BigInt(amountAtomic);

        if (senderBalance < transferAmount) {
          throw new Error(`Insufficient funds: balance ${senderBalance} < ${transferAmount}`);
        }

        const receiver = db.prepare('SELECT balance_atomic FROM accounts WHERE address = ?').get(to);
        const receiverBalance = BigInt(receiver ? receiver.balance_atomic : '0');

        const newSenderBalance = (senderBalance - transferAmount).toString();
        const newReceiverBalance = (receiverBalance + transferAmount).toString();

        db.prepare('INSERT INTO accounts (address, balance_atomic) VALUES (?, ?) ON CONFLICT(address) DO UPDATE SET balance_atomic = ?').run(
          from,
          newSenderBalance,
          newSenderBalance
        );

        db.prepare('INSERT INTO accounts (address, balance_atomic) VALUES (?, ?) ON CONFLICT(address) DO UPDATE SET balance_atomic = ?').run(
          to,
          newReceiverBalance,
          newReceiverBalance
        );

        db.prepare('INSERT INTO nonces (nonce, used_at) VALUES (?, ?)').run(nonce, ts);

        const currentBlock = Number(db.prepare('SELECT count(*) as count FROM transactions').get().count) + 1;
        db.prepare(`
          INSERT INTO transactions (tx_hash, from_addr, to_addr, amount_atomic, nonce, block_number, ts, raw_payload)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(txHash, from, to, amountAtomic, nonce, currentBlock, ts, JSON.stringify(paymentPayload));

        return {
          from,
          to,
          amountAtomic,
          timestamp: Math.floor(Date.now() / 1000),
          blockNumber: currentBlock,
          txHash,
        };
      });

      // 5. Emit event to Blue collector if configured
      const collectorUrl = config.collectorUrl || process.env.COLLECTOR_URL || `http://localhost:${DEFAULT_PORTS.BLUE_COLLECTOR}`;
      const attackerPayTo = (config.attackerPayTo || process.env.ATTACKER_PAYTO || '').toLowerCase();
      const fundsLost = to === attackerPayTo ? amountAtomic : '0';

      try {
        fetch(`${collectorUrl}/events`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${config.eventToken || process.env.EVENT_TOKEN || 'dev-event-secret-token'}`,
          },
          body: JSON.stringify({
            event_id: crypto.randomUUID(),
            run_id: req.body.run_id || 'run-default',
            trace_id: req.body.trace_id || 'trace-' + Date.now(),
            worker: 'blue-chain',
            attack: req.body.attack_id || null,
            seed: req.body.seed || null,
            target: req.body.target || 'BLUE_V1',
            decision: 'SETTLE',
            reason: 'OK',
            layer: 'L7',
            pin_hash: null,
            amount_atomic: amountAtomic,
            chain_delta_atomic: amountAtomic,
            funds_lost_atomic: fundsLost,
            latency_ms: 1.0,
            policy_digest: null,
            ts: new Date().toISOString(),
            details: { txHash, from, to, blockNumber: receipt.blockNumber },
          }),
        }).catch(() => {});
      } catch {}

      return res.json({
        success: true,
        txHash,
        receipt,
      });
    } catch (err: any) {
      return res.status(400).json({ success: false, error: err.message || 'Settlement failed' });
    }
  });

  return { app, port, db };
}

if (require.main === module || (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename))) {
  const { app, port } = createChainServer();
  app.listen(port, '0.0.0.0', () => {
    console.log(`[blue-chain] Mock blockchain server listening on http://0.0.0.0:${port}`);
  });
}
