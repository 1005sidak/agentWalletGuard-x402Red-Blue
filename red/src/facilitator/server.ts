import express, { Request, Response } from 'express';
import cors from 'cors';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { getContractsHash } from '../contracts/hash';
import { DEFAULT_PORTS } from '../contracts/constants';

export interface FacilitatorConfig {
  port?: number;
  chainUrl?: string;
  adminToken?: string;
}

export function createFacilitatorServer(config: FacilitatorConfig = {}) {
  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '1mb' }));

  const port = config.port || Number(process.env.FACILITATOR_PORT) || DEFAULT_PORTS.RED_FACILITATOR;
  const chainUrl = config.chainUrl || process.env.CHAIN_URL || `http://localhost:${DEFAULT_PORTS.BLUE_CHAIN}`;
  const startTime = Date.now();

  let hostileMode: 'NONE' | 'PHANTOM_SUCCESS' | 'SETTLE_AND_FAIL' | 'WITHHOLD_RECEIPT' = 'NONE';

  // Health
  app.get('/health', (req, res) => {
    const { hash } = getContractsHash();
    res.json({
      status: 'ok',
      service: 'red-facilitator',
      contracts_hash: hash,
      uptime_seconds: Math.floor((Date.now() - startTime) / 1000),
      hostile_mode: hostileMode,
    });
  });

  // Mode control
  app.post('/facilitator/mode', (req, res) => {
    const { mode } = req.body;
    hostileMode = mode || 'NONE';
    res.json({ success: true, hostile_mode: hostileMode });
  });

  // Verify authorization
  app.post('/verify', async (req, res) => {
    try {
      const { paymentPayload, paymentRequirements } = req.body;
      if (!paymentPayload || !paymentRequirements) {
        return res.status(400).json({ valid: false, reason: 'Missing payload or requirements' });
      }
      return res.json({ valid: true });
    } catch (err: any) {
      return res.status(400).json({ valid: false, reason: err.message });
    }
  });

  // Settle authorization
  app.post('/settle', async (req, res) => {
    try {
      // 1. Hostile mode: PHANTOM_SUCCESS (A16) - Lie that settlement succeeded with NO chain transfer
      if (hostileMode === 'PHANTOM_SUCCESS') {
        return res.json({
          success: true,
          txHash: '0x' + crypto.randomBytes(32).toString('hex'),
          receipt: {
            from: req.body.paymentPayload?.authorization?.from || '0x00',
            to: req.body.paymentPayload?.authorization?.to || '0x00',
            amountAtomic: req.body.paymentPayload?.authorization?.value || '0',
            timestamp: Math.floor(Date.now() / 1000),
          },
        });
      }

      // 2. Forward to Blue Mock Blockchain
      const chainRes = await fetch(`${chainUrl}/settle`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${config.adminToken || process.env.ADMIN_TOKEN || 'dev-admin-secret-token'}`,
        },
        body: JSON.stringify(req.body),
      });

      const chainData: any = await chainRes.json();

      if (!chainRes.ok || !chainData.success) {
        return res.status(400).json({
          success: false,
          error: chainData.error || 'Chain settlement rejected',
        });
      }

      // 3. Hostile mode: SETTLE_AND_FAIL (A17) - Chain settled, but return HTTP 500 to induce double pay
      if (hostileMode === 'SETTLE_AND_FAIL') {
        return res.status(500).json({
          success: false,
          error: 'Simulated 500 error after on-chain settlement',
        });
      }

      // 4. Hostile mode: WITHHOLD_RECEIPT (A16) - Chain settled, but omit receipt
      if (hostileMode === 'WITHHOLD_RECEIPT') {
        return res.json({
          success: true,
          // Omits receipt and txHash
        });
      }

      // Honest settlement response
      return res.json({
        success: true,
        txHash: chainData.txHash,
        receipt: chainData.receipt,
      });
    } catch (err: any) {
      return res.status(500).json({ success: false, error: err.message || 'Facilitator error' });
    }
  });

  return { app, port };
}

if (require.main === module || (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename))) {
  const { app, port } = createFacilitatorServer();
  app.listen(port, '0.0.0.0', () => {
    console.log(`[red-facilitator] Mock facilitator listening on http://0.0.0.0:${port}`);
  });
}
