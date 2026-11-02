import { LocalAccount } from 'viem';
import { EndpointsRegistry } from '../contracts/registry.schema';
import { PinStore } from './pin-store';
import { createGuardedWallet } from './wallet-guard';
import { checkTransport, TransportCheckParams } from './l0-transport';
import { parseAndSanitize402, L1ParseResult, L1SanitizedRequirement } from './l1-input';
import { checkIdentity, MatchedEndpoint } from './l2-identity';
import { checkPriceAndApproval, ApprovalToken } from './l3-price';
import { createBudgetManager, BudgetManager, BudgetConfig } from './l5-budget';
import { createBehaviourTracker, BehaviourTracker, BehaviourConfig } from './l6-behaviour';
import { reconcileSettlement, ReconcileParams, ReconcileResult } from './l7-reconcile';
import { createAuditLogger, AuditLogger, AuditConfig, wrapFailClosed, FailClosedContext } from './l8-audit';
import { GuardBlockError } from '../contracts/x402-types';

export * from './pin-store';
export * from './wallet-guard';
export * from './l0-transport';
export * from './l1-input';
export * from './l2-identity';
export * from './l3-price';
export * from './l5-budget';
export * from './l6-behaviour';
export * from './l7-reconcile';
export * from './l8-audit';
export * from './v0';

export interface BlueV1GuardOptions {
  account: LocalAccount;
  registry: EndpointsRegistry;
  budgetDbPath: string;
  auditDbPath?: string;
  collectorUrl?: string;
  eventToken?: string;
  chainUrl?: string;
  runId?: string;
  maxWindowSeconds?: number;
}

export interface GuardEvaluationContext {
  url: string;
  method: string;
  raw402Body: string | object;
  intentId: string;
  approvalToken?: ApprovalToken | null;
  lastSeenQuoteAtomic?: string | null;
  runId?: string;
  traceId?: string;
  attack?: string | null;
  seed?: number | null;
}

export interface GuardEvaluationResult {
  allowed: boolean;
  selectedRequirement: L1SanitizedRequirement;
  matchedEndpoint: MatchedEndpoint;
  quoteHash: string;
  guardedWallet: LocalAccount;
  reconcile: (initialPayerBalance: string, txHash?: string) => Promise<ReconcileResult>;
  commitBudget: () => void;
  releaseBudget: () => void;
}

export class BlueV1Guard {
  public pinStore: PinStore;
  public budgetManager: BudgetManager;
  public behaviourTracker: BehaviourTracker;
  public auditLogger: AuditLogger;
  public guardedWallet: LocalAccount;
  public registry: EndpointsRegistry;
  private rawAccount: LocalAccount;
  private chainUrl: string;

  constructor(options: BlueV1GuardOptions) {
    this.rawAccount = options.account;
    this.registry = options.registry;
    this.chainUrl = options.chainUrl || 'http://localhost:4040';

    this.pinStore = new PinStore();
    this.guardedWallet = createGuardedWallet({
      account: options.account,
      pinStore: this.pinStore,
      maxWindowSeconds: options.maxWindowSeconds || 30,
      onBlock: (code, layer, details) => {
        this.auditLogger.logEvent({
          target: 'BLUE_V1',
          decision: 'BLOCK',
          reason: code,
          layer: layer as any,
          details: details as Record<string, unknown>,
        });
      },
      onSign: (pinHash, details) => {
        this.auditLogger.logEvent({
          target: 'BLUE_V1',
          decision: 'SIGN',
          reason: 'OK',
          layer: 'L4',
          pin_hash: pinHash,
          details: details as Record<string, unknown>,
        });
      },
    });

    this.budgetManager = createBudgetManager(options.budgetDbPath, {
      dailyAtomic: options.registry.globalCaps.dailyAtomic,
      perCallAtomic: options.registry.globalCaps.perCallAtomic,
    });

    this.behaviourTracker = createBehaviourTracker({
      maxVelocityPerMinute: options.registry.globalCaps.velocityPerMin,
      maxConsecutive402s: 3,
    });

    this.auditLogger = createAuditLogger({
      logFilePath: options.auditDbPath,
      collectorUrl: options.collectorUrl,
      eventToken: options.eventToken,
      runId: options.runId,
      worker: 'blue-guard',
    });
  }

  /**
   * Evaluates an incoming 402 challenge through the full L0-L8 Blue V1 defensive pipeline.
   */
  public async evaluate402(ctx: GuardEvaluationContext): Promise<GuardEvaluationResult> {
    const failClosedCtx: FailClosedContext = {
      logger: this.auditLogger,
      runId: ctx.runId,
      traceId: ctx.traceId,
      attack: ctx.attack,
      seed: ctx.seed,
    };

    return wrapFailClosed(async () => {
      // 0. L6 Behaviour Tracking: Velocity & Loop check
      this.behaviourTracker.recordAttempt(ctx.url, ctx.intentId);

      // 1. L0 Transport Check: Exact origin allowlist & no redirects
      const allowedOrigins = Object.values(this.registry.merchants).map((m) => m.origin);
      checkTransport({
        url: ctx.url,
        allowedOrigins,
      });

      // 2. L1 Input Validation & Prompt Injection Sanitization
      const l1Result: L1ParseResult = parseAndSanitize402(ctx.raw402Body);
      const req = l1Result.accepts[0]; // Choose primary payment requirement

      failClosedCtx.amountAtomic = req.maxAmountRequired;

      // 3. L2 Merchant & Asset Identity Check
      const matched = checkIdentity({
        url: ctx.url,
        method: ctx.method,
        payTo: req.payTo,
        asset: req.asset,
        network: req.network,
        registry: this.registry,
      });

      // 4. L3 Price Bands & Cryptographic Approval Gate
      checkPriceAndApproval({
        resource: req.resource,
        amountAtomic: req.maxAmountRequired,
        endpoint: matched.endpoint,
        intentId: ctx.intentId,
        approvalToken: ctx.approvalToken,
        lastSeenAmountAtomic: ctx.lastSeenQuoteAtomic,
      });

      // 5. L5 Budget Reservation (Atomic SQLite WAL)
      this.budgetManager.reserve({
        intentId: ctx.intentId,
        resource: req.resource,
        amountAtomic: req.maxAmountRequired,
      });

      // 6. L4 Wallet Quote Pinning
      const pinChainId = (req.network === 'base-sepolia') ? 84532 : (req.network === 'base' || req.network === 'base-mainnet') ? 8453 : matched.endpoint.chainId;
      const quoteHash = this.pinStore.pin({
        payTo: req.payTo,
        asset: req.asset,
        amountAtomic: req.maxAmountRequired,
        chainId: pinChainId,
        assetName: matched.endpoint.assetName,
        assetVersion: matched.endpoint.assetVersion,
        maxWindowSeconds: matched.endpoint.maxWindowSeconds,
      });

      // Log ALLOW event
      this.auditLogger.logEvent({
        run_id: ctx.runId,
        trace_id: ctx.traceId,
        attack: ctx.attack,
        seed: ctx.seed,
        target: 'BLUE_V1',
        decision: 'ALLOW',
        reason: 'OK',
        layer: 'L8',
        pin_hash: quoteHash,
        amount_atomic: req.maxAmountRequired,
        details: { intentId: ctx.intentId, resource: req.resource },
      });

      return {
        allowed: true,
        selectedRequirement: req,
        matchedEndpoint: matched,
        quoteHash,
        guardedWallet: this.guardedWallet,
        commitBudget: () => {
          this.budgetManager.commit(ctx.intentId, req.maxAmountRequired);
          this.behaviourTracker.recordSuccess(ctx.url, ctx.intentId);
        },
        releaseBudget: () => {
          this.budgetManager.release(ctx.intentId);
        },
        reconcile: async (initialPayerBalance: string, txHash?: string) => {
          return reconcileSettlement({
            chainUrl: this.chainUrl,
            payerAddress: this.rawAccount.address,
            expectedPayTo: req.payTo,
            expectedAmountAtomic: req.maxAmountRequired,
            initialPayerBalanceAtomic: initialPayerBalance,
            txHash,
          });
        },
      };
    }, failClosedCtx);
  }

  public close() {
    this.budgetManager.close();
    this.auditLogger.close();
  }
}
