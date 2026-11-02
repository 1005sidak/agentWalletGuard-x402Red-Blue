/**
 * Blue V0 Protection Module
 * Reproduces the baseline protections of the original x402-agent-wallet repository
 * without leaking V1 hardening into it.
 *
 * Baseline behaviors:
 * 1. Float-based spend tracking in USD (Number(x)/1e6).
 * 2. Host checking based on 402 resource URL (vulnerable to trailing-dot, subdomains, ports).
 * 3. Never checks payTo (G1) - policy has no payTo field.
 * 4. Never checks asset address or chainId (G2).
 * 5. String approvalRef check: any non-empty string passes (G15).
 * 6. Records spend only after merchant returns x-payment-response (G4, G14).
 * 7. No wallet-level quote pinning (G6).
 */

export interface V0PolicyConfig {
  dailyCapUsd?: number;
  perRequestCapUsd?: number;
  approvalThresholdUsd?: number;
  blockedHosts?: string[];
}

export class BlueV0Guard {
  private dailyCapUsd: number;
  private perRequestCapUsd: number;
  private approvalThresholdUsd: number;
  private blockedHosts: Set<string>;
  private spentTodayUsd = 0;

  constructor(config: V0PolicyConfig = {}) {
    this.dailyCapUsd = config.dailyCapUsd ?? 50.0; // $50 daily
    this.perRequestCapUsd = config.perRequestCapUsd ?? 30.0; // $30 per call
    this.approvalThresholdUsd = config.approvalThresholdUsd ?? 15.0; // $15 approval
    this.blockedHosts = new Set(config.blockedHosts || ['evil.example', 'hostile.local']);
  }

  /**
   * Baseline pre-signing policy check
   */
  check(params: {
    resource: string;
    amountAtomic: string;
    approvalRef?: string;
  }): { allowed: boolean; reason?: string } {
    const amountUsd = Number(params.amountAtomic) / 1e6;

    // 1. Host blocklist check (naive exact match, vulnerable to trailing dot and subdomains)
    try {
      const parsedUrl = new URL(params.resource);
      if (this.blockedHosts.has(parsedUrl.hostname)) {
        return { allowed: false, reason: 'ORIGIN_NOT_ALLOWED' };
      }
    } catch {
      return { allowed: false, reason: 'PARSE_REJECT' };
    }

    // 2. Per-request cap
    if (amountUsd > this.perRequestCapUsd) {
      return { allowed: false, reason: 'PRICE_OUT_OF_BAND' };
    }

    // 3. Approval gate (flawed: any non-empty string passes!)
    if (amountUsd >= this.approvalThresholdUsd) {
      if (!params.approvalRef || params.approvalRef.trim() === '') {
        return { allowed: false, reason: 'APPROVAL_REQUIRED' };
      }
    }

    // 4. Daily cap check
    if (this.spentTodayUsd + amountUsd > this.dailyCapUsd) {
      return { allowed: false, reason: 'BUDGET_EXHAUSTED' };
    }

    return { allowed: true };
  }

  /**
   * In V0, spend is recorded only after settlement response is received
   */
  recordSpend(amountAtomic: string): void {
    const amountUsd = Number(amountAtomic) / 1e6;
    this.spentTodayUsd += amountUsd;
  }

  getSpentTodayUsd(): number {
    return this.spentTodayUsd;
  }

  reset(): void {
    this.spentTodayUsd = 0;
  }
}
