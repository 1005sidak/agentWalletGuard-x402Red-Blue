import { GuardBlockError } from '../contracts/x402-types';

export interface ReconcileParams {
  chainUrl: string;
  payerAddress: string;
  expectedPayTo: string;
  expectedAmountAtomic: string;
  initialPayerBalanceAtomic: string;
  initialPayeeBalanceAtomic?: string;
  txHash?: string;
}

export interface ReconcileResult {
  settledOnChain: boolean;
  actualAmountAtomic: string;
  txHash?: string;
}

/**
 * L7 Independent On-Chain Reconciliation Layer:
 * - Directly queries the mock blockchain (never trusting facilitator or merchant claims)
 * - Verifies payer balance decreased by exactly the pinned amount
 * - Verifies recipient balance increased by exactly the pinned amount
 * - Verifies on-chain transaction records match expected parameters
 */
export async function reconcileSettlement(params: ReconcileParams): Promise<ReconcileResult> {
  const {
    chainUrl,
    payerAddress,
    expectedPayTo,
    expectedAmountAtomic,
    initialPayerBalanceAtomic,
    initialPayeeBalanceAtomic,
    txHash,
  } = params;

  const expectedAmount = BigInt(expectedAmountAtomic);
  const initialPayer = BigInt(initialPayerBalanceAtomic);

  // 1. Fetch final payer balance from mock blockchain
  let finalPayerBalanceAtomic = '0';
  try {
    const res = await fetch(`${chainUrl}/balances?address=${payerAddress.toLowerCase()}`);
    if (!res.ok) {
      throw new Error(`Chain balances query returned HTTP ${res.status}`);
    }
    const data: any = await res.json();
    finalPayerBalanceAtomic = data.balance_atomic || '0';
  } catch (err: any) {
    throw new GuardBlockError('SETTLEMENT_MISMATCH', 'L7', `Failed to query payer balance on-chain: ${err.message}`);
  }

  const finalPayer = BigInt(finalPayerBalanceAtomic);
  const payerDelta = initialPayer - finalPayer;

  // 2. Validate payer balance decreased by exactly expected amount
  if (payerDelta !== expectedAmount) {
    throw new GuardBlockError(
      'SETTLEMENT_MISMATCH',
      'L7',
      `On-chain payer balance delta mismatch: expected decrease of ${expectedAmountAtomic}, but measured ${payerDelta.toString()}`,
      {
        initialPayerBalance: initialPayerBalanceAtomic,
        finalPayerBalance: finalPayerBalanceAtomic,
        expectedAmount: expectedAmountAtomic,
        measuredDelta: payerDelta.toString(),
      }
    );
  }

  // 3. If initial payee balance was known, verify payee balance rose
  if (initialPayeeBalanceAtomic !== undefined) {
    try {
      const res = await fetch(`${chainUrl}/balances?address=${expectedPayTo.toLowerCase()}`);
      if (res.ok) {
        const data: any = await res.json();
        const finalPayee = BigInt(data.balance_atomic || '0');
        const initialPayee = BigInt(initialPayeeBalanceAtomic);
        const payeeDelta = finalPayee - initialPayee;

        if (payeeDelta !== expectedAmount) {
          throw new GuardBlockError(
            'SETTLEMENT_MISMATCH',
            'L7',
            `On-chain payee balance delta mismatch: expected increase of ${expectedAmountAtomic}, but measured ${payeeDelta.toString()}`
          );
        }
      }
    } catch (err: any) {
      if (err instanceof GuardBlockError) throw err;
      // Network failure on payee query
      throw new GuardBlockError('SETTLEMENT_MISMATCH', 'L7', `Failed to query payee balance: ${err.message}`);
    }
  }

  // 4. If txHash is provided, verify on-chain transaction record
  if (txHash) {
    try {
      const res = await fetch(`${chainUrl}/transactions/${txHash}`);
      if (!res.ok) {
        throw new GuardBlockError(
          'SETTLEMENT_MISMATCH',
          'L7',
          `Claimed transaction ${txHash} does not exist on blockchain`
        );
      }
      const tx: any = await res.json();
      if (tx.to_addr.toLowerCase() !== expectedPayTo.toLowerCase()) {
        throw new GuardBlockError(
          'SETTLEMENT_MISMATCH',
          'L7',
          `On-chain transaction payee mismatch: expected ${expectedPayTo}, found ${tx.to_addr}`
        );
      }
      if (tx.amount_atomic !== expectedAmountAtomic) {
        throw new GuardBlockError(
          'SETTLEMENT_MISMATCH',
          'L7',
          `On-chain transaction amount mismatch: expected ${expectedAmountAtomic}, found ${tx.amount_atomic}`
        );
      }
    } catch (err: any) {
      if (err instanceof GuardBlockError) throw err;
      throw new GuardBlockError('SETTLEMENT_MISMATCH', 'L7', `Failed to verify transaction on-chain: ${err.message}`);
    }
  }

  return {
    settledOnChain: true,
    actualAmountAtomic: expectedAmountAtomic,
    txHash,
  };
}
