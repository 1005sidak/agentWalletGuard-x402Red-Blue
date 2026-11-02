import { describe, it, expect } from 'vitest';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { verifyTypedData } from 'viem';
import { wrapFetchWithPayment } from 'x402-fetch';
import { PinStore } from '../src/guard/pin-store';
import { createGuardedWallet } from '../src/guard/wallet-guard';
import { TOKEN_NAME, TOKEN_VERSION } from '../src/contracts/constants';

describe('Phase 0 Spike — Wallet Wrapper & x402-fetch 1.2.0 Compatibility', () => {
  const privateKey = generatePrivateKey();
  const rawAccount = privateKeyToAccount(privateKey);
  const pinStore = new PinStore();

  const honestPayTo = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' as const;
  const honestAsset = '0x0000000000000000000000000000000000001010' as const;
  const amountAtomic = '1000000'; // 1.0 TUSD
  const chainId = 84532; // base-sepolia chain ID used by x402

  it('proves guarded wallet satisfies x402 account detection and performs honest signing', async () => {
    let signCalled = false;
    const guardedAccount = createGuardedWallet({
      account: rawAccount,
      pinStore,
      onSign: () => {
        signCalled = true;
      },
    });

    // Pin the honest quote
    pinStore.pin({
      pin_id: 'pin-1',
      intent_id: 'intent-1',
      payTo: honestPayTo,
      asset: honestAsset,
      amountAtomic,
      chainId,
      assetName: TOKEN_NAME,
      assetVersion: TOKEN_VERSION,
      resource: 'http://localhost:4020/products/mouse',
      expiresAt: Date.now() + 60000,
    });

    // Mock fetch that returns a 402 with x402 requirements on the first call, and 200 on retry
    let callCount = 0;
    let receivedPaymentHeader: string | null = null;

    const mockFetch = async (input: any, init?: any): Promise<Response> => {
      callCount++;
      if (callCount === 1) {
        const body = JSON.stringify({
          x402Version: 1,
          accepts: [
            {
              scheme: 'exact',
              network: 'base-sepolia',
              maxAmountRequired: amountAtomic,
              resource: 'http://localhost:4020/products/mouse',
              description: 'Wireless Mouse Purchase',
              mimeType: 'application/json',
              asset: honestAsset,
              payTo: honestPayTo,
              maxTimeoutSeconds: 30,
              extra: {
                name: TOKEN_NAME,
                version: TOKEN_VERSION,
              },
            },
          ],
        });
        return new Response(body, {
          status: 402,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      // Second call (retry with X-PAYMENT)
      receivedPaymentHeader = init?.headers?.['X-PAYMENT'] || null;
      return new Response(JSON.stringify({ status: 'ok', order_id: 'ord-123' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    };

    const fetchWithPayment = wrapFetchWithPayment(mockFetch as any, guardedAccount, BigInt(amountAtomic));
    const response = await fetchWithPayment('http://localhost:4020/products/mouse');

    expect(response.status).toBe(200);
    expect(callCount).toBe(2);
    expect(signCalled).toBe(true);
    expect(receivedPaymentHeader).toBeDefined();

    // Verify decoded header
    const decoded = JSON.parse(Buffer.from(receivedPaymentHeader!, 'base64').toString('utf8'));
    expect(decoded.payload.authorization.to.toLowerCase()).toBe(honestPayTo.toLowerCase());
    expect(decoded.payload.authorization.value).toBe(amountAtomic);

    // Verify signature cryptographically using viem
    const domain = {
      name: TOKEN_NAME,
      version: TOKEN_VERSION,
      chainId,
      verifyingContract: honestAsset,
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

    const validSig = await verifyTypedData({
      address: rawAccount.address,
      domain,
      types,
      primaryType: 'TransferWithAuthorization',
      message: {
        from: rawAccount.address,
        to: honestPayTo,
        value: BigInt(amountAtomic),
        validAfter: BigInt(decoded.payload.authorization.validAfter),
        validBefore: BigInt(decoded.payload.authorization.validBefore),
        nonce: decoded.payload.authorization.nonce,
      },
      signature: decoded.payload.signature,
    });
    expect(validSig).toBe(true);
  });

  it('proves firewall blocks unpinned signing attempts with SIGN_UNPINNED', async () => {
    const unpinnedAccount = createGuardedWallet({
      account: rawAccount,
      pinStore, // empty or missing this pin
    });

    const mockFetch = async () => {
      const body = JSON.stringify({
        x402Version: 1,
        accepts: [
          {
            scheme: 'exact',
            network: 'base-sepolia',
            maxAmountRequired: '5000000',
            resource: 'http://localhost:4020/products/unpinned',
            description: 'Unpinned Product',
            mimeType: 'application/json',
            asset: honestAsset,
            payTo: honestPayTo,
            maxTimeoutSeconds: 30,
            extra: { name: TOKEN_NAME, version: TOKEN_VERSION },
          },
        ],
      });
      return new Response(body, { status: 402, headers: { 'Content-Type': 'application/json' } });
    };

    const fetchWithPayment = wrapFetchWithPayment(mockFetch as any, unpinnedAccount, BigInt(10000000));
    await expect(fetchWithPayment('http://localhost:4020/products/unpinned')).rejects.toThrowError(
      /SIGN_UNPINNED/
    );
  });

  it('proves firewall blocks consumed pin reuse with PIN_CONSUMED', async () => {
    const pinHash = pinStore.pin({
      pin_id: 'pin-reuse',
      intent_id: 'intent-reuse',
      payTo: honestPayTo,
      asset: honestAsset,
      amountAtomic: '200000',
      chainId,
      assetName: TOKEN_NAME,
      assetVersion: TOKEN_VERSION,
      resource: 'http://localhost:4020/products/reuse',
      expiresAt: Date.now() + 60000,
    });

    // Consume it once
    pinStore.consume(pinHash);

    const guardedAccount = createGuardedWallet({
      account: rawAccount,
      pinStore,
    });

    const mockFetch = async () => {
      const body = JSON.stringify({
        x402Version: 1,
        accepts: [
          {
            scheme: 'exact',
            network: 'base-sepolia',
            maxAmountRequired: '200000',
            resource: 'http://localhost:4020/products/reuse',
            description: 'Reused Pin Product',
            mimeType: 'application/json',
            asset: honestAsset,
            payTo: honestPayTo,
            maxTimeoutSeconds: 30,
            extra: { name: TOKEN_NAME, version: TOKEN_VERSION },
          },
        ],
      });
      return new Response(body, { status: 402, headers: { 'Content-Type': 'application/json' } });
    };

    const fetchWithPayment = wrapFetchWithPayment(mockFetch as any, guardedAccount, BigInt(1000000));
    await expect(fetchWithPayment('http://localhost:4020/products/reuse')).rejects.toThrowError(
      /PIN_CONSUMED/
    );
  });

  it('proves firewall blocks signMessage and signTransaction with SIGN_FORBIDDEN', async () => {
    const guardedAccount = createGuardedWallet({
      account: rawAccount,
      pinStore,
    });

    expect(() => guardedAccount.signMessage({ message: 'test' })).toThrowError(/SIGN_FORBIDDEN/);
    expect(() => guardedAccount.signTransaction({} as any)).toThrowError(/SIGN_FORBIDDEN/);
  });
});
