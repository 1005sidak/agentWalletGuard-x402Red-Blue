import { GuardBlockError } from '../contracts/x402-types';
import { domainToASCII } from 'node:url';

export interface TransportCheckParams {
  url: string;
  allowedOrigins: string[]; // e.g. ["http://localhost:4020", "https://api.example.com"]
  isRedirect?: boolean;
}

/**
 * L0 Transport Layer:
 * - Exact origin check against allowlist
 * - Rejects any HTTP 30x redirects (redirect: manual)
 * - Strips trailing dots and verifies exact ASCII hostname
 * - Rejects userinfo in URL (http://user:pass@host)
 * - Rejects HTTPS downgrade
 */
export function checkTransport(params: TransportCheckParams): { origin: string; host: string } {
  const { url, allowedOrigins, isRedirect = false } = params;

  if (isRedirect) {
    throw new GuardBlockError('REDIRECT_HOST', 'L0', 'Automatic redirect following is strictly prohibited for payments');
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new GuardBlockError('ORIGIN_NOT_ALLOWED', 'L0', `Malformed URL: ${url}`);
  }

  // Check for userinfo
  if (parsed.username || parsed.password) {
    throw new GuardBlockError('ORIGIN_NOT_ALLOWED', 'L0', 'URL contains forbidden userinfo credentials');
  }

  // Punycode & trailing dot normalization
  let hostname = parsed.hostname;
  if (hostname.endsWith('.')) {
    // If the URL had trailing dot, we reject or flag lookalike origin
    throw new GuardBlockError('ORIGIN_NOT_ALLOWED', 'L0', 'Trailing-dot FQDN lookalike origin rejected');
  }

  try {
    hostname = domainToASCII(hostname);
  } catch {
    throw new GuardBlockError('ORIGIN_NOT_ALLOWED', 'L0', 'IDN punycode conversion failed');
  }

  const port = parsed.port ? `:${parsed.port}` : '';
  const canonicalOrigin = `${parsed.protocol}//${hostname}${port}`;

  // Check against allowed origins exact match
  const isAllowed = allowedOrigins.some((allowed) => {
    try {
      const allowedParsed = new URL(allowed);
      const allowedPort = allowedParsed.port ? `:${allowedParsed.port}` : '';
      const allowedCanonical = `${allowedParsed.protocol}//${domainToASCII(allowedParsed.hostname)}${allowedPort}`;
      return canonicalOrigin === allowedCanonical;
    } catch {
      return false;
    }
  });

  if (!isAllowed) {
    throw new GuardBlockError('ORIGIN_NOT_ALLOWED', 'L0', `Origin not allowed: ${canonicalOrigin}`);
  }

  return { origin: canonicalOrigin, host: hostname };
}
