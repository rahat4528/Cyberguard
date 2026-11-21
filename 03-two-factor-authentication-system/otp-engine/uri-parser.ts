import { TotpAlgorithm } from './totp.js';

export interface ParsedOtpAuthUri {
  type: 'totp' | 'hotp';
  label: string;
  account: string;
  issuer?: string;
  secret: string;
  algorithm: TotpAlgorithm;
  digits: number;
  period: number;
  counter?: bigint;
}

/**
 * Strictly parses and validates otpauth:// URIs per Key URI Format
 * Prevents hostile payloads, code injection, and malformed inputs.
 */
export function parseOtpAuthUri(uriString: string): ParsedOtpAuthUri {
  if (!uriString || !uriString.startsWith('otpauth://')) {
    throw new Error('Invalid URI: Must start with otpauth://');
  }

  const url = new URL(uriString);
  const typeStr = url.hostname.toLowerCase();
  if (typeStr !== 'totp' && typeStr !== 'hotp') {
    throw new Error(`Unsupported OTP type: ${typeStr}. Only totp and hotp supported.`);
  }

  // Label parsing: format is "Issuer:Account" or just "Account"
  const rawPath = decodeURIComponent(url.pathname.replace(/^\//, ''));
  let issuerFromLabel: string | undefined;
  let account = rawPath;

  if (rawPath.includes(':')) {
    const parts = rawPath.split(':');
    issuerFromLabel = parts[0].trim();
    account = parts.slice(1).join(':').trim();
  }

  const queryIssuer = url.searchParams.get('issuer')?.trim();
  const finalIssuer = queryIssuer || issuerFromLabel || 'Unknown Service';

  const secret = url.searchParams.get('secret')?.trim();
  if (!secret) {
    throw new Error('Invalid URI: Missing secret parameter');
  }

  // Algorithm
  const algRaw = (url.searchParams.get('algorithm') || 'SHA1').toUpperCase();
  let algorithm: TotpAlgorithm = 'SHA-1';
  if (algRaw === 'SHA256' || algRaw === 'SHA-256') algorithm = 'SHA-256';
  else if (algRaw === 'SHA512' || algRaw === 'SHA-512') algorithm = 'SHA-512';

  // Digits
  const digits = Number(url.searchParams.get('digits') || 6);
  if (digits < 6 || digits > 8) {
    throw new Error('Invalid URI: Digits must be 6, 7, or 8');
  }

  // Period (for TOTP)
  const period = Number(url.searchParams.get('period') || 30);
  if (period <= 0 || period > 300) {
    throw new Error('Invalid URI: Period must be between 1 and 300 seconds');
  }

  // Counter (for HOTP)
  let counter: bigint | undefined;
  if (typeStr === 'hotp') {
    const counterStr = url.searchParams.get('counter');
    if (counterStr === null) {
      throw new Error('Invalid URI: HOTP requires counter parameter');
    }
    counter = BigInt(counterStr);
  }

  return {
    type: typeStr as 'totp' | 'hotp',
    label: rawPath,
    account,
    issuer: finalIssuer,
    secret,
    algorithm,
    digits,
    period,
    counter
  };
}
