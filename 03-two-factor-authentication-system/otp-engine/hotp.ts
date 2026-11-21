import crypto from 'node:crypto';
import { decodeBase32 } from './base32.js';

export interface HotpOptions {
  digits?: number; // 6, 7, or 8 (default: 6)
}

/**
 * RFC 4226 HOTP: HMAC-Based One-Time Password Algorithm
 * @param secret Base32 string or raw Buffer
 * @param counter 64-bit integer counter (BigInt or number)
 */
export function generateHOTP(secret: string | Buffer, counter: bigint | number, options: HotpOptions = {}): string {
  const digits = options.digits || 6;
  if (digits < 6 || digits > 8) {
    throw new Error('HOTP digits must be between 6 and 8');
  }

  const key = typeof secret === 'string' ? decodeBase32(secret) : secret;
  const counterBig = BigInt(counter);

  // 64-bit big-endian counter buffer
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(counterBig, 0);

  // Compute HMAC-SHA-1
  const hmac = crypto.createHmac('sha1', key).update(counterBuffer).digest();

  // Dynamic Truncation (DT): extract 4-byte dynamic binary code
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binaryCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binaryCode % (10 ** digits);
  return otp.toString().padStart(digits, '0');
}

/**
 * Verify HOTP code with look-ahead window
 */
export function verifyHOTP(
  candidateCode: string,
  secret: string | Buffer,
  currentCounter: bigint | number,
  lookAheadWindow: number = 10,
  options: HotpOptions = {}
): { valid: boolean; matchedCounter?: bigint } {
  const currentBig = BigInt(currentCounter);
  for (let i = 0; i <= lookAheadWindow; i++) {
    const testCounter = currentBig + BigInt(i);
    const expected = generateHOTP(secret, testCounter, options);
    if (crypto.timingSafeEqual(Buffer.from(candidateCode), Buffer.from(expected))) {
      return { valid: true, matchedCounter: testCounter };
    }
  }
  return { valid: false };
}
