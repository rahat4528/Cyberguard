import crypto from 'node:crypto';
import { decodeBase32 } from './base32.js';

export type TotpAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512';

export interface TotpOptions {
  period?: number;       // default: 30s
  digits?: number;       // default: 6
  algorithm?: TotpAlgorithm; // default: SHA-1
  t0?: number;           // default: 0
  offsetSeconds?: number;// per-device time correction offset
}

function getHmacAlgorithm(alg: TotpAlgorithm): string {
  switch (alg) {
    case 'SHA-256': return 'sha256';
    case 'SHA-512': return 'sha512';
    default: return 'sha1';
  }
}

/**
 * RFC 6238 TOTP: Time-Based One-Time Password Algorithm
 * 64-bit integer timestamp math safe beyond 2038.
 */
export function generateTOTP(
  secret: string | Buffer,
  timestampSeconds?: number,
  options: TotpOptions = {}
): string {
  const period = options.period || 30;
  const digits = options.digits || 6;
  const algorithm = options.algorithm || 'SHA-1';
  const t0 = options.t0 || 0;
  const offset = options.offsetSeconds || 0;

  const now = timestampSeconds !== undefined ? timestampSeconds : Math.floor(Date.now() / 1000);
  const adjustedTime = now + offset;
  const timeStep = BigInt(Math.floor((adjustedTime - t0) / period));

  const key = typeof secret === 'string' ? decodeBase32(secret) : secret;
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(timeStep, 0);

  const hmacAlg = getHmacAlgorithm(algorithm);
  const hmac = crypto.createHmac(hmacAlg, key).update(counterBuffer).digest();

  // Dynamic Truncation
  const offsetByte = hmac[hmac.length - 1] & 0x0f;
  const binaryCode =
    ((hmac[offsetByte] & 0x7f) << 24) |
    ((hmac[offsetByte + 1] & 0xff) << 16) |
    ((hmac[offsetByte + 2] & 0xff) << 8) |
    (hmac[offsetByte + 3] & 0xff);

  const otp = binaryCode % (10 ** digits);
  return otp.toString().padStart(digits, '0');
}

/**
 * Calculates remaining seconds in the current time step for dynamic countdown ring
 */
export function getRemainingSeconds(period: number = 30, timestampSeconds?: number): number {
  const now = timestampSeconds !== undefined ? timestampSeconds : Math.floor(Date.now() / 1000);
  const rem = period - (now % period);
  return rem === 0 ? period : rem;
}

/**
 * TOTP Verifier with replay protection and drift window (+/- 1 step)
 */
export class TotpVerifier {
  private usedSteps: Set<string> = new Set(); // accountId:timeStep

  public verify(
    candidateCode: string,
    secret: string | Buffer,
    accountId: string,
    timestampSeconds?: number,
    options: TotpOptions = {}
  ): { valid: boolean; reason?: string } {
    const period = options.period || 30;
    const now = timestampSeconds !== undefined ? timestampSeconds : Math.floor(Date.now() / 1000);
    const offset = options.offsetSeconds || 0;
    const currentStep = Math.floor((now + offset) / period);

    // Test drift window: -1, 0, +1
    for (let drift = -1; drift <= 1; drift++) {
      const step = currentStep + drift;
      const testTime = step * period;
      const expected = generateTOTP(secret, testTime, options);

      if (crypto.timingSafeEqual(Buffer.from(candidateCode), Buffer.from(expected))) {
        const stepKey = `${accountId}:${step}`;
        // REPLAY PROTECTION: reject if this step was already used
        if (this.usedSteps.has(stepKey)) {
          return { valid: false, reason: 'Code already used in current time window (Replay Attack).' };
        }
        this.usedSteps.add(stepKey);
        return { valid: true };
      }
    }

    return { valid: false, reason: 'Invalid OTP code' };
  }
}
