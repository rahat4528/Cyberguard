import crypto from 'node:crypto';

const RFC4648_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * RFC 4648 Base32 Decoding
 * Accepts uppercase/lowercase, ignores spaces and hyphens, handles optional '=' padding,
 * and strictly rejects invalid characters.
 */
export function decodeBase32(input: string): Buffer {
  // Sanitize: remove whitespace, hyphens, and convert to uppercase
  const sanitized = input.replace(/[\s\-=]/g, '').toUpperCase();
  if (sanitized.length === 0) {
    throw new Error('Base32 input is empty');
  }

  // Validate characters
  for (let i = 0; i < sanitized.length; i++) {
    if (!RFC4648_ALPHABET.includes(sanitized[i])) {
      throw new Error(`Invalid Base32 character: ${sanitized[i]}`);
    }
  }

  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (let i = 0; i < sanitized.length; i++) {
    const val = RFC4648_ALPHABET.indexOf(sanitized[i]);
    value = (value << 5) | val;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/**
 * Keyed Fingerprint of Secret for Safe Deduplication
 * Compares keyed HMAC hashes so secrets are never compared or stored in plaintext.
 */
export function computeSecretFingerprint(secret: string, key: string = 'cyberguard-dedupe-key'): string {
  const secretBuf = decodeBase32(secret);
  return crypto.createHmac('sha256', key).update(secretBuf).digest('hex');
}
