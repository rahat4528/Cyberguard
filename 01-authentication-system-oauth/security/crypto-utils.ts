import crypto from 'node:crypto';

/**
 * Constant-time string equality check using crypto.timingSafeEqual
 */
export function timingSafeStringCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');
  if (bufA.length !== bufB.length) {
    // Perform dummy timingSafeEqual to avoid timing leakage on length mismatch
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Generate cryptographically secure random string
 */
export function generateRandomString(bytes: number = 32): string {
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Generate cryptographically secure base64url string
 */
export function generateRandomBase64Url(bytes: number = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

/**
 * Hash password using scrypt with modern security parameters (OWASP aligned)
 */
export function hashPassword(password: string, salt?: string): { salt: string; hash: string } {
  const finalSalt = salt || crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, finalSalt, 64, {
    N: 32768, // CPU/memory cost
    r: 8,     // block size
    p: 1,     // parallelization
    maxmem: 64 * 1024 * 1024
  });
  return {
    salt: finalSalt,
    hash: derivedKey.toString('hex')
  };
}

/**
 * Verify password against stored hash in constant time
 */
export function verifyPassword(password: string, salt: string, storedHash: string): boolean {
  const { hash } = hashPassword(password, salt);
  return timingSafeStringCompare(hash, storedHash);
}

/**
 * Compute RFC 7636 S256 code challenge from code_verifier
 */
export function computeS256CodeChallenge(codeVerifier: string): string {
  return crypto.createHash('sha256').update(codeVerifier).digest('base64url');
}

/**
 * Strictly verify RFC 7636 PKCE. Rejects 'plain' or unsupported methods.
 */
export function verifyPKCE(codeVerifier: string, codeChallenge: string, method: string): boolean {
  if (method !== 'S256') {
    return false; // RFC 9700 strictly mandates S256
  }
  if (!codeVerifier || codeVerifier.length < 43 || codeVerifier.length > 128) {
    return false; // RFC 7636 verifier length constraint: 43-128 chars
  }
  const computed = computeS256CodeChallenge(codeVerifier);
  return timingSafeStringCompare(computed, codeChallenge);
}

/**
 * Cryptographic Hash Chaining for Tamper-Evident Audit Logs
 */
export function calculateAuditEntryHash(
  previousHash: string,
  timestamp: string,
  eventType: string,
  actor: string,
  details: string
): string {
  const payload = `${previousHash}|${timestamp}|${eventType}|${actor}|${details}`;
  return crypto.createHash('sha256').update(payload).digest('hex');
}
