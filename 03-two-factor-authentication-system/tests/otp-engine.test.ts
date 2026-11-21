import test from 'node:test';
import assert from 'node:assert';
import { decodeBase32, computeSecretFingerprint } from '../otp-engine/base32.js';
import { generateTOTP, getRemainingSeconds, TotpVerifier } from '../otp-engine/totp.js';
import { parseOtpAuthUri } from '../otp-engine/uri-parser.js';

test('Base32: Decode edge cases (spaces, hyphens, lowercase, padding, and invalid characters)', () => {
  const secret = 'JBSWY3DPEHPK3PXP'; // Base32 for "Hello!Þ­¾ï"

  // Standard uppercase
  const buf1 = decodeBase32(secret);
  assert.strictEqual(buf1.toString('utf-8', 0, 6), 'Hello!');

  // Lowercase with spaces and hyphens
  const buf2 = decodeBase32('jbswy-3dpeh pk3pxp===');
  assert.deepStrictEqual(buf1, buf2);

  // Invalid characters reject strictly
  assert.throws(() => decodeBase32('INVALID_CHAR_1890!'), /Invalid Base32 character/);
});

test('URI Parser: Strict otpauth URI validation and parsing', () => {
  const uri = 'otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60';
  const parsed = parseOtpAuthUri(uri);

  assert.strictEqual(parsed.type, 'totp');
  assert.strictEqual(parsed.issuer, 'Example');
  assert.strictEqual(parsed.account, 'alice@google.com');
  assert.strictEqual(parsed.algorithm, 'SHA-256');
  assert.strictEqual(parsed.digits, 8);
  assert.strictEqual(parsed.period, 60);

  // Hostile schemes and missing parameters reject
  assert.throws(() => parseOtpAuthUri('https://evil.com?secret=123'), /Must start with otpauth:\/\//);
  assert.throws(() => parseOtpAuthUri('otpauth://totp/test'), /Missing secret parameter/);
});

test('TOTP Engine: Step boundary behavior and countdown calculation', () => {
  const secret = 'JBSWY3DPEHPK3PXP';

  // Countdown calculations for 30s period
  assert.strictEqual(getRemainingSeconds(30, 29), 1);
  assert.strictEqual(getRemainingSeconds(30, 30), 30);
  assert.strictEqual(getRemainingSeconds(30, 59), 1);
  assert.strictEqual(getRemainingSeconds(30, 60), 30);

  // Different time steps produce different codes
  const codeAt29 = generateTOTP(secret, 29, { period: 30 });
  const codeAt30 = generateTOTP(secret, 30, { period: 30 });
  assert.notStrictEqual(codeAt29, codeAt30);
});

test('TOTP Verifier: Drift window tolerance and replay attack protection', () => {
  const verifier = new TotpVerifier();
  const secret = 'JBSWY3DPEHPK3PXP';
  const accountId = 'acc_alice_01';
  const now = 1000000;

  const validCode = generateTOTP(secret, now);

  // 1. Initial valid submission
  const res1 = verifier.verify(validCode, secret, accountId, now);
  assert.strictEqual(res1.valid, true);

  // 2. Replay attack with same code in same time window
  const res2 = verifier.verify(validCode, secret, accountId, now);
  assert.strictEqual(res2.valid, false);
  assert.ok(res2.reason?.includes('Replay Attack'));
});
