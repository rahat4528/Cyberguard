import test from 'node:test';
import assert from 'node:assert';
import { generateHOTP } from '../otp-engine/hotp.js';
import { generateTOTP } from '../otp-engine/totp.js';

// RFC 4226 Appendix D Test Vectors
test('RFC 4226 Appendix D: Exact HOTP Test Vectors (Counters 0 to 9)', () => {
  // Secret: ASCII "12345678901234567890" (20 bytes)
  const secret = Buffer.from('12345678901234567890', 'ascii');

  const expectedVectors = [
    { count: 0, otp: '755224' },
    { count: 1, otp: '287082' },
    { count: 2, otp: '359152' },
    { count: 3, otp: '969429' },
    { count: 4, otp: '338314' },
    { count: 5, otp: '254676' },
    { count: 6, otp: '287922' },
    { count: 7, otp: '162583' },
    { count: 8, otp: '399871' },
    { count: 9, otp: '520489' }
  ];

  for (const v of expectedVectors) {
    const code = generateHOTP(secret, v.count, { digits: 6 });
    assert.strictEqual(code, v.otp, `HOTP mismatch at count ${v.count}`);
  }
});

// RFC 6238 Appendix B Test Vectors
test('RFC 6238 Appendix B: Exact TOTP Test Vectors (SHA-1, SHA-256, SHA-512, 8 digits)', () => {
  const secretSha1 = Buffer.from('12345678901234567890', 'ascii'); // 20 bytes
  const secretSha256 = Buffer.from('12345678901234567890123456789012', 'ascii'); // 32 bytes
  const secretSha512 = Buffer.from('1234567890123456789012345678901234567890123456789012345678901234', 'ascii'); // 64 bytes

  const testVectors = [
    {
      time: 59,
      sha1: '94287082',
      sha256: '46119246',
      sha512: '90693936'
    },
    {
      time: 1111111109,
      sha1: '07081804',
      sha256: '68084774',
      sha512: '25091201'
    },
    {
      time: 1111111111,
      sha1: '14050471',
      sha256: '67062674',
      sha512: '99943326'
    },
    {
      time: 1234567890,
      sha1: '89005924',
      sha256: '91819424',
      sha512: '93441116'
    },
    {
      time: 2000000000,
      sha1: '69279037',
      sha256: '90698825',
      sha512: '38618901'
    },
    {
      time: 20000000000, // Beyond Unix 2038 epoch!
      sha1: '65353130',
      sha256: '77737706',
      sha512: '47863826'
    }
  ];

  for (const v of testVectors) {
    const codeSha1 = generateTOTP(secretSha1, v.time, { digits: 8, algorithm: 'SHA-1' });
    assert.strictEqual(codeSha1, v.sha1, `SHA-1 mismatch at time ${v.time}`);

    const codeSha256 = generateTOTP(secretSha256, v.time, { digits: 8, algorithm: 'SHA-256' });
    assert.strictEqual(codeSha256, v.sha256, `SHA-256 mismatch at time ${v.time}`);

    const codeSha512 = generateTOTP(secretSha512, v.time, { digits: 8, algorithm: 'SHA-512' });
    assert.strictEqual(codeSha512, v.sha512, `SHA-512 mismatch at time ${v.time}`);
  }
});
