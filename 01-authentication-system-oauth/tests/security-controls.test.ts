import test from 'node:test';
import assert from 'node:assert';
import { RateLimiter } from '../backend/rate-limiter.js';
import { validateStartupConfig } from '../security/startup-checks.js';
import { DatabaseStore } from '../database/store.js';
import { seedDatabase } from '../database/seed.js';

test('Security Controls: Rate limiter sliding window and brute-force throttling', () => {
  const limiter = new RateLimiter(3, 1000); // 3 attempts per second

  assert.strictEqual(limiter.checkLimit('ip_1.2.3.4').allowed, true);
  assert.strictEqual(limiter.checkLimit('ip_1.2.3.4').allowed, true);
  assert.strictEqual(limiter.checkLimit('ip_1.2.3.4').allowed, true);

  // 4th attempt should be blocked
  const blocked = limiter.checkLimit('ip_1.2.3.4');
  assert.strictEqual(blocked.allowed, false);
  assert.strictEqual(blocked.remaining, 0);
  assert.ok(blocked.retryAfterMs > 0);

  // Different IP is unaffected (isolation)
  assert.strictEqual(limiter.checkLimit('ip_9.9.9.9').allowed, true);
});

test('Security Controls: Startup configuration validation refuses insecure settings', () => {
  // Insecure production with HTTP
  const insecureHttp = validateStartupConfig({
    nodeEnv: 'production',
    port: 4000,
    issuerUrl: 'http://auth.insecure.com',
    keyEncryptionKey: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    sessionSecret: 'long-enough-session-secret-32-chars-long',
    databasePath: './data.json',
    auditLogPath: './audit.json',
    tokenExpirySeconds: 900,
    refreshTokenExpirySeconds: 604800,
    codeExpirySeconds: 60
  });
  assert.strictEqual(insecureHttp.valid, false);
  assert.ok(insecureHttp.errors.some(e => e.includes('must use HTTPS')));

  // Insecure production with short KEK
  const shortKek = validateStartupConfig({
    nodeEnv: 'production',
    port: 4000,
    issuerUrl: 'https://auth.secure.com',
    keyEncryptionKey: 'too-short',
    sessionSecret: 'long-enough-session-secret-32-chars-long',
    databasePath: './data.json',
    auditLogPath: './audit.json',
    tokenExpirySeconds: 900,
    refreshTokenExpirySeconds: 604800,
    codeExpirySeconds: 60
  });
  assert.strictEqual(shortKek.valid, false);
  assert.ok(shortKek.errors.some(e => e.includes('KEY_ENCRYPTION_KEY')));
});

test('Security Controls: Plaintext Canary Test (Confirming no plaintext passwords or raw secrets)', () => {
  const db = new DatabaseStore();
  seedDatabase(db);

  const rawJson = JSON.stringify({
    users: Array.from(db.users.values()),
    clients: Array.from(db.clients.values()),
    auditLogs: db.auditLogs
  });

  // Canary strings that must NEVER be found in stored database records
  const canaries = [
    'AdminPass!2026#Secure',
    'AlicePass!2026#Secure',
    'BobPass!2026#Secure',
    'portal-secret-2026'
  ];

  for (const canary of canaries) {
    assert.strictEqual(
      rawJson.includes(canary),
      false,
      `CRITICAL VIOLATION: Canary plaintext secret "${canary}" was discovered in database state!`
    );
  }
});
