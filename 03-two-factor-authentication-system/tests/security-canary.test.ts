import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import { AuthenticatorVault } from '../secure-storage/vault.js';

test('Security Canary Test: OTP secret seeds never leak in plaintext to files or storage', () => {
  const canaryFile = './test_canary_vault.json';
  if (fs.existsSync(canaryFile)) fs.unlinkSync(canaryFile);

  const vault = new AuthenticatorVault(canaryFile);
  vault.unlockWithPin('987654');

  const canarySecret = 'JBSWY3DPEHPK3PXP'; // Seed string
  vault.addAccount({
    issuer: 'TopSecretInfrastructure',
    account: 'canary_user',
    secret: canarySecret,
    type: 'totp',
    algorithm: 'SHA-256',
    digits: 8,
    period: 30,
    counter: '0',
    favorite: true
  });

  // Read raw file from disk
  const rawDiskContent = fs.readFileSync(canaryFile, 'utf-8');

  // Verify canary secret never appears in plaintext
  assert.strictEqual(
    rawDiskContent.includes(canarySecret),
    false,
    'CRITICAL VIOLATION: OTP Secret Seed leaked in plaintext to disk!'
  );

  // Clean up
  if (fs.existsSync(canaryFile)) fs.unlinkSync(canaryFile);
  if (fs.existsSync(`${canaryFile}.bak`)) fs.unlinkSync(`${canaryFile}.bak`);
});
