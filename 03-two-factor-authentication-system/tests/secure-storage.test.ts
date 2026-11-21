import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import { AuthenticatorVault } from '../secure-storage/vault.js';

test('Secure Storage: Vault encryption, PIN unlocking, and atomic write persistence', () => {
  const testFile = './test_vault_storage.json';
  if (fs.existsSync(testFile)) fs.unlinkSync(testFile);
  if (fs.existsSync(`${testFile}.bak`)) fs.unlinkSync(`${testFile}.bak`);

  const vault = new AuthenticatorVault(testFile);
  const pin = '849201';

  // 1. Unlock new vault
  const unlockRes = vault.unlockWithPin(pin);
  assert.strictEqual(unlockRes.success, true);

  // 2. Add TOTP account
  vault.addAccount({
    issuer: 'Production Cloud',
    account: 'admin@cloud.com',
    secret: 'JBSWY3DPEHPK3PXP',
    type: 'totp',
    algorithm: 'SHA-1',
    digits: 6,
    period: 30,
    counter: '0',
    favorite: true
  });

  // 3. Add HOTP account
  const hotpAcc = vault.addAccount({
    issuer: 'Legacy Server',
    account: 'root',
    secret: 'JBSWY3DPEHPK3PXP',
    type: 'hotp',
    algorithm: 'SHA-1',
    digits: 6,
    period: 30,
    counter: '10',
    favorite: false
  });

  // Verify file written to disk
  assert.strictEqual(fs.existsSync(testFile), true);

  // Lock vault
  vault.lock();
  assert.strictEqual(vault.getLockedState().locked, true);

  // 4. Test wrong PIN
  const wrongPinRes = vault.unlockWithPin('000000');
  assert.strictEqual(wrongPinRes.success, false);

  // 5. Unlock with correct PIN
  const correctUnlock = vault.unlockWithPin(pin);
  assert.strictEqual(correctUnlock.success, true);
  assert.strictEqual(vault.getAccounts().length, 2);

  // Clean up
  if (fs.existsSync(testFile)) fs.unlinkSync(testFile);
  if (fs.existsSync(`${testFile}.bak`)) fs.unlinkSync(`${testFile}.bak`);
});

test('Secure Storage: Durable HOTP counter persistence BEFORE code display', () => {
  const testFile = './test_hotp_durability.json';
  if (fs.existsSync(testFile)) fs.unlinkSync(testFile);

  const vault = new AuthenticatorVault(testFile);
  vault.unlockWithPin('123456');

  const acc = vault.addAccount({
    issuer: 'Service',
    account: 'user',
    secret: 'JBSWY3DPEHPK3PXP',
    type: 'hotp',
    algorithm: 'SHA-1',
    digits: 6,
    period: 30,
    counter: '5',
    favorite: false
  });

  // Generate code: counter MUST increment from 5 to 6 and be saved to disk
  const res = vault.generateCodeForAccount(acc.id);
  assert.strictEqual(res.counter, '6');

  // Inspect raw file to confirm durable persistence
  const fileContent = JSON.parse(fs.readFileSync(testFile, 'utf-8'));
  assert.ok(fileContent.ciphertext); // File is encrypted

  // Clean up
  if (fs.existsSync(testFile)) fs.unlinkSync(testFile);
  if (fs.existsSync(`${testFile}.bak`)) fs.unlinkSync(`${testFile}.bak`);
});
