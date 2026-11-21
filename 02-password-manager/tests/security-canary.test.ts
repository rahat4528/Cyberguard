import test from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { VaultDatabaseStore } from '../database/store.js';
import { deriveMasterKey, deriveKeysFromMaster } from '../client-crypto/kdf.js';
import { wrapVaultKey, encryptPayload } from '../client-crypto/aead.js';

test('Security Canary Test: Server state and database dumps contain zero plaintext passwords or notes', () => {
  const db = new VaultDatabaseStore();

  const canaryMasterPassword = 'CANARY_PLAINTEXT_MASTER_PASSWORD_DO_NOT_LEAK!';
  const canaryNote = 'CANARY_PLAINTEXT_SECRET_BANK_PIN_9876!';
  const canarySitePassword = 'CANARY_PLAINTEXT_SITE_PASSWORD_ABC123!';

  const salt = 'canary_salt_12345';
  const masterKey = deriveMasterKey(canaryMasterPassword, salt);
  const { kek, authKey } = deriveKeysFromMaster(masterKey);

  // Register user
  const vaultKey = crypto.randomBytes(32);
  const wrappedVaultKey = wrapVaultKey(vaultKey, kek);

  const serverAuthSalt = crypto.randomBytes(16).toString('hex');
  const serverAuthHash = crypto.scryptSync(authKey, serverAuthSalt, 32).toString('hex');

  const userId = 'usr_canary_test';
  db.users.set(userId, {
    id: userId,
    email: 'canary@cyberguard.local',
    authSalt: salt,
    authHash: serverAuthHash,
    serverAuthSalt,
    wrappedVaultKey,
    kdfParams: { N: 32768, r: 8, p: 1 },
    createdAt: new Date().toISOString()
  });

  // Encrypt item client-side
  const itemPayload = JSON.stringify({ password: canarySitePassword, notes: canaryNote });
  const itemEnvelope = encryptPayload(itemPayload, vaultKey, `${userId}:item_canary:v1:k1`);

  db.items.set('item_canary', {
    id: 'item_canary',
    userId,
    envelope: itemEnvelope,
    revision: 1,
    isDeleted: false,
    updatedAt: new Date().toISOString()
  });

  // Dump entire raw database state
  const rawDbDump = JSON.stringify({
    users: Array.from(db.users.values()),
    items: Array.from(db.items.values()),
    auditEvents: db.auditEvents
  });

  // Verify canaries never appear in server state
  assert.strictEqual(
    rawDbDump.includes(canaryMasterPassword),
    false,
    'CRITICAL VIOLATION: Master password leaked in raw database state!'
  );
  assert.strictEqual(
    rawDbDump.includes(canaryNote),
    false,
    'CRITICAL VIOLATION: Secret note leaked in raw database state!'
  );
  assert.strictEqual(
    rawDbDump.includes(canarySitePassword),
    false,
    'CRITICAL VIOLATION: Credential password leaked in raw database state!'
  );
});
