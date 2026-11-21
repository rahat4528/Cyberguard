import test from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { deriveMasterKey, deriveKeysFromMaster } from '../client-crypto/kdf.js';
import {
  encryptPayload,
  decryptPayload,
  wrapVaultKey,
  unwrapVaultKey
} from '../client-crypto/aead.js';

test('KDF & Domain Separation: HKDF splits Master Key into independent KEK and AuthKey', () => {
  const masterPassword = 'MySuperSecureMasterPassword!2026';
  const salt = 'random_account_salt_1234567890abcdef';
  const masterKey = deriveMasterKey(masterPassword, salt);

  const { kek, authKey } = deriveKeysFromMaster(masterKey);

  assert.strictEqual(kek.length, 32);
  assert.strictEqual(authKey.length, 64); // 32 bytes hex
  assert.notStrictEqual(kek.toString('hex'), authKey);
});

test('AEAD: Encryption & Decryption roundtrip with tag validation', () => {
  const key = crypto.randomBytes(32);
  const plaintext = JSON.stringify({ username: 'alice', password: 'SecretPassword99!' });
  const aad = 'usr_01:item_101:v1:k1';

  const envelope = encryptPayload(plaintext, key, aad);
  assert.ok(envelope.ciphertext);
  assert.ok(envelope.iv);
  assert.ok(envelope.tag);
  assert.strictEqual(envelope.aad, aad);

  const decrypted = decryptPayload(envelope, key, aad);
  assert.strictEqual(decrypted, plaintext);
});

test('AEAD Security: Decryption with wrong key fails at authentication tag', () => {
  const key = crypto.randomBytes(32);
  const wrongKey = crypto.randomBytes(32);
  const plaintext = 'Sensitive Note Content';
  const aad = 'usr_01:item_102:v1:k1';

  const envelope = encryptPayload(plaintext, key, aad);

  assert.throws(() => {
    decryptPayload(envelope, wrongKey, aad);
  }, /unable to authenticate data/i);
});

test('AEAD Security: Tampering with ciphertext or tag is immediately detected', () => {
  const key = crypto.randomBytes(32);
  const plaintext = 'Financial Credentials';
  const aad = 'usr_01:item_103:v1:k1';

  const envelope = encryptPayload(plaintext, key, aad);

  // Tamper ciphertext
  const tamperedCiphertext = envelope.ciphertext.slice(0, -2) + 'aa';
  assert.throws(() => {
    decryptPayload({ ...envelope, ciphertext: tamperedCiphertext }, key, aad);
  });

  // Tamper tag
  const tamperedTag = envelope.tag.slice(0, -2) + 'ff';
  assert.throws(() => {
    decryptPayload({ ...envelope, tag: tamperedTag }, key, aad);
  });
});

test('AEAD Security: Associated Data (AAD) swapping attack prevention', () => {
  const key = crypto.randomBytes(32);
  const plaintext = 'Confidential Item';
  const originalAad = 'usr_alice:item_001:v1:k1';
  const swappedAad = 'usr_bob:item_001:v1:k1'; // Attempted cross-user swap

  const envelope = encryptPayload(plaintext, key, originalAad);

  // Decryption expecting user bob's AAD must fail
  assert.throws(() => {
    decryptPayload(envelope, key, swappedAad);
  }, /AAD mismatch: Ciphertext swapping attack detected!/);
});

test('Key Wrapping: Master Password change re-wraps Vault Key without re-encrypting items', () => {
  // 1. Initial Master Password
  const salt = 'account_salt_12345';
  const masterKey1 = deriveMasterKey('OldMasterPass!2026', salt);
  const { kek: kek1 } = deriveKeysFromMaster(masterKey1);

  // 2. Generate random 256-bit Vault Key
  const vaultKey = crypto.randomBytes(32);
  const wrappedKey1 = wrapVaultKey(vaultKey, kek1);

  // 3. Encrypt an item with vaultKey
  const itemPayload = 'My bank login credentials';
  const itemEnvelope = encryptPayload(itemPayload, vaultKey, 'usr_01:item_bank:v1:k1');

  // 4. Change Master Password -> generates new KEK
  const masterKey2 = deriveMasterKey('NewMasterPass!2026#Updated', salt);
  const { kek: kek2 } = deriveKeysFromMaster(masterKey2);

  // Unwrap vaultKey with kek1, re-wrap with kek2 (Zero re-encryption of items needed!)
  const unwrappedVaultKey = unwrapVaultKey(wrappedKey1, kek1);
  const wrappedKey2 = wrapVaultKey(unwrappedVaultKey, kek2);

  // Old KEK can no longer unwrap the vault key
  assert.throws(() => {
    unwrapVaultKey(wrappedKey2, kek1);
  });

  // New KEK unwraps vault key and decrypts existing item perfectly!
  const restoredVaultKey = unwrapVaultKey(wrappedKey2, kek2);
  const decryptedItem = decryptPayload(itemEnvelope, restoredVaultKey, 'usr_01:item_bank:v1:k1');
  assert.strictEqual(decryptedItem, itemPayload);
});
