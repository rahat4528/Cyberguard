import test from 'node:test';
import assert from 'node:assert';
import {
  timingSafeStringCompare,
  hashPassword,
  verifyPassword,
  computeS256CodeChallenge,
  verifyPKCE,
  calculateAuditEntryHash
} from '../security/crypto-utils.js';
import { DatabaseStore } from '../database/store.js';

test('Cryptography: timing-safe string comparison', () => {
  assert.strictEqual(timingSafeStringCompare('secret_token_12345', 'secret_token_12345'), true);
  assert.strictEqual(timingSafeStringCompare('secret_token_12345', 'secret_token_99999'), false);
  assert.strictEqual(timingSafeStringCompare('short', 'much_longer_string'), false);
});

test('Cryptography: password hashing and verification', () => {
  const password = 'SuperSecretMasterPassword!2026';
  const { salt, hash } = hashPassword(password);

  assert.ok(salt.length >= 32);
  assert.ok(hash.length >= 64);
  assert.strictEqual(verifyPassword(password, salt, hash), true);
  assert.strictEqual(verifyPassword('WrongPassword', salt, hash), false);
});

test('Cryptography: RFC 7636 PKCE S256 verification', () => {
  const verifier = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
  const challenge = computeS256CodeChallenge(verifier);

  // Valid S256 verifier and challenge
  assert.strictEqual(verifyPKCE(verifier, challenge, 'S256'), true);

  // Wrong verifier
  assert.strictEqual(verifyPKCE('wrong_verifier_at_least_43_characters_long_abcdef', challenge, 'S256'), false);

  // Rejection of 'plain' method (RFC 9700 mandate)
  assert.strictEqual(verifyPKCE(verifier, verifier, 'plain'), false);

  // Rejection of invalid length (< 43 or > 128)
  assert.strictEqual(verifyPKCE('too_short', challenge, 'S256'), false);
});

test('Cryptography: Tamper-evident Audit Hash Chaining', () => {
  const db = new DatabaseStore();
  db.logAudit('USER_LOGIN', 'usr_01', 'User logged in');
  db.logAudit('CLIENT_UPDATE', 'usr_admin', 'Client redirect URI updated');
  db.logAudit('KEY_ROTATION', 'system', 'Scheduled key rotation');

  // Verify chain integrity
  const initialCheck = db.verifyAuditChain();
  assert.strictEqual(initialCheck.valid, true);

  // Tamper with second entry
  db.auditLogs[1].details = 'MALICIOUS_TAMPERED_DETAILS';
  const tamperedCheck = db.verifyAuditChain();
  assert.strictEqual(tamperedCheck.valid, false);
  assert.strictEqual(tamperedCheck.brokenAt, db.auditLogs[1].id);
});
