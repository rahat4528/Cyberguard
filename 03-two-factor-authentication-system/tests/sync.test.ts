import test from 'node:test';
import assert from 'node:assert';
import { mergeVaultAccounts } from '../sync-service/sync-client.js';
import { AuthenticatorAccount } from '../secure-storage/vault.js';

test('Sync Protocol: Deterministic merge conflict resolution', () => {
  const localAccounts: AuthenticatorAccount[] = [
    {
      id: 'acc_1',
      issuer: 'Service A',
      account: 'alice',
      secret: 'SECRET_A',
      type: 'totp',
      algorithm: 'SHA-1',
      digits: 6,
      period: 30,
      counter: '0',
      favorite: false,
      updatedAt: '2026-11-22T01:00:00Z'
    },
    {
      id: 'acc_hotp',
      issuer: 'HOTP Service',
      account: 'alice',
      secret: 'SECRET_H',
      type: 'hotp',
      algorithm: 'SHA-1',
      digits: 6,
      period: 30,
      counter: '15', // Lower counter
      favorite: false,
      updatedAt: '2026-11-22T02:00:00Z'
    }
  ];

  const remoteAccounts: AuthenticatorAccount[] = [
    {
      id: 'acc_2',
      issuer: 'Service B', // Remote has new account
      account: 'alice',
      secret: 'SECRET_B',
      type: 'totp',
      algorithm: 'SHA-1',
      digits: 6,
      period: 30,
      counter: '0',
      favorite: true,
      updatedAt: '2026-11-22T01:30:00Z'
    },
    {
      id: 'acc_hotp',
      issuer: 'HOTP Service',
      account: 'alice',
      secret: 'SECRET_H',
      type: 'hotp',
      algorithm: 'SHA-1',
      digits: 6,
      period: 30,
      counter: '22', // Higher counter on remote!
      favorite: false,
      updatedAt: '2026-11-22T01:30:00Z'
    }
  ];

  const merged = mergeVaultAccounts(localAccounts, remoteAccounts);

  // 1. Union of accounts (acc_1, acc_2, acc_hotp)
  assert.strictEqual(merged.length, 3);

  // 2. Highest HOTP counter wins (22 > 15) to prevent rollback
  const hotp = merged.find(a => a.id === 'acc_hotp');
  assert.strictEqual(hotp?.counter, '22');
});
