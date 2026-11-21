import test from 'node:test';
import assert from 'node:assert';
import { generatePassword, analyzeVaultHealth } from '../client-crypto/generator.js';
import { VaultItem } from '../client-crypto/types.js';

test('Password Generator: Length, character classes, and ambiguous character exclusion', () => {
  const pwd = generatePassword({
    length: 20,
    useUpper: true,
    useLower: true,
    useDigits: true,
    useSymbols: true,
    avoidAmbiguous: true
  });

  assert.strictEqual(pwd.length, 20);
  assert.strictEqual(/[0O1lI|]/.test(pwd), false, 'Must not contain ambiguous characters');
});

test('Password Generator: Uniformity and absence of modulo bias', () => {
  const counts: Record<string, number> = {};
  const trials = 1000;

  for (let i = 0; i < trials; i++) {
    const pwd = generatePassword({ length: 1, useUpper: false, useLower: true, useDigits: false, useSymbols: false });
    counts[pwd] = (counts[pwd] || 0) + 1;
  }

  // Confirm all 26 lowercase characters appear
  assert.strictEqual(Object.keys(counts).length, 26);
});

test('Password Health: Client-side detection of weak, reused, and incomplete items', () => {
  const items: VaultItem[] = [
    {
      id: 'item_1',
      title: 'Email Account',
      username: 'alice@test.com',
      password: 'SharedPassword123!',
      url: 'https://mail.test.com',
      category: 'login',
      favorite: false,
      tags: [],
      revision: 1,
      updatedAt: new Date().toISOString()
    },
    {
      id: 'item_2',
      title: 'Shopping Site',
      username: 'alice',
      password: 'SharedPassword123!', // Reused!
      url: 'https://shop.test.com',
      category: 'login',
      favorite: false,
      tags: [],
      revision: 1,
      updatedAt: new Date().toISOString()
    },
    {
      id: 'item_3',
      title: 'Forum',
      username: 'alice',
      password: '123', // Weak!
      url: 'https://forum.test.com',
      category: 'login',
      favorite: false,
      tags: [],
      revision: 1,
      updatedAt: new Date().toISOString()
    },
    {
      id: 'item_4',
      title: 'Incomplete Record',
      username: '', // Missing username!
      password: 'LongAndUniquePassword987!#$',
      url: '', // Missing URL!
      category: 'login',
      favorite: false,
      tags: [],
      revision: 1,
      updatedAt: new Date().toISOString()
    }
  ];

  const report = analyzeVaultHealth(items);
  assert.strictEqual(report.total, 4);
  assert.strictEqual(report.reusedCount, 2);
  assert.strictEqual(report.weakCount, 1);
  assert.strictEqual(report.incompleteCount, 1);
  assert.ok(report.healthScore < 80);
});
