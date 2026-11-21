import crypto from 'node:crypto';
import { VaultItem, PasswordHealthSummary } from './types.js';

export interface GeneratorOptions {
  length: number;
  useUpper?: boolean;
  useLower?: boolean;
  useDigits?: boolean;
  useSymbols?: boolean;
  avoidAmbiguous?: boolean;
}

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?';
const AMBIGUOUS = '0O1lI|';

/**
 * Rejection Sampling CSPRNG to select random character without modulo bias
 */
function secureRandomPick(charset: string): string {
  const len = charset.length;
  const maxValidByte = 256 - (256 % len);
  let randomByte = 0;

  do {
    randomByte = crypto.randomBytes(1)[0];
  } while (randomByte >= maxValidByte);

  return charset[randomByte % len];
}

export function generatePassword(options: GeneratorOptions): string {
  let charset = '';
  if (options.useUpper ?? true) charset += UPPER;
  if (options.useLower ?? true) charset += LOWER;
  if (options.useDigits ?? true) charset += DIGITS;
  if (options.useSymbols ?? true) charset += SYMBOLS;

  if (options.avoidAmbiguous) {
    charset = charset.split('').filter(ch => !AMBIGUOUS.includes(ch)).join('');
  }

  if (charset.length === 0) {
    charset = LOWER + DIGITS;
  }

  const result: string[] = [];
  for (let i = 0; i < options.length; i++) {
    result.push(secureRandomPick(charset));
  }
  return result.join('');
}

/**
 * Client-Side Password Health Analysis
 */
export function analyzeVaultHealth(items: VaultItem[]): PasswordHealthSummary {
  let weakCount = 0;
  let incompleteCount = 0;
  const passwordMap = new Map<string, string[]>(); // hash -> itemIds
  const flaggedItems: { itemId: string; title: string; issues: string[] }[] = [];

  for (const item of items) {
    const issues: string[] = [];

    // Weak check
    if (!item.password || item.password.length < 12) {
      issues.push('Weak password (<12 characters)');
      weakCount++;
    }

    // Incomplete check
    if (!item.username || !item.url) {
      issues.push('Missing username or website URL');
      incompleteCount++;
    }

    // Reused check (keyed hash in memory, never persists)
    if (item.password) {
      const passHash = crypto.createHash('sha256').update(item.password).digest('hex');
      const existing = passwordMap.get(passHash) || [];
      existing.push(item.id);
      passwordMap.set(passHash, existing);
    }

    if (issues.length > 0) {
      flaggedItems.push({ itemId: item.id, title: item.title, issues });
    }
  }

  let reusedCount = 0;
  for (const [_, ids] of passwordMap.entries()) {
    if (ids.length > 1) {
      reusedCount += ids.length;
      for (const id of ids) {
        const flagged = flaggedItems.find(f => f.itemId === id);
        if (flagged) {
          if (!flagged.issues.includes('Reused password across accounts')) {
            flagged.issues.push('Reused password across accounts');
          }
        } else {
          const item = items.find(i => i.id === id);
          if (item) {
            flaggedItems.push({
              itemId: item.id,
              title: item.title,
              issues: ['Reused password across accounts']
            });
          }
        }
      }
    }
  }

  const total = items.length;
  const deductions = (weakCount * 30) + (reusedCount * 25) + (incompleteCount * 15);
  const healthScore = total === 0 ? 100 : Math.max(0, 100 - Math.round(deductions));

  return {
    total,
    weakCount,
    reusedCount,
    incompleteCount,
    healthScore,
    flaggedItems
  };
}
