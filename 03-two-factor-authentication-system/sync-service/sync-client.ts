import { AuthenticatorAccount } from '../secure-storage/vault.js';

export interface SyncRecord {
  accounts: AuthenticatorAccount[];
  version: number;
}

/**
 * Merge two vaults following deterministic conflict resolution rules:
 * 1. Union of accounts by unique ID.
 * 2. Newest update timestamp wins for metadata.
 * 3. Max value wins for HOTP counter (prevents counter rollback).
 */
export function mergeVaultAccounts(
  local: AuthenticatorAccount[],
  remote: AuthenticatorAccount[]
): AuthenticatorAccount[] {
  const mergedMap = new Map<string, AuthenticatorAccount>();

  for (const acc of local) {
    mergedMap.set(acc.id, { ...acc });
  }

  for (const remoteAcc of remote) {
    const existing = mergedMap.get(remoteAcc.id);
    if (!existing) {
      mergedMap.set(remoteAcc.id, { ...remoteAcc });
      continue;
    }

    // Merge HOTP counter: maximum value wins!
    let finalCounter = existing.counter;
    if (existing.type === 'hotp' && remoteAcc.type === 'hotp') {
      const c1 = BigInt(existing.counter || '0');
      const c2 = BigInt(remoteAcc.counter || '0');
      finalCounter = (c1 > c2 ? c1 : c2).toString();
    }

    // Newest update timestamp wins for metadata
    const tLocal = new Date(existing.updatedAt).getTime();
    const tRemote = new Date(remoteAcc.updatedAt).getTime();

    if (tRemote > tLocal) {
      mergedMap.set(remoteAcc.id, {
        ...remoteAcc,
        counter: finalCounter
      });
    } else {
      existing.counter = finalCounter;
      mergedMap.set(existing.id, existing);
    }
  }

  return Array.from(mergedMap.values());
}
