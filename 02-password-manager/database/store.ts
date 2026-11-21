import crypto from 'node:crypto';
import { EncryptedEnvelope } from '../client-crypto/types.js';

export interface ServerUserAccount {
  id: string;
  email: string;
  authSalt: string;          // Salt for master key derivation
  authHash: string;          // scrypt hash of the Authentication Key
  serverAuthSalt: string;    // Salt for server-side auth hashing
  wrappedVaultKey: EncryptedEnvelope;
  wrappedRecoveryKey?: EncryptedEnvelope;
  kdfParams: { N: number; r: number; p: number };
  createdAt: string;
}

export interface StoredVaultItem {
  id: string;
  userId: string;
  envelope: EncryptedEnvelope;
  revision: number;
  isDeleted: boolean;
  updatedAt: string;
}

export class VaultDatabaseStore {
  public users: Map<string, ServerUserAccount> = new Map();
  public items: Map<string, StoredVaultItem> = new Map();
  public auditEvents: { id: string; timestamp: string; event: string; userId: string }[] = [];

  public logEvent(event: string, userId: string): void {
    this.auditEvents.push({
      id: 'evt_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
      timestamp: new Date().toISOString(),
      event,
      userId
    });
  }
}
