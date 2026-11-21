import fs from 'node:fs';
import path from 'node:path';
import { calculateAuditEntryHash, hashPassword } from '../security/crypto-utils.js';

export interface User {
  id: string;
  email: string;
  passwordHash: string;
  salt: string;
  name: string;
  role: 'admin' | 'user';
  status: 'active' | 'suspended';
  createdAt: string;
}

export interface OAuthClient {
  clientId: string;
  clientSecretHash?: string;
  clientSecretSalt?: string;
  clientName: string;
  clientType: 'confidential' | 'public';
  redirectUris: string[];
  allowedScopes: string[];
  status: 'active' | 'suspended';
  createdAt: string;
}

export interface AuthorizationCode {
  code: string;
  clientId: string;
  redirectUri: string;
  userId: string;
  scope: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  nonce?: string;
  expiresAt: number;
  used: boolean;
  issuedTokens: string[]; // Token families or jti
}

export interface TokenRecord {
  jti: string;
  tokenHash: string;
  clientId: string;
  userId: string;
  scope: string;
  type: 'access' | 'refresh';
  tokenFamily: string;
  isRevoked: boolean;
  expiresAt: number;
  createdAt: number;
}

export interface UserSession {
  sessionId: string;
  userId: string;
  userAgent: string;
  ipAddress: string;
  createdAt: string;
  expiresAt: number;
  isRevoked: boolean;
}

export interface UserConsent {
  userId: string;
  clientId: string;
  grantedScopes: string[];
  updatedAt: string;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  eventType: string;
  actor: string;
  details: string;
  previousHash: string;
  entryHash: string;
}

export class DatabaseStore {
  public users: Map<string, User> = new Map();
  public clients: Map<string, OAuthClient> = new Map();
  public authCodes: Map<string, AuthorizationCode> = new Map();
  public tokens: Map<string, TokenRecord> = new Map();
  public sessions: Map<string, UserSession> = new Map();
  public consents: Map<string, UserConsent> = new Map();
  public auditLogs: AuditLogEntry[] = [];
  private persistencePath?: string;

  constructor(persistencePath?: string) {
    this.persistencePath = persistencePath;
  }

  // --- Audit Log with Cryptographic Hash Chaining ---
  public logAudit(eventType: string, actor: string, details: string): AuditLogEntry {
    const previousHash = this.auditLogs.length > 0
      ? this.auditLogs[this.auditLogs.length - 1].entryHash
      : '0000000000000000000000000000000000000000000000000000000000000000';
    
    const timestamp = new Date().toISOString();
    const id = 'audit_' + Date.now() + '_' + Math.floor(Math.random() * 10000);
    const entryHash = calculateAuditEntryHash(previousHash, timestamp, eventType, actor, details);

    const entry: AuditLogEntry = {
      id,
      timestamp,
      eventType,
      actor,
      details,
      previousHash,
      entryHash
    };

    this.auditLogs.push(entry);
    return entry;
  }

  public verifyAuditChain(): { valid: boolean; brokenAt?: string } {
    for (let i = 0; i < this.auditLogs.length; i++) {
      const current = this.auditLogs[i];
      const prevHash = i === 0
        ? '0000000000000000000000000000000000000000000000000000000000000000'
        : this.auditLogs[i - 1].entryHash;

      if (current.previousHash !== prevHash) {
        return { valid: false, brokenAt: current.id };
      }

      const calculated = calculateAuditEntryHash(
        current.previousHash,
        current.timestamp,
        current.eventType,
        current.actor,
        current.details
      );

      if (calculated !== current.entryHash) {
        return { valid: false, brokenAt: current.id };
      }
    }
    return { valid: true };
  }

  // --- Token Family Management & Revocation ---
  public revokeTokenFamily(tokenFamily: string): number {
    let count = 0;
    for (const [_, token] of this.tokens.entries()) {
      if (token.tokenFamily === tokenFamily && !token.isRevoked) {
        token.isRevoked = true;
        count++;
      }
    }
    return count;
  }
}
