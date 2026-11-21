import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { generateHOTP } from '../otp-engine/hotp.js';
import { generateTOTP, getRemainingSeconds } from '../otp-engine/totp.js';

export interface AuthenticatorAccount {
  id: string;
  issuer: string;
  account: string;
  secret: string; // Base32
  type: 'totp' | 'hotp';
  algorithm: 'SHA-1' | 'SHA-256' | 'SHA-512';
  digits: number;
  period: number;
  counter: string; // Serialized BigInt
  group?: string;
  favorite: boolean;
  updatedAt: string;
}

export interface EncryptedVaultFile {
  version: number;
  salt: string;
  iv: string;
  tag: string;
  aad: string;
  ciphertext: string;
}

export class AuthenticatorVault {
  private accounts: Map<string, AuthenticatorAccount> = new Map();
  private isUnlocked: boolean = false;
  private vaultKey: Buffer | null = null;
  private salt: string | null = null;
  private failedAttempts: number = 0;
  private lockedUntilMs: number = 0;

  constructor(private vaultFilePath: string = './authenticator_vault.json') {}

  public getLockedState(): { locked: boolean; retryAfterMs: number } {
    const now = Date.now();
    if (now < this.lockedUntilMs) {
      return { locked: true, retryAfterMs: this.lockedUntilMs - now };
    }
    return { locked: !this.isUnlocked, retryAfterMs: 0 };
  }

  // Escalating backoff delays for PIN protection
  public unlockWithPin(pin: string, vaultData?: EncryptedVaultFile): { success: boolean; error?: string; delayMs?: number } {
    const now = Date.now();
    if (now < this.lockedUntilMs) {
      return { success: false, error: 'Locked due to failed attempts', delayMs: this.lockedUntilMs - now };
    }

    if (!vaultData && fs.existsSync(this.vaultFilePath)) {
      try {
        const fileContent = fs.readFileSync(this.vaultFilePath, 'utf-8');
        vaultData = JSON.parse(fileContent);
      } catch {
        return { success: false, error: 'Failed to read vault file' };
      }
    }

    if (!vaultData) {
      // Create initial empty vault
      this.salt = crypto.randomBytes(16).toString('hex');
      this.vaultKey = crypto.scryptSync(pin, this.salt, 32);
      this.isUnlocked = true;
      this.failedAttempts = 0;
      this.saveAtomic();
      return { success: true };
    }

    // Derive key using stored salt
    this.salt = vaultData.salt;
    const derivedKey = crypto.scryptSync(pin, vaultData.salt, 32);

    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, Buffer.from(vaultData.iv, 'hex'));
      decipher.setAAD(Buffer.from(vaultData.aad, 'utf-8'));
      decipher.setAuthTag(Buffer.from(vaultData.tag, 'hex'));

      let decrypted = decipher.update(vaultData.ciphertext, 'hex', 'utf-8');
      decrypted += decipher.final('utf-8');

      const parsed: AuthenticatorAccount[] = JSON.parse(decrypted);
      this.accounts.clear();
      for (const acc of parsed) {
        this.accounts.set(acc.id, acc);
      }

      this.vaultKey = derivedKey;
      this.isUnlocked = true;
      this.failedAttempts = 0;
      return { success: true };
    } catch {
      this.failedAttempts++;
      let delay = 0;
      if (this.failedAttempts >= 5) delay = 30000;
      else if (this.failedAttempts >= 3) delay = 5000;

      if (delay > 0) {
        this.lockedUntilMs = Date.now() + delay;
      }
      return { success: false, error: 'Invalid PIN', delayMs: delay };
    }
  }

  public lock(): void {
    this.isUnlocked = false;
    this.vaultKey = null;
    this.accounts.clear();
  }

  public addAccount(account: Omit<AuthenticatorAccount, 'id' | 'updatedAt'>): AuthenticatorAccount {
    if (!this.isUnlocked || !this.vaultKey) {
      throw new Error('Vault is locked');
    }

    const id = 'acc_' + crypto.randomBytes(8).toString('hex');
    const newRecord: AuthenticatorAccount = {
      ...account,
      id,
      updatedAt: new Date().toISOString()
    };

    this.accounts.set(id, newRecord);
    this.saveAtomic();
    return newRecord;
  }

  public getAccounts(): AuthenticatorAccount[] {
    if (!this.isUnlocked) {
      throw new Error('Vault is locked');
    }
    return Array.from(this.accounts.values());
  }

  public generateCodeForAccount(accountId: string): { code: string; remainingSeconds?: number; counter?: string } {
    if (!this.isUnlocked) {
      throw new Error('Vault is locked');
    }

    const acc = this.accounts.get(accountId);
    if (!acc) {
      throw new Error('Account not found');
    }

    if (acc.type === 'totp') {
      const code = generateTOTP(acc.secret, undefined, {
        period: acc.period,
        digits: acc.digits,
        algorithm: acc.algorithm
      });
      const remainingSeconds = getRemainingSeconds(acc.period);
      return { code, remainingSeconds };
    }

    // CRITICAL SECURITY REQUIREMENT: HOTP counter MUST be incremented and durably flushed
    // to disk BEFORE code is shown to user, preventing counter reuse upon crash!
    const currentCounter = BigInt(acc.counter || '0');
    const code = generateHOTP(acc.secret, currentCounter, { digits: acc.digits });

    // Increment counter & persist immediately
    acc.counter = (currentCounter + 1n).toString();
    acc.updatedAt = new Date().toISOString();
    this.saveAtomic();

    return { code, counter: acc.counter };
  }

  // Atomic file write: write to .tmp -> flush -> atomic rename -> backup
  public saveAtomic(): void {
    if (!this.vaultKey || !this.salt) return;

    const data = JSON.stringify(Array.from(this.accounts.values()));
    const iv = crypto.randomBytes(12);
    const salt = this.salt;
    const aad = 'cyberguard-2fa-vault-v1';

    const cipher = crypto.createCipheriv('aes-256-gcm', this.vaultKey, iv);
    cipher.setAAD(Buffer.from(aad, 'utf-8'));

    let ciphertext = cipher.update(data, 'utf-8', 'hex');
    ciphertext += cipher.final('hex');
    const tag = cipher.getAuthTag().toString('hex');

    const filePayload: EncryptedVaultFile = {
      version: 1,
      salt,
      iv: iv.toString('hex'),
      tag,
      aad,
      ciphertext
    };

    const serialized = JSON.stringify(filePayload, null, 2);
    const dir = path.dirname(this.vaultFilePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const tmpFile = `${this.vaultFilePath}.tmp`;
    const bakFile = `${this.vaultFilePath}.bak`;

    // 1. Write to temp file and flush
    const fd = fs.openSync(tmpFile, 'w');
    fs.writeSync(fd, serialized);
    fs.fsyncSync(fd);
    fs.closeSync(fd);

    // 2. Backup previous copy if exists
    if (fs.existsSync(this.vaultFilePath)) {
      fs.copyFileSync(this.vaultFilePath, bakFile);
    }

    // 3. Atomic rename
    fs.renameSync(tmpFile, this.vaultFilePath);
  }
}
