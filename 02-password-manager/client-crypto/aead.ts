import crypto from 'node:crypto';
import { EncryptedEnvelope } from './types.js';

/**
 * Constant-time string equality check
 */
export function timingSafeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Encrypt arbitrary payload using AES-256-GCM with Associated Data (AAD)
 */
export function encryptPayload(payload: string, key: Buffer, aad: string): EncryptedEnvelope {
  const iv = crypto.randomBytes(12); // 96-bit random nonce
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad, 'utf-8'));

  let ciphertext = cipher.update(payload, 'utf-8', 'hex');
  ciphertext += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');

  return {
    ciphertext,
    iv: iv.toString('hex'),
    tag,
    aad,
    version: 1
  };
}

/**
 * Decrypt payload using AES-256-GCM and verify authentication tag & AAD
 */
export function decryptPayload(envelope: EncryptedEnvelope, key: Buffer, expectedAad?: string): string {
  if (expectedAad && envelope.aad !== expectedAad) {
    throw new Error('AAD mismatch: Ciphertext swapping attack detected!');
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'hex'));
  decipher.setAAD(Buffer.from(envelope.aad, 'utf-8'));
  decipher.setAuthTag(Buffer.from(envelope.tag, 'hex'));

  let decrypted = decipher.update(envelope.ciphertext, 'hex', 'utf-8');
  decrypted += decipher.final('utf-8');
  return decrypted;
}

/**
 * Wrap a random Vault Key (256-bit) under KEK with AES-256-GCM
 */
export function wrapVaultKey(vaultKey: Buffer, kek: Buffer, aad: string = 'cyberguard-vault-key-wrap'): EncryptedEnvelope {
  return encryptPayload(vaultKey.toString('hex'), kek, aad);
}

/**
 * Unwrap a Vault Key under KEK
 */
export function unwrapVaultKey(envelope: EncryptedEnvelope, kek: Buffer, aad: string = 'cyberguard-vault-key-wrap'): Buffer {
  const hex = decryptPayload(envelope, kek, aad);
  return Buffer.from(hex, 'hex');
}
