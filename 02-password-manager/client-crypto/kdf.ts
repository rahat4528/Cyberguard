import crypto from 'node:crypto';

export interface DerivedVaultKeys {
  kek: Buffer;       // 256-bit Key-Encryption Key (never leaves client)
  authKey: string;   // 256-bit Authentication Key sent to server (hex)
}

/**
 * Derives a 256-bit Master Key from Master Password using scrypt
 */
export function deriveMasterKey(password: string, salt: string): Buffer {
  return crypto.scryptSync(password, salt, 32, {
    N: 32768,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024
  });
}

/**
 * HKDF-SHA256 Domain Separation: splits Master Key into KEK and Auth Key
 */
export function deriveKeysFromMaster(masterKey: Buffer): DerivedVaultKeys {
  // 1. Derive KEK (Used solely on client to wrap/unwrap the Vault Key)
  const kek = crypto.hkdfSync(
    'sha256',
    masterKey,
    Buffer.alloc(0),
    Buffer.from('cyberguard-vault-kek', 'utf-8'),
    32
  );

  // 2. Derive Auth Key (Sent to server to authenticate, server stores slow hash of this)
  const authKeyBuf = crypto.hkdfSync(
    'sha256',
    masterKey,
    Buffer.alloc(0),
    Buffer.from('cyberguard-vault-auth', 'utf-8'),
    32
  );

  return {
    kek: Buffer.from(kek),
    authKey: Buffer.from(authKeyBuf).toString('hex')
  };
}
