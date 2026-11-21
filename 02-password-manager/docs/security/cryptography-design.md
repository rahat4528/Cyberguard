# Cryptography Design: 02-password-manager

## Key Hierarchy & Domain Separation
```
Master Password
      │
      ▼ (Argon2id / scrypt, unique per-account 16-byte random salt)
Master Key (256-bit)
      │
      ▼ HKDF-SHA256 (Domain Separation)
      ├─► "cyberguard-vault-kek"  ──────► Key-Encryption Key (KEK) [Never leaves client]
      └─► "cyberguard-vault-auth" ──────► Authentication Key (Sent to server for auth)
                                                 │
                                                 ▼ (scrypt / Argon2id on server)
                                          Server-Stored Hash

Vault Key (Random 256-bit CSPRNG)
      │
      ├─► Wrapped by KEK (AES-256-GCM) ──► Stored on Server as Wrapped Vault Key
      └─► Wrapped by Recovery Key (AES-256-GCM) ──► Stored as Wrapped Recovery Key
```

## Envelope Encryption & AAD Binding
Each vault item is encrypted using AES-256-GCM with a fresh random 96-bit IV:
- **Ciphertext**: AES-256-GCM(itemPayload, perItemKey or vaultKey, iv, aad)
- **Associated Data (AAD)**: `${userId}:${itemId}:${schemaVersion}:${keyVersion}`
- **Integrity**: Decryption aborts immediately if the 128-bit authentication tag does not verify.

## Password Generator Security
- Pure cryptographically secure randomness via platform CSPRNG (`crypto.getRandomValues` / `crypto.randomBytes`).
- Strict rejection sampling to prevent modulo bias across uneven character set sizes.
- Configurable rules: uppercase, lowercase, numbers, symbols, ambiguous character exclusion.
